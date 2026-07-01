import { Service, PlatformAccessory, CharacteristicValue } from 'homebridge';

import { RainPointPlatform, DeviceAccessoryContext } from './platform';
import { NormalizedDeviceStatus } from './api/RainPointClientInterface';

export class ValveAccessory {
  private service: Service;

  private isOn: boolean = false;
  private isOnline: boolean = false;
  private remainingDuration: number = 0;
  private setDuration: number = 1200;

  private lastCommandTime = 0;
  private readonly COMMAND_DEBOUNCE_MS = 5000;

  constructor(
    private readonly platform: RainPointPlatform,
    private readonly accessory: PlatformAccessory,
    private readonly context: DeviceAccessoryContext,
  ) {
    // Only manage the accessory-level AccessoryInformation when this valve IS
    // the accessory's primary service (flat-valve mode, one Valve per
    // accessory). When part of a multi-valve irrigation-system accessory, the
    // IrrigationSystemAccessory owns AccessoryInformation — otherwise each
    // ValveAccessory handler would overwrite it and the last port wins
    // (clobbering the device name + serial with a single zone's values).
    const isPrimary = !this.accessory.services.some(
      s => s.UUID === this.platform.Service.IrrigationSystem.UUID,
    );
    if (isPrimary) {
      this.accessory.getService(this.platform.Service.AccessoryInformation)!
        .setCharacteristic(this.platform.Characteristic.Name, this.context.portName)
        .setCharacteristic(this.platform.Characteristic.SerialNumber, `${this.context.deviceId}_${this.context.port}`)
        .setCharacteristic(this.platform.Characteristic.Model, this.context.model)
        .setCharacteristic(this.platform.Characteristic.Manufacturer, 'RainPoint');
    }

    // Look up the valve service by subtype. On an irrigation-system accessory
    // multiple Valve services share one accessory (zone1, zone2, ...);
    // getService(Service.Valve) WITHOUT a subtype matches the FIRST valve by
    // UUID only, so the port=2 handler would grab zone1's service and clobber
    // its Name characteristic. Matching by subtype (`zone${port}`) targets the
    // correct per-zone service. In flat-valve mode each accessory owns a single
    // Valve service with no subtype, so fall back to the first Valve service.
    const subType = `zone${this.context.port}`;
    this.service = this.accessory.services.find(
      s => s.UUID === this.platform.Service.Valve.UUID && s.subtype === subType,
    ) ?? this.accessory.services.find(
      s => s.UUID === this.platform.Service.Valve.UUID && !s.subtype,
    ) ?? this.accessory.addService(this.platform.Service.Valve, this.context.portName, subType);

    this.service.setCharacteristic(this.platform.Characteristic.Name, this.context.portName);
    this.service.setCharacteristic(
      this.platform.Characteristic.ValveType,
      this.platform.Characteristic.ValveType.IRRIGATION,
    );

    this.service.getCharacteristic(this.platform.Characteristic.Active)
      .onGet(this.getActive.bind(this))
      .onSet(this.setActive.bind(this));

    this.service.getCharacteristic(this.platform.Characteristic.InUse)
      .onGet(this.getInUse.bind(this));

    this.service.getCharacteristic(this.platform.Characteristic.SetDuration)
      .onGet(this.getSetDuration.bind(this))
      .onSet(this.setSetDuration.bind(this));

    this.service.getCharacteristic(this.platform.Characteristic.RemainingDuration)
      .onGet(this.getRemainingDuration.bind(this));
  }

  getContext(): DeviceAccessoryContext {
    return this.context;
  }

  updateStatus(status: NormalizedDeviceStatus): void {
    this.isOnline = status.online;

    const zone = status.zones.find(z => z.port === this.context.port);
    if (zone) {
      this.isOn = zone.isOn;
      this.remainingDuration = zone.remainingDuration;
    } else {
      this.isOn = false;
      this.remainingDuration = 0;
    }

    this.service.updateCharacteristic(
      this.platform.Characteristic.Active,
      this.isOn ? this.platform.Characteristic.Active.ACTIVE : this.platform.Characteristic.Active.INACTIVE,
    );

    this.service.updateCharacteristic(
      this.platform.Characteristic.InUse,
      this.isOn ? this.platform.Characteristic.InUse.IN_USE : this.platform.Characteristic.InUse.NOT_IN_USE,
    );

    if (this.remainingDuration > 0) {
      this.service.updateCharacteristic(
        this.platform.Characteristic.RemainingDuration,
        this.remainingDuration,
      );
    }
  }

  async getActive(): Promise<CharacteristicValue> {
    return this.isOn
      ? this.platform.Characteristic.Active.ACTIVE
      : this.platform.Characteristic.Active.INACTIVE;
  }

  async setActive(value: CharacteristicValue): Promise<void> {
    const targetActive = value as number;
    const Characteristic = this.platform.Characteristic;
    const turnOn = targetActive === Characteristic.Active.ACTIVE;
    this.platform.log.info(
      '[%s] Setting valve to %s',
      this.context.portName,
      turnOn ? 'ON' : 'OFF',
    );

    // Apply the optimistic state BEFORE the awaited API call. The Home app
    // issues a GET InUse/Active immediately after the SET returns, and if that
    // GET reads the (stale) status map it caches "Off" for ~10-15s. Updating
    // the status map + characteristics first means the GET sees the commanded
    // state. The MQTT accumulator is also seeded so real-time pushes merge
    // onto the intended state instead of reverting it.
    this.isOn = turnOn;
    this.remainingDuration = turnOn ? this.setDuration : 0;
    this.platform.applyOptimisticZoneState(
      this.context.deviceId, this.context.port, turnOn, this.remainingDuration,
    );
    this.service.updateCharacteristic(
      Characteristic.Active, turnOn ? Characteristic.Active.ACTIVE : Characteristic.Active.INACTIVE,
    );
    this.service.updateCharacteristic(
      Characteristic.InUse, turnOn ? Characteristic.InUse.IN_USE : Characteristic.InUse.NOT_IN_USE,
    );
    this.service.updateCharacteristic(
      Characteristic.RemainingDuration, this.remainingDuration,
    );

    try {
      if (turnOn) {
        await this.platform.client.turnZoneOn(
          this.context.deviceId, this.context.port, this.setDuration,
        );
      } else {
        await this.platform.client.turnZoneOff(
          this.context.deviceId, this.context.port,
        );
      }
    } catch (error) {
      // Revert the optimistic state on failure.
      this.platform.log.error('Failed to set valve: %s', error);
      this.isOn = !turnOn;
      this.remainingDuration = 0;
      this.platform.applyOptimisticZoneState(
        this.context.deviceId, this.context.port, !turnOn, 0,
      );
      this.service.updateCharacteristic(
        Characteristic.Active, turnOn ? Characteristic.Active.INACTIVE : Characteristic.Active.ACTIVE,
      );
      this.service.updateCharacteristic(
        Characteristic.InUse, turnOn ? Characteristic.InUse.NOT_IN_USE : Characteristic.InUse.IN_USE,
      );
      this.service.updateCharacteristic(Characteristic.RemainingDuration, 0);
      throw error;
    }
  }

  async getInUse(): Promise<CharacteristicValue> {
    return this.isOn
      ? this.platform.Characteristic.InUse.IN_USE
      : this.platform.Characteristic.InUse.NOT_IN_USE;
  }

  async getSetDuration(): Promise<CharacteristicValue> {
    return this.setDuration;
  }

  async setSetDuration(value: CharacteristicValue): Promise<void> {
    this.setDuration = value as number;
    this.platform.log.debug(
      '[%s] Set duration to %d seconds (%d minutes)',
      this.context.portName,
      this.setDuration,
      Math.floor(this.setDuration / 60),
    );
  }

  async getRemainingDuration(): Promise<CharacteristicValue> {
    return this.remainingDuration;
  }
}
