import { Service, PlatformAccessory, CharacteristicValue } from 'homebridge';

const DEFAULT_DURATION_SEC = 1200;

import { RainPointPlatform, DeviceAccessoryContext } from './platform';
import { NormalizedDevice, NormalizedDeviceStatus } from './api/RainPointClientInterface';
import { ValveAccessory } from './ValveAccessory';
import { zoneDisplayName } from './naming';

export class IrrigationSystemAccessory {
  private systemService: Service;
  private valveAccessories: ValveAccessory[] = [];
  private isOnline: boolean = false;
  private readonly valveSetDurations: Map<number, number> = new Map();

  constructor(
    private readonly platform: RainPointPlatform,
    private readonly accessory: PlatformAccessory,
    private readonly context: DeviceAccessoryContext,
    private readonly device: NormalizedDevice,
  ) {
    this.platform.log.debug('[%s] IrrigationSystemAccessory ctor: device.name=%s portNumber=%d portDescribe=%s accessory.displayName=%s',
      device.name, device.name, device.portNumber, JSON.stringify(device.portDescribe), this.accessory.displayName);
    this.accessory.getService(this.platform.Service.AccessoryInformation)!
      .setCharacteristic(this.platform.Characteristic.Name, device.name)
      .setCharacteristic(this.platform.Characteristic.SerialNumber, device.id)
      .setCharacteristic(this.platform.Characteristic.Model, device.model)
      .setCharacteristic(this.platform.Characteristic.Manufacturer, 'RainPoint');
    // Keep the accessory's displayName in sync with the device name. A cached
    // accessory from a prior run may have a stale displayName (e.g. a valve
    // service name from when zone detection was different); the web UI shows
    // displayName, so update it explicitly here.
    this.accessory.displayName = device.name;

    this.systemService = this.accessory.getService(this.platform.Service.IrrigationSystem)
      || this.accessory.addService(this.platform.Service.IrrigationSystem);
    // Force the system service's displayName + Name characteristic to the device
    // name (a cached service may carry a stale name from a previous run).
    this.systemService.displayName = device.name;

    this.systemService.setCharacteristic(this.platform.Characteristic.Name, device.name);
    this.systemService.setCharacteristic(
      this.platform.Characteristic.ProgramMode,
      this.platform.Characteristic.ProgramMode.NO_PROGRAM_SCHEDULED,
    );

    this.systemService.getCharacteristic(this.platform.Characteristic.Active)
      .onGet(this.getActive.bind(this))
      .onSet(this.setActive.bind(this));

    this.systemService.getCharacteristic(this.platform.Characteristic.InUse)
      .onGet(this.getInUse.bind(this));

    this.createValveServices();
  }

  getContext(): DeviceAccessoryContext {
    return this.context;
  }

  private createValveServices(): void {
    const portNumber = this.device.portNumber || 1;

    for (let port = 1; port <= portNumber; port++) {
      const zoneName = zoneDisplayName(this.device, port, false);
      const subType = `zone${port}`;
      // Look up the existing valve service by subtype ONLY (not displayName).
      // getService(string) matches by subtype OR name, which can collide when a
      // cached service from a prior run carries a stale displayName that happens
      // to equal another zone's intended name. Matching subtype explicitly keeps
      // each port's service stable across restarts.
      let valveService = this.accessory.services.find(
        s => s.subtype === subType && s.UUID === this.platform.Service.Valve.UUID,
      );
      this.platform.log.debug('[%s] zone %d: zoneName=%s subType=%s existingService=%s',
        this.device.name, port, zoneName, subType, valveService ? `yes(display=${valveService.displayName})` : 'no');
      if (!valveService) {
        valveService = this.accessory.addService(
          this.platform.Service.Valve, zoneName, subType);
      }

      // Unconditionally overwrite displayName + Name so a cached service from a
      // prior run (e.g. a 1-zone run that named zone1 "Right Valve") is renamed
      // to the current zone name.
      valveService.displayName = zoneName;
      valveService.setCharacteristic(this.platform.Characteristic.Name, zoneName);
      valveService.setCharacteristic(
        this.platform.Characteristic.ValveType,
        this.platform.Characteristic.ValveType.IRRIGATION,
      );

      const valveContext: DeviceAccessoryContext = {
        ...this.context,
        port,
        portName: zoneName,
      };

      const valveHandler = new ValveAccessory(this.platform, this.accessory, valveContext);
      this.valveAccessories.push(valveHandler);

      valveService.getCharacteristic(this.platform.Characteristic.Active)
        .onGet(() => this.getValveActive(port))
        .onSet((value) => this.setValveActive(port, value));

      valveService.getCharacteristic(this.platform.Characteristic.InUse)
        .onGet(() => this.getValveInUse(port));

      valveService.getCharacteristic(this.platform.Characteristic.SetDuration)
        .onGet(() => this.getValveSetDuration(port))
        .onSet((value) => this.setValveSetDuration(port, value));

      valveService.getCharacteristic(this.platform.Characteristic.RemainingDuration)
        .onGet(() => this.getValveRemainingDuration(port));

      this.systemService.addLinkedService(valveService);
    }

    // Remove stale valve services left over from a prior run (e.g. a zone that
    // no longer exists, or a service whose subtype doesn't match the current
    // zone1..zoneN scheme). This keeps the accessory tidy across detection changes.
    const validSubtypes = new Set<string>();
    for (let p = 1; p <= portNumber; p++) {
      validSubtypes.add(`zone${p}`);
    }
    const staleValveServices = this.accessory.services.filter(
      s => s.UUID === this.platform.Service.Valve.UUID
        && (!s.subtype || !validSubtypes.has(s.subtype)),
    );
    for (const stale of staleValveServices) {
      this.platform.log.debug('[%s] Removing stale valve service %s',
        this.device.name, stale.subtype || stale.displayName);
      this.accessory.removeService(stale);
    }
  }

  updateStatus(status: NormalizedDeviceStatus): void {
    this.isOnline = status.online;

    for (const valve of this.valveAccessories) {
      valve.updateStatus(status);
    }

    this.systemService.updateCharacteristic(
      this.platform.Characteristic.Active,
      this.isOnline
        ? this.platform.Characteristic.Active.ACTIVE
        : this.platform.Characteristic.Active.INACTIVE,
    );
  }

  private async getActive(): Promise<CharacteristicValue> {
    return this.isOnline
      ? this.platform.Characteristic.Active.ACTIVE
      : this.platform.Characteristic.Active.INACTIVE;
  }

  private async setActive(value: CharacteristicValue): Promise<void> {
    this.platform.log.info(
      '[%s] Setting irrigation system to %s',
      this.device.name,
      value ? 'ON' : 'OFF',
    );
  }

  private async getInUse(): Promise<CharacteristicValue> {
    const anyOn = this.valveAccessories.some(v => {
      const ctx = v.getContext();
      const status = this.platform.getDeviceStatus(ctx.deviceId);
      const zone = status?.zones.find(z => z.port === ctx.port);
      return zone?.isOn ?? false;
    });
    return anyOn
      ? this.platform.Characteristic.InUse.IN_USE
      : this.platform.Characteristic.InUse.NOT_IN_USE;
  }

  private async getValveActive(port: number): Promise<CharacteristicValue> {
    const status = this.platform.getDeviceStatus(this.context.deviceId);
    const zone = status?.zones.find(z => z.port === port);
    return zone?.isOn
      ? this.platform.Characteristic.Active.ACTIVE
      : this.platform.Characteristic.Active.INACTIVE;
  }

  private async setValveActive(port: number, value: CharacteristicValue): Promise<void> {
    const targetActive = value as number;
    const zoneName = this.device.portDescribe[port - 1] || `Zone ${port}`;
    this.platform.log.info(
      '[%s] Setting %s to %s',
      this.device.name,
      zoneName,
      targetActive === 1 ? 'ON' : 'OFF',
    );

    try {
      const valveService = this.accessory.services.find(
        s => s.subtype === `zone${port}` && s.UUID === this.platform.Service.Valve.UUID,
      );
      const Characteristic = this.platform.Characteristic;

      if (targetActive === this.platform.Characteristic.Active.ACTIVE) {
        const duration = this.valveSetDurations.get(port) ?? DEFAULT_DURATION_SEC;
        await this.platform.client.turnZoneOn(this.context.deviceId, port, duration);

        // Seed the platform's MQTT accumulator + status map so real-time MQTT
        // pushes merge onto the commanded state instead of reverting to a
        // stale "0" run flag from the previous stop.
        this.platform.applyOptimisticZoneState(this.context.deviceId, port, true, duration);

        // Optimistic update: immediately reflect ON + remaining duration so the
        // Home app doesn't show a stale state / "Waiting" before MQTT confirms.
        valveService?.updateCharacteristic(Characteristic.Active, Characteristic.Active.ACTIVE);
        valveService?.updateCharacteristic(Characteristic.InUse, Characteristic.InUse.IN_USE);
        valveService?.updateCharacteristic(Characteristic.RemainingDuration, duration);
      } else {
        await this.platform.client.turnZoneOff(this.context.deviceId, port);

        this.platform.applyOptimisticZoneState(this.context.deviceId, port, false, 0);

        valveService?.updateCharacteristic(Characteristic.Active, Characteristic.Active.INACTIVE);
        valveService?.updateCharacteristic(Characteristic.InUse, Characteristic.InUse.NOT_IN_USE);
        valveService?.updateCharacteristic(Characteristic.RemainingDuration, 0);
      }
    } catch (error) {
      this.platform.log.error('Failed to control valve: %s', error);
      throw error;
    }
  }

  private async getValveInUse(port: number): Promise<CharacteristicValue> {
    const status = this.platform.getDeviceStatus(this.context.deviceId);
    const zone = status?.zones.find(z => z.port === port);
    return zone?.isOn
      ? this.platform.Characteristic.InUse.IN_USE
      : this.platform.Characteristic.InUse.NOT_IN_USE;
  }

  private async getValveSetDuration(port: number): Promise<CharacteristicValue> {
    return this.valveSetDurations.get(port) ?? DEFAULT_DURATION_SEC;
  }

  private async setValveSetDuration(port: number, value: CharacteristicValue): Promise<void> {
    const duration = value as number;
    this.valveSetDurations.set(port, duration);
    this.platform.log.debug('[%s] Set duration for zone %d to %d seconds (%d minutes)',
      this.device.name, port, duration, Math.floor(duration / 60));
  }

  private async getValveRemainingDuration(port: number): Promise<CharacteristicValue> {
    const status = this.platform.getDeviceStatus(this.context.deviceId);
    const zone = status?.zones.find(z => z.port === port);
    return zone?.remainingDuration ?? 0;
  }
}
