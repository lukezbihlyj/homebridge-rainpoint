import {
  API,
  DynamicPlatformPlugin,
  Logger,
  PlatformAccessory,
  PlatformConfig,
  Service,
  Characteristic,
  UnknownContext,
} from 'homebridge';

import type { NormalizedZoneStatus } from './api/RainPointClientInterface';
import {
  PLATFORM_NAME, PLUGIN_NAME,
} from './settings';
import {
  RainPointClient,
  Provider,
  NormalizedDevice,
  NormalizedDeviceStatus,
} from './api/RainPointClientInterface';
import { RainPointHomeClient } from './api/RainPointHomeClient';
import { RainPointTyClient } from './api/RainPointTyClient';
import {
  DEFAULT_POLL_INTERVAL,
  MIN_POLL_INTERVAL,
  DEVICE_TYPE_GATEWAY,
  DEVICE_TYPE_SENSOR,
} from './api/constants';
import { ValveAccessory } from './ValveAccessory';
import { SensorAccessory } from './SensorAccessory';
import { IrrigationSystemAccessory } from './IrrigationSystemAccessory';
import { zoneDisplayName } from './naming';

export interface DeviceAccessoryContext {
  deviceId: string;
  port: number;
  name: string;
  model: string;
  productId: string;
  deviceType: string;
  isSubDevice: boolean;
  parentId?: string;
  addr: number;
  portName: string;
  zoneNames: string[];
}

export class RainPointPlatform implements DynamicPlatformPlugin {
  public readonly Service: typeof Service = this.api.hap.Service;
  public readonly Characteristic: typeof Characteristic = this.api.hap.Characteristic;

  public readonly accessories: PlatformAccessory<UnknownContext>[] = [];
  public client: RainPointClient;

  private readonly provider: Provider;
  private readonly email: string;
  private readonly password: string;
  private readonly region: string;
  private readonly countryCode: string;
  private readonly homeIndex: number;
  private readonly pollInterval: number;
  private readonly flatValves: boolean;
  private readonly debugmode: boolean;

  private pollTimer: NodeJS.Timeout | null = null;
  private accessoryHandlers: Map<string, ValveAccessory | SensorAccessory | IrrigationSystemAccessory> = new Map();
  private deviceStatusMap: Map<string, NormalizedDeviceStatus> = new Map();
  private discoveredDeviceIds: Set<string> = new Set();
  // Per-sub-device accumulator of the latest DPs from MQTT pushes. Each TY
  // MQTT push carries only ONE DP (e.g. {"107":10}), so we must merge each
  // push into the existing set before deriving zone state — otherwise a push
  // for DP 107 alone would zero out 106/109 and flicker the valve OFF.
  private mqttDpAccumulator: Map<string, Record<string, unknown>> = new Map();
  // Cached NormalizedDevice records from the last discovery. Used to resolve
  // a device's zoneDps (workStatus/manualTimer/manualSwitch DPs per zone)
  // when re-seeding the accumulator from a polled status snapshot.
  private normalizedDevices: Map<string, NormalizedDevice> = new Map();
  // Sub-device routing for MQTT DP pushes. TY DP pushes arrive on the
  // GATEWAY's topic `smart/mb/in/{gwId}` with a `cid` field identifying the
  // sub-device (mesh node). This map keys `${gwId}/${cid}` -> sub-device
  // devId so the push is applied to the correct valve accessory. Built in
  // discoverDevices() from each NormalizedDevice's parentId + nodeId.
  private subDeviceByGwCid: Map<string, string> = new Map();
  // Reverse: gateway devId -> true, for quick "is this devId a gateway" checks.
  private gatewayDevIds: Set<string> = new Set();

  constructor(
    public readonly log: Logger,
    public readonly platformConfig: PlatformConfig,
    public readonly api: API,
  ) {
    this.provider = (platformConfig.provider as Provider) || 'home';
    this.email = platformConfig.email as string || '';
    this.password = platformConfig.password as string || '';
    // Region is split per provider: RainPoint Home uses regionHome (US/CN),
    // RainPoint TY uses regionTy (AZ/EU/IN/CN). Each has its own config field
    // and is shown conditionally in the UI based on the selected provider.
    // Falls back to the legacy `region` field if the per-provider field is unset.
    this.region = this.provider === 'ty'
      ? (platformConfig.regionTy as string || platformConfig.region as string || 'AZ')
      : (platformConfig.regionHome as string || platformConfig.region as string || 'US');
    this.countryCode = platformConfig.countryCode as string || '1';
    this.homeIndex = platformConfig.homeIndex as number ?? 0;
    this.pollInterval = platformConfig.pollInterval as number ?? DEFAULT_POLL_INTERVAL;
    this.flatValves = platformConfig.flatValves as boolean ?? false;
    this.debugmode = platformConfig.debugmode as boolean ?? false;

    if (this.pollInterval < MIN_POLL_INTERVAL) {
      this.pollInterval = MIN_POLL_INTERVAL;
    }

    if (!this.email || !this.password) {
      this.log.warn('Missing required configuration: email and password are required');
      this.client = null!;
      return;
    }

    this.client = this.createClient();

    this.log.info('Initializing RainPoint platform (provider: %s):', this.provider, platformConfig.name || 'RainPoint');

    this.api.on('didFinishLaunching', async () => {
      this.log.debug('Executed didFinishLaunching callback');
      await this.discoverDevices();
    });
  }

  private createClient(): RainPointClient {
    const config = {
      email: this.email,
      password: this.password,
      region: this.region,
      countryCode: this.countryCode,
      // Persist the TY cloud session (sid/ecode/endpoint) across homebridge restarts
      // so we don't re-login every reload. User.storagePath() is the homebridge
      // per-instance storage dir; the TY client keys the session file by email.
      storageDir: this.api.user.storagePath(),
    };

    if (this.provider === 'ty') {
      return new RainPointTyClient(config, this.log);
    }
    return new RainPointHomeClient(config, this.log);
  }

  configureAccessory(accessory: PlatformAccessory<UnknownContext>): void {
    this.log.info('Loading accessory from cache:', accessory.displayName);
    this.accessories.push(accessory);
  }

  async discoverDevices(): Promise<void> {
    try {
      this.log.info('Connecting to RainPoint API (provider: %s)...', this.provider);
      await this.client.login();

      this.log.info('Fetching homes...');
      const homes = await this.client.getHomes();
      if (homes.length === 0) {
        this.log.warn('No homes found in your RainPoint account');
        return;
      }

      const homeIndex = Math.min(this.homeIndex, homes.length - 1);
      const home = homes[homeIndex]!;
      this.client.setHome(home.id);
      this.log.info('Using home: %s (%s)', home.name, home.id);

      this.log.info('Fetching devices...');
      const devices = await this.client.getDevices();
      this.log.info('Found %d device(s)', devices.length);

      this.discoveredDeviceIds.clear();
      this.subDeviceByGwCid.clear();
      this.gatewayDevIds.clear();
      this.normalizedDevices.clear();

      for (const device of devices) {
        this.registerDevice(device);
        this.normalizedDevices.set(device.id, device);
        // Build the (gwId, cid) -> sub-device devId routing map for MQTT DP
        // pushes. cid == the sub-device's mesh nodeId. Also record gateway
        // devIds (the parentId) so handleMqttStatusUpdate can detect that a
        // push's deviceId is a gateway and remap via cid.
        if (device.parentId) {
          this.gatewayDevIds.add(device.parentId);
          if (device.nodeId) {
            this.subDeviceByGwCid.set(`${device.parentId}/${device.nodeId}`, device.id);
          }
        }
      }

      this.cleanupStaleAccessories();

      // Set up MQTT for real-time DP updates before starting polling.
      // The client connects to the Tuya broker using credentials derived
      // from the login session (sid, ecode, uid, partnerIdentity) and
      // subscribes to per-device topics `smart/mb/in/{devId}` for each
      // discovered device — that is where real-time DP pushes actually
      // arrive (verified from the decompiled app:
      // com.thingclips.sdk.device.pbpqqdp:2301). The user topic
      // {partnerIdentity}/mb/{uid} only carries user-level events.
      if (this.provider === 'ty') {
        const tyClient = this.client as RainPointTyClient;
        tyClient.setOnStatusUpdate((deviceId: string, dps: Map<string, unknown>, cid?: string) => {
          this.handleMqttStatusUpdate(deviceId, dps, cid);
        });
        // When MQTT connects, stop polling (MQTT is the source of truth).
        // When it disconnects, restart polling as a fallback.
        tyClient.setOnMqttConnect((connected: boolean) => {
          if (connected) {
            // MQTT session is clean:true — messages sent during the disconnect
            // gap are NOT queued by the broker. Run a one-shot catch-up poll
            // right now so any state change that happened while disconnected is
            // reflected, THEN stop the interval (real-time updates take over).
            // pollStatus() also re-seeds the MQTT DP accumulator from the fresh
            // snapshot so the next MQTT push merges into current state, not
            // the stale pre-disconnect accumulator.
            this.log.info('MQTT connected — catch-up poll then stopping interval');
            this.pollStatus().finally(() => {
              if (this.pollTimer) {
                clearInterval(this.pollTimer);
                this.pollTimer = null;
              }
            });
          } else {
            this.log.info('MQTT disconnected — restarting polling as fallback');
            this.startPolling();
          }
        });
        // Build the MQTT subscription device-id list. Sub-device (valve) DP
        // pushes are reported by their gateway and arrive on the GATEWAY's
        // topic `smart/mb/in/{gwId}`, not the sub-device's own topic. The
        // gateway device itself is skipped by getDevices() (see
        // RainPointTyClient.getDevices), so discoveredDeviceIds only holds
        // sub-device devIds. Add each sub-device's parentId (the gateway
        // devId) so we subscribe to the gateway topics too. Dedup via Set.
        const mqttDevIds = new Set<string>(this.discoveredDeviceIds);
        for (const device of devices) {
          if (device.parentId) {
            mqttDevIds.add(device.parentId);
          }
        }
        tyClient.connectMqtt(Array.from(mqttDevIds));
      }

      // Start polling initially — will be stopped once MQTT connects
      this.startPolling();
    } catch (error) {
      this.log.error('Failed to discover devices:', error);
    }
  }

  /**
   * Handle a real-time DP update from MQTT. Builds a minimal
   * NormalizedDeviceStatus from the incoming DPs and updates the device
   * status map, then pushes to all accessories. This bypasses the poll cycle
   * for faster state reflection (the app relies on MQTT push, not polling).
   */
  private handleMqttStatusUpdate(deviceId: string, dps: Map<string, unknown>, cid?: string): void {
    // TY DP pushes arrive on the GATEWAY's topic (deviceId == gwId) with a
    // `cid` identifying the sub-device. Remap to the sub-device devId so the
    // status is applied to the correct valve accessory. If the push's
    // deviceId is already a known sub-device (non-gateway), use it directly.
    let targetDeviceId = deviceId;
    if (cid && this.gatewayDevIds.has(deviceId)) {
      const subId = this.subDeviceByGwCid.get(`${deviceId}/${cid}`);
      if (subId) {
        targetDeviceId = subId;
      } else {
        this.log.debug('[TY] MQTT: no sub-device mapped for gw=%s cid=%s, skipping', deviceId, cid);
        return;
      }
    }

    if (!this.discoveredDeviceIds.has(targetDeviceId)) {
      return;
    }

    // Each TY MQTT push carries only ONE DP. Merge into the per-device
    // accumulator so zone state is derived from the full current set, not a
    // single-DP snapshot (which would zero the run flag and flicker OFF).
    const merged = this.mqttDpAccumulator.get(targetDeviceId) ?? {};
    for (const [k, v] of dps) {
      merged[k] = v;
    }
    // When the valve stops (WorkStatus "0"), clear the timer DPs so the zone
    // reads as off with 0 remaining, not a stale countdown value.
    if (String(merged['106']) === '0') {
      delete merged['107']; delete merged['109'];
    }
    if (String(merged['153']) === '0') {
      delete merged['154']; delete merged['156'];
    }
    this.mqttDpAccumulator.set(targetDeviceId, merged);
    const parsedDps = merged;

    const zones: NormalizedZoneStatus[] = [];

    // Map known zone DPs from the accumulated values. The zone-specific DPs
    // (WorkStatus=106/153, ManualTimer=107/154, ManualSwitch=108/155,
    // RemainTime=109/156) are the RainPoint TY irrigation schema. Zone 1 uses
    // the base 106-109 range; zone 2 uses 153-156 (+47 offset).
    //
    // Live capture showed DP 107 is the DECREMENTING remaining-minutes timer
    // (20->19->18...), while 109 (RemainTime) updates less frequently. Use
    // 107 as the primary remaining-duration source, 109 as fallback.
    const zoneConfigs = [
      { port: 1, runDp: 106, timerDp: 107, remainDp: 109 },
      { port: 2, runDp: 153, timerDp: 154, remainDp: 156 },
    ];

    for (const zc of zoneConfigs) {
      const rawRun = parsedDps[String(zc.runDp)];
      const rawTimer = parsedDps[String(zc.timerDp)];
      const rawRemain = parsedDps[String(zc.remainDp)];
      // Only emit a zone if we've seen its run OR timer DP at least once.
      if (rawRun === undefined && rawTimer === undefined && rawRemain === undefined) {
        continue;
      }
      const isOn = String(rawRun ?? '') === '1';
      const remainingMin = Number(rawTimer ?? rawRemain ?? 0);
      zones.push({
        port: zc.port,
        name: zc.port === 1 ? 'Zone 1' : 'Zone 2',
        isOn,
        remainingDuration: Number.isFinite(remainingMin) && remainingMin > 0
          ? Math.round(remainingMin * 60) : 0,
      });
    }

    const moisture = (parsedDps['9'] ?? parsedDps['14'] ?? parsedDps['humidity']
      ?? parsedDps['soil_humidity'] ?? null) as number | null;
    const temperature = (parsedDps['10'] ?? parsedDps['15'] ?? parsedDps['temperature']
      ?? parsedDps['temp_current'] ?? null) as number | null;
    const battery = (parsedDps['11'] ?? parsedDps['17'] ?? parsedDps['battery_percentage']
      ?? parsedDps['residual_electricity'] ?? null) as number | null;

    const status: NormalizedDeviceStatus = {
      deviceId: targetDeviceId,
      online: true,
      zones,
      moisture,
      temperature,
      battery,
    };

    this.log.debug('[TY] MQTT: routed status for gw=%s cid=%s -> sub-device=%s zones=%d (run=%s timer=%s)',
      deviceId, cid || '-', targetDeviceId, zones.length,
      zones[0]?.isOn ?? '-', zones[0]?.remainingDuration ?? '-');

    this.deviceStatusMap.set(targetDeviceId, status);
    this.updateAccessories();
  }

  private registerDevice(device: NormalizedDevice): void {
    this.log.debug('Device: %s (%s) - type: %s, ports: %d, sub: %s',
      device.name, device.model, device.deviceType, device.portNumber, device.isSubDevice);

    this.discoveredDeviceIds.add(device.id);

    if (device.deviceType === DEVICE_TYPE_GATEWAY) {
      this.log.debug('Skipping gateway device: %s', device.name);
      return;
    }

    if (device.deviceType === DEVICE_TYPE_SENSOR) {
      this.registerSensorAccessory(device);
      return;
    }

    if (this.flatValves) {
      this.registerFlatValves(device);
    } else {
      this.registerIrrigationSystem(device);
    }
  }

  private registerFlatValves(device: NormalizedDevice): void {
    for (let port = 1; port <= device.portNumber; port++) {
      const zoneName = zoneDisplayName(device, port, true);
      this.registerValveAccessory(device, port, zoneName);
    }
  }

  private registerValveAccessory(
    device: NormalizedDevice,
    port: number,
    name: string,
  ): void {
    const uniqueId = this.debugmode ? `dev_${device.id}_port${port}` : `${device.id}_port${port}`;
    const uuid = this.api.hap.uuid.generate(uniqueId);
    const existingAccessory = this.accessories.find(acc => acc.UUID === uuid);

    const context: DeviceAccessoryContext = {
      deviceId: device.id,
      port,
      name,
      model: device.model,
      productId: device.productId,
      deviceType: device.deviceType,
      isSubDevice: device.isSubDevice,
      parentId: device.parentId,
      addr: device.addr,
      portName: name,
      zoneNames: device.portDescribe,
    };

    if (existingAccessory) {
      this.log.info('Restoring existing valve accessory from cache:', existingAccessory.displayName);
      existingAccessory.context = context as unknown as UnknownContext;
      this.api.updatePlatformAccessories([existingAccessory]);
      const handler = new ValveAccessory(this, existingAccessory, context);
      this.accessoryHandlers.set(uniqueId, handler);
    } else {
      this.log.info('Adding new valve accessory:', name);
      const accessory = new this.api.platformAccessory(name, uuid);
      accessory.context = context as unknown as UnknownContext;
      const handler = new ValveAccessory(this, accessory, context);
      this.accessoryHandlers.set(uniqueId, handler);
      this.api.registerPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [accessory]);
    }
  }

  private registerSensorAccessory(device: NormalizedDevice): void {
    const uniqueId = this.debugmode ? `dev_${device.id}` : device.id;
    const uuid = this.api.hap.uuid.generate(uniqueId);
    const existingAccessory = this.accessories.find(acc => acc.UUID === uuid);

    const context: DeviceAccessoryContext = {
      deviceId: device.id,
      port: 0,
      name: device.name,
      model: device.model,
      productId: device.productId,
      deviceType: DEVICE_TYPE_SENSOR,
      isSubDevice: device.isSubDevice,
      parentId: device.parentId,
      addr: device.addr,
      portName: device.name,
      zoneNames: device.portDescribe,
    };

    if (existingAccessory) {
      this.log.info('Restoring existing sensor accessory from cache:', existingAccessory.displayName);
      existingAccessory.context = context as unknown as UnknownContext;
      this.api.updatePlatformAccessories([existingAccessory]);
      const handler = new SensorAccessory(this, existingAccessory, context);
      this.accessoryHandlers.set(uniqueId, handler);
    } else {
      this.log.info('Adding new sensor accessory:', device.name);
      const accessory = new this.api.platformAccessory(device.name, uuid);
      accessory.context = context as unknown as UnknownContext;
      const handler = new SensorAccessory(this, accessory, context);
      this.accessoryHandlers.set(uniqueId, handler);
      this.api.registerPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [accessory]);
    }
  }

  private registerIrrigationSystem(device: NormalizedDevice): void {
    const uniqueId = this.debugmode ? `dev_sys_${device.id}` : `sys_${device.id}`;
    const uuid = this.api.hap.uuid.generate(uniqueId);
    const existingAccessory = this.accessories.find(acc => acc.UUID === uuid);

    const context: DeviceAccessoryContext = {
      deviceId: device.id,
      port: 0,
      name: device.name,
      model: device.model,
      productId: device.productId,
      deviceType: device.deviceType,
      isSubDevice: device.isSubDevice,
      parentId: device.parentId,
      addr: device.addr,
      portName: device.name,
      zoneNames: device.portDescribe,
    };

    if (existingAccessory) {
      this.log.info('Restoring existing irrigation system accessory from cache:', existingAccessory.displayName);
      existingAccessory.context = context as unknown as UnknownContext;
      this.api.updatePlatformAccessories([existingAccessory]);
      const handler = new IrrigationSystemAccessory(this, existingAccessory, context, device);
      this.accessoryHandlers.set(uniqueId, handler);
    } else {
      this.log.info('Adding new irrigation system accessory:', device.name);
      const accessory = new this.api.platformAccessory(device.name, uuid);
      accessory.context = context as unknown as UnknownContext;
      const handler = new IrrigationSystemAccessory(this, accessory, context, device);
      this.accessoryHandlers.set(uniqueId, handler);
      this.api.registerPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [accessory]);
    }
  }

  private startPolling(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
    }

    const intervalSeconds = this.pollInterval;
    this.log.info('Starting status polling every %d seconds', intervalSeconds);

    this.pollTimer = setInterval(async () => {
      // Skip polling if MQTT is connected — real-time updates are active
      if (this.provider === 'ty'
        && (this.client as RainPointTyClient).getMqttConnected()) {
        return;
      }
      await this.pollStatus();
    }, intervalSeconds * 1000);

    this.pollStatus();
  }

  private async pollStatus(): Promise<void> {
    try {
      const deviceIds = Array.from(this.discoveredDeviceIds);
      if (deviceIds.length === 0) {
        return;
      }

      const statuses = await this.client.getDeviceStatuses(deviceIds);
      for (const [deviceId, status] of statuses) {
        this.deviceStatusMap.set(deviceId, status);
        // Re-seed the MQTT DP accumulator from the fresh REST snapshot so
        // the next MQTT push merges into current state, not stale DPs from
        // before a disconnect. We only set the zone run + timer DPs (the
        // ones MQTT pushes update) — other DPs (moisture/temp/battery) are
        // carried by the NormalizedDeviceStatus directly, not the accumulator.
        if (this.provider === 'ty') {
          const seeded: Record<string, unknown> = {};
          const device = this.normalizedDevices.get(deviceId);
          for (const zone of status.zones) {
            const zoneDp = device?.zoneDps?.[zone.port - 1];
            if (!zoneDp) {
              continue;
            }
            seeded[String(zoneDp.workStatus)] = zone.isOn ? '1' : '0';
            if (zone.remainingDuration > 0) {
              const min = Math.round(zone.remainingDuration / 60);
              if (min > 0) {
                seeded[String(zoneDp.manualTimer)] = min;
              }
            }
          }
          this.mqttDpAccumulator.set(deviceId, seeded);
        }
      }
      this.updateAccessories();
    } catch (error) {
      this.log.error('Polling failed:', error);
    }
  }

  private updateAccessories(): void {
    for (const [, handler] of this.accessoryHandlers) {
      const context = handler.getContext();
      const status = this.deviceStatusMap.get(context.deviceId);
      if (status) {
        handler.updateStatus(status);
      }
    }
  }

  getDeviceStatus(deviceId: string): NormalizedDeviceStatus | undefined {
    return this.deviceStatusMap.get(deviceId);
  }

  private cleanupStaleAccessories(): void {
    const currentIds = new Set<string>();
    for (const [uniqueId] of this.accessoryHandlers) {
      currentIds.add(this.api.hap.uuid.generate(uniqueId));
    }

    const staleAccessories = this.accessories.filter(acc => !currentIds.has(acc.UUID));

    if (staleAccessories.length > 0) {
      this.log.info('Removing %d stale accessory(s)', staleAccessories.length);
      this.api.unregisterPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, staleAccessories);
    }
  }
}
