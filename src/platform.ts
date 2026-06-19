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

import { PLATFORM_NAME, PLUGIN_NAME } from './settings';
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

      for (const device of devices) {
        this.registerDevice(device);
      }

      this.cleanupStaleAccessories();
      this.startPolling();
    } catch (error) {
      this.log.error('Failed to discover devices:', error);
    }
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
