import { Service, PlatformAccessory, CharacteristicValue } from 'homebridge';

import { RainPointPlatform, DeviceAccessoryContext } from './platform';
import { NormalizedDeviceStatus } from './api/RainPointClientInterface';

export class SensorAccessory {
  private humidityService: Service;
  private temperatureService: Service | null = null;
  private batteryService: Service | null = null;

  private moisture: number | null = null;
  private temperature: number | null = null;
  private batteryLevel: number | null = null;

  constructor(
    private readonly platform: RainPointPlatform,
    private readonly accessory: PlatformAccessory,
    private readonly context: DeviceAccessoryContext,
  ) {
    this.accessory.getService(this.platform.Service.AccessoryInformation)!
      .setCharacteristic(this.platform.Characteristic.Name, this.context.portName)
      .setCharacteristic(this.platform.Characteristic.SerialNumber, this.context.deviceId)
      .setCharacteristic(this.platform.Characteristic.Model, this.context.model)
      .setCharacteristic(this.platform.Characteristic.Manufacturer, 'RainPoint');

    this.humidityService = this.accessory.getService(this.platform.Service.HumiditySensor)
      || this.accessory.addService(this.platform.Service.HumiditySensor);

    this.humidityService.setCharacteristic(this.platform.Characteristic.Name, this.context.portName);

    this.humidityService.getCharacteristic(this.platform.Characteristic.CurrentRelativeHumidity)
      .onGet(this.getCurrentRelativeHumidity.bind(this));

    this.temperatureService = this.accessory.getService(this.platform.Service.TemperatureSensor)
      || this.accessory.addService(this.platform.Service.TemperatureSensor);

    this.temperatureService.setCharacteristic(
      this.platform.Characteristic.Name,
      `${this.context.portName} Temperature`,
    );

    this.temperatureService.getCharacteristic(this.platform.Characteristic.CurrentTemperature)
      .onGet(this.getCurrentTemperature.bind(this));

    this.batteryService = this.accessory.getService(this.platform.Service.Battery)
      || this.accessory.addService(this.platform.Service.Battery);

    this.batteryService.getCharacteristic(this.platform.Characteristic.BatteryLevel)
      .onGet(this.getBatteryLevel.bind(this));

    this.batteryService.getCharacteristic(this.platform.Characteristic.StatusLowBattery)
      .onGet(this.getStatusLowBattery.bind(this));
  }

  getContext(): DeviceAccessoryContext {
    return this.context;
  }

  updateStatus(status: NormalizedDeviceStatus): void {
    this.moisture = status.moisture;
    this.temperature = status.temperature;
    this.batteryLevel = status.battery;

    if (this.moisture !== null) {
      this.humidityService.updateCharacteristic(
        this.platform.Characteristic.CurrentRelativeHumidity,
        this.moisture,
      );
    }

    if (this.temperature !== null && this.temperatureService) {
      this.temperatureService.updateCharacteristic(
        this.platform.Characteristic.CurrentTemperature,
        this.temperature,
      );
    }

    if (this.batteryLevel !== null && this.batteryService) {
      this.batteryService.updateCharacteristic(
        this.platform.Characteristic.BatteryLevel,
        this.batteryLevel,
      );

      const lowBattery = this.batteryLevel <= 20
        ? this.platform.Characteristic.StatusLowBattery.BATTERY_LEVEL_LOW
        : this.platform.Characteristic.StatusLowBattery.BATTERY_LEVEL_NORMAL;

      this.batteryService.updateCharacteristic(
        this.platform.Characteristic.StatusLowBattery,
        lowBattery,
      );
    }
  }

  async getCurrentRelativeHumidity(): Promise<CharacteristicValue> {
    return this.moisture ?? 0;
  }

  async getCurrentTemperature(): Promise<CharacteristicValue> {
    return this.temperature ?? 0;
  }

  async getBatteryLevel(): Promise<CharacteristicValue> {
    return this.batteryLevel ?? 100;
  }

  async getStatusLowBattery(): Promise<CharacteristicValue> {
    const level = this.batteryLevel ?? 100;
    return level <= 20
      ? this.platform.Characteristic.StatusLowBattery.BATTERY_LEVEL_LOW
      : this.platform.Characteristic.StatusLowBattery.BATTERY_LEVEL_NORMAL;
  }
}
