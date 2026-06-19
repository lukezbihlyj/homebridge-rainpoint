import https from 'https';
import crypto from 'crypto';
import os from 'os';

import {
  BaseResponse,
  LoginInfo,
  Home,
  MainDevice,
  SubDevice,
  DeviceStatus,
  MultipleDeviceStatus,
  ControlResponse,
  ControlWorkModeParams,
  ControlWorkModeDPParams,
} from './types';

import {
  getBaseUrl,
  getDeviceType,
  API_VERSION,
  APP_CODE,
  SCENE_TYPE,
  DEVICE_TYPE_GATEWAY,
  DEVICE_TYPE_SENSOR,
  DP_CODE_IRRIGATION,
  CONTROL_MODE_NEXT,
  CONTROL_MODE_MANUAL,
  STOP_ALL_PARAM,
  buildZoneOnParam,
  buildZoneOnWithDurationParam,
} from './constants';

import {
  RainPointClient,
  RainPointClientConfig,
  Logger,
  NormalizedDevice,
  NormalizedDeviceStatus,
  NormalizedHome,
  NormalizedZoneStatus,
} from './RainPointClientInterface';


function md5(input: string): string {
  return crypto.createHash('md5').update(input, 'utf8').digest('hex');
}

export class RainPointHomeClient implements RainPointClient {
  private token: string = '';
  private refreshTokenValue: string = '';
  private tokenExpired: number = 0;
  private hid: string = '';
  private userDeviceName: string = '';
  private userProductKey: string = '';
  private readonly baseUrl: string;
  private readonly deviceId: string;
  private static deviceIdStorage: string | null = null;

  constructor(
    private config: RainPointClientConfig,
    private log: Logger,
  ) {
    this.baseUrl = getBaseUrl(config.region);
    this.deviceId = RainPointHomeClient.getOrCreateDeviceId();
  }

  private static getOrCreateDeviceId(): string {
    if (RainPointHomeClient.deviceIdStorage) {
      return RainPointHomeClient.deviceIdStorage;
    }
    const uuid = crypto.randomUUID().replace(/-/g, '');
    RainPointHomeClient.deviceIdStorage = uuid;
    return uuid;
  }

  async login(): Promise<void> {
    const isocode = this.config.region === 'CN' ? 'CN' : 'US';
    const areaCode = this.config.region === 'CN' ? '86' : '1';
    const hashedPassword = md5(this.config.password);

    const response = await this.request<LoginInfo>(
      'POST',
      '/auth/basic/app/login',
      {
        areaCode,
        phoneOrEmail: this.config.email,
        password: hashedPassword,
        pushId: '',
        deviceType: 1,
        deviceModel: os.hostname() || 'homebridge',
        language: 'en',
        isocode,
        deviceId: this.deviceId,
        osVersion: 33,
      },
      false,
    );

    this.token = response.data.token;
    this.refreshTokenValue = response.data.refreshToken;
    this.tokenExpired = response.data.tokenExpired;
    this.userDeviceName = response.data.user.deviceName;
    this.userProductKey = response.data.user.productKey;

    this.log.info('Logged in to RainPoint Home API as %s', this.config.email);
  }

  async ensureAuthenticated(): Promise<void> {
    if (Date.now() >= this.tokenExpired) {
      await this.refreshAccessToken();
    }
  }

  private async refreshAccessToken(): Promise<void> {
    try {
      const response = await this.request<TokenResponse>(
        'POST',
        '/auth/basic/app/token/refresh',
        { refreshToken: this.refreshTokenValue },
        false,
      );

      this.token = response.data.token;
      this.refreshTokenValue = response.data.refreshToken;
      this.tokenExpired = response.data.tokenExpired;
      this.log.debug('Refreshed RainPoint Home access token');
    } catch (error) {
      this.log.error('Failed to refresh token, re-authenticating...');
      await this.login();
    }
  }

  setHome(homeId: string): void {
    this.hid = homeId;
  }

  async getHomes(): Promise<NormalizedHome[]> {
    const response = await this.request<Home[]>('GET', '/app/member/appHome/list');
    return response.data.map(h => ({ id: h.hid, name: h.homeName }));
  }

  async getDevices(): Promise<NormalizedDevice[]> {
    const response = await this.request<MainDevice[]>(
      'GET',
      `/app/device/getDeviceByHid?hid=${encodeURIComponent(this.hid)}`,
    );

    const devices: NormalizedDevice[] = [];
    for (const device of response.data) {
      const deviceType = getDeviceType(device.model);
      if (deviceType === DEVICE_TYPE_GATEWAY) continue;

      const zoneNames = this.parsePortDescribe(device.portDescribe, device.portNumber);

      if (deviceType === DEVICE_TYPE_SENSOR) {
        devices.push(this.normalizeDevice(device, 0, device.name, false));
        if (device.subDevices) {
          for (const sub of device.subDevices) {
            devices.push(this.normalizeDevice(sub, sub.addr, sub.name || device.name, true, device.mid));
          }
        }
        continue;
      }

      devices.push(this.normalizeDevice(device, 0, device.name, false, undefined, zoneNames));
      if (device.subDevices) {
        for (const sub of device.subDevices) {
          const subZoneNames = this.parsePortDescribe(sub.portDescribe, sub.portNumber);
          devices.push(this.normalizeDevice(sub, sub.addr, sub.name || device.name, true, device.mid, subZoneNames));
        }
      }
    }

    return devices;
  }

  async getDeviceStatuses(deviceIds: string[]): Promise<Map<string, NormalizedDeviceStatus>> {
    const result = new Map<string, NormalizedDeviceStatus>();

    if (deviceIds.length === 1) {
      const status = await this.getDeviceStatus(deviceIds[0]!);
      result.set(status.MID, this.normalizeStatus(status));
      return result;
    }

    const response = await this.request<MultipleDeviceStatus[]>(
      'POST',
      '/app/device/multipleDeviceStatus',
      { MIDS: deviceIds },
    );

    for (const multiStatus of response.data) {
      const deviceStatus = this.convertMultipleDeviceStatus(multiStatus);
      result.set(multiStatus.mid, this.normalizeStatus(deviceStatus));
    }

    return result;
  }

  async turnZoneOn(deviceId: string, port: number, durationSeconds?: number): Promise<void> {
    const device = await this.findDevice(deviceId);
    if (!device) throw new Error(`Device ${deviceId} not found`);

    const userDeviceInfo = this.getUserDeviceInfo();
    const durationMinutes = durationSeconds ? Math.floor(durationSeconds / 60) : 0;
    const isSubDevice = device.isSubDevice;
    const addr = device.addr;

    if (isSubDevice) {
      const mode = durationMinutes > 0 ? CONTROL_MODE_MANUAL : CONTROL_MODE_NEXT;
      const param = durationMinutes > 0
        ? buildZoneOnWithDurationParam(port, durationMinutes)
        : buildZoneOnParam(port);
      await this.controlWorkModeDP({
        mid: deviceId,
        productKey: userDeviceInfo.productKey,
        deviceName: userDeviceInfo.deviceName,
        mode,
        addr,
        port: 0,
        param,
        dpCode: DP_CODE_IRRIGATION,
      });
    } else {
      await this.controlWorkMode({
        mid: deviceId,
        productKey: userDeviceInfo.productKey,
        deviceName: userDeviceInfo.deviceName,
        mode: CONTROL_MODE_NEXT,
        addr: 0,
        port,
        param: '',
        duration: durationMinutes,
      });
    }
  }

  async turnZoneOff(deviceId: string, port: number): Promise<void> {
    const device = await this.findDevice(deviceId);
    if (!device) throw new Error(`Device ${deviceId} not found`);

    const userDeviceInfo = this.getUserDeviceInfo();
    const isSubDevice = device.isSubDevice;
    const addr = device.addr;

    if (isSubDevice) {
      await this.controlWorkModeDP({
        mid: deviceId,
        productKey: userDeviceInfo.productKey,
        deviceName: userDeviceInfo.deviceName,
        mode: CONTROL_MODE_NEXT,
        addr,
        port: 0,
        param: STOP_ALL_PARAM,
        dpCode: DP_CODE_IRRIGATION,
      });
    } else {
      await this.controlWorkMode({
        mid: deviceId,
        productKey: userDeviceInfo.productKey,
        deviceName: userDeviceInfo.deviceName,
        mode: CONTROL_MODE_NEXT,
        addr: 0,
        port: 255,
        param: '',
        duration: 0,
      });
    }
  }

  private async findDevice(deviceId: string): Promise<NormalizedDevice | undefined> {
    const devices = await this.getDevices();
    return devices.find(d => d.id === deviceId);
  }

  private getUserDeviceInfo(): { deviceName: string; productKey: string } {
    return {
      deviceName: this.userDeviceName,
      productKey: this.userProductKey,
    };
  }

  private normalizeDevice(
    device: MainDevice | SubDevice,
    addr: number,
    name: string,
    isSubDevice: boolean,
    parentId?: string,
    zoneNames?: string[],
  ): NormalizedDevice {
    const portNumber = device.portNumber || 1;
    return {
      id: isSubDevice ? (device as SubDevice).sid : device.mid,
      name,
      model: device.model,
      productId: device.productKey ?? '',
      online: device.enabled !== 0,
      portNumber,
      portDescribe: zoneNames ?? this.parsePortDescribe(device.portDescribe, portNumber),
      deviceType: getDeviceType(device.model),
      isSubDevice,
      parentId,
      addr,
    };
  }

  private parsePortDescribe(portDescribe: string | undefined, portNumber: number): string[] {
    if (!portDescribe) {
      return Array.from({ length: portNumber }, (_, i) => `Zone ${i + 1}`);
    }
    const parts = portDescribe.split('|');
    return Array.from({ length: portNumber }, (_, i) => parts[i]?.trim() || `Zone ${i + 1}`);
  }

  private normalizeStatus(status: DeviceStatus): NormalizedDeviceStatus {
    const zones: NormalizedZoneStatus[] = [];
    const portNumber = 1;
    const state = status.state || '';
    const firstChar = state.charAt(0);
    const isOnline = firstChar ? parseInt(firstChar) > 0 : false;

    for (let port = 1; port <= portNumber; port++) {
      const portKey = `D${String(port).padStart(2, '0')}`;
      const portValue = (status[portKey] as string) || state;
      const portFirstChar = portValue ? portValue.charAt(0) : '0';
      zones.push({
        port,
        name: `Zone ${port}`,
        isOn: portFirstChar ? parseInt(portFirstChar) > 0 : false,
        remainingDuration: 0,
      });
    }

    return {
      deviceId: status.MID,
      online: isOnline,
      zones,
      moisture: null,
      temperature: null,
      battery: null,
    };
  }

  private convertMultipleDeviceStatus(multiStatus: MultipleDeviceStatus): DeviceStatus {
    const status: Record<string, unknown> = {
      MID: multiStatus.mid,
      iotId: multiStatus.iotId,
      propVer: multiStatus.propVer,
      state: '',
      connected: '1',
      softVer: '',
      recich: 1,
      updateTime: {},
      timeDiff: 0,
      onlineTimeStamp: 0,
    };

    for (const param of multiStatus.status) {
      status[param.id] = param.value;
      if (param.id === 'state' || param.id === 'State') {
        status['state'] = param.value;
      }
      if (param.id === 'connected' || param.id === 'Connected') {
        status['connected'] = param.value;
      }
    }

    return status as unknown as DeviceStatus;
  }

  private async getDeviceStatus(mid: string): Promise<DeviceStatus> {
    const response = await this.request<DeviceStatus>(
      'GET',
      `/app/device/getDeviceStatus?mid=${encodeURIComponent(mid)}`,
    );
    return response.data;
  }

  private async controlWorkMode(params: ControlWorkModeParams): Promise<ControlResponse> {
    const response = await this.request<ControlResponse>(
      'POST',
      '/app/device/controlWorkMode',
      params,
    );
    return response.data;
  }

  private async controlWorkModeDP(params: ControlWorkModeDPParams): Promise<ControlResponse> {
    const response = await this.request<ControlResponse>(
      'POST',
      '/app/device/controlWorkModeDP',
      params,
    );
    return response.data;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    requireAuth: boolean = true,
  ): Promise<BaseResponse<T>> {
    if (requireAuth) {
      await this.ensureAuthenticated();
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'lang': 'en',
      'version': API_VERSION,
      'appCode': APP_CODE,
      'sceneType': SCENE_TYPE,
    };

    if (requireAuth && this.token) {
      headers['auth'] = this.token;
    }

    if (this.hid) {
      headers['hid'] = this.hid;
    }

    const url = new URL(path, this.baseUrl);
    const urlStr = url.toString();

    const requestBody = body ? JSON.stringify(body) : undefined;

    this.log.debug('%s %s', method, urlStr);
    if (requestBody) {
      this.log.debug('Request body: %s', requestBody);
    }

    return new Promise((resolve, reject) => {
      const urlObj = new URL(urlStr);
      const options: https.RequestOptions = {
        hostname: urlObj.hostname,
        port: urlObj.port || 443,
        path: urlObj.pathname + urlObj.search,
        method,
        headers,
        rejectUnauthorized: false,
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data) as BaseResponse<T>;
            if (parsed.code !== 0) {
              const error = new Error(`API error ${parsed.code}: ${parsed.msg}`);
              (error as Error & { code: number }).code = parsed.code;
              reject(error);
              return;
            }
            this.log.debug('Response: %s', data.substring(0, 500));
            resolve(parsed);
          } catch (e) {
            reject(new Error(`Failed to parse API response: ${e}`));
          }
        });
      });

      req.on('error', (e) => {
        reject(new Error(`HTTP request failed: ${e.message}`));
      });

      req.setTimeout(20000, () => {
        req.destroy(new Error('Request timed out'));
      });

      if (requestBody) {
        req.write(requestBody);
      }
      req.end();
    });
  }
}

interface TokenResponse {
  token: string;
  refreshToken: string;
  tokenExpired: number;
}