import https from 'https';
import crypto from 'crypto';

import {
  BaseResponse,
  LoginInfo,
  Home,
  MainDevice,
  SubDevice,
  DeviceStatus,
  MultipleDeviceStatus,
  ControlWorkModeParams,
} from './types';

import {
  getBaseUrl,
  getDeviceType,
  API_VERSION,
  APP_CODE,
  SCENE_TYPE,
  DEVICE_TYPE_GATEWAY,
  DEVICE_TYPE_SENSOR,
  DEVICE_TYPE_VALVE,
  DEVICE_TYPE_CONTROLLER,
  DEVICE_TYPE_IRRIGATION,
  CONTROL_MODE_OPEN,
  CONTROL_MODE_CLOSE,
} from './constants';

import { decodeValve, decodeSensor } from './home-decoder';

import {
  RainPointClient,
  RainPointClientConfig,
  Logger,
  NormalizedDevice,
  NormalizedDeviceStatus,
  NormalizedZoneStatus,
} from './RainPointClientInterface';


function md5(input: string): string {
  return crypto.createHash('md5').update(input, 'utf8').digest('hex');
}

interface HubStatus {
  online: boolean;
  /** sub-device addr -> raw payload string (e.g. "10#..." / "11#..." / ASCII). */
  byAddr: Map<number, string>;
  /** The hub/main-device's own `state` payload (addr 0). */
  state: string | null;
}

interface HubRequestEntry {
  mid: string;
  deviceName: string;
  productKey: string;
}

export class RainPointHomeClient implements RainPointClient {
  private token: string = '';
  private refreshTokenValue: string = '';
  private tokenExpired: number = 0;
  private hid: string = '';
  private readonly baseUrl: string;

  /**
   * Cache of normalized devices from the last getDevices() call. Required so
   * control + status requests can resolve each accessory id to its hub mid,
   * the hub's deviceName/productKey (needed in every controlWorkMode +
   * multipleDeviceStatus request body), and the sub-device addr.
   */
  private deviceCache: Map<string, NormalizedDevice> = new Map();

  constructor(
    private config: RainPointClientConfig,
    private log: Logger,
  ) {
    this.baseUrl = getBaseUrl(config.region);
  }

  async login(): Promise<void> {
    // areaCode is the phone dial code (e.g. "1" US, "86" CN), sourced from the
    // configured countryCode. Matches ha-rainpoint's country_codes mapping.
    const areaCode = this.config.countryCode || '1';
    const hashedPassword = md5(this.config.password);
    // Deterministic deviceId per (email, areaCode) — same as ha-rainpoint, so
    // re-logins don't rotate the server-side session identity.
    const deviceId = md5(`${this.config.email}${areaCode}`);

    const response = await this.request<LoginInfo>(
      'POST',
      '/auth/basic/app/login',
      {
        areaCode,
        phoneOrEmail: this.config.email,
        password: hashedPassword,
        deviceId,
      },
      false,
    );

    this.token = response.data.token;
    this.refreshTokenValue = response.data.refreshToken;
    // tokenExpired is a relative duration in SECONDS; combine with the server
    // `ts` (ms) to get an absolute expiry. Comparing Date.now() against the
    // raw seconds value (the old behavior) always evaluates true and forced a
    // refresh before every request.
    this.tokenExpired = response.ts + response.data.tokenExpired * 1000;

    this.log.info('Logged in to RainPoint Home API as %s', this.config.email);
  }

  async ensureAuthenticated(): Promise<void> {
    // Refresh 5 minutes before expiry (matches ha-rainpoint).
    if (Date.now() >= this.tokenExpired - 5 * 60 * 1000) {
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
      this.tokenExpired = response.ts + response.data.tokenExpired * 1000;
      this.log.debug('Refreshed RainPoint Home access token');
    } catch (error) {
      this.log.error('Failed to refresh token, re-authenticating...');
      await this.login();
    }
  }

  setHome(homeId: string): void {
    this.hid = homeId;
  }

  async getHomes(): Promise<{ id: string; name: string }[]> {
    const response = await this.request<Home[]>('GET', '/app/member/appHome/list');
    return response.data.map(h => ({ id: h.hid, name: h.homeName }));
  }

  async getDevices(): Promise<NormalizedDevice[]> {
    const response = await this.request<MainDevice[]>(
      'GET',
      `/app/device/getDeviceByHid?hid=${encodeURIComponent(this.hid)}`,
    );

    const devices: NormalizedDevice[] = [];
    this.deviceCache.clear();

    for (const device of response.data) {
      const deviceType = getDeviceType(device.model);
      if (deviceType === DEVICE_TYPE_GATEWAY) continue;

      const zoneNames = this.parsePortDescribe(device.portDescribe, device.portNumber);

      if (deviceType === DEVICE_TYPE_SENSOR) {
        const mainNorm = this.normalizeDevice(device, 0, device.name, false);
        devices.push(mainNorm);
        this.deviceCache.set(mainNorm.id, mainNorm);
        if (device.subDevices) {
          for (const sub of device.subDevices) {
            const subNorm = this.normalizeDevice(sub, sub.addr, sub.name || device.name, true, device.mid);
            devices.push(subNorm);
            this.deviceCache.set(subNorm.id, subNorm);
          }
        }
        continue;
      }

      const mainNorm = this.normalizeDevice(device, 0, device.name, false, undefined, zoneNames);
      devices.push(mainNorm);
      this.deviceCache.set(mainNorm.id, mainNorm);
      if (device.subDevices) {
        for (const sub of device.subDevices) {
          const subZoneNames = this.parsePortDescribe(sub.portDescribe, sub.portNumber);
          const subNorm = this.normalizeDevice(sub, sub.addr, sub.name || device.name, true, device.mid, subZoneNames);
          devices.push(subNorm);
          this.deviceCache.set(subNorm.id, subNorm);
        }
      }
    }

    return devices;
  }

  async getDeviceStatuses(deviceIds: string[]): Promise<Map<string, NormalizedDeviceStatus>> {
    const result = new Map<string, NormalizedDeviceStatus>();
    if (deviceIds.length === 0) return result;

    // Ensure the device cache is populated (control + status resolution depend
    // on knowing each id's hub, addr, deviceName and productKey).
    if (this.deviceCache.size === 0) {
      await this.getDevices();
    }

    // Resolve the unique set of hub mids to query. A sub-device's status is
    // delivered inside its hub's status response (keyed by addr), so we only
    // ever query hubs — never sub-device sids directly.
    const hubEntries = new Map<string, HubRequestEntry>();
    for (const id of deviceIds) {
      const dev = this.deviceCache.get(id);
      const hubId = dev?.parentId ?? id;
      if (hubEntries.has(hubId)) continue;
      const hub = this.deviceCache.get(hubId);
      hubEntries.set(hubId, {
        mid: hubId,
        deviceName: hub?.deviceName ?? '',
        productKey: hub?.productId ?? '',
      });
    }

    const hubStatuses = await this.fetchHubStatuses([...hubEntries.values()]);

    for (const id of deviceIds) {
      const dev = this.deviceCache.get(id);
      if (!dev) {
        result.set(id, this.emptyStatus(id, false));
        continue;
      }
      const hubId = dev.parentId ?? id;
      const hs = hubStatuses.get(hubId);
      // Sub-devices read their payload from the hub's byAddr map (addr);
      // main devices read the hub's own `state` payload.
      const payload = dev.isSubDevice
        ? (hs?.byAddr.get(dev.addr) ?? null)
        : (hs?.state ?? null);
      const fallbackOnline = hs?.online ?? false;
      result.set(id, this.decodeDeviceStatus(id, dev, payload, fallbackOnline));
    }

    return result;
  }

  async turnZoneOn(deviceId: string, port: number, durationSeconds?: number): Promise<void> {
    const { hubId, hub, addr } = this.resolveControlTarget(deviceId);
    await this.controlWorkMode({
      mid: hubId,
      addr,
      deviceName: hub.deviceName,
      productKey: hub.productId,
      port,
      mode: CONTROL_MODE_OPEN,
      duration: durationSeconds ?? 0,
    });
  }

  async turnZoneOff(deviceId: string, port: number): Promise<void> {
    const { hubId, hub, addr } = this.resolveControlTarget(deviceId);
    await this.controlWorkMode({
      mid: hubId,
      addr,
      deviceName: hub.deviceName,
      productKey: hub.productId,
      port,
      mode: CONTROL_MODE_CLOSE,
      duration: 0,
    });
  }

  /**
   * Resolve a device id (main or sub) to the controlWorkMode target triple:
   * the hub mid + hub record (for deviceName/productKey) + the addr to send.
   * Sub-devices address their own addr; main devices address addr 0.
   */
  private resolveControlTarget(deviceId: string): {
    hubId: string;
    hub: NormalizedDevice;
    addr: number;
  } {
    const dev = this.deviceCache.get(deviceId);
    if (!dev) throw new Error(`Device ${deviceId} not found`);
    const hubId = dev.parentId ?? deviceId;
    const hub = this.deviceCache.get(hubId);
    if (!hub) throw new Error(`Hub ${hubId} not found for device ${deviceId}`);
    const addr = dev.isSubDevice ? dev.addr : 0;
    return { hubId, hub, addr };
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
      deviceName: device.deviceName ?? '',
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

  private emptyStatus(deviceId: string, online: boolean): NormalizedDeviceStatus {
    return {
      deviceId,
      online,
      zones: [],
      moisture: null,
      temperature: null,
      battery: null,
    };
  }

  /**
   * Decode a raw payload string into a NormalizedDeviceStatus, routing by
   * device type/model. Valve-class devices yield zones; sensor-class devices
   * yield moisture/temperature/battery.
   */
  private decodeDeviceStatus(
    deviceId: string,
    dev: NormalizedDevice,
    payload: string | null,
    fallbackOnline: boolean,
  ): NormalizedDeviceStatus {
    if (!payload) {
      return this.emptyStatus(deviceId, fallbackOnline);
    }

    const deviceType = dev.deviceType;
    if (
      deviceType === DEVICE_TYPE_VALVE
      || deviceType === DEVICE_TYPE_CONTROLLER
      || deviceType === DEVICE_TYPE_IRRIGATION
    ) {
      const decoded = decodeValve(payload);
      const zones: NormalizedZoneStatus[] = [];
      for (let port = 1; port <= dev.portNumber; port++) {
        const z = decoded.zones.get(port);
        zones.push({
          port,
          name: dev.portDescribe[port - 1] ?? `Zone ${port}`,
          isOn: z?.open ?? false,
          remainingDuration: z?.durationSeconds ?? 0,
        });
      }
      return {
        deviceId,
        online: decoded.hubOnline ?? fallbackOnline,
        zones,
        moisture: null,
        temperature: null,
        battery: null,
      };
    }

    if (deviceType === DEVICE_TYPE_SENSOR || deviceType.startsWith('HWS')) {
      const decoded = decodeSensor(payload, dev.model);
      return {
        deviceId,
        online: true,
        zones: [],
        moisture: decoded.moisture,
        temperature: decoded.temperature,
        battery: decoded.battery,
      };
    }

    return this.emptyStatus(deviceId, fallbackOnline);
  }

  /**
   * Fetch status for a set of hubs. Uses multipleDeviceStatus for >1 hub,
   * single getDeviceStatus for 1. The multipleDeviceStatus request body is
   * {"devices":[{"deviceName","mid","productKey"},...]} — NOT {"MIDS":[...]}.
   */
  private async fetchHubStatuses(hubs: HubRequestEntry[]): Promise<Map<string, HubStatus>> {
    const result = new Map<string, HubStatus>();
    if (hubs.length === 0) return result;

    if (hubs.length === 1) {
      const data = await this.getDeviceStatus(hubs[0]!.mid);
      result.set(hubs[0]!.mid, this.extractSingleHubStatus(data));
      return result;
    }

    const response = await this.request<MultipleDeviceStatus[]>(
      'POST',
      '/app/device/multipleDeviceStatus',
      { devices: hubs },
    );

    for (const multi of response.data) {
      const byAddr = new Map<number, string>();
      let state: string | null = null;
      for (const param of multi.status) {
        const id = param.id;
        if (id === 'state' || id === 'State') {
          state = param.value;
          continue;
        }
        if (id.startsWith('D')) {
          const addr = parseInt(id.substring(1), 10);
          if (!Number.isNaN(addr) && param.value) {
            byAddr.set(addr, param.value);
          }
        }
      }
      result.set(multi.mid, {
        online: byAddr.size > 0 || state !== null,
        byAddr,
        state,
      });
    }

    return result;
  }

  private extractSingleHubStatus(data: DeviceStatus): HubStatus {
    const byAddr = new Map<number, string>();
    const state = data.state || null;
    // Single getDeviceStatus returns per-sub-device payloads as D01..D41
    // (zero-padded). Also tolerate non-padded D1.. keys.
    for (let addr = 1; addr <= 41; addr++) {
      const padded = `D${String(addr).padStart(2, '0')}`;
      const bare = `D${addr}`;
      const val = (data[padded] as string) ?? (data[bare] as string);
      if (typeof val === 'string' && val) {
        byAddr.set(addr, val);
      }
    }
    const connected = data.connected;
    const online = (typeof connected === 'string' ? connected !== '0' : true) || byAddr.size > 0;
    return { online, byAddr, state };
  }

  private async getDeviceStatus(mid: string): Promise<DeviceStatus> {
    const response = await this.request<DeviceStatus>(
      'GET',
      `/app/device/getDeviceStatus?mid=${encodeURIComponent(mid)}`,
    );
    return response.data;
  }

  private async controlWorkMode(params: ControlWorkModeParams): Promise<void> {
    try {
      await this.request('POST', '/app/device/controlWorkMode', params);
    } catch (error) {
      // Code 4 = device already in the requested state (idempotent). The
      // battle-tested integration treats this as success, not an error.
      const code = (error as Error & { code?: number }).code;
      if (code === 4) {
        this.log.debug('controlWorkMode: device already in requested state (code 4)');
        return;
      }
      throw error;
    }
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

    // Auth headers match ha-rainpoint: auth, lang, appCode, version, sceneType.
    // No `hid` header is sent (hid is passed as a query param where needed).
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