import type { Logger as HomebridgeLogger } from 'homebridge';

export type Provider = 'home' | 'ty';

export type Logger = HomebridgeLogger;

export interface RainPointClientConfig {
  email: string;
  password: string;
  region: string;
  countryCode?: string;
  /**
   * Optional directory for persisting the cloud session (sid/ecode/endpoint)
   * across homebridge restarts. When provided, the client loads any saved
   * session on construction and only re-logs in if the session is missing or
   * rejected by the server. Homebridge plugins typically pass User.storagePath().
   */
  storageDir?: string;
}

export interface NormalizedDevice {
  id: string;
  name: string;
  model: string;
  productId: string;
  online: boolean;
  portNumber: number;
  portDescribe: string[];
  deviceType: string;
  isSubDevice: boolean;
  parentId?: string;
  addr: number;
  /**
   * Per-zone switch (valve on/off) datapoint IDs. Index 0 = zone 1's switch DP,
   * index 1 = zone 2's, etc. The Tuya/RainPoint TY device exposes each valve as
   * a distinct DP (e.g. 104 for zone 1, 155 for zone 2 on a split controller).
   * When omitted, the legacy port-number DP scheme (DP 1, 2, ...) is assumed.
   */
  zoneSwitchDps?: number[];
}

export interface NormalizedZoneStatus {
  port: number;
  name: string;
  isOn: boolean;
  remainingDuration: number;
}

export interface NormalizedDeviceStatus {
  deviceId: string;
  online: boolean;
  zones: NormalizedZoneStatus[];
  moisture: number | null;
  temperature: number | null;
  battery: number | null;
}

export interface NormalizedHome {
  id: string;
  name: string;
}

export interface RainPointClient {
  login(): Promise<void>;
  ensureAuthenticated(): Promise<void>;
  getHomes(): Promise<NormalizedHome[]>;
  setHome(homeId: string): void;
  getDevices(): Promise<NormalizedDevice[]>;
  getDeviceStatuses(deviceIds: string[]): Promise<Map<string, NormalizedDeviceStatus>>;
  turnZoneOn(deviceId: string, port: number, durationSeconds?: number): Promise<void>;
  turnZoneOff(deviceId: string, port: number): Promise<void>;
}
