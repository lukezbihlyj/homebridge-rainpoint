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
  /**
   * Cloud deviceName (MAC-based identifier) used in control + status requests.
   * For sub-devices this is the sub-device's own deviceName; control requests
   * must use the parent hub's deviceName, resolved via parentId at call time.
   */
  deviceName: string;
  online: boolean;
  portNumber: number;
  portDescribe: string[];
  deviceType: string;
  isSubDevice: boolean;
  parentId?: string;
  addr: number;
  /**
   * Mesh node id for TY sub-devices (from deviceTopo.nodeId). Real-time DP
   * pushes arrive on the GATEWAY's MQTT topic `smart/mb/in/{gwId}` and
   * identify the sub-device via the `cid` field, which equals this nodeId.
   * Used to route MQTT DP updates to the correct sub-device accessory.
   */
  nodeId?: string;
  /**
   * Per-zone switch (valve on/off) datapoint IDs. Index 0 = zone 1's switch DP,
   * index 1 = zone 2's, etc. The Tuya/RainPoint TY device exposes each valve as
   * a distinct DP (e.g. 104 for zone 1, 155 for zone 2 on a split controller).
   * When omitted, the legacy port-number DP scheme (DP 1, 2, ...) is assumed.
   */
  zoneSwitchDps?: number[];
  /**
   * Per-zone resolved DP ids (from thing.m.product.thing.model). Each zone has
   * the WorkStatus (run flag, enum "1"=running), ManualTimer (countdown minutes,
   * writable 0-60), ManualSwitch (bool on/off), and RemainTime (remaining min,
   * read-only) DPs. Resolved by code-name per zone, NOT by offset — the +51
   * offset heuristic is wrong for multi-zone products (zone 2's WorkStatus is
   * 153, not switchDp+2). When absent, fall back to zoneSwitchDps offsets.
   */
  zoneDps?: NormalizedZoneDps[];
}

export interface NormalizedZoneDps {
  /** Run-state enum DP (rw, code WorkStatus/LeftWorkStatus/RightWorkStatus). */
  workStatus: number;
  /** Writable countdown timer DP (rw value, minutes, 0-60). */
  manualTimer: number;
  /** Writable on/off switch DP (rw bool). */
  manualSwitch: number;
  /** Read-only remaining-time DP (ro value, minutes). */
  remainTime: number;
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
