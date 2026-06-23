export const API_BASE_URL = 'https://region{areaCode}.homgarus.com:1443/';
export const API_PORT = 1443;
export const API_VERSION = '1.16.1065';
export const APP_CODE = '2';
export const SCENE_TYPE = '1';

export const AREA_CODE_CN = '0';
export const AREA_CODE_INTERNATIONAL = '3';

export const DEFAULT_POLL_INTERVAL = 30;
export const MIN_POLL_INTERVAL = 10;

export const WORK_FREE = 0;
export const WORK_ON = 1;
export const WORK_IRRIGATION = 1;
export const WORK_MIST = 2;
export const WORK_CYCLE = 3;
export const WORK_SOAK = 7;

export const CTRL_NONE = 0;
export const CTRL_LOCAL = 1;
export const CTRL_APP = 2;
export const CTRL_CTRL_CENTER = 3;
export const CTRL_PLAN = 4;
export const CTRL_PLATFORM = 5;
export const CTRL_VOICE = 6;

// controlWorkMode `mode` field values (verified against the battle-tested
// ha-rainpoint integration): 1 = open valve, 0 = close valve. The earlier
// NEXT/MANUAL scheme was a misread of the app capture.
export const CONTROL_MODE_CLOSE = 0;
export const CONTROL_MODE_OPEN = 1;

export const DP_TYPE_PARAM = 0;
export const DP_TYPE_STATUS = 1;
export const DP_TYPE_CONTROL = 2;
export const DP_TYPE_ATTRIBUTE = 3;

export const DP_CODE_IRRIGATION = 7;
export const DP_CODE_RF_POWER = 5;
export const DP_CODE_WATER_SUPPORT = 12;
export const DP_CODE_CHANNEL_ENABLE = 16;
export const DP_CODE_ZONE_INFO = 20;
export const DP_CODE_PLAN_INFO = 21;
export const DP_CODE_PLAN_CONFIG = 22;
export const DP_CODE_WARNINGS = 27;
export const DP_CODE_MODEL_CODE = 33;

export const DEVICE_TYPE_CONTROLLER = 'HCC';
export const DEVICE_TYPE_SENSOR = 'HCS';
export const DEVICE_TYPE_VALVE = 'HTV';
export const DEVICE_TYPE_GATEWAY = 'HWG';
export const DEVICE_TYPE_WATER_STATION = 'HWS';
export const DEVICE_TYPE_IRRIGATION = 'HIS';

export function getDeviceType(model: string): string {
  const prefix = model.replace(/[\d_]+.*/, '').toUpperCase();
  if (prefix.startsWith('HCC')) return DEVICE_TYPE_CONTROLLER;
  if (prefix.startsWith('HCS')) return DEVICE_TYPE_SENSOR;
  if (prefix.startsWith('HTV')) return DEVICE_TYPE_VALVE;
  if (prefix.startsWith('HWG')) return DEVICE_TYPE_GATEWAY;
  if (prefix.startsWith('HWS')) return DEVICE_TYPE_WATER_STATION;
  if (prefix.startsWith('HIS')) return DEVICE_TYPE_IRRIGATION;
  return prefix;
}

export function getBaseUrl(region: string): string {
  const areaCode = region === 'CN' ? AREA_CODE_CN : AREA_CODE_INTERNATIONAL;
  return API_BASE_URL.replace('{areaCode}', areaCode);
}