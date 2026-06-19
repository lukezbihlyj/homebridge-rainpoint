export const API_BASE_URL = 'https://region{areaCode}.homgarus.com:1443/';
export const API_PORT = 1443;
export const API_VERSION = '1.16.1057';
export const APP_CODE = '2';
export const SCENE_TYPE = '0';

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

export const CONTROL_MODE_NEXT = 0;
export const CONTROL_MODE_MANUAL = 1;
export const CONTROL_MODE_SMART = 2;
export const CONTROL_MODE_CYCLE = 3;

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

export const STOP_ALL_PARAM = '060F0000000000';

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

export function prefixParamZero(n: number, byteLength: number = 1, reverse: boolean = true): string {
  const hexLength = 2 * byteLength;
  let value = n;
  if (value < 0) {
    value += Math.pow(2, 8 * byteLength);
  }
  let result = (Array(hexLength).join('0') + value.toString(16).toUpperCase()).slice(-hexLength);
  if (reverse && byteLength > 1) {
    result = reverseParam(result);
  }
  return result;
}

export function reverseParam(hexString: string): string {
  if (hexString.length % 2 !== 0) return '';
  let result = '';
  for (let i = 0; i < hexString.length; i += 2) {
    result = hexString.substring(i, i + 2) + result;
  }
  return result;
}

export function buildZoneOnParam(zoneIndex: number): string {
  const zoneBitmask = 1 << (zoneIndex - 1);
  return '03' + prefixParamZero(zoneBitmask, 1) + '0000';
}

export function buildZoneOnWithDurationParam(zoneIndex: number, durationMinutes: number): string {
  const zoneBitmask = 1 << (zoneIndex - 1);
  return prefixParamZero(zoneBitmask, 1) + '00' + prefixParamZero(durationMinutes, 1);
}