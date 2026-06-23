// =============================================================================
// Shared constants — used by both the RainPoint Home (HomGar cloud) and
// RainPoint TY (Tuya) clients. Provider-agnostic only.
// =============================================================================

// Polling thresholds (platform-level; apply regardless of provider).
export const DEFAULT_POLL_INTERVAL = 30;
export const MIN_POLL_INTERVAL = 10;

// Device-type detection (model prefix -> device class). Both clients use this.
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