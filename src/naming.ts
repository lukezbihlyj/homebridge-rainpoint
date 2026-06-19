import { NormalizedDevice } from './api/RainPointClientInterface';

/**
 * Per-zone display name for a device.
 *
 * Naming convention:
 *  - 1-valve device  -> "{deviceName}"             (flat) / "{deviceName}: Valve" (irrigation-system)
 *  - 2+ valve device -> "{deviceName}: {zoneLabel}"  where zoneLabel is the user's
 *                       portDescribe (e.g. "Left Valve") or falls back to "Valve N".
 *
 * `device.name` is always used as the prefix so multi-valve accessories sort
 * together and the source device is obvious from the name.
 */
export function zoneDisplayName(device: NormalizedDevice, port: number, flat: boolean): string {
  const label = device.portDescribe[port - 1] || `Valve ${port}`;
  if (device.portNumber <= 1) {
    return flat ? device.name : `${device.name}: Valve`;
  }
  return `${device.name}: ${label}`;
}