/**
 * RainPoint Home (HomGar cloud) payload decoders.
 *
 * Ported from the battle-tested funkadelic/ha-rainpoint integration
 * (custom_components/rainpoint/api/{decoders,utils,validators}.py).
 *
 * Device status `value` strings come in two encodings:
 *   - Hex TLV:  "10#<hex>" or "11#<hex>"  -> a flat [dpId][type][value...] stream
 *   - ASCII:    "1,-84,1;0,149,0,0,0,0|0,6,0,0,0,0" (valves)
 *               "1,-73,1;694,70,G=292478"          (moisture_full)
 *               "1,0,1;707(...),42(...),P=9709(...)" (display hub)
 *
 * The type byte determines value width; 0xAD values are little-endian, all
 * others big-endian.
 *
 * Confirmed valve DP map (from live payload captures in ha-rainpoint):
 *   0x18        hub online state   (type 0xDC, value 0x01 = online)
 *   0x18 + N    zone N open state  (type 0xD8, value LSB = open)
 *   0x24 + N    zone N remaining   (type 0xAD, 2-byte little-endian SECONDS)
 */

const TYPE_WIDTHS: Record<number, number> = {
  0xD8: 1, // zone state
  0xDC: 1, // hub state
  0xAD: 2, // zone duration (seconds, little-endian)
  0x20: 2, // timer/schedule config
  0xE1: 2,
  0xB7: 4, // schedule/timer extended
  0x9F: 4, // schedule/timer extended
  0xC4: 1,
  0xC5: 1,
  0xC6: 1,
};

// Battery status code -> percent. Captured from ha-rainpoint validators.py.
const BATTERY_MAP: Record<number, number> = {
  0x0FFF: 100, 0x0FFE: 90, 0x0FFD: 80, 0x0FFC: 70, 0x0FFB: 60,
  0x0FFA: 50, 0x0FF9: 40, 0x0FF8: 30, 0x0FF7: 20, 0x0FF6: 10,
};

const HUB_STATE_DP = 0x18;
const ZONE_DURATION_DP_BASE = 0x24;
const MAX_ZONES = 8;

export interface DecodedValveZone {
  open: boolean;
  durationSeconds: number;
}

export interface DecodedValve {
  hubOnline: boolean | null;
  zones: Map<number, DecodedValveZone>;
}

export interface DecodedSensor {
  moisture: number | null;
  temperature: number | null;
  battery: number | null;
}

interface TlvEntry {
  type: number;
  value: number;
}

function hexToBytes(hex: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    out.push(parseInt(hex.substring(i, i + 2), 16));
  }
  return out;
}

function parsePayloadBytes(raw: string): number[] {
  const idx = raw.indexOf('#');
  if (idx < 0) {
    throw new Error(`Payload missing '#' separator: ${raw}`);
  }
  return hexToBytes(raw.substring(idx + 1));
}

/**
 * Walk a flat [dpId][type][value...] byte stream into {dpId: {type, value}}.
 * Unknown type bytes advance one byte for re-alignment (matches ha-rainpoint's
 * _scan_htv213_dp_map). 0xAD values are little-endian; all others big-endian.
 */
function parseDpMap(bytes: number[]): Map<number, TlvEntry> {
  const map = new Map<number, TlvEntry>();
  let i = 0;
  while (i < bytes.length - 1) {
    const dpId = bytes[i]!;
    const typeByte = bytes[i + 1]!;
    const width = TYPE_WIDTHS[typeByte];
    if (width === undefined) {
      i += 1;
      continue;
    }
    if (i + 2 + width > bytes.length) break;
    let value = 0;
    if (typeByte === 0xAD) {
      for (let k = 0; k < width; k++) {
        value |= bytes[i + 2 + k]! << (8 * k);
      }
    } else {
      for (let k = 0; k < width; k++) {
        value = (value << 8) | bytes[i + 2 + k]!;
      }
    }
    map.set(dpId, { type: typeByte, value });
    i += 2 + width;
  }
  return map;
}

function le16(b: number[], offset: number): number {
  return (b[offset]! | (b[offset + 1]! << 8)) & 0xFFFF;
}

function signed8(b: number[], offset: number): number {
  const v = b[offset]!;
  return v < 128 ? v : v - 256;
}

// Unused for accessory state but kept for completeness of moisture_full decode.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function extractRssi(b: number[]): number | null {
  return b.length > 1 ? signed8(b, 1) : null;
}

function statusCodeAt(b: number[], off: number, off2: number): number {
  return (b[off]! | (b[off2]! << 8)) & 0xFFFF;
}

function batteryFromStatus(code: number): number | null {
  if (code in BATTERY_MAP) return BATTERY_MAP[code]!;
  return null;
}

function isHexPayload(raw: string): boolean {
  return raw.startsWith('10#') || raw.startsWith('11#');
}

function isAsciiPayload(raw: string): boolean {
  return raw.includes(',') && (raw.includes(';') || raw.includes('|') || raw.includes('='));
}

/** Decode a valve payload (hex TLV or ASCII) into hub online + per-zone state. */
export function decodeValve(raw: string): DecodedValve {
  try {
    if (isHexPayload(raw)) {
      const bytes = parsePayloadBytes(raw);
      const dpMap = parseDpMap(bytes);
      const hubEntry = dpMap.get(HUB_STATE_DP);
      let hubOnline: boolean | null = null;
      if (hubEntry && hubEntry.type === 0xDC) {
        hubOnline = hubEntry.value === 0x01;
      }
      const zones = new Map<number, DecodedValveZone>();
      for (let n = 1; n <= MAX_ZONES; n++) {
        const stateEntry = dpMap.get(HUB_STATE_DP + n);
        if (!stateEntry || stateEntry.type !== 0xD8) continue;
        const open = (stateEntry.value & 0x01) === 0x01;
        let durationSeconds = 0;
        const durEntry = dpMap.get(ZONE_DURATION_DP_BASE + n);
        if (durEntry && durEntry.type === 0xAD) {
          durationSeconds = durEntry.value;
        }
        zones.set(n, { open, durationSeconds });
      }
      return { hubOnline, zones };
    }
    if (isAsciiPayload(raw)) {
      return decodeValveAscii(raw);
    }
  } catch (e) {
    // fall through to empty
  }
  return { hubOnline: null, zones: new Map() };
}

/**
 * Decode HTV213FRF/HTV245FRF ASCII valve payload.
 * Format: [flags],[rssi],[flags];[zone1]|[zone2]
 * Each zone: [id?],[state],[duration],[...]
 */
function decodeValveAscii(raw: string): DecodedValve {
  const zones = new Map<number, DecodedValveZone>();
  const semi = raw.indexOf(';');
  if (semi < 0) return { hubOnline: true, zones };
  const zonePart = raw.substring(semi + 1);
  let n = 1;
  for (const section of zonePart.split('|')) {
    const parts = section.split(',');
    if (parts.length < 3) continue;
    const state = parseInt(parts[1]!, 10);
    const duration = parseInt(parts[2]!, 10);
    if (Number.isNaN(state)) continue;
    zones.set(n, { open: state !== 0, durationSeconds: Number.isNaN(duration) ? 0 : duration });
    n++;
  }
  return { hubOnline: true, zones };
}

/** HCS026FRF / HCS005FRF / HCS003FRF — moisture only. */
function decodeMoistureSimple(raw: string): DecodedSensor {
  const b = parsePayloadBytes(raw);
  if (b.length < 9) return { moisture: null, temperature: null, battery: null };
  const moisture = b[6]!;
  const code = statusCodeAt(b, 7, 8);
  return { moisture, temperature: null, battery: batteryFromStatus(code) };
}

/** HCS021FRF / HCS024FRF-V1 / HCS666* / HCS999* — moisture + temp + lux. */
function decodeMoistureFull(raw: string): DecodedSensor {
  const b = parsePayloadBytes(raw);
  if (b.length < 16) return decodeMoistureSimple(raw);
  // b5 = 0x85 tag, b6:7 = temp F*10 LE, b8 = 0x88 tag, b9 = moisture,
  // b10 = 0xC6 tag, b11:12 = lux*10 LE, b14:15 = battery status.
  const tempRawF10 = le16(b, 6);
  const tempC = (tempRawF10 / 10.0 - 32.0) * 5.0 / 9.0;
  const moisture = b[9]!;
  const code = statusCodeAt(b, 14, 15);
  return { moisture, temperature: Math.round(tempC * 10) / 10, battery: batteryFromStatus(code) };
}

/** HCS012ARF rain gauge — only battery is useful for our accessories. */
function decodeRain(raw: string): DecodedSensor {
  const b = parsePayloadBytes(raw);
  if (b.length < 24) return { moisture: null, temperature: null, battery: null };
  const code = statusCodeAt(b, 22, 23);
  return { moisture: null, temperature: null, battery: batteryFromStatus(code) };
}

/**
 * HWS019WRF-V2 display hub CSV payload.
 * Format: flags;current(min/max/count),current(...),P=pressure(...)
 * First positional reading = temperature (F*10), second = humidity %.
 */
function decodeDisplayHub(raw: string): DecodedSensor {
  const semi = raw.indexOf(';');
  if (semi < 0) return { moisture: null, temperature: null, battery: null };
  let temperature: number | null = null;
  let humidity: number | null = null;
  for (const item of raw.substring(semi + 1).split(',')) {
    const token = item.trim();
    if (!token) continue;
    const head = token.split('(')[0]!.trim();
    if (token.includes('=')) continue; // keyed reading like P=...
    if (temperature === null) {
      const tempF10 = parseInt(head, 10);
      if (!Number.isNaN(tempF10)) {
        temperature = Math.round(((tempF10 / 10.0 - 32.0) * 5.0 / 9.0) * 10) / 10;
      }
    } else if (humidity === null) {
      const h = parseInt(head, 10);
      if (!Number.isNaN(h)) humidity = h;
    }
  }
  return { moisture: humidity, temperature, battery: null };
}

const MOISTURE_SIMPLE_MODELS = new Set([
  'HCS026FRF', 'HCS005FRF', 'HCS003FRF',
]);

const MOISTURE_FULL_MODELS = new Set([
  'HCS021FRF', 'HCS024FRF-V1', 'HCS666FRF', 'HCS666RFR-P',
  'HCS999FRF', 'HCS999FRF-P', 'HCS666FRF-X', 'HCS044FRF',
]);

/** Decode a sensor payload by model. Returns nulls when the model is unsupported. */
export function decodeSensor(raw: string, model: string): DecodedSensor {
  try {
    if (model === 'HCS012ARF') return decodeRain(raw);
    if (MOISTURE_SIMPLE_MODELS.has(model)) return decodeMoistureSimple(raw);
    if (MOISTURE_FULL_MODELS.has(model)) return decodeMoistureFull(raw);
    if (model.startsWith('HWS')) return decodeDisplayHub(raw);
    // Fallback: try moisture_full layout, then simple.
    if (isHexPayload(raw)) {
      const full = decodeMoistureFull(raw);
      if (full.moisture !== null || full.temperature !== null || full.battery !== null) {
        return full;
      }
      return decodeMoistureSimple(raw);
    }
    if (isAsciiPayload(raw) && model.startsWith('HCS')) {
      return decodeMoistureFullAscii(raw);
    }
  } catch (e) {
    // fall through
  }
  return { moisture: null, temperature: null, battery: null };
}

function decodeMoistureFullAscii(raw: string): DecodedSensor {
  const semi = raw.indexOf(';');
  if (semi < 0) return { moisture: null, temperature: null, battery: null };
  const parts = raw.substring(semi + 1).split(',');
  if (parts.length < 2) return { moisture: null, temperature: null, battery: null };
  const tempRawF10 = parseInt(parts[0]!, 10);
  const moisture = parseInt(parts[1]!, 10);
  const tempC = Number.isNaN(tempRawF10) ? null
    : Math.round(((tempRawF10 / 10.0 - 32.0) * 5.0 / 9.0) * 10) / 10;
  return {
    moisture: Number.isNaN(moisture) ? null : moisture,
    temperature: tempC,
    battery: null,
  };
}