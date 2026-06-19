import { ParsedDpStatus } from './types';

export function hexToBytes(hex: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substring(i, i + 2), 16));
  }
  return bytes;
}

export function parseDpStatus(stateHex: string, hasDpIdPrefix: boolean = true): ParsedDpStatus[] {
  const bytes = hexToBytes(stateHex);
  const results: ParsedDpStatus[] = [];
  let offset = 0;

  while (offset < bytes.length) {
    let dpId = 0;

    if (hasDpIdPrefix) {
      dpId = bytes[offset];
      offset++;
    }

    if (offset >= bytes.length) break;

    const typeByte = bytes[offset];
    offset++;

    let typeCode: number;
    let typeLen: number;
    let typeValue: number[];

    if ((typeByte & 0x80) === 0) {
      typeCode = (typeByte >> 4) & 0x07;
      typeLen = 1;
      typeValue = [typeByte];
    } else {
      const typeBits = (typeByte >> 2) & 0x1F;
      const lengthBits = typeByte & 0x03;
      typeLen = lengthBits + 1;

      if (typeBits <= 30) {
        typeCode = typeBits + 8;
        const dataLen = lengthBits + 2;
        typeValue = Array.from(bytes.slice(offset, offset + dataLen));
        offset += dataLen;
      } else {
        if (offset >= bytes.length) break;
        const nextByte = bytes[offset] & 0xFF;
        offset++;
        typeCode = nextByte + 0x27;
        const dataLen = lengthBits + 2;
        typeValue = Array.from(bytes.slice(offset, offset + dataLen));
        offset += dataLen;
      }
    }

    results.push({ dpId, typeCode, typeLen, typeValue });
  }

  return results;
}

export function bytesToHex(bytes: number[]): string {
  return bytes.map(b => b.toString(16).toUpperCase().padStart(2, '0')).join('');
}

export function hexToSignedInt(hex: string, bits: number = 8): number {
  let value = parseInt(hex, 16);
  if (value >= Math.pow(2, bits - 1)) {
    value -= Math.pow(2, bits);
  }
  return value;
}

export function hexToUnsignedInt(hex: string): number {
  return parseInt(hex, 16);
}

export function findDpByCode(parsed: ParsedDpStatus[], dpCode: number): ParsedDpStatus | undefined {
  return parsed.find(dp => dp.dpId === dpCode);
}

export function getDpIntValue(dp: ParsedDpStatus): number {
  if (dp.typeValue.length === 0) return 0;
  if (dp.typeValue.length === 1) return dp.typeValue[0];
  return dp.typeValue.reduce((acc, val, idx) => {
    return acc | (val << (8 * idx));
  }, 0);
}

export function parseWorkMode(dpValue: number): { workMode: number; controlMode: number } {
  return {
    workMode: dpValue & 0x0F,
    controlMode: (dpValue >> 4) & 0x0F,
  };
}

export function isValveOpen(dpValue: number): number {
  return 5 * (31 & dpValue);
}