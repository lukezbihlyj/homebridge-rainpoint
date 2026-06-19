import https from 'https';
import crypto from 'crypto';
import { URL } from 'url';
import { v4 as uuidv4 } from 'uuid';

import {
  RainPointClient,
  RainPointClientConfig,
  Logger,
  NormalizedDevice,
  NormalizedDeviceStatus,
  NormalizedHome,
  NormalizedZoneStatus,
} from './RainPointClientInterface';
import {
  DEVICE_TYPE_GATEWAY,
  DEVICE_TYPE_VALVE,
  DEVICE_TYPE_SENSOR,
  DEVICE_TYPE_IRRIGATION,
} from './constants';

const APP_KEY = 'u9hs9dxd7cpcnj5ewcak';
const APP_SECRET = '5r4deyaxxdktnd4gxtn3vuatuvvgeprm';
const TTID = `sdk_international@${APP_KEY}`;
const CH_KEY = '03048afb';

// ET_VERSION is hardcoded "3" in ThingApiParams.smali (iput-object "3" -> ET_VERSION).
// initUrlParams() puts et=ET_VERSION into URL params, and when et=="3" also sets cp=gzip.
const API_ET_VERSION = '3';

// Per-API version strings extracted from the decompiled APK call sites
// (ApiParams.<init>(apiName, version) in pqdbppq.smali / dqdpbbd.smali / qqddbpb.smali /
//  FamilyExtraBusiness.smali). The Tuya gateway validates the (a, v) pair server-side
// and returns API_OR_API_VERSION_WRONG if they don't match its registered schema.
const API_VERSIONS: Record<string, string> = {
  // The app uses username.token.get (v2.0) with postData {countryCode, username, isUid},
  // NOT email.token.create. Verified via Frida capture6: the live app's token request
  // sends field "username" (not "email") and uses API thing.m.user.username.token.get.
  // Using the wrong endpoint returns a publicKey that the login server rejects with
  // USER_PASSWD_WRONG because the passwd was RSA-encrypted with the wrong key.
  'thing.m.user.username.token.get': '2.0',
  'thing.m.user.email.password.login': '3.0',
  // location.extend.list (v1.0) returns an object {<homeId>: {defaultHome:"0"}}, NOT an
  // array. Verified via the live app's response: {"result":{"157747002":{"defaultHome":"0"}}}.
  // The app parses it as a HashMap (FamilyExtraBusiness.smali asyncHashMap).
  'thing.m.location.extend.list': '1.0',
  // m.life.location.get (v3.4) fetches a single home's details by gid. Returns
  // HomeResponseBean with name + rooms + devices. Used to resolve home names.
  'm.life.location.get': '3.4',
  'thing.m.my.group.device.list': '2.1',
  'thing.m.device.dp.get': '1.0',
  'thing.m.device.dp.publish': '1.0',
};

// HMAC key format confirmed via Frida memory scan of libthing_security.so:
//   PACKAGE_NAME + "_" + CERT_SHA256_COLON + "_" + BMP_SECRET_ASCII + "_" + APP_SECRET
// Discovered by dumping the native lib's writable memory after initJNI and testing each
// printable run against a captured (signString, signature) pair. The earlier guess
// (CERT_SHA256_PLAIN + CERT_COLON + BMP_HEX + APP_SECRET) was wrong on two counts:
//   - first segment is the PACKAGE NAME "com.baldr.rainpoint", NOT the plain-hex cert
//   - BMP secret is the raw ASCII string, NOT hex-encoded bytes
const PACKAGE_NAME = 'com.baldr.rainpoint';
const CERT_SHA256_COLON = '2F:0B:FA:2B:F9:48:5B:D4:AC:29:11:EB:CE:32:D4:60:38:65:FE:9B:38:47:5F:AF:DF:E0:2C:D6:02:E3:93:B6';
const BMP_SECRET_ASCII = 'sv3cc3v445yqkggja8aexmjdgeqygsvv';

const HMAC_KEY = `${PACKAGE_NAME}_${CERT_SHA256_COLON}_${BMP_SECRET_ASCII}_${APP_SECRET}`;

const REGION_ENDPOINTS: Record<string, string> = {
  EU: 'https://a1-eu.baldrgroup.net/api.json',
  AZ: 'https://a1-us.baldrgroup.net/api.json',
  IN: 'https://a1-in.baldrgroup.net/api.json',
  RU: 'https://a1.iot334.com/api.json',
  US: 'https://a1-us.baldrgroup.net/api.json',
};

function md5(data: string): string {
  return crypto.createHash('md5').update(data, 'utf8').digest('hex');
}

function mobileHash(data: string): string {
  const pre = md5(data);
  return pre.slice(8, 16) + pre.slice(0, 8) + pre.slice(24, 32) + pre.slice(16, 24);
}

/**
 * Faithful port of ThingApiParams.checkAPIName() (smali line 497-580).
 *
 * If the apiName starts with "thing", the SDK prepends "@xx2@" and then runs
 * replaceAll("@xx2@thing", "smartlife"). Net effect: the "thing" prefix is
 * rewritten to "smartlife". Non-thing names pass through unchanged.
 *
 * The rewritten name is what the Tuya cloud gateway receives in the `a` field
 * and what participates in the HMAC sign string. The per-API version lookup
 * still uses the ORIGINAL thing.m.* name (apiVersion is set in the constructor
 * before checkAPIName runs).
 */
function rewriteApiName(action: string): string {
  if (action.startsWith('thing')) {
    return '@xx2@' + action;
  }
  return action;
}

function finalizeApiName(action: string): string {
  return rewriteApiName(action).replaceAll('@xx2@thing', 'smartlife');
}

function generateDeviceId(): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let id = '';
  for (let i = 0; i < 44; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return id;
}

function formUrlEncode(params: Record<string, string>): string {
  // application/x-www-form-urlencoded: spaces become +, same as OkHttp FormBody
  return Object.entries(params)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v).replace(/%20/g, '+')}`)
    .join('&');
}

// ---------------------------------------------------------------------------
// Native crypto port: getEncryptoKey (AES-GCM key derivation)
// ---------------------------------------------------------------------------
// Reversed from libthing_security.so FUN_00115368 (getEncryptoKey JNI) +
// FUN_001179f8 (cipher dispatcher) + FUN_00117780 (HMAC init).
//
// The native function uses an HMAC-SHA256 cipher (cipher id=6, name "SHA256"
// at lib offset 0x1090fe). The "key string" global at 0x139070 (set during
// doCommandNative init) holds the full HMAC_KEY (verified via memory read).
//
// Algorithm (verified against 9 captured test vectors, all match):
//   hash = HMAC-SHA256(key=requestId, msg=HMAC_KEY)  // 32-byte digest
//   key  = ASCII hex of first 8 bytes  // 16-byte string like "31786ab9ad78b501"
//
// When ecode is set (post-login sessions), the native code appends "_" + ecode
// to the key string before HMAC. For unauthenticated requests ecode is null,
// so the key string is just HMAC_KEY.
// ---------------------------------------------------------------------------

function deriveEncryptoKey(requestId: string, ecode?: string): Buffer {
  // The native code builds the key string as: HMAC_KEY (+ "_" + ecode if ecode set).
  // When ecode is null/empty, it uses HMAC_KEY directly (the global at 0x139070).
  const keyString = ecode ? `${HMAC_KEY}_${ecode}` : HMAC_KEY;
  const hash = crypto.createHmac('sha256', requestId).update(keyString, 'utf8').digest('hex');
  // The 16-byte AES key is the ASCII bytes of the first 16 hex characters.
  return Buffer.from(hash.substring(0, 16), 'ascii');
}

// AES-GCM encrypt: returns base64(nonce[12] + ciphertext + tag[16])
// Matches the app's decryptBytesAppendedNonce2Bytes format (nonce prepended).
function aesGcmEncryptBase64(key: Buffer, plaintext: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-128-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ct, tag]).toString('base64');
}

// AES-GCM decrypt: input is base64(nonce[12] + ciphertext + tag[16])
// Matches the app's decryptBytesAppendedNonce2Bytes format.
// Note: decrypted data may be gzipped (et=3) — caller must check gzip magic (1f 8b).
function aesGcmDecryptBase64(key: Buffer, b64: string): string {
  const raw = Buffer.from(b64, 'base64');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(raw.length - 16);
  const ct = raw.subarray(12, raw.length - 16);
  const decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
  decipher.setAuthTag(tag);
  let decrypted = Buffer.concat([decipher.update(ct), decipher.final()]);
  // et=3: check for gzip magic and decompress
  if (decrypted.length >= 2 && decrypted[0] === 0x1f && decrypted[1] === 0x8b) {
    decrypted = require('zlib').gunzipSync(decrypted);
  }
  return decrypted.toString('utf8');
}

interface TuyaApiResponse {
  success: boolean;
  result?: unknown;
  errorCode?: string;
  errorMsg?: string;
  t?: number;
}

interface TuyaLoginResult {
  sid: string;
  uid: string;
  ecode: string;
  timezone: string;
  expire_time: number;
  access_token: string;
  refresh_token: string;
  terminal_id: string;
  homeId?: string;
  domain?: {
    mobileApiUrl?: string;
    regionCode?: string;
  };
}

interface TuyaTokenResult {
  token: string;
  publicKey: string;
  pbKey: string;
  exponent: string;
}

interface TuyaDevice {
  id?: string;
  devId: string;
  uuid?: string;
  name: string;
  online?: boolean;
  cloudOnline?: boolean;
  connectionStatus?: number;
  // The TY group.device.list response has NO `category` field (unlike the classic
  // Tuya device list). Devices are classified by structure instead:
  //   - Gateway: deviceTopo == {} (empty) + has localKey/mac/gatewayVerCAD
  //   - Sub-device (valve/sensor): deviceTopo.parentDevId + deviceTopo.nodeId
  category?: string;
  productId?: string;
  product_id?: string;
  product_name?: string;
  model?: string;
  productVer?: string;
  ownerId?: string;
  parent_id?: string | null;
  deviceTopo?: {
    parentDevId?: string;
    nodeId?: string;
  };
  baseAttribute?: number;
  devAttribute?: number;
  switchDp?: number;
  switchDps?: number[];
  dpCodes?: string[];
  dps?: Record<string, unknown>;
  dataPointInfo?: {
    dps?: Record<string, unknown>;
    dpName?: Record<string, string>;
  };
  isSubDevice?: boolean;
  sub?: boolean;
}

interface TuyaDpResult {
  dps?: Record<string, unknown>;
}

interface TuyaStatusItem {
  code: string;
  value: unknown;
}

class TuyaApiError extends Error {
  code?: string;
  constructor(message: string, code?: string) {
    super(message);
    this.code = code;
  }
}

export class RainPointTyClient implements RainPointClient {
  private sid: string = '';
  private ecode: string = '';
  private endpoint: string;
  private deviceId: string;
  private readonly countryCode: string;
  private homeId: string = '';
  private static deviceIdStorage: string | null = null;
  // Cache of deviceId -> NormalizedDevice, populated by getDevices(). Used by
  // turnZoneOn/Off to resolve a 1-based port number to the device's per-zone
  // switch DP (RainPoint TY uses 104/155/... rather than DP 1/2/...).
  private deviceCache: Map<string, NormalizedDevice> = new Map();
  private readonly sessionFile: string | null;
  private sessionRestored = false;

  constructor(
    private config: RainPointClientConfig,
    private log: Logger,
  ) {
    const region = config.region || 'EU';
    this.endpoint = REGION_ENDPOINTS[region] || REGION_ENDPOINTS.EU!;
    // countryCode defaults to "1" (US/Canada). The Tuya/Thingclips account is keyed by
    // countryCode + email — a wrong countryCode yields USER_PASSWD_WRONG because the
    // (code, email) pair doesn't match any account, even when the email exists elsewhere.
    this.countryCode = config.countryCode || '1';
    this.deviceId = RainPointTyClient.getOrCreateDeviceId();
    // Persist the session (sid/ecode/endpoint) to disk so homebridge restarts don't
    // trigger a fresh login every time. Tuya sessions last days/weeks (the app stays
    // logged in across long gaps). The session is keyed by email so multiple accounts
    // don't collide.
    if (config.storageDir) {
      const safeEmail = config.email.replace(/[^a-zA-Z0-9@._-]/g, '_');
      this.sessionFile = `${config.storageDir}/rainpoint-ty-session-${safeEmail}.json`;
      this.loadSession();
    } else {
      this.sessionFile = null;
    }
  }

  /** Load a saved session (sid/ecode/endpoint) from disk, if present. */
  private loadSession(): void {
    if (!this.sessionFile) {
      return;
    }
    try {
      const fs = require('fs');
      if (!fs.existsSync(this.sessionFile)) {
        return;
      }
      const raw = fs.readFileSync(this.sessionFile, 'utf8');
      const saved = JSON.parse(raw) as { sid?: string; ecode?: string; endpoint?: string };
      if (saved.sid) {
        this.sid = saved.sid;
        this.ecode = saved.ecode || '';
        if (saved.endpoint) {
          this.endpoint = saved.endpoint;
        }
        this.sessionRestored = true;
        this.log.info('[TY] Restored saved session (sid=%s..., endpoint=%s)',
          this.sid.slice(0, 12), this.endpoint);
      }
    } catch (e) {
      this.log.warn('[TY] Failed to load saved session: %s', e);
    }
  }

  /** Persist the current session (sid/ecode/endpoint) to disk. */
  private saveSession(): void {
    if (!this.sessionFile) {
      return;
    }
    try {
      const fs = require('fs');
      const data = JSON.stringify({
        sid: this.sid,
        ecode: this.ecode,
        endpoint: this.endpoint,
      });
      fs.writeFileSync(this.sessionFile, data, 'utf8');
      this.log.debug('[TY] Saved session to %s', this.sessionFile);
    } catch (e) {
      this.log.warn('[TY] Failed to save session: %s', e);
    }
  }

  /** Clear the saved session file (called when the server rejects the sid). */
  private clearSession(): void {
    this.sid = '';
    this.ecode = '';
    this.sessionRestored = false;
    if (!this.sessionFile) {
      return;
    }
    try {
      const fs = require('fs');
      if (fs.existsSync(this.sessionFile)) {
        fs.unlinkSync(this.sessionFile);
      }
    } catch (e) {
      this.log.warn('[TY] Failed to clear saved session: %s', e);
    }
  }

  private static getOrCreateDeviceId(): string {
    if (RainPointTyClient.deviceIdStorage) {
      return RainPointTyClient.deviceIdStorage;
    }
    const id = generateDeviceId();
    RainPointTyClient.deviceIdStorage = id;
    return id;
  }

  async login(): Promise<void> {
    // If a session was restored from disk (or is otherwise already present), skip
    // the login flow entirely. The saved sid/ecode will be validated lazily on the
    // first authenticated request; if the server rejects them, request() clears
    // the session and re-logs in (see the SESSION_ERROR_CODES retry in request()).
    // This avoids re-running token.get + password.login on every homebridge restart.
    if (this.sid) {
      this.log.debug('[TY] Session already present (sid=%s...) — skipping login',
        this.sid.slice(0, 12));
      return;
    }
    // No fallback: a second request on failure would trigger anti-abuse blocking.
    // The encrypted login flow (token.create → RSA-encrypt password → password.login)
    // is the only flow the app uses.
    await this.loginEx();
  }

  private async loginEx(): Promise<void> {
    this.log.debug('[TY] Creating username token for encrypted login...');
    // The app calls thing.m.user.username.token.get (v2.0) with postData
    // {countryCode, username, isUid:false}. Verified via Frida capture6.
    // Using email.token.create returns a publicKey bound to a different validation
    // path, causing USER_PASSWD_WRONG at login despite a correct RSA passwd.
    const tokenResult = await this.request<TuyaTokenResult>(
      'thing.m.user.username.token.get',
      {
        countryCode: this.countryCode,
        username: this.config.email,
        isUid: false,
      },
      false,
    );

    this.log.debug('[TY] Token created, encrypting password with RSA...');

    // MD5Util.md5AsBase64(password) returns the MD5 as LOWERCASE hex. Verified at runtime
    // via Frida hook on the live app: MD5("UPY2256yu") = "d0f7595d08d85b58a5be27ea561881e1"
    // (lowercase). Node's md5().digest('hex') is also lowercase, so no case conversion needed.
    const passwdMd5 = md5(this.config.password);
    this.log.debug('[TY] password MD5 (lowercase): %s', passwdMd5);

    // RSAUtil.encrypt uses FixedSecureRandom — a deterministic SecureRandom whose
    // nextBytes() repeats the same 20-byte seed forever. This means the PKCS1 v1.5
    // padding string PS is IDENTICAL every time for the same key size. Tuya's server
    // appears to compare the RSA ciphertext (not just the decrypted plaintext), so we
    // MUST reproduce the exact same padding bytes. Node's crypto.publicEncrypt uses a
    // real CSPRNG, so we build the PKCS1 block manually and do a raw RSA public-key
    // operation (modexp) with the token's modulus + exponent.
    const encryptedPass = this.rsaEncryptFixedPadding(
      tokenResult.publicKey,
      tokenResult.exponent,
      passwdMd5,
    );
    this.log.debug('[TY] RSA-encrypted passwd (len=%d): %s', encryptedPass.length, encryptedPass);

    // LoginBusiness.smali email.password.login builds options as:
    //   "{\"group\": 1,\"mfaCode\": \"" + mfaCode + "\"}"
    // where mfaCode is "" for a normal (non-MFA) login. The outer string is a raw JSON
    // string (putPostData takes Object, fastjson serializes the String as-is).
    const result = await this.request<TuyaLoginResult>(
      'thing.m.user.email.password.login',
      {
        countryCode: this.countryCode,
        email: this.config.email,
        passwd: encryptedPass,
        ifencrypt: 1,
        options: '{"group": 1,"mfaCode": ""}',
        token: tokenResult.token,
      },
      false,
    );

    this.handleLoginResult(result);
  }

  private buildRsaPublicKeyDer(n: Buffer, e: Buffer): Buffer {
    if (n[0]! & 0x80) {
      n = Buffer.concat([Buffer.from([0x00]), n]);
    }
    if (e[0]! & 0x80) {
      e = Buffer.concat([Buffer.from([0x00]), e]);
    }
    const nTag = Buffer.concat([Buffer.from([0x02]), this.derEncodeLength(n.length), n]);
    const eTag = Buffer.concat([Buffer.from([0x02]), this.derEncodeLength(e.length), e]);
    const innerLen = nTag.length + eTag.length;
    return Buffer.concat([
      Buffer.from([0x30]),
      this.derEncodeLength(innerLen),
      nTag,
      eTag,
    ]);
  }

  private derEncodeLength(len: number): Buffer {
    if (len < 128) {
      return Buffer.from([len]);
    }
    if (len <= 0xFF) {
      return Buffer.from([0x81, len]);
    }
    return Buffer.from([0x82, (len >> 8) & 0xFF, len & 0xFF]);
  }

  /**
   * RSA-encrypt the password MD5 hex with PKCS1 v1.5 padding using Tuya's
   * FixedSecureRandom — a deterministic 20-byte seed repeated to fill the
   * padding string. Tuya's server compares the ciphertext, so the padding
   * bytes must match exactly.
   *
   * @param publicKeyDecimal decimal modulus string from token.create
   * @param exponentDecimal  decimal exponent string (e.g. "3")
   * @param plaintext         the MD5 hex string (lowercase, 32 chars)
   * @returns 256-char lowercase hex ciphertext
   */
  private rsaEncryptFixedPadding(
    publicKeyDecimal: string,
    exponentDecimal: string,
    plaintext: string,
  ): string {
    // FixedSecureRandom.seed = 20 bytes (see FixedSecureRandom.smali array_0).
    const FIXED_SEED = Buffer.from([
      0xAA, 0xFD, 0x12, 0xF6, 0x59, 0xCA, 0xE6, 0x34,
      0x89, 0xB4, 0x79, 0xE5, 0x07, 0x6D, 0xDE, 0xC2,
      0xF0, 0x6C, 0xB5, 0x8F,
    ]);

    const n = BigInt(publicKeyDecimal);
    const e = BigInt(exponentDecimal || '3');
    const msg = Buffer.from(plaintext, 'utf8');
    const keyBytes = (n.toString(16).length + 1) >> 1; // modulus byte length (128 for RSA-1024)
    const psLen = keyBytes - msg.length - 3; // PKCS1: 0x00 0x02 [PS] 0x00 [msg]

    // Build PS by repeating the fixed seed (FixedSecureRandom.nextBytes behavior).
    const ps = Buffer.alloc(psLen);
    for (let i = 0; i < psLen; i++) {
      ps[i] = FIXED_SEED[i % FIXED_SEED.length];
    }

    // Assemble the PKCS1 v1.5 block: 0x00 || 0x02 || PS || 0x00 || msg
    const block = Buffer.concat([Buffer.from([0x00, 0x02]), ps, Buffer.from([0x00]), msg]);
    if (block.length !== keyBytes) {
      throw new Error(`PKCS1 block length ${block.length} != key length ${keyBytes}`);
    }

    // Raw RSA: ciphertext = block^e mod n. Interpret block as big-endian integer.
    let m = BigInt(0);
    for (let i = 0; i < block.length; i++) {
      m = (m << 8n) | BigInt(block[i]);
    }
    let c = 1n;
    // Square-and-multiply for c = m^e mod n
    let exp = e;
    while (exp > 0n) {
      if (exp & 1n) c = (c * m) % n;
      m = (m * m) % n;
      exp >>= 1n;
    }

    // Encode ciphertext as fixed-width keyBytes hex (lowercase).
    let hex = c.toString(16);
    if (hex.length < keyBytes * 2) {
      hex = '0'.repeat(keyBytes * 2 - hex.length) + hex;
    }
    return hex;
  }

  private handleLoginResult(result: TuyaLoginResult): void {
    this.sid = result.sid;
    this.ecode = result.ecode;
    if (result.domain?.mobileApiUrl) {
      const newEndpoint = result.domain.mobileApiUrl + '/api.json';
      if (newEndpoint !== this.endpoint) {
        this.log.debug('Tuya endpoint redirected to: %s', result.domain.mobileApiUrl);
        this.endpoint = newEndpoint;
      }
    }
    this.sessionRestored = false;
    this.saveSession();
    this.log.info('Logged in to RainPoint TY API as %s', this.config.email);
  }

  async ensureAuthenticated(): Promise<void> {
    if (!this.sid) {
      await this.login();
    }
  }

  setHome(homeId: string): void {
    this.homeId = homeId;
  }

  async getHomes(): Promise<NormalizedHome[]> {
    // location.extend.list returns {<homeId>: {defaultHome:"0"}}, NOT an array.
    // Verified via the live app: {"result":{"157747002":{"defaultHome":"0"}}}.
    // The app parses it as a HashMap (FamilyExtraBusiness.smali asyncHashMap).
    const result = await this.request<Record<string, { defaultHome?: string }>>(
      'thing.m.location.extend.list',
      {},
    );
    const homeIds = Object.keys(result || {});
    const homes: NormalizedHome[] = [];
    for (const homeId of homeIds) {
      // Resolve the home name via m.life.location.get (v3.4, postData {gid}).
      // HomeResponseBean has {name, gid, id, ...}. Fall back to the homeId if the
      // detail fetch fails (the name is only used for logging — setHome uses the id).
      let name = homeId;
      try {
        const detail = await this.request<{ name?: string }>(
          'm.life.location.get',
          { gid: Number(homeId) },
        );
        if (detail?.name) {
          name = detail.name;
        }
      } catch (e) {
        this.log.warn('[TY] Failed to fetch home detail for %s: %s', homeId, e);
      }
      homes.push({ id: homeId, name });
    }
    return homes;
  }

  async getDevices(): Promise<NormalizedDevice[]> {
    const result = await this.request<TuyaDevice[]>(
      'thing.m.my.group.device.list',
      {},
      this.homeId,
    );

    const devices: NormalizedDevice[] = [];
    for (const device of result) {
      // TY sub-devices are individual zones (each deviceTopo.parentDevId sub-device
      // is one irrigation zone). The gateway has no parent. So each non-gateway
      // device is a single-port valve.
      const isSubDevice = !!(device.deviceTopo?.parentDevId || device.parent_id);
      const deviceType = this.classifyDevice(device);

      // Skip the gateway — platform.ts's registerDevice filters it out anyway via
      // DEVICE_TYPE_GATEWAY, but returning it as a 1-port valve would create a
      // bogus accessory. The gateway record is only useful as a parentId for its
      // children, which we capture below.
      if (deviceType === DEVICE_TYPE_GATEWAY) {
        this.log.debug('[TY] Skipping gateway device: %s (%s)', device.name, device.devId);
        continue;
      }

      // Detect per-zone valve switch DPs from the device's datapoints. The
      // RainPoint TY irrigation controller exposes each valve as a distinct DP:
      //   zone 1 -> DP 104, zone 2 -> DP 155, zone 3 -> DP 206, ... (step 51)
      // A "split" controller (e.g. Back Garden) has BOTH 104 and 155 => 2 zones.
      // A single-valve controller has only 104 => 1 zone. We also honor dpName
      // entries containing "Valve" as switch DPs (e.g. 155="Right Valve").
      const { zoneSwitchDps, zoneNames } = this.detectValveZones(device);

      devices.push({
        id: device.devId || device.id || '',
        name: device.name,
        model: device.model || device.productVer || device.productId || '',
        productId: device.productId || device.product_id || '',
        online: device.cloudOnline ?? device.online ?? (device.connectionStatus === 1),
        portNumber: zoneSwitchDps.length,
        // Per-zone names: use dpName-derived names when available, else the device
        // name for a single-zone device, else "Zone N".
        portDescribe: zoneNames,
        deviceType,
        isSubDevice,
        parentId: device.deviceTopo?.parentDevId || device.parent_id || undefined,
        addr: 0,
        zoneSwitchDps,
      });
    }

    // Refresh the device cache so turnZoneOn/Off can resolve port -> switch DP.
    this.deviceCache = new Map(devices.map(d => [d.id, d]));

    return devices;
  }

  async getDeviceStatuses(deviceIds: string[]): Promise<Map<string, NormalizedDeviceStatus>> {
    const result = new Map<string, NormalizedDeviceStatus>();
    const devices = await this.getDevices();

    for (const deviceId of deviceIds) {
      const device = devices.find(d => d.id === deviceId);
      if (!device) {
        continue;
      }

      try {
        const statusResult = await this.request<TuyaDpResult | TuyaStatusItem[]>(
          'thing.m.device.dp.get',
          { devId: deviceId },
        );

        const dpsMap = new Map<string, unknown>();
        if (Array.isArray(statusResult)) {
          for (const item of statusResult) {
            dpsMap.set(item.code, item.value);
          }
        } else if (statusResult.dps) {
          for (const [key, value] of Object.entries(statusResult.dps)) {
            dpsMap.set(key, value);
          }
        }

        const zones: NormalizedZoneStatus[] = [];
        const switchDps = device.zoneSwitchDps;
        for (let port = 1; port <= device.portNumber; port++) {
          // Use the per-zone switch DP when available (RainPoint TY pattern:
          // 104 for zone 1, 155 for zone 2, ...). Fall back to the legacy
          // port-number DP scheme (DP 1, 2, ...) for devices without zoneSwitchDps.
          const switchDp = switchDps?.[port - 1];
          const isOn = switchDp !== undefined
            ? dpsMap.get(String(switchDp)) === true
            : (dpsMap.get(String(port)) === true || dpsMap.get(`switch_${port}`) === true);

          // Countdown/remaining duration: best-effort. The RainPoint TY countdown
          // DP isn't at a consistent offset from the switch DP across valve groups,
          // so we don't try to read it here — the InUse characteristic falls back
          // to 0 (not running), which is safe. A future capture of an active valve
          // can pin down the countdown DP per zone.
          const remaining = 0;

          zones.push({
            port,
            name: device.portDescribe[port - 1] || `Zone ${port}`,
            isOn,
            remainingDuration: remaining,
          });
        }

        const moisture = dpsMap.get('9') ?? dpsMap.get('14')
          ?? dpsMap.get('humidity') ?? dpsMap.get('soil_humidity') ?? null;
        const temperature = dpsMap.get('10') ?? dpsMap.get('15')
          ?? dpsMap.get('temperature') ?? dpsMap.get('temp_current') ?? null;
        const battery = dpsMap.get('11') ?? dpsMap.get('17')
          ?? dpsMap.get('battery_percentage') ?? dpsMap.get('residual_electricity') ?? null;

        result.set(deviceId, {
          deviceId,
          online: device.online,
          zones,
          moisture: moisture as number | null,
          temperature: temperature as number | null,
          battery: battery as number | null,
        });
      } catch (error) {
        this.log.error('Failed to get status for device %s: %s', deviceId, error);
      }
    }

    return result;
  }

  async turnZoneOn(deviceId: string, port: number, durationSeconds?: number): Promise<void> {
    // qqddbpb.smali dp.publish: postData requires gwId + devId + dps (as JSON string).
    // For non-sub-devices gwId == devId (the device is its own gateway).
    // The DP key for the valve on/off is the per-zone switch DP (RainPoint TY:
    // 104 for zone 1, 155 for zone 2, ...) when known; otherwise fall back to
    // the legacy port-number DP scheme (DP 1, 2, ...).
    const switchDp = this.resolveSwitchDp(deviceId, port);
    const dps: Record<string, unknown> = { [String(switchDp)]: true };
    if (durationSeconds) {
      // Countdown DP is unknown per-zone for the TY scheme; omit rather than
      // risk writing the wrong DP. The valve still turns on; only the auto-off
      // timer isn't set server-side (HomeKit's SetDuration handles local timing).
    }
    await this.request('thing.m.device.dp.publish', {
      gwId: deviceId,
      devId: deviceId,
      dps: JSON.stringify(dps),
    });
    this.log.debug('Turned ON zone %d (DP %s) on device %s', port, switchDp, deviceId);
  }

  async turnZoneOff(deviceId: string, port: number): Promise<void> {
    const switchDp = this.resolveSwitchDp(deviceId, port);
    await this.request('thing.m.device.dp.publish', {
      gwId: deviceId,
      devId: deviceId,
      dps: JSON.stringify({ [String(switchDp)]: false }),
    });
    this.log.debug('Turned OFF zone %d (DP %s) on device %s', port, switchDp, deviceId);
  }

  /**
   * Resolve a 1-based zone port number to the device's valve switch DP.
   * Uses the cached device's zoneSwitchDps when available (populated by
   * getDevices); falls back to the port number itself for legacy devices.
   */
  private resolveSwitchDp(deviceId: string, port: number): number {
    const device = this.deviceCache.get(deviceId);
    if (device?.zoneSwitchDps && device.zoneSwitchDps[port - 1] !== undefined) {
      return device.zoneSwitchDps[port - 1]!;
    }
    return port;
  }

  /**
   * Classify a TY device. The thing.m.my.group.device.list response has NO
   * `category` field (unlike the classic Tuya device list), so we classify by
   * structure + datapoints instead:
   *   - Gateway: deviceTopo is empty/missing AND it's the parent (other devices
   *     point at it via deviceTopo.parentDevId). Detected by absence of a
   *     parentDevId.
   *   - Sensor: a sub-device whose dps has no irrigation valve DP. (RainPoint
   *     sensors are rare in this OEM; we currently treat every sub-device as a
   *     valve unless its productId/dps indicates otherwise.)
   *   - Valve / irrigation: any sub-device with a parentDevId.
   *
   * Returns the HomGar-style device type strings (DEVICE_TYPE_GATEWAY / VALVE /
   * SENSOR / IRRIGATION) so platform.ts's existing routing works unchanged.
   */
  private classifyDevice(device: TuyaDevice): string {
    // Gateway: no parent. The gateway record also has localKey/mac but we don't
    // require those — absence of deviceTopo.parentDevId is sufficient.
    const hasParent = !!(device.deviceTopo?.parentDevId || device.parent_id);
    if (!hasParent) {
      return DEVICE_TYPE_GATEWAY;
    }
    // Sub-device: treat as an irrigation valve/zone by default. The RainPoint
    // irrigation sub-devices all expose valve-style dps (e.g. "155":true for
    // "Right Valve"). There is no sensor variant in the captured account.
    return DEVICE_TYPE_VALVE;
  }

  /**
   * Detect per-zone valve switch datapoints for a RainPoint TY irrigation device.
   *
   * The RainPoint TY controller exposes each valve as a distinct DP. Observed
   * pattern (from a captured 3-device account):
   *   - Single-valve device (Front Garden R/L, productId ew946yrp3pgbaziu):
   *     DPs 101-128, valve on/off = DP 104 (boolean).
   *   - Split 2-valve device (Back Garden, productId pjnbcfv3bzwg4yyo):
   *     DPs 101-128 (zone 1, switch 104) AND DPs 150-167 (zone 2, switch 155,
   *     dpName "Right Valve"). The switch DPs pair by +51: 104 <-> 155.
   *
   * IMPORTANT: a valve group's switch DP may be ABSENT from the current dps
   * snapshot when the device is offline (e.g. Back Garden, cloudOnline=false,
   * omits DP 104 even though the valve exists). So zone COUNT is determined by
   * DP-range presence (a group exists if ANY dps fall in its range), NOT by
   * whether the specific switch DP is currently reported. The switch DP is then
   * assigned by the +51 pattern regardless of snapshot presence — status
   * polling reads it if present, else reports the zone as off.
   *
   * Group ranges (each spans ~28 DPs centered on its switch DP):
   *   group 1: DPs  90-149  (switch 104)
   *   group 2: DPs 141-200  (switch 155)  — overlaps group 1, so we instead
   *   use non-overlapping buckets: group N owns DPs in [101+51*(N-1), 150+51*(N-1)]
   *
   * We also honor dpName entries containing "Valve" as explicit switch DPs
   * (defensive for future firmware that may use a different pattern).
   *
   * Returns the switch DP IDs (ascending) and per-zone names (from dpName when
   * available, else the device name for single-zone, else "Zone N").
   */
  private detectValveZones(device: TuyaDevice): { zoneSwitchDps: number[]; zoneNames: string[] } {
    const dps = device.dataPointInfo?.dps ?? device.dps ?? {};
    const dpName = device.dataPointInfo?.dpName ?? {};
    const dpKeys = Object.keys(dps).map(k => Number(k)).filter(n => !Number.isNaN(n));

    // Valve-group switch DPs follow the +51 pattern: 104, 155, 206, 257, ...
    // A group N is considered present if the device reports ANY DP in its range
    // [101 + 51*(N-1), 149 + 51*(N-1)] (covers the observed 101-128 and 150-167
    // spans with margin). This catches a group even when its switch DP is
    // temporarily absent (offline device).
    const MAX_ZONES = 8;
    const GROUP_SPAN = 51;
    const GROUP_START = 101;   // first DP of group 1's range
    const SWITCH_BASE = 104;   // switch DP of group 1
    const GROUP_WIDTH = 49;    // group N spans [101+51*(N-1), 149+51*(N-1)]

    const switchDps: number[] = [];
    for (let n = 0; n < MAX_ZONES; n++) {
      const rangeLo = GROUP_START + GROUP_SPAN * n;
      const rangeHi = rangeLo + GROUP_WIDTH;
      const hasGroupDp = dpKeys.some(k => k >= rangeLo && k <= rangeHi);
      if (hasGroupDp) {
        switchDps.push(SWITCH_BASE + GROUP_SPAN * n);
      }
    }

    // Also honor dpName entries containing "Valve" (case-insensitive). These are
    // explicit valve on/off DPs the firmware named. Dedupe + sort.
    for (const [dpStr, name] of Object.entries(dpName)) {
      if (typeof name !== 'string' || !/valve/i.test(name)) {
        continue;
      }
      const dp = Number(dpStr);
      if (!Number.isNaN(dp) && !switchDps.includes(dp)) {
        switchDps.push(dp);
      }
    }

    switchDps.sort((a, b) => a - b);

    // Fallback: if no valve groups detected at all (firmware without the standard
    // pattern, or a completely empty dps snapshot), assume a single zone using
    // the legacy DP 1 scheme so the accessory still appears.
    if (switchDps.length === 0) {
      this.log.warn('[TY] No valve groups detected for %s (productId=%s); '
        + 'assuming single zone with legacy DP 1. dps keys: %s',
        device.name, device.productId, Object.keys(dps).join(','));
      return {
        zoneSwitchDps: [1],
        zoneNames: [device.name],
      };
    }

    // Build per-zone names. Prefer dpName; fall back to the device name for a
    // single-zone device, else "Zone N" / "Left Valve" / "Right Valve" by index.
    const DEFAULT_NAMES: Record<number, string> = { 0: 'Left Valve', 1: 'Right Valve' };
    const zoneNames = switchDps.map((dp, i) => {
      const named = dpName[String(dp)];
      if (typeof named === 'string' && named.trim()) {
        return named;
      }
      if (switchDps.length === 1) {
        return device.name;
      }
      return DEFAULT_NAMES[i] ?? `Zone ${i + 1}`;
    });

    this.log.debug('[TY] %s: detected %d zone(s) switchDps=%s names=%s',
      device.name, switchDps.length, switchDps.join(','), JSON.stringify(zoneNames));

    return { zoneSwitchDps: switchDps, zoneNames };
  }

  private getDeviceType(category: string): string {
    // Legacy helper retained for the HomGar-style category strings; unused by
    // the TY flow (which has no category field). Defensive: tolerate undefined.
    switch ((category || '').toLowerCase()) {
    case 'sf':
      return DEVICE_TYPE_IRRIGATION;
    case 'wg2':
    case 'sz':
      return DEVICE_TYPE_VALVE;
    case 'sensor':
      return DEVICE_TYPE_SENSOR;
    default:
      return category || DEVICE_TYPE_VALVE;
    }
  }

  /**
   * Make a Tuya mobile API request.
   *
   * Based on APK decompilation of ThingApiParams.getRequestBody():
   * - HTTP POST to the bare endpoint URL (no query params)
   * - Body is application/x-www-form-urlencoded
   * - postData in the body is the RAW JSON string (not hashed)
   * - postData in the sign string is mobileHash(postData)
   * - The sign covers both URL params and postData (hashed)
   */
  private async request<T>(
    action: string,
    data: Record<string, unknown>,
    requireSid: boolean | string = true,
    retried = false,
  ): Promise<T> {
    if (requireSid !== false) {
      await this.ensureAuthenticated();
    }

    const gid = typeof requireSid === 'string' ? requireSid : undefined;
    const needsSid = requireSid !== false;

    const d = new Date();
    const postDataStr = JSON.stringify(data);
    const requestId = uuidv4();
    this.log.debug('[TY] plaintext postData for %s: %s', action, postDataStr);

    // When et=3, the Business layer AES-GCM encrypts ALL postData before sending.
    // The server decrypts postData using the key derived from requestId (via native
    // getEncryptoKey). The sign covers the ENCRYPTED postData (base64), not the raw JSON.
    //
    // ecode handling: the ecode-suffixed key (HMAC_KEY + "_" + ecode) is only valid
    // AFTER login. Pre-login calls (token.get + password.login, signaled by
    // requireSid === false) must derive the key WITHOUT ecode — even if a saved
    // session was restored (which would otherwise populate this.ecode). Using the
    // ecode key for token.get causes the server's no-ecode-encrypted response to
    // fail GCM auth ("unable to authenticate data").
    const ecode = requireSid === false ? undefined : (this.ecode || undefined);
    const encKey = deriveEncryptoKey(requestId, ecode);
    const encryptedPostData = aesGcmEncryptBase64(encKey, postDataStr);

    // Per-API version (Tuya gateway validates a+v server-side). Defaults to "*" for
    // any API not in the map, matching ThingApiParams' default apiVersion field.
    // Version lookup uses the ORIGINAL thing.m.* name (pre-rewrite), matching how
    // the APK constructor sets apiVersion before checkAPIName() mutates apiName.
    const apiVersion = API_VERSIONS[action] ?? '*';

    // checkAPIName() rewrite: thing.m.* -> smartlife.m.* (via @xx2@ prepend + replaceAll).
    // The rewritten name is what the gateway receives in `a` and what enters the sign string.
    const apiName = finalizeApiName(action);

    // --- Build the sign map (URL params + postData for signing) ---
    // APK: getRequestBody() merges getUrlParams() + getPostBody() into one map for signing
    // postData in the sign map is the ENCRYPTED base64 string (hashed via mobileHash)
    const signMap: Record<string, string> = {
      a: apiName,
      deviceId: this.deviceId,
      os: 'Android',
      lang: 'en_US',
      v: apiVersion,
      clientId: APP_KEY,
      time: Math.round(d.getTime() / 1000).toString(),
      postData: mobileHash(encryptedPostData),  // hashed encrypted postData for sign
      et: API_ET_VERSION,
      ttid: TTID,
      appVersion: '1.2.5',
      requestId: requestId,
      chKey: CH_KEY,
    };

    if (gid) {
      signMap.gid = gid;
    }

    if (needsSid && this.sid) {
      signMap.sid = this.sid;
    }

    // Signed keys list from APK: ThingApiSignManager.bdpdqbp
    const valuesToSign = new Set([
      'a', 'v', 'lat', 'lon', 'lang', 'deviceId', 'appVersion', 'ttid',
      'isH5', 'h5Token', 'os', 'clientId', 'postData', 'time', 'requestId',
      'et', 'n4h5', 'sid', 'sp', 'chKey',
    ]);

    const sortedKeys = Object.keys(signMap).sort();
    let strToSign = '';
    for (const key of sortedKeys) {
      if (!valuesToSign.has(key) || !signMap[key]) {
        continue;
      }
      if (strToSign) {
        strToSign += '||';
      }
      strToSign += `${key}=${signMap[key]}`;
    }

    const sign = crypto.createHmac('sha256', HMAC_KEY).update(strToSign).digest('hex');

    // --- Build the POST body map ---
    // When et=3, postData is the AES-GCM encrypted base64 string (not raw JSON).
    // The server decrypts it using the key derived from requestId.
    const bodyParams: Record<string, string> = {
      postData: encryptedPostData,  // ENCRYPTED base64 in body
      sign: sign,
      a: apiName,
      deviceId: this.deviceId,
      os: 'Android',
      lang: 'en_US',
      v: apiVersion,
      clientId: APP_KEY,
      time: signMap.time,
      et: API_ET_VERSION,
      cp: 'gzip',
      ttid: TTID,
      appVersion: '1.2.5',
      appRnVersion: '5.97',
      sdkVersion: '6.8.0',
      deviceCoreVersion: '6.8.0',
      osSystem: '17',
      platform: 'sdk_gphone16k_arm64',
      timeZoneId: 'America/Los_Angeles',
      channel: 'oem',
      nd: '1',
      customDomainSupport: '1',
      requestId: signMap.requestId,
      chKey: CH_KEY,
      bizData: JSON.stringify({ brand: 'google', customDomainSupport: '1', nd: '1', sdkInt: '37' }),
    };

    if (gid) {
      bodyParams.gid = gid;
    }

    if (needsSid && this.sid) {
      bodyParams.sid = this.sid;
    }

    const bodyStr = formUrlEncode(bodyParams);

    const urlObj = new URL(this.endpoint);
    this.log.debug('[TY] POST %s', this.endpoint);
    this.log.debug('[TY] sign string: %s', strToSign);
    this.log.debug('[TY] body: %s', bodyStr);

    // Error codes that indicate the saved sid is no longer valid and the client
    // must re-login (then retry the request once). These are the typical Tuya
    // session-expired signatures; the gateway returns them when the sid is
    // missing/expired/revoked rather than re-issuing one silently.
    const SESSION_ERROR_CODES = new Set([
      'SESSION_EXPIRED', 'SESSION_INVALID', 'INVALID_SESSION',
      'SID_INVALID', 'NOT_LOGIN', 'Frequently_Invoke',
    ]);

    const doRequest = (): Promise<T> => new Promise((resolve, reject) => {
      const options: https.RequestOptions = {
        hostname: urlObj.hostname,
        port: urlObj.port || 443,
        path: urlObj.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Thing-UA=APP/Android/1.2.5/SDK/6.8.0',
          'Connection': 'keep-alive',
          'channel_type': 'oem_app',
          'channel_key': APP_KEY,
          'x-client-trace-id': signMap.requestId,
        },
        rejectUnauthorized: false,
      };

      const req = https.request(options, (res) => {
        let responseData = '';
        res.on('data', (chunk) => {
          responseData += chunk;
        });
        res.on('end', () => {
          this.log.debug('[TY] Response: %s', responseData);
          try {
            const parsed = JSON.parse(responseData);
            // The gateway returns two response shapes:
            //   (1) Encrypted: {t, sign, result:"<base64 AES-GCM ciphertext>"} — no "success" field.
            //       The real {success, result, ...} is inside the encrypted result.
            //   (2) Plain: {success, result, ...} — error responses or unencrypted APIs.
            // We detect (1) by the presence of "sign" + "result" without "success",
            // then decrypt with the same key derived from requestId (pure JS, no emulator).
            let decoded = parsed;
            if (parsed && typeof parsed === 'object' && 'sign' in parsed && 'result' in parsed && !('success' in parsed)) {
              const requestId = signMap.requestId;
              const resultB64 = parsed.result as string;
              this.log.debug('[TY] Response is encrypted (sign=%s), decrypting (requestId=%s)...', parsed.sign, requestId);
              const decKey = deriveEncryptoKey(requestId, ecode);
              const decryptedJson = aesGcmDecryptBase64(decKey, resultB64);
              this.log.debug('[TY] Decrypted response: %s', decryptedJson);
              decoded = JSON.parse(decryptedJson);
            }
            const apiResp = decoded as TuyaApiResponse;
            if (!apiResp.success) {
              reject(new TuyaApiError(`Tuya API error: ${apiResp.errorMsg || 'Unknown'} (code: ${apiResp.errorCode})`, apiResp.errorCode));
              return;
            }
            resolve(apiResp.result as T);
          } catch (e) {
            reject(new Error(`Failed to parse Tuya API response: ${e}`));
          }
        });
      });

      req.on('error', (e) => {
        reject(new Error(`HTTP request failed: ${e.message}`));
      });

      req.setTimeout(20000, () => {
        req.destroy(new Error('Request timed out'));
      });

      req.write(bodyStr);
      req.end();
    });

    // First attempt. If the server rejects with a session-expired code AND this
    // request was made with a saved (restored) sid, clear the session, log back
    // in, and retry exactly once. The retry reuses the SAME signMap (same
    // requestId/time/postData), only the bodyParams.sid changes — which is fine
    // because the gateway keys validation on the sid, not the requestId.
    return doRequest().catch((err) => {
      const code = (err as TuyaApiError)?.code;
      const wasUsingRestoredSid = this.sessionRestored || (needsSid && this.sid);
      if (code && SESSION_ERROR_CODES.has(code) && wasUsingRestoredSid && !retried) {
        this.log.warn('[TY] Session rejected (code=%s) — clearing saved session and re-logging in...', code);
        this.clearSession();
        return this.login().then(() => {
          // Re-issue the request with the fresh sid. The recursive call passes
          // retried=true so a second session error surfaces instead of looping.
          return this.request<T>(action, data, requireSid, true);
        });
      }
      throw err;
    });
  }
}
