import https from 'https';
import crypto from 'crypto';
import { URL } from 'url';
import { v4 as uuidv4 } from 'uuid';
import mqtt from 'mqtt';

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
  // thing.m.product.thing.model (v1.0) {productId, productVersion} -> canonical
  // DP schema (ThingSmartThingModel: services[] with properties{code,type,range}).
  // The authoritative per-product DP definition list — the plugin fetches this
  // once per productId to resolve each zone's WorkStatus/ManualTimer/ManualSwitch/
  // RemainTime DPs by code (instead of hardcoding offsets like 104/155, which are
  // wrong for multi-zone RainPoint products). Verified live 2026-06-20.
  'thing.m.product.thing.model': '1.0',
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

// MQTT broker hostnames per region (mobileMqttsUrl from encrypted regions file).
// RainPoint TY uses private-label Tuya brokers at *.baldrgroup.net.
const MQTT_BROKERS: Record<string, string> = {
  EU: 'm1-eu.baldrgroup.net',
  AZ: 'm1-us.baldrgroup.net',
  IN: 'm1-in.baldrgroup.net',
  US: 'm1-us.baldrgroup.net',
};
const MQTT_PORT = 8883;

// The MQTT broker port may come from the login response domain.mqttsPort;
// fall back to this default.
const DEFAULT_MQTT_PORT = 8883;

// Hardcoded salt used in the MQTT clientId construction (from bqbppdq.smali).
const MQTT_CLIENTID_SALT = 'sdkfasodifca';
const MQTT_CLIENTID_TAG = 'DEFAULT';

function md5(data: string): string {
  return crypto.createHash('md5').update(data, 'utf8').digest('hex');
}

// MD5 of the HMAC_KEY — used as the key for the MQTT password derivation.
// doCommandNative(cmd=2, ecode) = MD5( md5_hex(HMAC_KEY) + ecode ).
// Verified against 26 Frida-captured test vectors. See reverse-engineering/
// docs in the homebridge-re-tools repo for the full derivation.
const MD5_HEX_HMAC_KEY = md5(HMAC_KEY);

/**
 * Derive the MQTT password for RainPoint TY's SdkMqttCertificationInfo auth.
 *
 * The app calls ThingNetworkSecurity.doCommandNative(app, 2, ecode.getBytes(),
 * null, mD) which computes MD5( md5_hex(HMAC_KEY) + ecode ), then takes the
 * 16 chars from the middle: raw.substring(len/2 - 8, len/2 + 8).
 *
 * For a 32-char hex string (MD5 output), mid=16, so substring(8, 24).
 *
 * Reversed from libthing_security.so via Frida — see the re-tools docs.
 */
function deriveMqttPassword(ecode: string): string {
  const raw = md5(MD5_HEX_HMAC_KEY + ecode);
  // raw is 32 chars; password = raw.substring(8, 24) (16 chars from the middle)
  return raw.substring(8, 24);
}

/**
 * Derive the MQTT username for SdkMqttCertificationInfo auth.
 *
 * Format (from qpqbppd.smali / SdkMqttCertificationInfo.qddqppb):
 *   {partnerIdentity}_v1_{appId}_{chKey}_mb_{sid}{last16(md5(md5(appId)+ecode))}
 *
 * - partnerIdentity: from the login response (e.g. "p1306631")
 * - appId: ThingSmartNetWork.mAppId (= APP_KEY)
 * - chKey: ThingNetworkSecurity.getChKey(app, appId.getBytes()) = CH_KEY
 * - sid: from the login response
 * - last16: md5(md5(appId) + ecode).substring(16, 32) (last 16 chars of 32-char MD5 hex)
 */
function deriveMqttUsername(
  partnerIdentity: string,
  appId: string,
  chKey: string,
  sid: string,
  ecode: string,
): string {
  const md5AppId = md5(appId);
  const last16 = md5(md5AppId + ecode).substring(16, 32);
  return `${partnerIdentity}_v1_${appId}_${chKey}_mb_${sid}${last16}`;
}

/**
 * Derive the MQTT clientId for SdkMqttCertificationInfo auth.
 *
 * Format (from bqbppdq.smali / MqttServerManager.initMqttConfig):
 *   {packageName}_mb_{deviceId}_{md5(uid + "sdkfasodifca")}_{tag}
 *
 * - packageName: "com.baldr.rainpoint"
 * - deviceId: the same per-install device UUID used for API requests
 * - uid: from the login response
 * - "sdkfasodifca": hardcoded salt (bqbppdq.smali:1483)
 * - tag: "DEFAULT" (pdqdqbd.smali:380)
 */
function deriveMqttClientId(packageName: string, deviceId: string, uid: string): string {
  return `${packageName}_mb_${deviceId}_${md5(uid + MQTT_CLIENTID_SALT)}_${MQTT_CLIENTID_TAG}`;
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
  expire_time?: number;
  homeId?: string;
  // RainPoint TY private cloud login response. Unlike the standard Tuya login,
  // this cloud does NOT return access_token/refresh_token — MQTT auth derives
  // credentials from sid+ecode+uid+partnerIdentity instead (see
  // deriveMqttPassword/deriveMqttUsername). The domain block carries the MQTT
  // broker hostname (mobileMqttsUrl) and port (mqttsPort).
  domain?: {
    mobileApiUrl?: string;
    regionCode?: string;
    mobileMqttsUrl?: string;
    mqttsPort?: number;
    mobileMqttUrl?: string;
    mqttPort?: number;
    [key: string]: unknown;
  };
  // partnerIdentity is a string (e.g. "p1306631") — the OEM identity used in
  // the MQTT username and subscription topic ({partnerIdentity}/mb/{uid}).
  partnerIdentity?: string;
  extras?: Record<string, unknown>;
  username?: string;
  nickname?: string;
  email?: string;
  userType?: number;
  accountType?: number;
  phoneCode?: string;
  mobile?: string;
  [key: string]: unknown;
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
  // Per-device AES key (16 chars). The gateway's localKey decrypts MQTT DP
  // pushes that arrive on smart/mb/in/{gwId} (Tuya "Thing" protocol 2.2
  // binary frame, AES-128-ECB/PKCS5). Sub-devices typically share the
  // gateway's localKey for cloud-pushed DPs.
  localKey?: string;
  local_key?: string;
}

interface TuyaDpResult {
  dps?: Record<string, unknown>;
}

interface TuyaStatusItem {
  code: string;
  value: unknown;
}

// thing.m.product.thing.model response (ThingSmartThingModel). The canonical
// per-product DP schema: services[].properties[] each with {abilityId, code,
// accessMode (ro/rw), typeSpec}. abilityId is the dpId; code is the human name
// (WorkStatus, ManualTimer, ...); accessMode tells writable vs read-only.
interface ThingModel {
  modelId?: string;
  productId?: string;
  productVersion?: string;
  services?: Array<{
    code?: string;
    properties?: ThingModelProperty[];
  }>;
}
interface ThingModelProperty {
  abilityId: number;
  code?: string;
  accessMode?: 'ro' | 'rw' | 'wr';
  typeSpec?: {
    type: string;
    min?: number;
    max?: number;
    step?: number;
    unit?: string;
    range?: string[];
  };
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
  private uid: string = '';
  private partnerIdentity: string = '';
  private mqttBroker: string = '';
  private mqttPort: number = DEFAULT_MQTT_PORT;
  private endpoint: string;
  private deviceId: string;
  private readonly countryCode: string;
  private readonly region: string;
  private homeId: string = '';
  private static deviceIdStorage: string | null = null;
  // Cache of deviceId -> NormalizedDevice, populated by getDevices(). Used by
  // turnZoneOn/Off to resolve a 1-based port number to the device's per-zone
  // switch DP (RainPoint TY uses 104/155/... rather than DP 1/2/...).
  private deviceCache: Map<string, NormalizedDevice> = new Map();
  // Map of devId -> localKey for EVERY device returned by the device list
  // (gateways AND sub-devices). Used to AES-decrypt MQTT DP pushes that
  // arrive on `smart/mb/in/{devId}` as Tuya "Thing" protocol 2.2 binary
  // frames. The gateway's localKey decrypts pushes for its sub-devices.
  private localKeys: Map<string, string> = new Map();
  private readonly sessionFile: string | null;
  private sessionRestored = false;

  // MQTT push for real-time DP updates (replaces polling).
  private mqttClient: mqtt.MqttClient | null = null;
  private mqttConnected = false;
  // Callback set by platform to receive DP status updates outside poll cycle.
  private onStatusUpdate: ((deviceId: string, dps: Map<string, unknown>, cid?: string) => void) | null = null;
  // Callback for MQTT connect/disconnect events — platform uses this to
  // start/stop polling dynamically.
  private onMqttConnect: ((connected: boolean) => void) | null = null;
  // MQTT reconnect timer handle
  private mqttReconnectTimer: NodeJS.Timeout | null = null;

  constructor(
    private config: RainPointClientConfig,
    private log: Logger,
  ) {
    const region = config.region || 'EU';
    this.region = region;
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

  /** Load a saved session from disk, if present. */
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
      const saved = JSON.parse(raw) as {
        sid?: string; ecode?: string; endpoint?: string;
        uid?: string; partnerIdentity?: string;
        mqttBroker?: string; mqttPort?: number;
      };
      if (saved.sid) {
        this.sid = saved.sid;
        this.ecode = saved.ecode || '';
        this.uid = saved.uid || '';
        this.partnerIdentity = saved.partnerIdentity || '';
        this.mqttBroker = saved.mqttBroker || '';
        this.mqttPort = saved.mqttPort || DEFAULT_MQTT_PORT;
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

  /** Persist the current session to disk. */
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
        uid: this.uid,
        partnerIdentity: this.partnerIdentity,
        mqttBroker: this.mqttBroker,
        mqttPort: this.mqttPort,
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
    this.uid = '';
    this.partnerIdentity = '';
    this.mqttBroker = '';
    this.sessionRestored = false;
    this.disconnectMqtt();
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
    this.uid = result.uid;
    // partnerIdentity is a string (e.g. "p1306631") used in MQTT auth.
    this.partnerIdentity = typeof result.partnerIdentity === 'string' ? result.partnerIdentity : '';
    // MQTT broker info comes from the login response domain block.
    if (result.domain?.mobileMqttsUrl) {
      this.mqttBroker = result.domain.mobileMqttsUrl;
    }
    if (result.domain?.mqttsPort) {
      this.mqttPort = result.domain.mqttsPort;
    }
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
    if (this.partnerIdentity) {
      this.log.info('[TY] partnerIdentity=%s, mqttBroker=%s:%d',
        this.partnerIdentity, this.mqttBroker, this.mqttPort);
    }
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
      // Capture every device's localKey (gateways AND sub-devices) for
      // decrypting MQTT DP pushes. The gateway is skipped as an accessory
      // below, but its localKey is required to decrypt pushes that arrive
      // on smart/mb/in/{gwId} for its sub-devices.
      const lk = device.localKey || device.local_key;
      if (lk) {
        this.localKeys.set(device.devId, lk);
      }

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

      // Detect per-zone valve switch DPs from the device's datapoints (fallback
      // only — used to count zones + name them when the product schema isn't
      // available). The authoritative per-zone control/status DPs come from
      // thing.m.product.thing.model below.
      const { zoneSwitchDps, zoneNames } = this.detectValveZones(device);

      devices.push({
        id: device.devId || device.id || '',
        name: device.name,
        model: device.model || device.productVer || device.productId || '',
        productId: device.productId || device.product_id || '',
        online: device.cloudOnline ?? device.online ?? (device.connectionStatus === 1),
        portNumber: zoneSwitchDps.length,
        portDescribe: zoneNames,
        deviceType,
        isSubDevice,
        parentId: device.deviceTopo?.parentDevId || device.parent_id || undefined,
        addr: 0,
        // Mesh node id — the `cid` field in MQTT DP pushes on the gateway's
        // topic identifies which sub-device the update is for.
        nodeId: device.deviceTopo?.nodeId,
        zoneSwitchDps,
      });
    }

    // Refresh the device cache so turnZoneOn/Off can resolve port -> switch DP.
    this.deviceCache = new Map(devices.map(d => [d.id, d]));

    // Resolve per-zone control/status DPs from thing.m.product.thing.model.
    // The thing.model returns the canonical DP schema (abilityId + code +
    // accessMode + typeSpec) per product. RainPoint irrigation products expose
    // per-zone blocks named WorkStatus/ManualTimer/ManualSwitch/RemainTime (for
    // single-zone products) or Left*/Right* prefixed (for multi-zone). We group
    // the properties by zone prefix and resolve each zone's run/timer/switch/
    // remain DPs by code — this is the authoritative, model-independent mapping
    // (the +51 offset heuristic was wrong for multi-zone: zone 2's WorkStatus
    // is 153, not switchDp+2).
    await this.resolveZoneDpsFromSchema(devices);

    return devices;
  }

  /**
   * Fetch thing.m.product.thing.model for each distinct productId and resolve
   * the per-zone control/status DPs (WorkStatus, ManualTimer, ManualSwitch,
   * RemainTime) by code name. Populates device.zoneDps. Cached per productId for
   * the process lifetime.
   *
   * Verified schema (live capture) for two RainPoint irrigation products:
   *   ew946yrp3pgbaziu (1-zone): WorkStatus=106, ManualTimer=107,
   *     ManualSwitch=108, LeftTime=109
   *   pjnbcfv3bzwg4yyo (2-zone): zone1 Left* = 106/107/108/109,
   *     zone2 Right* = 153/154/155/156
   *
   * For products without a thing.model (or without WorkStatus DPs), zoneDps is
   * left undefined and the caller falls back to the +offset heuristic.
   */
  private productSchemaCache = new Map<string, ThingModelProperty[]>();
  private async resolveZoneDpsFromSchema(devices: NormalizedDevice[]): Promise<void> {
    const productIds = Array.from(new Set(devices.map(d => d.productId).filter(Boolean)));
    for (const pid of productIds) {
      if (this.productSchemaCache.has(pid) || pid === '(none)') {
        continue;
      }
      try {
        const model = await this.request<ThingModel>(
          'thing.m.product.thing.model',
          { productId: pid, productVersion: '1.0.0' },
        );
        const props = model?.services?.flatMap(s => s.properties ?? []) ?? [];
        this.productSchemaCache.set(pid, props);
        this.log.debug('[TY] thing.model for %s: %d properties', pid, props.length);
      } catch (error) {
        this.log.warn('[TY] Failed to fetch thing.model for %s: %s', pid, error);
        this.productSchemaCache.set(pid, []);
      }
    }

    // Resolve per-zone DPs. Group properties by zone prefix derived from the code:
    // "WorkStatus" / "ManualTimer" etc -> zone prefix "" (single-zone)
    // "LeftWorkStatus" / "RightManualTimer" etc -> "Left" / "Right"
    // A zone is present if it has a WorkStatus property (the run-state anchor).
    for (const device of devices) {
      const props = this.productSchemaCache.get(device.productId);
      if (!props || props.length === 0) {
        continue;
      }
      const zones = this.groupPropertiesByZone(props);
      if (zones.length === 0) {
        continue;
      }
      device.zoneDps = zones.map(z => ({
        workStatus: z.byCode.WorkStatus ?? z.byCode.ManualSwitch ?? 0,
        manualTimer: z.byCode.ManualTimer ?? 0,
        manualSwitch: z.byCode.ManualSwitch ?? 0,
        remainTime: z.byCode.RemainTime ?? z.byCode.LeftTime ?? 0,
      }));
      // If the schema declared more zones than detectValveZones found (e.g. a
      // 2-zone product where only zone-1's dps were present in the snapshot),
      // trust the schema — it's the authoritative zone count.
      if (zones.length > device.portNumber) {
        device.portNumber = zones.length;
        if (device.portDescribe.length < zones.length) {
          for (let i = device.portDescribe.length; i < zones.length; i++) {
            device.portDescribe.push(zones[i].name);
          }
        }
      }
      this.log.debug('[TY] %s resolved %d zone(s) from schema: %s',
        device.name, zones.length, JSON.stringify(device.zoneDps));
    }
  }

  /**
   * Group thing.model properties into zones. RainPoint irrigation codes use a
   * Left/Right prefix for multi-zone products and bare codes for single-zone —
   * BUT some single-zone products ALSO have a `LeftTime` code where "Left" is
   * part of the name, not a zone prefix. We distinguish them by checking whether
   * the SAME role exists with both Left and Right prefixes: if both
   * LeftWorkStatus and RightWorkStatus exist, the product is multi-zone and the
   * prefix is a zone marker; otherwise bare codes form one zone.
   *
   * Returns one entry per zone, in zone order (Left before Right, unprefixed =
   * single zone). Each zone's byCode map indexes the code WITHOUT its prefix
   * (e.g. "RightWorkStatus" -> "WorkStatus") so the same lookup works per zone.
   */
  private groupPropertiesByZone(props: ThingModelProperty[]): Array<{ name: string; byCode: Record<string, number> }> {
    // First pass: detect whether this product uses a Left/Right zone scheme.
    // A role R is zone-prefixed if both LeftR and RightR appear as codes.
    const codes = new Set(props.map(p => p.code ?? '').filter(Boolean));
    const hasLeftRightZoneScheme = ['WorkStatus', 'ManualSwitch', 'ManualTimer'].some(role =>
      codes.has(`Left${role}`) && codes.has(`Right${role}`),
    );

    const zones = new Map<string, Record<string, number>>();
    for (const p of props) {
      const code = p.code ?? '';
      let prefix = '';
      let role = code;
      if (hasLeftRightZoneScheme) {
        // Multi-zone: strip Left/Right prefix, it's a zone marker.
        const m = code.match(/^(Left|Right)(.+)$/);
        if (m) {
          prefix = m[1];
          role = m[2];
        }
      }
      // Single-zone: keep the full code as the role (LeftTime stays LeftTime).
      if (!zones.has(prefix)) {
        zones.set(prefix, {});
      }
      zones.get(prefix)![role] = p.abilityId;
    }
    // A real irrigation zone has a WorkStatus (or ManualSwitch) anchor. Order:
    // unprefixed first (single-zone), then Left, then Right, then any others.
    const order = ['', 'Left', 'Right'];
    const sortedPrefixes = Array.from(zones.keys()).sort((a, b) => {
      const ia = order.indexOf(a);
      const ib = order.indexOf(b);
      if (ia !== -1 && ib !== -1) {
        return ia - ib;
      }
      if (ia !== -1) {
        return -1;
      }
      if (ib !== -1) {
        return 1;
      }
      return a.localeCompare(b);
    });
    const DEFAULT_NAMES: Record<string, string> = { '': 'Valve', Left: 'Left Valve', Right: 'Right Valve' };
    const result: Array<{ name: string; byCode: Record<string, number> }> = [];
    for (const prefix of sortedPrefixes) {
      const byCode = zones.get(prefix)!;
      if (byCode.WorkStatus === undefined && byCode.ManualSwitch === undefined) {
        continue;
      }
      result.push({ name: DEFAULT_NAMES[prefix] ?? prefix, byCode });
    }
    return result;
  }

  /**
   * Public escape hatch for diagnostics / RE: call any Tuya mobile API action by
   * name with arbitrary postData and return the raw decrypted response. Reuses
   * the full request pipeline (signing, AES-GCM encrypt/decrypt, sid injection)
   * so it exercises the EXACT same wire path as production calls. Used by the
   * standalone schema-probe script archived in the homebridge-re-tools repo.
   */
  async debugRequest<T = unknown>(
    action: string,
    data: Record<string, unknown>,
    requireSid: boolean | string = true,
  ): Promise<T> {
    return this.request<T>(action, data, requireSid);
  }

  // --------------------------------------------------------------------------
  // MQTT push — real-time DP updates from Tuya cloud broker.
  //
  // The RainPoint TY app uses MQTT-over-TLS (port 8883) to receive instant DP
  // changes. The SDK (SdkMqttCertificationInfo, obfuscated class qpqbppd)
  // derives credentials entirely from the login response — no access_token:
  //
  //   username  = {partnerIdentity}_v1_{appId}_{chKey}_mb_{sid}{last16(md5(md5(appId)+ecode))}
  //   password  = doCommandNative(2, ecode).substring(8, 24)
  //             = MD5( md5_hex(HMAC_KEY) + ecode ).substring(8, 24)
  //   clientId  = {packageName}_mb_{deviceId}_{md5(uid + "sdkfasodifca")}_DEFAULT
  //   topic     = {partnerIdentity}/mb/{uid}   (single subscription — all devices)
  //   broker    = ssl://{domain.mobileMqttsUrl}:{domain.mqttsPort}
  //
  // The doCommandNative(cmd=2) algorithm was reversed from libthing_security.so
  // via Frida on an arm64 Android emulator. See the reverse-engineering docs in
  // the homebridge-re-tools repo for the full derivation.
  // --------------------------------------------------------------------------

  /**
   * Register a callback for real-time DP status updates received via MQTT.
   * Called by the platform layer once, after device discovery.
   */
  setOnStatusUpdate(cb: (deviceId: string, dps: Map<string, unknown>, cid?: string) => void): void {
    this.onStatusUpdate = cb;
  }

  /**
   * Register a callback for MQTT connection state changes. The platform uses
   * this to stop polling when MQTT is connected and restart it on disconnect.
   */
  setOnMqttConnect(cb: (connected: boolean) => void): void {
    this.onMqttConnect = cb;
  }

  /**
   * Connect to the Tuya MQTT broker using SdkMqttCertificationInfo credentials
   * derived from the login session (sid, ecode, uid, partnerIdentity).
   * Subscribes to the single user topic {partnerIdentity}/mb/{uid} — all
   * device DP updates arrive on this topic.
   */
  /**
   * Connect to the Tuya MQTT broker. Subscribes to:
   *   - `{partnerIdentity}/mb/{uid}` — user-level topic (home/family events).
   *   - `smart/mb/in/{devId}` — PER-DEVICE topic. This is where real-time DP
   *     pushes actually arrive (verified from the decompiled app:
   *     com.thingclips.sdk.device.pbpqqdp:2301 and
   *     com.thingclips.sdk.bluetooth.dpppbbd:554 subscribe to
   *     "smart/mb/in/" + devId for each device). The user topic does NOT
   *     receive DP pushes — subscribing only to it yields zero PUBLISH
   *     packets even though SUBACK grants QoS 1. The broker's ACL rejects
   *     wildcard filters (`#`, `smart/mb/#`) with granted=128, so we must
   *     subscribe to each device topic individually.
   */
  async connectMqtt(deviceIds: string[] = []): Promise<void> {
    if (!this.sid || !this.ecode || !this.uid || !this.partnerIdentity) {
      this.log.warn('[TY] MQTT: session incomplete (sid/ecode/uid/partnerIdentity), skipping');
      return;
    }
    if (this.mqttClient) {
      return; // already connected or connecting
    }

    const brokerHost = this.mqttBroker || MQTT_BROKERS[this.region] || MQTT_BROKERS.AZ!;
    const brokerPort = this.mqttPort || MQTT_PORT;
    const url = `tls://${brokerHost}:${brokerPort}`;

    const username = deriveMqttUsername(
      this.partnerIdentity, APP_KEY, CH_KEY, this.sid, this.ecode,
    );
    const password = deriveMqttPassword(this.ecode);
    const clientId = deriveMqttClientId(PACKAGE_NAME, this.deviceId, this.uid);
    const userTopic = `${this.partnerIdentity}/mb/${this.uid}`;
    // Per-device DP push topics — the actual destination for real-time
    // device state changes. One topic per device, no wildcards (ACL blocks them).
    const deviceTopics = deviceIds.map(id => `smart/mb/in/${id}`);

    this.log.info('[TY] MQTT: connecting to %s (clientId=%s..., userTopic=%s, deviceTopics=%d)',
      url, clientId.slice(0, 24), userTopic, deviceTopics.length);

    // Last Will & Testament (LWT). The Tuya SDK registers a will on the
    // CONNECT packet (MqttModel.smali:3036) — the broker uses this as a
    // presence/registration marker: without it, the broker accepts the
    // connection + subscription (CONNACK returnCode=0, SUBACK granted=0)
    // but does NOT route DP pushes to the client. The will payload is a
    // fixed JSON shape:
    //   {"clientId":"<clientId>","deviceType":"ANDROID","message":"","userName":"<username>"}
    // published to the static topic "tuya/smart/will" (pqpbpqd.dpdbqdp,
    // computed as "thing/smart/will".replace("hing","uya")) at QoS 1,
    // retain=false. We use "homebridge" as deviceType since we aren't the
    // Android app — the broker doesn't validate this field, only its
    // presence in the CONNECT packet.
    const willTopic = 'tuya/smart/will';
    const willPayload = JSON.stringify({
      clientId,
      deviceType: 'ANDROID',
      message: '',
      username,
    });

    try {
      this.mqttClient = mqtt.connect(url, {
        clientId,
        username,
        password,
        clean: true,
        reconnectPeriod: 15000,
        connectTimeout: 30000,
        rejectUnauthorized: false,
        // Tuya broker requires a will in the CONNECT packet to route DP
        // pushes — see note above. QoS 1, retain false, matches the app.
        will: {
          topic: willTopic,
          payload: willPayload,
          qos: 1,
          retain: false,
        },
      });

      this.mqttClient.on('connect', () => {
        this.mqttConnected = true;
        this.log.info('[TY] MQTT: connected to %s', brokerHost);
        // Subscribe to the user topic + one per-device topic for each
        // discovered device. The broker's ACL rejects wildcard filters
        // (`#`, `smart/mb/#`) with granted=128 (0x80), which mqtt.js treats
        // as a subscribe failure — so we subscribe only to exact topic
        // names. All entries here are exact (no wildcards), so SUBACK
        // returns granted=1 for each and delivery works.
        const topics = [userTopic, ...deviceTopics];
        this.mqttClient!.subscribe(topics, { qos: 1 }, (err, granted) => {
          if (err) {
            this.log.warn('[TY] MQTT: subscribe failed: %s', err);
          } else {
            this.log.info('[TY] MQTT: subscribed to %d topic(s)', topics.length);
            if (granted) {
              for (const g of granted) {
                this.log.info('[TY] MQTT: granted qos=%d for %s', g.qos, g.topic);
              }
            }
          }
        });
        // Notify platform so it can stop polling (MQTT is the source of truth)
        if (this.onMqttConnect) {
          this.onMqttConnect(true);
        }
      });

      this.mqttClient.on('message', (topic: string, payload: Buffer) => {
        this.log.info('[TY] MQTT: message on topic=%s (%d bytes)', topic, payload.length);
        this.handleMqttPayload(payload, topic);
      });

      this.mqttClient.on('close', () => {
        this.mqttConnected = false;
        this.log.info('[TY] MQTT: disconnected — falling back to polling');
        // Notify platform to restart polling
        if (this.onMqttConnect) {
          this.onMqttConnect(false);
        }
      });

      this.mqttClient.on('error', (err) => {
        this.log.warn('[TY] MQTT: error: %s', err.message);
      });

      // Protocol-level debug: log every MQTT packet sent/received so we can
      // see the exact CONNECT/CONNACK/SUBSCRIBE/SUBACK/PUBLISH flow when
      // diagnosing connection or message issues.
      this.mqttClient.on('packetsend', (packet) => {
        const p = packet as { cmd: string };
        const s = JSON.stringify(packet);
        this.log.info('[TY] MQTT >> %s: %s', p.cmd, s.length > 300 ? s.substring(0, 300) + '...' : s);
      });
      this.mqttClient.on('packetreceive', (packet) => {
        const p = packet as { cmd: string };
        const s = JSON.stringify(packet);
        this.log.info('[TY] MQTT << %s: %s', p.cmd, s.length > 300 ? s.substring(0, 300) + '...' : s);
      });
    } catch (e) {
      this.log.warn('[TY] MQTT: connection failed: %s', e);
    }
  }

  /**
   * Handle an incoming MQTT payload. Two formats are possible:
   *
   *  1. Plaintext JSON — starts with '{'. Some user-topic messages and the
   *     `tylink/` protocol use raw JSON. Parsed directly.
   *
   *  2. Tuya "Thing" protocol 2.2 binary frame — starts with the ASCII
   *     version tag "2.2" (bytes 0x32 0x2E 0x32). This is the format real-time
   *     DP pushes arrive in on `smart/mb/in/{devId}`. Frame layout (from the
   *     decompiled app, com.thingclips.sdk.mqtt.qbpppdb / MsgProtocol2_2):
   *
   *       [0:3]   = "2.2"               (protocol version, ASCII)
   *       [3:7]   = CRC32 of [7:end]    (little-endian int32)
   *       [7:11]  = sequence number     (int32)
   *       [11:15] = origin              (int32)
   *       [15:end]= AES-128-ECB/PKCS5-encrypted JSON, key = device localKey
   *
   *     The decrypted JSON has fields: `protocol`, `pv`, `gwId`, `t`, `data`
   *     (and sometimes `sign`). `data` holds the dps. We resolve the localKey
   *     from the topic's devId via the device-list cache (gateway localKey
   *     decrypts pushes for its sub-devices).
   */
  private handleMqttPayload(payload: Buffer, topic?: string): void {
    const prefix = payload.subarray(0, 3).toString('latin1');
    let msg: Record<string, unknown>;

    if (prefix === '2.2' || prefix === '2.3' || prefix === '2.1' || prefix === '1.1') {
      // Tuya Thing binary frame — decrypt with the topic device's localKey.
      this.log.info('[TY] MQTT: received %s binary frame on %s (%d bytes)',
        prefix, topic || '?', payload.length);
      try {
        msg = this.parseTuyaBinaryFrame(payload, topic);
        this.log.info('[TY] MQTT: %s frame decrypted: %s',
          prefix, JSON.stringify(msg).length > 300
            ? JSON.stringify(msg).substring(0, 300) + '...' : JSON.stringify(msg));
      } catch (e) {
        this.log.warn('[TY] MQTT: failed to decode %s frame on %s: %s',
          prefix, topic || '?', e);
        return;
      }
    } else {
      // Plaintext JSON (user topic, tylink/, etc.)
      const payloadStr = payload.toString('utf8');
      this.log.info('[TY] MQTT: received message on %s (%d bytes): %s',
        topic || '?', payload.length,
        payloadStr.length > 200 ? payloadStr.substring(0, 200) + '...' : payloadStr);
      try {
        msg = JSON.parse(payloadStr);
      } catch {
        this.log.warn('[TY] MQTT: unparseable non-JSON, non-binary payload on %s', topic || '?');
        return;
      }
    }

    this.handleMqttMessage(msg, topic);
  }

  /**
   * Parse a Tuya "Thing" protocol binary frame (version 2.2/2.3/2.1/1.1).
   * Decrypts the AES-128-ECB/PKCS5 encrypted body with the topic device's
   * localKey and returns the inner JSON object. CRC verification is skipped
   * (some pushes have a different CRC scheme; decryption success is the
   * real validity check).
   */
  private parseTuyaBinaryFrame(payload: Buffer, topic?: string): Record<string, unknown> {
    // The topic is `smart/mb/in/{devId}` (or a user/wildcard topic). The
    // devId is the segment after the last '/'. The localKey for that devId
    // decrypts the frame. For sub-device pushes, the devId is the GATEWAY
    // and the gateway's localKey is used.
    let devId: string | undefined;
    if (topic) {
      const lastSlash = topic.lastIndexOf('/');
      if (lastSlash >= 0 && lastSlash < topic.length - 1) {
        devId = topic.substring(lastSlash + 1);
      }
    }
    const localKey = devId ? this.localKeys.get(devId) : undefined;
    if (!localKey) {
      throw new Error(`no localKey for devId ${devId} (have ${this.localKeys.size} keys: ${Array.from(this.localKeys.keys()).map(k => k.slice(0,10)).join(',')})`);
    }
    if (payload.length < 15) {
      throw new Error(`frame too short (${payload.length} bytes)`);
    }
    // Encrypted body = bytes [15:end].
    const ct = payload.subarray(15);
    const key = Buffer.from(localKey, 'utf8');
    const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
    decipher.setAutoPadding(true);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return JSON.parse(pt.toString('utf8'));
  }

  /**
   * Handle a parsed MQTT message. Expected format (Tuya DP push):
   * {
   *   "t": 1718500000,
   *   "data": { "dps": { "106": "1", ... }, "dpsTime": {...} },
   *   "deviceId": "<device_id>",
   *   "gwId": "<gateway_id>",
   *   "protocol": 4,
   *   "type": "dp"
   * }
   */
  private handleMqttMessage(msg: Record<string, unknown>, topic?: string): void {
    // deviceId may be in the payload (msg.deviceId) OR derivable from the
    // topic. Per-device DP pushes arrive on `smart/mb/in/{devId}` — the
    // payload may or may not echo the deviceId, so fall back to the topic
    // suffix (the segment after the last '/'), matching the app's
    // topic2devId() helper (com.thingclips.sdk.mqtt.bqbppdq:5496).
    let deviceId = msg.deviceId as string | undefined;
    if (!deviceId && topic) {
      const lastSlash = topic.lastIndexOf('/');
      if (lastSlash >= 0 && lastSlash < topic.length - 1) {
        deviceId = topic.substring(lastSlash + 1);
      }
    }
    const data = msg.data as Record<string, unknown> | undefined;
    const protocol = msg.protocol as number;
    const msgType = msg.type as string;

    this.log.info('[TY] MQTT: parsed msg: deviceId=%s protocol=%s type=%s',
      deviceId || '(none)', protocol, msgType || '(none)');

    if (!deviceId || !data) {
      this.log.info('[TY] MQTT: skipping msg without deviceId/data');
      return;
    }

    // Only handle DP data changes (protocol=4 or type="dp").
    if (protocol !== 4 && msgType !== 'dp') {
      this.log.info('[TY] MQTT: skipping non-DP msg (protocol=%s type=%s)', protocol, msgType);
      return;
    }

    const dps = data.dps as Record<string, unknown> | undefined;
    if (!dps) {
      this.log.info('[TY] MQTT: msg has no dps field, data keys: %s', Object.keys(data).join(','));
      return;
    }

    // cid identifies the sub-device (mesh node) within a gateway push. The
    // topic devId is the GATEWAY; cid maps to the sub-device's nodeId.
    const cid = typeof data.cid === 'string' ? data.cid : undefined;

    this.log.info('[TY] MQTT: DP update for %s (cid=%s): %s',
      deviceId, cid || '-', JSON.stringify(dps));

    // Forward the parsed DPs to the platform callback.
    if (this.onStatusUpdate) {
      const dpsMap = new Map(Object.entries(dps));
      this.onStatusUpdate(deviceId, dpsMap, cid);
    }
  }

  /** Disconnect MQTT and clean up. */
  disconnectMqtt(): void {
    if (this.mqttReconnectTimer) {
      clearTimeout(this.mqttReconnectTimer);
      this.mqttReconnectTimer = null;
    }
    if (this.mqttClient) {
      this.mqttClient.end(true);
      this.mqttClient = null;
    }
    this.mqttConnected = false;
  }

  getMqttConnected(): boolean {
    return this.mqttConnected;
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

        // Verbose raw dump of the dp.get response — debug only (homebridge -D),
        // since it fires every poll cycle. Useful when diagnosing a device that
        // reports an unexpected state.
        this.log.debug('[TY] dp.get for %s (%s): %s',
          deviceId, device.name, JSON.stringify(statusResult));

        const dpsMap = new Map<string, unknown>();
        if (Array.isArray(statusResult)) {
          // Some Tuya clouds return [{code, value}, ...] for dp.get.
          for (const item of statusResult) {
            dpsMap.set(item.code, item.value);
          }
        } else if (statusResult.dps) {
          // Standard shape: {dps: {dpId: value, ...}}.
          for (const [key, value] of Object.entries(statusResult.dps)) {
            dpsMap.set(key, value);
          }
        } else if (statusResult && typeof statusResult === 'object') {
          // RainPoint TY private cloud returns dp.get as a FLAT object of
          // {dpId: value, ...} with NO wrapping `dps` key (e.g.
          // {"101":0,"104":false,"108":true,...}). Without this branch every
          // poll yields an empty dpsMap, so isOn is always false and manual
          // toggles never reflect in HomeKit. Treat the raw object as the dps
          // map when it has numeric-string keys and no `dps`/array shape.
          for (const [key, value] of Object.entries(statusResult)) {
            dpsMap.set(key, value);
          }
        }
        this.log.debug('[TY] %s parsed dps=%s',
          device.name, JSON.stringify(Object.fromEntries(dpsMap)));

        const zones: NormalizedZoneStatus[] = [];
        const switchDps = device.zoneSwitchDps;
        const zoneDps = device.zoneDps;
        for (let port = 1; port <= device.portNumber; port++) {
          // Valve state is read from the per-zone WorkStatus DP (run-state enum,
          // "1"=running) resolved from thing.m.product.thing.model. The switch DP
          // (104/155) is a "valve installed" config flag that stays false while
          // running — reading it always reported OFF.
          //
          // WorkStatus is an enum; "1" = running, anything else = idle. RemainTime
          // (or LeftTime on single-zone products) is the remaining minutes; HomeKit
          // expects seconds so we ×60.
          //
          // Fallback when zoneDps is absent (no thing.model): use the empirical
          // +offset from the switch DP (run = switch+2, remain = switch+3). This
          // is only correct for the 1-zone product ew946yrp3pgbaziu and is WRONG
          // for multi-zone (zone 2 WorkStatus is 153, not switchDp+2). The schema
          // path above is authoritative.
          const zd = zoneDps?.[port - 1];
          const runDp = zd?.workStatus ?? (switchDps?.[port - 1] !== undefined ? switchDps[port - 1]! + 2 : undefined);
          const remainingDp = zd?.remainTime ?? (switchDps?.[port - 1] !== undefined ? switchDps[port - 1]! + 3 : undefined);
          const runValue = runDp !== undefined ? dpsMap.get(String(runDp)) : undefined;
          const isOn = String(runValue) === '1';

          const remainingMin = remainingDp !== undefined
            ? Number(dpsMap.get(String(remainingDp)))
            : NaN;
          const remaining = Number.isFinite(remainingMin) && remainingMin > 0
            ? Math.round(remainingMin * 60)
            : 0;

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
    // RainPoint TY valve control — VERIFIED semantics (live test 2026-06-20):
    //   ManualSwitch = false  → START the valve
    //   ManualSwitch = true   → STOP the valve
    //   ManualTimer = N       → run duration in minutes (sets the countdown)
    // The "switch" is INVERTED (false=on). Writing true when it's already true is a
    // no-op — earlier attempts failed because 108 was stuck at true from a prior
    // stop. To start reliably we set ManualTimer=N AND ManualSwitch=false together.
    //
    // gwId must be the parent gateway's devId for sub-devices (qqddbpb.smali
    // dp.publish requires gwId + devId + dps; gwId==devId for sub-devices is silently
    // accepted but never reaches the device).
    const device = this.deviceCache.get(deviceId);
    const zoneDp = device?.zoneDps?.[port - 1];
    const manualTimerDp = zoneDp?.manualTimer
      ?? (this.resolveSwitchDp(deviceId, port) + 3);
    const manualSwitchDp = zoneDp?.manualSwitch;
    const gwId = this.resolveGwId(deviceId);
    // HomeKit SetDuration is in SECONDS; ManualTimer is in MINUTES (typeSpec max 60).
    // Convert seconds→minutes, clamp to [1,60]. Default 10 min if no duration.
    const durationMin = durationSeconds
      ? Math.min(60, Math.max(1, Math.round(durationSeconds / 60)))
      : 10;
    // START = ManualTimer=N + ManualSwitch=false (the false is what triggers the run).
    const dps: Record<string, unknown> = { [String(manualTimerDp)]: durationMin };
    if (manualSwitchDp) {
      dps[String(manualSwitchDp)] = false;
    }
    // The accessory layer logs the user-facing "Setting <zone> to ON" at info;
    // this lower-level dp detail is debug only to avoid duplicating every toggle.
    this.log.debug('[TY] dp.publish ON: devId=%s gwId=%s port=%d dps=%s',
      deviceId, gwId, port, JSON.stringify(dps));
    const result = await this.request('thing.m.device.dp.publish', {
      gwId,
      devId: deviceId,
      dps: JSON.stringify(dps),
    });
    this.log.debug('[TY] dp.publish ON result for %s: %s', deviceId, JSON.stringify(result));
  }

  async turnZoneOff(deviceId: string, port: number): Promise<void> {
    // STOP = ManualSwitch=true + ManualTimer=0 (clear the countdown).
    const device = this.deviceCache.get(deviceId);
    const zoneDp = device?.zoneDps?.[port - 1];
    const manualTimerDp = zoneDp?.manualTimer
      ?? (this.resolveSwitchDp(deviceId, port) + 3);
    const gwId = this.resolveGwId(deviceId);
    const dps: Record<string, unknown> = { [String(manualTimerDp)]: 0 };
    if (zoneDp?.manualSwitch) {
      dps[String(zoneDp.manualSwitch)] = true;
    }
    this.log.debug('[TY] dp.publish OFF: devId=%s gwId=%s port=%d dps=%s',
      deviceId, gwId, port, JSON.stringify(dps));
    const result = await this.request('thing.m.device.dp.publish', {
      gwId,
      devId: deviceId,
      dps: JSON.stringify(dps),
    });
    this.log.debug('[TY] dp.publish OFF result for %s: %s', deviceId, JSON.stringify(result));
  }

  /**
   * Resolve the gateway devId for a dp.publish command. RainPoint TY irrigation
   * zones are sub-devices of a parent gateway; the cloud forwards the DP to the
   * gateway, which relays it to the sub-device. If the cached device has a
   * parentId, use it; otherwise the device is its own gateway (gwId == devId).
   */
  private resolveGwId(deviceId: string): string {
    const device = this.deviceCache.get(deviceId);
    if (device?.parentId) {
      return device.parentId;
    }
    return deviceId;
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
