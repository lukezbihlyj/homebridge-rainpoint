export interface RainPointConfig {
  name?: string;
  email: string;
  password: string;
  /** Region for RainPoint Home provider (US or CN). */
  regionHome?: string;
  /** Region for RainPoint TY (Tuya) provider (AZ, EU, IN, or CN). */
  regionTy?: string;
  /** @deprecated use regionHome/regionTy. Kept for backward compat only. */
  region?: string;
  homeIndex?: number;
  pollInterval?: number;
  flatValves?: boolean;
  debugmode?: boolean;
}

export interface BaseResponse<T> {
  code: number;
  msg: string;
  data: T;
  ts: number;
}

export interface LoginInfo {
  token: string;
  refreshToken: string;
  tokenExpired: number;
  user: User;
}

export interface User {
  uid: string;
  areaCode: string;
  phone: string;
  email: string;
  nickname: string;
  photo: string;
  iotId: string;
  productKey: string;
  deviceName: string;
  deviceSecret: string;
  isocode: string;
  lang: string;
  agreementVer: string;
  log: number;
  notice: number;
  config: string;
  tmpEmail: string;
}

export interface TokenResponse {
  token: string;
  refreshToken: string;
  tokenExpired: number;
}

export interface Home {
  hid: string;
  homeName: string;
  homeVersion: number;
  address: string;
  config: string;
  currency: number;
  tempUnit: number;
  lengthUnit: number;
  timeUnit: number;
  volumeUnit: number;
}

export interface MainDevice {
  hid: string;
  mid: string;
  did: string;
  iotId: string;
  productKey: string;
  deviceName: string;
  model: string;
  modelCode: number;
  pcode: number;
  portNumber: number;
  name: string;
  displayModel: string;
  style: string;
  function: string;
  param: string;
  paramVersion: number;
  mac: string;
  mac1: string;
  softVer: string;
  soft1Ver: string;
  enabled: number;
  createTime: number;
  planJson: string;
  portDescribe: string;
  recich: number;
  attributeKv: DeviceAttribute[];
  subDevices: SubDevice[];
  alerts: unknown[];
}

export interface SubDevice {
  sid: string;
  mid: string;
  addr: number;
  did: string;
  iotId: string;
  productKey: string;
  deviceName: string;
  pcode: number;
  modelCode: number;
  name: string;
  model: string;
  displayModel: string;
  softVer: string;
  portDescribe: string;
  param: string;
  style: string;
  function: string;
  portNumber: number;
  alerts: unknown[];
  mac: string;
  paramVersion: number;
  attributeKv: DeviceAttribute[];
  planJson: string;
  enabled: number;
}

export interface DeviceAttribute {
  dpId: number;
  dpCode: number;
  dpType: number;
  dpPort: number;
  identity: string;
  value: string;
}

export interface DeviceStatus {
  MID: string;
  iotId: string;
  state: string;
  propVer: string;
  connected: string;
  D01: string;
  D02: string;
  D03: string;
  D04: string;
  D05: string;
  D06: string;
  D07: string;
  D08: string;
  D09: string;
  D10: string;
  D11: string;
  D12: string;
  D13: string;
  D14: string;
  D15: string;
  D16: string;
  D17: string;
  D18: string;
  D19: string;
  D20: string;
  D21: string;
  D22: string;
  D23: string;
  D24: string;
  D25: string;
  D26: string;
  D27: string;
  D28: string;
  D29: string;
  D30: string;
  D31: string;
  D32: string;
  D33: string;
  D34: string;
  D35: string;
  D36: string;
  D37: string;
  D38: string;
  D39: string;
  D40: string;
  D41: string;
  softVer: string;
  recich: number;
  updateTime: Record<string, number>;
  timeDiff: number;
  onlineTimeStamp: number;
  [key: string]: string | number | Record<string, number>;
}

export interface MultipleDeviceStatus {
  mid: string;
  iotId: string;
  propVer: string;
  status: QueryDParam[];
}

export interface QueryDParam {
  id: string;
  time: number;
  value: string;
}

export interface DParam {
  time: number;
  value: string;
}

export interface ControlResponse {
  state: string;
  timestamp: number;
}

export interface RealtimeStateResponse {
  timestamp: number;
  state: string;
  expire: number;
}

export interface SubscribeRequest {
  hid: string;
  hidList: string[];
  subscribe: SubscribeDevice[];
  unsubscribe: SubscribeDevice[];
  userInfo: SubUserInfo;
}

export interface SubscribeDevice {
  mid: string;
  productKey: string;
  deviceName: string;
}

export interface SubUserInfo {
  deviceName: string;
  productKey: string;
  pushId: string;
  deviceType: number;
  notice: number;
}

export interface ControlWorkModeParams {
  mid: string;
  productKey: string;
  deviceName: string;
  mode: number;
  addr: number;
  port: number;
  param: string;
  duration: number;
}

export interface ControlWorkModeDPParams {
  mid: string;
  productKey: string;
  deviceName: string;
  mode: number;
  addr: number;
  port: number;
  param: string;
  dpCode: number;
}

export interface RecDeviceModel {
  model: string;
  modelCode: number;
  productCode: number;
  portNumber: number;
  displayModel: string;
  panelId: string;
  productCategory: string;
  productBrand: string;
  productColumn: number;
  sceneType: number;
  subDeviceType: number;
  accessoryFlag: boolean;
  hasDistribution: boolean;
  isMainDevice: boolean;
  infoEnabled: number;
  sort: number;
  supportSmart: number;
  distributionName: string;
  defaultSubDevice: DefaultSubDevice[];
  supportedSubDevice: number[];
  productImage: unknown[];
  dp: RecDeviceDpModel[];
}

export interface DefaultSubDevice {
  modelCode: number;
  name: string;
  addr: number;
  pcode: number;
  portNumber: number;
  isDefault: boolean;
}

export interface RecDeviceDpModel {
  dpId: number;
  dpCode: number;
  dpPort: number;
  dpType: number;
  dpFlags: number;
  identity: string;
  endpoint: number;
  require: number;
  specs: RecDeviceDpSpec;
}

export interface RecDeviceDpSpec {
  identity: string;
  dataType: number;
  dataTypeSub: number;
  length: number;
  mask: number;
  min: number;
  max: number;
  step: number;
  decimal: number;
  defaultValue: string;
  unit: number;
  require: number;
  langField: string;
  enums: RecDeviceDpSpecEnum[];
  bit: RecDeviceDpSpec[];
  child: RecDeviceDpSpec[];
  input: RecDeviceDpSpec[];
  output: RecDeviceDpSpec[];
  item: RecDeviceDpSpec[];
}

export interface RecDeviceDpSpecEnum {
  lang: string;
  param: string;
  value: number;
}

export interface ParsedDpStatus {
  dpId: number;
  typeCode: number;
  typeLen: number;
  typeValue: number[];
}

export interface DeviceZoneInfo {
  port: number;
  name: string;
  isOn: boolean;
  workMode: number;
  remainingDuration: number;
  moisture: number | null;
  temperature: number | null;
  battery: number | null;
}