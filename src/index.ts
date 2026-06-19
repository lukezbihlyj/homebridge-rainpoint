import { API } from 'homebridge';

import { PLATFORM_NAME } from './settings';
import { RainPointPlatform } from './platform';

export = (api: API) => {
  api.registerPlatform(PLATFORM_NAME, RainPointPlatform);
};