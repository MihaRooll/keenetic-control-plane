import * as overview from './overview.js';
import * as connection from './connection.js';
import * as internetUplink from './internet-uplink.js';
import * as staffWifi from './staff-wifi.js';
import * as guestWifi from './guest-wifi.js';
import * as vpn from './vpn.js';
import * as domain from './domain.js';
import * as entryPages from './entry-pages.js';
import * as diagnostics from './diagnostics.js';
import * as showcase from './showcase.js';

/** Экраны в порядке бокового меню. */
export const menuScreens = [
  overview,
  connection,
  internetUplink,
  staffWifi,
  guestWifi,
  vpn,
  domain,
  entryPages,
  diagnostics,
];

/** Служебная витрина — только по прямому хешу. */
export const showcaseScreen = showcase;

/** @type {Record<string, typeof overview>} */
export const screenMap = Object.fromEntries(
  menuScreens.map((screen) => [screen.meta.id, screen]),
);

export { overview, connection, internetUplink, staffWifi, guestWifi, vpn, domain, entryPages, diagnostics, showcase };
