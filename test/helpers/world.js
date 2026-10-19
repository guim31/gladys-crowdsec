// -----------------------------------------------------------------------------
// A complete test world: the SDK's fake Gladys, a fake CrowdSec LAPI, a
// temporary /data and a manual clock, with the integration wired on top
// through registerHandlers. No timer runs: the tests read the LAPI with
// `world.hub.pollNow()`. (Adapted from guim31/gladys-traefik.)
// -----------------------------------------------------------------------------

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFakeGladys } from '@gladysassistant/integration-sdk/testing';
import { registerHandlers } from '../../src/app.js';
import { lapiIds } from '../../src/devices.js';
import { Store } from '../../src/store.js';
import { API_KEY, BASE, FIXTURES, FakeCrowdsec, MACHINE } from './fakeCrowdsec.js';

// The integration logs every change; keep the test output readable.
process.env.LOG_LEVEL ??= 'silent';

// The fixtures were recorded on 19/10/2026 around 19:50 UTC.
export function createClock(start = Date.UTC(2026, 9, 19, 19, 52, 0)) {
  const clock = {
    time: start,
    now: () => clock.time,
    advance(ms) {
      clock.time += ms;
    },
  };
  return clock;
}

export const MACHINE_CONFIG = {
  machine_id: MACHINE.id,
  machine_password: MACHINE.password,
};

export async function createWorld({
  clock = createClock(),
  crowdsec = new FakeCrowdsec(),
  config = {},
  machine = true,
  devices = [],
  connect = true,
  dataDir = mkdtempSync(join(tmpdir(), 'gladys-crowdsec-')),
  timings = {},
  timers = false,
} = {}) {
  const gladys = createFakeGladys({
    config: {
      url: BASE,
      api_key: API_KEY,
      language: 'en',
      ...(machine ? MACHINE_CONFIG : {}),
      ...config,
    },
    devices,
  });
  const app = registerHandlers(gladys, {
    store: new Store(dataDir),
    request: crowdsec.request,
    timers,
    timings,
    now: clock.now,
  });
  if (connect) {
    await gladys.connect();
    await app.ready;
  }
  return { gladys, fake: gladys.fake, crowdsec, app, hub: app.hub, clock, dataDir };
}

export const idsOf = (world) => lapiIds(world.gladys);

/** Add the discovered device in Gladys, as the user would. */
export async function createDevices(world) {
  for (const device of world.fake.discoveredDevices) {
    await world.fake.deviceCreated(device);
  }
}

export { API_KEY, BASE, FIXTURES, FakeCrowdsec, MACHINE };
