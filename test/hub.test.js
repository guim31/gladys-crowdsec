// -----------------------------------------------------------------------------
// The hub against the SDK's fake Gladys and a fake LAPI: discovery, states,
// new decisions and alerts as scene events, persistence across restarts,
// errors, quiet logs, the widget, the scene actions and the reading timer of
// the container.
// -----------------------------------------------------------------------------

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { validateWidgetContent } from '@gladysassistant/integration-sdk';
import { KEYS } from '../src/devices.js';
import { MAX_EVENTS_PER_READ, TRIGGERS, WIDGET_KEY, maskAddress, parseTarget } from '../src/hub.js';
import { ACTIONS } from '../src/widgets.js';
import { FakeCrowdsec, createClock, createDevices, createWorld, idsOf } from './helpers/world.js';

const events = (world, key) => world.fake.sceneEvents.filter((event) => event.key === key);
const state = (world, key) => world.fake.lastState(idsOf(world).feature(key));

async function captureLogs(t, level, fn) {
  const lines = [];
  const write = (chunk) => {
    lines.push(...String(chunk).split('\n').filter(Boolean));
    return true;
  };
  const before = process.env.LOG_LEVEL;
  process.env.LOG_LEVEL = level;
  const stdout = t.mock.method(process.stdout, 'write', write);
  const stderr = t.mock.method(process.stderr, 'write', write);
  try {
    await fn();
  } finally {
    stdout.mock.restore();
    stderr.mock.restore();
    process.env.LOG_LEVEL = before;
  }
  return lines;
}

test('one CrowdSec device in Discovery, alerts only with a machine account', async (t) => {
  const world = await createWorld();
  t.after(() => world.app.stop());
  const [device] = world.fake.discoveredDevices;
  assert.equal(device.name, 'CrowdSec');
  assert.equal(device.should_poll, false);
  assert.deepEqual(
    device.features.map((f) => f.external_id.split(':').pop()),
    ['reachable', 'local_decisions', 'community_decisions', 'alerts_24h', 'last_scenario'],
  );
  assert.equal(world.fake.connectionStatus.connected, true);
  assert.equal(world.fake.sceneEvents.length, 0, 'what is already there is not news');

  const bouncerOnly = await createWorld({ machine: false });
  t.after(() => bouncerOnly.app.stop());
  assert.ok(
    !bouncerOnly.fake.discoveredDevices[0].features.some((f) =>
      f.external_id.endsWith('alerts_24h'),
    ),
  );
});

test('the states at once when the device is added, then only the changes', async (t) => {
  const world = await createWorld();
  t.after(() => world.app.stop());
  assert.equal(world.fake.states.length, 0, 'nothing published before the device is added');
  await createDevices(world);
  assert.equal(state(world, KEYS.REACHABLE), 1);
  assert.equal(state(world, KEYS.LOCAL_DECISIONS), 4);
  assert.equal(state(world, KEYS.COMMUNITY_DECISIONS), 0);
  assert.equal(state(world, KEYS.ALERTS_24H), 5);
  assert.equal(state(world, KEYS.LAST_SCENARIO), 'manual test', 'the latest alert');
  assert.deepEqual(
    world.fake.transports.map((e) => e.transport),
    ['local'],
  );
  assert.ok(world.fake.widgetRefreshes.length > 0);

  const before = world.fake.states.length;
  await world.hub.pollNow();
  assert.equal(world.fake.states.length, before, 'nothing changed, nothing sent');
  // The second read is a delta of the stream, not the full list.
  const streams = world.crowdsec.requests.filter((r) => r.url.includes('/stream'));
  assert.match(streams.at(-1).url, /\/v1\/decisions\/stream$/);

  world.crowdsec.addCommunity(3);
  await world.hub.pollNow();
  assert.equal(state(world, KEYS.COMMUNITY_DECISIONS), 3);
  assert.equal(events(world, TRIGGERS.DECISION_ADDED).length, 0, 'community is not local');
});

test('a new attack: a decision with its country, and an alert', async (t) => {
  const world = await createWorld();
  t.after(() => world.app.stop());
  await createDevices(world);
  world.crowdsec.attack({ value: '203.0.113.50', scenario: 'crowdsecurity/http-probing' });
  await world.hub.pollNow();
  const [decision] = events(world, TRIGGERS.DECISION_ADDED);
  assert.deepEqual(decision.data, {
    ip: '203.0.113.50',
    scope: 'Ip',
    type: 'ban',
    scenario: 'crowdsecurity/http-probing',
    origin: 'crowdsec',
    duration_minutes: 240,
    country: 'NL',
  });
  const [alert] = events(world, TRIGGERS.ALERT_RAISED);
  assert.deepEqual(alert.data, {
    scenario: 'crowdsecurity/http-probing',
    ip: '203.0.113.50',
    scope: 'Ip',
    country: 'NL',
    as_name: 'EXAMPLE-AS',
    events_count: 6,
    decisions: 1,
  });
  assert.equal(state(world, KEYS.LOCAL_DECISIONS), 5);
  assert.equal(state(world, KEYS.ALERTS_24H), 6);
  assert.equal(state(world, KEYS.LAST_SCENARIO), 'crowdsecurity/http-probing');

  await world.hub.pollNow();
  assert.equal(events(world, TRIGGERS.DECISION_ADDED).length, 1, 'announced once');
  assert.equal(events(world, TRIGGERS.ALERT_RAISED).length, 1, 'announced once');
});

test('a decision added by hand, without machine account: no country, still announced', async (t) => {
  const world = await createWorld({ machine: false });
  t.after(() => world.app.stop());
  world.crowdsec.addDecision({ value: '192.0.2.77', scenario: 'manual', origin: 'cscli' });
  await world.hub.pollNow();
  const [decision] = events(world, TRIGGERS.DECISION_ADDED);
  assert.equal(decision.data.country, '');
  assert.equal(decision.data.origin, 'cscli');
  assert.equal(events(world, TRIGGERS.ALERT_RAISED).length, 0);
});

test('a deleted or expired decision leaves the counts', async (t) => {
  const clock = createClock();
  const world = await createWorld({ clock });
  t.after(() => world.app.stop());
  await createDevices(world);
  world.crowdsec.remove(5);
  await world.hub.pollNow();
  assert.equal(state(world, KEYS.LOCAL_DECISIONS), 3);
  // The captcha on the range ends after 56 minutes, even if a delta is lost.
  clock.advance(58 * 60_000);
  world.crowdsec.delivered.add(999); // a stream that says nothing about it
  await world.hub.pollNow();
  assert.equal(state(world, KEYS.LOCAL_DECISIONS), 2);
});

test('a restart announces what was added meanwhile, once, and nothing else', async (t) => {
  const crowdsec = new FakeCrowdsec();
  const first = await createWorld({ crowdsec });
  await first.app.stop();
  crowdsec.addDecision({ value: '203.0.113.60' });
  const second = await createWorld({ crowdsec, dataDir: first.dataDir });
  await second.app.stop();
  const added = events(second, TRIGGERS.DECISION_ADDED);
  assert.deepEqual(
    added.map((e) => e.data.ip),
    ['203.0.113.60'],
  );
  assert.equal(events(second, TRIGGERS.ALERT_RAISED).length, 0);

  const third = await createWorld({ crowdsec, dataDir: first.dataDir });
  t.after(() => third.app.stop());
  assert.equal(third.fake.sceneEvents.length, 0, 'not twice');
});

test('another LAPI address starts afresh: no event for what it already has', async (t) => {
  const first = await createWorld();
  await first.app.stop();
  const second = await createWorld({
    dataDir: first.dataDir,
    config: { url: 'http://192.0.2.11:8080' },
    crowdsec: new FakeCrowdsec(),
  });
  t.after(() => second.app.stop());
  // The fake answers on any host: the same decisions, but another LAPI.
  assert.equal(second.fake.sceneEvents.length, 0);
});

test('a flood of decisions fires at most MAX_EVENTS_PER_READ events', async (t) => {
  const world = await createWorld({ machine: false });
  t.after(() => world.app.stop());
  for (let i = 1; i <= 40; i += 1) {
    world.crowdsec.addDecision({ value: `203.0.113.${100 + i}` });
  }
  await world.hub.pollNow();
  const added = events(world, TRIGGERS.DECISION_ADDED);
  assert.equal(added.length, MAX_EVENTS_PER_READ);
  assert.equal(added.at(-1).data.ip, '203.0.113.140', 'the latest ones');
});

test('the LAPI unreachable: one failed read tolerated, then reachable 0, back with a full read', async (t) => {
  const world = await createWorld();
  t.after(() => world.app.stop());
  await createDevices(world);
  world.crowdsec.failure = 'down';
  await world.hub.pollNow();
  assert.equal(state(world, KEYS.REACHABLE), 1);
  assert.equal(world.fake.connectionStatus.connected, false);
  await world.hub.pollNow();
  assert.equal(state(world, KEYS.REACHABLE), 0);
  assert.equal(world.fake.transports.at(-1).transport, 'unreachable');
  world.crowdsec.failure = null;
  await world.hub.pollNow();
  assert.equal(state(world, KEYS.REACHABLE), 1);
  assert.equal(world.fake.transports.at(-1).transport, 'local');
  const streams = world.crowdsec.requests.filter((r) => r.url.includes('/stream'));
  assert.match(streams.at(-1).url, /startup=true/, 'a lost delta is read again in full');
});

test('a wrong key, a wrong machine password: readable statuses, decisions still followed', async (t) => {
  const wrongKey = await createWorld({ config: { api_key: 'nope' } });
  t.after(() => wrongKey.app.stop());
  assert.equal(wrongKey.fake.connectionStatus.connected, false);
  assert.match(wrongKey.fake.connectionStatus.message.en, /bouncer key refused/);

  const crowdsec = new FakeCrowdsec();
  crowdsec.machineRefused = true;
  const wrongMachine = await createWorld({ crowdsec });
  t.after(() => wrongMachine.app.stop());
  await createDevices(wrongMachine);
  assert.equal(wrongMachine.fake.connectionStatus.connected, true);
  assert.equal(state(wrongMachine, KEYS.LOCAL_DECISIONS), 4);
  assert.equal(state(wrongMachine, KEYS.ALERTS_24H), undefined);
  const ack = await wrongMachine.fake.action('test_connection');
  assert.match(ack.data.message.en, /machine login or password refused/);
});

test('configuration missing or wrong: a readable status, no request', async (t) => {
  for (const [config, pattern] of [
    [{ url: '' }, /Enter the address/],
    [{ url: 'ftp://x' }, /Address not understood/],
    [{ api_key: '' }, /bouncer key/],
  ]) {
    const crowdsec = new FakeCrowdsec();
    const world = await createWorld({ config, crowdsec });
    t.after(() => world.app.stop());
    assert.equal(world.fake.connectionStatus.connected, false);
    assert.match(world.fake.connectionStatus.message.en, pattern);
    assert.equal(crowdsec.requests.length, 0);
  }
});

test('a normal reading cycle writes nothing at the info level, never a full address', async (t) => {
  const world = await createWorld();
  t.after(() => world.app.stop());
  await createDevices(world);
  const lines = await captureLogs(t, 'info', async () => {
    for (let cycle = 0; cycle < 4; cycle += 1) {
      world.crowdsec.attack({ value: `203.0.113.${200 + cycle}` });
      world.clock.advance(60_000);
      await world.hub.pollNow();
    }
  });
  assert.equal(events(world, TRIGGERS.DECISION_ADDED).length, 4);
  assert.deepEqual(lines, []);
});

test('a lasting failure writes one line per change, never a secret', async (t) => {
  const world = await createWorld();
  t.after(() => world.app.stop());
  world.crowdsec.failure = 'down';
  const lines = await captureLogs(t, 'info', async () => {
    for (let cycle = 0; cycle < 5; cycle += 1) {
      await world.hub.pollNow();
    }
    world.crowdsec.failure = null;
    await world.hub.pollNow();
  });
  assert.equal(lines.length, 3, lines.join('\n')); // the error, unreachable, connected
  const text = lines.join('\n');
  assert.ok(!text.includes('test-bouncer-key') && !text.includes('test-machine-password'));
});

test('the widget: tiles, latest decisions first, within the budget', async (t) => {
  const world = await createWorld();
  t.after(() => world.app.stop());
  world.crowdsec.attack({ value: '203.0.113.50' });
  await world.hub.pollNow();
  const ack = await world.fake.widgetGet(WIDGET_KEY, { language: 'fr' });
  assert.equal(ack.success, true, ack.error);
  const content = ack.data.content;
  assert.deepEqual(validateWidgetContent(content), []);
  assert.ok(content.components.length <= 8);
  const tiles = content.components.filter((c) => c.type === 'value');
  assert.deepEqual(
    tiles.map((c) => [c.label, c.value]),
    [
      ['Locales', 5],
      ['Communauté', 0],
      ['Alertes 24 h', 6],
    ],
  );
  const rows = content.components.find((c) => c.type === 'status').items;
  assert.equal(rows[0].label, '203.0.113.50');
  assert.equal(rows[0].value, 'ssh-bf · 4 h 0');
  const captcha = rows.find((r) => r.label === '198.51.100.0/24');
  assert.equal(captcha.icon, 'help-circle');
  assert.match(captcha.value, /… · 57 min$/, 'a long scenario is cut, not the time left');
  assert.ok(captcha.value.length <= 40);

  const refreshed = await world.fake.widgetAction(WIDGET_KEY, ACTIONS.REFRESH);
  assert.equal(refreshed.success, true, refreshed.error);
});

test('the widget when CrowdSec does not answer, and with no decision', async (t) => {
  const world = await createWorld({ crowdsec: new FakeCrowdsec({ decisions: [], alerts: [] }) });
  t.after(() => world.app.stop());
  let content = (await world.fake.widgetGet(WIDGET_KEY)).data.content;
  assert.ok(content.components.some((c) => c.type === 'text' && /nobody/.test(c.text)));
  world.crowdsec.failure = 'down';
  await world.hub.pollNow();
  content = (await world.fake.widgetGet(WIDGET_KEY)).data.content;
  assert.ok(content.components.some((c) => c.type === 'text' && /does not answer/.test(c.text)));
  assert.deepEqual(validateWidgetContent(content), []);
});

test('scene action: the state of CrowdSec in a sentence, unreachable as an answer', async (t) => {
  const world = await createWorld({ config: { language: 'fr' } });
  t.after(() => world.app.stop());
  const ack = await world.fake.sceneAction('get_status');
  assert.equal(ack.success, true, ack.error);
  assert.deepEqual(ack.data.outputs, {
    reachable: true,
    local_decisions: 4,
    community_decisions: 0,
    alerts_24h: 5,
    last_ip: '192.0.2.50',
    last_scenario: 'manual test',
    sentence:
      'CrowdSec : 4 décision(s) locale(s), 0 décision(s) de la communauté, 5 alerte(s) en 24 h (192.0.2.50, manual test).',
  });
  world.crowdsec.failure = 'down';
  world.clock.advance(60_000);
  const down = await world.fake.sceneAction('get_status');
  assert.equal(down.data.outputs.reachable, false);
  assert.equal(down.data.outputs.sentence, 'CrowdSec : CrowdSec ne répond pas.');
});

test('scene action: unban refused unless enabled, with a machine account and an address', async (t) => {
  const disabled = await createWorld();
  t.after(() => disabled.app.stop());
  let ack = await disabled.fake.sceneAction('delete_decision', { ip: '192.0.2.50' });
  assert.equal(ack.success, false);
  assert.match(ack.error, /disabled/);

  const noMachine = await createWorld({ machine: false, config: { allow_unban: 'enabled' } });
  t.after(() => noMachine.app.stop());
  ack = await noMachine.fake.sceneAction('delete_decision', { ip: '192.0.2.50' });
  assert.match(ack.error, /machine account/);

  const world = await createWorld({ config: { allow_unban: 'enabled' } });
  t.after(() => world.app.stop());
  ack = await world.fake.sceneAction('delete_decision', { ip: 'not-an-ip' });
  assert.match(ack.error, /Not an IP address/);
  ack = await world.fake.sceneAction('delete_decision', { ip: ' 203.0.113.7 ' });
  assert.equal(ack.success, true, ack.error);
  assert.deepEqual(ack.data.outputs, {
    deleted: 2,
    sentence: 'CrowdSec: 2 decision(s) deleted on 203.0.113.7.',
  });
  assert.equal(world.hub.local.size, 2, 'read again after the deletion');
  ack = await world.fake.sceneAction('delete_decision', { ip: '198.51.100.0/24' });
  assert.equal(ack.data.outputs.deleted, 1);
  const deletes = world.crowdsec.requests.filter((r) => r.method === 'DELETE');
  assert.match(deletes.at(-1).url, /\?range=198\.51\.100\.0%2F24$/);
});

test('"Test the connection" sums up CrowdSec in the four languages', async (t) => {
  const world = await createWorld({ machine: false });
  t.after(() => world.app.stop());
  const ack = await world.fake.action('test_connection');
  assert.equal(ack.success, true, ack.error);
  assert.deepEqual(Object.keys(ack.data.message), ['en', 'fr', 'de', 'es']);
  assert.equal(
    ack.data.message.en,
    'CrowdSec: Connected, 4 local decision(s), 0 community decision(s), no machine account: no alerts',
  );
});

test('the internal timer reads the LAPI and publishes the changes, without any poll from Gladys', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const world = await createWorld({ timers: true, config: { poll_interval: '30' } });
  t.after(() => world.app.stop());
  world.crowdsec.addDecision({ value: '203.0.113.70' });
  t.mock.timers.tick(30_000);
  await new Promise((resolve) => setImmediate(resolve));
  for (let i = 0; i < 20 && events(world, TRIGGERS.DECISION_ADDED).length === 0; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.equal(events(world, TRIGGERS.DECISION_ADDED).length, 1);
});

test('a damaged /data file does not block the reads', async (t) => {
  const first = await createWorld();
  await first.app.stop();
  writeFileSync(join(first.dataDir, 'crowdsec-state.json'), '{"lastDecisionId": "x", ');
  const world = await createWorld({ dataDir: first.dataDir });
  t.after(() => world.app.stop());
  assert.equal(world.fake.connectionStatus.connected, true);
  assert.equal(world.fake.sceneEvents.length, 0);
});

test('addresses: masked for the logs, parsed for the unban action', () => {
  assert.equal(maskAddress('203.0.113.7'), '203.0.113.x');
  assert.equal(maskAddress('198.51.100.0/24'), '198.51.100.x/24');
  assert.equal(maskAddress('2001:db8:1:2::5'), '2001:db8:…');
  assert.deepEqual(parseTarget('203.0.113.7'), { ip: '203.0.113.7' });
  assert.deepEqual(parseTarget('2001:db8::/32'), { range: '2001:db8::/32' });
  assert.equal(parseTarget('203.0.113.0/33'), null);
  assert.equal(parseTarget('example.org'), null);
  assert.equal(parseTarget(undefined), null);
});
