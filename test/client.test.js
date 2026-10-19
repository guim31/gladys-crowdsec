// -----------------------------------------------------------------------------
// The LAPI client on the real answers of CrowdSec v1.8.1 (test/fixtures):
// stream, alerts, login, deletion, durations and the errors the user can meet.
// -----------------------------------------------------------------------------

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CrowdsecClient,
  ERROR_KINDS,
  USER_AGENT,
  normalizeAlert,
  parseDuration,
} from '../src/crowdsec/client.js';
import { parseServerUrl } from '../src/config.js';
import { API_KEY, BASE, FIXTURES, FakeCrowdsec, MACHINE } from './helpers/fakeCrowdsec.js';

const NOW = Date.UTC(2026, 9, 19, 19, 52, 0);

function clientOf(crowdsec, machine = true) {
  return new CrowdsecClient({
    url: BASE,
    apiKey: API_KEY,
    machineId: machine ? MACHINE.id : '',
    machinePassword: machine ? MACHINE.password : '',
    request: crowdsec.request,
    now: () => NOW,
  });
}

test('Go durations', () => {
  assert.equal(parseDuration('3h59m50s'), (3 * 3600 + 59 * 60 + 50) * 1000);
  assert.equal(parseDuration('56m56s'), (56 * 60 + 56) * 1000);
  assert.equal(parseDuration('167h59m10.5s'), (167 * 3600 + 59 * 60 + 10.5) * 1000);
  assert.equal(parseDuration('-4s'), -4000);
  assert.equal(parseDuration('45m'), 45 * 60_000);
  assert.equal(parseDuration('5ms'), null);
  assert.equal(parseDuration(''), null);
  assert.equal(parseDuration(undefined), null);
});

test('the stream: full at startup, then the deltas, with end dates', async () => {
  const crowdsec = new FakeCrowdsec();
  const client = clientOf(crowdsec);
  const full = await client.stream({ startup: true });
  assert.deepEqual(
    full.added.map((d) => [d.id, d.origin, d.type, d.scope, d.value]),
    [
      [2, 'cscli', 'captcha', 'Range', '198.51.100.0/24'],
      [3, 'crowdsec', 'ban', 'Ip', '203.0.113.7'],
      [4, 'crowdsec', 'ban', 'Ip', '203.0.113.7'],
      [5, 'cscli', 'ban', 'Ip', '192.0.2.50'],
    ],
  );
  assert.equal(full.added[0].until, NOW + (56 * 60 + 56) * 1000);
  const empty = await client.stream();
  assert.deepEqual(empty, { added: [], deleted: [] }, 'null lists read as empty');
  const request = crowdsec.requests.at(-1);
  assert.equal(request.headers['x-api-key'], API_KEY);
  assert.equal(request.headers['user-agent'], USER_AGENT);
});

test('the real delta: a new ban and an expired one', async () => {
  const client = new CrowdsecClient({
    url: BASE,
    apiKey: API_KEY,
    request: async () => ({ status: 200, body: JSON.stringify(FIXTURES.delta) }),
    now: () => NOW,
  });
  const delta = await client.stream();
  assert.deepEqual(
    delta.added.map((d) => [d.id, d.scenario, d.value]),
    [[6, 'crowdsecurity/ssh-bf', '203.0.113.9']],
  );
  assert.deepEqual(
    delta.deleted.map((d) => d.id),
    [5],
  );
});

test('alerts: the real ones, small, and the community ones left out', async () => {
  const alerts = FIXTURES.alerts.map(normalizeAlert);
  assert.equal(alerts.length, 5);
  const ssh = alerts.find((a) => a.id === 3);
  assert.deepEqual(ssh, {
    id: 3,
    scenario: 'crowdsecurity/ssh-bf',
    value: '203.0.113.7',
    scope: 'Ip',
    country: '',
    asName: '',
    eventsCount: 6,
    simulated: false,
    createdAt: Date.parse('2026-10-19T19:48:52Z'),
    startAt: Date.parse('2026-10-19T21:50:01Z'),
    decisionIds: [3],
  });
  assert.equal(
    normalizeAlert({
      id: 9,
      scenario: 'update : +15000/-0 IPs',
      source: { scope: 'Community blocklist', value: '' },
      decisions: [{ id: 101, origin: 'CAPI' }],
    }),
    null,
  );
  assert.equal(normalizeAlert({ id: 10, source: { scope: 'lists:firehol' } }), null);
});

test('the machine login: a name/version User-Agent, one token reused', async () => {
  const crowdsec = new FakeCrowdsec();
  const client = clientOf(crowdsec);
  await client.alerts('24h');
  await client.alerts('1h');
  assert.equal(crowdsec.tokens, 1);
  const login = crowdsec.requests.find((r) => r.url.endsWith('/v1/watchers/login'));
  assert.match(login.headers['user-agent'], /^gladys-crowdsec\/\d+\.\d+\.\d+$/);
  // A token refused (LAPI restarted): logged in again, once.
  crowdsec.tokens += 1;
  const alerts = await client.alerts('1h');
  assert.equal(alerts.length, 5);
  assert.equal(crowdsec.tokens, 3);
});

test('the machine refused: a machine_auth error, not a bouncer one', async () => {
  const crowdsec = new FakeCrowdsec();
  crowdsec.machineRefused = true;
  await assert.rejects(clientOf(crowdsec).alerts('24h'), { kind: ERROR_KINDS.MACHINE_AUTH });
});

test('deleting decisions counts what the LAPI says', async () => {
  const crowdsec = new FakeCrowdsec();
  const client = clientOf(crowdsec);
  assert.equal(await client.deleteDecisions({ ip: '203.0.113.7' }), 2);
  assert.equal(await client.deleteDecisions({ ip: '203.0.113.7' }), 0);
  assert.equal(await client.deleteDecisions({ range: '198.51.100.0/24' }), 1);
});

test('errors: unreachable, key refused, not a LAPI, TLS', async () => {
  const crowdsec = new FakeCrowdsec();
  crowdsec.failure = 'down';
  await assert.rejects(clientOf(crowdsec).stream(), { kind: ERROR_KINDS.UNREACHABLE });
  crowdsec.failure = null;
  const wrongKey = new CrowdsecClient({ url: BASE, apiKey: 'nope', request: crowdsec.request });
  await assert.rejects(wrongKey.stream(), { kind: ERROR_KINDS.AUTH });
  const other = new CrowdsecClient({
    url: BASE,
    apiKey: API_KEY,
    request: async () => ({ status: 200, body: '<html>router</html>' }),
  });
  await assert.rejects(other.stream(), { kind: ERROR_KINDS.NOT_CROWDSEC });
  const notFound = new CrowdsecClient({
    url: BASE,
    apiKey: API_KEY,
    request: async () => ({ status: 404, body: '' }),
  });
  await assert.rejects(notFound.stream(), { kind: ERROR_KINDS.NOT_CROWDSEC });
  const tls = new CrowdsecClient({
    url: BASE,
    apiKey: API_KEY,
    request: async () => {
      const error = new TypeError('fetch failed');
      error.cause = { code: 'DEPTH_ZERO_SELF_SIGNED_CERT' };
      throw error;
    },
  });
  await assert.rejects(tls.stream(), { kind: ERROR_KINDS.TLS });
});

test('the address typed by the user', () => {
  assert.equal(parseServerUrl('192.0.2.10:8080'), 'http://192.0.2.10:8080');
  assert.equal(parseServerUrl('http://192.0.2.10:8080/'), 'http://192.0.2.10:8080');
  assert.equal(parseServerUrl('https://lapi.example.org/v1'), 'https://lapi.example.org');
  assert.equal(parseServerUrl('https://example.org/crowdsec/'), 'https://example.org/crowdsec');
  assert.equal(parseServerUrl('http://user:pass@192.0.2.10:8080'), null);
  assert.equal(parseServerUrl('ftp://192.0.2.10'), null);
  assert.equal(parseServerUrl('   '), null);
});
