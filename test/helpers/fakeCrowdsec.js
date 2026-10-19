// -----------------------------------------------------------------------------
// An in-memory CrowdSec Local API, starting from the real answers of CrowdSec
// v1.8.1 (test/fixtures/crowdsec), behaving like the Docker test did: the
// stream of a bouncer key (full, then deltas), the machine login (refused with
// the `node` User-Agent, as the real LAPI does), the alerts, the deletion.
// -----------------------------------------------------------------------------

import { readFileSync } from 'node:fs';

export const BASE = 'http://192.0.2.10:8080';
export const API_KEY = 'test-bouncer-key';
export const MACHINE = { id: 'gladys', password: 'test-machine-password' };

const fixture = (name) =>
  JSON.parse(readFileSync(new URL(`../fixtures/crowdsec/${name}`, import.meta.url), 'utf8'));

export const FIXTURES = {
  startup: fixture('stream-startup.json'),
  delta: fixture('stream-delta.json'),
  alerts: fixture('alerts-24h.json'),
  community: fixture('stream-community.json'),
  login: fixture('login.json'),
};

const json = (status, data) => ({ status, body: JSON.stringify(data) });

export class FakeCrowdsec {
  constructor({ decisions = FIXTURES.startup.new, alerts = FIXTURES.alerts } = {}) {
    /** @type {Map<number, object>} active decisions, raw */
    this.decisions = new Map(structuredClone(decisions).map((d) => [d.id, d]));
    this.alerts = structuredClone(alerts);
    /** ids the bouncer already received */
    this.delivered = new Set();
    this.nextId = Math.max(0, ...this.decisions.keys()) + 1;
    this.nextAlertId = Math.max(0, ...this.alerts.map((a) => a.id)) + 1;
    /** 'down': the server does not answer; a number: that HTTP status. */
    this.failure = null;
    this.machineRefused = false;
    this.requests = [];
    this.tokens = 0;
  }

  /** Add a decision, as a scenario or cscli would; returns it. */
  addDecision({ value, scenario = 'crowdsecurity/ssh-bf', type = 'ban', origin = 'crowdsec' }) {
    const decision = {
      duration: '3h59m59s',
      id: this.nextId++,
      origin,
      scenario,
      scope: value.includes('/') ? 'Range' : 'Ip',
      type,
      uuid: `00000000-0000-4000-8000-${String(this.nextId).padStart(12, '0')}`,
      value,
    };
    this.decisions.set(decision.id, decision);
    return decision;
  }

  /** A decision and its alert, with a country, as a scenario of CrowdSec. */
  attack({ value, scenario = 'crowdsecurity/ssh-bf', country = 'NL', asName = 'EXAMPLE-AS' }) {
    const decision = this.addDecision({ value, scenario });
    const now = new Date().toISOString();
    this.alerts.unshift({
      capacity: 5,
      created_at: now,
      decisions: [{ ...decision, simulated: false }],
      events_count: 6,
      id: this.nextAlertId++,
      kind: 'crowdsec',
      scenario,
      simulated: false,
      source: { as_name: asName, cn: country, ip: value, scope: 'Ip', value },
      start_at: now,
      stop_at: now,
    });
    return decision;
  }

  /** Community blocklist: `count` CAPI decisions. */
  addCommunity(count) {
    for (let i = 0; i < count; i += 1) {
      this.addDecision({
        value: `198.18.${Math.floor(i / 250)}.${(i % 250) + 1}`,
        scenario: 'crowdsecurity/http-probing',
        origin: 'CAPI',
      });
    }
  }

  remove(id) {
    this.decisions.delete(id);
  }

  /** The request seam of src/crowdsec/client.js. */
  request = async (url, { method = 'GET', headers = {}, body } = {}) => {
    this.requests.push({ url, method, headers });
    if (this.failure === 'down') {
      const error = new TypeError('fetch failed');
      error.cause = { code: 'ECONNREFUSED' };
      throw error;
    }
    if (typeof this.failure === 'number') {
      return { status: this.failure, body: '' };
    }
    const { pathname, searchParams } = new URL(url);
    if (pathname === '/v1/decisions/stream' && method === 'GET') {
      if (headers['x-api-key'] !== API_KEY) {
        return json(403, { message: 'access forbidden' });
      }
      const active = [...this.decisions.values()];
      if (searchParams.get('startup') === 'true') {
        this.delivered = new Set(active.map((d) => d.id));
        return json(200, { new: active, deleted: [] });
      }
      const added = active.filter((d) => !this.delivered.has(d.id));
      const deleted = [...this.delivered]
        .filter((id) => !this.decisions.has(id))
        .map((id) => ({ duration: '-1s', id, origin: 'cscli', scope: 'Ip', type: 'ban' }));
      this.delivered = new Set(active.map((d) => d.id));
      return json(200, {
        new: added.length ? added : null,
        deleted: deleted.length ? deleted : [],
      });
    }
    if (pathname === '/v1/watchers/login' && method === 'POST') {
      const input = JSON.parse(body);
      if (
        this.machineRefused ||
        !/^[\w.-]+\/[\w.-]+/.test(headers['user-agent'] ?? '') ||
        input.machine_id !== MACHINE.id ||
        input.password !== MACHINE.password
      ) {
        return json(401, { code: 401, message: 'incorrect Username or Password' });
      }
      this.tokens += 1;
      return json(200, { ...FIXTURES.login, token: `token-${this.tokens}` });
    }
    const token = headers.authorization === `Bearer token-${this.tokens}` && this.tokens > 0;
    if (pathname === '/v1/alerts' && method === 'GET') {
      if (!token) {
        return json(401, { code: 401, message: 'cookie token is empty' });
      }
      return json(200, this.alerts);
    }
    if (pathname === '/v1/decisions' && method === 'DELETE') {
      if (!token) {
        return json(401, { code: 401, message: 'cookie token is empty' });
      }
      const target = searchParams.get('ip') ?? searchParams.get('range');
      const ids = [...this.decisions.values()].filter((d) => d.value === target).map((d) => d.id);
      ids.forEach((id) => this.decisions.delete(id));
      return json(200, { nbDeleted: String(ids.length) });
    }
    return json(404, { message: 'Page or Method not found' });
  };
}
