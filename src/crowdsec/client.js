// -----------------------------------------------------------------------------
// CrowdSec Local API (LAPI) client, checked against CrowdSec v1.8.1:
//
//   bouncer key (header X-Api-Key), read-only:
//     GET /v1/decisions/stream?dedup=false&startup=true   every active decision
//     GET /v1/decisions/stream                what changed since the last call
//                                             of this bouncer: { new, deleted }
//   machine account (optional):
//     POST /v1/watchers/login                 { machine_id, password } → JWT
//     GET  /v1/alerts?since=24h&include_capi=false
//     DELETE /v1/decisions?ip=…&contains=false (or range=…) → { nbDeleted: "1" }
//
// A decision is { id, origin, type, scope, value, scenario, duration, uuid };
// `duration` is the time left, in Go notation ("3h59m50s", "-4s" once over).
// The stream is the way bouncers are meant to follow decisions: one full
// answer, then small deltas, even with a community blocklist of tens of
// thousands of addresses.
//
// Pitfall: the LAPI refuses the machine login (401 "incorrect Username or
// Password") when the User-Agent is `node`, Node's default for fetch. A
// `name/version` User-Agent is accepted: every request sends one.
// -----------------------------------------------------------------------------

import { readFileSync } from 'node:fs';

export const ERROR_KINDS = Object.freeze({
  UNREACHABLE: 'unreachable', // no answer: down, wrong address, firewall
  TLS: 'tls', // the certificate does not verify
  AUTH: 'auth', // the bouncer key is refused
  MACHINE_AUTH: 'machine_auth', // the machine login or password is refused
  NOT_CROWDSEC: 'not_crowdsec', // something answers, not the LAPI
  HTTP: 'http', // any other HTTP error
});

export class CrowdsecError extends Error {
  /**
   * @param {string} kind one of ERROR_KINDS
   * @param {string} message English, for the logs (never contains a secret)
   * @param {object} [extra] { status }
   */
  constructor(kind, message, extra = {}) {
    super(message);
    this.name = 'CrowdsecError';
    this.kind = kind;
    Object.assign(this, extra);
  }
}

const TLS_CODES = new Set([
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'CERT_HAS_EXPIRED',
  'ERR_TLS_CERT_ALTNAME_INVALID',
]);

// The first answer of the stream holds the community blocklist: about 200
// bytes per address, a few MB for the largest lists.
export const MAX_BODY_BYTES = 32 * 1024 * 1024;

const VERSION = (() => {
  try {
    return JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).version;
  } catch {
    return '0';
  }
})();
export const USER_AGENT = `gladys-crowdsec/${VERSION}`;

/**
 * The one function that talks to the network (fetch). The client takes it as
 * a parameter: the tests replace it with an in-memory LAPI
 * (test/helpers/fakeCrowdsec.js).
 * @returns {Promise<{ status: number, body: string }>}
 */
export async function httpRequest(url, { method = 'GET', headers = {}, body, timeoutMs = 15_000 }) {
  const response = await fetch(url, {
    method,
    headers,
    body,
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs),
  });
  const length = Number(response.headers.get('content-length') ?? 0);
  if (length > MAX_BODY_BYTES) {
    await response.body?.cancel();
    throw new Error('Response too large');
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body ?? []) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      await response.body.cancel().catch(() => {});
      throw new Error('Response too large');
    }
    chunks.push(chunk);
  }
  return { status: response.status, body: Buffer.concat(chunks).toString('utf8') };
}

/**
 * A Go duration ("3h59m50.12s", "56m", "-4s") in milliseconds, null when not
 * understood.
 */
export function parseDuration(text) {
  if (typeof text !== 'string') {
    return null;
  }
  const match = text
    .trim()
    .match(/^(-)?(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m(?!s))?(?:(\d+(?:\.\d+)?)s)?$/);
  if (!match || !(match[2] || match[3] || match[4])) {
    return null;
  }
  const ms =
    (Number(match[2] ?? 0) * 3600 + Number(match[3] ?? 0) * 60 + Number(match[4] ?? 0)) * 1000;
  return match[1] ? -ms : ms;
}

// Origins of the decisions CrowdSec did not take on this installation: the
// community blocklist (CAPI) and the third-party blocklists of the console.
export const COMMUNITY_ORIGINS = new Set(['capi', 'lists']);
export const isCommunity = (origin) => COMMUNITY_ORIGINS.has(String(origin).toLowerCase());

const str = (value, max = 255) => (typeof value === 'string' ? value.slice(0, max) : '');

/**
 * A decision of the stream, normalized; null when unusable.
 * @param {object} raw
 * @param {number} receivedAt when the answer arrived (ms), to turn the time
 *   left into an end date
 */
export function normalizeDecision(raw, receivedAt) {
  if (!raw || typeof raw !== 'object' || !Number.isInteger(raw.id)) {
    return null;
  }
  const left = parseDuration(raw.duration);
  return {
    id: raw.id,
    origin: str(raw.origin, 64),
    type: str(raw.type, 64),
    scope: str(raw.scope, 64),
    value: str(raw.value, 128),
    scenario: str(raw.scenario),
    until: left === null ? null : receivedAt + left,
  };
}

/**
 * An alert, kept small (no events); null for the community and blocklist
 * alerts (one per pull, with thousands of decisions).
 */
export function normalizeAlert(raw) {
  if (!raw || typeof raw !== 'object' || !Number.isInteger(raw.id)) {
    return null;
  }
  const decisions = Array.isArray(raw.decisions) ? raw.decisions : [];
  const sourceScope = str(raw.source?.scope).toLowerCase();
  if (
    decisions.some((decision) => isCommunity(decision?.origin)) ||
    sourceScope.startsWith('lists:') ||
    sourceScope === 'community blocklist'
  ) {
    return null;
  }
  const time = (value) => {
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : null;
  };
  return {
    id: raw.id,
    scenario: str(raw.scenario),
    value: str(raw.source?.value ?? raw.source?.ip, 128),
    scope: str(raw.source?.scope, 64),
    country: str(raw.source?.cn, 8),
    asName: str(raw.source?.as_name, 128),
    eventsCount: Number.isInteger(raw.events_count) ? raw.events_count : 0,
    simulated: raw.simulated === true,
    createdAt: time(raw.created_at),
    startAt: time(raw.start_at) ?? time(raw.created_at),
    decisionIds: decisions.map((decision) => decision?.id).filter(Number.isInteger),
  };
}

export class CrowdsecClient {
  /**
   * @param {object} options
   * @param {string} options.url base URL, `http(s)://host[:port][/path]`
   * @param {string} options.apiKey bouncer key
   * @param {string} [options.machineId] machine account, for the alerts
   * @param {string} [options.machinePassword]
   * @param {typeof httpRequest} [options.request] test seam
   * @param {() => number} [options.now]
   */
  constructor({ url, apiKey, machineId = '', machinePassword = '', request, now }) {
    this.url = url;
    this.apiKey = apiKey;
    this.machineId = machineId;
    this.machinePassword = machinePassword;
    this.request = request ?? httpRequest;
    this.now = now ?? (() => Date.now());
    this.token = null;
    this.tokenExpires = 0;
  }

  get hasMachine() {
    return Boolean(this.machineId && this.machinePassword);
  }

  async send(path, { method = 'GET', headers = {}, body, authKind = ERROR_KINDS.AUTH } = {}) {
    let response;
    try {
      response = await this.request(`${this.url}${path}`, {
        method,
        headers: { accept: 'application/json', 'user-agent': USER_AGENT, ...headers },
        body,
        timeoutMs: 15_000,
      });
    } catch (err) {
      const code = err.cause?.code ?? err.code;
      if (TLS_CODES.has(code)) {
        throw new CrowdsecError(ERROR_KINDS.TLS, `Certificate refused (${code})`);
      }
      throw new CrowdsecError(ERROR_KINDS.UNREACHABLE, code ?? err.name ?? err.message);
    }
    const { status } = response;
    if (status === 401 || status === 403) {
      throw new CrowdsecError(authKind, `Credentials refused (HTTP ${status})`, { status });
    }
    if (status === 404 || (status >= 300 && status < 400)) {
      throw new CrowdsecError(
        ERROR_KINDS.NOT_CROWDSEC,
        `No CrowdSec Local API at this address (HTTP ${status})`,
        { status },
      );
    }
    if (status < 200 || status >= 300) {
      throw new CrowdsecError(ERROR_KINDS.HTTP, `Unexpected answer (HTTP ${status})`, { status });
    }
    try {
      return JSON.parse(response.body);
    } catch {
      throw new CrowdsecError(ERROR_KINDS.NOT_CROWDSEC, `The answer of ${path} is not JSON`);
    }
  }

  /**
   * The decision stream: every active decision with `startup`, else what
   * changed since the previous call of this bouncer key.
   * @returns {Promise<{ added: object[], deleted: object[] }>}
   */
  async stream({ startup = false } = {}) {
    // dedup=false: by default the LAPI sends one decision per address (the
    // longest), hiding a local ban behind a community one.
    const data = await this.send(
      `/v1/decisions/stream?dedup=false${startup ? '&startup=true' : ''}`,
      {
        headers: { 'x-api-key': this.apiKey },
      },
    );
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new CrowdsecError(ERROR_KINDS.NOT_CROWDSEC, 'The answer is not a decision stream');
    }
    const receivedAt = this.now();
    const list = (value) =>
      (Array.isArray(value) ? value : [])
        .map((raw) => normalizeDecision(raw, receivedAt))
        .filter(Boolean);
    // An empty list comes as null.
    return { added: list(data.new), deleted: list(data.deleted) };
  }

  async login() {
    const data = await this.send('/v1/watchers/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ machine_id: this.machineId, password: this.machinePassword }),
      authKind: ERROR_KINDS.MACHINE_AUTH,
    });
    if (typeof data?.token !== 'string') {
      throw new CrowdsecError(ERROR_KINDS.NOT_CROWDSEC, 'The login answer holds no token');
    }
    this.token = data.token;
    const expires = Date.parse(data.expire);
    // Renewed a minute before it expires (one hour by default).
    this.tokenExpires = (Number.isFinite(expires) ? expires : this.now() + 3600_000) - 60_000;
  }

  /** A request with the machine token, logged in again once when it expired. */
  async machineSend(path, options = {}) {
    for (let attempt = 0; ; attempt += 1) {
      if (!this.token || this.now() >= this.tokenExpires) {
        await this.login();
      }
      try {
        return await this.send(path, {
          ...options,
          headers: { authorization: `Bearer ${this.token}` },
          authKind: ERROR_KINDS.MACHINE_AUTH,
        });
      } catch (err) {
        if (err.kind === ERROR_KINDS.MACHINE_AUTH && attempt === 0) {
          this.token = null; // revoked or LAPI restarted with a new secret
          continue;
        }
        throw err;
      }
    }
  }

  /**
   * The alerts started since `since` (Go duration: "24h", "1h"), without the
   * community ones.
   */
  async alerts(since) {
    const data = await this.machineSend(
      `/v1/alerts?since=${encodeURIComponent(since)}&include_capi=false&limit=1000`,
    );
    if (data !== null && !Array.isArray(data)) {
      throw new CrowdsecError(ERROR_KINDS.NOT_CROWDSEC, 'The answer is not a list of alerts');
    }
    return (data ?? []).map(normalizeAlert).filter(Boolean);
  }

  /**
   * Delete the decisions on an address (`ip`) or a range (`range`).
   * @returns {Promise<number>} how many were deleted
   */
  async deleteDecisions({ ip, range }) {
    // contains=false: the decisions on this address, or inside this range.
    // The default (true) deletes the ones containing it instead: nothing for
    // a range, and a whole range ban for an address.
    const query = ip ? `ip=${encodeURIComponent(ip)}` : `range=${encodeURIComponent(range)}`;
    const data = await this.machineSend(`/v1/decisions?${query}&contains=false`, {
      method: 'DELETE',
    });
    const count = Number(data?.nbDeleted);
    return Number.isFinite(count) ? count : 0;
  }
}
