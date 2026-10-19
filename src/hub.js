// -----------------------------------------------------------------------------
// The CrowdSec hub: the Local API read on a timer of the container (the
// interval chosen in the configuration); the states of the device published
// when they change, the scene events fired for each new local decision and
// alert, and the views the widget and the scene actions read.
//
// Decisions follow the stream of the bouncer key: every active decision at
// the first read (and again every hour, and after any failed read, so that a
// lost delta never lingers), then the deltas. Alerts (machine account only)
// are read for the last 24 hours once an hour, and for the last hour at the
// other reads, merged by id.
//
// Gladys never polls the device (should_poll: false): the interval goes up to
// 5 minutes, beyond the fixed list of the core scheduler, and the scene events
// must fire whether the device is added or not.
//
// The highest decision and alert ids already seen are kept in /data
// (src/store.js): what happened while the integration restarted is still
// announced, once. Full addresses are logged at the debug level only.
// -----------------------------------------------------------------------------

import { DEVICE_TRANSPORTS, createLogger } from '@gladysassistant/integration-sdk';
import { isIP } from 'node:net';
import { buildLapiDevice, lapiIds, lapiValues } from './devices.js';
import { CrowdsecClient, CrowdsecError, ERROR_KINDS, isCommunity } from './crowdsec/client.js';
import { hostOf, normalizeConfig } from './config.js';
import { ProblemLog } from './problems.js';
import { ACTION_TEXT, CONNECTION_TEXT, ERROR_TEXT, REPORT_TEXT, labelled, pick } from './texts.js';

const logger = createLogger({ name: 'crowdsec-hub' });

export const WIDGET_KEY = 'decisions';

// Scene trigger keys (manifest `scene_triggers`): permanent once published.
export const TRIGGERS = Object.freeze({
  DECISION_ADDED: 'decision_added',
  ALERT_RAISED: 'alert_raised',
});

export const HUB_TIMINGS = {
  // An unchanged value is sent again this often: Gladys shows "no recent
  // value" after 48 hours.
  heartbeatMs: 12 * 3600_000,
  // A scene action reads the LAPI again when the last read is older.
  freshMs: 15_000,
  // Every active decision is read again this often (the stream otherwise).
  fullSyncMs: 3600_000,
};

export const ALERT_WINDOW_MS = 24 * 3600_000;

// Failed reads in a row before the LAPI counts as unreachable: a restart of
// CrowdSec (a few seconds) does not flip the device.
export const FAILURES_BEFORE_UNREACHABLE = 2;

// Scene events per kind and per read, at most: a scan that bans hundreds of
// addresses at once must not send hundreds of notifications.
export const MAX_EVENTS_PER_READ = 20;

const object = (value) => (value && typeof value === 'object' ? value : {});
const integer = (value) => (Number.isInteger(value) && value >= 0 ? value : 0);

/**
 * An address for the info logs: the last part hidden ("203.0.113.x",
 * "2001:db8:…").
 */
export function maskAddress(value) {
  const text = String(value ?? '');
  const [address, prefix] = text.split('/');
  let masked;
  if (isIP(address) === 4) {
    masked = address.replace(/\.\d+$/, '.x');
  } else if (isIP(address) === 6) {
    masked = `${address.split(':').slice(0, 2).join(':')}:…`;
  } else {
    masked = '…';
  }
  return prefix === undefined ? masked : `${masked}/${prefix}`;
}

/** An IP address or a CIDR range typed by the user; null when it is neither. */
export function parseTarget(raw) {
  const text = typeof raw === 'string' ? raw.trim() : '';
  const [address, prefix, extra] = text.split('/');
  const version = isIP(address ?? '');
  if (!version || extra !== undefined) {
    return null;
  }
  if (prefix === undefined) {
    return { ip: address };
  }
  const bits = Number(prefix);
  if (!/^\d+$/.test(prefix) || bits > (version === 4 ? 32 : 128)) {
    return null;
  }
  return { range: `${address}/${bits}` };
}

/** Minutes left of a decision, 0 when unknown. */
export const minutesLeft = (decision, now) =>
  decision.until === null ? 0 : Math.max(0, Math.round((decision.until - now) / 60_000));

export class CrowdsecHub {
  /**
   * @param {object} options
   * @param {object} options.gladys GladysIntegration (or the SDK's fake Gladys)
   * @param {object} options.store persistence (src/store.js)
   * @param {Function} [options.request] HTTP seam (src/crowdsec/client.js)
   * @param {boolean} [options.timers] the reading timer (off in tests)
   * @param {object} [options.timings] HUB_TIMINGS overrides
   * @param {() => number} [options.now]
   */
  constructor({ gladys, store, request, timers = true, timings, now }) {
    this.gladys = gladys;
    this.store = store;
    this.request = request;
    this.timersEnabled = timers;
    this.timings = { ...HUB_TIMINGS, ...timings };
    this.now = now ?? (() => Date.now());
    // Defaults until start(): a handler reached after a failed start still
    // answers with a readable message.
    this.config = normalizeConfig({});
    this.client = null;
    this.signature = null;
    this.machineSignature = null;
    this.resetReads();
    this.transport = null;
    this.connection = null;
    this.discovered = null;
    this.saved = { initialized: false, reachable: null, lastDecisionId: 0, lastAlertId: 0 };
    this.pollTimer = null;
    this.stopped = false;
    // What fails again at every cycle (Gladys refusing, the reading loop, the
    // alerts): one line when it starts, one when it ends.
    this.problems = new ProblemLog(logger);
  }

  /** Forget everything read from the LAPI (another address or key). */
  resetReads() {
    /** @type {Map<number, object>} active local decisions, by id */
    this.local = new Map();
    /** @type {Map<number, number|null>} active community decisions: id → end */
    this.community = new Map();
    this.synced = false;
    this.fullSyncAt = 0;
    this.readAt = 0;
    this.error = null;
    this.failures = 0;
    this.polling = null;
    this.resetAlerts();
  }

  resetAlerts() {
    /** @type {Map<number, object>} alerts of the last 24 hours, by id */
    this.alerts = new Map();
    this.alertsReadAt = 0;
    this.alertsFullAt = 0;
    this.alertsError = null;
  }

  // --- Lifecycle -------------------------------------------------------------

  async start(config) {
    const saved = object(await this.store.load());
    this.saved = {
      initialized: saved.initialized === true,
      alertsInitialized: saved.alertsInitialized === true,
      reachable: typeof saved.reachable === 'boolean' ? saved.reachable : null,
      lastDecisionId: integer(saved.lastDecisionId),
      lastAlertId: integer(saved.lastAlertId),
      lastScenario: typeof saved.lastScenario === 'string' ? saved.lastScenario : '',
      url: typeof saved.url === 'string' ? saved.url : null,
    };
    await this.reconfigure(config);
  }

  /** Gladys reconnected (it restarted): send everything again. */
  async resync(config) {
    this.gladys.forgetPublishedStates?.();
    this.transport = null;
    this.connection = null;
    this.discovered = null;
    await this.reconfigure(config);
  }

  async reconfigure(config) {
    const languageChanged = this.signature !== null && this.config.language !== config.language;
    this.config = config;
    const signature = JSON.stringify([config.url, config.apiKey]);
    const machineSignature = JSON.stringify([config.machineId, config.machinePassword]);
    if (signature !== this.signature || machineSignature !== this.machineSignature) {
      const sameLapi = signature === this.signature;
      this.signature = signature;
      this.machineSignature = machineSignature;
      this.client =
        config.url && config.apiKey
          ? new CrowdsecClient({
              url: config.url,
              apiKey: config.apiKey,
              machineId: config.machineId,
              machinePassword: config.machinePassword,
              request: this.request,
              now: this.now,
            })
          : null;
      if (sameLapi) {
        // Only the machine account changed: the decisions stay, but the
        // stream of the new client starts again from a full read.
        this.synced = false;
        this.resetAlerts();
      } else {
        this.resetReads();
      }
      this.discovered = null; // "Alerts (24 h)" may come or go
      // Another LAPI: what was saved about the previous one means nothing.
      if (config.url && this.saved.url !== config.url) {
        this.saved = {
          initialized: false,
          alertsInitialized: false,
          reachable: null,
          lastDecisionId: 0,
          lastAlertId: 0,
          lastScenario: '',
          url: config.url,
        };
      }
    }
    if (languageChanged) {
      this.discovered = null; // new feature names for the Discovery tab
    }
    try {
      if (this.client) {
        await this.pollNow({ publish: true });
      } else {
        await this.afterChanges(true, { publish: true });
      }
    } finally {
      this.schedulePoll();
    }
  }

  async stop() {
    this.stopped = true;
    clearTimeout(this.pollTimer);
    await this.store.flush();
  }

  schedulePoll() {
    clearTimeout(this.pollTimer);
    if (!this.timersEnabled || this.stopped || !this.client) {
      return;
    }
    this.pollTimer = setTimeout(async () => {
      try {
        await this.pollNow();
        this.problems.recover('poll', 'Reading CrowdSec works again');
      } catch (err) {
        this.problems.fail('poll', `Poll failed: ${err.message}`, 'error');
      }
      this.schedulePoll();
    }, this.config.pollIntervalMs);
  }

  // --- Reading the LAPI ------------------------------------------------------

  /** Read the LAPI now and publish what changed. */
  async pollNow({ publish = false } = {}) {
    const changed = await this.poll();
    await this.afterChanges(changed, { publish });
  }

  /** Read again when the last read is older than `freshMs` (scene actions). */
  async refreshIfStale() {
    if (this.client && this.now() - this.readAt >= this.timings.freshMs) {
      await this.pollNow();
    }
  }

  /**
   * Read the LAPI and apply what changed. Concurrent calls share the read.
   * @returns {Promise<boolean>} whether the widget shows something new
   */
  poll() {
    if (!this.client) {
      return Promise.resolve(false);
    }
    if (!this.polling) {
      const polling = this.read(this.client).finally(() => {
        // A read of a previous client must not drop the promise of the current one.
        if (this.polling === polling) {
          this.polling = null;
        }
      });
      this.polling = polling;
    }
    return this.polling;
  }

  async read(client) {
    const now = this.now();
    const startup = !this.synced || now - this.fullSyncAt >= this.timings.fullSyncMs;
    let delta;
    try {
      delta = await client.stream({ startup });
    } catch (err) {
      if (!(err instanceof CrowdsecError)) {
        throw err;
      }
      return client === this.client && this.applyFailure(err);
    }
    if (client !== this.client) {
      return false;
    }
    const alerts = client.hasMachine ? await this.readAlerts(client, now) : null;
    if (client !== this.client) {
      return false;
    }
    return this.applySuccess({ delta, startup, alerts });
  }

  /**
   * The alerts since the last hour (the last day once an hour). A failure is
   * kept apart: the decisions still count.
   * @returns {Promise<{ list: object[], full: boolean }|null>}
   */
  async readAlerts(client, now) {
    const full = this.alertsFullAt === 0 || now - this.alertsFullAt >= this.timings.fullSyncMs;
    try {
      const list = await client.alerts(full ? '24h' : '1h');
      if (this.alertsError) {
        logger.info('CrowdSec alerts can be read again');
      }
      this.alertsError = null;
      return { list, full };
    } catch (err) {
      if (!(err instanceof CrowdsecError)) {
        throw err;
      }
      if (this.alertsError?.kind !== err.kind) {
        logger.warn(`CrowdSec alerts: ${err.message}`);
      }
      this.alertsError = { kind: err.kind, message: err.message };
      return null;
    }
  }

  /** Whether the LAPI counts as reachable (after a few failed reads in a row). */
  get reachable() {
    return this.synced && this.saved.reachable !== false;
  }

  /** Whether the alerts count is known (machine account that works). */
  get alertsKnown() {
    return Boolean(this.client?.hasMachine) && this.alertsReadAt > 0 && !this.alertsError;
  }

  async applySuccess({ delta, startup, alerts }) {
    // Everything below up to the scene events is synchronous: a configuration
    // change cannot slip between the reading and the saved state it updates.
    const saved = this.saved;
    const client = this.client;
    const now = this.now();
    // The return is logged with the connection status ("Connected to…").
    let widgetChanged = this.error !== null || !this.synced;
    let dirty = saved.reachable !== true || !saved.initialized;
    const initialized = saved.initialized;
    this.error = null;
    this.failures = 0;
    saved.reachable = true;
    this.readAt = now;

    // Decisions.
    const before = JSON.stringify([[...this.local.keys()], this.community.size]);
    if (startup) {
      this.local = new Map();
      this.community = new Map();
      this.fullSyncAt = now;
    }
    for (const decision of delta.deleted) {
      this.local.delete(decision.id);
      this.community.delete(decision.id);
    }
    const added = [];
    let maxId = 0;
    for (const decision of delta.added) {
      maxId = Math.max(maxId, decision.id);
      if (decision.until !== null && decision.until <= now) {
        continue;
      }
      if (isCommunity(decision.origin)) {
        this.community.set(decision.id, decision.until);
      } else {
        this.local.set(decision.id, decision);
        added.push(decision);
      }
    }
    // The stream says when a decision expires; this covers a lost delta.
    for (const [id, decision] of this.local) {
      if (decision.until !== null && decision.until <= now) {
        this.local.delete(id);
      }
    }
    for (const [id, until] of this.community) {
      if (until !== null && until <= now) {
        this.community.delete(id);
      }
    }
    if (JSON.stringify([[...this.local.keys()], this.community.size]) !== before) {
      widgetChanged = true;
    }
    this.synced = true;

    // New local decisions: the ones above the highest id already seen.
    const fresh = initialized
      ? added.filter((decision) => decision.id > saved.lastDecisionId).sort((a, b) => a.id - b.id)
      : [];
    if (startup && maxId > 0 && maxId < saved.lastDecisionId) {
      // The database of CrowdSec was reset: ids start again from 1.
      logger.info('CrowdSec decision ids went back: database reset?');
      saved.lastDecisionId = maxId;
      dirty = true;
    }
    if (maxId > saved.lastDecisionId) {
      saved.lastDecisionId = maxId;
      dirty = true;
    }
    saved.initialized = true;

    // Alerts.
    let freshAlerts = [];
    if (alerts) {
      const alertsBefore = JSON.stringify([...this.alerts.keys()]);
      if (alerts.full) {
        this.alerts = new Map();
        this.alertsFullAt = now;
      }
      let maxAlertId = 0;
      for (const alert of alerts.list) {
        this.alerts.set(alert.id, alert);
        maxAlertId = Math.max(maxAlertId, alert.id);
      }
      for (const [id, alert] of this.alerts) {
        if ((alert.startAt ?? now) < now - ALERT_WINDOW_MS) {
          this.alerts.delete(id);
        }
      }
      this.alertsReadAt = now;
      if (saved.alertsInitialized) {
        freshAlerts = alerts.list
          .filter((alert) => alert.id > saved.lastAlertId)
          .sort((a, b) => a.id - b.id);
      }
      if (alerts.full && maxAlertId > 0 && maxAlertId < saved.lastAlertId) {
        saved.lastAlertId = maxAlertId;
        dirty = true;
      }
      if (maxAlertId > saved.lastAlertId) {
        saved.lastAlertId = maxAlertId;
        dirty = true;
      }
      if (!saved.alertsInitialized) {
        saved.alertsInitialized = true;
        dirty = true;
      }
      if (JSON.stringify([...this.alerts.keys()]) !== alertsBefore) {
        widgetChanged = true;
      }
    }

    const scenario = this.latestScenario();
    if (scenario && scenario !== saved.lastScenario) {
      saved.lastScenario = scenario;
      dirty = true;
    }

    // Written only when something changed: no wear of the SD card at every read.
    if (dirty) {
      this.store.save(saved);
    }

    const events = [];
    for (const decision of fresh.slice(-MAX_EVENTS_PER_READ)) {
      logger.debug(
        `New decision: ${decision.type} ${decision.scope}:${decision.value} (${decision.scenario})`,
      );
      events.push([
        TRIGGERS.DECISION_ADDED,
        {
          ip: decision.value,
          scope: decision.scope,
          type: decision.type,
          scenario: decision.scenario,
          origin: decision.origin,
          duration_minutes: minutesLeft(decision, now),
          country: this.countryOf(decision),
        },
      ]);
    }
    for (const alert of freshAlerts.slice(-MAX_EVENTS_PER_READ)) {
      logger.debug(`New alert: ${alert.scenario} from ${alert.scope}:${alert.value}`);
      events.push([
        TRIGGERS.ALERT_RAISED,
        {
          scenario: alert.scenario,
          ip: alert.value,
          scope: alert.scope,
          country: alert.country,
          as_name: alert.asName,
          events_count: alert.eventsCount,
          decisions: alert.decisionIds.length,
        },
      ]);
    }
    const skipped = fresh.length + freshAlerts.length - events.length;
    if (skipped > 0) {
      logger.info(`${skipped} scene event(s) skipped: more than ${MAX_EVENTS_PER_READ} at once`);
    }
    for (const [key, data] of events) {
      if (client !== this.client) {
        return false; // reconfigured meanwhile: the old LAPI's news are stale
      }
      await this.fire(key, data);
    }
    if (client === this.client) {
      await this.publishStates();
    }
    return widgetChanged || events.length > 0;
  }

  async applyFailure(err) {
    const wasError = this.error?.kind;
    this.error = { kind: err.kind, message: err.message };
    this.failures += 1;
    this.readAt = this.now();
    // A delta may have been lost with the answer: start again from a full read.
    this.fullSyncAt = 0;
    if (wasError !== err.kind) {
      logger.warn(`CrowdSec: ${err.message}`);
    }
    if (this.failures >= FAILURES_BEFORE_UNREACHABLE && this.saved.reachable !== false) {
      const wasReachable = this.saved.reachable === true;
      this.saved.reachable = false;
      this.store.save(this.saved);
      if (wasReachable) {
        logger.info('CrowdSec is unreachable');
      }
    }
    // Every failed read: "reachable" 0 once unreachable, and its heartbeat
    // during a long outage (the SDK skips the repeats).
    await this.publishStates();
    return wasError !== err.kind;
  }

  /** The country of the alert behind a decision, '' when unknown. */
  countryOf(decision) {
    for (const alert of this.alerts.values()) {
      if (alert.decisionIds.includes(decision.id)) {
        return alert.country;
      }
    }
    return '';
  }

  /** The scenario of the latest alert, or else of the latest local decision. */
  latestScenario() {
    let latest = null;
    for (const alert of this.alerts.values()) {
      if (!latest || alert.id > latest.id) {
        latest = alert;
      }
    }
    if (latest?.scenario) {
      return latest.scenario;
    }
    const decisions = this.latestDecisions(1);
    return decisions[0]?.scenario || this.saved.lastScenario || '';
  }

  /** The active local decisions, latest first. */
  latestDecisions(count = Infinity) {
    return [...this.local.values()].sort((a, b) => b.id - a.id).slice(0, count);
  }

  async fire(key, data) {
    try {
      await this.gladys.publishSceneEvent(key, data);
    } catch (err) {
      this.problems.fail('event', `Scene event ${key} refused: ${err.message}`);
    }
  }

  // --- Publishing to Gladys --------------------------------------------------

  isCreated(externalId) {
    return (this.gladys.devices ?? []).some((device) => device.external_id === externalId);
  }

  /** Publish the Discovery list when it changed (a machine account, a language…). */
  async publishDevices({ force = false } = {}) {
    let devices;
    if (!this.client) {
      devices = [];
    } else if (this.reachable) {
      devices = [
        buildLapiDevice(this.gladys, {
          language: this.config.language,
          alerts: this.client.hasMachine,
        }),
      ];
    } else {
      return; // nothing read: keep the list Gladys has
    }
    const key = JSON.stringify(devices);
    if (!force && key === this.discovered) {
      return;
    }
    try {
      await this.gladys.publishDiscoveredDevices(devices);
      this.discovered = key;
      this.problems.recover('discovered', 'Discovered devices accepted again');
    } catch (err) {
      this.problems.fail('discovered', `Discovered devices refused: ${err.message}`);
    }
  }

  /** "Search" in the Discovery tab: read the LAPI, publish the list again. */
  async rediscover() {
    await this.poll();
    await this.afterChanges(true, { publish: true });
  }

  /**
   * The user added (or updated) the device: its states sent before were
   * dropped by Gladys, and a device deleted then added again needs its badge.
   */
  async onDeviceCreated() {
    this.transport = null;
    await this.publishStates();
    await this.publishTransports();
    this.gladys.requestWidgetRefresh(WIDGET_KEY);
  }

  /** Gladys asks for a refresh (onPoll, only if it polls anyway). */
  async pollDevice() {
    await this.pollNow();
  }

  /**
   * The states of the device, when added. The SDK skips the values Gladys
   * already has (and sends an unchanged one again after `heartbeatMs`).
   */
  async publishStates() {
    if (this.readAt === 0 || !this.isCreated(lapiIds(this.gladys).device)) {
      return;
    }
    const states = lapiValues(this.gladys, {
      reachable: this.reachable,
      local: this.local.size,
      community: this.community.size,
      alerts: this.alertsKnown ? this.alerts.size : null,
      lastScenario: this.latestScenario(),
    });
    try {
      await this.gladys.publishChangedStates(states, { heartbeat: this.timings.heartbeatMs });
      this.problems.recover('states', 'States accepted again');
    } catch (err) {
      this.problems.fail('states', `States refused: ${err.message}`);
    }
  }

  async afterChanges(widgetChanged, { publish = false } = {}) {
    await this.publishDevices({ force: publish });
    await this.publishTransports();
    await this.publishConnectionStatus();
    if (widgetChanged) {
      this.gladys.requestWidgetRefresh(WIDGET_KEY);
    }
  }

  /** The badge of the device: local, or unreachable. */
  async publishTransports() {
    const externalId = lapiIds(this.gladys).device;
    if (!this.client || this.readAt === 0 || !this.isCreated(externalId)) {
      return;
    }
    const transport = this.reachable ? DEVICE_TRANSPORTS.LOCAL : DEVICE_TRANSPORTS.UNREACHABLE;
    if (this.transport === transport) {
      return;
    }
    try {
      await this.gladys.publishTransports([{ external_id: externalId, transport }]);
      this.transport = transport;
      this.problems.recover('transports', 'Transports accepted again');
    } catch (err) {
      this.problems.fail('transports', `Transports refused: ${err.message}`);
    }
  }

  /** The status under the integration name. */
  connectionStatus() {
    if (this.config.url === '') {
      return { connected: false, message: CONNECTION_TEXT.noUrl };
    }
    if (!this.config.url) {
      return { connected: false, message: CONNECTION_TEXT.invalidUrl };
    }
    if (!this.config.apiKey) {
      return { connected: false, message: CONNECTION_TEXT.noKey };
    }
    if (this.error) {
      return { connected: false, message: ERROR_TEXT[this.error.kind] };
    }
    return { connected: true };
  }

  async publishConnectionStatus() {
    const status = this.connectionStatus();
    const key = JSON.stringify(status);
    if (key === this.connection) {
      return;
    }
    try {
      await this.gladys.setConnectionStatus(status.connected, status.message);
      this.connection = key;
      if (status.connected) {
        logger.info(`Connected to the CrowdSec Local API (${hostOf(this.config.url)})`);
      }
      this.problems.recover('connection', 'Connection status accepted again');
    } catch (err) {
      this.problems.fail('connection', `Connection status refused: ${err.message}`);
    }
  }

  // --- Views and commands (widget, scene actions, report) --------------------

  /** Throws the reason the LAPI cannot answer, if any. */
  assertReadable() {
    const status = this.connectionStatus();
    if (!status.connected) {
      throw new Error(pick(status.message, this.config.language));
    }
  }

  /** "Test the connection": read the LAPI now, one line. */
  async testConnection() {
    await this.pollNow({ publish: true });
    const message = {};
    for (const [language, text] of Object.entries(REPORT_TEXT)) {
      const status = this.connectionStatus();
      if (!status.connected) {
        message[language] = pick(status.message, language);
        continue;
      }
      const parts = [text.ok, text.local(this.local.size), text.community(this.community.size)];
      if (!this.client.hasMachine) {
        parts.push(text.noMachine);
      } else if (this.alertsError) {
        parts.push(pick(ERROR_TEXT[this.alertsError.kind], language));
      } else {
        parts.push(text.alerts(this.alerts.size));
      }
      message[language] = labelled('CrowdSec', parts.join(', '), language);
    }
    return message;
  }

  /**
   * Delete the decisions on an address or a range (scene action). Refused
   * unless enabled in the configuration, with a machine account.
   * @returns {Promise<{ deleted: number, value: string }>}
   */
  async unban(raw) {
    const language = this.config.language;
    if (!this.config.allowUnban) {
      throw new Error(pick(ACTION_TEXT.unbanDisabled, language));
    }
    this.assertReadable();
    if (!this.client.hasMachine) {
      throw new Error(pick(ACTION_TEXT.noMachine, language));
    }
    const target = parseTarget(raw);
    if (!target) {
      throw new Error(pick(ACTION_TEXT.badAddress, language));
    }
    const value = target.ip ?? target.range;
    let deleted;
    try {
      deleted = await this.client.deleteDecisions(target);
    } catch (err) {
      if (err instanceof CrowdsecError) {
        throw new Error(pick(ERROR_TEXT[err.kind] ?? ERROR_TEXT[ERROR_KINDS.HTTP], language), {
          cause: err,
        });
      }
      throw err;
    }
    logger.info(`Scene action: ${deleted} decision(s) deleted on ${maskAddress(value)}`);
    logger.debug(`Decisions deleted on ${value}`);
    await this.pollNow(); // the stream reports the deletion: counts and widget
    return { deleted, value };
  }
}
