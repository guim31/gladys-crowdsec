// -----------------------------------------------------------------------------
// Integration configuration: defaults (they mirror the `default` values of the
// manifest `config_schema`, see test/manifest.test.js) and normalization, so
// the rest of the code never deals with strings, blanks or `undefined`.
//
// One CrowdSec Local API (LAPI, port 8080): a bouncer key (read-only access to
// the decisions) and, optionally, a machine account (login and password) for
// the alerts and for deleting a decision.
// -----------------------------------------------------------------------------

export const LANGUAGES = ['en', 'fr', 'de', 'es'];

// Refresh intervals offered in the configuration, in seconds.
export const POLL_INTERVALS = ['30', '60', '120', '300'];

export const UNBAN_CHOICES = ['disabled', 'enabled'];

export const DEFAULT_CONFIG = {
  url: '',
  api_key: '',
  machine_id: '',
  machine_password: '',
  allow_unban: 'disabled',
  poll_interval: '60',
  language: 'fr',
};

/**
 * Parse the address typed by the user into a base URL: a bare host or IP
 * (`192.0.2.10:8080`, HTTP by default) or a full URL. A trailing `/v1` (copied
 * from the documentation) is dropped, any other path kept (a LAPI behind a
 * reverse proxy sub-path).
 * @param {unknown} raw
 * @returns {string|null} `http(s)://host[:port][/path]`, null when unusable
 */
export function parseServerUrl(raw) {
  if (typeof raw !== 'string') {
    return null;
  }
  const text = raw.trim();
  if (!text) {
    return null;
  }
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`;
  let url;
  try {
    url = new URL(withScheme);
  } catch {
    return null;
  }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) {
    return null;
  }
  // Credentials in the address would end up in the logs.
  if (url.username || url.password) {
    return null;
  }
  const path = url.pathname.replace(/\/+$/, '').replace(/\/v1$/i, '');
  return `${url.origin}${path}`;
}

/** Host part shown to the user (no scheme). */
export const hostOf = (url) => url.replace(/^https?:\/\//, '');

/**
 * @param {Record<string, unknown>} raw the configuration returned by the SDK
 */
export function normalizeConfig(raw = {}) {
  const source = raw && typeof raw === 'object' ? raw : {};
  const text = (key) => (typeof source[key] === 'string' ? source[key].trim() : '');
  const typed = text('url');
  const pollInterval = POLL_INTERVALS.includes(String(source.poll_interval))
    ? String(source.poll_interval)
    : DEFAULT_CONFIG.poll_interval;
  const machineId = text('machine_id');
  // A password may legitimately start or end with a space: kept as typed.
  const machinePassword =
    typeof source.machine_password === 'string' ? source.machine_password : '';
  return {
    // '' when nothing was typed yet, null when what was typed is unusable.
    url: typed ? parseServerUrl(typed) : '',
    apiKey: text('api_key'),
    // The machine account counts only when both halves are there.
    machineId: machineId && machinePassword ? machineId : '',
    machinePassword: machineId && machinePassword ? machinePassword : '',
    allowUnban: source.allow_unban === 'enabled',
    pollIntervalMs: Number(pollInterval) * 1000,
    language: LANGUAGES.includes(source.language) ? source.language : DEFAULT_CONFIG.language,
  };
}
