// -----------------------------------------------------------------------------
// The Gladys device, proposed in the Discovery tab (the user adds it):
//
//   one "CrowdSec" device for the Local API:
//     reachable             input/binary    1 the LAPI answers, 0 otherwise
//     local_decisions       counter-sensor  active decisions taken here
//                                           (scenarios, cscli, console…)
//     community_decisions   counter-sensor  active decisions of the community
//                                           blocklist and of the blocklists
//     alerts_24h            counter-sensor  alerts started in the last 24 h
//                                           (machine account only)
//     last_scenario         text/text       scenario of the latest alert or
//                                           local decision
//
// Published with should_poll: false: the integration reads the LAPI on its own
// timer (src/hub.js), at the interval chosen in the configuration.
// -----------------------------------------------------------------------------

import { DEVICE_FEATURE_CATEGORIES, DEVICE_FEATURE_TYPES } from '@gladysassistant/integration-sdk';

export const LAPI_TYPE = 'lapi';
export const LAPI_ID = 'main';
export const MODEL = 'CrowdSec Local API';

// Suffixes of the feature external ids: permanent once published.
export const KEYS = Object.freeze({
  REACHABLE: 'reachable',
  LOCAL_DECISIONS: 'local_decisions',
  COMMUNITY_DECISIONS: 'community_decisions',
  ALERTS_24H: 'alerts_24h',
  LAST_SCENARIO: 'last_scenario',
});

// Feature names, in the language chosen in the configuration (Gladys does not
// tell a device integration the user's language). Frozen at creation in Gladys.
export const NAMES = {
  en: {
    [KEYS.REACHABLE]: 'Reachable',
    [KEYS.LOCAL_DECISIONS]: 'Local decisions',
    [KEYS.COMMUNITY_DECISIONS]: 'Community decisions',
    [KEYS.ALERTS_24H]: 'Alerts (24 h)',
    [KEYS.LAST_SCENARIO]: 'Last scenario',
  },
  fr: {
    [KEYS.REACHABLE]: 'Joignable',
    [KEYS.LOCAL_DECISIONS]: 'Décisions locales',
    [KEYS.COMMUNITY_DECISIONS]: 'Décisions de la communauté',
    [KEYS.ALERTS_24H]: 'Alertes (24 h)',
    [KEYS.LAST_SCENARIO]: 'Dernier scénario',
  },
  de: {
    [KEYS.REACHABLE]: 'Erreichbar',
    [KEYS.LOCAL_DECISIONS]: 'Lokale Entscheidungen',
    [KEYS.COMMUNITY_DECISIONS]: 'Community-Entscheidungen',
    [KEYS.ALERTS_24H]: 'Alarme (24 h)',
    [KEYS.LAST_SCENARIO]: 'Letztes Szenario',
  },
  es: {
    [KEYS.REACHABLE]: 'Accesible',
    [KEYS.LOCAL_DECISIONS]: 'Decisiones locales',
    [KEYS.COMMUNITY_DECISIONS]: 'Decisiones de la comunidad',
    [KEYS.ALERTS_24H]: 'Alertas (24 h)',
    [KEYS.LAST_SCENARIO]: 'Último escenario',
  },
};

// Display bounds (the core never applies them on write). The community
// blocklist reaches a few tens of thousands of addresses.
export const MAX_LOCAL = 100_000;
export const MAX_COMMUNITY = 1_000_000;
export const MAX_ALERTS = 100_000;

export const lapiIds = (gladys) => gladys.externalIds(LAPI_TYPE, LAPI_ID);

const sensor = (name, externalId, category, type, extra) => ({
  name,
  external_id: externalId,
  category,
  type,
  read_only: true,
  has_feedback: false,
  ...extra,
});

const counter = (name, externalId, max) =>
  sensor(
    name,
    externalId,
    DEVICE_FEATURE_CATEGORIES.COUNTER_SENSOR,
    DEVICE_FEATURE_TYPES.SENSOR.INTEGER,
    { keep_history: true, min: 0, max },
  );

/**
 * The discovery payload of the LAPI. "Alerts (24 h)" only with a machine
 * account: the bouncer key cannot read the alerts.
 */
export function buildLapiDevice(gladys, { language = 'en', alerts = false } = {}) {
  const ids = lapiIds(gladys);
  const names = NAMES[language] ?? NAMES.en;
  const features = [
    sensor(
      names[KEYS.REACHABLE],
      ids.feature(KEYS.REACHABLE),
      DEVICE_FEATURE_CATEGORIES.INPUT,
      DEVICE_FEATURE_TYPES.SENSOR.BINARY,
      { keep_history: true, min: 0, max: 1 },
    ),
    counter(names[KEYS.LOCAL_DECISIONS], ids.feature(KEYS.LOCAL_DECISIONS), MAX_LOCAL),
    counter(names[KEYS.COMMUNITY_DECISIONS], ids.feature(KEYS.COMMUNITY_DECISIONS), MAX_COMMUNITY),
  ];
  if (alerts) {
    features.push(counter(names[KEYS.ALERTS_24H], ids.feature(KEYS.ALERTS_24H), MAX_ALERTS));
  }
  features.push(
    sensor(
      names[KEYS.LAST_SCENARIO],
      ids.feature(KEYS.LAST_SCENARIO),
      DEVICE_FEATURE_CATEGORIES.TEXT,
      DEVICE_FEATURE_TYPES.TEXT.TEXT,
      { keep_history: true, min: 0, max: 0 },
    ),
  );
  return {
    name: 'CrowdSec',
    external_id: ids.device,
    model: MODEL,
    should_poll: false,
    params: [],
    features,
  };
}

/**
 * The values of the device: only "reachable" when the LAPI does not answer
 * (the counts keep their last value).
 * @param {object} view { reachable, local, community, alerts (null: unknown), lastScenario }
 */
export function lapiValues(gladys, { reachable, local, community, alerts, lastScenario }) {
  const ids = lapiIds(gladys);
  const values = [{ key: KEYS.REACHABLE, state: reachable ? 1 : 0 }];
  if (reachable) {
    values.push(
      { key: KEYS.LOCAL_DECISIONS, state: local },
      { key: KEYS.COMMUNITY_DECISIONS, state: community },
    );
    if (alerts !== null) {
      values.push({ key: KEYS.ALERTS_24H, state: alerts });
    }
    if (lastScenario) {
      values.push({ key: KEYS.LAST_SCENARIO, text: lastScenario });
    }
  }
  return values.map(({ key, ...value }) => ({
    device_feature_external_id: ids.feature(key),
    ...value,
  }));
}
