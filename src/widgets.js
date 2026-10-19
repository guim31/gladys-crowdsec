// -----------------------------------------------------------------------------
// Dashboard widget (manifest `widgets`, Gladys 5.1+): `decisions`.
//
// The use case: a glance at the wall tablet tells whether someone is knocking
// at the door of the home servers, and who was banned lately. So the widget
// shows the active local decisions, the community blocklist and the alerts of
// the last 24 hours, then the latest local decisions — address, scenario and
// time left — latest first.
//
// The figures are sent as values, not bound to device features: the widget
// works before the device is added.
//
// Budget (8 components, 2 texts): three tiles, one text when CrowdSec or its
// alerts do not answer, one status list, a Refresh button.
// -----------------------------------------------------------------------------

import { WIDGET_COLORS } from '@gladysassistant/integration-sdk';
import { WIDGET_KEY, minutesLeft } from './hub.js';
import { CONNECTION_TEXT, ERROR_TEXT, pick } from './texts.js';

// Action key of the button: permanent once published.
export const ACTIONS = Object.freeze({ REFRESH: 'refresh' });

export const MAX_ROWS = 8;

export const TEXT = {
  empty: {
    en: 'No active local decision: nobody was banned lately.',
    fr: "Aucune décision locale active : personne n'a été banni récemment.",
    de: 'Keine aktive lokale Entscheidung: In letzter Zeit wurde niemand gesperrt.',
    es: 'Ninguna decisión local activa: nadie ha sido bloqueado últimamente.',
  },
  local: { en: 'Local', fr: 'Locales', de: 'Lokal', es: 'Locales' },
  community: { en: 'Community', fr: 'Communauté', de: 'Community', es: 'Comunidad' },
  alerts: { en: 'Alerts 24 h', fr: 'Alertes 24 h', de: 'Alarme 24 h', es: 'Alertas 24 h' },
  more: { en: 'Others', fr: 'Autres', de: 'Weitere', es: 'Otras' },
  refresh: { en: 'Refresh', fr: 'Actualiser', de: 'Aktualisieren', es: 'Actualizar' },
  refreshed: {
    en: 'CrowdSec read again.',
    fr: 'CrowdSec relu.',
    de: 'CrowdSec neu gelesen.',
    es: 'CrowdSec leído de nuevo.',
  },
};

const ROW_STYLE = {
  ban: { icon: 'slash', color: WIDGET_COLORS.DANGER },
  captcha: { icon: 'help-circle', color: WIDGET_COLORS.WARNING },
};
const OTHER_STYLE = { icon: 'shield', color: WIDGET_COLORS.WARNING };

const fit = (text, max) => (text.length > max ? `${text.slice(0, max - 1).trimEnd()}…` : text);

/** "3 h 58" or "12 min": the time left of a decision. */
export function formatLeft(minutes) {
  if (minutes >= 60) {
    const hours = Math.floor(minutes / 60);
    return hours >= 48 ? `${Math.round(hours / 24)} d` : `${hours} h ${minutes % 60}`;
  }
  return `${minutes} min`;
}

/** "crowdsecurity/ssh-bf" → "ssh-bf": the author prefix takes room for nothing. */
export const shortScenario = (scenario) => scenario.replace(/^[a-z0-9_-]+\//i, '');

function message(text, language) {
  return {
    ttl_seconds: 300,
    components: [{ type: 'text', variant: 'body', text: pick(text, language) }],
  };
}

async function get(hub, { language = 'en' }) {
  const status = hub.connectionStatus();
  if (!hub.client) {
    return message(status.message ?? CONNECTION_TEXT.noUrl, language);
  }
  const now = hub.now();
  const decisions = hub.latestDecisions();
  const components = [
    {
      type: 'value',
      value: hub.local.size,
      label: pick(TEXT.local, language),
      icon: 'slash',
      color: hub.local.size > 0 ? WIDGET_COLORS.DANGER : WIDGET_COLORS.NEUTRAL,
    },
    {
      type: 'value',
      value: hub.community.size,
      label: pick(TEXT.community, language),
      icon: 'users',
      color: WIDGET_COLORS.NEUTRAL,
    },
  ];
  if (hub.client.hasMachine && hub.alertsKnown) {
    components.push({
      type: 'value',
      value: hub.alerts.size,
      label: pick(TEXT.alerts, language),
      icon: 'alert-triangle',
      color: hub.alerts.size > 0 ? WIDGET_COLORS.WARNING : WIDGET_COLORS.NEUTRAL,
    });
  }

  if (hub.failing) {
    components.push({
      type: 'text',
      variant: 'body',
      text: pick(ERROR_TEXT[hub.error.kind], language),
    });
  } else if (hub.alertsError) {
    components.push({
      type: 'text',
      variant: 'body',
      text: pick(ERROR_TEXT[hub.alertsError.kind], language),
    });
  }

  if (decisions.length > 0) {
    const shown = decisions.length > MAX_ROWS ? decisions.slice(0, MAX_ROWS - 1) : decisions;
    const items = shown.map((decision) => {
      // The time left stays whole: a long scenario name is cut instead.
      const left = ` · ${formatLeft(minutesLeft(decision, now))}`;
      return {
        label: fit(decision.value || '-', 40),
        value: `${fit(shortScenario(decision.scenario) || decision.type, 40 - left.length)}${left}`,
        ...(ROW_STYLE[decision.type] ?? OTHER_STYLE),
      };
    });
    if (decisions.length > shown.length) {
      items.push({
        label: pick(TEXT.more, language),
        value: `+${decisions.length - shown.length}`,
        icon: 'more-horizontal',
        color: WIDGET_COLORS.NEUTRAL,
      });
    }
    components.push({ type: 'status', items });
  } else if (!hub.failing) {
    components.push({ type: 'text', variant: 'body', text: pick(TEXT.empty, language) });
  }

  components.push({
    type: 'button',
    label: pick(TEXT.refresh, language),
    icon: 'refresh-cw',
    style: 'secondary',
    action: { key: ACTIONS.REFRESH },
  });

  return { ttl_seconds: hub.failing ? 30 : 60, components };
}

async function action(hub, { actionKey }) {
  if (actionKey !== ACTIONS.REFRESH) {
    throw new Error(`Unknown action ${actionKey}`);
  }
  await hub.pollNow();
  if (hub.error) {
    return { message: ERROR_TEXT[hub.error.kind] };
  }
  return { message: TEXT.refreshed };
}

export const WIDGETS = {
  [WIDGET_KEY]: { get, action },
};
