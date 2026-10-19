// -----------------------------------------------------------------------------
// Scene action handlers (manifest `scene_actions`, Gladys 5.1+).
//
// - get_status: sums up CrowdSec for a message (decisions, alerts, the latest
//   ban), what a condition on the device cannot put in words. It reads the
//   LAPI again when the last read is older than 15 seconds.
// - delete_decision: unbans an address or a range. Off unless enabled in the
//   configuration, and only with a machine account (the bouncer key is
//   read-only). The one command of the integration: a scene that unbans on a
//   condition is the user's choice, a mistake only lets an attacker in again
//   until CrowdSec catches it anew.
// -----------------------------------------------------------------------------

import { shortScenario } from './widgets.js';
import { REPORT_TEXT, UNBAN_TEXT, labelled } from './texts.js';

export const SCENE_ACTIONS = {
  async get_status(hub) {
    if (!hub.client) {
      hub.assertReadable(); // no address or key: the configuration to fix
    }
    await hub.refreshIfStale();
    const language = hub.config.language;
    const text = REPORT_TEXT[language] ?? REPORT_TEXT.en;
    const latest = hub.latestDecisions(1)[0];
    if (hub.error || !hub.reachable) {
      // "CrowdSec does not answer" is an answer: the scene goes on with it.
      return {
        reachable: false,
        local_decisions: 0,
        community_decisions: 0,
        alerts_24h: 0,
        last_ip: '',
        last_scenario: '',
        sentence: `${labelled('CrowdSec', text.unreachable, language)}.`,
      };
    }
    const parts = [text.local(hub.local.size), text.community(hub.community.size)];
    if (hub.alertsKnown) {
      parts.push(text.alerts(hub.alerts.size));
    }
    return {
      reachable: true,
      local_decisions: hub.local.size,
      community_decisions: hub.community.size,
      alerts_24h: hub.alertsKnown ? hub.alerts.size : 0,
      last_ip: latest?.value ?? '',
      last_scenario: hub.latestScenario(),
      sentence: `${labelled('CrowdSec', parts.join(', '), language)}${
        latest ? ` (${latest.value}, ${shortScenario(latest.scenario)})` : ''
      }.`,
    };
  },

  async delete_decision(hub, { fields = {} }) {
    const { deleted, value } = await hub.unban(fields.ip);
    const language = hub.config.language;
    return {
      deleted,
      sentence: `${labelled(
        'CrowdSec',
        (UNBAN_TEXT[language] ?? UNBAN_TEXT.en).deleted(deleted, value),
        language,
      )}.`,
    };
  },
};
