# CrowdSec

[CrowdSec](https://www.crowdsec.net/) reads the logs of your servers (SSH, web
server, Home Assistant, Nextcloud…), recognizes attacks with its scenarios
(brute force, scans, exploits) and **bans** the attacking addresses through its
bouncers (firewall, reverse proxy). It also shares what it sees: every
installation receives the **community blocklist**. This integration brings
CrowdSec into Gladys: a "CrowdSec" device with the active decisions and the
alerts of the day, scenes that fire on each new ban or alert (to send yourself a
notification with the address and the scenario), an action that unbans an
address, and a dashboard widget with the latest banned addresses.

Tested against a real CrowdSec v1.8.1 (Docker, SSH brute force replayed from a
log file, decisions added and deleted with `cscli`). Developed without a
production installation and its community blocklist: feedback welcome on
[the issues](https://github.com/guim31/gladys-crowdsec/issues).

## What you need

- Gladys Assistant 5.1.0 or later.
- CrowdSec 1.5 or later, with its **Local API** (LAPI, port 8080) reachable from
  the Gladys machine. A native install listens on `127.0.0.1:8080` only: set
  `listen_uri: 0.0.0.0:8080` under `api.server` in
  `/etc/crowdsec/config.yaml` (and keep port 8080 closed to the internet). The
  Docker image already listens on every interface: publish its port 8080.
- A **bouncer key** (read-only access to the decisions).
- Optional: a **machine account** (login and password) to read the alerts and to
  unban an address.

The integration reads the decision stream of its bouncer key: the full list at
start and once an hour, only the changes otherwise (one minute by default).
With a machine account, it also reads the alerts of the last hour. Nothing goes
to the internet.

## Getting started

### 1. Create a bouncer key

On the CrowdSec machine:

```bash
cscli bouncers add gladys
```

With Docker: `docker exec crowdsec cscli bouncers add gladys`. The key is
printed once: copy it.

### 2. Create a machine account (optional)

For the alerts, the country of the attackers and the unban action:

```bash
cscli machines add gladys --password 'a-long-password' -f /dev/null
```

`-f /dev/null` matters: without it, `cscli` writes the new credentials over the
ones of the local CrowdSec agent.

### 3. Configure the integration

In Gladys, **Integrations → CrowdSec → Configuration**:

- **Local API address**: `http://192.168.1.2:8080` (the machine of CrowdSec);
- **Bouncer key**: the key of step 1;
- **Machine login** and **Machine password**: the account of step 2, or empty;
- **Deleting decisions from scenes**: disabled by default, see below;
- **Refresh interval**: from 30 seconds to 5 minutes;
- **Language of the names**: names of the features and scene results.

**Test the connection** sums up what the integration reads.

### 4. Add the device

In the **Discover** tab, add the "CrowdSec" device. The widget and the scene
triggers work without it.

## The device

The "CrowdSec" device has these features:

| Feature                 | Meaning                                                                      |
| ----------------------- | ---------------------------------------------------------------------------- |
| **Reachable**           | 1 when the Local API answers, 0 after two failed reads in a row              |
| **Local decisions**     | Active decisions taken here: scenarios of CrowdSec, `cscli`, the console     |
| **Community decisions** | Active decisions of the community blocklist and of the subscribed blocklists |
| **Alerts (24 h)**       | Alerts started in the last 24 hours (machine account only)                   |
| **Last scenario**       | Scenario of the latest alert, or of the latest local decision                |

Each number keeps its history, for a chart of the attacks over the weeks.

## Dashboard

The **CrowdSec decisions** widget shows the active local decisions, the
community blocklist and the alerts of the day, then the latest banned
addresses: address or range, scenario and time left, a red icon for a ban, an
orange one for a captcha. **Refresh** reads CrowdSec again.

## Scenes

### Triggers

- **New local decision**: CrowdSec bans an address (or asks a captcha). The
  filter keeps only the bans or only the captchas. Variables: the address or
  range, the scope (`Ip`, `Range`), the remediation (`ban`, `captcha`), the
  scenario, the origin (`crowdsec` for a scenario, `cscli` for a decision added
  by hand), the duration in minutes, and the country of the attacker when
  CrowdSec knows it (machine account and GeoIP enrichment).
- **New alert**: a scenario fires on a source (machine account only), with or
  without a decision (a scenario in simulation mode raises alerts without
  banning). Variables: the scenario, the source address, the scope, the
  country, the network operator, the number of events and of decisions taken.

A scenario that bans fires both triggers: pick one for your notifications.
Decisions of the community blocklist never fire a trigger: they come by tens of
thousands. When more than 20 decisions or alerts arrive in one read (a large
scan), only the 20 latest fire a scene.

### Actions

- **State of CrowdSec**: reads the counts for the next actions — reachable or
  not, local and community decisions, alerts of the last 24 hours, the latest
  banned address, the last scenario — and a ready-made sentence such as
  "CrowdSec: 3 local decision(s), 15012 community decision(s), 5 alert(s) in
  24 h (203.0.113.7, ssh-bf)."
- **Delete a decision (unban)**: deletes every decision on an address
  (`203.0.113.7`) or a range (`203.0.113.0/24`), from the community blocklist
  too (it comes back at the next pull of the blocklist). The address field
  accepts the variables of the trigger. **Disabled by default**: enable
  "Deleting decisions from scenes" in the configuration, with a machine
  account. Outputs: the number of decisions deleted and a sentence.

### Scene ideas

- **New local decision** → send a message: "CrowdSec banned
  {{triggerEvent.data.ip}} ({{triggerEvent.data.scenario}}, {{triggerEvent.data.country}})".
- Every morning, **State of CrowdSec** → send its sentence: the night of your
  servers in one line.
- When the **Reachable** feature turns to 0, send a message: the protection of
  the house is down.
- A button of the dashboard that runs **Delete a decision (unban)** on the
  address of a family member banned by mistake.

## Troubleshooting

- **"CrowdSec does not answer"**: check the address and the port from the
  Gladys machine (`curl http://192.168.1.2:8080/health` answers
  `{"status":"up"}`), and the `listen_uri` of a native install.
- **"bouncer key refused"**: the key was mistyped or deleted
  (`cscli bouncers list`); create a new one.
- **"machine login or password refused: no alerts"**: check with
  `cscli machines list` that the machine exists and is validated. The
  decisions are still read.
- **"no CrowdSec Local API at this address"**: the address points to another
  service; the Local API answers on port 8080 by default.
- **"certificate refused"**: use the `http://` address on the local network, or
  a certificate Gladys trusts.
- **No country in the variables**: CrowdSec adds the country with the
  `crowdsecurity/geoip-enrich` parser, and only to the alerts: it needs the
  machine account.
- More details in the logs of the integration (Integrations → CrowdSec →
  Logs). Full addresses appear only with `LOG_LEVEL=debug`.

## Limits

- One CrowdSec Local API per integration.
- Decisions on a country or an AS (scopes other than `Ip` and `Range`) are not
  counted: the stream of a bouncer only carries addresses and ranges.
- The alerts need a machine account: with the bouncer key alone, no alerts and
  no country.
- Adding a decision (banning an address) is not offered: CrowdSec and `cscli`
  do it better.
- The CrowdSec console (app.crowdsec.net) is not read.
