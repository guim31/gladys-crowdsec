# CrowdSec for Gladys Assistant

An external integration for [Gladys Assistant](https://gladysassistant.com)
that brings [CrowdSec](https://www.crowdsec.net/), the collaborative intrusion
prevention engine, into Gladys: which addresses are banned, what attacked your
servers today, and a notification the moment it happens.

- **A CrowdSec device**: reachable, active local decisions, community
  blocklist decisions, alerts of the last 24 hours, last scenario.
- **Scene triggers**: a new local decision (address, scenario, duration,
  country when known), a new alert (scenario, source, country, network
  operator).
- **Scene actions**: state of CrowdSec in a ready-made sentence, and — off by
  default — delete a decision (unban an address or a range).
- **Dashboard widget**: the counts and the latest banned addresses, with their
  scenario and time left.
- Texts in English, French, German and Spanish.

Tested against a real CrowdSec v1.8.1 (official Docker image, SSH brute force
replayed from a log file, decisions added and deleted with `cscli`, bouncer
key and machine account). Developed without a production installation:
feedback welcome on [the issues](https://github.com/guim31/gladys-crowdsec/issues).

## Requirements

- Gladys Assistant 5.1.0 or later.
- CrowdSec 1.5 or later, its Local API (port 8080) reachable from the Gladys
  machine.
- A bouncer key (`cscli bouncers add gladys`) and, for the alerts and the
  unban action, a machine account
  (`cscli machines add gladys --password … -f /dev/null`).

## Installation

In Gladys, open **Integrations → Install from GitHub** and enter
`https://github.com/guim31/gladys-crowdsec`. Then open its configuration,
enter the address of the Local API and the bouncer key (and the machine
account if any), and add the device from the Discover tab.

The full guide: [docs/en.md](docs/en.md) (also in [French](docs/fr.md),
[German](docs/de.md) and [Spanish](docs/es.md)).

## How it works

The container follows the decision stream of its bouncer key
(`GET /v1/decisions/stream`): every active decision at start and once an
hour, only the additions and deletions at the other reads (every minute by
default). With a machine account it logs in (`POST /v1/watchers/login`) and
reads the alerts of the last hour (`GET /v1/alerts`), the last 24 hours once
an hour. The highest decision and alert ids already seen are kept in `/data`,
so a ban during a restart is announced once. Full IP addresses are logged at
the debug level only.

## Limits

- One Local API per integration.
- Decisions on a country or an AS are not counted (the bouncer stream only
  carries addresses and ranges).
- Without a machine account: no alerts, no country.
- At most 20 scene events per read: a large scan does not send hundreds of
  notifications.
- A self-signed HTTPS certificate is not accepted (use `http://` on the local
  network).

## Development

```bash
npm ci
npm run format:check && npm run lint && npm test
npx -y github:GladysAssistant/integration-store --skip-image-check .
```

See [CLAUDE.md](CLAUDE.md) for the project rules and the notes on the CrowdSec
Local API.

## Credits

- [CrowdSec](https://github.com/crowdsecurity/crowdsec) by CrowdSec and
  contributors (MIT): the answers in `test/fixtures/crowdsec` come from its
  official Docker image (`stream-community.json` is written by hand in the
  same format, a test instance has no community blocklist).
- The CrowdSec logo on the cover is the official one, from the
  [CrowdSec documentation repository](https://github.com/crowdsecurity/crowdsec-docs/blob/main/crowdsec-docs/static/img/crowdsec_logo.png);
  it belongs to CrowdSec.

Not affiliated with CrowdSec.

## License

Apache-2.0, see [LICENSE](LICENSE).
