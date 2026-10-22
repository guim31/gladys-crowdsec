# Changelog

All notable changes to this integration are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [semantic versioning](https://semver.org/).

Describe each change under `## [Unreleased]` as you make it. The Release
workflow moves that section under the version it ships, and the section becomes
the notes of the version's GitHub Release.

## [Unreleased]

## [1.0.1] - 2026-10-22

### Security

- Rebuilt on Node.js 24.22.1, the October 2026 security release (remote code
  execution in the Brotli decoder, CVE-2026-111497; TLS hostname and DNS
  fixes).

## [1.0.0] - 2026-10-19

### Added

- A "CrowdSec" device: reachable, active local decisions, community blocklist
  decisions, alerts of the last 24 hours (with a machine account), last
  scenario.
- Scene triggers: a new local decision (address, scenario, remediation,
  duration, country when known), with a ban/captcha filter, and a new alert
  (scenario, source, country, network operator, events).
- Scene actions: state of CrowdSec with a ready-made sentence, and deleting
  the decisions on an address or a range (off by default, machine account
  needed).
- Dashboard widget: active decisions, alerts of the day and the latest banned
  addresses with their scenario and time left.
- "Test the connection" action, texts in English, French, German and Spanish.

[Unreleased]: https://github.com/guim31/gladys-crowdsec/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/guim31/gladys-crowdsec/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/guim31/gladys-crowdsec/releases/tag/v1.0.0
