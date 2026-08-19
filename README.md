<!--
README.md

v0.0.01:
  - initial project overview
  - document ADC/C++/MariaDB/Debian 13/systemd baseline

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# dc24h.eu

`dc24h.eu-v0.0.01` is the initial foundation for a Direct Connect hub using the ADC network protocol.

## Baseline

- Protocol: ADC (BASE foundation)
- Text encoding: UTF-8
- Base language/locale: US English / `en_US.UTF-8`
- Implementation: C++20
- Database: MariaDB with `utf8mb4`
- Operating system: Debian 13
- Service manager: systemd
- Default ADC TCP port: 1511
- Author for this project bootstrap: `gpt-5.6-sol`
- Project date: `2026-08-19`

## v0.0.01 scope

The initial release provides a buildable daemon, TCP listener, ADC SUP/SID/INF startup exchange, UTF-8 validation, SID allocation, basic routing for INF/MSG/SCH/RES traffic, MariaDB event persistence, Debian installation automation, systemd service definition, CI, architecture documentation and ADRs.

It intentionally does **not** claim full ADC ecosystem compatibility yet. Authentication, permissions enforcement, ADCS/TLS, extension negotiation, anti-flood controls, full ADC state validation and production observability belong to subsequent releases.

See `docs/readme.md`, `docs/architecture.md`, `docs/install.md`, and `docs/dc24h.eu-v0.0.01.md`.
