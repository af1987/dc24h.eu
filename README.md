<!--
README.md

v0.0.02:
  - raise project description to dc24h.eu-v0.0.02
  - document ADC 1.0.4 state validation, TIGR identity and B/D/E/F routing
  - document new CTest coverage and libgcrypt dependency

v0.0.01:
  - initial project overview
  - document ADC/C++/MariaDB/Debian 13/systemd baseline

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# dc24h.eu

`dc24h.eu-v0.0.02` is a C++20 Direct Connect hub foundation implementing the ADC network protocol for Debian 13.

## Baseline

- Protocol: ADC 1.0.4 BASE profile
- Session hash in v0.0.02: TIGR (Tiger/192)
- Text encoding: UTF-8, with ADC escape validation
- Base language/locale: US English / `en_US.UTF-8`
- Implementation: C++20
- Database: MariaDB with `utf8mb4`
- Operating system: Debian 13
- Service manager: systemd
- Default ADC TCP port: 1511
- Author: `gpt-5.6-sol`
- Project/release date: `2026-08-19`

## v0.0.02 scope

This release adds a stateful ADC login path (`PROTOCOL -> IDENTIFY -> NORMAL`), requires `BASE` and `TIGR` during negotiation, verifies `CID = Tiger(PID)`, removes the private `PD` value before forwarding `BINF`, validates sender SIDs, checks client IPv4 INF values, routes B/D/E/F ADC message types, synchronizes current user INF records for newly identified clients and adds focused protocol/hash tests.

The hub remains an early implementation. Registered-user password verification (`GPA`/`PAS`), operator permissions, bans, ADCS/TLS, IPv6 listening, anti-flood controls, full extension coverage and production observability remain future work.

See `docs/readme.md`, `docs/architecture.md`, `docs/install.md`, `docs/dc24h.eu-v0.0.02.md` and `docs/adr/0006-adc-1.0.4-state-tigr.md`.
