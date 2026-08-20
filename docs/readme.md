<!--
readme.md

v0.0.03:
  - update documentation index for dc24h.eu-v0.0.03
  - add user-class/set-command ADR and release manifest references

v0.0.02:
  - update documentation index for dc24h.eu-v0.0.02
  - add ADC state/TIGR ADR and release manifest references

v0.0.01:
  - add documentation index and project baseline

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# dc24h.eu documentation

This directory is the authoritative design and operations documentation for `dc24h.eu-v0.0.03`.

## Documents

- `architecture.md` — component boundaries, ADC flow, account model and trust boundaries.
- `instructions.md` — permanent engineering, versioning, ADR, password-security and C++ pair rules.
- `changelog.md` — release history.
- `install.md` — Debian 13 installation, tests, systemd and first-Master bootstrap.
- `dc24h.eu-v0.0.03.md` — current release manifest.
- `dc24h.eu-v0.0.02.md` — previous release manifest.
- `dc24h.eu-v0.0.01.md` — initial release manifest.
- `adr/*.md` — Architecture Decision Records.

## Current protocol profile

- ADC base specification: 1.0.4
- Required features: `BASE`, `TIGR`
- Text: UTF-8
- Base language/runtime locale: US English / `en_US.UTF-8`

## Current account profile

- MariaDB account class: signed numeric `user_class`.
- Classes: `-1, 0, 1, 2, 3, 4, 5, 10`.
- Password storage: salted PBKDF2-HMAC-SHA256.
- Account mutation commands: loopback-only in v0.0.03.
- Authorized classes after bootstrap: Admin (5) and Master (10).
