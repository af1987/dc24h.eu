<!--
readme.md

v0.0.02:
  - update documentation index for dc24h.eu-v0.0.02
  - add ADC state/TIGR ADR and release manifest references

v0.0.01:
  - add documentation index and project baseline

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# dc24h.eu documentation

This directory is the authoritative design and operations documentation for `dc24h.eu-v0.0.02`.

## Documents

- `architecture.md` — component boundaries, ADC state flow, trust boundaries and routing.
- `instructions.md` — permanent engineering, versioning, ADR and C++ pair rules.
- `changelog.md` — release history.
- `install.md` — Debian 13 installation, tests and systemd operation.
- `dc24h.eu-v0.0.02.md` — release manifest and v0.0.02 scope.
- `dc24h.eu-v0.0.01.md` — previous release manifest.
- `adr/*.md` — Architecture Decision Records.

## Current protocol profile

- ADC base specification: 1.0.4
- Required features: `BASE`, `TIGR`
- Text: UTF-8
- Base language/runtime locale: US English / `en_US.UTF-8`

Protocol references used by v0.0.02 are the ADC project base 1.0.4 specification and the official TIGR extension documentation.
