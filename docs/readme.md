<!--
readme.md

v0.0.07:
  - index the class/nickname policy and auto-registration release
  - point operations to ADR-0011 and the v0.0.07 manifest

v0.0.06:
  - index moderation/timed-policy release documentation and ADR-0010
  - record ncdc interoperability validation

v0.0.05:
  - update the index for complete user administration and online queries
  - add release v0.0.05 and ADR-0009 references

v0.0.04:
  - update documentation index for dc24h.eu-v0.0.04
  - document separate add/change password semantics
  - add passwordless registration, class listing and ADR-0008 references

v0.0.03:
  - add user-class/set-command ADR and release manifest references

v0.0.02:
  - add ADC state/TIGR ADR and release manifest references

v0.0.01:
  - add documentation index and project baseline

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# dc24h.eu documentation

This directory is the authoritative design and operations documentation for `dc24h.eu-v0.0.07`.

## Documents

- `architecture.md` — ADC flow, persistence, account lifecycle, moderation enforcement and online queries.
- `instructions.md` — permanent engineering, versioning, ADR, password-security and C++ pair rules.
- `changelog.md` — release history.
- `install.md` — Debian 13 installation, tests, systemd and first-Master bootstrap.
- `dc24h.eu-v0.0.07.md` — current release manifest and full policy/account-key table.
- `dc24h.eu-v0.0.06.md` — previous moderation and interoperability manifest.
- `dc24h.eu-v0.0.05.md` — previous release manifest.
- `dc24h.eu-v0.0.04.md` — earlier release manifest.
- `dc24h.eu-v0.0.03.md` — earlier release manifest.
- `dc24h.eu-v0.0.02.md` — earlier protocol-hardening release manifest.
- `dc24h.eu-v0.0.01.md` — initial release manifest.
- `adr/*.md` — Architecture Decision Records.

## Current baseline

- Hub: `dc24h.eu`
- ADC base specification: 1.0.4
- Required features: `BASE`, `TIGR`
- Text: UTF-8
- Base language/runtime locale: US English / `en_US.UTF-8`
- Implementation: C++20
- Database: MariaDB / `utf8mb4`
- OS/service manager: Debian 13 / systemd
- Author/date: `gpt-5.6-sol`, `2026-08-21`

## Current account profile

Canonical numeric classes are `-1, 0, 1, 2, 3, 4, 5, 10`. Passwords are PBKDF2-HMAC-SHA256 hashes; an account may intentionally have `NULL` `password_hash` until its first password is assigned.

Supported protected commands:

- `!set key.user.new.username.class.password=[username.class.password]`
- `!set key.user.new.username.class=[username.class]`
- `!set key.user.new.id.password=[id.password]` — adds only if no password exists.
- `!set key.user.change.id.password=[id.password]` — replaces the password.
- `!set key.user.info.userlist.class=[class]` — returns registered users and enabled/password state; `[]` defaults to class 0.

v0.0.07 adds persistent class thresholds, nickname admission rules, controlled self-registration, password setup deadlines, authentication IP and account metadata/telemetry. The complete key table is in `dc24h.eu-v0.0.07.md`; architectural decisions are in ADR-0011. ADC connectivity is validated with `ncdc`.
