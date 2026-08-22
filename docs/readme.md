<!--
readme.md

v0.0.10:
  - index tagged password hashing, central RBAC and hostname bans
  - point to ADR-0014 and the v0.0.10 release manifest

v0.0.09:
  - index the protected per-hub home and split MariaDB configuration
  - point operations to ADR-0013 and the v0.0.09 release manifest
  - summarize the reviewed v0.0.09 release checks

v0.0.08:
  - index persistent kick/ban behavior and ADR-0012
  - point operations to the v0.0.08 manifest

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

This directory is the authoritative design and operations documentation for `dc24h.eu-v0.0.10`.

## Documents

- `architecture.md` — ADC flow, persistence, per-hub deployment, account lifecycle, moderation enforcement and online queries.
- `instructions.md` — permanent engineering, deployment security, versioning, ADR, password-security and C++ pair rules.
- `changelog.md` — release history.
- `install.md` — Debian 13 installation, hub-home settings administration, tests, systemd and first-Master bootstrap.
- `dc24h.eu-v0.0.10.md` — current password, RBAC and hostname-ban release manifest.
- `dc24h.eu-v0.0.09.md` — previous per-hub home and settings administration release manifest.
- `dc24h.eu-v0.0.08.md` — previous kick/ban release manifest and command table.
- `dc24h.eu-v0.0.07.md` — previous policy/account-key manifest.
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
- Installed hub home: `/var/lib/dc24h.eu/dc24h.eu`
- Configuration: non-secret `dc24h.conf` plus protected `database.cnf`
- Installer secret input: hidden prompt or root-owned mode-`0600` file on a
  clean install; automatic credential reuse without rotation on reinstall
- Author/date: `gpt-5.6-sol`, `2026-08-21`

## Current account profile

Canonical numeric classes are `-1, 0, 1, 2, 3, 4, 5, 10`. New passwords use
tagged MD5 by the v0.0.10 compatibility requirement; verification also accepts
the existing tagged PBKDF2-HMAC-SHA256 format. MD5 is not recommended for
secure password storage. An account may intentionally have `NULL`
`password_hash` until its first password is assigned.

Supported protected commands:

- `!set key.user.new.username.class.password=[username.class.password]`
- `!set key.user.new.username.class=[username.class]`
- `!set key.user.new.id.password=[id.password]` — adds only if no password exists.
- `!set key.user.change.id.password=[id.password]` — replaces the password.
- `!set key.user.info.userlist.class=[class]` — returns registered users and enabled/password state; `[]` defaults to class 0.

v0.0.08 added persistent kick rejoin blocks, typed permanent/temporary bans,
soft-unban audit and admission enforcement by nickname, CID, IPv4, range,
prefix or exact share. The command table is in `dc24h.eu-v0.0.08.md`;
architectural decisions are in ADR-0012. ADC connectivity and moderation flows
are validated with `ncdc`.

v0.0.09 moved the installed service into
`/var/lib/dc24h.eu/dc24h.eu`, separates MariaDB credentials into a strict
Connector/C option file, and adds root-only `list`, `get`, `set` and `check`
operations through `01-edit-hub-settings.sh` and `dc24h-settings`. See
`dc24h.eu-v0.0.09.md` and ADR-0013. Reviewed Debian 13.6 checks include a clean
warnings-as-errors Release build, CTest 8/8 with ShellCheck, repeated installer
executions and schema application, transactional settings cases, an
active verified systemd unit, real `ncdc 1.23.1` ADC/TIGR echo/reconnect, and
successful local forbidden-name, C++ pair and secret scans. Remote GitHub CI is
the required final merge gate for PR #9.

v0.0.10 centralizes command authorization in a deny-by-default RBAC module and
adds exact/wildcard reverse-hostname bans. See `dc24h.eu-v0.0.10.md` and
ADR-0014. Release checks passed for password/RBAC/host matchers, repeated schema
migration, the active systemd unit and real `ncdc` ADC/TIGR echo/reconnect.
GitHub CI remains the final gate for PR #10.
