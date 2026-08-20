<!--
README.md

v0.0.03:
  - raise project description to dc24h.eu-v0.0.03
  - add persistent numeric user classes and protected !set account commands
  - document PBKDF2 password storage and local bootstrap boundary

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

`dc24h.eu-v0.0.03` is a C++20 Direct Connect hub foundation implementing the ADC network protocol for Debian 13.

## Baseline

- Protocol: ADC 1.0.4 BASE profile
- Session hash: TIGR (Tiger/192)
- Text encoding: UTF-8, with ADC escape validation
- Base language/locale: US English / `en_US.UTF-8`
- Implementation: C++20
- Database: MariaDB with `utf8mb4`
- Operating system: Debian 13
- Service manager: systemd
- Default ADC TCP port: 1511
- Author: `gpt-5.6-sol`
- Project/release date: `2026-08-19`

## v0.0.03 scope

This release adds persistent account classes and hub-local user management commands. Supported classes are:

| Class | Description |
| ---: | --- |
| -1 | Hublist pingers |
| 0 | Regular users |
| 1 | Registered users |
| 2 | VIP users |
| 3 | Operator user |
| 4 | Cheef user |
| 5 | Admin user |
| 10 | Master user |

Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes. The management commands are intercepted by the hub and are not broadcast to other clients.

Supported keys:

- `!set key.user.new.username.class.password=[username.class.password]`
- `!set key.user.change.id.password=[id.password]`
- `!set key.user.new.id.password=[id.password]` — compatibility alias for changing a password by account database ID.

For v0.0.03, account-changing `!set` commands are loopback-only and require the sending nickname to map to an enabled Admin (5) or Master (10) account. If there are no enabled accounts, a local client may create the first Master account; use the current ADC nickname for that bootstrap account so later commands are authorized.

Registered-user ADC VERIFY authentication (`GPA`/`PAS`) is still a future release. Therefore v0.0.03 deliberately keeps account-changing commands on loopback rather than trusting a remote nickname as proof of authentication.

See `docs/readme.md`, `docs/architecture.md`, `docs/install.md`, `docs/dc24h.eu-v0.0.03.md` and `docs/adr/0007-user-classes-set-commands.md`.
