<!--
README.md

v0.0.08:
  - raise project description to dc24h.eu-v0.0.08
  - add persistent key.kicks/key.bans admission and audit behavior

v0.0.07:
  - raise project description to dc24h.eu-v0.0.07
  - add class/nickname policy, auto-registration and account security metadata

v0.0.06:
  - raise project description to dc24h.eu-v0.0.06
  - add moderation enforcement, timed privileges and ncdc compatibility

v0.0.05:
  - raise project description to dc24h.eu-v0.0.05
  - add complete user administration and online lookup keys
  - add temporary class, +passwd, final-Master and DNS policies

v0.0.04:
  - raise project description to dc24h.eu-v0.0.04
  - separate add-password and change-password semantics
  - add passwordless account creation and private user list by class

v0.0.03:
  - add persistent numeric user classes and protected !set account commands
  - document PBKDF2 password storage and local bootstrap boundary

v0.0.02:
  - document ADC 1.0.4 state validation, TIGR identity and B/D/E/F routing

v0.0.01:
  - initial ADC/C++/MariaDB/Debian 13/systemd project overview

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# dc24h.eu

`dc24h.eu-v0.0.08` is a C++20 Direct Connect ADC hub for Debian 13.

## Baseline

- Hub name: `dc24h.eu`
- Network protocol: ADC 1.0.4 BASE profile
- Session hash: TIGR (Tiger/192)
- Text encoding: UTF-8
- Base language/locale: US English / `en_US.UTF-8`
- Implementation: C++20
- Database: MariaDB with `utf8mb4`
- Operating system: Debian 13
- Service manager: systemd
- Default ADC TCP port: 1511
- Reverse DNS: disabled by default (`dns_lookup=0`)
- Author: `gpt-5.6-sol`
- Release date: `2026-08-21`

## User management keys

Commands are sent through the existing protected hub-local `!set` command path and are answered with a private hub `IMSG`; password-bearing commands are not broadcast.

- Register a user with a password:
  `!set key.user.new.username.class.password=[username.class.password]`
- Register a user without a password:
  `!set key.user.new.username.class=[username.class]`
- Add a password only when the account currently has no password:
  `!set key.user.new.id.password=[id.password]`
- Change/replace the password for an existing account ID:
  `!set key.user.change.id.password=[id.password]`
- Show all registered users in a class, including enabled state, in the private response:
  `!set key.user.info.userlist.class=[class]`

The v0.0.08 command set adds `key.kicks` (default rejoin delay), `key.bans`
(maximum temporary duration), typed kick/ban operations and append-oriented
MariaDB audit. Active address bans are checked after accept; nickname, ADC CID,
prefix and share bans are checked before NORMAL. See
`docs/dc24h.eu-v0.0.08.md` for syntax and defaults.

`key.user.new.id.password` is not an alias for password change. If a password already exists, no database change is made. `key.user.change.username.password=[username.]` resets a password to `NULL`, after which the current local nickname may set it once with `+passwd <password>`.

## User classes

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

Passwords are persisted only as salted PBKDF2-HMAC-SHA256 hashes. Passwordless registrations store `NULL` in `accounts.password_hash` until `key.user.new.id.password` assigns the first password.

The management trust boundary remains loopback-only (`127.0.0.1`) because ADC VERIFY (`GPA`/`PAS`) is not implemented. Timed policies persist in MariaDB with UTC expiry and are enforced before ADC routing. Delegated registration is capped at class 1.

ADC/TIGR connectivity, kick denial/expiry, ban/unban and restart persistence are
validated with Debian 13 `ncdc 1.23.1` against an isolated MariaDB instance.

See `docs/readme.md`, `docs/architecture.md`, `docs/install.md`,
`docs/dc24h.eu-v0.0.08.md` and
`docs/adr/0012-persistent-kicks-bans.md`.
