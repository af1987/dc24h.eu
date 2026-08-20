<!--
README.md

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
Date: 2026-08-20
-->

# dc24h.eu

`dc24h.eu-v0.0.04` is a C++20 Direct Connect hub foundation implementing ADC for Debian 13.

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
- Author: `gpt-5.6-sol`
- Release date: `2026-08-20`

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
- Show all enabled users in a class in the private response:
  `!set key.user.info.userlist.class=[class]`

`key.user.new.id.password` is deliberately **not** an alias for password change in v0.0.04. If a password already exists, no database change is made and the command tells the operator to use `key.user.change.id.password` instead.

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

The current management trust boundary remains loopback-only (`127.0.0.1`) and requires Admin (5) or Master (10) after first-Master bootstrap because ADC VERIFY (`GPA`/`PAS`) is not implemented yet.

See `docs/readme.md`, `docs/architecture.md`, `docs/install.md`, `docs/dc24h.eu-v0.0.04.md` and `docs/adr/0008-user-password-lifecycle-userlist.md`.
