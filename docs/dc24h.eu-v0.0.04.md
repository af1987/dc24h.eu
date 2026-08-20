<!--
dc24h.eu-v0.0.04.md

v0.0.04:
  - define dc24h.eu-v0.0.04 release manifest
  - document separate account password lifecycle commands
  - document private user-list-by-class command
  - record author gpt-5.6-sol and release date 2026-08-20

Author: gpt-5.6-sol
Date: 2026-08-20
-->

# dc24h.eu-v0.0.04

## Release identity

- Program: `dc24h.eu`
- Version: `0.0.04`
- Release: `dc24h.eu-v0.0.04`
- Author: `gpt-5.6-sol`
- Date: `2026-08-20`
- Repository: `af1987/dc24h.eu`
- Development branch: `agent/dc24h-v0.0.04`
- Target branch: `main`

## Platform baseline

- Direct Connect protocol: ADC 1.0.4 BASE profile
- Text encoding: UTF-8
- Base language: US English
- Runtime locale: `en_US.UTF-8`
- Implementation: C++20
- Database: MariaDB / `utf8mb4`
- Operating system: Debian 13
- Service manager: systemd

## v0.0.04 scope

This release makes the account password lifecycle explicit. The command that adds a password to a passwordless account is no longer an alias for password replacement. It also adds passwordless user creation and a private list of enabled users filtered by numeric class.

## Commands

### Register with password

`!set key.user.new.username.class.password=[username.class.password]`

Creates a new enabled account with the selected class and a PBKDF2-HMAC-SHA256 password hash.

### Register without password

`!set key.user.new.username.class=[username.class]`

Creates a new enabled account with `password_hash=NULL`.

### Add first password

`!set key.user.new.id.password=[id.password]`

Sets a password only when the enabled account currently has no password. If a password is already present, no update is performed and the result instructs the operator to use the change command.

### Change password

`!set key.user.change.id.password=[id.password]`

Replaces the password hash for the selected enabled account ID. This is the only v0.0.04 key intended to change an existing password.

### List users by class

`!set key.user.info.userlist.class=[class]`

Returns all enabled accounts in the selected class in the hub-local private response. The management message is intercepted before normal ADC broadcast routing.

## Supported classes

| Value | Meaning |
| ---: | --- |
| -1 | Hublist pingers |
| 0 | Regular users |
| 1 | Registered users |
| 2 | VIP users |
| 3 | Operator user |
| 4 | Cheef user |
| 5 | Admin user |
| 10 | Master user |

## Persistence changes

`accounts.password_hash` changes from `VARCHAR(255) NOT NULL` to nullable `VARCHAR(255)`. Existing password hashes are not cleared. Passwordless registrations use `NULL`; the first-password command uses a conditional update so an existing hash cannot be overwritten accidentally.

## Security boundary

Management commands remain restricted to IPv4 loopback (`127.0.0.1`). After first-Master bootstrap, the requesting ADC nickname must map to an enabled Admin (5) or Master (10) account. This remains necessary until ADC VERIFY (`GPA`/`PAS`) provides authenticated registered-user identity.

Plaintext passwords are never persisted and are not included in command result messages.

## Source changes

- `src/database.cpp` / `src/database.hpp` — nullable-password persistence, conditional first-password insertion, class-filtered account listing.
- `src/user_commands.cpp` / `src/user_commands.hpp` — new parser/action semantics and private list result generation.
- `tests/user_commands_tests.cpp` — parser regressions for all v0.0.04 user-management keys.
- `sql/schema.sql` — nullable `password_hash` migration.
- `src/version.cpp` / `src/version.hpp`, `VERSION`, `CMakeLists.txt`, `deploy/dc24h.service` — v0.0.04 metadata.
- `docs/*` — release, architecture, installation, instructions and changelog updates.

## Architecture decision

See `docs/adr/0008-user-password-lifecycle-userlist.md`.

## Known limitation

Registered-user ADC VERIFY authentication is not part of v0.0.04, so protected account management stays local-only.
