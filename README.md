<!--
README.md

v0.0.11:
  - raise project description to dc24h.eu-v0.0.11
  - replace MD5 writes with Argon2id and legacy login-time migration
  - add active password/IP/reconnect/clone abuse protections

v0.0.10:
  - raise project description to dc24h.eu-v0.0.10
  - add tagged MD5 password compatibility and dual verification
  - add centralized RBAC and hostname ban targets

v0.0.09:
  - raise project description to dc24h.eu-v0.0.09
  - add the protected per-hub home and split MariaDB configuration
  - document the validated local hub-settings administration tool
  - record the reviewed Debian 13.6, systemd and ncdc release checks

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
Date: 2026-08-22
-->

# dc24h.eu

`dc24h.eu-v0.0.11` is a C++20 Direct Connect ADC hub for Debian 13.

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
- Hub home: `/var/lib/dc24h.eu/dc24h.eu`
- Runtime configuration: `dc24h.conf` plus protected `database.cnf`
- Default ADC TCP port: 1511
- Reverse DNS: disabled by default (`dns_lookup=0`)
- Author: `gpt-5.6-sol`
- Release date: `2026-08-22`

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

The moderation command set provides `key.kicks` (default rejoin delay), `key.bans`
(maximum temporary duration), typed kick/ban operations and append-oriented
MariaDB audit. Active address bans are checked after accept; nickname, ADC CID,
prefix and share bans are checked before NORMAL. See
`docs/dc24h.eu-v0.0.08.md` for syntax and defaults.

`key.user.new.id.password` is not an alias for password change. If a password already exists, no database change is made. `key.user.change.username.password=[username.]` resets a password to `NULL`, after which the current local nickname may set it once with `+passwd <password>`.

## Per-hub deployment and local settings

v0.0.09 installs the service account and runtime files under the protected home
`/var/lib/dc24h.eu/dc24h.eu`. The root-owned `dc24h.conf` contains non-secret
hub and listener options and refers to the adjacent `database.cnf`. The latter
is a strict MariaDB `[client]` option file which is validated by the application
and read by MariaDB Connector/C; both files are installed as `root:dc24h` mode
`0640`.

The root-only wrapper in the hub home delegates to `/usr/local/bin/dc24h-settings`
and exposes only four database-backed operations:

```text
01-edit-hub-settings.sh HUB_HOME list
01-edit-hub-settings.sh HUB_HOME get KEY
01-edit-hub-settings.sh HUB_HOME set KEY VALUE
01-edit-hub-settings.sh HUB_HOME check
```

All operations require one canonical direct child of `/var/lib/dc24h.eu`,
validate the complete set of 30 settings, and never provide an arbitrary SQL or
delete interface. Updates lock the setting rows with `FOR UPDATE`, validate the
complete candidate snapshot and commit or roll back atomically.

On a clean install, `scripts/install.sh` obtains the database password through
a hidden prompt or an absolute root-owned mode-`0600` file named by
`DC24H_DB_PASSWORD_FILE`. A reinstall automatically reuses the protected
`database.cnf` (or a legacy inline password during migration), does not run a
silent password rotation, and never accepts the password itself in an
environment variable or command argument.

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

New passwords use Argon2id with the OWASP minimum profile (`m=19456 KiB`,
`t=2`, `p=1`) and a unique random salt. Verification remains read-compatible
with tagged PBKDF2-HMAC-SHA256 and MD5 records; a successful legacy
verification atomically replaces that record with Argon2id.
Passwordless registrations store `NULL` in `accounts.password_hash` until
`key.user.new.id.password` assigns the first password. New MD5 hashes are never
created.

## Active anti-abuse controls

`anti_abuse.cpp` / `anti_abuse.hpp` enforce temporary IP bans
(`AddIPTempBan`, `pwd_tmpban`, `LoginError`), independent password-failure
counters, account IP authorization (`mAuthIP`), per-IP session limits
(`max_users_from_ip`, `CntConnIP`), reconnect throttling with reason
`Reconnecting too fast`, and configurable client clone detection
(`CheckUserClone`, `clone_detect_count`, `clone_det_tban_time`,
`clone_ip_tban_time`). Defaults are active in `dc24h.conf.example`.

## RBAC and authorization

Every parsed account/moderation command is mapped to an explicit permission in
the paired `rbac.cpp` / `rbac.hpp` module and is denied by default when no
mapping exists. Operator (3) can perform bounded registration, inspect users
and moderate live sessions,
Admin (5) can manage accounts and bans, and Master (10) is required for role
changes and hub configuration. Existing class-difference rules and delegated
capabilities add contextual restrictions; they do not bypass an unknown
command denial.

Ban targets now include exact or leading-wildcard reverse hostnames using
`host`, for example
`!set key.bans.add=[host|*.example.net|1d|Repeated abuse]`. IP/range bans remain
the stronger network boundary because reverse DNS is not authenticated.

The management trust boundary remains loopback-only (`127.0.0.1`) because ADC VERIFY (`GPA`/`PAS`) is not implemented. Timed policies persist in MariaDB with UTC expiry and are enforced before ADC routing. Delegated registration is capped at class 1.

The v0.0.11 Debian 13 warnings-as-errors Release build and CTest pass 9/9,
including focused Argon2id and active anti-abuse tests. MariaDB retained 30
canonical settings, the installed systemd unit is active at exposure score 3.0,
and real `ncdc 1.23.1` echoed both connection and post-restart markers.

See `docs/readme.md`, `docs/architecture.md`, `docs/install.md`,
`docs/dc24h.eu-v0.0.11.md`,
`docs/adr/0015-argon2id-and-connection-abuse-protection.md`, ADR-0014 and the
earlier deployment ADR-0013.
