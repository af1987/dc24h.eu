<!--
architecture.md

v0.0.07:
  - add persistent hub settings and nickname admission policy
  - add self-registration, account IP binding and password deadlines
  - add account telemetry and kick-message filtering

v0.0.06:
  - add persistent moderation attributes and expiring policies
  - add routing enforcement, delegated privileges and private OPChat
  - make SUP negotiation compatible with ncdc identification

v0.0.05:
  - add complete persistent registered-user administration
  - add restart-scoped class overrides and online IPv4/hostname queries
  - add password reset/self-service and final-Master protection

v0.0.04:
  - split first-password assignment from replacement
  - add passwordless accounts and private class listing

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# Architecture — dc24h.eu-v0.0.07

## Baseline

`dc24h.eu` is a C++20 Direct Connect hub for Debian 13. It implements the ADC 1.0.4 BASE/TIGR profile, validates UTF-8, stores persistent state in MariaDB `utf8mb4`, uses US English / `en_US.UTF-8`, and runs under systemd. v0.0.07 adds configurable class/nickname admission, controlled self-registration and account security metadata.

## Runtime flow

1. systemd starts `/usr/local/bin/dc24h.eu /etc/dc24h.eu/dc24h.conf` after MariaDB.
2. `main` loads strict `key=value` configuration and selects the US UTF-8 locale.
3. `Database` connects through MariaDB Connector/C and applies idempotent schema updates.
4. `Server` listens on IPv4 TCP port 1511 by default and allocates a four-character ADC SID per connection.
5. `AdcProtocol` negotiates BASE/TIGR in SUP, validates UTF-8/escaping, TIGR PID/CID identity, INF fields and B/D/E/F routing. BINF `SU` is not required to repeat SUP features.
6. NORMAL-state `BMSG` text beginning with `!set `, `+passwd ` or `+regme ` is intercepted before broadcast.
7. The server validates the loopback and class boundary, then delegates persistent operations to `UserCommandProcessor`/`Database` or evaluates live-session queries itself.
8. Runtime policy snapshots filter INF and routed commands before delivery.
9. The result is escaped and returned only to the requester as `IMSG`.

## Components

- `src/adc.cpp` / `src/adc.hpp`: ADC parsing, state machine and routing decisions.
- `src/hash.cpp` / `src/hash.hpp`: ADC Base32 and TIGR identity derivation.
- `src/user.cpp` / `src/user.hpp`: canonical numeric classes and PBKDF2-HMAC-SHA256 passwords.
- `src/hub_settings.cpp` / `src/hub_settings.hpp`: canonical policy keys, normalization and nickname checks.
- `src/user_commands.cpp` / `src/user_commands.hpp`: complete key grammar, duration parsing, validation and persistent command execution.
- `src/database.cpp` / `src/database.hpp`: mutex-serialized MariaDB operations, account invariants and UTC-expiring policies.
- `src/server.cpp` / `src/server.hpp`: listener, sessions, moderation enforcement, private OPChat, temporary classes, online IPv4 and optional reverse DNS.
- `src/config.cpp` / `src/config.hpp`: runtime configuration including `dns_lookup=0|1`.
- `src/version.cpp` / `src/version.hpp`: `0.0.07`, release identity, author and date.

Every production and test `*.cpp` has a matching `*.hpp` and vice versa.

## Persistent account model

`accounts` contains identity/password/class state, moderation fields, authentication IP, email/public note, kick-message visibility, password-change state and login/logout telemetry. `settings` stores validated class, nickname, self-registration and password policies. `user_timed_policies` stores one UTC expiry per account/policy. Supported classes remain `-1, 0, 1, 2, 3, 4, 5, 10`; legacy `role` is not authoritative.

Passwords use salted PBKDF2-HMAC-SHA256 with 210000 iterations, a 16-byte random salt and a 32-byte derived key. Plaintext passwords and hashes are never returned in command messages. Password-presence information is reported only as `set`/`unset`.

Removal, disabling and permanent class demotion query the target while holding the database mutex. If the operation would eliminate the final enabled Master (10), it is rejected.

## Command groups

### Registration and passwords

- `key.user.new.username.class.password=[username.class.password]`
- `key.user.new.username.class=[username.class]`
- `key.user.new.id.password=[id.password]` — first password only.
- `key.user.change.id.password=[id.password]` — replacement by ID.
- `key.user.change.username.password=[username.password]` — replacement by nickname; an empty password resets to `NULL`.
- `+passwd <password>` — local first-password self-service for the current nickname.

### Account lifecycle and classes

- `key.user.remove.username=[username]`
- `key.user.disable.username=[username]`
- `key.user.enable.username=[username]`
- `key.user.change.username.class=[username.class]`
- `key.user.change.username.class.temp=[username.class]`

The temporary class is held in memory, capped at Admin (5), used as the effective class, and lost on restart.

### Private information

- `key.user.info.userlist.class=[class]`; `[]` means class 0.
- `key.user.info.username=[username]`
- `key.user.info.ip.hostname.username=[username]`
- `key.user.info.hostname.username=[username]`
- `key.user.info.userlist.ip=[IPv4]`
- `key.user.info.userlist.iprange=[start-end]`
- `key.user.info.userlist.subnet=[network/prefix]`

Account information comes from MariaDB. IP and hostname information comes only from current sessions. Reverse DNS occurs only when `dns_lookup=1`; otherwise hostname results explicitly report it disabled.

## Trust boundaries

ADC VERIFY (`GPA`/`PAS`) is not implemented in v0.0.07. Management commands therefore require IPv4 loopback plus the configured class/capability boundary. `+passwd` and enabled `+regme` are explicit self-service exceptions; account IP binding is enforced during identification.

## Hub policy and self-registration

MariaDB-backed `key.class.*` values control registration/kick differences, PM/download class reach and minimum classes. `key.nick.*` values are checked before a session becomes NORMAL. `+regme` is disabled by default and, when enabled, checks the selected class, optional prefix, class-specific `SS` byte threshold and minimum password length. Passwordless registrations receive a deadline; the server disconnects an unchanged account after the configured timeout.

## Moderation and routing

Persistent flags hide share fields and ADC operator CT bits during BINF construction. The self-visibility threshold filters user INF, broadcasts, direct messages and feature-routed traffic for lower-class recipients.

Timed policies are loaded with account state and checked against the current epoch. `gag`, `no_chat`, `no_pm`, `no_search` and `no_download` block their ADC command families before routing. `can_kick`, `can_register`, temporary hidden share and `opchat` enable only their documented capabilities. An update refreshes connected sessions immediately; expiry checks need no scheduler.

Protected kick and non-punitive disconnect are separate live-session operations. Kick checks the actor class against the target threshold. Disconnect closes the socket without treating the event as a kick.

## Concurrency and deployment

The hub uses one worker thread per client. `clients_mutex_` protects live ADC state, `temporary_classes_mutex_` protects restart-scoped overrides, and `Database` serializes the MariaDB connection. DNS is executed outside the clients lock. The target deployment is Debian 13 with systemd, MariaDB, libmariadb and libgcrypt.

See ADR-0011 for the v0.0.07 policy model, admission boundaries and migration decisions.
