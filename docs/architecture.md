<!--
architecture.md

v0.0.05:
  - add complete persistent registered-user administration
  - add restart-scoped class overrides and online IPv4/hostname queries
  - add password reset/self-service and final-Master protection

v0.0.04:
  - split first-password assignment from replacement
  - add passwordless accounts and private class listing

Author: gpt-5.6-sol
Date: 2026-08-20
-->

# Architecture — dc24h.eu-v0.0.05

## Baseline

`dc24h.eu` is a C++20 Direct Connect hub for Debian 13. It implements the ADC 1.0.4 BASE/TIGR profile, validates UTF-8, stores persistent state in MariaDB `utf8mb4`, uses US English / `en_US.UTF-8`, and runs under systemd.

## Runtime flow

1. systemd starts `/usr/local/bin/dc24h.eu /etc/dc24h.eu/dc24h.conf` after MariaDB.
2. `main` loads strict `key=value` configuration and selects the US UTF-8 locale.
3. `Database` connects through MariaDB Connector/C and applies idempotent schema updates.
4. `Server` listens on IPv4 TCP port 1511 by default and allocates a four-character ADC SID per connection.
5. `AdcProtocol` validates ADC states, UTF-8/escaping, TIGR PID/CID identity, INF fields and B/D/E/F routing.
6. NORMAL-state `BMSG` text beginning with `!set ` or `+passwd ` is intercepted before broadcast.
7. The server validates the loopback and class boundary, then delegates persistent operations to `UserCommandProcessor`/`Database` or evaluates live-session queries itself.
8. The result is escaped and returned only to the requester as `IMSG`.

## Components

- `src/adc.cpp` / `src/adc.hpp`: ADC parsing, state machine and routing decisions.
- `src/hash.cpp` / `src/hash.hpp`: ADC Base32 and TIGR identity derivation.
- `src/user.cpp` / `src/user.hpp`: canonical numeric classes and PBKDF2-HMAC-SHA256 passwords.
- `src/user_commands.cpp` / `src/user_commands.hpp`: complete key grammar, validation and persistent command execution.
- `src/database.cpp` / `src/database.hpp`: mutex-serialized MariaDB operations and account invariants.
- `src/server.cpp` / `src/server.hpp`: listener, sessions, private commands, temporary classes, online IPv4 and optional reverse DNS.
- `src/config.cpp` / `src/config.hpp`: runtime configuration including `dns_lookup=0|1`.
- `src/version.cpp` / `src/version.hpp`: `0.0.05`, release identity, author and date.

Every production and test `*.cpp` has a matching `*.hpp` and vice versa.

## Persistent account model

`accounts` contains `id`, unique `nick`, nullable `password_hash`, compatibility `role`, signed `user_class`, `enabled`, `created_at` and `updated_at`. Supported classes are `-1, 0, 1, 2, 3, 4, 5, 10`; legacy `role` is not authoritative.

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

ADC VERIFY (`GPA`/`PAS`) is not implemented in v0.0.05. Therefore all `!set` commands require IPv4 loopback plus an enabled effective Admin (5) or Master (10). The first local Master with an initial password may be created only while no enabled account exists. `+passwd` is also loopback-only and performs a conditional first-password insert, preventing overwrite.

## Concurrency and deployment

The hub uses one worker thread per client. `clients_mutex_` protects live ADC state, `temporary_classes_mutex_` protects restart-scoped overrides, and `Database` serializes the MariaDB connection. DNS is executed outside the clients lock. The target deployment is Debian 13 with systemd, MariaDB, libmariadb and libgcrypt.

See ADR-0009 for the v0.0.05 decisions and trade-offs.
