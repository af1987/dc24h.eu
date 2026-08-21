<!--
architecture.md

v0.0.09:
  - move runtime configuration into the protected per-hub home
  - split non-secret hub configuration from MariaDB Connector/C options
  - add transaction-safe local administration for all 30 hub settings
  - define repeatable credential reuse and atomic installer sequencing

v0.0.08:
  - add persistent kick/ban audit and typed admission targets
  - define pre-NORMAL enforcement, expiry, soft-unban and identity stability

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

# Architecture — dc24h.eu-v0.0.09

## Baseline

`dc24h.eu` is a C++20 Direct Connect hub for Debian 13. It implements the ADC
1.0.4 BASE/TIGR profile, validates UTF-8, stores persistent state in MariaDB
`utf8mb4`, uses US English / `en_US.UTF-8`, and runs under systemd. v0.0.09
places the installed instance in a protected per-hub home, separates MariaDB
credentials from normal runtime settings and adds a local validated settings
administration path. The v0.0.08 kick and ban admission model is unchanged.

## Runtime flow

1. systemd starts `/usr/local/bin/dc24h.eu /var/lib/dc24h.eu/dc24h.eu/dc24h.conf`
   after MariaDB, with that protected hub home as `HOME` and working directory.
2. `main` loads strict `key=value` runtime configuration, resolves the adjacent
   `database.cnf`, and selects the US UTF-8 locale.
3. The configuration layer validates exactly one MariaDB `[client]` section,
   all seven required options, file type and safe permissions. `Database` then
   asks MariaDB Connector/C to read that option file, connects with `utf8mb4`
   and applies idempotent schema updates.
4. `Server` listens on IPv4 TCP port 1511 by default, checks active address
   bans immediately after accept, and allocates a four-character ADC SID.
5. `AdcProtocol` negotiates BASE/TIGR in SUP, validates UTF-8/escaping, TIGR
   PID/CID identity, unique INF names and B/D/E/F routing. BINF `SU` is not
   required to repeat SUP features.
6. Before NORMAL, the server checks active nickname, CID, address, range,
   prefix and share targets. A lookup failure rejects admission.
7. NORMAL-state `BMSG` text beginning with `!set `, `+passwd ` or `+regme ` is intercepted before broadcast.
8. The server validates the loopback and class boundary, then delegates persistent operations to `UserCommandProcessor`/`Database` or evaluates live-session queries itself.
9. Runtime policy snapshots filter INF and routed commands before delivery.
10. The result is escaped and returned only to the requester as `IMSG`.

## Components

- `src/adc.cpp` / `src/adc.hpp`: ADC parsing, state machine and routing decisions.
- `src/hash.cpp` / `src/hash.hpp`: ADC Base32 and TIGR identity derivation.
- `src/user.cpp` / `src/user.hpp`: canonical numeric classes and PBKDF2-HMAC-SHA256 passwords.
- `src/hub_settings.cpp` / `src/hub_settings.hpp`: canonical policy keys, normalization and nickname checks.
- `src/moderation.cpp` / `src/moderation.hpp`: target normalization, duration parsing and admission matching.
- `src/user_commands.cpp` / `src/user_commands.hpp`: complete key grammar, duration parsing, validation and persistent command execution.
- `src/database.cpp` / `src/database.hpp`: mutex-serialized MariaDB operations,
  account invariants, UTC-expiring policies and transaction-safe setting snapshots.
- `src/server.cpp` / `src/server.hpp`: listener, sessions, moderation enforcement, private OPChat, temporary classes, online IPv4 and optional reverse DNS.
- `src/config.cpp` / `src/config.hpp`: runtime configuration, split MariaDB
  option-file validation, relative path resolution and legacy inline migration support.
- `src/settings_cli.cpp` / `src/settings_cli.hpp`: root-only `list`, `get`, `set`
  and `check` handling for the canonical 30 settings.
- `scripts/01-edit-hub-settings.sh`: validates the supplied hub-home boundary
  and delegates to `/usr/local/bin/dc24h-settings` without parsing credentials.
- `scripts/install.sh`: creates the hub home, migrates runtime configuration,
  securely creates or reuses protected MariaDB options, validates the staged
  deployment and installs/restarts the service.
- `src/version.cpp` / `src/version.hpp`: `0.0.09`, release identity, author and date.

Every production and test `*.cpp` has a matching `*.hpp` and vice versa.

## Per-hub deployment home

The installed instance has the fixed canonical home
`/var/lib/dc24h.eu/dc24h.eu`. The base directory is `root:root` mode `0755`;
the instance home and `scripts/` are `root:dc24h` mode `0750`. `dc24h.conf` and
`database.cnf` are `root:dc24h` mode `0640`, and the installed wrapper is mode
`0750`. The `dc24h` account uses the instance path as its account home but has
`/usr/sbin/nologin`. systemd additionally exposes the home through
`ReadOnlyPaths`, so the daemon can read but cannot replace its configuration or
administration script.

The active runtime file contains `database_config=database.cnf` and no inline
database credentials. A relative reference must be a basename beside
`dc24h.conf`; parent components and symbolic links are rejected. The option file
must define `protocol=tcp`, `host`, `port`, `database`, `user`, `password` and
`default-character-set=utf8mb4` exactly once beneath one `[client]` section.
Blank lines and option-file comments are allowed. The parser retains the older
inline `database_*` form only for migration compatibility and rejects mixing it
with `database_config`.

`01-edit-hub-settings.sh` requires root, an already canonical absolute home and
one safe direct child name beneath `/var/lib/dc24h.eu`. The compiled
`dc24h-settings` tool repeats the directory, ownership and mode checks, loads
the same split configuration and uses the normal `Config` and `Database`
layers. Neither component invokes a MariaDB command-line client or exposes raw
SQL.

On a clean installation, the root-only installer reads a new password from a
hidden prompt or from an absolute, root-owned, mode-`0600`, non-symlink regular
file selected by `DC24H_DB_PASSWORD_FILE`. The variable contains only a path,
not the secret. On a reinstall, an existing `database.cnf` is authoritative;
when migrating the combined legacy configuration, its inline password is
preserved. The installer rejects a new password file in either case and does
not silently issue `ALTER USER` or rotate the credential.

After building and passing CTest, the installer updates MariaDB and reapplies
the schema, atomically replaces both home configuration files, validates them
with the just-built `dc24h-settings` and canonical home argument, installs the
tested artifacts, and only then restarts the service. After the service is
active, the legacy
`/etc/dc24h.eu/dc24h.conf` path is atomically replaced by a symlink to the
non-secret home `dc24h.conf`. Privileged project scripts use `/bin/bash` and a
fixed system `PATH`.

## Persistent account model

`accounts` contains identity/password/class state, moderation fields,
authentication IP, email/public note, kick-message visibility, password-change
state and login/logout telemetry. `settings` stores validated class, nickname,
self-registration, password and kick/ban limits. `user_timed_policies` stores
one UTC expiry per account/policy. `moderation_entries` stores append-oriented
kick/ban actions, normalized targets, actor/reason, expiry and soft-revocation
audit. Supported classes remain `-1, 0, 1, 2, 3, 4, 5, 10`; legacy `role` is
not authoritative. The settings administration snapshot requires exactly 30
canonical rows. A `set` starts a MariaDB transaction, selects the complete
snapshot using `FOR UPDATE`, normalizes the candidate value, checks nickname
minimum/maximum and kick/ban invariants, then commits the upsert or rolls back.
This row locking coordinates the daemon and separate CLI processes rather than
relying only on an in-process mutex.

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

ADC VERIFY (`GPA`/`PAS`) is not implemented in v0.0.09. In-hub management
commands therefore require IPv4 loopback plus the configured class/capability
boundary. `+passwd` and enabled `+regme` are explicit self-service exceptions;
account IP binding and active moderation entries are enforced during
identification. The separate local settings tool has a different boundary:
root execution plus the protected hub-home ownership and mode contract.

## Hub policy and self-registration

MariaDB-backed `key.class.*` values control registration/kick differences, PM/download class reach and minimum classes. `key.nick.*` values are checked before a session becomes NORMAL. `+regme` is disabled by default and, when enabled, checks the selected class, optional prefix, class-specific `SS` byte threshold and minimum password length. Passwordless registrations receive a deadline; the server disconnects an unchanged account after the configured timeout.

## Moderation and routing

Persistent flags hide share fields and ADC operator CT bits during BINF construction. The self-visibility threshold filters user INF, broadcasts, direct messages and feature-routed traffic for lower-class recipients.

Timed policies are loaded with account state and checked against the current epoch. `gag`, `no_chat`, `no_pm`, `no_search` and `no_download` block their ADC command families before routing. `can_kick`, `can_register`, temporary hidden share and `opchat` enable only their documented capabilities. An update refreshes connected sessions immediately; expiry checks need no scheduler.

Protected kick and non-punitive disconnect are separate live-session operations.
`key.kicks` stores the default rejoin delay; `key.bans` stores the maximum
temporary duration. Kick checks the actor class, persists a nickname/CID entry,
then closes the socket. Disconnect closes the socket without an entry.

Ban targets are explicitly typed as nickname, CID, IPv4, inclusive range/CIDR,
nickname prefix or exact `SS` share size. Temporary rows stop matching at UTC
expiry; permanent rows have no expiry. Unban records revocation actor, time and
reason instead of deleting history. Address checks occur after accept, while
verified identity/share checks occur before NORMAL. `NI`, `ID`, `PD` and `SS` cannot
change after NORMAL, preventing identity-policy drift.

## Concurrency and deployment

The hub uses one worker thread per client. `clients_mutex_` protects live ADC
state, `moderation_mutex_` serializes admission decisions with new kick/ban
rows, `temporary_classes_mutex_` protects restart-scoped overrides, and each
`Database` object serializes its MariaDB connection. Transactional `FOR UPDATE`
locking protects a complete settings update across the daemon and CLI
connections. Socket writes use duplicated descriptors outside state locks and
fail closed without blocking on client backpressure. DNS is executed outside
the clients lock. The target deployment is Debian 13 with systemd, MariaDB,
libmariadb and libgcrypt.

See ADR-0013 for the v0.0.09 home, configuration and local administration
decision. ADR-0012 remains authoritative for kick/ban admission, and ADR-0011
remains authoritative for class, nickname and self-registration policy.

## v0.0.09 verification

The release candidate was verified on Debian 13.6 with a clean Release build
using warnings as errors and CTest 8/8, including ShellCheck. The installer ran
repeatedly; its final current-installer run reused the existing credential
without new password input. The schema was applied repeatedly and the complete
30-row snapshot
remained valid. `list`, `get`, `set` and `check`, invalid keys/ranges, both
relational invariants and 12 concurrent update attempts ended with a successful
final `check`. The systemd unit was active, passed unit verification and
received exposure score `3.0`. A real Debian `ncdc 1.23.1` client completed
ADC/TIGR echo and post-restart reconnect/echo. Local forbidden-name, C++ pair
and secret scans passed. Remote GitHub CI is the required final merge gate for
PR #9.
