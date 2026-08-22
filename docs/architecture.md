<!--
architecture.md

v0.0.13:
  - add explicit ADC syntax, length, login-order and login-flag boundaries
  - add typed protocol-flood/authentication bans and SQL escaping status

v0.0.12:
  - add native ADCS with configurable TLS minimum and TLS-only operation
  - add hard line/output ceilings and phase-specific connection timeouts
  - document certificate deployment and ncdc as a test client only

v0.0.11:
  - adopt Argon2id with read-only legacy verification and automatic upgrade
  - add active IP, reconnect, password-failure and clone protections
  - document bounded runtime controls and OWASP rationale

v0.0.10:
  - add tagged MD5/PBKDF2 password verification architecture
  - centralize deny-by-default RBAC command authorization
  - extend persistent admission controls with hostname targets

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
Date: 2026-08-22
-->

# Architecture — dc24h.eu-v0.0.13

## Baseline

`dc24h.eu` is a C++20 Direct Connect hub for Debian 13. It implements the ADC
1.0.4 BASE/TIGR profile, validates UTF-8, stores persistent state in MariaDB
`utf8mb4`, uses US English / `en_US.UTF-8`, and runs under systemd. v0.0.13
retains native ADCS and bounded transports, then makes ADC syntax, logical-line
length, login ordering, login flags and protocol-flood enforcement explicit.

## Runtime flow

1. systemd starts `/usr/local/bin/dc24h.eu /var/lib/dc24h.eu/dc24h.eu/dc24h.conf`
   after MariaDB, with that protected hub home as `HOME` and working directory.
2. `main` loads strict `key=value` runtime configuration, resolves the adjacent
   `database.cnf`, and selects the US UTF-8 locale.
3. The configuration layer validates exactly one MariaDB `[client]` section,
   all seven required options, file type and safe permissions. `Database` then
   asks MariaDB Connector/C to read that option file, connects with `utf8mb4`
   and applies idempotent schema updates.
4. `Server` listens on IPv4 TCP port 1511 for ADC and, when compiled and
   configured, port 1512 for ADCS. OpenSSL performs a deadline-bounded TLS
   handshake before ADC input is parsed. In `tls_only_mode`, port 1511 is not
   opened. `AntiAbuse` rejects a
   current temporary ban, an over-limit source address or a reconnect inside
   the configured interval before database and DNS admission work. The server
   then checks active address,
   range and (when configured by an active entry) reverse-hostname bans after
   accept, and allocates a four-character ADC SID.
5. Before routing, `CheckProtoLen()` applies configured/hard length ceilings,
   `CheckProtoSyntax()` validates UTF-8, ADC escaping and allowlisted headers,
   and `CheckUserLogin()` checks message order against explicit protocol,
   identity and NORMAL flags. `AdcProtocol` then negotiates BASE/TIGR, validates
   TIGR PID/CID identity, unique INF names and B/D/E/F routing. BINF `SU` is not
   required to repeat SUP features.
6. Before NORMAL, the server checks active nickname, CID, address, range, host,
   prefix and share targets, `mAuthIP`, and the configured AP/VE clone count. A
   database lookup failure rejects admission.
7. NORMAL-state `BMSG` text beginning with `!set `, `+passwd ` or `+regme ` is intercepted before broadcast.
8. The server validates the loopback boundary, maps the parsed action through
   central deny-by-default RBAC, applies contextual class/capability rules, then
   delegates persistent operations to `UserCommandProcessor`/`Database` or
   evaluates live-session queries itself.
9. Runtime policy snapshots filter INF and routed commands before delivery.
10. The result is escaped and returned only to the requester as `IMSG`.

## Components

- `src/adc.cpp` / `src/adc.hpp`: ADC parsing, state machine and routing decisions.
- `src/hash.cpp` / `src/hash.hpp`: ADC Base32 and TIGR identity derivation.
- `src/user.cpp` / `src/user.hpp`: canonical numeric classes, Argon2id password
  writes, legacy MD5/PBKDF2 verification and upgrade detection.
- `src/anti_abuse.cpp` / `src/anti_abuse.hpp`: temporary IP bans, independent
  failure windows, connection/reconnect limits, `mAuthIP`, clone accounting and
  sliding protocol-command windows with `eBT_FLOOD`/`eBT_PASSW` types.
- `src/io_limits.cpp` / `src/io_limits.hpp`: `ReadLineLocal()`, the hard
  `MAX_MESS_SIZE`/`MAX_SEND_SIZE` ceilings and configurable
  `mLineSizeMax`/`max_outbuf_size` limits.
- `src/tls_transport.cpp` / `src/tls_transport.hpp`: OpenSSL server context,
  `USE_TLS_PROXY`/`USE_FEARTLS_PROXY`, handshake deadlines and one bounded
  raw-or-encrypted socket abstraction.
- `src/rbac.cpp` / `src/rbac.hpp`: command permissions, minimum class hierarchy
  and deny-by-default authorization decisions.
- `src/hub_settings.cpp` / `src/hub_settings.hpp`: canonical policy keys, normalization and nickname checks.
- `src/moderation.cpp` / `src/moderation.hpp`: target normalization, duration parsing and admission matching.
- `src/user_commands.cpp` / `src/user_commands.hpp`: complete key grammar, duration parsing, validation and persistent command execution.
- `src/database.cpp` / `src/database.hpp`: mutex-serialized MariaDB operations,
  account invariants, UTC-expiring policies, transaction-safe setting snapshots
  and centralized `WriteStringConstant()` SQL literal escaping.
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
- `src/version.cpp` / `src/version.hpp`: `0.0.13`, release identity, author and date.

## Input-validation and temporary-ban boundary

Socket data is rejected before database, DNS or routing work when it violates
the ADC length, syntax or session-order contract. Each accepted logical line is
also recorded in a bounded sliding per-IP window. Exceeding
`protocol_flood_limit` within `protocol_flood_window` calls
`AddIPTempBan(..., eBT_FLOOD)` for `protocol_flood_tmpban` seconds. An overlong
logical line is treated as an immediate flood event and closed.

Password failures and Authorization IP mismatches feed independent IP/account
windows; reaching the threshold applies `eBT_PASSW` for `pwd_tmpban` seconds.
The current ADC profile does not expose GPA/PAS, so account passwords are not a
complete remote ADC authentication mechanism. The design intentionally omits
NMDC Lock-to-Key: ADC BASE/TIGR and TIGR PID/CID are used instead.

SQL strings currently pass through `Database::WriteStringConstant()` using the
active MariaDB connection. This prevents unescaped literal concatenation in
the existing query layer but remains weaker and harder to audit than prepared
statements; all new query APIs should prefer bound parameters.

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

The `tls/` directory is also `root:dc24h` mode `0750`; `server.crt` and
`server.key` are `root:dc24h` mode `0640`. A clean install creates a temporary
self-signed bootstrap certificate without overwriting an existing pair.
Operators should replace it atomically with a CA-issued certificate before
public service. The private key may not be a symlink, world-readable or
group/world writable.

## Secure and bounded transport

Both listener paths feed the same ADC state machine and support ordinary ADC
clients such as DC++, EiskaltDC++ and other conforming implementations. `ncdc`
is only the automated interoperability client; it is not a runtime dependency
or a client restriction.

The CMake switches `USE_TLS_PROXY` and `USE_FEARTLS_PROXY` expose encrypted
transport capability. Runtime keys select certificate, private key, ADCS port,
handshake deadline and minimum `TLS1.2` or `TLS1.3`; the supplied profile uses
TLS 1.3. Compression, renegotiation and TLS 1.3 early data are disabled.

Input is accumulated only by `ReadLineLocal()`. A logical ADC line longer than
`mLineSizeMax` is rejected before another append and closes the connection;
`MAX_MESS_SIZE` is the non-configurable upper ceiling. Every outgoing message
must fit both `max_outbuf_size` and `MAX_SEND_SIZE`. Synchronous bounded writes
avoid an unbounded per-client queue.

Timeout keys map to protocol stages: `Key` covers SUP negotiation,
`ValidateNick` covers INF identity validation, `Login` caps the whole
pre-NORMAL exchange, `MyINFO` caps INF processing, `Password` caps required
first-password setup, and `General` caps normal-session idle time and bounded
writes. TLS handshakes have an independent deadline.

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

New password writes use the standard Argon2id PHC representation with a
16-byte random salt and OWASP's minimum `m=19456 KiB`, `t=2`, `p=1` profile.
Verification accepts legacy tagged `md5$…` and PBKDF2-HMAC-SHA256 records only
to migrate them: after a successful check, the same row is conditionally
updated to Argon2id. Malformed or untagged hashes fail closed. Plaintext
passwords and hashes are never returned in command messages, and new MD5
records cannot be created.

## Connection-abuse model

`AntiAbuse` owns synchronized monotonic-clock state. `AddIPTempBan()` stores an
expiry and generic reason; `LoginError()` uses independent per-account and
per-IP sliding windows and applies `pwd_tmpban` after the configured threshold.
`CntConnIP()` enforces `max_users_from_ip`; disconnect timestamps trigger a
temporary ban with reason `Reconnecting too fast`. `CheckUserClone()` counts
equal AP/VE fingerprints per source IP when `clone_detect_count` is nonzero and
releases its count on disconnect. `mAuthIP()` admits an unbound account or an
exact configured address only. All durations and counts are bounded during
configuration loading.

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

ADC VERIFY (`GPA`/`PAS`) is not implemented in v0.0.11. In-hub management
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
exact/leading-wildcard reverse hostname, nickname prefix or exact `SS` share
size. Hostname bans trigger reverse lookup only while an active host entry
exists; they are convenience controls because PTR data is not authenticated.
Temporary rows stop matching at UTC
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
libmariadb, libgcrypt and libargon2.

See ADR-0015 for Argon2id and connection-abuse decisions. ADR-0014 remains the
historical password compatibility, RBAC and host-ban decision. ADR-0013
remains authoritative for the protected home and local administration;
ADR-0012 remains authoritative for the rest of kick/ban admission.

## v0.0.11 verification

Debian 13 warnings-as-errors Release build and CTest pass 9/9. The focused test
covers password bans, address binding, per-IP limits, reconnect throttling and
clone detection; password regression covers Argon2id and legacy reads. MariaDB
11.8 retained 30 canonical settings, the installed systemd unit is active with
exposure score 3.0, and real `ncdc 1.23.1` echoed both the connection and
post-restart markers. The release manifest records the complete validation.
