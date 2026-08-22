<!--
changelog.md

v0.0.10:
  - add tagged password hashing, central RBAC and hostname bans
  - record compatibility and security boundaries for MD5/reverse DNS

v0.0.09:
  - add the protected per-hub home and local database settings administration
  - record secure repeat installation and reviewed release validation

v0.0.08:
  - add persistent, auditable kick and ban admission controls

v0.0.07:
  - add class/nickname policy, auto-registration and account security release

v0.0.06:
  - add moderation enforcement, timed privileges and ncdc interoperability

v0.0.05:
  - add the complete user administration and online-query release

v0.0.04:
  - add dc24h.eu-v0.0.04 password-lifecycle and user-list release

v0.0.03:
  - add dc24h.eu-v0.0.03 user-class and account-command release

v0.0.02:
  - add dc24h.eu-v0.0.02 protocol hardening release

v0.0.01:
  - start release history with dc24h.eu-v0.0.01

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# Changelog

## dc24h.eu-v0.0.10 — 2026-08-21

Author: `gpt-5.6-sol`

### Added

- Paired `rbac.cpp` / `rbac.hpp` module with explicit permissions and minimum
  user classes.
- Tagged `md5$…` password generation plus dual MD5/PBKDF2-SHA256 verification.
- Database password verification API for enabled accounts.
- Exact and leading-wildcard `host` ban targets with normalized admission
  matching and MariaDB constraint migration.
- ADR-0014 and the v0.0.10 release manifest.

### Changed

- Raised canonical runtime, CMake, test, documentation and systemd metadata to
  `0.0.10` / `dc24h.eu-v0.0.10`.
- Every parsed account/moderation command now crosses one central
  deny-by-default RBAC decision before execution.
- Operator (3) can perform bounded registration, view protected information and
  moderate live sessions; Admin (5) manages accounts and bans; Master (10)
  changes roles and global hub configuration. Existing contextual
  difference/capability checks remain.
- Admission performs reverse lookup only while a live hostname ban requires
  it. Existing IP, CIDR/range, nickname, CID, prefix and share targets remain.

### Security

- Unknown actions and roles have no implicit permission and fail closed.
- Hash formats are tagged and malformed/untagged values are rejected; digest
  comparisons are constant-time.
- MD5 is the requested compatibility default but is fast, unsalted and unsafe
  against offline guessing. Explicit PBKDF2-SHA256 generation remains
  available and is preferred for production until a memory-hard replacement is
  adopted.
- Reverse DNS is not authenticated. Host bans are convenience filters; IP/range
  bans and authenticated identity remain stronger boundaries.

### Validation

- Debian 13 warnings-as-errors Release build and CTest passed 8/8.
- MariaDB 11.8 schema application passed repeatedly with all 30 settings and
  the hostname target constraint intact.
- A live localhost hostname ban denied admission with ADC status 230 and was
  soft-revoked after the test.
- The active v0.0.10 systemd unit passed verification with exposure score 3.0.
- Real `ncdc 1.23.1` echoed the connection marker, reconnected after service
  restart and echoed the post-restart marker.
- Local pair, history, forbidden-name and diff checks passed; GitHub CI on PR
  #10 remains the final remote gate.

## dc24h.eu-v0.0.09 — 2026-08-21

Author: `gpt-5.6-sol`

### Added

- Protected hub home at `/var/lib/dc24h.eu/dc24h.eu`, with root-owned runtime,
  MariaDB and administration files.
- Strict `database.cnf` template containing the standard MariaDB `[client]`
  options read by Connector/C.
- Paired `settings_cli.cpp` / `settings_cli.hpp` executable target
  `/usr/local/bin/dc24h-settings`.
- Root-only `01-edit-hub-settings.sh HUB_HOME` wrapper with `list`, `get`, `set`
  and `check` operations.
- Split-configuration parser tests, CLI help, executable wrapper, shell syntax
  and ShellCheck CTest targets.
- ADR-0013 and the v0.0.09 release manifest.

### Changed

- Raised canonical runtime, CMake, test, documentation and systemd metadata to
  `0.0.09`.
- systemd now uses the protected hub home as `HOME`, working directory,
  configuration location and explicit read-only path.
- The active runtime file now contains `database_config=database.cnf`; the
  application validates the option file before Connector/C reads it.
- The installer migrates an existing home or legacy `/etc/dc24h.eu/dc24h.conf`,
  preserves non-database runtime options, updates the service-account home and
  preserves the existing home or legacy database password without a silent
  rotation.
- A clean install now obtains its password from a hidden prompt or an absolute
  root-owned mode-`0600` file named by `DC24H_DB_PASSWORD_FILE`; the environment
  carries only the file path. After an active service is confirmed, the legacy
  `/etc` configuration path becomes a symlink to the non-secret home config.
- Installation now orders Release build/CTest, database/schema setup, atomic
  config publication, validation with the just-built settings tool, artifact
  installation and restart.
- All setting snapshots now require exactly 30 canonical rows. Updates validate
  the complete candidate snapshot within a `FOR UPDATE` transaction.

### Security

- MariaDB credentials are separated from the ordinary runtime configuration
  and protected as `root:dc24h` mode `0640`.
- The option-file parser rejects mixed credentials, duplicate/unknown/missing
  keys, unsupported protocol/charset values, symlinks and unsafe permissions.
- The local administration path requires root, a canonical direct-child hub
  home with exact owner/modes, and exposes no arbitrary SQL or delete operation.
- Invalid settings or broken nickname/kick-ban invariants roll back without a
  partial write.
- Privileged scripts use `/bin/bash`, a fixed system `PATH`, root-only staging
  and explicit non-symlink checks. The password is not accepted as an
  environment-variable value or command argument.

### Validation

- Debian 13.6 clean Release build with warnings treated as errors completed;
  CTest, including ShellCheck, passed 8/8.
- The installer completed repeated executions. The final current-installer run
  took no new password, reused the existing `database.cnf` credential and
  performed no silent rotation or secret-valued environment input.
- `sql/schema.sql` was applied repeatedly and the database retained exactly 30
  canonical settings.
- Live `list`, `get`, `set` and `check`, invalid-key/range cases, both
  relational invariants and 12 concurrent update attempts completed with a
  successful final `check`.
- `dc24h.service` was active, its unit passed verification and
  `systemd-analyze security` reported exposure score `3.0`.
- A real Debian `ncdc 1.23.1` ADC/TIGR session echoed
  `ncdc-v0.0.09-connection-test`, then reconnected after service restart and
  echoed `ncdc-v0.0.09-after-restart`.
- Local forbidden-name, C++ pair and secret scans passed.
- Remote GitHub CI is the required final merge gate for PR #9.

## dc24h.eu-v0.0.08 — 2026-08-21

Author: `gpt-5.6-sol`

### Added

- Exact global keys `key.kicks=300` for the default kick rejoin delay and
  `key.bans=31536000` for the maximum temporary duration.
- Paired `moderation.cpp` / `moderation.hpp` target, duration and matcher module.
- Symmetric `key.kicks.add/remove/info/list` and
  `key.bans.add/remove/info/list` protected operations.
- Typed nickname, ADC CID, IPv4, range/CIDR, nickname-prefix and exact-share
  ban targets.
- MariaDB `moderation_entries` audit with UTC expiry and soft-revocation actor,
  time and reason.
- ADR-0012 and the v0.0.08 release manifest.

### Changed

- Raised canonical runtime, CMake, documentation and systemd metadata to
  `0.0.08`.
- Punitive kick now writes a nickname/CID rejoin block before socket shutdown;
  non-punitive disconnect remains unchanged.
- Active address bans are enforced after accept, and identity/share bans before
  ADC NORMAL.
- Duplicate INF names and post-login `NI`, `ID`, `PD` or `SS` changes are
  rejected.
- Expanded systemd sandboxing with empty capability sets, private devices,
  namespace/SUID/realtime restrictions, kernel/clock protection and `UMask`.

### Security

- Admission fails closed if the moderation lookup cannot reach MariaDB.
- Ban inputs use explicit target kinds and canonical IPv4 parsing instead of
  ambiguous target inference or operator-provided regular expressions.
- Ban history is never deleted by unban, and management remains loopback-only
  until ADC VERIFY authentication is implemented.

### Validation

- Debian 13 Release build with project warnings promoted to errors; CTest 2/2.
- Idempotent schema application twice on isolated MariaDB 11.8, with 30 seeded
  settings and the moderation table/index/constraint shape verified.
- Real `ncdc 1.23.1` ADC/TIGR echo with three clients, kick denial/revocation,
  timed ban denial, private list/info, soft-unban, restart persistence and
  Master-only broad/permanent authorization.
- Forbidden-name, C++ pair, secret and systemd unit checks.

## dc24h.eu-v0.0.07 — 2026-08-21

Author: `gpt-5.6-sol`

### Added

- Twenty-eight validated MariaDB-backed class, nickname, auto-registration and password settings.
- Paired `hub_settings.cpp` / `hub_settings.hpp` policy module.
- `+regme <password>` with configured class, prefix, share and password checks.
- Initial-password deadlines for passwordless accounts.
- Account authentication IPv4, email, public note and kick-message visibility controls.
- Login/logout timestamps, login count, last-login IPv4 and registering-actor metadata.
- ADR-0011 and the v0.0.07 release manifest.

### Changed

- Raised canonical release metadata and systemd description to `0.0.07`.
- Extended private user information with registration, login and security metadata.
- Enforced nickname policy and optional account IP binding during ADC identification.
- Enforced configured registration/kick differences and PM/download class reach.

### Validation

- Release build and assertion-enabled CTest suites.
- Isolated MariaDB schema/migration validation.
- Real `ncdc 1.23.1` ADC/TIGR connection, public-message echo, Master bootstrap,
  policy/profile updates and prefixed `+regme` telemetry validation.

### Security

- Protected `!set` remains loopback-only until ADC VERIFY is available.
- Self-registration is disabled by default and never assigns a class above Operator (3).
- Password material is intercepted before broadcast and stored only as PBKDF2-HMAC-SHA256.

## dc24h.eu-v0.0.06 — 2026-08-21

Author: `gpt-5.6-sol`

### Added

- Non-punitive online disconnect and class-protected kick commands.
- Permanent kick-protection, hidden-share, hidden-operator, visibility-threshold and private-note attributes.
- MariaDB `user_timed_policies` for gag, download/chat/PM/search restrictions and kick/share/register/OPChat privileges.
- Duration parser with `m`, `h`, `d`, default durations and 365-day maximum.
- Routing enforcement for ADC `MSG`, `SCH`, `CTM` and `RCM` families.
- Private `!opchat <message>` delivery for Operator+ and active grantees.
- Immediate connected-session policy refresh and user-info policy reporting.
- ADR-0010 and v0.0.06 release manifest.

### Changed

- Raised canonical version/service/documentation metadata to `0.0.06`.
- Recorded author/date as `gpt-5.6-sol` / `2026-08-21`.
- BASE/TIGR remain required in SUP, but are no longer incorrectly required in BINF `SU`.
- Personalized BINF output removes hidden share fields and standard ADC operator bits.
- Hidden users' INF and routed traffic are suppressed for recipients below the configured class.

### Validation

- Release build and assertion-enabled CTest suites.
- MariaDB schema validation on an isolated database.
- Real `ncdc 1.23.1` ADC/TIGR connection, public-message echo, Master bootstrap and gag-enforcement run.

### Security

- Delegated registration is capped at class 1.
- Protected kick rejects insufficient actor classes; non-punitive disconnect remains separate.
- Private notes never enter public routing.
- Existing IPv4 loopback boundary remains until ADC VERIFY.

## dc24h.eu-v0.0.05 — 2026-08-20

Author: `gpt-5.6-sol`

### Added

- Account removal, disable/enable, permanent class change and complete registered-account information keys.
- Password replacement/reset by nickname plus non-overwriting local `+passwd` first-password self-service.
- Restart-scoped temporary class changes capped at Admin (5).
- Private online IPv4, hostname, exact-address, inclusive-range and CIDR-subnet queries.
- Optional `dns_lookup=0|1`, disabled by default.
- MariaDB `accounts.updated_at` metadata and database administration APIs.
- Release-mode CTest configuration that keeps assertion checks enabled.
- ADR-0009 and the `dc24h.eu-v0.0.05` release manifest.

### Changed

- Raised all canonical release metadata to `0.0.05` / `dc24h.eu-v0.0.05`.
- Class listing accepts `[]` as class 0 and includes both enabled and disabled accounts with password-presence state.
- Effective authorization uses a temporary class when present.
- Documentation, Debian 13 installation examples and systemd description now target v0.0.05.

### Security

- Reject removal, disabling or demotion of the final enabled Master.
- Keep every management response private and intercept all password-bearing commands before broadcast.
- Keep `!set` and `+passwd` loopback-only until ADC VERIFY exists.
- Never expose password hashes; report only whether a password is set.
- Disable reverse DNS by default.

## dc24h.eu-v0.0.04 — 2026-08-20

Author: `gpt-5.6-sol`

### Added

- Passwordless account creation: `!set key.user.new.username.class=[username.class]`.
- First-password assignment: `!set key.user.new.id.password=[id.password]`.
- Private class-filtered account query: `!set key.user.info.userlist.class=[class]`.
- MariaDB `create_user_without_password`, conditional `add_user_password_if_missing`, and `users_by_class` APIs.
- `AddPasswordResult` and `UserListEntry` database models.
- Parser regression tests proving that first-password assignment and password replacement are distinct actions.
- ADR-0008 documenting the password lifecycle and private class-list behavior.

### Changed

- Raised canonical program/release version to `0.0.04` / `dc24h.eu-v0.0.04`.
- Project author/date metadata now records `gpt-5.6-sol`, `2026-08-20` for this release.
- `accounts.password_hash` is nullable so an account may exist before its first password is assigned.
- `key.user.new.id.password` is no longer a compatibility alias for password change.
- `key.user.change.id.password` is the only command that intentionally replaces an existing password.
- CMake project version and systemd service description now report v0.0.04.
- Architecture, engineering instructions, installation guide and documentation index now describe v0.0.04 behavior.

### Security

- `key.user.new.id.password` performs no write when a password already exists and tells the operator to use the explicit change command.
- Password-bearing commands remain intercepted before broadcast and responses do not echo plaintext passwords.
- Passwords remain persisted as salted PBKDF2-HMAC-SHA256 hashes.
- The current management channel remains loopback-only with Admin (5)/Master (10) authorization after first-Master bootstrap.

## dc24h.eu-v0.0.03 — 2026-08-19

Author: `gpt-5.6-sol`

### Added

- Numeric account classes: `-1, 0, 1, 2, 3, 4, 5, 10`.
- `src/user.cpp` / `src/user.hpp` with canonical class mapping and PBKDF2-HMAC-SHA256 password hashing.
- `src/user_commands.cpp` / `src/user_commands.hpp` with protected `!set key.user.*` parser/executor.
- User creation with password and password change by database ID.
- MariaDB class lookup and empty-account bootstrap support.
- First local Master bootstrap and ADR-0007.

### Changed

- Raised canonical program/release version to `0.0.03` / `dc24h.eu-v0.0.03`.
- `accounts` gained signed `user_class SMALLINT`; legacy `role` remained for migration compatibility.
- `Server` began intercepting supported `BMSG !set` commands and returning hub-local `IMSG` responses.

### Security

- Plaintext passwords are not persisted.
- Account mutations are loopback-only until registered-user ADC VERIFY exists.

## dc24h.eu-v0.0.02 — 2026-08-19

Author: `gpt-5.6-sol`

### Added

- ADC 1.0.4 connection state tracking for PROTOCOL, IDENTIFY and NORMAL.
- `TIGR` session-hash negotiation, strict ADC Base32 helpers and Tiger/192 PID-to-CID verification through libgcrypt.
- B/D/E/F routing, sanitized INF state, user-list synchronization, focused unit tests and ADR-0006.

### Security

- Prevent sender SID spoofing and PID leakage.
- Reject malformed ADC escaping, malformed message headers and unsupported BASE/TIGR negotiation.

## dc24h.eu-v0.0.01 — 2026-08-19

Author: `gpt-5.6-sol`

### Added

- Initial C++20/CMake ADC hub project.
- UTF-8 ADC listener and SID allocation.
- MariaDB `utf8mb4` schema and connection-event audit.
- Debian 13 installer, systemd service, US English locale baseline, CI, documentation and ADR set.
