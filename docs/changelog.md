<!--
changelog.md

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
