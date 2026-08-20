<!--
changelog.md

v0.0.03:
  - add dc24h.eu-v0.0.03 user-class and account-command release

v0.0.02:
  - add dc24h.eu-v0.0.02 protocol hardening release

v0.0.01:
  - start release history with dc24h.eu-v0.0.01

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# Changelog

## dc24h.eu-v0.0.03 — 2026-08-19

Author: `gpt-5.6-sol`

### Added

- Numeric account classes: `-1, 0, 1, 2, 3, 4, 5, 10`.
- `src/user.cpp` / `src/user.hpp` with canonical class mapping and PBKDF2-HMAC-SHA256 password hashing.
- `src/user_commands.cpp` / `src/user_commands.hpp` with `!set key.user.*` parser/executor.
- `!set key.user.new.username.class.password=[username.class.password]`.
- `!set key.user.change.id.password=[id.password]`.
- `!set key.user.new.id.password=[id.password]` compatibility alias.
- MariaDB account creation, password change by database ID and class lookup methods.
- Local first-Master bootstrap when there are no enabled accounts.
- `tests/user_commands_tests.cpp` / `tests/user_commands_tests.hpp`.
- ADR-0007 for user classes, password storage and the temporary management trust boundary.

### Changed

- Raised canonical program/release version to `0.0.03` / `dc24h.eu-v0.0.03`.
- `accounts` now has signed `user_class SMALLINT`; legacy `role` remains for migration compatibility.
- `Server` intercepts supported `BMSG !set` commands before broadcast and replies with hub-local `IMSG`.
- Account-changing `!set` commands require IPv4 loopback and an enabled Admin (5) or Master (10) account after bootstrap.
- systemd description and current documentation now report v0.0.03.
- CMake/CTest includes user-command and password-hash regression coverage.

### Security

- Plaintext account passwords are not persisted.
- Passwords are encoded as salted PBKDF2-HMAC-SHA256 with 210000 iterations.
- Password-bearing commands are not broadcast to other hub users.
- Remote ADC nicknames are not accepted as proof of authorization while `GPA`/`PAS` remains unimplemented.

## dc24h.eu-v0.0.02 — 2026-08-19

Author: `gpt-5.6-sol`

### Added

- ADC 1.0.4 connection state tracking for PROTOCOL, IDENTIFY and NORMAL.
- `TIGR` session-hash negotiation alongside `BASE`.
- Strict ADC Base32 encode/decode helpers.
- Tiger/192 PID-to-CID verification through libgcrypt `TIGER1`.
- B/D/E/F routing with feature filters for F-type traffic.
- Merged sanitized client INF state and user-list synchronization for newly identified clients.
- Focused unit tests and CTest integration.
- ADR-0006 for ADC 1.0.4 state and TIGR policy.

### Changed

- Raised canonical program/release version to `0.0.02` / `dc24h.eu-v0.0.02`.
- Initial `BINF` now requires the assigned SID plus `ID`, `PD`, `NI` and `SU`.
- Client `PD` is removed before INF is forwarded.
- `I40.0.0.0` is replaced with the peer IPv4 address; conflicting explicit IPv4 values are rejected.
- Sender SID is checked before B/D/E/F routing.
- CI and Debian installer now install `libgcrypt20-dev` and execute CTest.
- systemd description now reports v0.0.02.

### Security

- Prevent client SID spoofing in routed messages.
- Prevent private PID leakage to other clients.
- Reject malformed ADC escape sequences and malformed message headers.
- Reject clients without the required ADC BASE/TIGR profile.

## dc24h.eu-v0.0.01 — 2026-08-19

Author: `gpt-5.6-sol`

### Added

- Initial C++20 project and CMake build.
- ADC TCP listener with newline framing.
- ADC SUP/SID/INF handshake foundation.
- UTF-8 validation and ADC metadata escaping.
- Four-character, 20-bit Base32 SID allocation.
- Basic routing for `BINF`, `BMSG`, `BSCH`, `BRES` and `BQUI`.
- MariaDB connection, `utf8mb4`, initial schema and connection event audit.
- Debian 13 installer.
- systemd service with a dedicated account and hardening.
- US English / `en_US.UTF-8` baseline.
- GitHub Actions build on a Debian 13 container.
- Architecture documentation, engineering instructions and ADR set.
- Per-file change/version headers.
