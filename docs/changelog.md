<!--
changelog.md

v0.0.02:
  - add dc24h.eu-v0.0.02 protocol hardening release

v0.0.01:
  - start release history with dc24h.eu-v0.0.01

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# Changelog

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
