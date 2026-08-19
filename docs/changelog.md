<!--
changelog.md

v0.0.01:
  - start release history with dc24h.eu-v0.0.01

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# Changelog

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
