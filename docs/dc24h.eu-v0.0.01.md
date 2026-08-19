<!--
dc24h.eu-v0.0.01.md

v0.0.01:
  - define release v0.0.01 scope, file manifest and limitations

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# dc24h.eu-v0.0.01

- Version: `0.0.01`
- Release name: `dc24h.eu-v0.0.01`
- Author: `gpt-5.6-sol`
- Date: `2026-08-19`
- Base branch: `main`
- Development branch: `agent/dc24h-v0.0.01`

## Release objective

Create the first maintainable, buildable foundation of `dc24h.eu` as an ADC Direct Connect hub for Debian 13.

## Technology baseline

- ADC
- UTF-8
- US English / `en_US.UTF-8`
- C++20
- MariaDB
- Debian 13
- systemd
- CMake

## File manifest

### Build and repository
- `.gitignore`
- `CMakeLists.txt`
- `VERSION`
- `.github/workflows/ci.yml`
- `README.md`

### C++ pairs
- `src/main.cpp` + `src/main.hpp`
- `src/version.cpp` + `src/version.hpp`
- `src/config.cpp` + `src/config.hpp`
- `src/database.cpp` + `src/database.hpp`
- `src/adc.cpp` + `src/adc.hpp`
- `src/server.cpp` + `src/server.hpp`

### Runtime/deployment
- `config/dc24h.conf.example`
- `sql/schema.sql`
- `deploy/dc24h.service`
- `scripts/install.sh`

### Documentation
- `docs/architecture.md`
- `docs/instructions.md`
- `docs/changelog.md`
- `docs/readme.md`
- `docs/install.md`
- `docs/dc24h.eu-v0.0.01.md`
- `docs/adr/*.md`

## Known limitations

This release is an architectural bootstrap, not a claim of complete ADC compatibility. Full protocol state validation, authentication, operator permissions, bans, ADCS/TLS, extension negotiation, anti-flood/rate limiting, IPv6 listener support, metrics and performance scaling remain future work.
