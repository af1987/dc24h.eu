<!--
dc24h.eu-v0.0.02.md

v0.0.02:
  - define release v0.0.02 scope, manifest, validation and limitations

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# dc24h.eu-v0.0.02

- Version: `0.0.02`
- Release name: `dc24h.eu-v0.0.02`
- Author: `gpt-5.6-sol`
- Date: `2026-08-19`
- Base branch: `main`
- Development branch: `agent/dc24h-v0.0.02`
- Target OS: Debian 13
- Service manager: systemd
- Database: MariaDB
- Language: C++20
- Base locale: US English / `en_US.UTF-8`

## Release objective

Advance the initial ADC hub foundation from stateless message-prefix routing to a stateful ADC 1.0.4 BASE/TIGR client-hub core with identity privacy, sender validation and correct B/D/E/F routing semantics.

## ADC profile

The v0.0.02 hub:

- expects the client to begin with `HSUP`;
- requires `ADBASE` and `ADTIGR`;
- replies with `ISUP ADTIGR ADBASE`;
- assigns a 20-bit four-character Base32 SID through `ISID`;
- sends hub `IINF` with `CT32`, name, description, version and supported features;
- accepts initial client `BINF` only in IDENTIFY;
- requires initial `ID`, `PD`, `NI` and `SU`;
- verifies `CID = Tiger(decoded PID)`;
- removes `PD` before forwarding client INF;
- enters NORMAL after successful identification.

## Routing profile

- B-type messages: all NORMAL clients, including sender.
- D-type messages: target SID only.
- E-type messages: target SID and sender.
- F-type messages: NORMAL clients matching required/excluded feature selectors.
- H-type messages: consumed by the hub, not forwarded.

All routed B/D/E/F headers are checked so that their sender SID equals the SID assigned to the TCP connection.

## Technology baseline

- ADC 1.0.4
- TIGR extension / Tiger/192 session hash
- UTF-8
- US English / `en_US.UTF-8`
- C++20
- CMake
- libgcrypt
- MariaDB
- Debian 13
- systemd

## Changed file manifest

### Build/repository

- `CMakeLists.txt`
- `VERSION`
- `.github/workflows/ci.yml`
- `README.md`

### C++ production

- `src/main.cpp`
- `src/version.cpp`
- `src/version.hpp`
- `src/adc.cpp`
- `src/adc.hpp`
- `src/server.cpp`
- `src/server.hpp`
- `src/hash.cpp` — new
- `src/hash.hpp` — new

### C++ tests

- `tests/adc_tests.cpp` — new
- `tests/adc_tests.hpp` — new

### Runtime/deployment

- `deploy/dc24h.service`
- `scripts/install.sh`

### Documentation

- `docs/architecture.md`
- `docs/instructions.md`
- `docs/changelog.md`
- `docs/readme.md`
- `docs/install.md`
- `docs/dc24h.eu-v0.0.02.md` — new
- `docs/adr/0006-adc-1.0.4-state-tigr.md` — new

## Validation

The v0.0.02 change adds CTest coverage for:

- ADC Base32 PID/CID data;
- Tiger/192 PID-to-CID verification with a fixed 24-byte PID vector;
- `HSUP -> ISUP/ISID/IINF` transition;
- initial `BINF` transition to NORMAL;
- removal of `PD`;
- replacement of `I40.0.0.0` with the connected peer IPv4 address;
- D-type target routing decision;
- rejection of sender SID spoofing.

CI builds and runs these tests inside a Debian 13 container.

## Known limitations

- Registered-user VERIFY state (`GPA`/`PAS`) is not implemented.
- Account/password, operator permission and ban enforcement are not implemented.
- Unicode NFC normalization is documented by ADC but not yet enforced by a normalization library.
- ADCS/TLS is not implemented.
- Listener is IPv4-only.
- No anti-flood/rate limiting or production metrics yet.
- Feature support is limited to the BASE/TIGR session profile; the hub is not claiming every ADC extension.
- The one-thread-per-client model remains from v0.0.01.

These limitations must remain visible until addressed by later versioned changes and ADRs.
