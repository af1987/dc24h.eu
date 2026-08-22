<!--
dc24h.eu-v0.0.13.md

v0.0.13:
  - describe ADC input validation, explicit login flags and typed bans
  - record SQL escaping/NMDC boundaries and release verification

Author: gpt-5.6-sol
Date: 2026-08-22
-->

# dc24h.eu-v0.0.13

- Program/version: `dc24h.eu` / `0.0.13`
- Release: `dc24h.eu-v0.0.13`
- Protocol/text: ADC 1.0.4 BASE/TIGR / UTF-8
- Platform: C++20, MariaDB `utf8mb4`, Debian 13, systemd
- Development branch: `agent/dc24h-v0.0.13`
- Author/date: `gpt-5.6-sol`, `2026-08-22`

## Scope

This release hardens the untrusted ADC input path. It names and tests syntax,
length and login-order checks, records successful login stages in explicit
flags and adds reconnect-persistent temporary bans for protocol floods and
authentication/Authorization IP failures. Native ADC/ADCS from v0.0.12 remains
unchanged. ncdc is used only as a temporary test client; conforming clients such
as DC++ and EiskaltDC++ remain production peers.

## Active controls

| Boundary | Code | Behavior |
| --- | --- | --- |
| ADC syntax | `CheckProtoSyntax()` | valid UTF-8, ADC escapes, controls, header and token shape |
| Logical length | `CheckProtoLen()` | configured ceiling plus `MAX_MESS_SIZE` |
| Login order | `CheckUserLogin()` | PROTOCOL/HSUP, IDENTIFY/BINF, then NORMAL |
| Login state | `LoginFlag` | separate protocol, identity and NORMAL completion bits |
| Protocol flood | `CheckProtocolFlood()`, `eBT_FLOOD` | sliding per-IP command window and temporary ban |
| Authentication/IP | `LoginError()`, `mAuthIP`, `eBT_PASSW` | independent IP/account failure windows and temporary ban |
| SQL literals | `Database::WriteStringConstant()` | Connector/C connection-aware escaping; partial protection |

Defaults are 120 logical messages in 10 seconds and a 300-second flood ban.
The password/authentication profile remains five failures in 300 seconds with
a 900-second ban. An overlong line is closed and immediately receives the
flood-ban type.

## Compatibility boundaries

The hub speaks ADC only. NMDC Lock-to-Key and `Lock2Key()` are intentionally
absent because they belong to another protocol and are not modern
authentication. ADC BASE/TIGR negotiation and TIGR PID/CID validation remain
mandatory. Full remote ADC account authentication still requires a future
GPA/PAS design; current local management trust remains loopback-only.

`WriteStringConstant()` centralizes existing SQL literal escaping, but the
project does not claim that manual escaping equals query parameterization. New
database methods should use prepared statements, and existing methods should be
migrated with focused tests.

## Files

- Updated paired sources: `src/adc.cpp` / `src/adc.hpp`,
  `src/anti_abuse.cpp` / `src/anti_abuse.hpp`, `src/server.cpp` /
  `src/server.hpp`, `src/config.cpp` / `src/config.hpp`, and
  `src/database.cpp` / `src/database.hpp`.
- Updated paired tests: `tests/adc_tests.cpp` / `tests/adc_tests.hpp`,
  `tests/anti_abuse_tests.cpp` / `tests/anti_abuse_tests.hpp`, and
  `tests/config_tests.cpp` / `tests/config_tests.hpp`.
- Updated configuration, installer, CI, systemd unit, version and docs.
- ADR: `docs/adr/0017-adc-input-validation-and-protocol-flood-bans.md`.

Every created or changed human-maintained file records its v0.0.13 change and
the requested `gpt-5.6-sol` / `2026-08-22` provenance. Every production/test
`*.cpp` has a matching `*.hpp` and vice versa.

## Verification record

- Clean warnings-as-errors Release build: passed.
- CTest: 10/10 passed, including syntax/length/order, login flags, typed bans,
  protocol-flood windows, configuration, TLS and bounded I/O.
- Installer upgrade on Debian 13.6 passed, reused the protected MariaDB/TLS
  inputs, retained 30 canonical settings and activated the v0.0.13 systemd
  unit.
- `systemd-analyze verify` passed; the active service exposure score is
  `3.0 OK`.
- TLS 1.3 negotiated `TLS_AES_256_GCM_SHA384`; TLS 1.2 was rejected by the
  configured minimum.
- Live out-of-order BINF received `ISTA 244`; a protocol burst and a 65536-byte
  line each produced a reconnect-persistent `Protocol flood limit exceeded`
  ban.
- Real `ncdc 1.23.1` completed ADC/TIGR, echoed
  `ncdc-v0.0.13-connection-test`, automatically reconnected after a systemd
  restart and echoed `ncdc-v0.0.13-after-restart`.
- Shell syntax, ShellCheck, file-pair/history, forbidden-name and diff checks
  passed locally.

## Security references

- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
