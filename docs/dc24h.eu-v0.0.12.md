<!--
dc24h.eu-v0.0.12.md

v0.0.12:
  - describe native ADCS/TLS-only transport and certificate deployment
  - record hard buffer limits, phase timeouts and release verification

Author: gpt-5.6-sol
Date: 2026-08-22
-->

# dc24h.eu-v0.0.12

- Program/version: `dc24h.eu` / `0.0.12`
- Release: `dc24h.eu-v0.0.12`
- Protocol/text: ADC / UTF-8
- Platform: C++20, MariaDB `utf8mb4`, Debian 13, systemd
- Development branch: `agent/dc24h-v0.0.12`
- Author/date: `gpt-5.6-sol`, `2026-08-22`

## Scope

This release adds native ADCS without replacing the ADC protocol engine.
Plain port 1511 and TLS port 1512 feed the same state machine; operators can
enable `tls_only_mode` to remove plaintext service. ncdc is used temporarily
for connection tests, while production remains compatible with conforming ADC
clients such as DC++ and EiskaltDC++.

## TLS controls

- CMake features: `USE_TLS_PROXY`, `USE_FEARTLS_PROXY`.
- Runtime keys: `tls_enabled`, `tls_only_mode`, `tls_port`,
  `tls_certificate`, `tls_private_key`, `tls_min_version` and
  `tls_handshake_timeout`.
- Accepted minimum versions: TLS 1.2 and TLS 1.3; release default: TLS 1.3.
- Disabled: TLS compression, renegotiation and TLS 1.3 early data.
- Certificate/key files must be absolute regular non-symlink files; the key
  cannot be world-readable or group/world writable.
- The clean installer generates a protected one-year bootstrap certificate
  and never overwrites an existing complete pair. Public deployments replace
  it with a CA-issued certificate.

## Resource and timeout controls

| Control | Default | Enforcement |
| --- | ---: | --- |
| `MAX_MESS_SIZE` | 65535 bytes | non-configurable logical-line ceiling |
| `mLineSizeMax` | 65535 bytes | checked by `ReadLineLocal()` before append; overflow closes |
| `MAX_SEND_SIZE` | 1048576 bytes | non-configurable outgoing-message ceiling |
| `max_outbuf_size` | 262144 bytes | per-message operational output ceiling |
| `Key` | 10 s | ADC SUP/protocol negotiation |
| `ValidateNick` | 15 s | ADC INF identity phase |
| `Login` | 30 s | total pre-NORMAL exchange |
| `MyINFO` | 30 s | INF processing |
| `Password` | 30 s | required initial password setup |
| `General` | 120 s | NORMAL idle and bounded write deadline |

TLS handshake timeout is separately configured as 10 seconds. Existing
v0.0.11 password, IP authorization, per-IP, reconnect and clone protections
remain active on both listener paths.

## Files

- New paired sources: `src/io_limits.cpp` / `src/io_limits.hpp` and
  `src/tls_transport.cpp` / `src/tls_transport.hpp`.
- New paired tests: `tests/security_transport_tests.cpp` /
  `tests/security_transport_tests.hpp`.
- Updated configuration, server, installer, CMake, CI and systemd unit.
- ADR: `docs/adr/0016-native-tls-bounded-io-and-timeouts.md`.

Every created or changed human-maintained file records its v0.0.12 change and
the requested `gpt-5.6-sol` / `2026-08-22` provenance. Every production/test
`*.cpp` has a matching `*.hpp` and vice versa.

## Verification record

- Clean warnings-as-errors Release build: passed.
- CTest: 10/10 passed, including TLS settings, fragmented/overflow input,
  output ceilings and strict configuration tests.
- Bash syntax and ShellCheck: passed.
- Runtime version: `0.0.12`; release name: `dc24h.eu-v0.0.12`.
- Installer clean upgrade/reinstall: passed; existing MariaDB credential and
  TLS pair were preserved, 30 settings validated, and the unit remained active.
- OpenSSL: TLS 1.3 negotiated `TLS_AES_256_GCM_SHA384`; TLS 1.2 was rejected by
  the configured minimum. TLS-only mode exposed 1512 and did not expose 1511,
  then the normal dual-listener policy was restored.
- A 65536-byte logical line received fatal `ISTA 240` and EOF. An idle SUP
  connection received `ISTA 230` and EOF after 10.01 seconds.
- Real `ncdc 1.23.1` completed ADC/TIGR and echoed
  `ncdc-v0.0.12-connection-test`, automatically reconnected after a systemd
  restart and echoed `ncdc-v0.0.12-after-restart`; it also completed ADCS and
  echoed `ncdc-v0.0.12-adcs-test`.
- `systemd-analyze verify` passed and the active unit's security exposure score
  remained `3.0 OK`.

## Security references

- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
