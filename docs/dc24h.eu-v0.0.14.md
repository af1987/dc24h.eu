<!--
dc24h.eu-v0.0.14.md

v0.0.14:
  - describe same-port WebAdmin, protected token and bounded HTTP profile
  - record canonical settings administration, audit and release verification

Author: gpt-5.6-sol
Date: 2026-08-22
-->

# dc24h.eu-v0.0.14

- Program/version: `dc24h.eu` / `0.0.14`
- Release: `dc24h.eu-v0.0.14`
- Protocol/text: ADC 1.0.4 BASE/TIGR / UTF-8
- Platform: C++20, MariaDB `utf8mb4`, Debian 13, systemd
- Development branch: `agent/dc24h-v0.0.14`
- Author/date: `gpt-5.6-sol`, `2026-08-22`

## Scope

This release adds a WebAdmin dashboard and settings API to the existing hub
listener. Plain port 1511 serves ADC and HTTP; encrypted port 1512 serves ADCS
and HTTPS when enabled. No separate administration port is opened. The ADC
protocol, UTF-8 policy and compatibility with conforming clients such as DC++
and EiskaltDC++ remain unchanged. ncdc is used only as a temporary connection
test client.

## HTTP and authorization profile

| Boundary | Behavior |
| --- | --- |
| Protocol probe | Fragment-safe, at most 1024 bytes, before ADC admission |
| HTTP framing | HTTP/1.1, CRLF, `Host`, one `Content-Length`, no transfer encoding |
| Request memory | `webadmin_max_request_size`, default 16384 bytes |
| Network policy | loopback-only by default |
| API authentication | bearer token, constant-time comparison |
| Token storage | absolute non-symlink owner-only file; never MariaDB/API/log |
| Response policy | no-store, restrictive CSP, frame/MIME/referrer controls |
| Connection model | one request then close |

The dashboard shell is served at `/webadmin`. It contains no token or settings
until the operator supplies the token. API routes are:

- `GET /webadmin/api/v1/status`
- `GET /webadmin/api/v1/settings`
- `PUT /webadmin/api/v1/settings` with `key\nvalue` UTF-8 text

Only canonical hub settings can be changed. The existing MariaDB transaction
locks and validates all 30 settings before committing, including nickname and
kick/ban cross-key invariants. Each attempted write is recorded in
`webadmin_audit` by a prepared statement.

## Deployment

The installer creates
`/var/lib/dc24h.eu/dc24h.eu/webadmin.token` from 256 random bits on a clean
installation, owns it as `dc24h:dc24h` mode `0600`, and preserves it on
upgrade. Runtime defaults are:

```ini
webadmin_enabled=1
webadmin_loopback_only=1
webadmin_token_file=/var/lib/dc24h.eu/dc24h.eu/webadmin.token
webadmin_max_request_size=16384
```

Changing this file or its token requires a systemd service restart. Public
non-loopback access should use HTTPS with a trusted certificate or an
authenticated local reverse proxy; plaintext remote administration is not a
supported secure deployment.

## Files

- Created paired implementation: `src/webadmin.cpp` / `src/webadmin.hpp`.
- Created paired tests: `tests/webadmin_tests.cpp` /
  `tests/webadmin_tests.hpp`.
- Updated server/config/database pairs, MariaDB schema, installer, systemd,
  example configuration, version metadata and required documentation.
- ADR: `docs/adr/0018-same-port-webadmin.md`.

Every created production/test `*.cpp` has a matching `*.hpp`. Human-maintained
changed files record v0.0.14 and the requested `gpt-5.6-sol` / `2026-08-22`
provenance.

## Verification record

- Warnings-as-errors Release build: passed.
- CTest: 11/11 passed, including same-port WebAdmin, ADC, TLS, bounded I/O,
  configuration, authorization and anti-abuse suites.
- The installer completed on Debian 13.6, generated/preserved the protected
  token, retained 30 canonical settings and activated the v0.0.14 unit.
- MariaDB schema application passed twice; `webadmin_audit` exists and a valid
  no-value-change settings PUT produced a successful audit row.
- HTTP dashboard returned 200, unauthenticated API returned 401, authenticated
  HTTP and HTTPS status returned 200, and the settings API returned all 30
  rows. Live testing found and fixed locale-grouped `Content-Length`; the
  regression suite now covers responses larger than 1000 bytes under
  `en_US.UTF-8`.
- `systemd-analyze verify` passed and the active service exposure score is
  `3.0 OK`. TLS 1.3 negotiated `TLS_AES_256_GCM_SHA384`; TLS 1.2 was rejected.
- Real `ncdc 1.23.1` completed ADC/TIGR and echoed
  `ncdc-v0.0.14-connection-test` after repeated HTTP requests. It automatically
  reconnected after systemd restart and echoed `ncdc-v0.0.14-after-restart`.
- Shell syntax, ShellCheck, C++ file pairing, history, forbidden-name and diff
  checks passed locally.

## Known boundaries

- v0.0.14 WebAdmin does not manage accounts, bans, TLS keys or systemd.
- IPv4 listener behavior remains unchanged; loopback recognition also accepts
  `::1` for a future IPv6 listener.
- Bearer tokens are reusable credentials. Rotation and short-lived browser
  sessions are future work.

## Security references

- [RFC 9112: HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
