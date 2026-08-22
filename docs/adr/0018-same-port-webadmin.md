<!--
0018-same-port-webadmin.md

v0.0.14:
  - decide bounded ADC/HTTP multiplexing on existing listener ports
  - decide loopback-plus-bearer authorization and settings-only scope
  - decide protected token provisioning and prepared audit persistence

Author: gpt-5.6-sol
Date: 2026-08-22
-->

# ADR-0018: Same-port WebAdmin

- Status: Accepted
- Date: 2026-08-22
- Release: `dc24h.eu-v0.0.14`
- Author: `gpt-5.6-sol`

## Context

The hub already owns plaintext ADC and optional TLS-wrapped ADCS listener
ports. Administration before v0.0.14 was either a loopback-only ADC command or
a root-only local CLI. Operators need a browser interface without another
public listener, another daemon or a second configuration authority.

HTTP and ADC have distinguishable initial lines, but TCP can fragment any
prefix. Classification must therefore avoid treating a fragmented `GET` as ADC
or a fragmented `HSUP` as HTTP. It must also happen before ADC admission so a
dashboard refresh cannot consume a SID, connection slot or reconnect budget.
An administrative HTTP surface introduces authentication, request smuggling,
cross-origin, secret storage and audit concerns.

## Decision

1. The existing plaintext and TLS listener workers perform a bounded tri-state
   probe: need more bytes, ADC, or HTTP. Only an allowlisted HTTP method plus a
   complete `HTTP/1.1` request line selects WebAdmin. Everything else enters
   the unchanged ADC path.
2. TLS negotiation, when applicable, occurs before this application protocol
   probe. Thus port 1511 can serve ADC/HTTP and port 1512 can serve ADCS/HTTPS;
   no third listener is created. `tls_only_mode` continues to remove port 1511.
3. HTTP accepts CRLF framing, a mandatory `Host`, at most one
   `Content-Length`, no `Transfer-Encoding`, a configured 4–64 KiB total limit,
   and exactly one request per connection. Responses disable caching, framing,
   MIME sniffing and broad content/script connections with defensive headers.
4. Serve a data-free dashboard shell at `/webadmin`. Require a bearer token for
   every API request. Load that token from an absolute regular non-symlink file
   with owner-only permissions and compare it without early exit. Keep
   `webadmin_loopback_only=1` as the deployment default.
5. Limit v0.0.14 to release/capacity status and list/update operations for the
   30 canonical MariaDB-backed settings. Reuse the existing normalization,
   complete-snapshot validation, `FOR UPDATE` transaction and invariants. Do
   not add arbitrary SQL, file, account/password or process-control endpoints.
6. Append every attempted setting change to `webadmin_audit` with source,
   action, target, outcome and UTC timestamp. Use a MariaDB prepared statement
   for this new database write. Never store the bearer token in the database.
7. The installer creates a random 256-bit hexadecimal token only when absent,
   installs it as `dc24h:dc24h` mode `0600`, and preserves it on upgrade.

This ADR extends ADR-0013's settings-administration decision with an HTTP
interface. It does not supersede the root-only CLI, ADC validation in ADR-0017,
or TLS/timeout policy in ADR-0016.

## Consequences

- Browser administration and ADC clients coexist on the ports operators
  already expose; firewall and systemd listener configuration do not expand.
- HTTP connections are isolated from ADC capacity and anti-abuse accounting.
- Loopback plus token is suitable for local operation; deliberate remote use
  additionally needs HTTPS or a trusted authenticated local reverse proxy.
- The simple close-after-response HTTP profile avoids pipelining and transfer
  decoding ambiguity, at the cost of a new TCP connection per API request.
- The UI can change hub policy but cannot manage accounts, bans or the service;
  those remain on their existing authorization paths.
- A service-owned token is readable by the daemon by design. Host/root
  compromise remains outside this boundary, and rotation requires replacing
  the file followed by a service restart.

## Alternatives considered

- A dedicated WebAdmin port was rejected because the requirement is to operate
  on the hub port and an extra listener expands firewall and attack surface.
- A second web daemon or embedded third-party HTTP framework was rejected for
  this bounded API because it adds deployment/dependency complexity and can
  create a second settings authority.
- Basic authentication and tokens embedded in the HTML were rejected because
  browser credential caching and accidental disclosure are harder to control.
- Cookie sessions were deferred because they require login, expiry, CSRF and
  session persistence semantics not needed for the initial local panel.
- Exposing existing ADC `!set` text through HTTP was rejected because it would
  bypass typed endpoint scope and couple browser input to chat parsing.

## References

- [RFC 9112: HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [ADC 1.0.4 specification](https://dc-protocols.github.io/ADC.html)
