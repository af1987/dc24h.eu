<!--
0017-adc-input-validation-and-protocol-flood-bans.md

v0.0.13:
  - decide early ADC syntax, length and login-order validation
  - decide explicit login flags and typed flood/authentication temporary bans
  - record SQL escaping and NMDC Lock-to-Key compatibility boundaries

Author: gpt-5.6-sol
Date: 2026-08-22
-->

# ADR-0017: ADC input validation and protocol-flood temporary bans

- Status: Accepted
- Date: 2026-08-22
- Release: `dc24h.eu-v0.0.13`
- Author: `gpt-5.6-sol`

## Context

ADR-0001 chose an ADC-only UTF-8 hub, ADR-0006 established the ADC state
machine, ADR-0015 introduced connection abuse controls, and ADR-0016 bounded
transport memory and time. The remaining input boundary was distributed across
the reader and parser, without named validation entry points, explicit
completion flags or a command-rate temporary-ban policy.

OWASP recommends validating untrusted data as early as possible, enforcing
syntactic and semantic constraints and bounding length. It also recommends
resource/rate limits for denial-of-service resistance and generic, throttled
authentication failures. Existing SQL literal escaping needs one named boundary
and an explicit statement that parameterized queries are preferred.

## Decision

1. Every complete ADC logical line passes `CheckProtoLen()` and
   `CheckProtoSyntax()` before semantic routing. The former enforces both the
   configured limit and `MAX_MESS_SIZE`; the latter requires valid UTF-8, valid
   ADC escapes, no raw controls and an allowlisted ADC header/token shape.
2. `CheckUserLogin()` permits only HSUP in PROTOCOL and BINF in IDENTIFY.
   Successful transitions set separate protocol, identity and NORMAL flags;
   state and flags must agree before NORMAL traffic is accepted.
3. Each accepted logical line enters a per-IP monotonic sliding window. A count
   above `protocol_flood_limit` within `protocol_flood_window` applies
   `AddIPTempBan(..., eBT_FLOOD)` for `protocol_flood_tmpban` seconds. An
   oversized logical line applies the same typed ban immediately.
4. Password failures and Authorization IP mismatches share the independent
   IP/account authentication window and apply `eBT_PASSW` after its threshold.
5. Centralize existing MariaDB string-literal quoting in
   `Database::WriteStringConstant()`. Treat it as partial defense; use prepared
   statements with bound parameters for new query APIs and migrate existing
   queries incrementally with regression coverage.
6. Retain the ADC-only decision from ADR-0001. Do not implement NMDC
   Lock-to-Key or `Lock2Key()`; BASE/TIGR negotiation and TIGR PID/CID
   verification are the relevant ADC controls.

## Consequences

- Malformed, oversized and out-of-order input is rejected before routing,
  database mutations or expensive admission work.
- High-rate sources are temporarily denied across reconnects, while normal
  command rates remain configurable and bounded.
- Login state is inspectable in tests without relying only on an enum value.
- Operators must tune the flood window for expected hub traffic; overly low
  values can disconnect legitimate active clients.
- Manual SQL escaping remains technical debt even though its use is now
  centralized and connection-aware.

## Alternatives considered

- Adding NMDC Lock-to-Key beside ADC was rejected because it creates a second,
  incompatible wire protocol and does not modernize authentication.
- Counting malformed commands only was rejected because syntactically valid
  high-rate floods still consume routing and fan-out resources.
- A process-global command counter was rejected because one abusive source
  could deny service to unrelated clients.
- Treating escaping as equivalent to prepared statements was rejected because
  correct quoting is context-sensitive and easier to regress during query
  construction.

## References

- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [ADC 1.0.4 specification](https://dc-protocols.github.io/ADC.html)
