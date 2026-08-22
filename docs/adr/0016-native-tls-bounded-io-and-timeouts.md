<!--
0016-native-tls-bounded-io-and-timeouts.md

v0.0.12:
  - decide native ADCS, optional TLS-only mode and protected certificate policy
  - decide hard line/output ceilings and phase-specific connection deadlines

Author: gpt-5.6-sol
Date: 2026-08-22
-->

# ADR-0016: Native TLS, bounded I/O and connection timeouts

- Status: Accepted
- Date: 2026-08-22
- Release: `dc24h.eu-v0.0.12`
- Author: `gpt-5.6-sol`

## Context

The ADC listener previously carried plaintext traffic and relied on finite
stack reads without a complete policy for accumulated logical lines, outgoing
messages or slow connection phases. A public hub needs confidentiality when
clients support ADCS, an enforceable encrypted-only deployment option, and
deterministic resource bounds for hostile or stalled peers.

TLS 1.3 defines the current transport protocol and removes obsolete algorithms.
OWASP recommends explicit input limits and resource/time limits against memory
exhaustion and slow-client denial of service.

## Decision

1. Implement TLS inside the C++ server with OpenSSL. CMake capabilities are
   named `USE_TLS_PROXY` and `USE_FEARTLS_PROXY`; runtime configuration still
   decides whether the listener is active.
2. Use one ADC state machine behind raw and encrypted `SocketTransport`
   instances. The standard defaults are ADC/1511 and ADCS/1512.
3. Allow minimum `TLS1.2` or `TLS1.3`, default to TLS 1.3, use AEAD cipher
   suites, and disable compression, renegotiation and TLS 1.3 early data.
4. `tls_only_mode=1` prevents creation of the plaintext listener. It is invalid
   unless TLS is compiled and enabled.
5. Require absolute regular non-symlink certificate/key paths and restricted
   private-key permissions. The installer preserves existing material and
   creates a protected self-signed pair only to bootstrap a clean install.
6. `ReadLineLocal()` checks each append against `mLineSizeMax` and the hard
   `MAX_MESS_SIZE`; overflow sends fatal ADC status and closes the connection.
7. Every outgoing message must fit `max_outbuf_size` and hard
   `MAX_SEND_SIZE`. Writes and handshakes have deadlines; no unbounded output
   queue is introduced.
8. Enforce separate `Key`, `ValidateNick`, `Login`, `MyINFO`, `Password` and
   `General` timeouts. All must be finite and nonzero.
9. Use ncdc only for release interoperability tests. Production accepts other
   conforming ADC clients and has no ncdc runtime dependency.

## Consequences

- Operators can retain compatibility with plaintext ADC or enforce ADCS only.
- Certificate lifecycle is now an operational responsibility; the bootstrap
  certificate is not a substitute for public PKI validation.
- Memory use per logical input/output operation is explicitly bounded, and
  stalled connection stages are reclaimed.
- TLS handshake work occurs only on the ADCS listener and is limited by a
  configurable deadline. Existing IP/reconnect admission controls remain in
  force for both listeners.
- TLS configuration adds an OpenSSL build/runtime dependency.

## Alternatives rejected

- A mandatory external TLS terminator was rejected because it cannot make
  `tls_only_mode` and per-session deadlines intrinsic to this deployment.
- Unlimited line accumulation followed by validation was rejected because the
  allocation itself is the denial-of-service condition.
- One global timeout was rejected because negotiation, login, password setup
  and normal idle periods have different operational meanings.
- Making ncdc a supported-client dependency was rejected; it is a test tool,
  not part of the server architecture.

## References

- [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
