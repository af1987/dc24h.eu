<!--
0011-class-nickname-autoreg-policy.md

v0.0.07:
  - record class-policy, nickname-admission and self-registration decisions
  - record account binding, password deadline and telemetry decisions

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# ADR-0011: Class, nickname and self-registration policy

- Status: Accepted
- Date: 2026-08-21
- Release: dc24h.eu-v0.0.07

## Context

The hub already has numeric account classes and complete user moderation, but fixed authorization rules leave operators unable to tune class relationships. Admission also lacks persistent nickname rules, controlled self-registration and first-password expiry. Account records need optional IP binding and useful audit metadata without exposing mutable telemetry as administrator-settable keys.

## Decision

1. Store policy in the existing MariaDB `settings` table under canonical `key.*` names.
2. Normalize and validate every value in `hub_settings.cpp` before persistence or runtime use.
3. Enforce nickname length, allowed characters and prefix policy before ADC NORMAL state.
4. Disable `+regme` by default. When enabled, cap its class at Operator (3) and enforce its prefix, class-specific share and password rules.
5. Mark passwordless accounts as requiring password setup. Start a session deadline at identification and disconnect the account if `+passwd` does not complete in time.
6. Enforce account authentication IPv4 at identification.
7. Treat registration/login/logout fields as telemetry returned by the private user-info key, not arbitrary setting keys.
8. Keep protected `!set` commands loopback-only until ADC VERIFY authentication exists. `+passwd` and enabled `+regme` are explicit self-service exceptions.
9. Suppress kick event notices according to each recipient's boolean and class-threshold fields; do not conflate this with hidden ADC operator bits.

## Consequences

- Policy changes survive restart and are auditable in MariaDB.
- Incorrect key types and unsupported classes fail closed.
- A restrictive nickname or minimum-class change affects subsequent identifications.
- Runtime class reach is enforced for registration, kick, PM and download requests. Thresholds for unimplemented plugin/topic/trigger command families are persisted for future consumers.
- Nickname-based self-service remains weaker than full ADC VERIFY; IP binding can narrow but does not replace protocol authentication.

## Validation

- Parser tests cover every v0.0.07 global key and all new account keys.
- Unit tests cover normalization, prefixes, allowed characters and release metadata.
- MariaDB migration tests cover seeded defaults and new account columns.
- `ncdc` validates BASE/TIGR identification and public-message echo.
