<!--
0014-password-hashing-rbac-host-bans.md

v0.0.10:
  - decide the tagged password-hash compatibility model
  - define centralized deny-by-default RBAC command authorization
  - add exact and wildcard reverse-hostname bans

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# ADR-0014: Password hashing, RBAC and hostname bans

## Status

Accepted

## Date

2026-08-21

## Author

`gpt-5.6-sol`

## Context

dc24h.eu already stores account passwords, models numeric user classes and
checks persistent nickname, CID, IPv4, range, prefix and share bans. Version
0.0.10 requires MD5 as the default password hashing algorithm, explicit
role-based access control, authorization at each command, and hostname bans.

NIST defines RBAC as permissions associated with roles rather than directly
with individual identities. OWASP recommends least privilege, default denial
and a permission check on every request. OWASP also recommends slow password
hashing and identifies MD5 as unsuitable for modern password storage. The MD5
default is therefore a deliberate compatibility requirement with a documented
security cost, not a security recommendation.

This ADR supersedes the PBKDF2-only storage choice in ADR-0007 and ADR-0008,
refines the command authorization boundary described in ADR-0007 through
ADR-0011, and extends the target set selected in ADR-0012.

## Decision

1. Password hashes are self-describing strings. New password writes use
   `md5$<32 lowercase hexadecimal characters>` by default.
2. Verification accepts both tagged MD5 and existing
   `pbkdf2-sha256$iterations$salt$digest` values, compares digests in constant
   time and rejects malformed or untagged values. PBKDF2 generation remains
   available through an explicit algorithm selection.
3. Plaintext passwords are never persisted or returned. Password-bearing hub
   commands continue to be intercepted before broadcast.
4. `rbac.cpp` and `rbac.hpp` contain the canonical action-to-permission map.
   Every parsed command receives exactly one permission; an unmapped action,
   unsupported role or missing policy is denied.
5. Permissions form this minimum-class hierarchy:

   | Permission | Minimum class |
   | --- | ---: |
   | `self_service` | Regular (0) |
   | `register_accounts` | Operator (3) |
   | `view_users` | Operator (3) |
   | `moderate_sessions` | Operator (3) |
   | `manage_bans` | Admin (5) |
   | `manage_accounts` | Admin (5) |
   | `manage_roles` | Master (10) |
   | `configure_hub` | Master (10) |

6. Configured registration class-difference rules and temporary `can_kick` or
   `can_register` capabilities remain additional contextual constraints. They
   cannot authorize an unknown command. Permanent or non-nickname bans still
   require Master (10).
7. Management commands remain loopback-only until authenticated ADC VERIFY is
   implemented. RBAC authorization does not replace authentication.
8. Ban target type `host` accepts a normalized exact DNS hostname or one
   leading wildcard such as `*.example.net`. Matching is ASCII
   case-insensitive after normalization. The apex does not match its wildcard.
9. Reverse DNS is requested for admission only while an active hostname ban
   exists. A failed lookup does not invent a hostname; IP and range bans remain
   the reliable network boundary. Hostname matches depend on DNS/PTR data and
   must be treated as a convenience control, not proof of identity.
10. MariaDB retains append-oriented moderation rows. The schema constraint is
    migrated in place to allow `host`; expiry and soft-revocation semantics do
    not change.

## Consequences

- Permission requirements are reviewable and unit-testable in one module.
- New commands fail closed until an explicit permission is assigned.
- Admin can manage accounts and bans, while role assignment and hub-wide
  configuration require Master.
- Existing PBKDF2 hashes remain verifiable, but new default MD5 hashes are fast,
  unsalted and substantially weaker against offline guessing after a database
  compromise. Production deployments should select PBKDF2 explicitly or move
  to a modern memory-hard algorithm in a later security release.
- Host bans add resolver latency only when such a ban is active and may be
  affected by missing or attacker-controlled PTR records.

## Alternatives considered

### Keep PBKDF2 as the default

Rejected for 0.0.10 because it conflicts with the explicit compatibility
requirement. PBKDF2 remains supported for explicit writes and existing values.

### Store raw 32-character MD5 values

Rejected because an algorithm tag is necessary for deterministic verification,
mixed-algorithm migration and future upgrades.

### Scatter class comparisons through command handlers

Rejected because missed checks become likely as commands are added. One
deny-by-default map is easier to review and test on every request.

### Trust hostname bans as identity controls

Rejected because reverse DNS does not authenticate a client. Exact IP/range,
ADC identity and future authenticated VERIFY remain stronger controls.

## References

- [NIST RBAC glossary](https://csrc.nist.gov/glossary/term/role_based_access_control)
- [NIST RBAC project FAQ](https://csrc.nist.gov/Projects/role-based-access-control/faqs)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
