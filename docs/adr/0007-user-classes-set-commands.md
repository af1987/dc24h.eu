<!--
0007-user-classes-set-commands.md

v0.0.03:
  - decide numeric user classes, password hashing and !set management boundary

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# ADR-0007 — User classes and protected `!set` account commands

## Status

Accepted

## Date

2026-08-19

## Author

`gpt-5.6-sol`

## Context

`dc24h.eu` needs persistent account classes and operator-facing commands for registering users and changing passwords. The current ADC core reaches NORMAL state but does not yet implement registered-user VERIFY with `GPA`/`PAS`.

A remote ADC nickname is therefore not authenticated. Allowing account writes based only on the `NI` value would let a remote client impersonate an administrative nickname. The existing `accounts.role` enum is also too coarse for the requested class model.

## Decision

For `dc24h.eu-v0.0.03`:

1. Add `accounts.user_class` as a signed numeric account class.
2. Accept only these application values: `-1`, `0`, `1`, `2`, `3`, `4`, `5`, `10`.
3. Keep the legacy `accounts.role` column temporarily for migration compatibility; it is not authoritative for v0.0.03 permissions.
4. Add `src/user.cpp` / `src/user.hpp` for the canonical `UserClass` model and password hashing helpers.
5. Store passwords as salted PBKDF2-HMAC-SHA256 with 210000 iterations, a 16-byte random salt and a 32-byte derived key.
6. Add `src/user_commands.cpp` / `src/user_commands.hpp` for:
   - `key.user.new.username.class.password`;
   - `key.user.change.id.password`;
   - `key.user.new.id.password` as a compatibility alias for password change by database account ID.
7. Intercept matching NORMAL-state `BMSG` commands before normal broadcast routing so password-bearing command text is not sent to other users.
8. Until ADC VERIFY is implemented, accept account-changing `!set` commands only from IPv4 loopback (`127.0.0.1`).
9. After bootstrap, require the sender's decoded ADC nickname to map to an enabled Admin (`5`) or Master (`10`) account.
10. When there are no enabled accounts, permit a local bootstrap only for creation of the first Master (`10`) account.
11. Return success/failure through a hub-local `IMSG` and never include the submitted password in the response.

## Consequences

The requested class model becomes persistent and explicit. Passwords are not stored in plaintext, and password-bearing commands are prevented from leaking through normal public chat broadcast.

The temporary loopback restriction deliberately limits administration until registered-user ADC authentication exists. This prevents a remote user from authorizing a write merely by choosing an administrative nickname.

The legacy `role` column and the new `user_class` column coexist during this migration stage. PBKDF2 also adds intentional CPU cost for password hashing.

## Alternatives considered

### Trust a remote Admin/Master nickname

Rejected because `NI` is not authenticated in v0.0.03 and can be impersonated.

### Store plaintext passwords

Rejected because disclosure of the database or logs would immediately expose credentials.

### Store a single fast SHA-256 password digest

Rejected because fast general-purpose hashes are not appropriate password-storage primitives.

### Require manual SQL for all user management

Rejected because the release explicitly requires hub `!set` management keys and a coherent application-layer account model.

### Implement full ADC VERIFY in the same release

Deferred. `GPA`/`PAS`, credential verification and remote authenticated authorization deserve a separate security-focused release and ADR.
