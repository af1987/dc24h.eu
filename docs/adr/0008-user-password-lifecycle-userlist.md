<!--
0008-user-password-lifecycle-userlist.md

v0.0.04:
  - define separate first-password and password-replacement operations
  - allow passwordless account creation
  - define private user listing by class
  - supersede the v0.0.03 new.id.password alias behavior from ADR-0007

Author: gpt-5.6-sol
Date: 2026-08-20
-->

# ADR-0008: Explicit user password lifecycle and private class listing

## Status

Accepted

## Date

2026-08-20

## Author

`gpt-5.6-sol`

## Context

In v0.0.03, `key.user.new.id.password` was implemented as a compatibility alias for `key.user.change.id.password`. That makes an operation named "new password" capable of replacing an already configured credential, which is ambiguous and can cause accidental password resets.

The project also needs to support accounts created before a password is assigned, for example through `key.user.new.username.class=[username.class]`. Finally, operators need a protected way to inspect all enabled users in one numeric class without broadcasting the result to the hub.

## Decision

1. `accounts.password_hash` becomes nullable. `NULL` means that an account exists but has never been assigned a password.
2. `key.user.new.username.class.password=[username.class.password]` creates an account with an initial password hash.
3. `key.user.new.username.class=[username.class]` creates an account with `password_hash=NULL`.
4. `key.user.new.id.password=[id.password]` is a first-password operation only. It uses a conditional database update that matches an enabled account only when `password_hash IS NULL OR password_hash=''`.
5. If `key.user.new.id.password` targets an enabled account that already has a password, no write is performed and the caller is told that the password already exists and that `key.user.change.id.password` must be used to replace it.
6. `key.user.change.id.password=[id.password]` is the only command that intentionally replaces an existing password by account database ID.
7. `key.user.info.userlist.class=[class]` returns every enabled account in the selected canonical class. The result is returned through the existing hub-local private `IMSG` response path and is not broadcast.
8. These commands continue to use the existing protected `!set ` chat prefix and v0.0.04 loopback/Admin-Master trust boundary.
9. This ADR supersedes only the `key.user.new.id.password` compatibility-alias decision in ADR-0007. The numeric class model, PBKDF2 storage policy and temporary local management trust boundary from ADR-0007 remain in force.

## Consequences

### Positive

- An operator cannot accidentally reset an existing password by using the first-password command.
- Passwordless registrations have an explicit database representation instead of placeholder credentials.
- Password replacement is intentional and easy to audit by command name.
- Class membership can be inspected without exposing the result to other hub users.
- Existing non-NULL password hashes survive the schema migration unchanged.

### Negative

- `password_hash` can no longer be treated as universally non-NULL by future code.
- Older scripts that relied on `new.id.password` as a password-change alias must switch to `change.id.password`.
- The class listing currently serializes the complete enabled-user set into one private response, so very large classes may require pagination in a later release.

## Alternatives considered

### Keep `new.id.password` as an alias for password replacement

Rejected because the command name does not communicate destructive replacement and conflicts with the requested first-password semantics.

### Use a sentinel password hash for passwordless accounts

Rejected because a sentinel can be confused with a valid credential state and complicates authentication logic. SQL `NULL` expresses the absence of an assigned password directly.

### Broadcast the class list to the hub

Rejected because account enumeration is an administrative query and should remain visible only to the requesting authorized client.

### Introduce a new persistence table for pending credentials

Rejected for v0.0.04 because nullable `password_hash` plus a conditional update is simpler, transactionally clear under the existing database mutex, and sufficient for the requested lifecycle.
