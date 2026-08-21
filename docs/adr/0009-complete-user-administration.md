<!--
0009-complete-user-administration.md

v0.0.05:
  - define the complete registered-user administration key set
  - separate persistent MariaDB changes from restart-scoped class overrides
  - define private online IPv4 and optional reverse-DNS queries
  - protect the final enabled Master account

Author: gpt-5.6-sol
Date: 2026-08-20
-->

# ADR-0009: Complete registered-user administration and online lookup keys

## Status

Accepted

## Date

2026-08-20

## Author

`gpt-5.6-sol`

## Context

Versions through 0.0.04 support registration, password lifecycle operations and class-filtered listing, but operators also need removal, temporary disable/enable, permanent and temporary class changes, complete registered-account details, and online IP/hostname searches. Password reset by nickname must leave the password unset so that the owner can assign a new password with `+passwd <password>`.

ADC VERIFY (`GPA`/`PAS`) is still absent, so a remote nickname cannot safely authorize account changes. Online network data belongs to active server sessions, while registered account data belongs to MariaDB.

## Decision

1. Keep the v0.0.04 protected private `BMSG` to `IMSG` management path. All administration and `+passwd` operations remain restricted to IPv4 loopback. `!set` commands require an enabled effective Admin (5) or Master (10), except first-Master bootstrap.
2. Add persistent keys:
   - `key.user.change.username.password=[username.password]`; an empty password resets the hash to SQL `NULL`;
   - `key.user.remove.username=[username]`;
   - `key.user.disable.username=[username]`;
   - `key.user.enable.username=[username]`;
   - `key.user.change.username.class=[username.class]`;
   - `key.user.info.username=[username]`.
3. `+passwd <password>` assigns a first password only to the enabled account matching the current local ADC nickname. It never overwrites an existing password.
4. `key.user.info.userlist.class=[]` defaults to class 0. Class listing includes enabled and disabled accounts and reports password state without exposing hashes.
5. Reject removal, disabling or demotion of the final enabled Master (10).
6. Add `key.user.change.username.class.temp=[username.class]`. Store the override only in server memory, cap it at Admin (5), use it as the effective authorization class, and discard it at process restart.
7. Add private online-session keys:
   - `key.user.info.ip.hostname.username=[username]`;
   - `key.user.info.hostname.username=[username]`;
   - `key.user.info.userlist.ip=[IPv4]`;
   - `key.user.info.userlist.iprange=[start-end]`;
   - `key.user.info.userlist.subnet=[network/prefix]`.
8. Add `dns_lookup=0|1`, defaulting to `0`. Resolve hostnames with reverse DNS only when enabled; never perform DNS for exact IP/range/subnet matching.
9. Add `accounts.updated_at` and expose ID, nickname, class, enabled state, password presence, creation time and update time through the registered-user information key. Never return a password hash.
10. Keep the C++ one-to-one `*.cpp`/`*.hpp` pair rule and file-level version histories.

## Consequences

### Positive

- The requested account-management lifecycle is available through one consistent key grammar and private response channel.
- Temporary privileges cannot survive a systemd restart or exceed Admin.
- Operators can inspect online IPv4 assignments without persisting connection identities.
- Password reset and first-password assignment are non-overwriting operations.
- The final active Master cannot be removed accidentally.

### Negative

- Reverse DNS can block a client worker while the resolver answers, so it is disabled by default.
- Online queries cover IPv4 sessions only because the v0.0.05 listener is IPv4-only.
- Temporary class overrides are node-local and are not suitable for a future multi-process deployment.
- The loopback trust boundary remains necessary until ADC VERIFY is implemented.

## Alternatives considered

### Persist temporary classes in MariaDB

Rejected because the requested behavior must disappear when the hub restarts.

### Store IP and hostname on the registered account

Rejected because the requested searches concern current sessions; persistent addresses become stale and increase retained personal data.

### Enable reverse DNS by default

Rejected because resolver latency and privacy policy should be explicit operator choices.

### Allow deletion of the only Master

Rejected because it can make protected administration inaccessible without direct database repair.

### Permit remote `+passwd` before ADC VERIFY

Rejected because an unauthenticated remote client could claim a reset nickname and take over its password.

## Superseded decisions

This ADR extends ADR-0007 and ADR-0008. It supersedes ADR-0008 only where class listing was limited to enabled accounts: v0.0.05 lists all registered accounts in the selected class and marks their enabled state. The earlier password-lifecycle rules remain in force.
