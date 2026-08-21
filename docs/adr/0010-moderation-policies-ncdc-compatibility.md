<!--
0010-moderation-policies-ncdc-compatibility.md

v0.0.06:
  - define persistent moderation attributes and expiring policy rows
  - define ADC routing enforcement and delegated privileges
  - document ncdc-compatible SUP-only BASE/TIGR negotiation

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# ADR-0010: Moderation policies, delegated privileges and ncdc compatibility

## Status

Accepted

## Date

2026-08-21

## Author

`gpt-5.6-sol`

## Context

The hub needs account protection, visibility controls, private operator notes, expiring communication/transfer/search restrictions and temporary delegated privileges. These controls must survive a process restart when their expiry has not passed, but must stop taking effect automatically afterwards.

The release must also be tested with `ncdc`. That test found that v0.0.05 incorrectly required `BASE` and `TIGR` to be repeated in the client's `BINF SU` field even though they were already negotiated in `SUP`.

## Decision

1. Store persistent account attributes in `accounts`: `kick_protect_class`, `hide_share`, `hide_operator_key`, `hide_from_class` and private `account_note`.
2. Store expiring state in `user_timed_policies(account_id, policy_key, expires_at)`. Supported keys are `gag`, `no_download`, `no_chat`, `no_pm`, `no_search`, `can_kick`, `hide_share`, `can_register` and `opchat`.
3. Accept duration syntax `Nm`, `Nh` or `Nd`, from one minute through 365 days. Applying a policy replaces its expiry. Removing a policy is idempotent for an existing account.
4. Enforce policies before normal ADC routing:
   - `gag` blocks public `BMSG`;
   - `no_chat` blocks public and private `MSG`;
   - `no_pm` blocks direct/echo `MSG`;
   - `no_search` blocks `SCH`;
   - `no_download` blocks `CTM` and `RCM` negotiation.
5. `hide_share` removes `SS`, `SF` and `SL` from emitted `BINF`. Permanent `hide_operator_key` clears ADC `CT` operator/super/owner bits 4, 8 and 16.
6. A user's `hide_from_class` suppresses its INF and routed traffic for recipients with a lower numeric class. Class `-1` restores visibility to all canonical classes.
7. `key.user.disconnect.username` closes a session without recording a punitive kick and bypasses kick protection. `key.user.kick.username` is punitive and rejects an actor whose effective class is less than or equal to the target's protection threshold.
8. Active `can_kick` permits the protected kick command. Active `can_register` permits creation only in classes at most Registered (1), preventing privilege escalation. Active `opchat` grants access to the private `!opchat <message>` channel; Operator and higher also have access.
9. Notes and permanent share/operator visibility controls remain Admin/Master operations. Self-visibility is available only to an enabled registered local account.
10. Continue the loopback trust boundary until ADC VERIFY exists. Password/self and management messages remain intercepted before broadcast.
11. Treat BASE/TIGR negotiation in `HSUP`/`ISUP` as authoritative. Do not require their duplication in `BINF SU`. PID/CID TIGR verification remains mandatory.
12. Validate release connectivity using `ncdc` against an isolated MariaDB database and TCP port.

## Consequences

### Positive

- Restrictions and delegated privileges expire automatically without a cleanup scheduler.
- Routing enforcement covers the relevant ADC command families instead of merely storing flags.
- Share, operator state and whole-user visibility are filtered before reaching unauthorized clients.
- Kick protection has an explicit class comparison and a separate non-punitive disconnect path.
- `ncdc` can complete ADC identification while TIGR identity validation remains intact.

### Negative

- Policy snapshots are refreshed on account changes and checked against wall-clock expiry; a database edit made outside the hub requires reconnect or an in-hub refresh operation.
- `no_download` prevents new ADC transfer negotiation but does not terminate an already established peer-to-peer transfer.
- `hide_operator_key` interprets the standard decimal ADC `CT` bit field; non-standard operator extensions are not rewritten.
- The private OPChat is intentionally minimal and uses hub-local `IMSG` delivery.

## Alternatives considered

### One column per timed restriction

Rejected because it creates repetitive migrations and makes new policy types expensive.

### Keep timed state only in memory

Rejected because active multi-day restrictions and privileges must survive systemd restarts.

### Poll and delete expired rows

Rejected because filtering by `expires_at > UTC_TIMESTAMP` and local expiry checks provide correct behavior without a scheduler.

### Continue requiring BASE/TIGR in BINF SU

Rejected because the requirement is redundant with SUP negotiation and prevents a conforming `ncdc` connection.

### Make disconnect synonymous with kick

Rejected because the request explicitly distinguishes a non-punitive session drop from kick/ban protection.

## Superseded decisions

This ADR extends ADR-0006 through ADR-0009. It supersedes only the ADR-0006/v0.0.02 assumption that BASE/TIGR must appear in the initial `BINF SU`; they remain mandatory in SUP negotiation and TIGR PID/CID verification remains unchanged.
