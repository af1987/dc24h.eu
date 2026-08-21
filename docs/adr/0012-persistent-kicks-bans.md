<!--
0012-persistent-kicks-bans.md

v0.0.08:
  - decide persistent, auditable kick and ban semantics
  - define typed admission targets, expiry, revocation and trust boundaries

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# ADR-0012: Persistent kicks and bans

## Status

Accepted

## Date

2026-08-21

## Author

`gpt-5.6-sol`

## Release

`dc24h.eu-v0.0.08`

## Context

The existing punitive kick only closed a live socket. It did not persist a
reason or prevent immediate re-entry, and the account-scoped timed-policy table
cannot represent anonymous clients, CID identities or address ranges. The hub
needs durable kick and ban behavior while retaining the separate non-punitive
disconnect operation and the loopback management boundary.

## Decision

1. Define `key.kicks` as the default kick rejoin delay in seconds (`300`, range
   `60..86400`) and `key.bans` as the maximum temporary action duration
   (`31536000`, range `60..31536000`). Enforce `key.kicks <= key.bans`.
2. Add a paired `moderation.cpp` / `moderation.hpp` module for typed target
   normalization, bounded durations and admission matching.
3. Store kick and ban history in `moderation_entries`. Use nullable expiry for
   permanent bans and soft-revocation fields for unban audit. Never use the
   account policy table for admission bans.
4. A kick records the decoded nickname and verified ADC CID atomically before
   socket shutdown. Either identity blocks re-entry until expiry; source IPv4
   is not inherited by a kick.
5. Bans support nickname, CID, IPv4, IPv4 range/CIDR, nickname prefix and exact
   share size. Inputs are normalized without operator-supplied regular
   expressions. Hostname bans are excluded because reverse DNS is optional and
   unstable.
6. Check address targets after accept. Check identity/share targets after the
   verified initial BINF and before NORMAL. Fail closed when MariaDB cannot
   perform the admission lookup.
7. Reject duplicate INF field names and post-NORMAL `NI`, `ID`, `PD` or `SS` updates
   so an accepted identity cannot evade a moderation decision.
8. Serialize admission checks with new kick/ban rows, so a matching session
   cannot cross the admission boundary between the decision and persistence.
9. Preserve `key.user.disconnect.username` as a non-punitive close and retain
   `key.user.kick.username` as a compatibility kick form. New structured
   operations use the `key.kicks.*` and `key.bans.*` namespaces.
10. Operator or active `can_kick` may kick within existing class rules. Ban
   creation, audit queries and revocation require Admin or Master. Permanent
   and non-nickname bans require Master, because an offline broad target cannot
   be proven not to include a protected account.
11. Keep results private. A public kick notice still follows existing
    recipient visibility controls; bans are not broadcast.

## Consequences

### Positive

- Punitive kicks now have their intended rejoin delay and survive process
  restart.
- Anonymous and registered users share one auditable admission-ban model.
- Typed IPv4 parsing prevents ambiguous target inference and reversed ranges.
- Expiry requires no deletion scheduler, and unban preserves accountability.
- CID-bound kicks avoid penalizing every local/NAT peer at one address.

### Negative

- Admission performs a serialized MariaDB query, including one early query for
  every accepted IPv4 connection.
- ASCII-only case folding does not provide full Unicode nickname
  canonicalization.
- Share bans apply only when the client supplies a valid ADC `SS` value.
- The current one-thread-per-client and unauthenticated ADC management model
  remain separate limitations.

## Alternatives considered

### Boolean feature flags for the two exact keys

Rejected because flags would not express the documented rejoin delay or
temporary-ban ceiling and could leave both keys without operational consumers.

### Reuse account timed policies

Rejected because that table has an account foreign key and cannot cover guests,
CID identities, address ranges or prefixes.

### Bind every kick to IPv4

Rejected because one kicked user could block unrelated users sharing a NAT or
the same local test address.

### Delete rows during unban

Rejected because removal would erase the actor, reason and moderation history.

### Hostname targets

Rejected for v0.0.08 because reverse DNS is not an authoritative identity and a
slow resolver would extend the admission critical path.

## Relationship to earlier decisions

This ADR extends ADR-0010's distinction between disconnect and protected kick,
and ADR-0011's MariaDB-backed admission policy. It supersedes only the earlier
behavior where a kick ended at socket shutdown without a rejoin block.

## Validation

Unit tests cover settings, duration parsing, every target normalizer/matcher and
immutable ADC identity fields. Isolated MariaDB migration and real `ncdc`
sessions cover kick denial/expiry, ban denial/unban and persistence after hub
restart.
