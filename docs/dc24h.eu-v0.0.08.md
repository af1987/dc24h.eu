<!--
dc24h.eu-v0.0.08.md

v0.0.08:
  - define persistent kick and ban settings, commands and admission behavior
  - record MariaDB audit, security boundaries and ncdc validation

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# dc24h.eu-v0.0.08

## Release identity

- Program/version: `dc24h.eu` / `0.0.08`
- Release: `dc24h.eu-v0.0.08`
- Author/date: `gpt-5.6-sol` / `2026-08-21`
- Repository: `https://github.com/af1987/dc24h.eu.git`
- Development branch: `agent/dc24h-v0.0.08`
- Target branch: `main`

## Platform contract

ADC 1.0.4 BASE/TIGR, UTF-8, US English / `en_US.UTF-8`, C++20,
MariaDB `utf8mb4`, Debian 13 and systemd. The default IPv4 ADC port is 1511.

## Required global keys

| Key | Type/range | Default | Meaning |
| --- | --- | ---: | --- |
| `key.kicks` | seconds, `60..86400` | `300` | default rejoin delay after a punitive kick |
| `key.bans` | seconds, `60..31536000` | `31536000` | maximum duration accepted for a temporary ban or explicit kick |

The invariant `key.kicks <= key.bans` is validated on load and update. Lowering
`key.bans` does not rewrite existing rows. Set values through the protected
forms `!set key.kicks=[seconds]` and `!set key.bans=[seconds]`.

## Kick keys

```text
!set key.kicks.add=[nickname|reason]
!set key.kicks.add=[nickname|duration|reason]
!set key.kicks.remove=[id|reason]
!set key.kicks.info=[id]
!set key.kicks.list=[limit]
```

The two-field form uses `key.kicks`. An explicit duration accepts `s`, `m`,
`h`, `d`, `w`, `M` (30 days) or `y` (365 days), must be at most `key.bans`,
and cannot be permanent. `limit` is `1..50`. Removal is a reasoned soft
revocation, so an erroneous long kick can be cancelled without erasing audit.

`!set key.user.kick.username=[nickname]` remains a compatibility form. It now
uses the configured default delay, writes a generic reason and creates the
same audit entry. `key.user.disconnect.username` remains non-punitive and does
not create a moderation row.

A kick stores the nickname and verified ADC CID before the socket is closed.
Re-entry matching either identity is rejected until expiry. It deliberately
does not block the whole source IPv4 address, so unrelated users behind one
address are not punished. Existing kick protection, class difference,
delegated `can_kick`, public kick notices and per-recipient hide controls still
apply.

## Ban keys

```text
!set key.bans.add=[kind|target|duration|reason]
!set key.bans.remove=[id|reason]
!set key.bans.info=[id]
!set key.bans.list=[limit]
```

`duration` is `permanent` or a temporary duration using the kick units and the
`key.bans` maximum. Reasons are mandatory printable UTF-8, exclude the `|`
separator and are limited to 1000 Unicode code points.

Permanent bans and all non-nickname target kinds require Master (10). Admin
may create temporary exact-nickname bans, subject to class and kick protection.

| Kind | Target form | Matching |
| --- | --- | --- |
| `nick` | decoded ADC nickname | ASCII-case-insensitive exact match |
| `cid` | 39-character uppercase Base32 CID | exact verified CID |
| `ip` | canonical IPv4 | exact connected address |
| `range` | `low..high` or `address/mask` | inclusive normalized IPv4 range |
| `prefix` | nickname prefix | ASCII-case-insensitive prefix |
| `share` | unsigned byte count | exact ADC `SS` when present |

Hostname bans are intentionally not implemented: reverse DNS is optional,
blocking and not a stable admission identity. IPv6 remains outside the v0.0.08
listener contract.

Ban creation, removal, details and lists require a loopback Admin (5) or Master
(10). A new ban cannot include the acting session and cannot disconnect a
matched session protected by the existing class/protection policy. All command
results are private hub messages.

## Persistence and admission

`moderation_entries` is an append-oriented MariaDB audit table. Each row stores
action and target types, normalized target values, reason, actor, creation and
optional expiry times. Unban is a soft revocation with its own time, actor and
reason; history is never deleted by the command.

Active IPv4 and range bans are checked immediately after TCP accept. Nickname,
CID, prefix and share checks run after ADC identity validation but before the
session becomes NORMAL or is broadcast. A database lookup failure rejects the
admission check. Expired and revoked entries do not match. Post-login changes
to `NI`, `ID`, `PD` or `SS`, and duplicate INF field names, are rejected.

## Validation

- Debian 13 Release build with all project warnings promoted to errors.
- CTest: ADC/TIGR/identity and user/moderation suites passed.
- `sql/schema.sql` applied twice to an isolated MariaDB 11.8 instance; 30
  settings were present and both new defaults matched.
- Real Debian `ncdc 1.23.1` clients completed ADC/TIGR connection and public
  message echo.
- A Master kicked a second client; immediate reconnect was rejected, and both
  expiry and reasoned kick revocation restored access.
- A timed nickname ban rejected reconnect, soft-unban restored access, and an
  active ban remained enforced after hub process restart.
- A third Admin client was denied both a broad range ban and a permanent ban;
  neither rejected operation created an audit row.

## Known security boundary

ADC VERIFY is not yet implemented. Management commands therefore remain
restricted to IPv4 loopback plus class/capability checks. This release freezes
identity and admission-share fields after NORMAL, but nickname-based account
authorization is still not a substitute for authenticated VERIFY. Production
deployments should restrict local access accordingly.
