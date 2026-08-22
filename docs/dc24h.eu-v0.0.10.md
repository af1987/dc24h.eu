<!--
dc24h.eu-v0.0.10.md

v0.0.10:
  - release tagged password hashing and verification
  - release centralized deny-by-default RBAC
  - release persistent exact/wildcard hostname bans

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# dc24h.eu-v0.0.10

## Release identity

- Program/version: `dc24h.eu` / `0.0.10`
- Release: `dc24h.eu-v0.0.10`
- Author/date: `gpt-5.6-sol` / `2026-08-21`
- Repository: `https://github.com/af1987/dc24h.eu.git`
- Development branch: `agent/dc24h-v0.0.10`
- Target branch: `main`
- Pull request: `#10`

## Platform contract

ADC 1.0.4 BASE/TIGR, UTF-8, US English / `en_US.UTF-8`, C++20,
MariaDB `utf8mb4`, Debian 13 and systemd remain mandatory. The project files
remain in `/root/dc24h.eu`; an installed instance uses the protected home
`/var/lib/dc24h.eu/dc24h.eu`.

## Password hashing and verification

New password writes use the requested default format:

```text
md5$0123456789abcdef0123456789abcdef
```

The prefix is mandatory. Verification accepts that format and the previous
tagged `pbkdf2-sha256$…` representation so existing accounts remain readable.
Digest comparisons are constant-time, malformed inputs fail closed, password
commands never return plaintext or hashes, and passwordless accounts still use
SQL `NULL`.

MD5 is fast, unsalted and not suitable for protecting passwords against an
offline database compromise. It is implemented here only because 0.0.10
requires it as the compatibility default. PBKDF2-SHA256 remains available via
explicit `PasswordHashAlgorithm::pbkdf2_sha256` selection.

## RBAC command authorization

The paired `src/rbac.cpp` / `src/rbac.hpp` module maps every known
`UserSetAction` to a permission and denies unknown actions by default.
Authorization runs after parsing and before command execution, including
explicit self-service policy checks.

| Permission | Minimum class | Examples |
| --- | ---: | --- |
| `self_service` | 0 | registration, first password, own visibility |
| `register_accounts` | 3 | create an account within class-difference rules |
| `view_users` | 3 | account/moderation information and lists |
| `moderate_sessions` | 3 | disconnect and kick |
| `manage_bans` | 5 | add/revoke kick and ban entries |
| `manage_accounts` | 5 | lifecycle, passwords, profile and timed policy |
| `manage_roles` | 10 | permanent/temporary class changes |
| `configure_hub` | 10 | database-backed hub setting changes |

Configured registration/kick differences and delegated timed capabilities are
evaluated in addition to the base permission. A permanent ban or a ban not
limited to a nickname remains Master-only. Protected commands remain
loopback-only until ADC VERIFY authentication is implemented.

## Banlist targets

The canonical syntax now includes host targets:

```text
!set key.bans.add=[host|client.example.net|1d|Repeated abuse]
!set key.bans.add=[host|*.example.net|1w|Abusive network]
```

Exact and leading-wildcard hostnames are normalized to lowercase and checked
against reverse DNS during admission. The wildcard matches subdomains but not
the apex. Resolver failure yields no host match. IP and CIDR/range bans remain
preferred because PTR records are not authenticated identity.

The complete target set is `nick`, `cid`, `ip`, `range`, `host`, `prefix` and
`share`; persistent kick identity rows remain internal. MariaDB expiry,
soft-revocation, actor/reason audit and indexed lookups are unchanged.

## Files added

- `src/rbac.cpp` and `src/rbac.hpp`
- `docs/adr/0014-password-hashing-rbac-host-bans.md`
- `docs/dc24h.eu-v0.0.10.md`

All created C++ implementations have matching headers. Every created or
modified human-maintained file records its v0.0.10 change in its history
header. Project sources contain neither prohibited legacy hub names nor their
associated abbreviated command prefix.

## Validation record

- Debian 13 Release configuration and build with warnings as errors passed;
  CTest passed 8/8, including ShellCheck.
- MariaDB 11.8 schema application passed repeatedly, retained exactly 30
  canonical settings and installed the `host` target constraint.
- A live `host=localhost` admission test returned ADC status 230 and the test
  row was then soft-revoked with actor/reason audit.
- The installed v0.0.10 systemd unit is active, passed unit verification and
  retained exposure score `3.0`.
- Real `ncdc 1.23.1` completed ADC/TIGR login and echoed
  `ncdc-v0.0.10-connection-test`; after service restart it reconnected and
  echoed `ncdc-v0.0.10-after-restart`.
- Pair, history, forbidden-name and diff checks passed locally. GitHub CI for
  PR #10 remains the final remote merge gate.
