<!--
dc24h.eu-v0.0.11.md

v0.0.11:
  - release Argon2id password storage and automatic legacy upgrades
  - release active password, IP, reconnect and clone abuse controls

Author: gpt-5.6-sol
Date: 2026-08-22
-->

# dc24h.eu-v0.0.11

## Release identity

- Program/version: `dc24h.eu` / `0.0.11`
- Release: `dc24h.eu-v0.0.11`
- Author/date: `gpt-5.6-sol` / `2026-08-22`
- Repository: `https://github.com/af1987/dc24h.eu.git`
- Development branch: `agent/dc24h-v0.0.11`
- Target branch: `main`
- Pull request: `#11`

## Platform contract

ADC 1.0.4 BASE/TIGR, UTF-8, US English / `en_US.UTF-8`, C++20, MariaDB
`utf8mb4`, Debian 13 and systemd remain mandatory. Source files are in
`/root/dc24h.eu`; the installed hub home remains
`/var/lib/dc24h.eu/dc24h.eu`.

## Password storage

New records use a standard Argon2id PHC string with a random salt and the OWASP
minimum profile:

```text
$argon2id$v=19$m=19456,t=2,p=1$<salt>$<digest>
```

Tagged `md5$…` and `pbkdf2-sha256$…` records are accepted only as legacy
verification inputs. A successful check conditionally updates the matching row
to Argon2id, so a concurrent password reset is not overwritten. Malformed and
untagged hashes fail closed. New MD5 generation has been removed.

## Active protections

| Control | Code/configuration | Default |
| --- | --- | ---: |
| Password failure ban | `AddIPTempBan()`, `LoginError()`, `pwd_tmpban` | 5 failures / 300 s; ban 900 s |
| Account IP authorization | `mAuthIP()` and login-time address comparison | exact when configured |
| Connections from one IP | `max_users_from_ip`, `CntConnIP()` | 10 |
| Reconnect throttling | reason `Reconnecting too fast` | 2 s |
| Clone detection | `CheckUserClone()`, `clone_detect_count` | 3 equal AP/VE sessions per IP |
| Clone observation/ban | `clone_det_tban_time`, `clone_ip_tban_time` | 600 s / 900 s |

The counters use `steady_clock`, are protected by one mutex, and are released
when the client worker disconnects. Admission checks run before DNS and
MariaDB address-ban work. Password failures use distinct account and IP
windows. Temporary anti-abuse state intentionally resets on process restart;
persistent operator bans remain in MariaDB.

## ADC authentication boundary

ADC GPA/PAS requires hashing the original password with a per-session random
challenge. An Argon2id record cannot reproduce that response. v0.0.11 does not
store plaintext or reversible account passwords; therefore ADC VERIFY remains
out of scope and protected in-hub management stays loopback-only. This is an
explicit security boundary, not a claim that a passwordless ADC session is
fully account-authenticated.

## Files added

- `src/anti_abuse.cpp` and `src/anti_abuse.hpp`
- `tests/anti_abuse_tests.cpp` and `tests/anti_abuse_tests.hpp`
- `docs/adr/0015-argon2id-and-connection-abuse-protection.md`
- `docs/dc24h.eu-v0.0.11.md`

All added C++ implementations have matching headers. Every created or modified
human-maintained file records its v0.0.11 change in its history header.

## Validation record

- Debian 13 warnings-as-errors Release build passed; CTest passed 9/9.
- Argon2id generation/verification, legacy MD5/PBKDF2 reads and upgrade
  detection passed.
- Temporary password bans, `mAuthIP`, per-IP counts, reconnect denial, clone
  detection and ban expiry passed deterministic tests.
- MariaDB 11.8 schema reapplied successfully and retained 30 canonical
  settings; the installed settings check passed.
- The installed v0.0.11 systemd unit is active, passed unit verification and
  retained exposure score `3.0`.
- Real `ncdc 1.23.1` completed ADC/TIGR login and echoed
  `ncdc-v0.0.11-connection-test`; after service restart it automatically
  reconnected and echoed `ncdc-v0.0.11-after-restart`.
- Local file-history/pair/forbidden-name scans and GitHub CI remain final
  release gates.
