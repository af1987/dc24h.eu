<!--
dc24h.eu-v0.0.06.md

v0.0.06:
  - define the moderation, restriction and delegated-privilege release
  - list every new key, duration default and routing effect
  - record ncdc validation and release provenance

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# dc24h.eu-v0.0.06

## Release identity

- Program/version: `dc24h.eu` / `0.0.06`
- Release: `dc24h.eu-v0.0.06`
- Author/date: `gpt-5.6-sol` / `2026-08-21`
- Repository: `https://github.com/af1987/dc24h.eu.git`
- Development branch: `agent/dc24h-v0.0.06`
- Target branch: `main`

## Platform baseline

ADC 1.0.4 BASE/TIGR, UTF-8, US English / `en_US.UTF-8`, C++20, MariaDB `utf8mb4`, Debian 13 and systemd. The default IPv4 ADC port remains 1511.

## New moderation keys

| Operation | Protected command |
| --- | --- |
| Disconnect without punitive kick | `!set key.user.disconnect.username=[username]` |
| Kick an online user | `!set key.user.kick.username=[username]` |
| Protect through actor class | `!set key.user.protect.username.class=[username.class]` |
| Hide/show share permanently | `!set key.user.hide.share.username=[username.1|0]` |
| Hide/show ADC operator key permanently | `!set key.user.hide.operator.username=[username.1|0]` |
| Add/replace private note; empty clears | `!set key.user.note.username=[username.note]` |
| Hide self below class; `-1` restores all | `!set key.user.self.hide.class=[class]` |

The protected kick compares the actor's effective class with `kick_protect_class`; a class less than or equal to the threshold cannot kick the target. Non-punitive disconnect deliberately bypasses this rule.

## Timed restrictions

| Restriction | Set key | Default | Remove key |
| --- | --- | ---: | --- |
| Public-chat gag | `key.user.restrict.gag.username.time` | 7 days | `key.user.restrict.gag.remove.username` |
| New downloads | `key.user.restrict.download.username.time` | 2 days | `key.user.restrict.download.remove.username` |
| Public and private chat | `key.user.restrict.chat.username.time` | 2 days | `key.user.restrict.chat.remove.username` |
| Private messages | `key.user.restrict.pm.username.time` | 7 days | `key.user.restrict.pm.remove.username` |
| Hub search | `key.user.restrict.search.username.time` | 7 days | `key.user.restrict.search.remove.username` |

Set syntax is `!set <key>=[username]` for the default or `!set <key>=[username.12h]` for an explicit duration. Durations accept `m`, `h`, `d`, from `1m` to `365d`. Remove syntax is `!set <remove-key>=[username]`.

## Timed delegated privileges

| Privilege | Set key | Default | Remove key |
| --- | --- | ---: | --- |
| Protected kick | `key.user.grant.kick.username.time` | 7 days | `key.user.grant.kick.remove.username` |
| Hidden share | `key.user.grant.hideshare.username.time` | 7 days | `key.user.grant.hideshare.remove.username` |
| Register class 0/1 users | `key.user.grant.register.username.time` | 7 days | `key.user.grant.register.remove.username` |
| Enter private OPChat | `key.user.grant.opchat.username.time` | 7 days | `key.user.grant.opchat.remove.username` |

OPChat messages use `!opchat <message>`. Operators and higher, plus accounts with an active `opchat` policy, receive the private hub `IMSG`.

## Routing enforcement

- `gag`: blocks `BMSG` main chat.
- `no_chat`: blocks broadcast/direct/echo `MSG`.
- `no_pm`: blocks direct/echo `MSG`.
- `no_search`: blocks ADC `SCH`.
- `no_download`: blocks new `CTM`/`RCM` peer-transfer negotiation.
- Hidden share removes `SS`, `SF`, `SL` from BINF.
- Hidden operator key clears standard ADC `CT` bits 4, 8 and 16.
- Self visibility suppresses INF and routed traffic for lower-class recipients.

## Persistence

Permanent attributes are stored on `accounts`. Expiring state is stored in `user_timed_policies` with an account foreign key and UTC microsecond expiry. `key.user.info.username` reports moderation attributes, active policy names/expiry epochs and the private note without exposing password hashes.

## ncdc validation

Validated with `ncdc 1.23.1` on Debian 13 against `adc://127.0.0.1:15116/` and isolated MariaDB databases. The client completed ADC/TIGR identification and received its echoed public message `ncdc-v0.0.06-connection-test`. A second run bootstrapped Master `v006admin`, stored a private note/protection class, applied `gag` for `1m`, verified the active row in MariaDB and observed `[restriction] public chat is restricted` for the blocked message.

The test corrected protocol negotiation: BASE/TIGR remain mandatory in SUP, but no longer have to be duplicated in BINF `SU`. TIGR PID/CID verification remains mandatory.

## Security boundary

Until ADC VERIFY is implemented, management, self-visibility and password self-service remain IPv4-loopback-only. Admin/Master controls permanent attributes and timed assignments. Delegated registration cannot create classes above Registered (1).

See ADR-0010 and `docs/architecture.md`.
