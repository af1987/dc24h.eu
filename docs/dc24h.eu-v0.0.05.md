<!--
dc24h.eu-v0.0.05.md

v0.0.05:
  - define the dc24h.eu-v0.0.05 release manifest
  - list complete user administration and online lookup keys
  - record gpt-5.6-sol and 2026-08-20 provenance

Author: gpt-5.6-sol
Date: 2026-08-20
-->

# dc24h.eu-v0.0.05

## Release identity

- Program/version: `dc24h.eu` / `0.0.05`
- Release: `dc24h.eu-v0.0.05`
- Author/date: `gpt-5.6-sol` / `2026-08-20`
- Repository: `https://github.com/af1987/dc24h.eu.git`
- Development branch: `agent/dc24h-v0.0.05`
- Target branch: `main`

## Platform

- Direct Connect ADC 1.0.4 BASE/TIGR
- UTF-8, US English, `en_US.UTF-8`
- C++20 and CMake
- MariaDB `utf8mb4`
- Linux Debian 13 and systemd
- Default IPv4 TCP port 1511

## Protected user keys

| Purpose | Command |
| --- | --- |
| List class; empty means 0 | `!set key.user.info.userlist.class=[class]` |
| Register with password | `!set key.user.new.username.class.password=[username.class.password]` |
| Register without password | `!set key.user.new.username.class=[username.class]` |
| Add first password by ID | `!set key.user.new.id.password=[id.password]` |
| Replace password by ID | `!set key.user.change.id.password=[id.password]` |
| Replace/reset password by nickname | `!set key.user.change.username.password=[username.password]` |
| Remove registration | `!set key.user.remove.username=[username]` |
| Disable registration | `!set key.user.disable.username=[username]` |
| Enable registration | `!set key.user.enable.username=[username]` |
| Change permanent class | `!set key.user.change.username.class=[username.class]` |
| Change class until restart, maximum 5 | `!set key.user.change.username.class.temp=[username.class]` |
| Show registered account information | `!set key.user.info.username=[username]` |
| Show online IP and hostname | `!set key.user.info.ip.hostname.username=[username]` |
| Show online hostname | `!set key.user.info.hostname.username=[username]` |
| Find online users by exact IP | `!set key.user.info.userlist.ip=[IPv4]` |
| Find online users by inclusive range | `!set key.user.info.userlist.iprange=[start-end]` |
| Find online users by subnet | `!set key.user.info.userlist.subnet=[network/prefix]` |

An empty nickname-password value such as `[alice.]` resets `password_hash` to `NULL`. The enabled local account using nickname `alice` may then use `+passwd NewStrongPassword` once. Existing passwords are never overwritten by `+passwd` or `key.user.new.id.password`.

## Classes

`-1` Hublist pinger, `0` Regular, `1` Registered, `2` VIP, `3` Operator, `4` Cheef, `5` Admin, `10` Master.

## Persistence and safety

MariaDB stores enabled state, canonical class, password hash presence and creation/update timestamps. Class lists include disabled accounts. Account information never exposes password hashes. The final enabled Master cannot be removed, disabled or demoted.

Temporary class overrides exist only in process memory and disappear after `systemctl restart dc24h.service`. Their maximum is Admin (5).

## Network information

Online lookup keys read current IPv4 sessions. `dns_lookup=0` is the default. With `dns_lookup=1`, hostname commands use reverse DNS; address matching itself never depends on DNS.

## Security boundary

Until ADC VERIFY is implemented, `!set` requires loopback and an enabled effective Admin/Master account after bootstrap. `+passwd` also remains loopback-only. Password-bearing messages are intercepted before broadcast and private responses never echo submitted passwords.

## Validation

- CMake Debug configuration on Debian 13.
- Build with `-Wall -Wextra -Wpedantic -Wconversion -Wshadow`.
- Assertion-based checks remain enabled in Release test targets.
- CTest protocol/TIGR suite.
- CTest complete user-key parser and password suite.

See ADR-0009 and `docs/architecture.md`.
