<!--
dc24h.eu-v0.0.07.md

v0.0.07:
  - define the class/nickname policy and self-registration release
  - list account security, profile and telemetry behavior

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# dc24h.eu-v0.0.07

Release date: 2026-08-21

Author: `gpt-5.6-sol`

## Platform contract

- Direct Connect protocol: ADC 1.0.4 BASE/TIGR
- Text: UTF-8
- Base language/locale: US English / `en_US.UTF-8`
- Program language: C++20
- Database: MariaDB `utf8mb4`
- Operating system: Debian 13
- Service manager: systemd
- Default TCP port: 1511

## Class permission keys

| Key | Default | Enforcement |
| --- | ---: | --- |
| `key.class.permission.register.difference` | 2 | actor class minus target registration class |
| `key.class.permission.kick.difference` | 0 | actor class minus target kick class |
| `key.class.permission.pm.difference` | 10 | highest class reachable by PM relative to sender |
| `key.class.permission.download.difference` | 10 | highest class reachable by CTM/RCM relative to sender |
| `key.class.minimum.usehub` | 0 | admission to hub services |
| `key.class.minimum.usehub.passive` | 0 | stored passive-client admission threshold |
| `key.class.minimum.register` | 3 | registration command access |
| `key.class.minimum.redirect` | 3 | stored redirect threshold |
| `key.class.minimum.broadcast` | 3 | stored general broadcast threshold |
| `key.class.minimum.broadcast.guests` | 3 | stored guest broadcast threshold |
| `key.class.minimum.broadcast.registered` | 3 | stored registered-user broadcast threshold |
| `key.class.minimum.broadcast.vip` | 3 | stored VIP broadcast threshold |
| `key.class.minimum.plugin.modify` | 5 | stored extension-management threshold |
| `key.class.minimum.topic.modify` | 5 | stored topic-management threshold |
| `key.class.minimum.trigger.modify` | 5 | stored trigger-management threshold |

Every key uses `!set <key>=[value]`. Class values must be one of `-1, 0, 1, 2, 3, 4, 5, 10`; differences must be `0..10`.

## Nickname keys

| Key | Default | Meaning |
| --- | --- | --- |
| `key.nick.length.maximum` | `64` | maximum UTF-8 code points |
| `key.nick.length.minimum` | `3` | minimum UTF-8 code points |
| `key.nick.characters.allowed` | empty | optional explicit ASCII character set |
| `key.nick.prefix` | empty | comma-separated admission prefixes |
| `key.nick.prefix.nocase` | `0` | ASCII case-insensitive prefix matching |
| `key.nick.prefix.autoreg` | empty | additional self-registration prefix |
| `key.nick.prefix.country` | empty | stored country-prefix policy |

## Self-registration and passwords

| Key | Default |
| --- | ---: |
| `key.user.autoreg.class` | `-1` (disabled) |
| `key.user.autoreg.minimum.share.registered` | `0` bytes |
| `key.user.autoreg.minimum.share.vip` | `0` bytes |
| `key.user.autoreg.minimum.share.operator` | `0` bytes |
| `key.user.password.minimum.length` | `8` bytes |
| `key.user.password.initial.timeout` | `300` seconds |

`key.account.password.setup.timeout` is an accepted alias for the canonical initial-timeout key. Self-registration uses `+regme <password>`, is limited to configured classes `0..3`, checks the client's ADC `SS` share value and never broadcasts the password. Passwordless administrator registrations must finish `+passwd <password>` within the configured `60..86400` second timeout.

## Account keys

- `key.user.auth.ip.username=[username.IPv4]`
- `key.user.auth.ip.remove.username=[username]`
- `key.user.email.username=[username.email]`; an empty email removes it.
- `key.user.note.public.username=[username.note]`; an empty note removes it.
- `key.user.hide.kick.username=[username.1|0]`
- `key.user.hide.kick.username.class=[username.class]`

The existing `key.user.info.username=[username]` response now includes `registered_at`, `registered_by`, `last_login_at`, `last_logout_at`, `login_count`, `last_login_ip`, `email`, `password_change_required`, `auth_ip`, public note and kick-message controls. These telemetry fields are not directly writable.

## Security boundary

Protected `!set` traffic remains loopback-only until ADC VERIFY is implemented. Account IP is checked before NORMAL state. `+regme` is disabled by default; both self-service commands are intercepted before chat routing. Passwords remain salted PBKDF2-HMAC-SHA256 values and are never returned.

## Validation

- Release build with `-Wall -Wextra -Wpedantic -Wconversion -Wshadow`.
- Assertion-enabled ADC/TIGR and user-policy CTest suites.
- Idempotent MariaDB schema application and seeded-setting checks.
- Real connection and message echo through Debian `ncdc 1.23.1`, plus Master
  bootstrap, policy/profile updates and prefixed `+regme` telemetry validation.
