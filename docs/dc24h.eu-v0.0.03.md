<!--
dc24h.eu-v0.0.03.md

v0.0.03:
  - define release v0.0.03 user classes, !set commands, validation and limitations

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# dc24h.eu-v0.0.03

- Version: `0.0.03`
- Release name: `dc24h.eu-v0.0.03`
- Author: `gpt-5.6-sol`
- Date: `2026-08-19`
- Base branch: `main`
- Development branch: `agent/dc24h-v0.0.03`
- Target OS: Debian 13
- Service manager: systemd
- Database: MariaDB
- Language: C++20
- Text encoding: UTF-8
- Base locale: US English / `en_US.UTF-8`

## Release objective

Add the first persistent user-class and account-management layer without weakening the ADC v0.0.02 protocol trust boundaries.

## User classes

| Value | Description |
| ---: | --- |
| -1 | Hublist pingers |
| 0 | Regular users |
| 1 | Registered users |
| 2 | VIP users |
| 3 | Operator user |
| 4 | Cheef user |
| 5 | Admin user |
| 10 | Master user |

The authoritative value is `accounts.user_class`. The old `role` column is retained only for migration compatibility.

## Management keys

Create a new account with class and password:

`!set key.user.new.username.class.password=[username.class.password]`

Change the password for database account ID `id`:

`!set key.user.change.id.password=[id.password]`

Accepted compatibility alias:

`!set key.user.new.id.password=[id.password]`

The account `id` is the MariaDB row ID, not the user class.

## Security model

- The command is decoded from a NORMAL ADC `BMSG` and intercepted before broadcast.
- The password is never returned in a hub response.
- The password is stored as salted PBKDF2-HMAC-SHA256, 210000 iterations, 16-byte random salt and 32-byte derived key.
- Account-changing `!set` commands are accepted only from `127.0.0.1` in v0.0.03.
- Once any enabled account exists, the sender's current ADC nickname must match an enabled Admin (5) or Master (10) account.
- If no enabled accounts exist, a local client may bootstrap only a Master (10) account.
- Remote nickname-based authorization is intentionally not enabled because ADC VERIFY (`GPA`/`PAS`) is not yet implemented.

## Changed file manifest

### Build/repository

- `CMakeLists.txt`
- `VERSION`
- `README.md`

### C++ production

- `src/version.cpp`
- `src/version.hpp`
- `src/database.cpp`
- `src/database.hpp`
- `src/server.cpp`
- `src/server.hpp`
- `src/user.cpp` — new
- `src/user.hpp` — new
- `src/user_commands.cpp` — new
- `src/user_commands.hpp` — new

### C++ tests

- `tests/user_commands_tests.cpp` — new
- `tests/user_commands_tests.hpp` — new

### Database/deployment

- `sql/schema.sql`
- `deploy/dc24h.service`

### Documentation

- `docs/architecture.md`
- `docs/instructions.md`
- `docs/changelog.md`
- `docs/readme.md`
- `docs/install.md`
- `docs/dc24h.eu-v0.0.03.md` — new
- `docs/adr/0007-user-classes-set-commands.md` — new

## Validation

The v0.0.03 CTest target covers:

- every supported numeric user class;
- rejection of unsupported class `6`;
- new-user key parsing;
- password-change parsing by database ID;
- `key.user.new.id.password` alias parsing;
- passwords containing dots;
- PBKDF2 hash format;
- successful and failed password verification.

The existing ADC/TIGR regression target remains enabled.

## Known limitations

- ADC registered-user VERIFY (`GPA`/`PAS`) is not implemented.
- Therefore remote Admin/Master account mutation is not enabled.
- The management path currently uses the ADC nickname only after loopback has already established the local trust boundary.
- Account login/password verification is not yet connected to the ADC state machine.
- Ban enforcement, ADCS/TLS, IPv6 listening, anti-flood controls and production metrics remain future work.
- The one-thread-per-client model remains.

## Pull request

The intended PR is from `agent/dc24h-v0.0.03` to `main`, with title `agent/dc24h-v0.0.03`.
