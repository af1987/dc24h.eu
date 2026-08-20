<!--
architecture.md

v0.0.03:
  - add persistent numeric user classes and user command processing
  - add PBKDF2 password hashing and account mutation APIs
  - define loopback/Admin-Master management boundary and first-Master bootstrap

v0.0.02:
  - add ADC 1.0.4 session-state architecture and TIGR identity validation
  - define sanitized INF state, user-list synchronization and B/D/E/F routing
  - add libgcrypt as the TIGR implementation dependency

v0.0.01:
  - define initial ADC hub architecture, trust boundaries and modules

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# Architecture — dc24h.eu-v0.0.03

## Goals

`dc24h.eu` is a Direct Connect hub implemented in C++20 for ADC. Version `0.0.03` keeps the ADC 1.0.4 BASE/TIGR core from v0.0.02 and introduces the first persistent account-class and account-management layer.

## Runtime view

1. systemd starts `/usr/local/bin/dc24h.eu /etc/dc24h.eu/dc24h.conf`.
2. `main` loads configuration and selects `en_US.UTF-8`.
3. `Database` connects to MariaDB using `utf8mb4` and ensures the account schema includes `user_class`.
4. `Server` binds the configured IPv4 TCP endpoint, default `0.0.0.0:1511`.
5. Each connection receives an ADC SID and owns an `AdcSession`.
6. `AdcProtocol` validates UTF-8, ADC escaping, state transitions and B/D/E/F routing.
7. The server keeps sanitized INF fields, including the current ADC nickname, and the peer IPv4 address.
8. A NORMAL `BMSG` whose decoded text begins with `!set ` is intercepted before normal broadcast routing.
9. The server applies the management trust boundary:
   - the connection must come from `127.0.0.1`;
   - normally the current decoded ADC nickname must match an enabled MariaDB account with class Admin (5) or Master (10);
   - when no enabled accounts exist, exactly the first local Master account may be bootstrapped.
10. `UserCommandProcessor` parses the key and validates username, account ID, class and password length.
11. `user.*` hashes the password with PBKDF2-HMAC-SHA256 and a random salt.
12. `Database` writes the account or updates the password by database `id`.
13. A hub-local `IMSG` reports success or failure. The original command is not broadcast.

## Modules

### `src/adc.*`

ADC 1.0.4 line validation, session state, SUP/TIGR negotiation, INF sanitization, sender-SID validation and routing decisions.

### `src/hash.*`

Strict ADC Base32 helpers and TIGR PID/CID verification.

### `src/user.*`

Canonical numeric `UserClass` model and password hashing/verification helpers.

### `src/user_commands.*`

Parser/executor for versioned `!set key.user.*` management commands.

### `src/server.*`

TCP listener, worker lifecycle, client state and routing. v0.0.03 also owns the trust boundary for account-changing chat commands.

### `src/database.*`

MariaDB connection and synchronized queries. The account API creates users, changes password by account database ID, resolves a class by nickname and detects an empty account set for first-Master bootstrap.

### `src/config.*`

Strict `key=value` configuration loading.

### `src/version.*`

Canonical runtime source for `0.0.03`, `dc24h.eu-v0.0.03`, author and project date.

### `tests/adc_tests.*`

ADC/TIGR regression tests retained from v0.0.02.

### `tests/user_commands_tests.*`

Regression tests for all class values, command parsing, dotted passwords and PBKDF2 verification.

## User class model

`accounts.user_class` is a signed `SMALLINT` with these application-valid values:

- `-1` Hublist pingers
- `0` Regular users
- `1` Registered users
- `2` VIP users
- `3` Operator user
- `4` Cheef user
- `5` Admin user
- `10` Master user

The older `accounts.role` column remains temporarily for schema compatibility but is not authoritative for v0.0.03 permissions.

## Management command grammar

Create a user:

`!set key.user.new.username.class.password=[username.class.password]`

Change password by account database ID:

`!set key.user.change.id.password=[id.password]`

Compatibility alias:

`!set key.user.new.id.password=[id.password]`

The password portion may contain additional dots; parsing splits only the required leading fields.

## Password storage

Plaintext passwords are not stored. `user.*` uses PBKDF2-HMAC-SHA256 with a 16-byte random salt, 210000 iterations and a 32-byte derived key. The encoded database form is:

`pbkdf2-sha256$iterations$salt-hex$digest-hex`

The command text exists transiently in process memory while the request is parsed and hashed. It is not included in success/error responses and is intercepted before broadcast.

## Trust boundaries

Remote ADC identity is not yet authenticated with `GPA`/`PAS`. Consequently, a remote nickname cannot authorize account mutations. v0.0.03 restricts account-changing `!set` commands to IPv4 loopback.

First-Master bootstrap is available only when the database contains no enabled account. After the first enabled account exists, the bootstrap path closes and Admin/Master nickname lookup is required.

A future release implementing ADC VERIFY should replace or extend this temporary local-administration boundary through a new ADR.

## Concurrency

The one-thread-per-client model remains. `clients_mutex_` protects connection state; `Database` serializes MariaDB Connector/C access. Password derivation happens outside the database lock.

## Deployment

Target OS is Debian 13. systemd remains the service manager. MariaDB and libgcrypt remain required dependencies. `scripts/install.sh` builds and executes CTest before enabling the service.
