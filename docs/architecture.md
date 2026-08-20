<!--
architecture.md

v0.0.04:
  - split first-password assignment from password replacement
  - allow passwordless account records with nullable password_hash
  - add private enabled-user listing by numeric class
  - add ADR-0008 for password lifecycle and user-list behavior

v0.0.03:
  - add persistent numeric user classes and user command processing
  - add PBKDF2 password hashing and account mutation APIs
  - define loopback/Admin-Master management boundary and first-Master bootstrap

v0.0.02:
  - add ADC 1.0.4 session-state architecture and TIGR identity validation

v0.0.01:
  - define initial ADC hub architecture, trust boundaries and modules

Author: gpt-5.6-sol
Date: 2026-08-20
-->

# Architecture — dc24h.eu-v0.0.04

## Goals

`dc24h.eu` is a Direct Connect hub implemented in C++20 for ADC on Debian 13. Version `0.0.04` keeps the ADC 1.0.4 BASE/TIGR core and the v0.0.03 numeric account-class model, while making account password lifecycle operations unambiguous and adding a private class-filtered account query.

## Runtime view

1. systemd starts `/usr/local/bin/dc24h.eu /etc/dc24h.eu/dc24h.conf`.
2. `main` loads configuration and selects `en_US.UTF-8`.
3. `Database` connects to MariaDB using `utf8mb4` and ensures `accounts.password_hash` is nullable.
4. `Server` binds the configured IPv4 ADC endpoint, default `0.0.0.0:1511`.
5. Each connection receives an ADC SID and owns an `AdcSession`.
6. `AdcProtocol` validates UTF-8, ADC escaping, session transitions and message routing.
7. A NORMAL `BMSG` whose decoded text begins with `!set ` is intercepted before broadcast.
8. The server applies the existing management trust boundary: IPv4 loopback plus enabled Admin (5) or Master (10), except first local Master bootstrap while no enabled account exists.
9. `UserCommandProcessor` parses the selected `key.user.*` command and validates username, account ID, class and password constraints.
10. Password-bearing operations hash plaintext in process memory with PBKDF2-HMAC-SHA256 before persistence.
11. `Database` performs one of four account mutations or the class-filtered query.
12. A hub-local `IMSG` returns the result to the requesting client. The management command is not broadcast.

## Modules

### `src/adc.*`

ADC 1.0.4 line validation, state machine, SUP/TIGR negotiation, INF sanitization, sender-SID validation and routing decisions.

### `src/hash.*`

Strict ADC Base32 helpers and TIGR PID/CID verification.

### `src/user.*`

Canonical numeric `UserClass` model and password hashing/verification helpers.

### `src/user_commands.*`

Parser/executor for protected user-management keys. v0.0.04 introduces distinct actions for account creation with/without a password, adding the first password, replacing a password, and listing users by class.

### `src/database.*`

Synchronized MariaDB persistence. v0.0.04 adds passwordless account creation, conditional first-password insertion and class-filtered account listing.

### `src/server.*`

TCP listener, connection lifecycle, ADC client state and routing. The existing protected `!set` interception provides the private `IMSG` response channel used by all v0.0.04 user commands.

### `src/version.*`

Canonical runtime source for `0.0.04`, `dc24h.eu-v0.0.04`, author `gpt-5.6-sol` and date `2026-08-20`.

### `tests/user_commands_tests.*`

Regression coverage for supported classes and parsing distinctions between password creation, first-password assignment, password replacement and class listing.

## User class model

`accounts.user_class` is signed `SMALLINT`. Application-valid values are:

- `-1` Hublist pingers
- `0` Regular users
- `1` Registered users
- `2` VIP users
- `3` Operator user
- `4` Cheef user
- `5` Admin user
- `10` Master user

The older `accounts.role` column remains for migration compatibility and is not authoritative for management permission checks.

## Management command grammar

Create a user with an initial password:

`!set key.user.new.username.class.password=[username.class.password]`

Create a user without a password:

`!set key.user.new.username.class=[username.class]`

Assign the first password by account database ID:

`!set key.user.new.id.password=[id.password]`

This operation uses a conditional database update and succeeds only when `password_hash` is `NULL` or empty. If a password already exists, the row is left unchanged and the response directs the operator to the change command.

Replace a password by account database ID:

`!set key.user.change.id.password=[id.password]`

List all enabled users for a numeric class:

`!set key.user.info.userlist.class=[class]`

The list result is serialized into the hub-local private response and is not routed to other users.

Passwords may contain additional dots because parsing consumes only the required leading separators.

## Password lifecycle and storage

Plaintext passwords are never persisted. The hash format remains salted PBKDF2-HMAC-SHA256 with 210000 iterations, a 16-byte random salt and 32-byte derived key:

`pbkdf2-sha256$iterations$salt-hex$digest-hex`

A passwordless registration stores `NULL` in `accounts.password_hash`. `key.user.new.id.password` transitions the account from no password to one password exactly once unless an explicit later `key.user.change.id.password` replaces it.

The separation prevents an operator from accidentally using a "new password" command as an implicit password reset.

## Trust boundaries

ADC VERIFY (`GPA`/`PAS`) is not implemented. Therefore a remote nickname is not sufficient proof of account identity. v0.0.04 keeps the protected management path restricted to `127.0.0.1` and an enabled Admin (5) or Master (10) nickname after bootstrap.

First-Master bootstrap remains available only while the database contains no enabled account and only for creation of a Master account with a password.

## Concurrency

The one-thread-per-client model remains. `clients_mutex_` protects connection state. `Database` serializes MariaDB Connector/C operations with its mutex. The conditional first-password update and its follow-up account-existence check run while holding that database mutex.

## Deployment

Target OS is Debian 13. systemd remains the service manager. MariaDB and libgcrypt remain required dependencies. UTF-8 storage uses MariaDB `utf8mb4`, while the runtime locale remains US English `en_US.UTF-8`.
