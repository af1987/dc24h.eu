<!--
install.md

v0.0.04:
  - update branch and release references to v0.0.04
  - document nullable password migration and separate password commands
  - add class-filtered private user-list example

v0.0.03:
  - document user-class schema and first-Master bootstrap
  - add user-command CTest coverage

v0.0.02:
  - add libgcrypt20-dev and CTest validation

v0.0.01:
  - add Debian 13 build, MariaDB and systemd installation procedure

Author: gpt-5.6-sol
Date: 2026-08-20
-->

# Installation — Debian 13

## Requirements

Run on Debian 13 with root/sudo access and network access to Debian package repositories.

The build requires a C++20 compiler, CMake, pkg-config, MariaDB Connector/C development files, libgcrypt development files, MariaDB server and `en_US.UTF-8` locale support.

## Automated install

```bash
git clone https://github.com/af1987/dc24h.eu.git
cd dc24h.eu
git checkout agent/dc24h-v0.0.04
sudo DC24H_DB_PASSWORD='replace-with-a-strong-password' ./scripts/install.sh
```

The installer builds the daemon, applies `sql/schema.sql`, runs CTest, installs the systemd unit and starts `dc24h.service`.

## Database migration for v0.0.04

The v0.0.04 schema intentionally permits accounts without an initial password:

```sql
ALTER TABLE accounts
    MODIFY COLUMN password_hash VARCHAR(255) NULL;
```

Both the application schema bootstrap and `sql/schema.sql` apply this shape. Existing non-NULL password hashes are preserved.

## First Master account

On a new database, connect a local ADC client through `127.0.0.1` and create the first Master with a password:

`!set key.user.new.username.class.password=[YourNick.10.StrongPasswordHere]`

Bootstrap succeeds only while there are no enabled accounts and only for class `10`. After that, protected management commands require a local sender whose current ADC nickname resolves to an enabled Admin (5) or Master (10).

ADC VERIFY (`GPA`/`PAS`) is still not implemented, so remote account management remains intentionally disabled.

## User management examples

Create a registered user with a password:

`!set key.user.new.username.class.password=[alice.1.StrongPasswordHere]`

Create a registered user without a password:

`!set key.user.new.username.class=[bob.1]`

Assign Bob's first password when his database ID is 7:

`!set key.user.new.id.password=[7.FirstStrongPassword]`

If ID 7 already has a password, no change is made. Use the explicit replacement command instead:

`!set key.user.change.id.password=[7.ReplacementStrongPassword]`

Show all enabled Operator-class users in the requesting client's private hub response:

`!set key.user.info.userlist.class=[3]`

Passwords may contain dots; the parser consumes only the required leading separators.

## Service operation

```bash
sudo systemctl status dc24h.service
sudo systemctl restart dc24h.service
sudo journalctl -u dc24h.service -f
```

## Manual build and test

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libmariadb-dev libgcrypt20-dev

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## MariaDB

The application uses database `dc24h`, MariaDB Connector/C and `utf8mb4`. `accounts.user_class` stores the canonical numeric class. `accounts.password_hash` may be `NULL` only for an account that has not received its first password yet.

## Network

The default ADC listener is TCP port `1511`. v0.0.04 remains IPv4-only. The administrative `!set` path remains restricted to `127.0.0.1`.

## systemd

The service runs as the dedicated `dc24h` account, depends on MariaDB and network-online, uses `en_US.UTF-8`, restarts on failure and retains the existing hardening directives.
