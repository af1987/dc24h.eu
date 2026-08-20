<!--
install.md

v0.0.03:
  - update branch and release references to v0.0.03
  - document user-class schema and first-Master bootstrap
  - add user-command CTest coverage to validation notes

v0.0.02:
  - add libgcrypt20-dev to Debian 13 requirements
  - run CTest as part of installation validation
  - update branch and release references to v0.0.02

v0.0.01:
  - add Debian 13 build, MariaDB and systemd installation procedure

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# Installation — Debian 13

## Requirements

Run on Debian 13 with root/sudo access and network access to Debian package repositories.

The build requires:

- C++20 compiler and build tools
- CMake
- pkg-config
- MariaDB Connector/C development files
- libgcrypt development files
- MariaDB server
- `en_US.UTF-8` locale support

## Automated install

Choose a strong database password containing 16-128 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `-`.

```bash
git clone https://github.com/af1987/dc24h.eu.git
cd dc24h.eu
git checkout agent/dc24h-v0.0.03
sudo DC24H_DB_PASSWORD='replace-with-a-strong-password' ./scripts/install.sh
```

The installer builds the daemon, applies `sql/schema.sql`, runs all CTest targets, installs the systemd unit and starts `dc24h.service`.

## First Master account

On a new database there are no enabled accounts. v0.0.03 provides one bootstrap path:

1. connect an ADC client locally to the hub through `127.0.0.1`;
2. use the nickname you want to become the first Master;
3. send:

`!set key.user.new.username.class.password=[YourNick.10.StrongPasswordHere]`

The bootstrap succeeds only while there are no enabled accounts and only for class `10` (Master). After the first account exists, all account-changing `!set` commands require a local sender whose current ADC nickname matches an enabled Admin (5) or Master (10) account.

Because registered-user ADC VERIFY (`GPA`/`PAS`) is not implemented in v0.0.03, remote account mutation is intentionally disabled.

## User management examples

Create a registered user:

`!set key.user.new.username.class.password=[alice.1.StrongPasswordHere]`

Create an operator:

`!set key.user.new.username.class.password=[operator1.3.AnotherStrongPassword]`

Change password for database account ID 5:

`!set key.user.change.id.password=[5.NewStrongPassword]`

Compatibility alias:

`!set key.user.new.id.password=[5.NewStrongPassword]`

Passwords may contain dots; the parser reserves only the leading separators needed for username/class or id.

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

CTest includes the ADC/TIGR suite and the v0.0.03 user-class / `!set` / PBKDF2 suite.

## MariaDB

The application uses database `dc24h`, MariaDB Connector/C and `utf8mb4`. `accounts.user_class` stores the numeric class. The legacy `role` column remains for compatibility but is not authoritative for v0.0.03.

## Network

The default ADC listener is TCP port `1511`. v0.0.03 remains IPv4-only. The administrative `!set` write path is restricted to `127.0.0.1`.

## systemd

The unit runs as the dedicated `dc24h` account, depends on MariaDB and network-online, uses the US UTF-8 locale and retains the existing hardening directives.
