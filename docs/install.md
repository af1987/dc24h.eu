<!--
install.md

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
- libgcrypt development files for TIGR
- MariaDB server
- `en_US.UTF-8` locale support

## Automated install

Choose a strong database password containing 16-128 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `-`.

```bash
git clone https://github.com/af1987/dc24h.eu.git
cd dc24h.eu
git checkout agent/dc24h-v0.0.02
sudo DC24H_DB_PASSWORD='replace-with-a-strong-password' ./scripts/install.sh
```

The installer:

- installs `build-essential`, CMake, pkg-config, `libmariadb-dev`, `libgcrypt20-dev`, MariaDB server and locales;
- enables `en_US.UTF-8`;
- creates the `dc24h` system user;
- creates the `dc24h` MariaDB database and restricted DB account;
- configures and builds the project;
- runs CTest;
- installs `/usr/local/bin/dc24h.eu`;
- installs `/etc/dc24h.eu/dc24h.conf`;
- installs/enables `dc24h.service`.

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

The application uses database `dc24h` and the MariaDB Connector/C client. Text is configured as `utf8mb4`. The installer applies `sql/schema.sql` and writes the supplied password to the protected runtime configuration.

## Network

The default ADC listener is TCP port `1511`. Configure host firewall and NAT explicitly for the deployment environment.

v0.0.02 still binds an IPv4 listener. IPv6 listener support is a future change even though ADC itself defines IPv6 fields.

## systemd

The unit runs as the dedicated `dc24h` account, depends on MariaDB and network-online, uses the US UTF-8 locale and retains hardening directives from v0.0.01.
