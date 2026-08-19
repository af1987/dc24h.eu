<!--
install.md

v0.0.01:
  - add Debian 13 build, MariaDB and systemd installation procedure

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# Installation — Debian 13

## Requirements

Run on Debian 13 with root/sudo access and network access to Debian package repositories.

## Automated install

Choose a strong database password containing 16-128 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `-`.

```bash
git clone https://github.com/af1987/dc24h.eu.git
cd dc24h.eu
git checkout agent/dc24h-v0.0.01
sudo DC24H_DB_PASSWORD='replace-with-a-strong-password' ./scripts/install.sh
```

The installer:
- installs C++ build tools, MariaDB development files/server and locales;
- enables `en_US.UTF-8`;
- creates the `dc24h` system user;
- creates the `dc24h` MariaDB database and restricted DB account;
- builds and installs `/usr/local/bin/dc24h.eu`;
- installs `/etc/dc24h.eu/dc24h.conf`;
- installs/enables `dc24h.service`.

## Service operation

```bash
sudo systemctl status dc24h.service
sudo systemctl restart dc24h.service
sudo journalctl -u dc24h.service -f
```

## Manual build

```bash
sudo apt-get install build-essential cmake pkg-config libmariadb-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

## Network

The default ADC listener is TCP port `1511`. Configure host firewall/NAT explicitly for the deployment environment.
