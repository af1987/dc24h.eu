#!/usr/bin/env bash
# install.sh
#
# v0.0.01:
#   - install Debian 13 build/runtime dependencies
#   - configure en_US.UTF-8 locale and MariaDB
#   - build/install dc24h.eu and enable systemd service
#
# Author: gpt-5.6-sol
# Date: 2026-08-19

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root (sudo)." >&2
    exit 1
fi

: "${DC24H_DB_PASSWORD:?Set DC24H_DB_PASSWORD to a strong database password}"

if [[ ! "${DC24H_DB_PASSWORD}" =~ ^[A-Za-z0-9._-]{16,128}$ ]]; then
    echo "DC24H_DB_PASSWORD must be 16-128 chars: A-Z a-z 0-9 . _ -" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libmariadb-dev \
    mariadb-server \
    locales

sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
locale-gen en_US.UTF-8

if ! id dc24h >/dev/null 2>&1; then
    useradd --system --home /nonexistent --shell /usr/sbin/nologin dc24h
fi

systemctl enable --now mariadb.service

mariadb <<SQL
CREATE DATABASE IF NOT EXISTS dc24h CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'dc24h'@'127.0.0.1' IDENTIFIED BY '${DC24H_DB_PASSWORD}';
ALTER USER 'dc24h'@'127.0.0.1' IDENTIFIED BY '${DC24H_DB_PASSWORD}';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX ON dc24h.* TO 'dc24h'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

mariadb dc24h < sql/schema.sql

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build --parallel
cmake --install build

if grep -q '^database_password=CHANGE_ME$' /etc/dc24h.eu/dc24h.conf; then
    sed -i "s/^database_password=CHANGE_ME$/database_password=${DC24H_DB_PASSWORD}/" \
        /etc/dc24h.eu/dc24h.conf
fi

chown root:dc24h /etc/dc24h.eu/dc24h.conf
chmod 0640 /etc/dc24h.eu/dc24h.conf

systemctl daemon-reload
systemctl enable --now dc24h.service
systemctl --no-pager --full status dc24h.service
