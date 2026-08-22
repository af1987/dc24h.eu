#!/bin/bash
# install.sh
#
# v0.0.13:
#   - migrate protocol-flood limits and typed temporary-ban defaults
#   - install dc24h.eu-v0.0.13 after the complete test gate
#
# v0.0.12:
#   - install OpenSSL and provision a protected TLS 1.3 certificate/key pair
#   - migrate TLS, bounded-buffer and ADC phase-timeout settings
#
# v0.0.11:
#   - install Argon2id and anti-abuse support for dc24h.eu-v0.0.11
#   - retain protected MariaDB, systemd and per-hub-home deployment
#
# v0.0.10:
#   - install dc24h.eu-v0.0.10 artifacts and generated file metadata
#   - retain protected credentials, schema migration and service checks
#
# v0.0.09:
#   - create the protected /var/lib/dc24h.eu/dc24h.eu hub home
#   - split runtime and MariaDB client configuration files
#   - install script 1 and the validated C++ settings administration tool
#   - preserve non-database runtime settings during legacy configuration migration
#   - keep reinstalls password-consistent and restart the upgraded service
#
# v0.0.02:
#   - install libgcrypt20-dev for ADC TIGR PID/CID verification
#   - run CTest before installing and starting the systemd service
#
# v0.0.01:
#   - install Debian 13 build/runtime dependencies
#   - configure en_US.UTF-8 locale and MariaDB
#   - build/install dc24h.eu and enable systemd service
#
# Author: gpt-5.6-sol
# Date: 2026-08-22

set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 0077

usage() {
    cat <<'USAGE'
Usage:
  sudo ./scripts/install.sh
  sudo env DC24H_DB_PASSWORD_FILE=/run/dc24h-db-password ./scripts/install.sh

Installs the dc24h.eu hub at /var/lib/dc24h.eu/dc24h.eu.
An existing database.cnf password is reused. A clean install prompts securely
unless DC24H_DB_PASSWORD_FILE names a root-owned, mode-0600 regular file.
USAGE
}

if [[ "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ "$#" -ne 0 ]]; then
    usage >&2
    exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root (sudo)." >&2
    exit 1
fi

password_file="${DC24H_DB_PASSWORD_FILE:-}"
unset DC24H_DB_PASSWORD_FILE

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly project_root
readonly hub_name="dc24h.eu"
readonly hub_home_base="/var/lib/dc24h.eu"
readonly hub_home="${hub_home_base}/${hub_name}"
readonly runtime_config="${hub_home}/dc24h.conf"
readonly database_config="${hub_home}/database.cnf"
readonly tls_directory="${hub_home}/tls"
readonly tls_certificate="${tls_directory}/server.crt"
readonly tls_private_key="${tls_directory}/server.key"
readonly legacy_config="/etc/dc24h.eu/dc24h.conf"

reject_symlink() {
    local path="$1"
    if [[ -L "${path}" ]]; then
        echo "Refusing symbolic-link deployment path: ${path}" >&2
        exit 1
    fi
}

validate_config_source() {
    local path="$1"
    local mode
    local mode_value
    if [[ ! -f "${path}" || -L "${path}" ]]; then
        echo "Configuration source must be a regular, non-symlink file: ${path}" >&2
        exit 1
    fi
    if [[ "$(stat -c '%u' "${path}")" -ne 0 ]]; then
        echo "Configuration source must be owned by root: ${path}" >&2
        exit 1
    fi
    mode="$(stat -c '%a' "${path}")"
    mode_value=$((8#${mode}))
    if (( (mode_value & 0022) != 0 )); then
        echo "Configuration source must not be group/world writable: ${path}" >&2
        exit 1
    fi
}

read_config_value() {
    local key="$1"
    local path="$2"
    awk -v target="${key}" '
        /^[[:space:]]*[#;]/ { next }
        {
            separator = index($0, "=")
            if (separator == 0) next
            candidate = substr($0, 1, separator - 1)
            value = substr($0, separator + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", candidate)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (candidate == target) {
                result = value
                count++
            }
        }
        END {
            if (count != 1 || result == "") exit 1
            print result
        }
    ' "${path}"
}

read_password_file() {
    local path="$1"
    local -a lines
    if [[ "${path}" != /* || ! -f "${path}" || -L "${path}" ]]; then
        echo "DC24H_DB_PASSWORD_FILE must be an absolute regular file." >&2
        exit 1
    fi
    if [[ "$(stat -c '%u:%a' "${path}")" != "0:600" ]]; then
        echo "DC24H_DB_PASSWORD_FILE must be root-owned with mode 0600." >&2
        exit 1
    fi
    mapfile -t lines < "${path}"
    if [[ "${#lines[@]}" -ne 1 || -z "${lines[0]}" ]]; then
        echo "DC24H_DB_PASSWORD_FILE must contain exactly one non-empty line." >&2
        exit 1
    fi
    printf '%s' "${lines[0]}"
}

temporary_runtime="$(mktemp /run/dc24h-runtime.XXXXXX)"
temporary_database="$(mktemp /run/dc24h-database.XXXXXX)"
staged_runtime=""
staged_database=""
cleanup() {
    rm -f -- "${temporary_runtime}" "${temporary_database}"
    if [[ -n "${staged_runtime}" ]]; then rm -f -- "${staged_runtime}"; fi
    if [[ -n "${staged_database}" ]]; then rm -f -- "${staged_database}"; fi
}
trap cleanup EXIT
chmod 0600 "${temporary_runtime}" "${temporary_database}"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libmariadb-dev \
    libgcrypt20-dev \
    libargon2-dev \
    libssl-dev \
    mariadb-server \
    locales \
    openssl \
    shellcheck

sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
locale-gen en_US.UTF-8

if ! getent group dc24h >/dev/null 2>&1; then
    groupadd --system dc24h
fi

if ! id dc24h >/dev/null 2>&1; then
    useradd --system \
        --gid dc24h \
        --home-dir "${hub_home}" \
        --no-create-home \
        --shell /usr/sbin/nologin \
        dc24h
else
    usermod --gid dc24h --home "${hub_home}" --shell /usr/sbin/nologin dc24h
fi

reject_symlink "${hub_home_base}"
reject_symlink "${hub_home}"
reject_symlink "${hub_home}/scripts"
reject_symlink "${tls_directory}"
reject_symlink "${runtime_config}"
reject_symlink "${database_config}"
reject_symlink "${tls_certificate}"
reject_symlink "${tls_private_key}"

install -d -o root -g root -m 0755 "${hub_home_base}"
install -d -o root -g dc24h -m 0750 "${hub_home}"
install -d -o root -g dc24h -m 0750 "${hub_home}/scripts"
install -d -o root -g dc24h -m 0750 "${tls_directory}"

if [[ -f "${tls_certificate}" && -f "${tls_private_key}" ]]; then
    validate_config_source "${tls_certificate}"
    validate_config_source "${tls_private_key}"
elif [[ -e "${tls_certificate}" || -e "${tls_private_key}" ]]; then
    echo "TLS certificate and private key must both exist or both be absent." >&2
    exit 1
else
    temporary_tls_directory="$(mktemp -d /run/dc24h-tls.XXXXXX)"
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
        -subj '/CN=dc24h.eu' \
        -addext 'subjectAltName=DNS:dc24h.eu' \
        -keyout "${temporary_tls_directory}/server.key" \
        -out "${temporary_tls_directory}/server.crt"
    install -o root -g dc24h -m 0640 \
        "${temporary_tls_directory}/server.crt" "${tls_certificate}"
    install -o root -g dc24h -m 0640 \
        "${temporary_tls_directory}/server.key" "${tls_private_key}"
    rm -rf -- "${temporary_tls_directory}"
fi

runtime_source="${project_root}/config/dc24h.conf.example"
if [[ -f "${runtime_config}" ]]; then
    runtime_source="${runtime_config}"
elif [[ -f "${legacy_config}" ]]; then
    runtime_source="${legacy_config}"
fi
validate_config_source "${runtime_source}"

database_password=""
if [[ -f "${database_config}" ]]; then
    validate_config_source "${database_config}"
    database_password="$(read_config_value password "${database_config}")"
    if [[ -n "${password_file}" ]]; then
        echo "Existing database.cnf is authoritative; password rotation is separate." >&2
        exit 1
    fi
elif [[ "${runtime_source}" == "${legacy_config}" ]] &&
     database_password="$(read_config_value database_password "${legacy_config}" 2>/dev/null)"; then
    if [[ -n "${password_file}" ]]; then
        echo "Legacy database password is preserved; password rotation is separate." >&2
        exit 1
    fi
elif [[ -n "${password_file}" ]]; then
    database_password="$(read_password_file "${password_file}")"
else
    read -r -s -p "New MariaDB password for dc24h (16-128 safe characters): " \
        database_password
    printf '\n'
fi

if [[ ! "${database_password}" =~ ^[A-Za-z0-9._-]{16,128}$ ]]; then
    echo "Database password must be 16-128 chars: A-Z a-z 0-9 . _ -" >&2
    exit 1
fi

add_runtime_history=0
if ! grep -q '^# v0\.0\.13:' "${runtime_source}"; then
    add_runtime_history=1
fi

awk -v add_history="${add_runtime_history}" '
    BEGIN {
        if (add_history == 1) {
            print "# dc24h.conf"
            print "#"
            print "# v0.0.13:"
            print "#   - migrate runtime configuration with protocol-flood defaults"
            print "#   - reference protected database.cnf credentials"
            print "#"
            print "# Author: gpt-5.6-sol"
            print "# Date: 2026-08-22"
            print ""
        }
    }
    /^[[:space:]]*database_(config|host|port|name|user|password)[[:space:]]*=/ {
        next
    }
    /^[[:space:]]*pwd_tmpban[[:space:]]*=/ { have_pwd_tmpban=1 }
    /^[[:space:]]*password_failure_limit[[:space:]]*=/ { have_failure_limit=1 }
    /^[[:space:]]*password_failure_window[[:space:]]*=/ { have_failure_window=1 }
    /^[[:space:]]*max_users_from_ip[[:space:]]*=/ { have_ip_limit=1 }
    /^[[:space:]]*reconnect_min_interval[[:space:]]*=/ { have_reconnect=1 }
    /^[[:space:]]*clone_detect_count[[:space:]]*=/ { have_clone_count=1 }
    /^[[:space:]]*clone_det_tban_time[[:space:]]*=/ { have_clone_window=1 }
    /^[[:space:]]*clone_ip_tban_time[[:space:]]*=/ { have_clone_ban=1 }
    /^[[:space:]]*protocol_flood_limit[[:space:]]*=/ { have_protocol_limit=1 }
    /^[[:space:]]*protocol_flood_window[[:space:]]*=/ { have_protocol_window=1 }
    /^[[:space:]]*protocol_flood_tmpban[[:space:]]*=/ { have_protocol_ban=1 }
    /^[[:space:]]*tls_enabled[[:space:]]*=/ { have_tls_enabled=1 }
    /^[[:space:]]*tls_only_mode[[:space:]]*=/ { have_tls_only=1 }
    /^[[:space:]]*tls_port[[:space:]]*=/ { have_tls_port=1 }
    /^[[:space:]]*tls_certificate[[:space:]]*=/ { have_tls_cert=1 }
    /^[[:space:]]*tls_private_key[[:space:]]*=/ { have_tls_key=1 }
    /^[[:space:]]*tls_min_version[[:space:]]*=/ { have_tls_min=1 }
    /^[[:space:]]*tls_handshake_timeout[[:space:]]*=/ { have_tls_handshake=1 }
    /^[[:space:]]*mLineSizeMax[[:space:]]*=/ { have_line_limit=1 }
    /^[[:space:]]*max_outbuf_size[[:space:]]*=/ { have_out_limit=1 }
    /^[[:space:]]*timeout_key[[:space:]]*=/ { have_timeout_key=1 }
    /^[[:space:]]*timeout_validate_nick[[:space:]]*=/ { have_timeout_nick=1 }
    /^[[:space:]]*timeout_login[[:space:]]*=/ { have_timeout_login=1 }
    /^[[:space:]]*timeout_myinfo[[:space:]]*=/ { have_timeout_myinfo=1 }
    /^[[:space:]]*timeout_password[[:space:]]*=/ { have_timeout_password=1 }
    /^[[:space:]]*timeout_general[[:space:]]*=/ { have_timeout_general=1 }
    { print }
    END {
        if (!have_pwd_tmpban) print "pwd_tmpban=900"
        if (!have_failure_limit) print "password_failure_limit=5"
        if (!have_failure_window) print "password_failure_window=300"
        if (!have_ip_limit) print "max_users_from_ip=10"
        if (!have_reconnect) print "reconnect_min_interval=2"
        if (!have_clone_count) print "clone_detect_count=3"
        if (!have_clone_window) print "clone_det_tban_time=600"
        if (!have_clone_ban) print "clone_ip_tban_time=900"
        if (!have_protocol_limit) print "protocol_flood_limit=120"
        if (!have_protocol_window) print "protocol_flood_window=10"
        if (!have_protocol_ban) print "protocol_flood_tmpban=300"
        if (!have_tls_enabled) print "tls_enabled=1"
        if (!have_tls_only) print "tls_only_mode=0"
        if (!have_tls_port) print "tls_port=1512"
        if (!have_tls_cert) print "tls_certificate=/var/lib/dc24h.eu/dc24h.eu/tls/server.crt"
        if (!have_tls_key) print "tls_private_key=/var/lib/dc24h.eu/dc24h.eu/tls/server.key"
        if (!have_tls_min) print "tls_min_version=TLS1.3"
        if (!have_tls_handshake) print "tls_handshake_timeout=10"
        if (!have_line_limit) print "mLineSizeMax=65535"
        if (!have_out_limit) print "max_outbuf_size=262144"
        if (!have_timeout_key) print "timeout_key=10"
        if (!have_timeout_nick) print "timeout_validate_nick=15"
        if (!have_timeout_login) print "timeout_login=30"
        if (!have_timeout_myinfo) print "timeout_myinfo=30"
        if (!have_timeout_password) print "timeout_password=30"
        if (!have_timeout_general) print "timeout_general=120"
        print "database_config=database.cnf"
    }
' "${runtime_source}" > "${temporary_runtime}"

if [[ -f "${database_config}" ]]; then
    install -m 0600 "${database_config}" "${temporary_database}"
else
    {
        printf '%s\n' '# database.cnf'
        printf '%s\n' '#'
        printf '%s\n' '# v0.0.13:'
        printf '%s\n' '#   - install protected MariaDB client credentials for this hub home'
        printf '%s\n' '#'
        printf '%s\n' '# Author: gpt-5.6-sol'
        printf '%s\n' '# Date: 2026-08-22'
        printf '\n[client]\n'
        printf 'protocol=tcp\n'
        printf 'host=127.0.0.1\n'
        printf 'port=3306\n'
        printf 'database=dc24h\n'
        printf 'user=dc24h\n'
        printf 'password=%s\n' "${database_password}"
        printf 'default-character-set=utf8mb4\n'
    } > "${temporary_database}"
fi

cmake -S "${project_root}" -B "${project_root}/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build "${project_root}/build" --parallel
ctest --test-dir "${project_root}/build" --output-on-failure

systemctl enable --now mariadb.service

mariadb --no-defaults --protocol=socket --user=root <<SQL
CREATE DATABASE IF NOT EXISTS dc24h CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'dc24h'@'127.0.0.1' IDENTIFIED BY '${database_password}';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX ON dc24h.* TO 'dc24h'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

mariadb --no-defaults --protocol=socket --user=root dc24h \
    < "${project_root}/sql/schema.sql"

mariadb --defaults-file="${temporary_database}" \
    --batch --skip-column-names --execute='SELECT 1' >/dev/null

staged_runtime="$(mktemp "${hub_home}/.dc24h.conf.XXXXXX")"
staged_database="$(mktemp "${hub_home}/.database.cnf.XXXXXX")"
install -o root -g dc24h -m 0640 "${temporary_runtime}" "${staged_runtime}"
install -o root -g dc24h -m 0640 "${temporary_database}" "${staged_database}"
mv -fT -- "${staged_runtime}" "${runtime_config}"
staged_runtime=""
mv -fT -- "${staged_database}" "${database_config}"
staged_database=""

"${project_root}/build/dc24h-settings" "${hub_home}" check

cmake --install "${project_root}/build"
install -o root -g dc24h -m 0750 \
    "${project_root}/scripts/01-edit-hub-settings.sh" \
    "${hub_home}/scripts/01-edit-hub-settings.sh"

[[ "$(stat -c '%U:%G:%a' "${hub_home}")" == "root:dc24h:750" ]]
[[ "$(stat -c '%U:%G:%a' "${runtime_config}")" == "root:dc24h:640" ]]
[[ "$(stat -c '%U:%G:%a' "${database_config}")" == "root:dc24h:640" ]]
[[ "$(stat -c '%U:%G:%a' "${tls_directory}")" == "root:dc24h:750" ]]
[[ "$(stat -c '%U:%G:%a' "${tls_certificate}")" == "root:dc24h:640" ]]
[[ "$(stat -c '%U:%G:%a' "${tls_private_key}")" == "root:dc24h:640" ]]
[[ "$(stat -c '%U:%G:%a' "${hub_home}/scripts")" == "root:dc24h:750" ]]
[[ "$(stat -c '%U:%G:%a' "${hub_home}/scripts/01-edit-hub-settings.sh")" == \
    "root:dc24h:750" ]]

/usr/local/bin/dc24h-settings "${hub_home}" check

systemctl daemon-reload
systemctl enable dc24h.service
systemctl restart dc24h.service
systemctl is-active --quiet dc24h.service

reject_symlink "/etc/dc24h.eu"
install -d -o root -g root -m 0755 "/etc/dc24h.eu"
legacy_staging_directory="$(mktemp -d /etc/dc24h.eu/.v0.0.13-link.XXXXXX)"
ln -s -- "${runtime_config}" "${legacy_staging_directory}/dc24h.conf"
mv -fT -- "${legacy_staging_directory}/dc24h.conf" "${legacy_config}"
rmdir -- "${legacy_staging_directory}"

systemctl --no-pager --full status dc24h.service
