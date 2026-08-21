#!/bin/bash
# install.sh
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
# Date: 2026-08-21

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
    mariadb-server \
    locales \
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
reject_symlink "${runtime_config}"
reject_symlink "${database_config}"

install -d -o root -g root -m 0755 "${hub_home_base}"
install -d -o root -g dc24h -m 0750 "${hub_home}"
install -d -o root -g dc24h -m 0750 "${hub_home}/scripts"

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
if ! grep -q '^# v0\.0\.09:' "${runtime_source}"; then
    add_runtime_history=1
fi

awk -v add_history="${add_runtime_history}" '
    BEGIN {
        if (add_history == 1) {
            print "# dc24h.conf"
            print "#"
            print "# v0.0.09:"
            print "#   - migrate runtime configuration to the protected hub home"
            print "#   - reference protected database.cnf credentials"
            print "#"
            print "# Author: gpt-5.6-sol"
            print "# Date: 2026-08-21"
            print ""
        }
    }
    /^[[:space:]]*database_(config|host|port|name|user|password)[[:space:]]*=/ {
        next
    }
    { print }
    END { print "database_config=database.cnf" }
' "${runtime_source}" > "${temporary_runtime}"

if [[ -f "${database_config}" ]]; then
    install -m 0600 "${database_config}" "${temporary_database}"
else
    {
        printf '%s\n' '# database.cnf'
        printf '%s\n' '#'
        printf '%s\n' '# v0.0.09:'
        printf '%s\n' '#   - install protected MariaDB client credentials for this hub home'
        printf '%s\n' '#'
        printf '%s\n' '# Author: gpt-5.6-sol'
        printf '%s\n' '# Date: 2026-08-21'
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
legacy_staging_directory="$(mktemp -d /etc/dc24h.eu/.v0.0.09-link.XXXXXX)"
ln -s -- "${runtime_config}" "${legacy_staging_directory}/dc24h.conf"
mv -fT -- "${legacy_staging_directory}/dc24h.conf" "${legacy_config}"
rmdir -- "${legacy_staging_directory}"

systemctl --no-pager --full status dc24h.service
