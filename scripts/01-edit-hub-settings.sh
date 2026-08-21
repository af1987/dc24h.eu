#!/bin/bash
# 01-edit-hub-settings.sh
#
# v0.0.09:
#   - add script 1 for validated MariaDB-backed hub settings administration
#   - accept a protected per-hub home and expose list/get/set/check only
#   - reject traversal, symlinked homes and unsafe instance names
#
# Author: gpt-5.6-sol
# Date: 2026-08-21

set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly DC24H_HOME_BASE="/var/lib/dc24h.eu"
readonly DC24H_SETTINGS_BINARY="/usr/local/bin/dc24h-settings"

usage() {
    cat <<'USAGE'
Usage:
  01-edit-hub-settings.sh HUB_HOME list
  01-edit-hub-settings.sh HUB_HOME get KEY
  01-edit-hub-settings.sh HUB_HOME set KEY VALUE
  01-edit-hub-settings.sh HUB_HOME check
USAGE
}

if [[ "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root (sudo)." >&2
    exit 1
fi

if [[ "$#" -lt 2 ]]; then
    usage >&2
    exit 2
fi

hub_home="$1"
shift

if [[ "${hub_home}" != /* || -L "${hub_home}" || ! -d "${hub_home}" ]]; then
    echo "HUB_HOME must be an existing absolute, non-symlink directory." >&2
    exit 1
fi

canonical_home="$(realpath -e -- "${hub_home}")"
if [[ "${canonical_home}" != "${hub_home}" ||
      "$(dirname -- "${canonical_home}")" != "${DC24H_HOME_BASE}" ]]; then
    echo "HUB_HOME must be one direct child of ${DC24H_HOME_BASE}." >&2
    exit 1
fi

hub_name="$(basename -- "${canonical_home}")"
if [[ ! "${hub_name}" =~ ^[A-Za-z0-9._-]+$ ||
      "${hub_name}" == "." || "${hub_name}" == ".." ]]; then
    echo "HUB_HOME contains an unsafe hub name." >&2
    exit 1
fi

case "$1" in
    list|check)
        [[ "$#" -eq 1 ]] || { usage >&2; exit 2; }
        ;;
    get)
        [[ "$#" -eq 2 ]] || { usage >&2; exit 2; }
        ;;
    set)
        [[ "$#" -eq 3 ]] || { usage >&2; exit 2; }
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

if [[ ! -x "${DC24H_SETTINGS_BINARY}" ]]; then
    echo "Missing settings binary: ${DC24H_SETTINGS_BINARY}" >&2
    exit 1
fi

exec "${DC24H_SETTINGS_BINARY}" "${canonical_home}" "$@"
