<!--
dc24h.eu-v0.0.09.md

v0.0.09:
  - define the protected per-hub home and split MariaDB configuration
  - document the validated database-backed settings administration interface
  - define secure credential creation and reuse without silent rotation
  - record reviewed validation and checks still open before merge

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# dc24h.eu-v0.0.09

## Release identity

- Program/version: `dc24h.eu` / `0.0.09`
- Release: `dc24h.eu-v0.0.09`
- Author/date: `gpt-5.6-sol` / `2026-08-21`
- Repository: `https://github.com/af1987/dc24h.eu.git`
- Development branch: `agent/dc24h-v0.0.09`
- Target branch: `main`
- Pull request: `#9`

## Platform contract

ADC 1.0.4 BASE/TIGR, UTF-8, US English / `en_US.UTF-8`, C++20,
MariaDB `utf8mb4`, Debian 13 and systemd remain the required baseline. The
default IPv4 ADC listener remains TCP port 1511. v0.0.09 changes installation,
configuration and local settings administration; it does not replace the
v0.0.08 moderation or ADC trust model.

## Implemented v0.0.09 scope

- Raise canonical runtime, CMake, test, documentation and systemd metadata to
  `0.0.09` / `dc24h.eu-v0.0.09`.
- Make `/var/lib/dc24h.eu/dc24h.eu` the installed hub and service-account home.
- Separate non-secret runtime options in `dc24h.conf` from MariaDB credentials
  in a strict standard `database.cnf`.
- Read the MariaDB option file through Connector/C rather than a shell parser or
  a MariaDB command-line client.
- Install the paired `settings_cli.cpp` / `settings_cli.hpp` implementation as
  `/usr/local/bin/dc24h-settings`.
- Install `01-edit-hub-settings.sh` in the hub home and expose only `list`,
  `get`, `set` and `check`.
- Require and validate exactly 30 canonical settings for every local read or
  update operation.
- Protect concurrent setting changes using a MariaDB transaction and
  `SELECT ... FOR UPDATE`.

## Per-hub home contract

The phrase `nazwa-huba` denotes one validated instance-name segment. It is not
installed literally. The v0.0.09 instance layout is:

| Path | Owner/mode | Purpose |
| --- | --- | --- |
| `/var/lib/dc24h.eu` | `root:root`, `0755` | parent of installed instances |
| `/var/lib/dc24h.eu/dc24h.eu` | `root:dc24h`, `0750` | canonical hub home |
| `dc24h.conf` | `root:dc24h`, `0640` | non-secret runtime configuration |
| `database.cnf` | `root:dc24h`, `0640` | Connector/C options and database secret |
| `scripts/` | `root:dc24h`, `0750` | instance-local administration directory |
| `scripts/01-edit-hub-settings.sh` | `root:dc24h`, `0750` | root-only settings wrapper |

The `dc24h` system account uses the canonical hub home and
`/usr/sbin/nologin`. systemd sets the same `HOME` and `WorkingDirectory`, starts
the daemon with the absolute `dc24h.conf` path and marks the home read-only for
the service. The root-owned files therefore remain readable but not writable
by the daemon.

## Split configuration

The canonical runtime file contains:

```ini
hub_name=dc24h.eu
hub_description=dc24h.eu Direct Connect ADC Hub
listen_address=0.0.0.0
listen_port=1511
max_clients=1024
locale=en_US.UTF-8
dns_lookup=0

database_config=database.cnf
```

The adjacent standard MariaDB option file contains:

```ini
[client]
protocol=tcp
host=127.0.0.1
port=3306
database=dc24h
user=dc24h
password=<installed-secret>
default-character-set=utf8mb4
```

`Config` validates the option file before `Database` supplies its canonical
path to MariaDB Connector/C through `MYSQL_READ_DEFAULT_FILE` and selects the
`client` option group. The file must contain exactly one `[client]` section and
each of the seven listed keys exactly once. Empty, duplicate or unknown values,
additional sections, a non-TCP protocol, a non-`utf8mb4` character set,
symlinks and unsafe modes are rejected.

A relative reference is resolved against the directory containing
`dc24h.conf`, must be a basename beside that file and cannot contain a parent
component. The parser retains the older inline `database_*` fields for
migration compatibility, but rejects any mixture of inline options and
`database_config`. The installed service and local editor always use the split
form.

## Installer and migration behavior

The root-only installer accepts no positional arguments. On a clean install it
obtains the 16–128-character password from a hidden prompt or an absolute,
root-owned, mode-`0600`, non-symlink regular file selected by
`DC24H_DB_PASSWORD_FILE`. The variable carries only a path; the password is not
accepted as an environment-variable value or command argument. Privileged
scripts use `/bin/bash` and a fixed system `PATH`.

For migration it preserves non-database lines from the first available source:
the active hub-home configuration, the legacy `/etc/dc24h.eu/dc24h.conf`, or
the repository example. It removes old inline/external database references and
appends one `database_config=database.cnf`. A reinstall automatically reuses
the existing `database.cnf`; an initial legacy migration reuses its inline
password. A new password file is rejected when either credential already
exists. MariaDB user creation is idempotent and no reinstall silently issues
`ALTER USER` or rotates the password. No v0.0.09 schema table or seed is added;
all existing data and the 30 setting rows are retained.

After the Release build and CTest pass, the installer configures MariaDB and
applies the schema, atomically publishes both configuration files, invokes the
just-built CLI as
`build/dc24h-settings /var/lib/dc24h.eu/dc24h.eu check`, installs the tested
artifacts, repeats the check with `/usr/local/bin/dc24h-settings`, and restarts
the service. Once the unit is active, the legacy
`/etc/dc24h.eu/dc24h.conf` is atomically replaced by a symlink to the non-secret
home runtime file.

## Settings administration interface

The installed commands are:

```text
01-edit-hub-settings.sh HUB_HOME list
01-edit-hub-settings.sh HUB_HOME get KEY
01-edit-hub-settings.sh HUB_HOME set KEY VALUE
01-edit-hub-settings.sh HUB_HOME check
```

Example:

```bash
DC24H_HUB_HOME=/var/lib/dc24h.eu/dc24h.eu
DC24H_SETTINGS_TOOL="${DC24H_HUB_HOME}/scripts/01-edit-hub-settings.sh"

sudo "${DC24H_SETTINGS_TOOL}" "${DC24H_HUB_HOME}" list
sudo "${DC24H_SETTINGS_TOOL}" "${DC24H_HUB_HOME}" get key.kicks
sudo "${DC24H_SETTINGS_TOOL}" "${DC24H_HUB_HOME}" set key.kicks 600
sudo "${DC24H_SETTINGS_TOOL}" "${DC24H_HUB_HOME}" check
```

The shell wrapper requires root, an existing canonical non-symlink absolute
directory, one safe direct child of `/var/lib/dc24h.eu`, valid command arity and
the installed `/usr/local/bin/dc24h-settings`. It delegates without loading the
credential file itself.

The compiled tool repeats the hub-home and exact `root:dc24h` ownership/mode
checks, loads `dc24h.conf`, verifies `database.cnf`, connects with Connector/C
and applies these semantics:

- `list` validates and prints all 30 canonical `key=value` rows in key order.
- `get` validates the complete snapshot and prints one canonical row.
- `set` normalizes one canonical key/value, validates and stores the candidate,
  then reads back and prints `updated key=value`.
- `check` prints `OK: 30 canonical hub settings are valid` only for a complete,
  valid snapshot.
- `key.account.password.setup.timeout` is accepted only as a compatibility
  alias and resolves to `key.user.password.initial.timeout`.
- Unknown keys, malformed values, missing/extra rows and cross-key invariant
  failures produce a non-zero result.
- There is no arbitrary SQL or delete operation, and no command prints the
  MariaDB credential.

For `set`, the database layer starts a transaction and locks the entire
canonical selection with `FOR UPDATE`. It validates the candidate snapshot,
including `key.kicks <= key.bans` and
`key.nick.length.minimum <= key.nick.length.maximum`, then commits the upsert.
Every exception or invalid invariant rolls the transaction back. A successful
database setting is observed on the next relevant settings lookup; changing a
configuration file still requires a service restart.

## Security and compatibility boundaries

- The database password remains plaintext at rest in `database.cnf`; Unix
  ownership/mode, root-only administration and the systemd read-only home are
  its protection boundary.
- The application database identity still has schema privileges because the
  daemon retains runtime idempotent schema bootstrap.
- Direct local settings updates retain `settings.updated_at` but do not yet
  record a separate actor, reason or previous-value audit row.
- v0.0.09 installs one fixed `dc24h.service`. A second simultaneous instance
  still needs distinct service, listener and database configuration.
- ADC VERIFY remains unimplemented. In-hub protected operations retain the
  existing loopback and account-class boundary; the settings CLI instead uses
  the root plus protected-filesystem boundary.

## Validation status

Reviewed results for the PR #9 candidate:

- Debian 13.6 clean Release configuration and build with warnings treated as
  errors completed; CTest, including ShellCheck, passed 8/8.
- The installer completed repeated executions. The final current-installer run
  provided no new password, reused the existing `database.cnf` and performed no
  silent rotation or secret-valued environment input.
- `sql/schema.sql` was applied repeatedly and exactly 30 canonical setting rows
  remained present.
- Live `list`, `get`, valid `set` and `check` passed. Invalid keys/ranges and
  both cross-key invariants failed as required. Twelve concurrent update
  attempts completed with a successful final `check`.
- `dc24h.service` was active from the protected home, the unit passed
  verification and `systemd-analyze security` reported exposure score `3.0`.
- A real Debian `ncdc 1.23.1` ADC/TIGR session echoed
  `ncdc-v0.0.09-connection-test`, reconnected after the service restart and
  echoed `ncdc-v0.0.09-after-restart`.

Local forbidden-name, C++ implementation/header pair and secret scans passed.
Remote GitHub CI is the required final merge gate for PR #9; its result is
verified on GitHub rather than inferred from these local checks.
