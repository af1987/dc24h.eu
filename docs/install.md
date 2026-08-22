<!--
install.md

v0.0.10:
  - install the 0.0.10 password, RBAC and hostname-ban release
  - document moderation constraint migration and ncdc release validation

v0.0.09:
  - install the protected /var/lib/dc24h.eu/dc24h.eu hub home
  - document split runtime/MariaDB configuration and legacy migration
  - add the root-only list/get/set/check settings administration workflow
  - document secret-safe clean install and credential-preserving reinstall
  - record reviewed Debian 13.6, systemd and ncdc validation

v0.0.08:
  - install persistent kick/ban schema and v0.0.08 branch
  - document moderation operations, migration and two-client ncdc validation

v0.0.07:
  - install v0.0.07 policy schema and branch
  - document auto-registration and ncdc validation

v0.0.06:
  - update branch and migration instructions for moderation policies
  - document duration keys, OPChat and ncdc connection validation

v0.0.05:
  - update branch and release references to v0.0.05
  - document updated_at migration and the complete user key set
  - document dns_lookup and temporary-class restart behavior

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
Date: 2026-08-21
-->

# Installation — Debian 13

## Requirements

Run on Debian 13 with root/sudo access and network access to Debian package repositories.

The build requires a C++20 compiler, CMake, pkg-config, MariaDB Connector/C
development files, libgcrypt development files, MariaDB server, ShellCheck and
`en_US.UTF-8` locale support.

## Automated install

```bash
git clone https://github.com/af1987/dc24h.eu.git
cd dc24h.eu
git checkout agent/dc24h-v0.0.10
sudo ./scripts/install.sh
```

On a clean install this command prompts without echo for a password containing
16–128 characters from `A-Z`, `a-z`, `0-9`, `.`, `_` and `-`. For an
unattended clean install, create a root-only input file without putting the
secret in the command line or environment:

```bash
sudo install -o root -g root -m 0600 /dev/null /run/dc24h-db-password
sudoedit /run/dc24h-db-password
sudo env DC24H_DB_PASSWORD_FILE=/run/dc24h-db-password \
  ./scripts/install.sh
sudo rm -f /run/dc24h-db-password
```

`DC24H_DB_PASSWORD_FILE` must name an absolute root-owned mode-`0600` regular,
non-symlink file containing exactly one non-empty line. The environment value
is only the path; `DC24H_DB_PASSWORD` is not supported. On reinstall, run
`sudo ./scripts/install.sh` without a password input: the installer reuses the
existing `database.cnf` password, or the inline password from the legacy config
during its first migration. It rejects a supplied password file when either
credential already exists and performs no implicit `ALTER USER` or password
rotation.

The installer accepts no positional arguments and always installs the
`dc24h.eu` instance at the path below. Its privileged scripts use `/bin/bash`
and a fixed system `PATH`. After dependency, account and directory preparation,
the deployment sequence is:

1. configure and build the Release targets, then pass CTest;
2. configure MariaDB and apply `sql/schema.sql`;
3. publish `dc24h.conf` and `database.cnf` atomically;
4. run the just-built
   `build/dc24h-settings /var/lib/dc24h.eu/dc24h.eu check`;
5. install the tested binaries, unit, examples and wrapper;
6. run the installed settings check, restart the unit and require it active;
7. atomically replace legacy `/etc/dc24h.eu/dc24h.conf` with a symlink to the
   non-secret home `dc24h.conf`.

## Installed hub home

The text `nazwa-huba` is a placeholder for one validated instance-name segment;
it is not a literal directory. The v0.0.10 instance is exactly:

`/var/lib/dc24h.eu/dc24h.eu`

| Path | Owner/mode | Purpose |
| --- | --- | --- |
| `/var/lib/dc24h.eu` | `root:root`, `0755` | instance parent |
| `/var/lib/dc24h.eu/dc24h.eu` | `root:dc24h`, `0750` | service-account home |
| `dc24h.conf` | `root:dc24h`, `0640` | non-secret runtime settings |
| `database.cnf` | `root:dc24h`, `0640` | MariaDB Connector/C options and password |
| `scripts/` | `root:dc24h`, `0750` | instance-local tools |
| `scripts/01-edit-hub-settings.sh` | `root:dc24h`, `0750` | settings wrapper |

The system account has this home and `/usr/sbin/nologin`. The root-owned files
are readable but not writable by the daemon.

The installed `dc24h.conf` is:

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

The adjacent credential file is a standard MariaDB option file:

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

The application validates exactly one `[client]` section and all seven options
before MariaDB Connector/C reads the file through its default-file API. It
rejects duplicate, unknown, missing or empty options, protocols other than
`tcp`, character sets other than `utf8mb4`, symlinks and unsafe modes. A
relative `database_config` must name a file beside `dc24h.conf`; it is resolved
against that file's directory rather than the caller's working directory.
Inline `database_*` options remain readable only for legacy migration and must
not be mixed with `database_config`.

## Database and configuration migration for v0.0.10

v0.0.10 adds no application table or setting seed. The installer reapplies the
complete idempotent schema, extends the append-oriented moderation constraint
with `host`, and retains the existing 30 settings:

```sql
ALTER TABLE accounts
    MODIFY COLUMN password_hash VARCHAR(255) NULL;

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS kick_protect_class SMALLINT NOT NULL DEFAULT -2,
    ADD COLUMN IF NOT EXISTS hide_share BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS hide_operator_key BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS hide_from_class SMALLINT NOT NULL DEFAULT -1,
    ADD COLUMN IF NOT EXISTS account_note TEXT NULL;

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS registered_by VARCHAR(64) NULL,
    ADD COLUMN IF NOT EXISTS password_change_required BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP NULL,
    ADD COLUMN IF NOT EXISTS last_logout_at TIMESTAMP NULL,
    ADD COLUMN IF NOT EXISTS login_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR(45) NULL,
    ADD COLUMN IF NOT EXISTS auth_ip VARCHAR(45) NULL,
    ADD COLUMN IF NOT EXISTS email VARCHAR(254) NULL,
    ADD COLUMN IF NOT EXISTS public_note TEXT NULL,
    ADD COLUMN IF NOT EXISTS hide_kick BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS hide_kick_through_class SMALLINT NOT NULL DEFAULT -2;

CREATE TABLE IF NOT EXISTS user_timed_policies (
    account_id BIGINT UNSIGNED NOT NULL,
    policy_key VARCHAR(32) NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    PRIMARY KEY (account_id, policy_key),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS moderation_entries (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    action_type VARCHAR(8) NOT NULL,
    target_type VARCHAR(16) NOT NULL,
    target_value VARCHAR(255) NOT NULL,
    secondary_value VARCHAR(255) NOT NULL DEFAULT '',
    reason VARCHAR(1000) NOT NULL,
    created_by VARCHAR(64) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at TIMESTAMP(6) NULL,
    revoked_at TIMESTAMP(6) NULL,
    revoked_by VARCHAR(64) NULL,
    revoke_reason VARCHAR(1000) NULL,
    INDEX idx_moderation_active (revoked_at, expires_at, action_type),
    INDEX idx_moderation_target
        (target_type, target_value, revoked_at, expires_at),
    INDEX idx_moderation_secondary
        (target_type, secondary_value, revoked_at, expires_at),
    INDEX idx_moderation_action (action_type, id),
    CONSTRAINT chk_moderation_action
        CHECK (action_type IN ('kick', 'ban')),
    CONSTRAINT chk_moderation_target
        CHECK (target_type IN
            ('identity', 'nick', 'cid', 'ip', 'range', 'prefix', 'share'))
);

-- The complete idempotent seed list contains 30 validated rows.
INSERT IGNORE INTO settings(setting_key, setting_value) VALUES
    ('key.kicks', '300'),
    ('key.bans', '31536000'),
    ('key.class.permission.register.difference', '2'),
    ('key.nick.length.minimum', '3'),
    ('key.user.autoreg.class', '-1'),
    ('key.user.password.initial.timeout', '300');
```

Both the application schema bootstrap and `sql/schema.sql` apply this shape.
Existing non-NULL password hashes, accounts, policies, moderation history and
setting values are preserved.

For runtime configuration migration, the installer chooses the first available
source in this order:

1. `/var/lib/dc24h.eu/dc24h.eu/dc24h.conf`;
2. legacy `/etc/dc24h.eu/dc24h.conf`;
3. `config/dc24h.conf.example` from the checkout.

It preserves non-database lines, removes every old inline `database_*` or
existing `database_config` line, and appends one
`database_config=database.cnf`. If `database.cnf` already exists, it is copied
unchanged through the atomic staging step and its password is reused for the
database connection. Otherwise a legacy inline password is preserved; only a
clean installation without either source asks for a new secret. MariaDB user
creation is idempotent and reinstall does not alter or silently rotate an
existing account password. Local listener, locale, capacity and DNS settings
are preserved.

Only after `dc24h.service` is active does the installer replace the legacy
`/etc/dc24h.eu/dc24h.conf` path with a symlink to
`/var/lib/dc24h.eu/dc24h.eu/dc24h.conf`. The target is the non-secret runtime
file; `database.cnf` remains only in the protected hub home.

## Local database-backed settings administration

Run the instance wrapper as root and always pass the canonical hub home:

```bash
DC24H_HUB_HOME=/var/lib/dc24h.eu/dc24h.eu
DC24H_SETTINGS_TOOL="${DC24H_HUB_HOME}/scripts/01-edit-hub-settings.sh"

sudo "${DC24H_SETTINGS_TOOL}" "${DC24H_HUB_HOME}" list
sudo "${DC24H_SETTINGS_TOOL}" "${DC24H_HUB_HOME}" get key.kicks
sudo "${DC24H_SETTINGS_TOOL}" "${DC24H_HUB_HOME}" set key.kicks 600
sudo "${DC24H_SETTINGS_TOOL}" "${DC24H_HUB_HOME}" set key.nick.prefix ''
sudo "${DC24H_SETTINGS_TOOL}" "${DC24H_HUB_HOME}" check
```

The shell script validates root execution, an existing non-symlink absolute
path, one safe direct child of `/var/lib/dc24h.eu`, command arity and the
presence of `/usr/local/bin/dc24h-settings`. It then delegates without reading
`database.cnf` or invoking the MariaDB command-line client.

The compiled tool repeats the canonical path, owner and mode checks, connects
through `Config` and MariaDB Connector/C, and provides only:

- `list` — prints all 30 canonical rows as sorted `key=value` lines;
- `get KEY` — prints one canonical row; the historical timeout alias resolves
  to `key.user.password.initial.timeout`;
- `set KEY VALUE` — normalizes the value and prints the stored canonical value;
- `check` — prints `OK: 30 canonical hub settings are valid` only after the
  complete snapshot and cross-setting invariants pass.

`set` starts a transaction, locks the complete setting selection using
`SELECT ... FOR UPDATE`, validates the candidate snapshot, performs the upsert
and commits. Unknown keys, malformed values, a missing/extra canonical row,
`key.kicks > key.bans` or
`key.nick.length.minimum > key.nick.length.maximum` fail and roll back. There
is no raw-SQL or delete operation. A database-backed change is visible on the
next relevant hub lookup; editing either configuration file requires
`systemctl restart dc24h.service`.

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

Show all registered Operator-class users in the requesting client's private hub response:

`!set key.user.info.userlist.class=[3]`

Use `!set key.user.info.userlist.class=[]` for the default Regular class 0. The result includes disabled accounts and marks enabled/password state.

Additional account operations:

```text
!set key.user.change.username.password=[alice.NewStrongPassword]
!set key.user.change.username.password=[alice.]
+passwd NewStrongPassword
!set key.user.remove.username=[alice]
!set key.user.disable.username=[alice]
!set key.user.enable.username=[alice]
!set key.user.change.username.class=[alice.3]
!set key.user.change.username.class.temp=[alice.5]
!set key.user.info.username=[alice]
```

The empty nickname-password resets the hash; `+passwd` assigns it once for the current local nickname. A temporary class disappears after hub restart and cannot exceed Admin (5). The final enabled Master cannot be removed, disabled or demoted.

Online session queries:

```text
!set key.user.info.ip.hostname.username=[alice]
!set key.user.info.hostname.username=[alice]
!set key.user.info.userlist.ip=[192.0.2.10]
!set key.user.info.userlist.iprange=[192.0.2.1-192.0.2.254]
!set key.user.info.userlist.subnet=[192.0.2.0/24]
```

Set `dns_lookup=1` in
`/var/lib/dc24h.eu/dc24h.eu/dc24h.conf` only if reverse DNS is desired, then
restart the service. Default is `0`.

## Moderation examples

```text
!set key.user.disconnect.username=[alice]
!set key.user.kick.username=[alice]
!set key.kicks=[300]
!set key.bans=[31536000]
!set key.kicks.add=[alice|Rule violation]
!set key.kicks.add=[alice|2h|Repeated rule violation]
!set key.kicks.info=[41]
!set key.kicks.list=[20]
!set key.kicks.remove=[41|Kick entered in error]
!set key.bans.add=[nick|alice|2w|Repeated abuse]
!set key.bans.add=[cid|W6AIUW3CLDF6OGHNVE4JPDDJ2P74IWRCF2O36TA|permanent|Identity abuse]
!set key.bans.add=[ip|192.0.2.10|2d|Address abuse]
!set key.bans.add=[range|192.0.2.0/24|1M|Network abuse]
!set key.bans.add=[host|client.example.net|2d|Host abuse]
!set key.bans.add=[host|*.example.net|1w|Domain abuse]
!set key.bans.add=[prefix|bot-|1y|Automated clients]
!set key.bans.add=[share|4096|1h|Exact-share test]
!set key.bans.info=[42]
!set key.bans.list=[20]
!set key.bans.remove=[42|Appeal accepted]
!set key.user.protect.username.class=[alice.4]
!set key.user.hide.share.username=[alice.1]
!set key.user.hide.operator.username=[alice.1]
!set key.user.note.username=[alice.Trusted local operator]
!set key.user.self.hide.class=[3]
!set key.user.restrict.gag.username.time=[alice]
!set key.user.restrict.gag.username.time=[alice.12h]
!set key.user.restrict.gag.remove.username=[alice]
!set key.user.grant.opchat.username.time=[alice.7d]
!set key.user.grant.opchat.remove.username=[alice]
!opchat private operator message
```

All moderation policy, restriction and privilege keys are listed with defaults
in `docs/dc24h.eu-v0.0.08.md`; the v0.0.09 local database editor is specified in
`docs/dc24h.eu-v0.0.09.md`. The older account-policy duration keys retain
`m`/`h`/`d`; new kick/ban actions accept `s`, `m`, `h`, `d`, `w`, `M` and `y`
up to the `key.bans` ceiling. Reasons are mandatory and use `|` separators.

Passwords may contain dots; the parser consumes only the required leading separators.

## Password and RBAC checks

New password writes are stored as tagged `md5$…` values by compatibility
requirement. Existing tagged PBKDF2-SHA256 hashes continue to verify. MD5 is
not a secure modern password-storage choice; use explicit PBKDF2 generation for
production accounts until the project adopts a memory-hard default.

Every parsed command is authorized before execution. Operator (3) can perform
bounded registration, view protected account/moderation information and
moderate live sessions, Admin (5) can manage accounts and bans, and Master (10)
is required for class changes and global hub settings. Unknown commands have
no implicit permission.

Hostname bans use reverse DNS even when ordinary operator DNS queries are
disabled. PTR data is not authenticated: pair `host` bans with `ip` or `range`
targets when the boundary must be reliable.

## Service operation

```bash
sudo systemctl status dc24h.service
sudo systemctl restart dc24h.service
sudo journalctl -u dc24h.service -f
```

## Manual build and test

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libmariadb-dev \
  libgcrypt20-dev shellcheck

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## ncdc ADC connection test

Install the Debian 13 client, start the hub, and create a different private
session directory for every client:

```bash
sudo apt-get install -y ncdc
umask 077
MASTER_SESSION_DIR="$(mktemp -d /tmp/dc24h-ncdc-master.XXXXXX)"
GUEST_SESSION_DIR="$(mktemp -d /tmp/dc24h-ncdc-guest.XXXXXX)"

# Run each command as a non-root user in its own terminal.
ncdc -c "${MASTER_SESSION_DIR}" -n
ncdc -c "${GUEST_SESSION_DIR}" -n
```

In the first `ncdc` session:

```text
/set nick V010Master
/open dc24h-v010 adc://127.0.0.1:1511/
/say ncdc-v0.0.10-connection-test
```

In the second session, use a different persistent client identity:

```text
/set nick V010Guest
/open dc24h-v010 adc://127.0.0.1:1511/
/say ncdc-v0.0.10-connection-test
```

For reproduction, require both clients to complete ADC/TIGR identification,
see the hub description and user count, and receive the echoed marker. On an
isolated release database, also change a setting with
`01-edit-hub-settings.sh`, run `check`, verify its effect on a new connection,
restore the default, restart `dc24h.service`, reconnect and repeat the echo.
BASE/TIGR remain negotiated in SUP and TIGR PID/CID validation remains active.

The v0.0.10 release test uses Debian 13 and a real `ncdc` client. It must
complete ADC/TIGR identification and echo `ncdc-v0.0.10-connection-test`; after
a service restart it must reconnect and echo `ncdc-v0.0.10-after-restart`. The
v0.0.08 historical moderation validation remains recorded in its own release
documents.

## v0.0.10 validation record

- A clean Release build with warnings treated as errors completed; CTest,
  including ShellCheck, passed 8/8.
- MariaDB 11.8 schema application completed repeatedly; all 30 canonical
  setting rows remained present and `dc24h-settings ... check` passed.
- The moderation constraint accepted `host`. A live `localhost` host ban denied
  admission with ADC status 230 and was soft-revoked after the check.
- The systemd unit passed verification; `systemd-analyze security` reported
  exposure score `3.0`, and the installed v0.0.10 service remained active.
- Real `ncdc 1.23.1` completed ADC/TIGR identification, echoed the release
  marker, reconnected after restart and echoed the post-restart marker.
- Local forbidden-name, C++ pair, history and diff scans passed.
- Remote GitHub CI is the required final merge gate for PR #10.

## MariaDB

The application uses database `dc24h`, MariaDB Connector/C and `utf8mb4`.
Connector/C reads connection options from the protected standard
`database.cnf`; the service and settings CLI do not parse a password argument.
`accounts.user_class` stores the canonical numeric class.
`accounts.password_hash` may be `NULL` for a passwordless registration or after
an administrator reset.

## Network

The default ADC listener is TCP port `1511`. v0.0.10 remains IPv4-only.
Administrative `!set` paths remain restricted to `127.0.0.1`; `+passwd` and
explicitly enabled `+regme` are self-service exceptions. The separate local
settings CLI requires root and the protected hub-home contract.

## systemd

The service runs as the dedicated `dc24h` account, depends on MariaDB and
network-online, uses `en_US.UTF-8`, and restarts on failure. It sets `HOME` and
`WorkingDirectory` to `/var/lib/dc24h.eu/dc24h.eu`, starts with that home's
`dc24h.conf`, exposes the home through `ReadOnlyPaths`, has no capabilities and
retains the Debian 13 filesystem, device, namespace, kernel and runtime
hardening directives in `deploy/dc24h.service`.
