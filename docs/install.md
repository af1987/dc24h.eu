<!--
install.md

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

The build requires a C++20 compiler, CMake, pkg-config, MariaDB Connector/C development files, libgcrypt development files, MariaDB server and `en_US.UTF-8` locale support.

## Automated install

```bash
git clone https://github.com/af1987/dc24h.eu.git
cd dc24h.eu
git checkout agent/dc24h-v0.0.07
sudo DC24H_DB_PASSWORD='replace-with-a-strong-password' ./scripts/install.sh
```

The installer builds the daemon, applies `sql/schema.sql`, runs CTest, installs the systemd unit and starts `dc24h.service`.

## Database migration for v0.0.07

The installer applies `sql/schema.sql`. v0.0.07 adds hub settings, account binding/profile fields, password setup state and login telemetry while retaining all earlier idempotent migrations:

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

-- The complete idempotent seed list contains 28 validated rows.
INSERT IGNORE INTO settings(setting_key, setting_value) VALUES
    ('key.class.permission.register.difference', '2'),
    ('key.nick.length.minimum', '3'),
    ('key.user.autoreg.class', '-1'),
    ('key.user.password.initial.timeout', '300');
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

Set `dns_lookup=1` in `/etc/dc24h.eu/dc24h.conf` only if reverse DNS is desired, then restart the service. Default is `0`.

## Moderation examples

```text
!set key.user.disconnect.username=[alice]
!set key.user.kick.username=[alice]
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

All current policy, restriction and privilege keys are listed with defaults in `docs/dc24h.eu-v0.0.07.md`. Explicit moderation durations use `m`, `h` or `d` and range from `1m` to `365d`.

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

## ncdc ADC connection test

Install the Debian 13 client, start the hub, and connect to its ADC listener:

```bash
sudo apt-get install -y ncdc
ncdc -n
```

In `ncdc`:

```text
/open dc24h adc://127.0.0.1:1511/
/say ncdc-v0.0.07-connection-test
```

A successful test shows the hub description, the connected nickname/user count and the echoed chat line. v0.0.07 is validated with Debian `ncdc`. BASE/TIGR are negotiated in SUP; TIGR PID/CID validation remains active.

## MariaDB

The application uses database `dc24h`, MariaDB Connector/C and `utf8mb4`. `accounts.user_class` stores the canonical numeric class. `accounts.password_hash` may be `NULL` for a passwordless registration or after an administrator reset.

## Network

The default ADC listener is TCP port `1511`. v0.0.07 remains IPv4-only. Administrative `!set` paths remain restricted to `127.0.0.1`; `+passwd` and explicitly enabled `+regme` are self-service exceptions.

## systemd

The service runs as the dedicated `dc24h` account, depends on MariaDB and network-online, uses `en_US.UTF-8`, restarts on failure and retains the existing hardening directives.
