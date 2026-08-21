<!--
0013-per-hub-home-and-settings-administration.md

v0.0.09:
  - choose a protected per-hub home and split Connector/C configuration
  - define the root-only validated database settings administration boundary
  - require complete row-locking transactions for setting changes
  - decide secure password acquisition, reuse and atomic install ordering

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# ADR-0013: Per-hub home and settings administration

## Status

Accepted

## Date

2026-08-21

## Author

`gpt-5.6-sol`

## Release

`dc24h.eu-v0.0.09`

## Context

The earlier service account used `/nonexistent` as its home and systemd loaded
one combined `/etc/dc24h.eu/dc24h.conf`. That file mixed normal hub/listener
options with the MariaDB password. It did not provide the requested
`/var/lib/dc24h.eu/<hub-name>` deployment boundary that an operator could pass
to one settings administration script.

The existing MariaDB `settings` table contains 30 canonical policy values. The
daemon validates values through `normalize_hub_setting()`, but an external raw
SQL editor could bypass ranges and the relational invariants between nickname
lengths and kick/ban durations. A separate process can also race a daemon or a
second administrator unless validation and update use database-level locking.

The design therefore needs one protected home, a database credential file that
MariaDB Connector/C understands directly, and a narrow root-only settings tool
that reuses the application configuration and database layers.

## Decision

1. Treat `nazwa-huba` as a placeholder for one validated instance-name segment,
   never as a literal directory. Install this hub at the exact canonical path
   `/var/lib/dc24h.eu/dc24h.eu`.
2. Make that path the home of the non-login `dc24h` system account. Keep the
   parent `root:root` mode `0755`; keep the hub home and `scripts/` as
   `root:dc24h` mode `0750`; keep both configuration files as `root:dc24h` mode
   `0640`; keep the wrapper as `root:dc24h` mode `0750`.
3. Configure systemd with the absolute hub-home `dc24h.conf`, set the same
   `HOME` and `WorkingDirectory`, retain the existing sandbox and add the hub
   home to `ReadOnlyPaths`.
4. Put hub, listener, locale, capacity and DNS options in `dc24h.conf`. The
   active file contains no inline credential and refers to the adjacent file
   through `database_config=database.cnf`.
5. Use a standard MariaDB option file with exactly one `[client]` section and
   exactly one each of `protocol`, `host`, `port`, `database`, `user`,
   `password` and `default-character-set`. Require `protocol=tcp` and
   `default-character-set=utf8mb4`.
6. Validate the option-file syntax, completeness, type, symlink status and safe
   mode before connecting. Resolve a relative filename beside `dc24h.conf`,
   reject relative parent components, and reject mixing `database_config` with
   inline `database_*` keys. Retain the older inline form only for migration
   compatibility.
7. Pass the validated canonical option-file path to MariaDB Connector/C through
   `MYSQL_READ_DEFAULT_FILE` and select `MYSQL_READ_DEFAULT_GROUP=client`.
   Neither the daemon nor settings tool invokes a MariaDB command-line client.
8. Install the paired C++ administration program as
   `/usr/local/bin/dc24h-settings`. Install
   `01-edit-hub-settings.sh` in the hub home's `scripts/` directory as the
   operator-facing entrypoint.
9. Require root in both layers. The wrapper canonicalizes the supplied absolute
   `HUB_HOME`, rejects symlinks/traversal and allows exactly one safe direct
   child of `/var/lib/dc24h.eu`. The C++ tool repeats that boundary plus exact
   owner/group/mode checks for the home and configuration files.
10. Expose only `list`, `get KEY`, `set KEY VALUE` and `check`. Do not expose an
    arbitrary SQL or delete interface. Do not print or accept the database
    credential in command arguments.
11. Require every read operation to validate a complete snapshot of exactly 30
    canonical settings. Normalize the historical
    `key.account.password.setup.timeout` alias to
    `key.user.password.initial.timeout`.
12. Implement `set` with `START TRANSACTION`, a deterministic full selection
    ending in `FOR UPDATE`, canonical normalization, complete candidate-snapshot
    validation, an upsert and `COMMIT`. Roll back every exception or invalid
    result. Enforce at least
    `key.kicks <= key.bans` and
    `key.nick.length.minimum <= key.nick.length.maximum` inside that locked
    transaction.
13. Consume database-backed changes on the next relevant settings lookup.
    Require a systemd restart for changes to `dc24h.conf` or `database.cnf`.
14. Make the installer migration-aware and repeatable. Preserve non-database
    runtime lines from the active home or legacy `/etc` configuration and
    rewrite the database reference to the split form.
15. On a clean install, accept a new password only through a hidden prompt or
    an absolute root-owned mode-`0600`, non-symlink file selected by
    `DC24H_DB_PASSWORD_FILE`; the environment contains only the path. On
    reinstall, reuse `database.cnf`, or reuse the legacy inline password during
    its first migration. Reject a new password file when a credential exists
    and do not silently rotate it or issue `ALTER USER`.
16. Use `/bin/bash` and a fixed `PATH` in privileged scripts. Order deployment
    as Release build/CTest, database/schema, atomic configuration publication,
    validation by the just-built settings tool, installation, installed-tool
    validation and restart. After the service is active, atomically replace the
    legacy `/etc/dc24h.eu/dc24h.conf` with a symlink to the non-secret home
    runtime file.

## Consequences

### Positive

- The installed hub has one explicit filesystem boundary shared by the account,
  service and administration interface.
- Operators can inspect the normal runtime file without exposing the database
  password stored in the adjacent protected file.
- Connector/C remains the only component that interprets connection options for
  an actual database connection.
- The wrapper is small and does not duplicate credential parsing, SQL or
  setting normalization in shell.
- Every local operation detects missing, extra or invalid setting rows before
  returning success.
- Database row locks coordinate updates across daemon and CLI connections, so a
  candidate cannot pass a stale cross-setting check and then commit an invalid
  pair.
- Root ownership and the systemd read-only path prevent the daemon from
  replacing its configuration or administration entrypoint.
- Reinstallation does not unexpectedly invalidate a deployed credential, and
  a clean-install secret is absent from process arguments and environment
  values.
- Testing precedes artifact installation, while staged configuration is
  validated before restart; the legacy path remains compatible without
  retaining a second secret-bearing file.

### Negative

- The application must strictly validate two configuration formats and preserve
  a limited legacy inline path during migration.
- The MariaDB password remains plaintext at rest; Unix ownership and mode are
  its confidentiality boundary.
- Root is required for even read-only `list`, `get` and `check` operations.
- Every `set` locks and validates all 30 canonical setting rows rather than only
  the selected key.
- `settings.updated_at` records time but no separate local actor, reason,
  previous value or rollback history.
- The application database identity retains schema privileges while runtime
  idempotent schema bootstrap remains enabled.
- One protected home does not by itself provide multiple simultaneous systemd
  instances; distinct instances still need separate ports, databases and units.
- Password rotation is deliberately outside the installer and requires a
  separate explicit, coordinated administrative procedure.

## Alternatives considered

### Keep the combined configuration under `/etc/dc24h.eu`

Rejected because it does not create the requested hub-specific home and
continues to mix a routinely inspected configuration with the database secret.

### Install a literal `nazwa-huba` directory

Rejected because that text denotes a variable path component. The requested hub
name is `dc24h.eu`, producing `/var/lib/dc24h.eu/dc24h.eu`.

### Source a shell credential file

Rejected because a configuration file would become executable root shell code.
The wrapper instead delegates to a C++ program, and Connector/C reads the
standard MariaDB option file.

### Pass the password directly in an environment variable

Rejected because process environments and shell invocation records can expose
the secret. An optional environment variable contains only the absolute path
to a root-owned mode-`0600` input file, and the inherited variable is unset
immediately after its path is copied.

### Rotate the password on every reinstall

Rejected because interruption between changing MariaDB and replacing
`database.cnf` can break service access, and routine code deployment should not
change an operational credential. Existing or migrated credentials are reused;
rotation is an explicit separate operation.

### Call the MariaDB CLI from the wrapper

Rejected because the script would need to interpret credentials, build SQL and
duplicate the C++ setting validator. It would also increase the risk of
password or quoting exposure.

### Offer an SQL console or delete command

Rejected because unrestricted SQL can bypass the canonical key allowlist,
exact 30-row contract, normalization and cross-key invariants. Removing seeded
rows also makes defaults implicit rather than auditable.

### Validate only the changed key

Rejected because nickname minimum/maximum and kick/ban limits are relational.
A locally valid value may make the complete snapshot invalid.

### Rely on the daemon's in-process mutex

Rejected because `dc24h-settings` uses another process and MariaDB connection.
`FOR UPDATE` inside one transaction supplies the required cross-process
serialization.

### Make the home writable by `dc24h`

Rejected because the service needs only read access to these files. Write access
would allow a compromised daemon to replace its own configuration or wrapper.

## Relationship to earlier decisions

This ADR extends ADR-0003's MariaDB persistence, ADR-0004's Debian 13/systemd
deployment and ADR-0011's validated MariaDB-backed policy model. It supersedes
only the deployment choices that use `/nonexistent` as the account home and a
combined `/etc/dc24h.eu/dc24h.conf` as the active installed configuration.
ADC, account authorization, moderation and the v0.0.08 admission decisions are
unchanged.

## Validation status

On Debian 13.6, the clean warnings-as-errors Release build completed and CTest,
including ShellCheck, passed 8/8. The installer completed repeated executions;
the final current-installer run supplied no new password and reused
`database.cnf` without silent rotation or secret-valued environment input.
Repeated schema application retained
exactly 30 settings. All four settings operations, invalid keys/ranges, both
relational invariants and 12 concurrent update attempts ended in a successful
final `check`.

The service was active, its unit passed verification and its systemd security
exposure score was `3.0`. A real Debian `ncdc 1.23.1` ADC/TIGR run completed
both the `ncdc-v0.0.09-connection-test` echo and the post-restart
`ncdc-v0.0.09-after-restart` reconnect/echo. Local forbidden-name, C++ pair and
secret scans passed. Remote GitHub CI is the required final merge gate for PR
#9; its result is verified on GitHub rather than inferred from local checks.
