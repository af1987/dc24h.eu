<!--
instructions.md

v0.0.09:
  - require the protected per-hub home and split database configuration
  - define the root-only validated settings administration boundary
  - require complete 30-row validation and transaction-safe updates
  - require secret-safe clean install and credential-preserving reinstall

v0.0.08:
  - define persistent kick/ban key, target, audit and admission rules
  - require immutable ADC identity and live ncdc moderation validation

v0.0.07:
  - add policy-key, self-registration and account-metadata rules
  - require paired hub-settings implementation and tests

v0.0.06:
  - require timed moderation policy persistence and routing enforcement
  - define duration, protection, delegated privilege and ncdc test rules

v0.0.05:
  - require the complete registered-user administration key set
  - define temporary-class, final-Master and online-query invariants
  - add private loopback +passwd and optional DNS rules

v0.0.04:
  - raise active release to dc24h.eu-v0.0.04
  - require strict separation of add-password and change-password commands
  - document passwordless account creation and private class-listing behavior

v0.0.03:
  - define numeric user class and protected account-command rules
  - require password hashing and authorization tests for account mutations

v0.0.02:
  - bind ADC work to ADC 1.0.4 and require protocol/security tests

v0.0.01:
  - define mandatory project, versioning, ADR and paired C++ file rules

Author: gpt-5.6-sol
Date: 2026-08-21
-->

# Engineering instructions

These rules apply to `dc24h.eu-v0.0.09` and later changes.

## Mandatory baseline

- Hub name: `dc24h.eu`.
- Network protocol: ADC, currently ADC base specification 1.0.4.
- Text encoding: UTF-8; follow ADC escaping and never emit invalid UTF-8.
- Base language: US English.
- Runtime locale: `en_US.UTF-8`.
- Implementation language: C++20.
- Database: MariaDB using `utf8mb4`.
- Target OS: Debian 13.
- Service manager: systemd.
- Build system: CMake.
- Installed hub home: `/var/lib/dc24h.eu/dc24h.eu`.

## Protocol rules

- Treat socket input as untrusted.
- Respect the ADC state machine and message header syntax.
- Never forward client PID (`PD`) to other clients.
- Validate sender SID before routing B/D/E/F traffic.
- Keep the selected session hash stable for a connection.
- Reject duplicate named INF fields and post-NORMAL changes to `NI`, `ID`, `PD` or `SS`.
- Document every new ADC extension, feature FOURCC, supported state and security implication.
- Wire-compatibility changes require protocol tests.
- BASE/TIGR are mandatory in SUP negotiation and TIGR PID/CID verification; do not require clients to repeat them in BINF `SU`.

## Account and user-class rules

Canonical numeric classes are `-1, 0, 1, 2, 3, 4, 5, 10`. Other class values must be rejected.

Passwords must never be stored in plaintext. Password hashes use the existing salted PBKDF2-HMAC-SHA256 representation unless changed through a security ADR.

The command semantics are intentionally non-overlapping:

- `key.user.new.username.class.password=[username.class.password]` creates a user with an initial password.
- `key.user.new.username.class=[username.class]` creates a user without a password. `accounts.password_hash` must remain `NULL` until an explicit password-add command succeeds.
- `key.user.new.id.password=[id.password]` may set a password only when the selected enabled account has no password. It must never overwrite an existing password. If a password is already present, return an informational error and make no change.
- `key.user.change.id.password=[id.password]` replaces an existing password by database ID.
- `key.user.change.username.password=[username.password]` replaces an existing password by nickname; an empty password resets it to SQL `NULL`.
- `+passwd <password>` assigns only a missing password to the current enabled local account and must never overwrite an existing hash.
- `key.user.info.userlist.class=[class]` returns all registered users in the selected class through the private response; `[]` defaults to class `0`, and enabled/password states are marked.
- Account and moderation command forms remain canonical as documented in
  `docs/dc24h.eu-v0.0.08.md`; the v0.0.09 deployment and local settings
  interface are documented in `docs/dc24h.eu-v0.0.09.md`.
- Global policy values are validated before storage in MariaDB; unknown keys and malformed values are rejected.
- `+regme` must enforce configured class, nickname prefix, share and password rules.
- Passwordless accounts receive a finite first-password deadline.
- Removal, disabling or demotion of the final enabled Master (10) must be rejected.
- A temporary class is memory-only, disappears on restart and cannot exceed Admin (5).
- IP, range, subnet and hostname keys inspect active IPv4 sessions only and return private results.
- Reverse DNS is disabled by default and may run only when `dns_lookup=1`.
- Timed policies use MariaDB UTC expiry, accept `m`/`h`/`d` durations from 1 minute through 365 days, and must be enforced before ADC routing.
- `gag`, `no_chat`, `no_pm`, `no_search` and `no_download` block the command families defined in ADR-0010.
- Permanent/timed hidden share must remove BINF `SS`, `SF`, `SL`; hidden operator state clears ADC `CT` bits 4/8/16.
- Kick protection blocks actor classes less than or equal to its threshold. Non-punitive disconnect is a distinct operation.
- `key.kicks` is the default punitive-kick rejoin delay in seconds;
  `key.bans` is the maximum temporary moderation duration. Both are validated
  before storage and must satisfy `key.kicks <= key.bans`.
- A punitive kick must persist its nickname/CID audit row before socket
  shutdown. A database failure must leave the target connected and return an
  error to the actor.
- Ban targets must be explicit (`nick`, `cid`, `ip`, `range`, `prefix` or
  `share`), normalized without user-supplied regular expressions and checked
  before ADC NORMAL. Address bans are also checked immediately after accept.
- Moderation reasons are mandatory printable UTF-8 and bounded to 1000 characters.
  Action, target, actor, creation, expiry and revocation metadata persist in
  MariaDB. Kick removal and unban are soft revocations and require their own
  reasons.
- Expired or revoked entries never deny admission. A failed MariaDB admission
  lookup fails closed. Ban information and lists remain private.
- A ban may not include the acting session or bypass existing class/kick
  protection for a matched online or registered nickname.
- Permanent bans and every target broader than an exact nickname require
  Master (10); Admin may create temporary exact-nickname bans within class
  protection.
- Delegated registration may create only Regular (0) or Registered (1) accounts.
- `!opchat` must remain private to Operator+ and active `opchat` grantees.

The live chat form uses the protected `!set ` prefix, for example `!set key.user.new.id.password=[5.StrongPassword]`.

Until ADC VERIFY (`GPA`/`PAS`) authenticates registered users, remote nicknames are not sufficient management authorization. Protected `!set` remains loopback-only; only the documented `+passwd` and `+regme` self-service paths may run remotely. Optional account IP binding narrows the admission boundary.

## Per-hub home and local settings rules

- The canonical installed instance is `/var/lib/dc24h.eu/dc24h.eu`; the text
  `nazwa-huba` is a placeholder for a validated instance-name segment and must
  never become a literal installation directory.
- `/var/lib/dc24h.eu` is `root:root` mode `0755`. The instance home and its
  `scripts/` directory are `root:dc24h` mode `0750`; `dc24h.conf` and
  `database.cnf` are `root:dc24h` mode `0640`; the installed wrapper is
  `root:dc24h` mode `0750`.
- The `dc24h` service account uses the instance path as its account home, keeps
  `/usr/sbin/nologin`, and must not have write access to the root-owned runtime
  files.
- The active `dc24h.conf` contains non-secret runtime options and exactly one
  `database_config=database.cnf` reference. New installations must not put
  inline database credentials in this file.
- A relative `database_config` is resolved against the directory containing
  `dc24h.conf`, must be a basename beside it, and must not be a symbolic link.
- `database.cnf` is a standard MariaDB option file read by Connector/C. It must
  have exactly one `[client]` section and define `protocol=tcp`, `host`, `port`,
  `database`, `user`, `password` and `default-character-set=utf8mb4` exactly
  once. Unknown sections/keys, duplicate or empty values, unsafe permissions
  and mixing with inline `database_*` keys must fail closed.
- The legacy inline database form may remain readable for migration, but the
  installed service and the local settings tool use the split configuration.
- Shell code must not `source` either configuration file. Database passwords
  must not be passed in command arguments, printed by administration commands
  or committed to the repository.
- A clean install may obtain the database password only from an interactive
  hidden prompt or an absolute root-owned mode-`0600` non-symlink regular file
  selected by `DC24H_DB_PASSWORD_FILE`. This variable contains a path, never the
  password value. Reject malformed files and unset the inherited environment
  variable immediately after copying its path.
- A reinstall reuses the existing `database.cnf` password; migration from the
  combined legacy configuration reuses its inline password. Supplying a new
  password file in either case must fail. Installation must not silently rotate
  the database account or issue `ALTER USER`; rotation is a separate explicit
  administrative workflow.
- Privileged scripts use `/bin/bash`, set a fixed system `PATH`, reject
  symlinked deployment/configuration inputs and stage sensitive output with
  root-only permissions.
- The installer order is Release build and CTest, MariaDB/schema application,
  atomic publication of `dc24h.conf` and `database.cnf`, validation with the
  just-built `dc24h-settings`, installation of those tested artifacts, and
  service restart. Only after the unit is active may the legacy
  `/etc/dc24h.eu/dc24h.conf` be atomically replaced by a symlink to the
  non-secret home runtime file.
- `01-edit-hub-settings.sh` requires root, canonicalizes `HUB_HOME`, limits it
  to one safe direct child of `/var/lib/dc24h.eu`, and delegates unchanged
  arguments to `/usr/local/bin/dc24h-settings`.
- The only local operations are `list`, `get KEY`, `set KEY VALUE` and `check`.
  Do not add arbitrary SQL or delete access without a new security ADR.
- `list`, `get` and `check` validate a complete snapshot of exactly 30 canonical
  settings. `key.account.password.setup.timeout` remains only a compatibility
  alias for `key.user.password.initial.timeout`.
- `set` must reuse `normalize_hub_setting()`, lock the complete selected
  snapshot using a MariaDB transaction and `FOR UPDATE`, enforce
  `key.kicks <= key.bans` and
  `key.nick.length.minimum <= key.nick.length.maximum`, and commit or roll back
  without leaving a partial update.
- Database-backed setting updates are consumed on the next relevant settings
  lookup. Changes to `dc24h.conf` or `database.cnf` require a service restart.

## File history rule

Every human-maintained source, configuration, deployment, SQL and documentation file must contain a file-level history header with filename, current project version, a concise description of additions/changes, author and date.

For C++ use valid C/C++ comments. The project may use a visual declaration separator such as `// ----------------------------------// DECLARATION //--`; never paste comment syntax that makes the target language invalid.

## C++ pair rule

Creating a `*.cpp` file requires creating the matching `*.hpp` file in the same change, and creating a `*.hpp` file requires the matching `*.cpp`. Matching basenames are mandatory for production and test C++ files.

## Version rule

A user-visible functional change must:

1. raise the program version;
2. update `src/version.cpp` and `src/version.hpp`;
3. update `VERSION` and CMake project version;
4. update release identifiers in deployment/documentation descriptions;
5. add a section to `docs/changelog.md`;
6. add/update `docs/dc24h.eu-vX.Y.Z.md`;
7. update affected file-history headers.

`VERSION` is the intentional exception: it remains a single machine-readable
semantic-version line. Its history and provenance live in `src/version.*`, the
release manifest and `docs/changelog.md`.

## ADR rule

Changes to architecture, protocol strategy, concurrency, persistence, deployment, security boundary or compatibility policy require an ADR in `docs/adr/*.md`.

Each ADR contains Title, Status, Date, Author, Context, Decision, Consequences and Alternatives considered. A newer ADR must explicitly identify any earlier decision it supersedes in whole or in part.

## Validation rule

Before publishing a PR:

- configure CMake against the Debian 13 dependency set;
- build with project warning flags;
- run CTest;
- run shell syntax and ShellCheck checks for `install.sh` and
  `01-edit-hub-settings.sh`;
- test strict split-config parsing, including duplicate, incomplete, mixed,
  over-permissive, parent-path and symlinked inputs;
- against isolated MariaDB, require exactly 30 settings and test local
  `list`, `get`, `set` and `check`, invalid values and both cross-key invariants;
- run a clean install and at least one reinstall on Debian 13; verify the
  account home, ownership, modes, atomic configuration publication, preserved
  runtime options and password reuse without rotation;
- review the final PR diff for accidental secret/password disclosure;
- document completed checks and any unverified environment-dependent checks in
  the PR;
- run a real ADC connection and public-message echo test with Debian 13 `ncdc`
  using a separate `-c` session directory for every client when connection,
  protocol, configuration or deployment behavior changes.
- for kick/ban changes, run two isolated `ncdc` clients and verify immediate
  denial, expiry or soft-unban recovery, and persistence across a hub restart.
- apply `sql/schema.sql` twice against an isolated MariaDB instance and verify
  the runtime schema bootstrap represents the same tables, indexes and seeds.

## Pull request rule

Work branches from `main` using `agent/<release-or-purpose>` and targets `main`. The PR description states scope, behavior changes, validation and known limitations.
