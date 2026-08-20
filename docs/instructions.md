<!--
instructions.md

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
Date: 2026-08-20
-->

# Engineering instructions

These rules apply to `dc24h.eu-v0.0.04` and later changes.

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

## Protocol rules

- Treat socket input as untrusted.
- Respect the ADC state machine and message header syntax.
- Never forward client PID (`PD`) to other clients.
- Validate sender SID before routing B/D/E/F traffic.
- Keep the selected session hash stable for a connection.
- Document every new ADC extension, feature FOURCC, supported state and security implication.
- Wire-compatibility changes require protocol tests.

## Account and user-class rules

Canonical numeric classes are `-1, 0, 1, 2, 3, 4, 5, 10`. Other class values must be rejected.

Passwords must never be stored in plaintext. Password hashes use the existing salted PBKDF2-HMAC-SHA256 representation unless changed through a security ADR.

The command semantics are intentionally non-overlapping:

- `key.user.new.username.class.password=[username.class.password]` creates a user with an initial password.
- `key.user.new.username.class=[username.class]` creates a user without a password. `accounts.password_hash` must remain `NULL` until an explicit password-add command succeeds.
- `key.user.new.id.password=[id.password]` may set a password only when the selected enabled account has no password. It must never overwrite an existing password. If a password is already present, return an informational error and make no change.
- `key.user.change.id.password=[id.password]` is the only command that replaces an existing password by database ID.
- `key.user.info.userlist.class=[class]` returns all enabled users in the selected class through the hub-local private response and must not be broadcast.

The live chat form uses the protected `!set ` prefix, for example `!set key.user.new.id.password=[5.StrongPassword]`.

Until ADC VERIFY (`GPA`/`PAS`) authenticates registered users, remote nicknames are not sufficient authorization for management operations. The v0.0.04 command path remains loopback-only and requires Admin (5) or Master (10), except the documented first local Master bootstrap while no enabled account exists.

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

## ADR rule

Changes to architecture, protocol strategy, concurrency, persistence, deployment, security boundary or compatibility policy require an ADR in `docs/adr/*.md`.

Each ADR contains Title, Status, Date, Author, Context, Decision, Consequences and Alternatives considered. A newer ADR must explicitly identify any earlier decision it supersedes in whole or in part.

## Validation rule

Before publishing a PR:

- configure CMake against the Debian 13 dependency set;
- build with project warning flags;
- run CTest;
- review the final PR diff for accidental secret/password disclosure;
- document completed checks and any unverified environment-dependent checks in the PR.

## Pull request rule

Work branches from `main` using `agent/<release-or-purpose>` and targets `main`. The PR description states scope, behavior changes, validation and known limitations.
