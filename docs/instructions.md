<!--
instructions.md

v0.0.03:
  - raise active release examples to dc24h.eu-v0.0.03
  - define numeric user class and protected account-command rules
  - require password hashing and authorization tests for account mutations

v0.0.02:
  - bind ADC implementation work to the ADC 1.0.4 specification
  - require protocol/privacy/security changes to include tests and ADR updates
  - update active release examples to dc24h.eu-v0.0.02

v0.0.01:
  - define mandatory project, versioning, ADR and paired C++ file rules

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# Engineering instructions

These rules apply to `dc24h.eu-v0.0.03` and later changes.

## Mandatory baseline

- Network protocol: ADC, currently targeted at ADC base specification 1.0.4.
- Text encoding: UTF-8. Protocol implementations must follow ADC escaping and must not emit invalid UTF-8.
- Base language: US English.
- Runtime locale: `en_US.UTF-8`.
- Implementation language: C++.
- Database: MariaDB.
- Target OS: Debian 13.
- Service manager: systemd.
- Build system: CMake.
- C++ standard: C++20 unless changed by ADR.

## Protocol rules

- Treat socket input as untrusted.
- Respect the ADC state machine and message header syntax.
- Never forward client PID (`PD`) to other clients.
- Validate sender SID against the connection before routing B/D/E/F traffic.
- Keep the selected session hash stable for the connection.
- Any new ADC extension must document its feature FOURCC, supported commands/states and security implications.
- A change affecting ADC wire compatibility must add or update protocol tests.

## Account and user-class rules

The canonical numeric classes are `-1, 0, 1, 2, 3, 4, 5, 10`. Do not silently reinterpret other values.

Account passwords must never be stored in plaintext. New password storage or authentication code requires a security-focused ADR and tests.

Until ADC VERIFY (`GPA`/`PAS`) authenticates registered users, remote nicknames are not sufficient authorization for account mutations. The v0.0.03 `!set` write path stays loopback-only and requires Admin (5) or Master (10), except the explicitly documented first-Master bootstrap when the account table is empty.

## File history rule

Every human-maintained source, configuration, deployment, SQL and documentation file must contain a file-level history header. The header must include the filename, current project version, a short list of what was added or changed, author and date.

For C++ use a valid C/C++ block comment, for Markdown use an HTML comment, and for other formats use their native comment syntax. Do not paste a comment syntax that makes the file invalid.

## C++ pair rule

Creating a `*.cpp` file requires creating the matching `*.hpp` file in the same change. Creating a `*.hpp` file requires creating the matching `*.cpp` file. Keep matching basenames.

The rule applies to production and test C++ files.

## Version rule

A user-visible functional change must:

1. raise the program version;
2. update `src/version.cpp`;
3. update `VERSION`;
4. update descriptions that contain the release identifier;
5. add a section to `docs/changelog.md`;
6. add or update the corresponding release manifest `docs/dc24h.eu-vX.Y.Z.md`;
7. update affected file history headers.

## ADR rule

A change that alters architecture, protocol strategy, concurrency, persistence, deployment, security boundaries or compatibility policy requires an ADR in `docs/adr/*.md`.

Each ADR contains: Title, Status, Date, Author, Context, Decision, Consequences and Alternatives considered.

## Validation rule

Before publishing a PR:

- configure with CMake on the Debian 13 dependency set;
- build with the project warning flags;
- run CTest;
- document checks and known limitations in the PR.

## Pull request rule

Work is branched from `main` using `agent/<release-or-purpose>`. Pull requests target `main`. The PR description must state scope, impact, validation and known limitations.
