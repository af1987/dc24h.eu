<!--
instructions.md

v0.0.01:
  - define mandatory project, versioning, ADR and paired C++ file rules

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# Engineering instructions

These rules apply to changes after `dc24h.eu-v0.0.01`.

## Mandatory baseline

- Network protocol: ADC.
- Text encoding: UTF-8.
- Base language: US English.
- Runtime locale: `en_US.UTF-8`.
- Implementation language: C++.
- Database: MariaDB.
- Target OS: Debian 13.
- Service manager: systemd.

## File history rule

Every human-maintained source, configuration, deployment, SQL and documentation file must contain a file-level history header. The header must include the filename, current project version, a short list of what was added or changed, author and date.

For C++ use a valid C/C++ block comment, for Markdown use an HTML comment, and for other formats use their native comment syntax. Do not paste a comment syntax that makes the file invalid.

## C++ pair rule

Creating a `*.cpp` file requires creating the matching `*.hpp` file in the same change. Creating a `*.hpp` file requires creating the matching `*.cpp` file. Keep matching basenames, for example `adc.cpp` + `adc.hpp`.

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

## Pull request rule

Work is branched from `main` using `agent/<release-or-purpose>`. Pull requests target `main`. The PR description must state scope, impact, validation and known limitations.
