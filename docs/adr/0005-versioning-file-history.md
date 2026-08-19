<!--
0005-versioning-file-history.md

v0.0.01:
  - formalize release version and per-file history policy

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# ADR-0005 — Versioning and file history headers

- Status: Accepted
- Date: 2026-08-19
- Author: gpt-5.6-sol

## Context

The project requires every maintained file to explain what was added or changed and requires release descriptions to move with the program version.

## Decision

Use a canonical program version plus a release name of the form dc24h.eu-vX.Y.Z. Store concise version history in native comments at the top of maintained files and maintain a release manifest and changelog.

## Consequences

Changes are traceable even when individual files are viewed outside Git history. Every functional release update touches version metadata and affected file headers.

## Alternatives considered

Relying exclusively on Git history was rejected because it does not satisfy the explicit per-file description requirement.
