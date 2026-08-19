<!--
0003-mariadb.md

v0.0.01:
  - choose MariaDB and utf8mb4 persistence

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# ADR-0003 — MariaDB persistence

- Status: Accepted
- Date: 2026-08-19
- Author: gpt-5.6-sol

## Context

Persistent hub accounts, settings and operational events require a relational store.

## Decision

Use MariaDB through Connector/C and store text using utf8mb4. v0.0.01 persists connection events and creates reserved account/settings tables.

## Consequences

Deployment requires MariaDB and libmariadb development files. Database access is serialized in v0.0.01; a pool can be introduced later with a new ADR.

## Alternatives considered

SQLite and PostgreSQL were not selected because the project requirement explicitly selects MariaDB.
