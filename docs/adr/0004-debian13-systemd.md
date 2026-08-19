<!--
0004-debian13-systemd.md

v0.0.01:
  - choose Debian 13 and systemd deployment model

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# ADR-0004 — Debian 13 and systemd

- Status: Accepted
- Date: 2026-08-19
- Author: gpt-5.6-sol

## Context

The hub needs a single supported production OS baseline and deterministic service lifecycle.

## Decision

Target Debian 13 and manage dc24h.eu with systemd. Run the daemon as a dedicated non-login user and apply basic systemd hardening.

## Consequences

Install and operational documentation can be specific and reproducible. Other distributions are unsupported until separately validated.

## Alternatives considered

SysV init, containers-only deployment and multi-distribution support were deferred because systemd on Debian 13 is the required baseline.
