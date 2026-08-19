<!--
architecture.md

v0.0.01:
  - define initial ADC hub architecture, trust boundaries and modules

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# Architecture — dc24h.eu-v0.0.01

## Goals

`dc24h.eu` is a Direct Connect hub implemented in C++ for the ADC protocol. Version `0.0.01` establishes a small, reviewable core that can be extended without mixing transport, protocol, persistence and operating-system concerns.

## Runtime view

1. systemd starts `/usr/local/bin/dc24h.eu /etc/dc24h.eu/dc24h.conf`.
2. `main` loads configuration and selects the `en_US.UTF-8` locale.
3. `Database` connects to MariaDB and ensures the initial schema exists.
4. `Server` binds the configured IPv4 TCP endpoint (default `0.0.0.0:1511`).
5. Each accepted connection receives a 20-bit, four-character Base32 session ID (SID).
6. Newline-framed messages are passed to `AdcProtocol`.
7. `AdcProtocol` rejects invalid UTF-8 and handles the v0.0.01 ADC BASE subset.
8. Connection lifecycle events are persisted to MariaDB.

## Modules

### `src/adc.*`
Protocol parsing policy, UTF-8 validation, ADC escaping, handshake response and routing decisions.

### `src/server.*`
TCP listener, connection lifecycle, SID generation, framing, worker threads, broadcasts and shutdown.

### `src/database.*`
MariaDB connection, `utf8mb4` selection, schema bootstrap and synchronized queries.

### `src/config.*`
Strict `key=value` configuration loading with explicit defaults.

### `src/version.*`
Single canonical runtime source for `0.0.01`, `dc24h.eu-v0.0.01`, author and creation date.

### `src/main.*`
Process startup, locale, signal handling and dependency wiring.

## Data model

- `connection_events`: operational connect/disconnect audit.
- `accounts`: reserved account model for future authentication.
- `settings`: persistent hub configuration values for future releases.

Passwords are never intended to be stored in plaintext. `accounts.password_hash` is reserved for a future password-authentication design.

## Protocol scope

v0.0.01 supports the foundation needed to evolve the hub:
- `HSUP` -> `ISUP`, `ISID`, `IINF`
- basic `BINF`
- basic `BMSG`
- basic `BSCH`
- basic `BRES`
- `BQUI`
- UTF-8 validation
- ADC string escaping for hub metadata

This is not yet a complete implementation of all ADC states, message contexts or extensions.

## Concurrency

The listener uses one worker thread per accepted client. Shared client state and the MariaDB connection are protected by mutexes. This is deliberately simple for the first version. A later ADR should be created before replacing this with an event-driven or coroutine model.

## Trust boundaries

Untrusted input begins at the TCP socket. Message size is capped, UTF-8 is validated, database text is escaped, and systemd runs the process as the dedicated `dc24h` user with hardening directives.

## Deployment

Target OS is Debian 13. `scripts/install.sh` installs build/runtime dependencies, configures the US UTF-8 locale, creates the MariaDB database/user, builds the project and enables `dc24h.service`.
