<!--
architecture.md

v0.0.02:
  - add ADC 1.0.4 session-state architecture and TIGR identity validation
  - define sanitized INF state, user-list synchronization and B/D/E/F routing
  - add libgcrypt as the TIGR implementation dependency

v0.0.01:
  - define initial ADC hub architecture, trust boundaries and modules

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# Architecture — dc24h.eu-v0.0.02

## Goals

`dc24h.eu` is a Direct Connect hub implemented in C++20 for the ADC protocol. Version `0.0.02` strengthens the first bootstrap by making the client-hub login stateful and by enforcing the identity and routing rules needed for an ADC 1.0.4 BASE/TIGR profile.

## Runtime view

1. systemd starts `/usr/local/bin/dc24h.eu /etc/dc24h.eu/dc24h.conf`.
2. `main` loads configuration and selects `en_US.UTF-8`.
3. `Database` connects to MariaDB using `utf8mb4`.
4. `Server` binds the configured IPv4 TCP endpoint, default `0.0.0.0:1511`.
5. Each accepted connection receives a 20-bit, four-character Base32 SID.
6. Newline-framed messages are passed to an `AdcSession` owned by that connection.
7. `AdcProtocol` validates UTF-8, ADC escaping, FOURCC/header syntax and the current ADC state.
8. During PROTOCOL the hub requires `BASE` and `TIGR`, replies with `ISUP`, `ISID` and hub `IINF`, then moves to IDENTIFY.
9. During IDENTIFY the client must send `BINF` with its assigned SID, `ID`, `PD`, `NI` and `SU`.
10. `hash.*` decodes the PID, computes canonical Tiger/192 through libgcrypt `TIGER1`, compares it with CID, and `adc.*` removes `PD` before any broadcast.
11. The server merges sanitized INF fields into per-client state and sends the current user list to a newly identified client before broadcasting the new client INF.
12. NORMAL traffic is routed by ADC message type: B=broadcast, D=direct, E=echo, F=feature-filtered, H=hub-only.
13. Connection lifecycle events remain persisted to MariaDB.

## Modules

### `src/adc.*`

ADC 1.0.4 line validation, state transitions, SUP/TIGR negotiation, INF sanitization, sender-SID validation and routing decisions.

### `src/hash.*`

Strict unpadded ADC Base32 helpers and TIGR PID/CID verification. The implementation uses `GCRY_MD_TIGER1`, which provides the commonly used Tiger/192 output order.

### `src/server.*`

TCP listener, worker lifecycle, SID allocation, per-client protocol sessions, merged INF state, user-list synchronization, B/D/E/F routing and systemd-friendly shutdown.

### `src/database.*`

MariaDB connection, `utf8mb4` selection, schema bootstrap and synchronized queries.

### `src/config.*`

Strict `key=value` configuration loading with explicit defaults.

### `src/version.*`

Canonical runtime source for `0.0.02`, `dc24h.eu-v0.0.02`, author and date.

### `src/main.*`

Process startup, locale, signals and dependency wiring.

### `tests/adc_tests.*`

Focused regression tests for Base32/TIGR, login state transitions, PID privacy, peer IPv4 correction, direct routing and SID spoof rejection.

## Protocol profile

v0.0.02 intentionally advertises:

- `BASE`
- `TIGR`

The hub requires both from the connecting client. TIGR is the selected session hash. A client without a compatible hash receives ADC status `247` and is disconnected.

The implementation recognizes the ADC state order:

- PROTOCOL
- IDENTIFY
- NORMAL

VERIFY is reserved for a future registered-user authentication release because `GPA`/`PAS` is not implemented yet.

## INF trust boundary

The client PID is private input. The hub verifies `Tiger(decoded PID) == decoded CID`, then strips the `PD` field from the forwarded `BINF`. The client cannot choose another sender SID. An IPv4 `I4` of `0.0.0.0` is replaced with the connected peer address; a different explicit IPv4 address is rejected in this release.

## Routing

- `B*` is sent to all NORMAL clients, including the sender.
- `D*` is sent only to the target SID.
- `E*` is sent to the target SID and echoed to the sender.
- `F*` is sent only to clients whose current `SU` set satisfies all `+FEATURE` and none of the `-FEATURE` selectors.
- `H*` remains local to the hub and is not forwarded.

## Data model

- `connection_events`: operational connect/disconnect audit.
- `accounts`: reserved account model for future authentication.
- `settings`: persistent hub configuration values for future releases.

No plaintext password storage is introduced.

## Concurrency

The listener retains one worker thread per accepted client. Client routing/INF state is protected by `clients_mutex_`; the MariaDB connection is separately synchronized by `Database`.

This remains deliberately simple. Moving to an event loop, io_uring, coroutines or sharded client state requires a new ADR.

## Trust boundaries and known limits

Untrusted input begins at the TCP socket. v0.0.02 caps line size, validates RFC 3629 UTF-8 structure, validates ADC escapes and headers, rejects SID spoofing, verifies TIGR identity and prevents PID disclosure.

The code does not yet implement Unicode NFC normalization, registered-user `GPA`/`PAS`, permissions, bans, ADCS/TLS, IPv6 listening, anti-flood/rate limiting, all ADC extensions or production metrics. These are explicit future milestones rather than implicit claims of compatibility.

## Deployment

Target OS is Debian 13. `scripts/install.sh` installs build/runtime dependencies, including MariaDB development files and `libgcrypt20-dev`, configures the US UTF-8 locale, creates the MariaDB database/user, runs build/tests and enables `dc24h.service`.
