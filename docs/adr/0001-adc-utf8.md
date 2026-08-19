<!--
0001-adc-utf8.md

v0.0.01:
  - choose ADC and UTF-8 as protocol/text baseline

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# ADR-0001 — ADC protocol and UTF-8 text

- Status: Accepted
- Date: 2026-08-19
- Author: gpt-5.6-sol

## Context

dc24h.eu is a new Direct Connect hub and needs one modern protocol baseline and one text encoding.

## Decision

Use ADC as the network protocol and UTF-8 for protocol text. v0.0.01 implements a deliberately small BASE foundation and grows compatibility through versioned changes.

## Consequences

The implementation can focus on ADC semantics without NMDC compatibility code. Invalid UTF-8 is rejected at the protocol boundary. Additional ADC extensions require explicit implementation and testing.

## Alternatives considered

NMDC-only and dual ADC/NMDC support were rejected for v0.0.01 because they increase parser and compatibility surface before the ADC core is mature.
