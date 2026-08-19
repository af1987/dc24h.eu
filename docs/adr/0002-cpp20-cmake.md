<!--
0002-cpp20-cmake.md

v0.0.01:
  - choose C++20 and CMake build tooling

Author: gpt-5.6-sol
Date: 2026-08-19
-->

# ADR-0002 — C++20 and CMake

- Status: Accepted
- Date: 2026-08-19
- Author: gpt-5.6-sol

## Context

The hub requires systems-level networking, predictable performance and a portable build definition.

## Decision

Implement the daemon in C++20 and build it with CMake. Keep protocol, transport, configuration and persistence in separate paired .cpp/.hpp modules.

## Consequences

The project gains modern standard-library facilities and conventional Linux tooling. Compiler warnings are enabled. New C++ modules must follow the paired-file rule.

## Alternatives considered

C, Rust and Go were considered but rejected because the project requirement explicitly selects C++.
