/*
    config_tests.hpp

    v0.0.12:
        - declare TLS, bounded-I/O and timeout configuration tests

    v0.0.11:
        - declare anti-abuse configuration regression coverage

    - split runtime/MariaDB configuration test entrypoint

        v0.0.09:
            - declare relative option-file and security validation tests

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#pragma once

namespace dc24h::tests {

int run_config_tests();

}  // namespace dc24h::tests
