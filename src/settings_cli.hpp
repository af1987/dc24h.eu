/*
    settings_cli.hpp

    - local MariaDB-backed hub settings administration entrypoint

        v0.0.09:
            - declare list, get, set and full-snapshot check command handling
            - require the hub home directory as the administration boundary

    Author: gpt-5.6-sol
    Date: 2026-08-21
*/

// ----------------------------------// DECLARATION //--

#pragma once

namespace dc24h {

int settings_cli_main(int argc, char** argv);

}  // namespace dc24h
