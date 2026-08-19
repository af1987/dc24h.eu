/*
    main.cpp

    v0.0.01:
        - load runtime configuration
        - initialize MariaDB and ADC server
        - handle SIGINT/SIGTERM for systemd shutdown
        - print dc24h.eu-v0.0.01 startup metadata

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#include "main.hpp"

#include "adc.hpp"
#include "config.hpp"
#include "database.hpp"
#include "server.hpp"
#include "version.hpp"

#include <atomic>
#include <csignal>
#include <exception>
#include <iostream>
#include <locale>
#include <string>

namespace {

std::atomic_bool stop_requested{false};

void handle_signal(int) {
    stop_requested.store(true);
}

}  // namespace

namespace dc24h {

int dc24h_main(int argc, char** argv) {
    const std::string config_path =
        argc >= 2 ? argv[1] : "/etc/dc24h.eu/dc24h.conf";

    if (argc > 2) {
        std::cerr << "Usage: dc24h.eu [config-file]\n";
        return 2;
    }

    try {
        const auto config = load_config(config_path);
        std::locale::global(std::locale(config.locale.c_str()));

        std::cout << release_name()
                  << " | author=" << project_author()
                  << " | date=" << project_date() << '\n';

        Database database(config);
        database.connect();
        database.initialize_schema();

        AdcProtocol protocol(config.hub_name, config.hub_description);
        Server server(config, protocol, database);

        std::signal(SIGINT, handle_signal);
        std::signal(SIGTERM, handle_signal);

        return server.run(stop_requested);
    } catch (const std::exception& ex) {
        std::cerr << "fatal: " << ex.what() << '\n';
        return 1;
    }
}

}  // namespace dc24h

int main(int argc, char** argv) {
    return dc24h::dc24h_main(argc, argv);
}
