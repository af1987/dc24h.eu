/*
    config.hpp

    v0.0.01:
        - add hub, network, locale and MariaDB configuration model
        - add UTF-8 configuration loader interface

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#pragma once

#include <cstdint>
#include <string>

namespace dc24h {

struct Config {
    std::string hub_name{"dc24h.eu"};
    std::string hub_description{"dc24h.eu Direct Connect ADC Hub"};
    std::string listen_address{"0.0.0.0"};
    std::uint16_t listen_port{1511};
    std::size_t max_clients{1024};
    std::string locale{"en_US.UTF-8"};

    std::string database_host{"127.0.0.1"};
    std::uint16_t database_port{3306};
    std::string database_name{"dc24h"};
    std::string database_user{"dc24h"};
    std::string database_password;
};

Config load_config(const std::string& path);

}  // namespace dc24h
