/*
    config.hpp

    v0.0.12:
        - add TLS/ADCS, TLS-only, I/O limit and phase-timeout settings

    v0.0.11:
        - add validated anti-abuse and temporary-ban runtime settings

    v0.0.09:
        - add a separate MariaDB option-file path to the runtime model
        - keep legacy inline database keys available for safe migration

    v0.0.05:
        - add dns_lookup switch for optional reverse DNS in user queries

    v0.0.01:
        - add hub, network, locale and MariaDB configuration model
        - add UTF-8 configuration loader interface

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

#pragma once

#include "anti_abuse.hpp"
#include "io_limits.hpp"
#include "tls_transport.hpp"

#include <cstdint>
#include <string>

namespace dc24h {

struct SessionTimeouts {
    std::uint32_t Key{10};
    std::uint32_t ValidateNick{15};
    std::uint32_t Login{30};
    std::uint32_t MyINFO{30};
    std::uint32_t Password{30};
    std::uint32_t General{120};
};

struct Config {
    std::string hub_name{"dc24h.eu"};
    std::string hub_description{"dc24h.eu Direct Connect ADC Hub"};
    std::string listen_address{"0.0.0.0"};
    std::uint16_t listen_port{1511};
    std::size_t max_clients{1024};
    std::string locale{"en_US.UTF-8"};
    bool dns_lookup{false};
    AntiAbuseSettings anti_abuse;
    TlsSettings tls;
    IoLimits io_limits;
    SessionTimeouts timeout;

    std::string database_config_path;
    std::string database_host{"127.0.0.1"};
    std::uint16_t database_port{3306};
    std::string database_name{"dc24h"};
    std::string database_user{"dc24h"};
    std::string database_password;
};

Config load_config(const std::string& path);

}  // namespace dc24h
