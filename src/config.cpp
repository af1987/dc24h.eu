/*
    config.cpp

    v0.0.05:
        - parse dns_lookup as a strict 0/1 configuration value

    v0.0.01:
        - implement key=value configuration parser
        - validate TCP/MariaDB ports and max client count
        - keep en_US.UTF-8 as baseline locale

    Author: gpt-5.6-sol
    Date: 2026-08-20
*/

#include "config.hpp"

#include <charconv>
#include <cctype>
#include <fstream>
#include <stdexcept>
#include <string_view>

namespace dc24h {
namespace {

std::string trim(std::string value) {
    const auto not_space = [](unsigned char c) { return !std::isspace(c); };
    while (!value.empty() && !not_space(static_cast<unsigned char>(value.front()))) {
        value.erase(value.begin());
    }
    while (!value.empty() && !not_space(static_cast<unsigned char>(value.back()))) {
        value.pop_back();
    }
    return value;
}

template <typename T>
T parse_integer(std::string_view text, const std::string& key) {
    T value{};
    const auto* begin = text.data();
    const auto* end = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(begin, end, value);
    if (ec != std::errc{} || ptr != end) {
        throw std::runtime_error("Invalid integer value for " + key);
    }
    return value;
}

}  // namespace

Config load_config(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("Unable to open configuration file: " + path);
    }

    Config config;
    std::string line;
    std::size_t line_number = 0;

    while (std::getline(input, line)) {
        ++line_number;
        line = trim(line);
        if (line.empty() || line.starts_with('#')) {
            continue;
        }

        const auto separator = line.find('=');
        if (separator == std::string::npos) {
            throw std::runtime_error("Invalid configuration line " + std::to_string(line_number));
        }

        const auto key = trim(line.substr(0, separator));
        const auto value = trim(line.substr(separator + 1));

        if (key == "hub_name") config.hub_name = value;
        else if (key == "hub_description") config.hub_description = value;
        else if (key == "listen_address") config.listen_address = value;
        else if (key == "listen_port") config.listen_port = parse_integer<std::uint16_t>(value, key);
        else if (key == "max_clients") config.max_clients = parse_integer<std::size_t>(value, key);
        else if (key == "locale") config.locale = value;
        else if (key == "dns_lookup") {
            if (value == "0") config.dns_lookup = false;
            else if (value == "1") config.dns_lookup = true;
            else throw std::runtime_error("dns_lookup must be 0 or 1");
        }
        else if (key == "database_host") config.database_host = value;
        else if (key == "database_port") config.database_port = parse_integer<std::uint16_t>(value, key);
        else if (key == "database_name") config.database_name = value;
        else if (key == "database_user") config.database_user = value;
        else if (key == "database_password") config.database_password = value;
        else throw std::runtime_error("Unknown configuration key: " + key);
    }

    if (config.listen_port == 0 || config.database_port == 0) {
        throw std::runtime_error("Ports must be in range 1..65535");
    }
    if (config.max_clients == 0) {
        throw std::runtime_error("max_clients must be greater than zero");
    }
    if (config.database_password.empty()) {
        throw std::runtime_error("database_password must not be empty");
    }

    return config;
}

}  // namespace dc24h
