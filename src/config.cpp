/*
    config.cpp

    v0.0.14:
        - load and validate the protected WebAdmin bearer-token file
        - parse loopback and bounded-request controls for same-port HTTP

    v0.0.13:
        - parse and bound protocol-flood rate/window/ban settings

    v0.0.12:
        - parse and validate TLS/ADCS, bounded buffers and phase timeouts
        - validate certificate/key file boundaries when TLS is enabled

    v0.0.11:
        - parse bounded password, IP, reconnect and clone protection settings

    v0.0.09:
        - load MariaDB credentials from a separate database.cnf file
        - resolve relative database config paths beside the hub config
        - reject mixed inline/external credentials and malformed option files

    v0.0.05:
        - parse dns_lookup as a strict 0/1 configuration value

    v0.0.01:
        - implement key=value configuration parser
        - validate TCP/MariaDB ports and max client count
        - keep en_US.UTF-8 as baseline locale

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

#include "config.hpp"

#include <charconv>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>

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

bool parse_boolean(std::string_view text, const std::string& key) {
    if (text == "0") return false;
    if (text == "1") return true;
    throw std::runtime_error(key + " must be 0 or 1");
}

void validate_tls_file(const std::string& configured,
                       const std::string& key,
                       bool private_file) {
    const std::filesystem::path path(configured);
    if (!path.is_absolute() || std::filesystem::is_symlink(
            std::filesystem::symlink_status(path)) ||
        !std::filesystem::is_regular_file(std::filesystem::status(path))) {
        throw std::runtime_error(
            key + " must be an absolute regular non-symlink file");
    }
    using perms = std::filesystem::perms;
    const auto permissions = std::filesystem::status(path).permissions();
    if ((permissions & (perms::group_write | perms::others_write)) !=
        perms::none) {
        throw std::runtime_error(key + " must not be group/world writable");
    }
    if (private_file &&
        (permissions & (perms::others_read | perms::others_exec)) !=
            perms::none) {
        throw std::runtime_error("tls_private_key must not be world-readable");
    }
}

std::string load_webadmin_token(const std::string& configured) {
    const std::filesystem::path path(configured);
    if (!path.is_absolute() ||
        std::filesystem::is_symlink(std::filesystem::symlink_status(path)) ||
        !std::filesystem::is_regular_file(std::filesystem::status(path))) {
        throw std::runtime_error(
            "webadmin_token_file must be an absolute regular non-symlink file");
    }
    using perms = std::filesystem::perms;
    const auto permissions = std::filesystem::status(path).permissions();
    const auto allowed = perms::owner_read | perms::owner_write;
    if ((permissions & perms::owner_read) == perms::none ||
        (permissions & ~allowed) != perms::none) {
        throw std::runtime_error(
            "webadmin_token_file permissions must be 0600 or stricter");
    }
    std::ifstream input(path);
    std::string token;
    std::string extra;
    if (!std::getline(input, token) || std::getline(input, extra) ||
        token.size() < 32U || token.size() > 128U) {
        throw std::runtime_error(
            "webadmin token must be one line containing 32..128 characters");
    }
    for (const unsigned char character : token) {
        if (character < 0x21U || character > 0x7eU) {
            throw std::runtime_error(
                "webadmin token must contain printable ASCII without spaces");
        }
    }
    return token;
}

std::pair<std::string, std::string> parse_assignment(
    std::string line,
    const std::filesystem::path& path,
    std::size_t line_number) {
    const auto separator = line.find('=');
    if (separator == std::string::npos) {
        throw std::runtime_error(
            "Invalid configuration line " + std::to_string(line_number) +
            " in " + path.string());
    }
    auto key = trim(line.substr(0, separator));
    auto value = trim(line.substr(separator + 1));
    if (key.empty()) {
        throw std::runtime_error(
            "Empty configuration key on line " +
            std::to_string(line_number) + " in " + path.string());
    }
    return {std::move(key), std::move(value)};
}

std::filesystem::path resolved_database_path(
    const std::filesystem::path& runtime_path,
    const std::string& configured_path) {
    std::filesystem::path database_path(configured_path);
    const bool relative = database_path.is_relative();
    if (relative && database_path.has_parent_path()) {
        throw std::runtime_error(
            "relative database_config must name a file beside dc24h.conf");
    }
    auto absolute_runtime = std::filesystem::absolute(runtime_path);
    std::error_code error;
    const auto canonical_runtime =
        std::filesystem::weakly_canonical(absolute_runtime, error);
    if (!error) absolute_runtime = canonical_runtime;
    const auto runtime_directory = absolute_runtime.parent_path();
    if (database_path.is_relative()) {
        database_path = runtime_directory / database_path;
    }
    database_path = database_path.lexically_normal();
    const auto link_status = std::filesystem::symlink_status(database_path);
    if (std::filesystem::is_symlink(link_status)) {
        throw std::runtime_error(
            "database_config must not be a symbolic link: " +
            database_path.string());
    }
    const auto file_status = std::filesystem::status(database_path);
    if (!std::filesystem::is_regular_file(file_status)) {
        throw std::runtime_error(
            "database_config is not a regular file: " +
            database_path.string());
    }
    const auto permissions = file_status.permissions();
    using perms = std::filesystem::perms;
    const auto allowed = perms::owner_read | perms::owner_write |
                         perms::group_read;
    if ((permissions & perms::owner_read) == perms::none ||
        (permissions & ~allowed) != perms::none) {
        throw std::runtime_error(
            "database_config permissions must be 0640 or stricter: " +
            database_path.string());
    }
    const auto canonical_database = std::filesystem::canonical(database_path);
    if (canonical_database.parent_path() != runtime_directory) {
        throw std::runtime_error(
            "database_config must be stored beside dc24h.conf");
    }
    return canonical_database;
}

void validate_database_config(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error(
            "Unable to open database configuration file: " + path.string());
    }

    const std::set<std::string> required{
        "protocol", "host", "port", "database", "user", "password",
        "default-character-set"};
    std::set<std::string> seen;
    std::string line;
    std::size_t line_number = 0;
    bool client_section = false;
    while (std::getline(input, line)) {
        ++line_number;
        line = trim(line);
        if (line.empty() || line.starts_with('#') || line.starts_with(';')) {
            continue;
        }
        if (line.front() == '[' && line.back() == ']') {
            if (line != "[client]" || client_section) {
                throw std::runtime_error(
                    "database_config must contain one [client] section");
            }
            client_section = true;
            continue;
        }
        if (!client_section) {
            throw std::runtime_error(
                "database options must follow the [client] section");
        }
        auto [key, value] = parse_assignment(line, path, line_number);
        if (!required.contains(key)) {
            throw std::runtime_error(
                "Unknown database configuration key: " + key);
        }
        if (!seen.insert(key).second) {
            throw std::runtime_error(
                "Duplicate database configuration key: " + key);
        }
        if (value.empty()) {
            throw std::runtime_error(
                "Empty database configuration value for: " + key);
        }
        if (key == "port" && parse_integer<std::uint16_t>(value, key) == 0U) {
            throw std::runtime_error("database port must be in range 1..65535");
        }
        if (key == "protocol" && value != "tcp") {
            throw std::runtime_error("database protocol must be tcp");
        }
        if (key == "default-character-set" && value != "utf8mb4") {
            throw std::runtime_error(
                "database default-character-set must be utf8mb4");
        }
    }
    if (!client_section || seen != required) {
        throw std::runtime_error(
            "database_config must define protocol, host, port, database, user, "
            "password and default-character-set exactly once");
    }
}

}  // namespace

Config load_config(const std::string& path) {
    const std::filesystem::path runtime_path(path);
    std::ifstream input(runtime_path);
    if (!input) {
        throw std::runtime_error("Unable to open configuration file: " + path);
    }

    Config config;
    std::set<std::string> seen;
    bool inline_database_setting = false;
    std::string line;
    std::size_t line_number = 0;

    while (std::getline(input, line)) {
        ++line_number;
        line = trim(line);
        if (line.empty() || line.starts_with('#')) {
            continue;
        }

        auto [key, value] = parse_assignment(line, runtime_path, line_number);
        if (!seen.insert(key).second) {
            throw std::runtime_error("Duplicate configuration key: " + key);
        }

        if (key == "hub_name") config.hub_name = value;
        else if (key == "hub_description") config.hub_description = value;
        else if (key == "listen_address") config.listen_address = value;
        else if (key == "listen_port") config.listen_port = parse_integer<std::uint16_t>(value, key);
        else if (key == "max_clients") config.max_clients = parse_integer<std::size_t>(value, key);
        else if (key == "locale") config.locale = value;
        else if (key == "dns_lookup") config.dns_lookup = parse_boolean(value, key);
        else if (key == "pwd_tmpban") config.anti_abuse.pwd_tmpban = parse_integer<std::uint32_t>(value, key);
        else if (key == "password_failure_limit") config.anti_abuse.password_failure_limit = parse_integer<std::uint32_t>(value, key);
        else if (key == "password_failure_window") config.anti_abuse.password_failure_window = parse_integer<std::uint32_t>(value, key);
        else if (key == "max_users_from_ip") config.anti_abuse.max_users_from_ip = parse_integer<std::size_t>(value, key);
        else if (key == "reconnect_min_interval") config.anti_abuse.reconnect_min_interval = parse_integer<std::uint32_t>(value, key);
        else if (key == "clone_detect_count") config.anti_abuse.clone_detect_count = parse_integer<std::size_t>(value, key);
        else if (key == "clone_det_tban_time") config.anti_abuse.clone_det_tban_time = parse_integer<std::uint32_t>(value, key);
        else if (key == "clone_ip_tban_time") config.anti_abuse.clone_ip_tban_time = parse_integer<std::uint32_t>(value, key);
        else if (key == "protocol_flood_limit") config.anti_abuse.protocol_flood_limit = parse_integer<std::size_t>(value, key);
        else if (key == "protocol_flood_window") config.anti_abuse.protocol_flood_window = parse_integer<std::uint32_t>(value, key);
        else if (key == "protocol_flood_tmpban") config.anti_abuse.protocol_flood_tmpban = parse_integer<std::uint32_t>(value, key);
        else if (key == "tls_enabled") config.tls.enabled = parse_boolean(value, key);
        else if (key == "tls_only_mode") config.tls.tls_only_mode = parse_boolean(value, key);
        else if (key == "tls_port") config.tls.port = parse_integer<std::uint16_t>(value, key);
        else if (key == "tls_certificate") config.tls.certificate = value;
        else if (key == "tls_private_key") config.tls.private_key = value;
        else if (key == "tls_min_version") config.tls.minimum_version = value;
        else if (key == "tls_handshake_timeout") config.tls.handshake_timeout_seconds = parse_integer<std::uint32_t>(value, key);
        else if (key == "mLineSizeMax") config.io_limits.mLineSizeMax = parse_integer<std::size_t>(value, key);
        else if (key == "max_outbuf_size") config.io_limits.max_outbuf_size = parse_integer<std::size_t>(value, key);
        else if (key == "timeout_key") config.timeout.Key = parse_integer<std::uint32_t>(value, key);
        else if (key == "timeout_validate_nick") config.timeout.ValidateNick = parse_integer<std::uint32_t>(value, key);
        else if (key == "timeout_login") config.timeout.Login = parse_integer<std::uint32_t>(value, key);
        else if (key == "timeout_myinfo") config.timeout.MyINFO = parse_integer<std::uint32_t>(value, key);
        else if (key == "timeout_password") config.timeout.Password = parse_integer<std::uint32_t>(value, key);
        else if (key == "timeout_general") config.timeout.General = parse_integer<std::uint32_t>(value, key);
        else if (key == "webadmin_enabled") config.webadmin.enabled = parse_boolean(value, key);
        else if (key == "webadmin_loopback_only") config.webadmin.loopback_only = parse_boolean(value, key);
        else if (key == "webadmin_token_file") config.webadmin.token_file = value;
        else if (key == "webadmin_max_request_size") config.webadmin.maximum_request_size = parse_integer<std::size_t>(value, key);
        else if (key == "database_config") {
            if (value.empty()) {
                throw std::runtime_error("database_config must not be empty");
            }
            config.database_config_path = value;
        }
        else if (key == "database_host") {
            inline_database_setting = true;
            config.database_host = value;
        }
        else if (key == "database_port") {
            inline_database_setting = true;
            config.database_port = parse_integer<std::uint16_t>(value, key);
        }
        else if (key == "database_name") {
            inline_database_setting = true;
            config.database_name = value;
        }
        else if (key == "database_user") {
            inline_database_setting = true;
            config.database_user = value;
        }
        else if (key == "database_password") {
            inline_database_setting = true;
            config.database_password = value;
        }
        else throw std::runtime_error("Unknown configuration key: " + key);
    }

    if (!config.database_config_path.empty()) {
        if (inline_database_setting) {
            throw std::runtime_error(
                "Do not mix database_config with inline database settings");
        }
        const auto database_path = resolved_database_path(
            runtime_path, config.database_config_path);
        config.database_config_path = database_path.string();
        validate_database_config(database_path);
    }

    if (config.listen_port == 0 || config.database_port == 0) {
        throw std::runtime_error("Ports must be in range 1..65535");
    }
    std::string tls_error;
    if (!valid_tls_settings(config.tls, tls_error)) {
        throw std::runtime_error(tls_error);
    }
    if (config.tls.enabled) {
        if (config.tls.port == config.listen_port && !config.tls.tls_only_mode) {
            throw std::runtime_error(
                "tls_port and listen_port must differ unless tls_only_mode=1");
        }
        validate_tls_file(config.tls.certificate, "tls_certificate", false);
        validate_tls_file(config.tls.private_key, "tls_private_key", true);
    }
    if (!valid_io_limits(config.io_limits)) {
        throw std::runtime_error(
            "mLineSizeMax/max_outbuf_size violate hard I/O limits");
    }
    const auto valid_timeout = [](std::uint32_t value) {
        return value > 0U && value <= 3600U;
    };
    if (!valid_timeout(config.timeout.Key) ||
        !valid_timeout(config.timeout.ValidateNick) ||
        !valid_timeout(config.timeout.Login) ||
        !valid_timeout(config.timeout.MyINFO) ||
        !valid_timeout(config.timeout.Password) ||
        !valid_timeout(config.timeout.General) ||
        config.timeout.Login < config.timeout.Key ||
        config.timeout.General < config.timeout.Login) {
        throw std::runtime_error("invalid session timeout configuration");
    }
    if (config.max_clients == 0) {
        throw std::runtime_error("max_clients must be greater than zero");
    }
    if (config.webadmin.maximum_request_size < 4096U ||
        config.webadmin.maximum_request_size > 65536U) {
        throw std::runtime_error(
            "webadmin_max_request_size must be in range 4096..65536");
    }
    if (config.webadmin.enabled) {
        if (config.webadmin.token_file.empty()) {
            throw std::runtime_error(
                "webadmin_token_file is required when WebAdmin is enabled");
        }
        config.webadmin.token =
            load_webadmin_token(config.webadmin.token_file);
    }
    if (config.anti_abuse.pwd_tmpban == 0U ||
        config.anti_abuse.pwd_tmpban > 86400U ||
        config.anti_abuse.password_failure_limit < 2U ||
        config.anti_abuse.password_failure_limit > 100U ||
        config.anti_abuse.password_failure_window == 0U ||
        config.anti_abuse.password_failure_window > 86400U ||
        config.anti_abuse.max_users_from_ip == 0U ||
        config.anti_abuse.max_users_from_ip > 65535U ||
        config.anti_abuse.reconnect_min_interval == 0U ||
        config.anti_abuse.reconnect_min_interval > 3600U ||
        config.anti_abuse.clone_detect_count > 65535U ||
        config.anti_abuse.clone_det_tban_time == 0U ||
        config.anti_abuse.clone_det_tban_time > 86400U ||
        config.anti_abuse.clone_ip_tban_time == 0U ||
        config.anti_abuse.clone_ip_tban_time > 86400U ||
        config.anti_abuse.protocol_flood_limit < 2U ||
        config.anti_abuse.protocol_flood_limit > 100000U ||
        config.anti_abuse.protocol_flood_window == 0U ||
        config.anti_abuse.protocol_flood_window > 3600U ||
        config.anti_abuse.protocol_flood_tmpban == 0U ||
        config.anti_abuse.protocol_flood_tmpban > 86400U) {
        throw std::runtime_error("invalid anti-abuse configuration limits");
    }
    if (config.database_config_path.empty() && config.database_password.empty()) {
        throw std::runtime_error("database_password must not be empty");
    }
    if (config.database_config_path.empty() &&
        (config.database_host.empty() || config.database_name.empty() ||
         config.database_user.empty())) {
        throw std::runtime_error(
            "database host, name and user must not be empty");
    }

    return config;
}

}  // namespace dc24h
