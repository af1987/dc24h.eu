/*
    database.cpp

    v0.0.01:
        - connect to MariaDB using utf8mb4
        - create initial operational tables
        - record connect/disconnect events with escaped values

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#include "database.hpp"

#include <stdexcept>
#include <vector>

namespace dc24h {

Database::Database(const Config& config) : config_(config) {}

Database::~Database() {
    std::lock_guard lock(mutex_);
    if (connection_ != nullptr) {
        mysql_close(connection_);
        connection_ = nullptr;
    }
}

void Database::connect() {
    std::lock_guard lock(mutex_);

    connection_ = mysql_init(nullptr);
    if (connection_ == nullptr) {
        throw std::runtime_error("mysql_init failed");
    }

    unsigned int timeout_seconds = 5;
    mysql_options(connection_, MYSQL_OPT_CONNECT_TIMEOUT, &timeout_seconds);

    if (mysql_real_connect(connection_,
                           config_.database_host.c_str(),
                           config_.database_user.c_str(),
                           config_.database_password.c_str(),
                           config_.database_name.c_str(),
                           config_.database_port,
                           nullptr,
                           0) == nullptr) {
        const std::string error = mysql_error(connection_);
        mysql_close(connection_);
        connection_ = nullptr;
        throw std::runtime_error("MariaDB connection failed: " + error);
    }

    if (mysql_set_character_set(connection_, "utf8mb4") != 0) {
        throw std::runtime_error("Unable to select utf8mb4: " + std::string(mysql_error(connection_)));
    }
}

void Database::initialize_schema() {
    std::lock_guard lock(mutex_);

    execute_locked(
        "CREATE TABLE IF NOT EXISTS connection_events ("
        "id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        "sid VARCHAR(4) NOT NULL,"
        "event_type VARCHAR(32) NOT NULL,"
        "remote_address VARCHAR(64) NOT NULL,"
        "created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),"
        "INDEX idx_connection_events_created_at (created_at),"
        "INDEX idx_connection_events_sid (sid)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    execute_locked(
        "CREATE TABLE IF NOT EXISTS accounts ("
        "id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        "nick VARCHAR(64) NOT NULL UNIQUE,"
        "password_hash VARCHAR(255) NOT NULL,"
        "role ENUM('user','operator','admin') NOT NULL DEFAULT 'user',"
        "enabled BOOLEAN NOT NULL DEFAULT TRUE,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    execute_locked(
        "CREATE TABLE IF NOT EXISTS settings ("
        "setting_key VARCHAR(128) NOT NULL PRIMARY KEY,"
        "setting_value TEXT NOT NULL,"
        "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP "
        "ON UPDATE CURRENT_TIMESTAMP"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
}

void Database::record_event(std::string_view sid,
                            std::string_view event,
                            std::string_view remote_address) {
    std::lock_guard lock(mutex_);
    const auto sid_sql = escape_locked(sid);
    const auto event_sql = escape_locked(event);
    const auto remote_sql = escape_locked(remote_address);

    execute_locked(
        "INSERT INTO connection_events(sid,event_type,remote_address) VALUES('" +
        sid_sql + "','" + event_sql + "','" + remote_sql + "')");
}

std::string Database::escape_locked(std::string_view value) {
    if (connection_ == nullptr) {
        throw std::runtime_error("MariaDB is not connected");
    }

    std::vector<char> output(value.size() * 2 + 1);
    const auto length = mysql_real_escape_string(
        connection_, output.data(), value.data(), static_cast<unsigned long>(value.size()));
    return std::string(output.data(), length);
}

void Database::execute_locked(const std::string& sql) {
    if (connection_ == nullptr) {
        throw std::runtime_error("MariaDB is not connected");
    }
    if (mysql_query(connection_, sql.c_str()) != 0) {
        throw std::runtime_error("MariaDB query failed: " + std::string(mysql_error(connection_)));
    }
}

}  // namespace dc24h
