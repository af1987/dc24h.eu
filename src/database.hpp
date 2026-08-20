/*
    database.hpp

    v0.0.03:
        - add persistent numeric user classes to account operations
        - add account creation, password update, class lookup and bootstrap checks

    v0.0.01:
        - add MariaDB connection lifecycle
        - add schema bootstrap and connection event persistence
        - serialize access to the MariaDB C connection

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#pragma once

#include "config.hpp"
#include "user.hpp"

#include <mysql.h>

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace dc24h {

class Database {
public:
    explicit Database(const Config& config);
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    void connect();
    void initialize_schema();
    void record_event(std::string_view sid,
                      std::string_view event,
                      std::string_view remote_address);

    std::uint64_t create_user(std::string_view username,
                              UserClass user_class,
                              std::string_view password_hash);
    bool update_user_password_by_id(std::uint64_t user_id,
                                    std::string_view password_hash);
    std::optional<UserClass> user_class_for_username(
        std::string_view username);
    bool has_any_enabled_users();

private:
    std::string escape_locked(std::string_view value);
    void execute_locked(const std::string& sql);

    const Config& config_;
    MYSQL* connection_{nullptr};
    std::mutex mutex_;
};

}  // namespace dc24h
