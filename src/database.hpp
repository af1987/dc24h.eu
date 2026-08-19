/*
    database.hpp

    v0.0.01:
        - add MariaDB connection lifecycle
        - add schema bootstrap and connection event persistence
        - serialize access to the MariaDB C connection

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#pragma once

#include "config.hpp"

#include <mysql.h>

#include <mutex>
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

private:
    std::string escape_locked(std::string_view value);
    void execute_locked(const std::string& sql);

    const Config& config_;
    MYSQL* connection_{nullptr};
    std::mutex mutex_;
};

}  // namespace dc24h
