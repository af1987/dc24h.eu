/*
    database.cpp

    - MariaDB persistence implementation

        v0.0.04:
            - make account password_hash nullable for passwordless registrations
            - add conditional password insertion that never overwrites an existing password
            - add enabled-user listing filtered by numeric class

        v0.0.03:
            - extend accounts with validated numeric user_class values
            - add account creation and password changes by database id
            - add class lookup and empty-account bootstrap check for protected !set commands

        v0.0.01:
            - connect to MariaDB using utf8mb4
            - create initial operational tables
            - record connect/disconnect events with escaped values

    Author: gpt-5.6-sol
    Date: 2026-08-20
*/

// ----------------------------------// DECLARATION //--

#include "database.hpp"

#include <limits>
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
        throw std::runtime_error(
            "Unable to select utf8mb4: " +
            std::string(mysql_error(connection_)));
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
        "password_hash VARCHAR(255) NULL,"
        "role ENUM('user','operator','admin') NOT NULL DEFAULT 'user',"
        "user_class SMALLINT NOT NULL DEFAULT 0,"
        "enabled BOOLEAN NOT NULL DEFAULT TRUE,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "INDEX idx_accounts_user_class (user_class)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    execute_locked(
        "ALTER TABLE accounts "
        "ADD COLUMN IF NOT EXISTS user_class SMALLINT NOT NULL DEFAULT 0");

    execute_locked(
        "ALTER TABLE accounts "
        "MODIFY COLUMN password_hash VARCHAR(255) NULL");

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

std::uint64_t Database::create_user(std::string_view username,
                                    UserClass user_class,
                                    std::string_view password_hash) {
    const auto class_value = static_cast<std::int16_t>(user_class);
    if (!is_valid_user_class(class_value)) {
        throw std::invalid_argument("invalid user class");
    }

    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    const auto password_sql = escape_locked(password_hash);

    if (mysql_query(
            connection_,
            ("INSERT INTO accounts(nick,password_hash,user_class,enabled) "
             "VALUES('" + username_sql + "','" + password_sql + "'," +
             std::to_string(class_value) + ",TRUE)")
                .c_str()) != 0) {
        const auto error_number = mysql_errno(connection_);
        if (error_number == 1062U) {
            throw std::runtime_error("username already exists");
        }
        throw std::runtime_error(
            "MariaDB query failed: " +
            std::string(mysql_error(connection_)));
    }

    return static_cast<std::uint64_t>(mysql_insert_id(connection_));
}

std::uint64_t Database::create_user_without_password(
    std::string_view username,
    UserClass user_class) {
    const auto class_value = static_cast<std::int16_t>(user_class);
    if (!is_valid_user_class(class_value)) {
        throw std::invalid_argument("invalid user class");
    }

    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);

    if (mysql_query(
            connection_,
            ("INSERT INTO accounts(nick,password_hash,user_class,enabled) "
             "VALUES('" + username_sql + "',NULL," +
             std::to_string(class_value) + ",TRUE)")
                .c_str()) != 0) {
        const auto error_number = mysql_errno(connection_);
        if (error_number == 1062U) {
            throw std::runtime_error("username already exists");
        }
        throw std::runtime_error(
            "MariaDB query failed: " +
            std::string(mysql_error(connection_)));
    }

    return static_cast<std::uint64_t>(mysql_insert_id(connection_));
}

bool Database::update_user_password_by_id(
    std::uint64_t user_id,
    std::string_view password_hash) {
    if (user_id == 0U) return false;

    std::lock_guard lock(mutex_);
    const auto password_sql = escape_locked(password_hash);

    execute_locked(
        "UPDATE accounts SET password_hash='" + password_sql +
        "' WHERE id=" + std::to_string(user_id) + " AND enabled=TRUE");

    return mysql_affected_rows(connection_) == 1;
}

AddPasswordResult Database::add_user_password_if_missing(
    std::uint64_t user_id,
    std::string_view password_hash) {
    if (user_id == 0U) return AddPasswordResult::user_not_found;

    std::lock_guard lock(mutex_);
    const auto password_sql = escape_locked(password_hash);

    execute_locked(
        "UPDATE accounts SET password_hash='" + password_sql +
        "' WHERE id=" + std::to_string(user_id) +
        " AND enabled=TRUE AND (password_hash IS NULL OR password_hash='')");

    if (mysql_affected_rows(connection_) == 1) {
        return AddPasswordResult::added;
    }

    execute_locked(
        "SELECT password_hash FROM accounts WHERE id=" +
        std::to_string(user_id) + " AND enabled=TRUE LIMIT 1");

    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        if (mysql_field_count(connection_) == 0U) {
            return AddPasswordResult::user_not_found;
        }
        throw std::runtime_error(
            "MariaDB result failed: " +
            std::string(mysql_error(connection_)));
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    if (row == nullptr) {
        mysql_free_result(result);
        return AddPasswordResult::user_not_found;
    }

    mysql_free_result(result);
    return AddPasswordResult::already_set;
}

std::vector<UserListEntry> Database::users_by_class(UserClass user_class) {
    const auto class_value = static_cast<std::int16_t>(user_class);
    if (!is_valid_user_class(class_value)) {
        throw std::invalid_argument("invalid user class");
    }

    std::lock_guard lock(mutex_);
    execute_locked(
        "SELECT id,nick FROM accounts WHERE user_class=" +
        std::to_string(class_value) + " AND enabled=TRUE ORDER BY id");

    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " +
            std::string(mysql_error(connection_)));
    }

    std::vector<UserListEntry> users;
    while (MYSQL_ROW row = mysql_fetch_row(result)) {
        if (row[0] == nullptr || row[1] == nullptr) continue;

        std::uint64_t id = 0;
        try {
            id = static_cast<std::uint64_t>(std::stoull(row[0]));
        } catch (...) {
            mysql_free_result(result);
            throw std::runtime_error("invalid account id stored in database");
        }

        users.push_back(UserListEntry{
            id,
            std::string(row[1]),
            user_class
        });
    }

    mysql_free_result(result);
    return users;
}

std::optional<UserClass> Database::user_class_for_username(
    std::string_view username) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);

    execute_locked(
        "SELECT user_class FROM accounts WHERE nick='" +
        username_sql + "' AND enabled=TRUE LIMIT 1");

    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        if (mysql_field_count(connection_) == 0U) {
            return std::nullopt;
        }
        throw std::runtime_error(
            "MariaDB result failed: " +
            std::string(mysql_error(connection_)));
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    if (row == nullptr || row[0] == nullptr) {
        mysql_free_result(result);
        return std::nullopt;
    }

    int parsed = 0;
    try {
        parsed = std::stoi(row[0]);
    } catch (...) {
        mysql_free_result(result);
        throw std::runtime_error("invalid user_class stored in database");
    }

    mysql_free_result(result);

    if (parsed < std::numeric_limits<std::int16_t>::min() ||
        parsed > std::numeric_limits<std::int16_t>::max()) {
        throw std::runtime_error("user_class is outside SMALLINT range");
    }

    const auto result_class =
        user_class_from_int(static_cast<std::int16_t>(parsed));
    if (!result_class.has_value()) {
        throw std::runtime_error("unsupported user_class stored in database");
    }
    return result_class;
}

bool Database::has_any_enabled_users() {
    std::lock_guard lock(mutex_);

    execute_locked("SELECT 1 FROM accounts WHERE enabled=TRUE LIMIT 1");

    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        if (mysql_field_count(connection_) == 0U) {
            return false;
        }
        throw std::runtime_error(
            "MariaDB result failed: " +
            std::string(mysql_error(connection_)));
    }

    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

std::string Database::escape_locked(std::string_view value) {
    if (connection_ == nullptr) {
        throw std::runtime_error("MariaDB is not connected");
    }

    std::vector<char> output(value.size() * 2 + 1);
    const auto length = mysql_real_escape_string(
        connection_,
        output.data(),
        value.data(),
        static_cast<unsigned long>(value.size()));
    return std::string(output.data(), length);
}

void Database::execute_locked(const std::string& sql) {
    if (connection_ == nullptr) {
        throw std::runtime_error("MariaDB is not connected");
    }
    if (mysql_query(connection_, sql.c_str()) != 0) {
        throw std::runtime_error(
            "MariaDB query failed: " +
            std::string(mysql_error(connection_)));
    }
}

}  // namespace dc24h
