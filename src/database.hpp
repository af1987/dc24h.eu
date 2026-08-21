/*
    database.hpp

    - MariaDB persistence API

        v0.0.05:
            - add complete registered-user administration operations
            - expose account details and password reset state
            - protect the last enabled Master from deletion or disabling

        v0.0.04:
            - allow accounts without an initial password
            - add add-password-if-missing result model
            - add user listing by numeric class

        v0.0.03:
            - add persistent numeric user classes to account operations
            - add account creation, password update, class lookup and bootstrap checks

        v0.0.01:
            - add MariaDB connection lifecycle
            - add schema bootstrap and connection event persistence
            - serialize access to the MariaDB C connection

    Author: gpt-5.6-sol
    Date: 2026-08-20
*/

// ----------------------------------// DECLARATION //--

#pragma once

#include "config.hpp"
#include "user.hpp"

#include <mysql.h>

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace dc24h {

enum class AddPasswordResult {
    added,
    already_set,
    user_not_found
};

enum class AccountChangeResult {
    changed,
    user_not_found,
    last_master
};

struct UserListEntry {
    std::uint64_t id{0};
    std::string username;
    UserClass user_class{UserClass::regular};
    bool enabled{true};
    bool has_password{false};
};

struct UserDetails {
    std::uint64_t id{0};
    std::string username;
    UserClass user_class{UserClass::regular};
    bool enabled{true};
    bool has_password{false};
    std::string created_at;
    std::string updated_at;
};

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
    std::uint64_t create_user_without_password(std::string_view username,
                                               UserClass user_class);
    bool update_user_password_by_id(std::uint64_t user_id,
                                    std::string_view password_hash);
    bool update_user_password_by_username(
        std::string_view username,
        const std::optional<std::string>& password_hash);
    AddPasswordResult add_user_password_if_missing(
        std::uint64_t user_id,
        std::string_view password_hash);
    AddPasswordResult add_user_password_if_missing(
        std::string_view username,
        std::string_view password_hash);
    std::vector<UserListEntry> users_by_class(UserClass user_class);
    std::optional<UserDetails> user_details(std::string_view username);
    AccountChangeResult remove_user(std::string_view username);
    AccountChangeResult set_user_enabled(std::string_view username,
                                         bool enabled);
    AccountChangeResult set_user_class(std::string_view username,
                                       UserClass user_class);
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
