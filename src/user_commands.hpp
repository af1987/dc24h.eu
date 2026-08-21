/*
    user_commands.hpp

    - hub-local user management command model

        v0.0.07:
            - add hub-setting and self-registration actions
            - add account IP, email, public-note and kick-message actions

        v0.0.06:
            - add moderation, visibility and account-note actions
            - add generic expiring restriction and delegated-privilege actions
            - add disconnect and protected kick live-session actions

        v0.0.05:
            - add complete account lifecycle and information key actions
            - add temporary-class and online IP/hostname query actions
            - add resettable password-by-username and +passwd self-service models

        v0.0.04:
            - distinguish adding a missing password from changing an existing password
            - add passwordless user registration command
            - add user-list-by-class information command

        v0.0.03:
            - define !set key parser for user registration and password changes
            - define execution result for hub command responses
            - support numeric user classes and account IDs

    Author: gpt-5.6-sol
    Date: 2026-08-21
*/

// ----------------------------------// DECLARATION //--

#pragma once

#include "user.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace dc24h {

class Database;

enum class UserSetAction {
    create_user,
    create_user_without_password,
    add_password_by_id,
    change_password_by_id,
    change_password_by_username,
    list_users_by_class,
    remove_user,
    disable_user,
    enable_user,
    change_class,
    change_class_temporarily,
    show_user_info,
    show_ip_and_hostname,
    show_hostname,
    find_users_by_ip,
    find_users_by_ip_range,
    find_users_by_subnet,
    self_add_password,
    disconnect_user,
    kick_user,
    set_kick_protection,
    set_hide_share,
    set_hide_operator_key,
    set_user_note,
    set_self_visibility,
    set_timed_policy,
    remove_timed_policy,
    set_hub_setting,
    self_register,
    set_auth_ip,
    remove_auth_ip,
    set_email,
    set_public_note,
    set_hide_kick,
    set_hide_kick_class
};

struct UserSetCommand {
    UserSetAction action{UserSetAction::create_user};
    std::string username;
    UserClass user_class{UserClass::regular};
    std::uint64_t user_id{0};
    std::string password;
    std::string query;
    std::string policy_key;
    std::string note;
    std::string setting_key;
    std::string setting_value;
    std::string actor_username;
    std::uint64_t duration_seconds{0};
    bool enabled{false};
};

struct UserSetResult {
    bool success{false};
    std::string message;
};

class UserCommandProcessor {
public:
    explicit UserCommandProcessor(Database& database);

    static std::optional<UserSetCommand> parse(std::string_view command,
                                               std::string& error);
    UserSetResult execute(std::string_view command);
    UserSetResult execute(const UserSetCommand& command);

    static bool requires_live_sessions(UserSetAction action) noexcept;

private:
    Database& database_;
};

}  // namespace dc24h
