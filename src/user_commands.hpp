/*
    user_commands.hpp

    - hub-local user management command model

        v0.0.04:
            - distinguish adding a missing password from changing an existing password
            - add passwordless user registration command
            - add user-list-by-class information command

        v0.0.03:
            - define !set key parser for user registration and password changes
            - define execution result for hub command responses
            - support numeric user classes and account IDs

    Author: gpt-5.6-sol
    Date: 2026-08-20
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
    list_users_by_class
};

struct UserSetCommand {
    UserSetAction action{UserSetAction::create_user};
    std::string username;
    UserClass user_class{UserClass::regular};
    std::uint64_t user_id{0};
    std::string password;
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

private:
    Database& database_;
};

}  // namespace dc24h
