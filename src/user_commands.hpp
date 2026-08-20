/*
    user_commands.hpp

    v0.0.03:
        - define !set key parser for user registration and password changes
        - define execution result for hub command responses
        - support numeric user classes and account IDs

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

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
    change_password_by_id
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
