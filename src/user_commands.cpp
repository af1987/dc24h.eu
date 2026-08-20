/*
    user_commands.cpp

    v0.0.03:
        - parse !set key.user.new.username.class.password
        - parse !set key.user.change.id.password and legacy new.id.password alias
        - validate usernames, numeric IDs and user classes before database writes
        - hash passwords before persistence

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#include "user_commands.hpp"

#include "database.hpp"

#include <charconv>
#include <limits>
#include <stdexcept>

namespace dc24h {
namespace {

constexpr std::string_view create_prefix =
    "!set key.user.new.username.class.password=[";
constexpr std::string_view change_prefix =
    "!set key.user.change.id.password=[";
constexpr std::string_view change_alias_prefix =
    "!set key.user.new.id.password=[";

bool unwrap(std::string_view command,
            std::string_view prefix,
            std::string_view& payload) {
    if (!command.starts_with(prefix) ||
        command.size() <= prefix.size() ||
        command.back() != ']') {
        return false;
    }

    payload = command.substr(prefix.size(),
                             command.size() - prefix.size() - 1U);
    return true;
}

bool valid_username(std::string_view username) noexcept {
    if (username.empty() || username.size() > 64U) return false;

    for (const unsigned char ch : username) {
        if (ch <= 0x20U || ch == 0x7FU || ch == '.' ||
            ch == '[' || ch == ']') {
            return false;
        }
    }
    return true;
}

std::optional<std::uint64_t> parse_id(std::string_view value) noexcept {
    if (value.empty()) return std::nullopt;

    std::uint64_t parsed = 0;
    const auto result =
        std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} ||
        result.ptr != value.data() + value.size() ||
        parsed == 0U) {
        return std::nullopt;
    }
    return parsed;
}

std::optional<std::int16_t> parse_class(std::string_view value) noexcept {
    if (value.empty()) return std::nullopt;

    int parsed = 0;
    const auto result =
        std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} ||
        result.ptr != value.data() + value.size() ||
        parsed < std::numeric_limits<std::int16_t>::min() ||
        parsed > std::numeric_limits<std::int16_t>::max()) {
        return std::nullopt;
    }
    return static_cast<std::int16_t>(parsed);
}

bool valid_password(std::string_view password) noexcept {
    if (password.size() < 8U || password.size() > 1024U) return false;
    for (const unsigned char ch : password) {
        if (ch < 0x20U || ch == 0x7FU) return false;
    }
    return true;
}

}  // namespace

UserCommandProcessor::UserCommandProcessor(Database& database)
    : database_(database) {}

std::optional<UserSetCommand> UserCommandProcessor::parse(
    std::string_view command,
    std::string& error) {
    error.clear();
    std::string_view payload;

    if (unwrap(command, create_prefix, payload)) {
        const auto first_dot = payload.find('.');
        const auto second_dot =
            first_dot == std::string_view::npos
                ? std::string_view::npos
                : payload.find('.', first_dot + 1U);

        if (first_dot == std::string_view::npos ||
            second_dot == std::string_view::npos) {
            error = "expected [username.class.password]";
            return std::nullopt;
        }

        const auto username = payload.substr(0, first_dot);
        const auto class_text =
            payload.substr(first_dot + 1U,
                           second_dot - first_dot - 1U);
        const auto password = payload.substr(second_dot + 1U);

        if (!valid_username(username)) {
            error = "invalid username";
            return std::nullopt;
        }

        const auto class_value = parse_class(class_text);
        if (!class_value.has_value() ||
            !is_valid_user_class(*class_value)) {
            error = "invalid user class";
            return std::nullopt;
        }

        if (!valid_password(password)) {
            error = "password must be 8-1024 printable UTF-8 bytes";
            return std::nullopt;
        }

        UserSetCommand parsed;
        parsed.action = UserSetAction::create_user;
        parsed.username = std::string(username);
        parsed.user_class = *user_class_from_int(*class_value);
        parsed.password = std::string(password);
        return parsed;
    }

    const bool is_change = unwrap(command, change_prefix, payload);
    const bool is_alias =
        !is_change && unwrap(command, change_alias_prefix, payload);

    if (is_change || is_alias) {
        const auto dot = payload.find('.');
        if (dot == std::string_view::npos) {
            error = "expected [id.password]";
            return std::nullopt;
        }

        const auto id_text = payload.substr(0, dot);
        const auto password = payload.substr(dot + 1U);
        const auto user_id = parse_id(id_text);

        if (!user_id.has_value()) {
            error = "invalid account id";
            return std::nullopt;
        }
        if (!valid_password(password)) {
            error = "password must be 8-1024 printable UTF-8 bytes";
            return std::nullopt;
        }

        UserSetCommand parsed;
        parsed.action = UserSetAction::change_password_by_id;
        parsed.user_id = *user_id;
        parsed.password = std::string(password);
        return parsed;
    }

    error = "unknown !set user key";
    return std::nullopt;
}

UserSetResult UserCommandProcessor::execute(std::string_view command) {
    std::string error;
    const auto parsed = parse(command, error);
    if (!parsed.has_value()) {
        return {false, error};
    }

    try {
        const auto password_hash = hash_password(parsed->password);

        if (parsed->action == UserSetAction::create_user) {
            const auto id =
                database_.create_user(parsed->username,
                                      parsed->user_class,
                                      password_hash);
            return {
                true,
                "user created: id=" + std::to_string(id) +
                    " username=" + parsed->username +
                    " class=" +
                    std::to_string(
                        static_cast<std::int16_t>(parsed->user_class))
            };
        }

        if (!database_.update_user_password_by_id(parsed->user_id,
                                                  password_hash)) {
            return {false, "account id not found"};
        }

        return {
            true,
            "password changed for id=" +
                std::to_string(parsed->user_id)
        };
    } catch (const std::exception& ex) {
        return {false, ex.what()};
    }
}

}  // namespace dc24h
