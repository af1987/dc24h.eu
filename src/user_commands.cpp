/*
    user_commands.cpp

    - hub-local user management command parser and executor

        v0.0.05:
            - add remove, disable, enable, class and account-detail keys
            - add password change/reset by username and private self +passwd parsing
            - add temporary class plus online IP, hostname, range and subnet queries
            - allow an empty class-list payload to select class 0

        v0.0.04:
            - add passwordless creation, first-password and class-list keys
            - keep password addition separate from password replacement

        v0.0.03:
            - parse initial registration and password-change keys
            - validate usernames, numeric IDs and user classes before database writes
            - hash passwords before persistence

    Author: gpt-5.6-sol
    Date: 2026-08-20
*/

// ----------------------------------// DECLARATION //--

#include "user_commands.hpp"

#include "database.hpp"

#include <charconv>
#include <limits>
#include <stdexcept>
#include <utility>

namespace dc24h {
namespace {

constexpr std::string_view create_with_password_prefix =
    "!set key.user.new.username.class.password=[";
constexpr std::string_view create_without_password_prefix =
    "!set key.user.new.username.class=[";
constexpr std::string_view add_password_prefix =
    "!set key.user.new.id.password=[";
constexpr std::string_view change_password_id_prefix =
    "!set key.user.change.id.password=[";
constexpr std::string_view change_password_username_prefix =
    "!set key.user.change.username.password=[";
constexpr std::string_view list_by_class_prefix =
    "!set key.user.info.userlist.class=[";
constexpr std::string_view remove_user_prefix =
    "!set key.user.remove.username=[";
constexpr std::string_view disable_user_prefix =
    "!set key.user.disable.username=[";
constexpr std::string_view enable_user_prefix =
    "!set key.user.enable.username=[";
constexpr std::string_view change_class_prefix =
    "!set key.user.change.username.class=[";
constexpr std::string_view temporary_class_prefix =
    "!set key.user.change.username.class.temp=[";
constexpr std::string_view user_info_prefix =
    "!set key.user.info.username=[";
constexpr std::string_view ip_and_host_prefix =
    "!set key.user.info.ip.hostname.username=[";
constexpr std::string_view hostname_prefix =
    "!set key.user.info.hostname.username=[";
constexpr std::string_view users_by_ip_prefix =
    "!set key.user.info.userlist.ip=[";
constexpr std::string_view users_by_range_prefix =
    "!set key.user.info.userlist.iprange=[";
constexpr std::string_view users_by_subnet_prefix =
    "!set key.user.info.userlist.subnet=[";
constexpr std::string_view self_password_prefix = "+passwd ";

bool unwrap(std::string_view command,
            std::string_view prefix,
            std::string_view& payload,
            bool allow_empty = false) {
    if (!command.starts_with(prefix) || command.empty() || command.back() != ']' ||
        (!allow_empty && command.size() <= prefix.size())) return false;
    payload = command.substr(prefix.size(), command.size() - prefix.size() - 1U);
    return allow_empty || !payload.empty();
}

bool valid_username(std::string_view username) noexcept {
    if (username.empty() || username.size() > 64U) return false;
    for (const unsigned char ch : username) {
        if (ch <= 0x20U || ch == 0x7FU || ch == '.' ||
            ch == '[' || ch == ']') return false;
    }
    return true;
}

bool valid_query(std::string_view query) noexcept {
    if (query.empty() || query.size() > 128U) return false;
    for (const unsigned char ch : query) {
        if (ch <= 0x20U || ch == 0x7FU || ch == '[' || ch == ']') return false;
    }
    return true;
}

std::optional<std::uint64_t> parse_id(std::string_view value) noexcept {
    if (value.empty()) return std::nullopt;
    std::uint64_t parsed = 0;
    const auto result =
        std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size() ||
        parsed == 0U) return std::nullopt;
    return parsed;
}

std::optional<std::int16_t> parse_class(std::string_view value) noexcept {
    if (value.empty()) return std::nullopt;
    int parsed = 0;
    const auto result =
        std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size() ||
        parsed < std::numeric_limits<std::int16_t>::min() ||
        parsed > std::numeric_limits<std::int16_t>::max()) return std::nullopt;
    return static_cast<std::int16_t>(parsed);
}

bool valid_password(std::string_view password) noexcept {
    if (password.size() < 8U || password.size() > 1024U) return false;
    for (const unsigned char ch : password) {
        if (ch < 0x20U || ch == 0x7FU) return false;
    }
    return true;
}

std::optional<UserClass> checked_class(std::string_view value,
                                       std::string& error) {
    const auto class_value = parse_class(value);
    if (!class_value.has_value() || !is_valid_user_class(*class_value)) {
        error = "invalid user class";
        return std::nullopt;
    }
    return user_class_from_int(*class_value);
}

std::optional<UserSetCommand> parse_create(std::string_view payload,
                                           bool with_password,
                                           std::string& error) {
    const auto first_dot = payload.find('.');
    const auto second_dot = first_dot == std::string_view::npos
        ? std::string_view::npos
        : payload.find('.', first_dot + 1U);
    if (first_dot == std::string_view::npos ||
        (with_password && second_dot == std::string_view::npos) ||
        (!with_password && second_dot != std::string_view::npos)) {
        error = with_password ? "expected [username.class.password]"
                              : "expected [username.class]";
        return std::nullopt;
    }

    const auto username = payload.substr(0, first_dot);
    const auto class_text = with_password
        ? payload.substr(first_dot + 1U, second_dot - first_dot - 1U)
        : payload.substr(first_dot + 1U);
    if (!valid_username(username)) {
        error = "invalid username";
        return std::nullopt;
    }
    const auto user_class = checked_class(class_text, error);
    if (!user_class.has_value()) return std::nullopt;

    UserSetCommand parsed;
    parsed.action = with_password ? UserSetAction::create_user
                                  : UserSetAction::create_user_without_password;
    parsed.username = std::string(username);
    parsed.user_class = *user_class;
    if (with_password) {
        const auto password = payload.substr(second_dot + 1U);
        if (!valid_password(password)) {
            error = "password must be 8-1024 printable UTF-8 bytes";
            return std::nullopt;
        }
        parsed.password = std::string(password);
    }
    return parsed;
}

std::optional<UserSetCommand> parse_id_password(std::string_view payload,
                                                UserSetAction action,
                                                std::string& error) {
    const auto dot = payload.find('.');
    if (dot == std::string_view::npos) {
        error = "expected [id.password]";
        return std::nullopt;
    }
    const auto user_id = parse_id(payload.substr(0, dot));
    const auto password = payload.substr(dot + 1U);
    if (!user_id.has_value()) {
        error = "invalid account id";
        return std::nullopt;
    }
    if (!valid_password(password)) {
        error = "password must be 8-1024 printable UTF-8 bytes";
        return std::nullopt;
    }
    UserSetCommand parsed;
    parsed.action = action;
    parsed.user_id = *user_id;
    parsed.password = std::string(password);
    return parsed;
}

std::optional<UserSetCommand> parse_username(std::string_view payload,
                                             UserSetAction action,
                                             std::string& error) {
    if (!valid_username(payload)) {
        error = "invalid username";
        return std::nullopt;
    }
    UserSetCommand parsed;
    parsed.action = action;
    parsed.username = std::string(payload);
    return parsed;
}

std::optional<UserSetCommand> parse_username_class(
    std::string_view payload,
    UserSetAction action,
    bool admin_maximum,
    std::string& error) {
    const auto dot = payload.find('.');
    if (dot == std::string_view::npos ||
        payload.find('.', dot + 1U) != std::string_view::npos) {
        error = "expected [username.class]";
        return std::nullopt;
    }
    const auto username = payload.substr(0, dot);
    if (!valid_username(username)) {
        error = "invalid username";
        return std::nullopt;
    }
    const auto user_class = checked_class(payload.substr(dot + 1U), error);
    if (!user_class.has_value()) return std::nullopt;
    if (admin_maximum && static_cast<std::int16_t>(*user_class) > 5) {
        error = "temporary class maximum is Admin (5)";
        return std::nullopt;
    }
    UserSetCommand parsed;
    parsed.action = action;
    parsed.username = std::string(username);
    parsed.user_class = *user_class;
    return parsed;
}

std::string change_error(AccountChangeResult result) {
    if (result == AccountChangeResult::user_not_found) {
        return "registered username not found";
    }
    if (result == AccountChangeResult::last_master) {
        return "operation rejected: at least one enabled Master (10) is required";
    }
    return {};
}

}  // namespace

UserCommandProcessor::UserCommandProcessor(Database& database)
    : database_(database) {}

std::optional<UserSetCommand> UserCommandProcessor::parse(
    std::string_view command,
    std::string& error) {
    error.clear();
    std::string_view payload;

    if (command.starts_with(self_password_prefix)) {
        const auto password = command.substr(self_password_prefix.size());
        if (!valid_password(password)) {
            error = "password must be 8-1024 printable UTF-8 bytes";
            return std::nullopt;
        }
        UserSetCommand parsed;
        parsed.action = UserSetAction::self_add_password;
        parsed.password = std::string(password);
        return parsed;
    }
    if (unwrap(command, create_with_password_prefix, payload)) {
        return parse_create(payload, true, error);
    }
    if (unwrap(command, create_without_password_prefix, payload)) {
        return parse_create(payload, false, error);
    }
    if (unwrap(command, add_password_prefix, payload)) {
        return parse_id_password(payload, UserSetAction::add_password_by_id, error);
    }
    if (unwrap(command, change_password_id_prefix, payload)) {
        return parse_id_password(payload, UserSetAction::change_password_by_id, error);
    }
    if (unwrap(command, change_password_username_prefix, payload, true)) {
        const auto dot = payload.find('.');
        if (dot == std::string_view::npos) {
            error = "expected [username.password]";
            return std::nullopt;
        }
        const auto username = payload.substr(0, dot);
        const auto password = payload.substr(dot + 1U);
        if (!valid_username(username)) {
            error = "invalid username";
            return std::nullopt;
        }
        if (!password.empty() && !valid_password(password)) {
            error = "password must be empty or 8-1024 printable UTF-8 bytes";
            return std::nullopt;
        }
        UserSetCommand parsed;
        parsed.action = UserSetAction::change_password_by_username;
        parsed.username = std::string(username);
        parsed.password = std::string(password);
        return parsed;
    }
    if (unwrap(command, list_by_class_prefix, payload, true)) {
        const auto user_class = payload.empty()
            ? std::optional<UserClass>{UserClass::regular}
            : checked_class(payload, error);
        if (!user_class.has_value()) return std::nullopt;
        UserSetCommand parsed;
        parsed.action = UserSetAction::list_users_by_class;
        parsed.user_class = *user_class;
        return parsed;
    }
    if (unwrap(command, remove_user_prefix, payload)) {
        return parse_username(payload, UserSetAction::remove_user, error);
    }
    if (unwrap(command, disable_user_prefix, payload)) {
        return parse_username(payload, UserSetAction::disable_user, error);
    }
    if (unwrap(command, enable_user_prefix, payload)) {
        return parse_username(payload, UserSetAction::enable_user, error);
    }
    if (unwrap(command, temporary_class_prefix, payload)) {
        return parse_username_class(payload,
                                    UserSetAction::change_class_temporarily,
                                    true,
                                    error);
    }
    if (unwrap(command, change_class_prefix, payload)) {
        return parse_username_class(payload,
                                    UserSetAction::change_class,
                                    false,
                                    error);
    }
    if (unwrap(command, user_info_prefix, payload)) {
        return parse_username(payload, UserSetAction::show_user_info, error);
    }
    if (unwrap(command, ip_and_host_prefix, payload)) {
        return parse_username(payload, UserSetAction::show_ip_and_hostname, error);
    }
    if (unwrap(command, hostname_prefix, payload)) {
        return parse_username(payload, UserSetAction::show_hostname, error);
    }

    const auto parse_query = [&](std::string_view prefix,
                                 UserSetAction action)
        -> std::optional<UserSetCommand> {
        std::string_view query;
        if (!unwrap(command, prefix, query)) return std::nullopt;
        if (!valid_query(query)) {
            error = "invalid IP query";
            return std::nullopt;
        }
        UserSetCommand parsed;
        parsed.action = action;
        parsed.query = std::string(query);
        return parsed;
    };
    if (command.starts_with(users_by_ip_prefix)) {
        return parse_query(users_by_ip_prefix, UserSetAction::find_users_by_ip);
    }
    if (command.starts_with(users_by_range_prefix)) {
        return parse_query(users_by_range_prefix,
                           UserSetAction::find_users_by_ip_range);
    }
    if (command.starts_with(users_by_subnet_prefix)) {
        return parse_query(users_by_subnet_prefix,
                           UserSetAction::find_users_by_subnet);
    }

    error = "unknown !set user key";
    return std::nullopt;
}

UserSetResult UserCommandProcessor::execute(std::string_view command) {
    std::string error;
    const auto parsed = parse(command, error);
    if (!parsed.has_value()) return {false, error};
    return execute(*parsed);
}

UserSetResult UserCommandProcessor::execute(const UserSetCommand& command) {
    try {
        switch (command.action) {
            case UserSetAction::create_user: {
                const auto id = database_.create_user(
                    command.username,
                    command.user_class,
                    hash_password(command.password));
                return {true, "user created: id=" + std::to_string(id) +
                    " username=" + command.username + " class=" +
                    std::to_string(static_cast<std::int16_t>(command.user_class))};
            }
            case UserSetAction::create_user_without_password: {
                const auto id = database_.create_user_without_password(
                    command.username, command.user_class);
                return {true, "user created without password: id=" +
                    std::to_string(id) + " username=" + command.username +
                    " class=" +
                    std::to_string(static_cast<std::int16_t>(command.user_class))};
            }
            case UserSetAction::add_password_by_id: {
                const auto outcome = database_.add_user_password_if_missing(
                    command.user_id, hash_password(command.password));
                if (outcome == AddPasswordResult::added) {
                    return {true, "password added for id=" +
                        std::to_string(command.user_id)};
                }
                if (outcome == AddPasswordResult::already_set) {
                    return {false, "password already exists for id=" +
                        std::to_string(command.user_id) +
                        "; no change made; use key.user.change.id.password to replace it"};
                }
                return {false, "account id not found"};
            }
            case UserSetAction::change_password_by_id:
                if (!database_.update_user_password_by_id(
                        command.user_id, hash_password(command.password))) {
                    return {false, "account id not found"};
                }
                return {true, "password changed for id=" +
                    std::to_string(command.user_id)};
            case UserSetAction::change_password_by_username: {
                const std::optional<std::string> password_hash =
                    command.password.empty()
                        ? std::nullopt
                        : std::optional<std::string>{hash_password(command.password)};
                if (!database_.update_user_password_by_username(
                        command.username, password_hash)) {
                    return {false, "registered username not found"};
                }
                return {true, command.password.empty()
                    ? "password reset for username=" + command.username +
                        "; user may set it with +passwd <password>"
                    : "password changed for username=" + command.username};
            }
            case UserSetAction::list_users_by_class: {
                const auto users = database_.users_by_class(command.user_class);
                std::string message = "user list class=" +
                    std::to_string(static_cast<std::int16_t>(command.user_class)) +
                    " (" + std::string(user_class_name(command.user_class)) + ")";
                if (users.empty()) return {true, message + ": empty"};
                message += ": ";
                bool first = true;
                for (const auto& user : users) {
                    if (!first) message += "; ";
                    first = false;
                    message += "id=" + std::to_string(user.id) +
                        " username=" + user.username +
                        " enabled=" + (user.enabled ? "yes" : "no") +
                        " password=" + (user.has_password ? "set" : "unset");
                }
                return {true, std::move(message)};
            }
            case UserSetAction::remove_user: {
                const auto outcome = database_.remove_user(command.username);
                const auto error = change_error(outcome);
                return error.empty()
                    ? UserSetResult{true, "user removed: username=" + command.username}
                    : UserSetResult{false, error};
            }
            case UserSetAction::disable_user:
            case UserSetAction::enable_user: {
                const bool enabled = command.action == UserSetAction::enable_user;
                const auto outcome =
                    database_.set_user_enabled(command.username, enabled);
                const auto error = change_error(outcome);
                return error.empty()
                    ? UserSetResult{true, std::string(enabled ? "user enabled: "
                                                             : "user disabled: ") +
                        "username=" + command.username}
                    : UserSetResult{false, error};
            }
            case UserSetAction::change_class: {
                const auto outcome = database_.set_user_class(
                    command.username, command.user_class);
                const auto error = change_error(outcome);
                return error.empty()
                    ? UserSetResult{true, "class changed: username=" +
                        command.username + " class=" +
                        std::to_string(static_cast<std::int16_t>(command.user_class))}
                    : UserSetResult{false, error};
            }
            case UserSetAction::show_user_info: {
                const auto details = database_.user_details(command.username);
                if (!details.has_value()) {
                    return {false, "registered username not found"};
                }
                return {true, "user info: id=" + std::to_string(details->id) +
                    " username=" + details->username + " class=" +
                    std::to_string(static_cast<std::int16_t>(details->user_class)) +
                    " (" + std::string(user_class_name(details->user_class)) + ")" +
                    " enabled=" + (details->enabled ? "yes" : "no") +
                    " password=" + (details->has_password ? "set" : "unset") +
                    " created_at=" + details->created_at +
                    " updated_at=" + details->updated_at};
            }
            case UserSetAction::self_add_password: {
                const auto outcome = database_.add_user_password_if_missing(
                    command.username, hash_password(command.password));
                if (outcome == AddPasswordResult::added) {
                    return {true, "password added for username=" + command.username};
                }
                if (outcome == AddPasswordResult::already_set) {
                    return {false, "password already exists; no change made"};
                }
                return {false, "enabled registered username not found"};
            }
            default:
                return {false, "command requires live session state"};
        }
    } catch (const std::exception& ex) {
        return {false, ex.what()};
    }
}

bool UserCommandProcessor::requires_live_sessions(
    UserSetAction action) noexcept {
    return action == UserSetAction::change_class_temporarily ||
           action == UserSetAction::show_ip_and_hostname ||
           action == UserSetAction::show_hostname ||
           action == UserSetAction::find_users_by_ip ||
           action == UserSetAction::find_users_by_ip_range ||
           action == UserSetAction::find_users_by_subnet;
}

}  // namespace dc24h
