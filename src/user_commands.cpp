/*
    user_commands.cpp

    - hub-local user management command parser and executor

        v0.0.07:
            - parse persistent hub settings and +regme self-registration
            - parse account IP, email, public-note and kick-message controls
            - execute the new MariaDB-backed actions

        v0.0.06:
            - parse moderation, visibility, note and protected-kick keys
            - parse duration-based restrictions and delegated privileges
            - execute persistent moderation policy updates through MariaDB

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
    Date: 2026-08-21
*/

// ----------------------------------// DECLARATION //--

#include "user_commands.hpp"

#include "database.hpp"
#include "hub_settings.hpp"

#include <arpa/inet.h>
#include <array>
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
constexpr std::string_view self_register_prefix = "+regme ";
constexpr std::string_view disconnect_prefix =
    "!set key.user.disconnect.username=[";
constexpr std::string_view kick_prefix =
    "!set key.user.kick.username=[";
constexpr std::string_view protect_prefix =
    "!set key.user.protect.username.class=[";
constexpr std::string_view hide_share_prefix =
    "!set key.user.hide.share.username=[";
constexpr std::string_view hide_operator_prefix =
    "!set key.user.hide.operator.username=[";
constexpr std::string_view note_prefix =
    "!set key.user.note.username=[";
constexpr std::string_view self_visibility_prefix =
    "!set key.user.self.hide.class=[";
constexpr std::string_view auth_ip_prefix =
    "!set key.user.auth.ip.username=[";
constexpr std::string_view auth_ip_remove_prefix =
    "!set key.user.auth.ip.remove.username=[";
constexpr std::string_view email_prefix =
    "!set key.user.email.username=[";
constexpr std::string_view public_note_prefix =
    "!set key.user.note.public.username=[";
constexpr std::string_view hide_kick_prefix =
    "!set key.user.hide.kick.username=[";
constexpr std::string_view hide_kick_class_prefix =
    "!set key.user.hide.kick.username.class=[";

struct TimedKeyDefinition {
    std::string_view prefix;
    std::string_view policy_key;
    std::uint64_t default_seconds;
    bool remove;
};

constexpr std::uint64_t day_seconds = 24U * 60U * 60U;
constexpr std::array<TimedKeyDefinition, 18> timed_keys{{
    {"!set key.user.restrict.gag.username.time=[", "gag", 7U * day_seconds, false},
    {"!set key.user.restrict.gag.remove.username=[", "gag", 0U, true},
    {"!set key.user.restrict.download.username.time=[", "no_download", 2U * day_seconds, false},
    {"!set key.user.restrict.download.remove.username=[", "no_download", 0U, true},
    {"!set key.user.restrict.chat.username.time=[", "no_chat", 2U * day_seconds, false},
    {"!set key.user.restrict.chat.remove.username=[", "no_chat", 0U, true},
    {"!set key.user.restrict.pm.username.time=[", "no_pm", 7U * day_seconds, false},
    {"!set key.user.restrict.pm.remove.username=[", "no_pm", 0U, true},
    {"!set key.user.restrict.search.username.time=[", "no_search", 7U * day_seconds, false},
    {"!set key.user.restrict.search.remove.username=[", "no_search", 0U, true},
    {"!set key.user.grant.kick.username.time=[", "can_kick", 7U * day_seconds, false},
    {"!set key.user.grant.kick.remove.username=[", "can_kick", 0U, true},
    {"!set key.user.grant.hideshare.username.time=[", "hide_share", 7U * day_seconds, false},
    {"!set key.user.grant.hideshare.remove.username=[", "hide_share", 0U, true},
    {"!set key.user.grant.register.username.time=[", "can_register", 7U * day_seconds, false},
    {"!set key.user.grant.register.remove.username=[", "can_register", 0U, true},
    {"!set key.user.grant.opchat.username.time=[", "opchat", 7U * day_seconds, false},
    {"!set key.user.grant.opchat.remove.username=[", "opchat", 0U, true}
}};

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
        if (ch <= 0x20U || ch == 0x7FU || ch == '.') return false;
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

bool valid_note(std::string_view note) noexcept {
    if (note.size() > 2000U) return false;
    for (const unsigned char ch : note) {
        if ((ch < 0x20U && ch != '\t') || ch == 0x7FU) return false;
    }
    return true;
}

bool valid_email(std::string_view email) noexcept {
    if (email.empty()) return true;
    if (email.size() > 254U || email.front() == '@' || email.back() == '@') {
        return false;
    }
    const auto at = email.find('@');
    if (at == std::string_view::npos ||
        email.find('@', at + 1U) != std::string_view::npos) return false;
    for (const unsigned char character : email) {
        if (character <= 0x20U || character == 0x7FU ||
            character == '[' || character == ']') return false;
    }
    return true;
}

bool valid_ipv4(std::string_view value) noexcept {
    in_addr address{};
    return ::inet_pton(AF_INET, std::string(value).c_str(), &address) == 1;
}

std::optional<std::uint64_t> parse_duration(
    std::string_view value) noexcept {
    if (value.size() < 2U) return std::nullopt;
    const char suffix = value.back();
    std::uint64_t multiplier = 0;
    if (suffix == 'm') multiplier = 60U;
    else if (suffix == 'h') multiplier = 60U * 60U;
    else if (suffix == 'd') multiplier = day_seconds;
    else return std::nullopt;

    std::uint64_t amount = 0;
    const auto number = value.substr(0, value.size() - 1U);
    const auto result = std::from_chars(
        number.data(), number.data() + number.size(), amount);
    constexpr std::uint64_t maximum = 365U * day_seconds;
    if (result.ec != std::errc{} ||
        result.ptr != number.data() + number.size() || amount == 0U ||
        amount > maximum / multiplier) return std::nullopt;
    const auto seconds = amount * multiplier;
    if (seconds < 60U || seconds > maximum) return std::nullopt;
    return seconds;
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

std::optional<UserSetCommand> parse_username_flag(
    std::string_view payload,
    UserSetAction action,
    std::string& error) {
    const auto dot = payload.find('.');
    if (dot == std::string_view::npos ||
        payload.find('.', dot + 1U) != std::string_view::npos) {
        error = "expected [username.0|1]";
        return std::nullopt;
    }
    const auto username = payload.substr(0, dot);
    const auto flag = payload.substr(dot + 1U);
    if (!valid_username(username)) {
        error = "invalid username";
        return std::nullopt;
    }
    if (flag != "0" && flag != "1") {
        error = "flag must be 0 or 1";
        return std::nullopt;
    }
    UserSetCommand parsed;
    parsed.action = action;
    parsed.username = std::string(username);
    parsed.enabled = flag == "1";
    return parsed;
}

std::optional<UserSetCommand> parse_timed_policy(
    std::string_view payload,
    const TimedKeyDefinition& definition,
    std::string& error) {
    const auto dot = payload.find('.');
    const auto username = dot == std::string_view::npos
        ? payload
        : payload.substr(0, dot);
    if (!valid_username(username)) {
        error = "invalid username";
        return std::nullopt;
    }
    if (definition.remove && dot != std::string_view::npos) {
        error = "remove key expects [username]";
        return std::nullopt;
    }

    UserSetCommand parsed;
    parsed.action = definition.remove
        ? UserSetAction::remove_timed_policy
        : UserSetAction::set_timed_policy;
    parsed.username = std::string(username);
    parsed.policy_key = std::string(definition.policy_key);
    if (!definition.remove) {
        parsed.duration_seconds = definition.default_seconds;
        if (dot != std::string_view::npos) {
            const auto duration = parse_duration(payload.substr(dot + 1U));
            if (!duration.has_value()) {
                error = "duration must be 1m..365d using m, h or d";
                return std::nullopt;
            }
            parsed.duration_seconds = *duration;
        }
    }
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

    if (command.starts_with(self_register_prefix)) {
        const auto password = command.substr(self_register_prefix.size());
        if (!valid_password(password)) {
            error = "password must be 8-1024 printable UTF-8 bytes";
            return std::nullopt;
        }
        UserSetCommand parsed;
        parsed.action = UserSetAction::self_register;
        parsed.password = std::string(password);
        return parsed;
    }
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
    if (unwrap(command, disconnect_prefix, payload)) {
        return parse_username(payload, UserSetAction::disconnect_user, error);
    }
    if (unwrap(command, kick_prefix, payload)) {
        return parse_username(payload, UserSetAction::kick_user, error);
    }
    if (unwrap(command, protect_prefix, payload)) {
        return parse_username_class(payload,
                                    UserSetAction::set_kick_protection,
                                    false,
                                    error);
    }
    if (unwrap(command, hide_share_prefix, payload)) {
        return parse_username_flag(payload, UserSetAction::set_hide_share, error);
    }
    if (unwrap(command, hide_operator_prefix, payload)) {
        return parse_username_flag(
            payload, UserSetAction::set_hide_operator_key, error);
    }
    if (unwrap(command, note_prefix, payload, true)) {
        const auto dot = payload.find('.');
        if (dot == std::string_view::npos) {
            error = "expected [username.note]";
            return std::nullopt;
        }
        const auto username = payload.substr(0, dot);
        const auto note = payload.substr(dot + 1U);
        if (!valid_username(username)) {
            error = "invalid username";
            return std::nullopt;
        }
        if (!valid_note(note)) {
            error = "note must be at most 2000 printable UTF-8 bytes";
            return std::nullopt;
        }
        UserSetCommand parsed;
        parsed.action = UserSetAction::set_user_note;
        parsed.username = std::string(username);
        parsed.note = std::string(note);
        return parsed;
    }
    if (unwrap(command, self_visibility_prefix, payload)) {
        const auto user_class = checked_class(payload, error);
        if (!user_class.has_value()) return std::nullopt;
        UserSetCommand parsed;
        parsed.action = UserSetAction::set_self_visibility;
        parsed.user_class = *user_class;
        return parsed;
    }
    if (unwrap(command, auth_ip_remove_prefix, payload)) {
        return parse_username(payload, UserSetAction::remove_auth_ip, error);
    }
    if (unwrap(command, auth_ip_prefix, payload)) {
        const auto dot = payload.find('.');
        if (dot == std::string_view::npos) {
            error = "expected [username.IPv4]";
            return std::nullopt;
        }
        const auto username = payload.substr(0, dot);
        const auto address = payload.substr(dot + 1U);
        if (!valid_username(username) || !valid_ipv4(address)) {
            error = "invalid username or IPv4 address";
            return std::nullopt;
        }
        UserSetCommand parsed;
        parsed.action = UserSetAction::set_auth_ip;
        parsed.username = std::string(username);
        parsed.query = std::string(address);
        return parsed;
    }
    if (unwrap(command, email_prefix, payload, true)) {
        const auto dot = payload.find('.');
        if (dot == std::string_view::npos) {
            error = "expected [username.email]";
            return std::nullopt;
        }
        const auto username = payload.substr(0, dot);
        const auto email = payload.substr(dot + 1U);
        if (!valid_username(username) || !valid_email(email)) {
            error = "invalid username or email";
            return std::nullopt;
        }
        UserSetCommand parsed;
        parsed.action = UserSetAction::set_email;
        parsed.username = std::string(username);
        parsed.query = std::string(email);
        return parsed;
    }
    if (unwrap(command, public_note_prefix, payload, true)) {
        const auto dot = payload.find('.');
        if (dot == std::string_view::npos) {
            error = "expected [username.note]";
            return std::nullopt;
        }
        const auto username = payload.substr(0, dot);
        const auto note = payload.substr(dot + 1U);
        if (!valid_username(username) || !valid_note(note)) {
            error = "invalid username or public note";
            return std::nullopt;
        }
        UserSetCommand parsed;
        parsed.action = UserSetAction::set_public_note;
        parsed.username = std::string(username);
        parsed.note = std::string(note);
        return parsed;
    }
    if (unwrap(command, hide_kick_class_prefix, payload)) {
        return parse_username_class(
            payload, UserSetAction::set_hide_kick_class, false, error);
    }
    if (unwrap(command, hide_kick_prefix, payload)) {
        return parse_username_flag(
            payload, UserSetAction::set_hide_kick, error);
    }
    for (const auto& definition : timed_keys) {
        if (!command.starts_with(definition.prefix)) continue;
        if (!unwrap(command, definition.prefix, payload)) {
            error = "malformed timed-policy payload";
            return std::nullopt;
        }
        return parse_timed_policy(payload, definition, error);
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

    if (command.starts_with("!set key.")) {
        constexpr std::string_view prefix = "!set ";
        const auto assignment = command.find("=[", prefix.size());
        if (assignment != std::string_view::npos && command.back() == ']') {
            const auto key = command.substr(
                prefix.size(), assignment - prefix.size());
            const auto value = command.substr(
                assignment + 2U, command.size() - assignment - 3U);
            const auto normalized = normalize_hub_setting(key, value, error);
            if (!normalized.has_value()) return std::nullopt;
            UserSetCommand parsed;
            parsed.action = UserSetAction::set_hub_setting;
            parsed.setting_key = std::string(key);
            parsed.setting_value = *normalized;
            return parsed;
        }
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
                    hash_password(command.password),
                    command.actor_username);
                return {true, "user created: id=" + std::to_string(id) +
                    " username=" + command.username + " class=" +
                    std::to_string(static_cast<std::int16_t>(command.user_class))};
            }
            case UserSetAction::create_user_without_password: {
                const auto id = database_.create_user_without_password(
                    command.username,
                    command.user_class,
                    command.actor_username);
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
            case UserSetAction::set_kick_protection:
                if (!database_.set_kick_protect_class(
                        command.username,
                        static_cast<std::int16_t>(command.user_class))) {
                    return {false, "registered username not found"};
                }
                return {true, "kick/ban protection changed: username=" +
                    command.username + " protected_through_class=" +
                    std::to_string(static_cast<std::int16_t>(command.user_class))};
            case UserSetAction::set_hide_share:
                if (!database_.set_hide_share(
                        command.username, command.enabled)) {
                    return {false, "registered username not found"};
                }
                return {true, "share visibility changed: username=" +
                    command.username + " hidden=" +
                    (command.enabled ? "yes" : "no")};
            case UserSetAction::set_hide_operator_key:
                if (!database_.set_hide_operator_key(
                        command.username, command.enabled)) {
                    return {false, "registered username not found"};
                }
                return {true, "operator key visibility changed: username=" +
                    command.username + " hidden=" +
                    (command.enabled ? "yes" : "no")};
            case UserSetAction::set_user_note:
                if (!database_.set_user_note(command.username, command.note)) {
                    return {false, "registered username not found"};
                }
                return {true, command.note.empty()
                    ? "account note removed: username=" + command.username
                    : "account note stored: username=" + command.username};
            case UserSetAction::set_auth_ip:
                if (!database_.set_user_auth_ip(
                        command.username,
                        std::optional<std::string>{command.query})) {
                    return {false, "registered username not found"};
                }
                return {true, "authentication IPv4 changed: username=" +
                    command.username + " address=" + command.query};
            case UserSetAction::remove_auth_ip:
                if (!database_.set_user_auth_ip(command.username, std::nullopt)) {
                    return {false, "registered username not found"};
                }
                return {true, "authentication IPv4 removed: username=" +
                    command.username};
            case UserSetAction::set_email:
                if (!database_.set_user_email(command.username, command.query)) {
                    return {false, "registered username not found"};
                }
                return {true, command.query.empty()
                    ? "email removed: username=" + command.username
                    : "email stored: username=" + command.username};
            case UserSetAction::set_public_note:
                if (!database_.set_user_public_note(
                        command.username, command.note)) {
                    return {false, "registered username not found"};
                }
                return {true, command.note.empty()
                    ? "public note removed: username=" + command.username
                    : "public note stored: username=" + command.username};
            case UserSetAction::set_hide_kick:
                if (!database_.set_hide_kick(
                        command.username, command.enabled)) {
                    return {false, "registered username not found"};
                }
                return {true, "kick-message visibility changed: username=" +
                    command.username + " hidden=" +
                    (command.enabled ? "yes" : "no")};
            case UserSetAction::set_hide_kick_class:
                if (!database_.set_hide_kick_through_class(
                        command.username,
                        static_cast<std::int16_t>(command.user_class))) {
                    return {false, "registered username not found"};
                }
                return {true, "kick-message class threshold changed: username=" +
                    command.username + " hidden_through_class=" +
                    std::to_string(static_cast<std::int16_t>(command.user_class))};
            case UserSetAction::set_self_visibility:
                if (!database_.set_hide_from_class(
                        command.username,
                        static_cast<std::int16_t>(command.user_class))) {
                    return {false, "enabled registered username not found"};
                }
                return {true, "self visibility changed: username=" +
                    command.username + " visible_from_class=" +
                    std::to_string(static_cast<std::int16_t>(command.user_class))};
            case UserSetAction::set_timed_policy:
                if (!database_.set_timed_policy(
                        command.username,
                        command.policy_key,
                        command.duration_seconds)) {
                    return {false, "enabled registered username not found"};
                }
                return {true, "timed policy set: username=" + command.username +
                    " policy=" + command.policy_key + " duration_seconds=" +
                    std::to_string(command.duration_seconds)};
            case UserSetAction::remove_timed_policy:
                if (!database_.remove_timed_policy(
                        command.username, command.policy_key)) {
                    return {false, "registered username not found"};
                }
                return {true, "timed policy removed: username=" +
                    command.username + " policy=" + command.policy_key};
            case UserSetAction::show_user_info: {
                const auto details = database_.user_details(command.username);
                if (!details.has_value()) {
                    return {false, "registered username not found"};
                }
                const auto runtime = database_.runtime_policy(command.username);
                std::string policies = "none";
                if (!runtime.timed_policies.empty()) {
                    policies.clear();
                    bool first = true;
                    for (const auto& policy : runtime.timed_policies) {
                        if (!first) policies += ',';
                        first = false;
                        policies += policy.policy_key + "@" +
                            std::to_string(policy.expires_at);
                    }
                }
                return {true, "user info: id=" + std::to_string(details->id) +
                    " username=" + details->username + " class=" +
                    std::to_string(static_cast<std::int16_t>(details->user_class)) +
                    " (" + std::string(user_class_name(details->user_class)) + ")" +
                    " enabled=" + (details->enabled ? "yes" : "no") +
                    " password=" + (details->has_password ? "set" : "unset") +
                    " registered_at=" + details->created_at +
                    " registered_by=" +
                    (details->registered_by.empty() ? "<unknown>" : details->registered_by) +
                    " updated_at=" + details->updated_at +
                    " last_login_at=" +
                    (details->last_login_at.empty() ? "<never>" : details->last_login_at) +
                    " last_logout_at=" +
                    (details->last_logout_at.empty() ? "<never>" : details->last_logout_at) +
                    " login_count=" + std::to_string(details->login_count) +
                    " last_login_ip=" +
                    (details->last_login_ip.empty() ? "<none>" : details->last_login_ip) +
                    " email=" + (details->email.empty() ? "<empty>" : details->email) +
                    " password_change_required=" +
                    (details->password_change_required ? "yes" : "no") +
                    " auth_ip=" +
                    (details->auth_ip.empty() ? "<any>" : details->auth_ip) +
                    " kick_protect_class=" +
                    std::to_string(details->kick_protect_class) +
                    " hide_share=" + (details->hide_share ? "yes" : "no") +
                    " hide_operator_key=" +
                    (details->hide_operator_key ? "yes" : "no") +
                    " visible_from_class=" +
                    std::to_string(details->hide_from_class) +
                    " hide_kick=" + (details->hide_kick ? "yes" : "no") +
                    " hide_kick_through_class=" +
                    std::to_string(details->hide_kick_through_class) +
                    " timed_policies=" + policies +
                    " note=" + (details->note.empty() ? "<empty>" : details->note) +
                    " public_note=" +
                    (details->public_note.empty() ? "<empty>" : details->public_note)};
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
            case UserSetAction::self_register: {
                const auto id = database_.create_user(
                    command.username,
                    command.user_class,
                    hash_password(command.password),
                    command.username);
                return {true, "self-registration complete: id=" +
                    std::to_string(id) + " username=" + command.username +
                    " class=" +
                    std::to_string(static_cast<std::int16_t>(command.user_class))};
            }
            case UserSetAction::set_hub_setting:
                if (!database_.set_hub_setting(
                        command.setting_key, command.setting_value)) {
                    return {false, "invalid hub setting"};
                }
                return {true, "hub setting changed: " + command.setting_key +
                    "=" + command.setting_value};
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
           action == UserSetAction::disconnect_user ||
           action == UserSetAction::kick_user ||
           action == UserSetAction::show_ip_and_hostname ||
           action == UserSetAction::show_hostname ||
           action == UserSetAction::find_users_by_ip ||
           action == UserSetAction::find_users_by_ip_range ||
           action == UserSetAction::find_users_by_subnet;
}

}  // namespace dc24h
