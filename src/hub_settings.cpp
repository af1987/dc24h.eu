/*
    hub_settings.cpp

    - persistent hub policy validation and nickname checks

        v0.0.07:
            - validate every class, nickname and auto-registration key
            - apply normalized MariaDB setting values to runtime policy
            - enforce UTF-8 code-point length, allowed characters and prefixes

    Author: gpt-5.6-sol
    Date: 2026-08-21
*/

// ----------------------------------// DECLARATION //--

#include "hub_settings.hpp"

#include "adc.hpp"
#include "user.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>
#include <vector>

namespace dc24h {
namespace {

template <typename T>
std::optional<T> parse_number(std::string_view value) noexcept {
    T parsed{};
    const auto result = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} ||
        result.ptr != value.data() + value.size()) return std::nullopt;
    return parsed;
}

bool is_difference_key(std::string_view key) noexcept {
    return key == "key.class.permission.register.difference" ||
           key == "key.class.permission.kick.difference" ||
           key == "key.class.permission.pm.difference" ||
           key == "key.class.permission.download.difference";
}

bool is_minimum_class_key(std::string_view key) noexcept {
    return key == "key.class.minimum.usehub" ||
           key == "key.class.minimum.usehub.passive" ||
           key == "key.class.minimum.register" ||
           key == "key.class.minimum.redirect" ||
           key == "key.class.minimum.broadcast" ||
           key == "key.class.minimum.broadcast.guests" ||
           key == "key.class.minimum.broadcast.registered" ||
           key == "key.class.minimum.broadcast.vip" ||
           key == "key.class.minimum.plugin.modify" ||
           key == "key.class.minimum.topic.modify" ||
           key == "key.class.minimum.trigger.modify";
}

bool is_share_key(std::string_view key) noexcept {
    return key == "key.user.autoreg.minimum.share.registered" ||
           key == "key.user.autoreg.minimum.share.vip" ||
           key == "key.user.autoreg.minimum.share.operator";
}

bool printable_value(std::string_view value, std::size_t maximum) noexcept {
    if (value.size() > maximum || !AdcProtocol::is_valid_utf8(value)) return false;
    for (const unsigned char character : value) {
        if (character < 0x20U || character == 0x7FU) return false;
    }
    return true;
}

std::size_t utf8_code_points(std::string_view value) noexcept {
    std::size_t count = 0;
    for (const unsigned char character : value) {
        if ((character & 0xC0U) != 0x80U) ++count;
    }
    return count;
}

std::vector<std::string_view> split_prefixes(std::string_view value) {
    std::vector<std::string_view> prefixes;
    std::size_t start = 0;
    while (start <= value.size()) {
        const auto separator = value.find(',', start);
        const auto end = separator == std::string_view::npos
            ? value.size()
            : separator;
        if (end > start) prefixes.push_back(value.substr(start, end - start));
        if (separator == std::string_view::npos) break;
        start = separator + 1U;
    }
    return prefixes;
}

bool starts_with_folded(std::string_view value,
                        std::string_view prefix,
                        bool folded) noexcept {
    if (value.size() < prefix.size()) return false;
    for (std::size_t index = 0; index < prefix.size(); ++index) {
        unsigned char left = static_cast<unsigned char>(value[index]);
        unsigned char right = static_cast<unsigned char>(prefix[index]);
        if (folded && left < 0x80U && right < 0x80U) {
            left = static_cast<unsigned char>(std::tolower(left));
            right = static_cast<unsigned char>(std::tolower(right));
        }
        if (left != right) return false;
    }
    return true;
}

}  // namespace

std::optional<std::string> normalize_hub_setting(
    std::string_view key,
    std::string_view value,
    std::string& error) {
    error.clear();
    if (is_difference_key(key)) {
        const auto parsed = parse_number<std::int16_t>(value);
        if (!parsed.has_value() || *parsed < 0 || *parsed > 10) {
            error = "class difference must be 0..10";
            return std::nullopt;
        }
        return std::to_string(*parsed);
    }
    if (is_minimum_class_key(key)) {
        const auto parsed = parse_number<std::int16_t>(value);
        if (!parsed.has_value() || !is_valid_user_class(*parsed)) {
            error = "minimum class must be a supported user class";
            return std::nullopt;
        }
        return std::to_string(*parsed);
    }
    if (key == "key.nick.length.maximum" ||
        key == "key.nick.length.minimum") {
        const auto parsed = parse_number<std::uint16_t>(value);
        if (!parsed.has_value() || *parsed == 0U || *parsed > 64U) {
            error = "nickname length must be 1..64";
            return std::nullopt;
        }
        return std::to_string(*parsed);
    }
    if (key == "key.nick.characters.allowed") {
        if (!printable_value(value, 512U)) {
            error = "allowed nickname characters must be printable UTF-8";
            return std::nullopt;
        }
        return std::string(value);
    }
    if (key == "key.nick.prefix" ||
        key == "key.nick.prefix.autoreg" ||
        key == "key.nick.prefix.country") {
        if (!printable_value(value, 256U)) {
            error = "nickname prefixes must be printable UTF-8";
            return std::nullopt;
        }
        return std::string(value);
    }
    if (key == "key.nick.prefix.nocase") {
        if (value != "0" && value != "1") {
            error = "flag must be 0 or 1";
            return std::nullopt;
        }
        return std::string(value);
    }
    if (key == "key.user.autoreg.class") {
        const auto parsed = parse_number<std::int16_t>(value);
        if (!parsed.has_value() || *parsed < -1 || *parsed > 3) {
            error = "auto-registration class must be -1 (disabled) or 0..3";
            return std::nullopt;
        }
        return std::to_string(*parsed);
    }
    if (is_share_key(key)) {
        const auto parsed = parse_number<std::uint64_t>(value);
        if (!parsed.has_value()) {
            error = "minimum share must be an unsigned byte count";
            return std::nullopt;
        }
        return std::to_string(*parsed);
    }
    if (key == "key.user.password.minimum.length") {
        const auto parsed = parse_number<std::uint16_t>(value);
        if (!parsed.has_value() || *parsed < 8U || *parsed > 128U) {
            error = "minimum password length must be 8..128 UTF-8 bytes";
            return std::nullopt;
        }
        return std::to_string(*parsed);
    }
    if (key == "key.user.password.initial.timeout" ||
        key == "key.account.password.setup.timeout") {
        const auto parsed = parse_number<std::uint32_t>(value);
        if (!parsed.has_value() || *parsed < 60U || *parsed > 86400U) {
            error = "initial password timeout must be 60..86400 seconds";
            return std::nullopt;
        }
        return std::to_string(*parsed);
    }

    error = "unknown hub setting key";
    return std::nullopt;
}

bool apply_hub_setting(HubSettings& settings,
                       std::string_view key,
                       std::string_view value) {
    const auto int16_value = [&] { return *parse_number<std::int16_t>(value); };
    const auto uint16_value = [&] { return *parse_number<std::uint16_t>(value); };
    const auto uint32_value = [&] { return *parse_number<std::uint32_t>(value); };
    const auto uint64_value = [&] { return *parse_number<std::uint64_t>(value); };

    if (key == "key.class.permission.register.difference") settings.register_class_difference = int16_value();
    else if (key == "key.class.permission.kick.difference") settings.kick_class_difference = int16_value();
    else if (key == "key.class.permission.pm.difference") settings.pm_class_difference = int16_value();
    else if (key == "key.class.permission.download.difference") settings.download_class_difference = int16_value();
    else if (key == "key.class.minimum.usehub") settings.minimum_use_hub = int16_value();
    else if (key == "key.class.minimum.usehub.passive") settings.minimum_use_hub_passive = int16_value();
    else if (key == "key.class.minimum.register") settings.minimum_register = int16_value();
    else if (key == "key.class.minimum.redirect") settings.minimum_redirect = int16_value();
    else if (key == "key.class.minimum.broadcast") settings.minimum_broadcast = int16_value();
    else if (key == "key.class.minimum.broadcast.guests") settings.minimum_broadcast_guests = int16_value();
    else if (key == "key.class.minimum.broadcast.registered") settings.minimum_broadcast_registered = int16_value();
    else if (key == "key.class.minimum.broadcast.vip") settings.minimum_broadcast_vip = int16_value();
    else if (key == "key.class.minimum.plugin.modify") settings.minimum_plugin_modify = int16_value();
    else if (key == "key.class.minimum.topic.modify") settings.minimum_topic_modify = int16_value();
    else if (key == "key.class.minimum.trigger.modify") settings.minimum_trigger_modify = int16_value();
    else if (key == "key.nick.length.maximum") settings.nick_length_maximum = uint16_value();
    else if (key == "key.nick.length.minimum") settings.nick_length_minimum = uint16_value();
    else if (key == "key.nick.characters.allowed") settings.nick_characters_allowed = std::string(value);
    else if (key == "key.nick.prefix") settings.nick_prefix = std::string(value);
    else if (key == "key.nick.prefix.nocase") settings.nick_prefix_nocase = value == "1";
    else if (key == "key.nick.prefix.autoreg") settings.nick_prefix_autoreg = std::string(value);
    else if (key == "key.nick.prefix.country") settings.nick_prefix_country = std::string(value);
    else if (key == "key.user.autoreg.class") settings.autoreg_class = int16_value();
    else if (key == "key.user.autoreg.minimum.share.registered") settings.autoreg_minimum_share_registered = uint64_value();
    else if (key == "key.user.autoreg.minimum.share.vip") settings.autoreg_minimum_share_vip = uint64_value();
    else if (key == "key.user.autoreg.minimum.share.operator") settings.autoreg_minimum_share_operator = uint64_value();
    else if (key == "key.user.password.minimum.length") settings.password_minimum_length = uint16_value();
    else if (key == "key.user.password.initial.timeout" || key == "key.account.password.setup.timeout") settings.password_initial_timeout = uint32_value();
    else return false;
    return true;
}

bool nickname_has_prefix(std::string_view nickname,
                         std::string_view prefix_list,
                         bool case_insensitive) {
    if (prefix_list.empty()) return true;
    const auto prefixes = split_prefixes(prefix_list);
    return std::any_of(prefixes.begin(), prefixes.end(), [&](const auto prefix) {
        return starts_with_folded(nickname, prefix, case_insensitive);
    });
}

bool nickname_allowed(std::string_view nickname,
                      const HubSettings& settings,
                      std::string& error) {
    error.clear();
    if (!AdcProtocol::is_valid_utf8(nickname)) {
        error = "nickname is not valid UTF-8";
        return false;
    }
    const auto length = utf8_code_points(nickname);
    if (length < settings.nick_length_minimum ||
        length > settings.nick_length_maximum) {
        error = "nickname length is outside configured limits";
        return false;
    }
    if (!settings.nick_characters_allowed.empty()) {
        for (const unsigned char character : nickname) {
            if (character >= 0x80U ||
                settings.nick_characters_allowed.find(
                    static_cast<char>(character)) == std::string::npos) {
                error = "nickname contains a character outside the configured set";
                return false;
            }
        }
    }
    if (!nickname_has_prefix(nickname,
                             settings.nick_prefix,
                             settings.nick_prefix_nocase)) {
        error = "nickname does not have an allowed prefix";
        return false;
    }
    return true;
}

}  // namespace dc24h
