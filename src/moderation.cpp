/*
    moderation.cpp

    - typed kick and ban policy helpers

        v0.0.08:
            - normalize nickname, CID, IPv4, range, prefix and share targets
            - parse bounded temporary durations and permanent bans
            - match active moderation targets during ADC admission
            - validate nicknames and reasons by UTF-8 code point

    Author: gpt-5.6-sol
    Date: 2026-08-21
*/

// ----------------------------------// DECLARATION //--

#include "moderation.hpp"

#include "adc.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>

namespace dc24h {
namespace {

constexpr std::uint64_t day_seconds = 24U * 60U * 60U;
constexpr std::uint64_t maximum_duration_seconds = 365U * day_seconds;

bool printable_utf8(std::string_view value,
                    std::size_t maximum_code_points,
                    bool allow_space) noexcept {
    if (value.empty() || !AdcProtocol::is_valid_utf8(value)) return false;
    std::size_t code_points = 0;
    for (std::size_t index = 0; index < value.size(); ++index) {
        const auto character = static_cast<unsigned char>(value[index]);
        if ((character & 0xC0U) != 0x80U) ++code_points;
        if (character < 0x20U || character == 0x7FU ||
            (!allow_space && character == 0x20U) || character == '|') {
            return false;
        }
        if (character == 0xC2U && index + 1U < value.size()) {
            const auto next = static_cast<unsigned char>(value[index + 1U]);
            if (next >= 0x80U && next <= 0x9FU) return false;
        }
    }
    return code_points <= maximum_code_points;
}

std::optional<std::uint32_t> ipv4_number(std::string_view value) noexcept {
    if (value.empty() || value.size() >= INET_ADDRSTRLEN) return std::nullopt;
    in_addr address{};
    const std::string copy(value);
    if (::inet_pton(AF_INET, copy.c_str(), &address) != 1) return std::nullopt;
    return ntohl(address.s_addr);
}

std::string ipv4_text(std::uint32_t value) {
    in_addr address{};
    address.s_addr = htonl(value);
    char buffer[INET_ADDRSTRLEN]{};
    if (::inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == nullptr) {
        return {};
    }
    return buffer;
}

bool ascii_equal(std::string_view left, std::string_view right) noexcept {
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        unsigned char left_character =
            static_cast<unsigned char>(left[index]);
        unsigned char right_character =
            static_cast<unsigned char>(right[index]);
        if (left_character < 0x80U) {
            left_character = static_cast<unsigned char>(
                std::tolower(left_character));
        }
        if (right_character < 0x80U) {
            right_character = static_cast<unsigned char>(
                std::tolower(right_character));
        }
        if (left_character != right_character) return false;
    }
    return true;
}

bool ascii_starts_with(std::string_view value,
                       std::string_view prefix) noexcept {
    return value.size() >= prefix.size() &&
        ascii_equal(value.substr(0, prefix.size()), prefix);
}

std::optional<ModerationTarget> normalize_range(
    std::string_view value,
    std::string& error) {
    std::uint32_t first = 0;
    std::uint32_t last = 0;
    const auto dots = value.find("..");
    const auto slash = value.find('/');

    if (dots != std::string_view::npos) {
        const auto low = ipv4_number(value.substr(0, dots));
        const auto high = ipv4_number(value.substr(dots + 2U));
        if (!low.has_value() || !high.has_value() || *low > *high) {
            error = "IPv4 range must be low..high with low not above high";
            return std::nullopt;
        }
        first = *low;
        last = *high;
    } else if (slash != std::string_view::npos) {
        const auto address = ipv4_number(value.substr(0, slash));
        std::uint16_t bits = 0;
        const auto bit_text = value.substr(slash + 1U);
        const auto parsed = std::from_chars(
            bit_text.data(), bit_text.data() + bit_text.size(), bits);
        if (!address.has_value() || parsed.ec != std::errc{} ||
            parsed.ptr != bit_text.data() + bit_text.size() || bits > 32U) {
            error = "IPv4 subnet must use address/0..32";
            return std::nullopt;
        }
        const std::uint32_t mask = bits == 0U
            ? 0U
            : std::numeric_limits<std::uint32_t>::max() << (32U - bits);
        first = *address & mask;
        last = first | ~mask;
    } else {
        error = "IPv4 range must use low..high or address/mask";
        return std::nullopt;
    }

    ModerationTarget target;
    target.kind = ModerationTargetKind::ipv4_range;
    target.value = ipv4_text(first);
    target.secondary_value = ipv4_text(last);
    return target;
}

}  // namespace

std::string_view moderation_action_name(ModerationAction action) noexcept {
    return action == ModerationAction::kick ? "kick" : "ban";
}

std::optional<ModerationAction> moderation_action_from_name(
    std::string_view value) noexcept {
    if (value == "kick") return ModerationAction::kick;
    if (value == "ban") return ModerationAction::ban;
    return std::nullopt;
}

std::string_view moderation_target_kind_name(
    ModerationTargetKind kind) noexcept {
    switch (kind) {
        case ModerationTargetKind::identity: return "identity";
        case ModerationTargetKind::nickname: return "nick";
        case ModerationTargetKind::cid: return "cid";
        case ModerationTargetKind::ipv4: return "ip";
        case ModerationTargetKind::ipv4_range: return "range";
        case ModerationTargetKind::nickname_prefix: return "prefix";
        case ModerationTargetKind::share_size: return "share";
    }
    return "unknown";
}

std::optional<ModerationTargetKind> moderation_target_kind_from_name(
    std::string_view value) noexcept {
    if (value == "identity") return ModerationTargetKind::identity;
    if (value == "nick") return ModerationTargetKind::nickname;
    if (value == "cid") return ModerationTargetKind::cid;
    if (value == "ip") return ModerationTargetKind::ipv4;
    if (value == "range") return ModerationTargetKind::ipv4_range;
    if (value == "prefix") return ModerationTargetKind::nickname_prefix;
    if (value == "share") return ModerationTargetKind::share_size;
    return std::nullopt;
}

std::optional<std::uint64_t> parse_moderation_duration(
    std::string_view value,
    std::string& error) {
    error.clear();
    if (value == "permanent") return 0U;
    if (value.size() < 2U) {
        error = "duration must use s, m, h, d, w, M or y";
        return std::nullopt;
    }

    const char unit = value.back();
    const auto number = value.substr(0, value.size() - 1U);
    std::uint64_t amount = 0;
    const auto parsed = std::from_chars(
        number.data(), number.data() + number.size(), amount);
    if (parsed.ec != std::errc{} ||
        parsed.ptr != number.data() + number.size() || amount == 0U) {
        error = "duration amount must be a positive integer";
        return std::nullopt;
    }

    std::uint64_t multiplier = 0;
    switch (unit) {
        case 's': multiplier = 1U; break;
        case 'm': multiplier = 60U; break;
        case 'h': multiplier = 60U * 60U; break;
        case 'd': multiplier = day_seconds; break;
        case 'w': multiplier = 7U * day_seconds; break;
        case 'M': multiplier = 30U * day_seconds; break;
        case 'y': multiplier = maximum_duration_seconds; break;
        default:
            error = "duration must use s, m, h, d, w, M or y";
            return std::nullopt;
    }
    if (amount > maximum_duration_seconds / multiplier) {
        error = "duration must not exceed 365 days";
        return std::nullopt;
    }
    const auto seconds = amount * multiplier;
    if (seconds > maximum_duration_seconds) {
        error = "duration must not exceed 365 days";
        return std::nullopt;
    }
    return seconds;
}

std::optional<ModerationTarget> normalize_ban_target(
    std::string_view kind,
    std::string_view value,
    std::string& error) {
    error.clear();
    ModerationTarget target;

    if (kind == "nick") {
        if (!printable_utf8(value, 64U, true)) {
            error = "nickname target must be 1..64 printable UTF-8 characters";
            return std::nullopt;
        }
        target.kind = ModerationTargetKind::nickname;
        target.value = std::string(value);
        return target;
    }
    if (kind == "cid") {
        if (value.size() != 39U ||
            !std::all_of(value.begin(), value.end(), [](char character) {
                return (character >= 'A' && character <= 'Z') ||
                    (character >= '2' && character <= '7');
            })) {
            error = "CID target must be 39 uppercase Base32 characters";
            return std::nullopt;
        }
        target.kind = ModerationTargetKind::cid;
        target.value = std::string(value);
        return target;
    }
    if (kind == "ip") {
        const auto address = ipv4_number(value);
        if (!address.has_value()) {
            error = "IP target must be a valid IPv4 address";
            return std::nullopt;
        }
        target.kind = ModerationTargetKind::ipv4;
        target.value = ipv4_text(*address);
        return target;
    }
    if (kind == "range") return normalize_range(value, error);
    if (kind == "prefix") {
        if (!printable_utf8(value, 64U, true)) {
            error = "nickname prefix must be 1..64 printable UTF-8 characters";
            return std::nullopt;
        }
        target.kind = ModerationTargetKind::nickname_prefix;
        target.value = std::string(value);
        return target;
    }
    if (kind == "share") {
        std::uint64_t bytes = 0;
        const auto parsed = std::from_chars(
            value.data(), value.data() + value.size(), bytes);
        if (value.empty() || parsed.ec != std::errc{} ||
            parsed.ptr != value.data() + value.size()) {
            error = "share target must be an unsigned byte count";
            return std::nullopt;
        }
        target.kind = ModerationTargetKind::share_size;
        target.value = std::to_string(bytes);
        return target;
    }

    error = "ban target kind must be nick, cid, ip, range, prefix or share";
    return std::nullopt;
}

bool valid_moderation_reason(std::string_view reason) noexcept {
    return printable_utf8(reason, 1000U, true);
}

bool valid_moderation_nickname(std::string_view nickname) noexcept {
    return printable_utf8(nickname, 64U, true);
}

bool moderation_target_matches(
    const ModerationTarget& target,
    std::string_view nickname,
    std::string_view cid,
    std::string_view ipv4,
    std::optional<std::uint64_t> share_size) noexcept {
    switch (target.kind) {
        case ModerationTargetKind::identity:
            return (!nickname.empty() && ascii_equal(target.value, nickname)) ||
                (!cid.empty() && target.secondary_value == cid);
        case ModerationTargetKind::nickname:
            return !nickname.empty() && ascii_equal(target.value, nickname);
        case ModerationTargetKind::cid:
            return !cid.empty() && target.value == cid;
        case ModerationTargetKind::ipv4:
            return !ipv4.empty() && target.value == ipv4;
        case ModerationTargetKind::ipv4_range: {
            const auto address = ipv4_number(ipv4);
            const auto first = ipv4_number(target.value);
            const auto last = ipv4_number(target.secondary_value);
            return address.has_value() && first.has_value() && last.has_value() &&
                *address >= *first && *address <= *last;
        }
        case ModerationTargetKind::nickname_prefix:
            return !nickname.empty() &&
                ascii_starts_with(nickname, target.value);
        case ModerationTargetKind::share_size: {
            if (!share_size.has_value()) return false;
            std::uint64_t expected = 0;
            const auto parsed = std::from_chars(
                target.value.data(),
                target.value.data() + target.value.size(),
                expected);
            return parsed.ec == std::errc{} &&
                parsed.ptr == target.value.data() + target.value.size() &&
                *share_size == expected;
        }
    }
    return false;
}

bool moderation_entry_active(const ModerationEntry& entry,
                             std::int64_t now) noexcept {
    return entry.revoked_at == 0 &&
        (entry.expires_at == 0 || entry.expires_at > now);
}

}  // namespace dc24h
