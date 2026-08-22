/*
    moderation.hpp

    - typed kick and ban policy model

        v0.0.10:
            - add normalized exact and wildcard hostname ban targets
            - include reverse hostname input in admission matching

        v0.0.08:
            - define persistent moderation actions and target kinds
            - declare duration, target normalization and admission matching helpers
            - declare the shared printable nickname validator

    Author: gpt-5.6-sol
    Date: 2026-08-21
*/

// ----------------------------------// DECLARATION //--

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace dc24h {

enum class ModerationAction {
    kick,
    ban
};

enum class ModerationTargetKind {
    identity,
    nickname,
    cid,
    ipv4,
    ipv4_range,
    hostname,
    nickname_prefix,
    share_size
};

struct ModerationTarget {
    ModerationTargetKind kind{ModerationTargetKind::nickname};
    std::string value;
    std::string secondary_value;
};

struct ModerationEntry {
    std::uint64_t id{0};
    ModerationAction action{ModerationAction::ban};
    ModerationTarget target;
    std::string reason;
    std::string created_by;
    std::int64_t created_at{0};
    std::int64_t expires_at{0};
    std::int64_t revoked_at{0};
    std::string revoked_by;
    std::string revoke_reason;
};

std::string_view moderation_action_name(ModerationAction action) noexcept;
std::optional<ModerationAction> moderation_action_from_name(
    std::string_view value) noexcept;

std::string_view moderation_target_kind_name(
    ModerationTargetKind kind) noexcept;
std::optional<ModerationTargetKind> moderation_target_kind_from_name(
    std::string_view value) noexcept;

std::optional<std::uint64_t> parse_moderation_duration(
    std::string_view value,
    std::string& error);

std::optional<ModerationTarget> normalize_ban_target(
    std::string_view kind,
    std::string_view value,
    std::string& error);

bool valid_moderation_reason(std::string_view reason) noexcept;
bool valid_moderation_nickname(std::string_view nickname) noexcept;

bool moderation_target_matches(
    const ModerationTarget& target,
    std::string_view nickname,
    std::string_view cid,
    std::string_view ipv4,
    std::optional<std::uint64_t> share_size,
    std::string_view hostname = {}) noexcept;

bool moderation_entry_active(const ModerationEntry& entry,
                             std::int64_t now) noexcept;

}  // namespace dc24h
