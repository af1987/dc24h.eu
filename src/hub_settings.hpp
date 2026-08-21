/*
    hub_settings.hpp

    - persistent hub policy model and validation helpers

        v0.0.07:
            - define class permission and minimum-class settings
            - define nickname, auto-registration and password policy settings
            - declare canonical key validation and nickname checks

    Author: gpt-5.6-sol
    Date: 2026-08-21
*/

// ----------------------------------// DECLARATION //--

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace dc24h {

struct HubSettings {
    std::int16_t register_class_difference{2};
    std::int16_t kick_class_difference{0};
    std::int16_t pm_class_difference{10};
    std::int16_t download_class_difference{10};

    std::int16_t minimum_use_hub{0};
    std::int16_t minimum_use_hub_passive{0};
    std::int16_t minimum_register{3};
    std::int16_t minimum_redirect{3};
    std::int16_t minimum_broadcast{3};
    std::int16_t minimum_broadcast_guests{3};
    std::int16_t minimum_broadcast_registered{3};
    std::int16_t minimum_broadcast_vip{3};
    std::int16_t minimum_plugin_modify{5};
    std::int16_t minimum_topic_modify{5};
    std::int16_t minimum_trigger_modify{5};

    std::uint16_t nick_length_maximum{64};
    std::uint16_t nick_length_minimum{3};
    std::string nick_characters_allowed;
    std::string nick_prefix;
    bool nick_prefix_nocase{false};
    std::string nick_prefix_autoreg;
    std::string nick_prefix_country;

    std::int16_t autoreg_class{-1};
    std::uint64_t autoreg_minimum_share_registered{0};
    std::uint64_t autoreg_minimum_share_vip{0};
    std::uint64_t autoreg_minimum_share_operator{0};
    std::uint16_t password_minimum_length{8};
    std::uint32_t password_initial_timeout{300};
};

std::optional<std::string> normalize_hub_setting(
    std::string_view key,
    std::string_view value,
    std::string& error);

bool apply_hub_setting(HubSettings& settings,
                       std::string_view key,
                       std::string_view normalized_value);

bool nickname_allowed(std::string_view nickname,
                      const HubSettings& settings,
                      std::string& error);

bool nickname_has_prefix(std::string_view nickname,
                         std::string_view prefix_list,
                         bool case_insensitive);

}  // namespace dc24h
