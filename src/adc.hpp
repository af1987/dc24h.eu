/*
    adc.hpp

    v0.0.01:
        - add ADC BASE handshake primitives
        - add UTF-8 validation and ADC string escaping
        - add routing decisions for INF, MSG, SCH and RES messages

    Author: gpt-5.6-sol
    Date: 2026-08-19
*/

#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace dc24h {

enum class BroadcastMode {
    none,
    others,
    all
};

struct AdcAction {
    std::vector<std::string> direct_messages;
    std::string broadcast_message;
    BroadcastMode broadcast_mode{BroadcastMode::none};
    bool disconnect{false};
};

class AdcProtocol {
public:
    AdcProtocol(std::string hub_name, std::string hub_description);

    AdcAction handle_line(std::string_view line, std::string_view sid) const;

    static bool is_valid_utf8(std::string_view text) noexcept;
    static std::string escape_adc(std::string_view value);

private:
    std::string hub_name_;
    std::string hub_description_;
};

}  // namespace dc24h
