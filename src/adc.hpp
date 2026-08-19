/*
    adc.hpp

    v0.0.02:
        - add ADC 1.0.4 PROTOCOL/IDENTIFY/NORMAL session state
        - add B/D/E/F routing decisions and feature filters
        - add sanitized INF metadata used by the server
        - require BASE and TIGR for the v0.0.02 session profile

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
#include <utility>
#include <vector>

namespace dc24h {

enum class AdcState {
    protocol,
    identify,
    normal
};

struct AdcSession {
    AdcState state{AdcState::protocol};
    std::string cid;
};

enum class RouteMode {
    none,
    broadcast,
    direct,
    echo,
    feature
};

struct AdcAction {
    std::vector<std::string> direct_messages;

    RouteMode route_mode{RouteMode::none};
    std::string routed_message;
    std::string target_sid;
    std::vector<std::string> required_features;
    std::vector<std::string> excluded_features;

    bool inf_update{false};
    bool became_normal{false};
    std::vector<std::pair<std::string, std::string>> inf_fields;

    bool disconnect{false};
};

class AdcProtocol {
public:
    AdcProtocol(std::string hub_name, std::string hub_description);

    AdcAction handle_line(std::string_view line,
                          std::string_view sid,
                          std::string_view remote_address,
                          AdcSession& session) const;

    static bool is_valid_utf8(std::string_view text) noexcept;
    static bool has_valid_escapes(std::string_view text) noexcept;
    static std::string escape_adc(std::string_view value);

private:
    std::string hub_name_;
    std::string hub_description_;
};

}  // namespace dc24h
