/*
    webadmin.hpp

    - HTTP WebAdmin interface served on the ADC/ADCS hub port

        v0.0.14:
            - declare bounded HTTP request parsing and protocol detection
            - declare token-authenticated status and hub-settings endpoints
            - keep administration callbacks independent from HTTP parsing

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#pragma once

#include "config.hpp"

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dc24h {

enum class ProtocolProbe {
    need_more,
    adc,
    http
};

enum class HttpRequestState {
    incomplete,
    complete,
    invalid,
    too_large
};

struct WebAdminRuntime {
    std::size_t online_clients{0};
    std::size_t maximum_clients{0};
    std::function<std::vector<std::pair<std::string, std::string>>()> settings;
    std::function<bool(std::string_view, std::string_view)> update_setting;
    std::function<void(std::string_view, std::string_view, bool)> audit;
};

class WebAdmin {
public:
    explicit WebAdmin(const Config& config);

    static ProtocolProbe classify_protocol(std::string_view bytes) noexcept;
    static HttpRequestState request_state(std::string_view bytes,
                                          std::size_t maximum_size) noexcept;

    std::string handle(std::string_view request,
                       std::string_view remote_address,
                       bool secure_transport,
                       const WebAdminRuntime& runtime) const;

private:
    const Config& config_;
};

}  // namespace dc24h
