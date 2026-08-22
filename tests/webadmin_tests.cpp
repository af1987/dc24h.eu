/*
    webadmin_tests.cpp

    - WebAdmin protocol and security regression tests

        v0.0.14:
            - verify fragmented ADC/HTTP classification and request bounds
            - verify loopback policy, bearer authentication and safe updates
            - verify status/settings JSON and dashboard responses
            - prevent localized digit grouping in HTTP Content-Length

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#include "webadmin_tests.hpp"

#include "config.hpp"
#include "webadmin.hpp"

#include <cassert>
#include <exception>
#include <locale>
#include <string>
#include <utility>
#include <vector>

namespace dc24h::tests {
namespace {

std::string request(std::string method,
                    std::string target,
                    std::string token = {},
                    std::string body = {}) {
    std::string result = std::move(method) + " " + std::move(target) +
        " HTTP/1.1\r\nHost: dc24h.eu\r\n";
    if (!token.empty()) result += "Authorization: Bearer " + token + "\r\n";
    result += "Content-Length: " + std::to_string(body.size()) +
        "\r\nConnection: close\r\n\r\n" + body;
    return result;
}

}  // namespace

int run_webadmin_tests() {
    assert(WebAdmin::classify_protocol("H") == ProtocolProbe::need_more);
    assert(WebAdmin::classify_protocol("HSUP ADBASE\n") == ProtocolProbe::adc);
    assert(WebAdmin::classify_protocol("G") == ProtocolProbe::need_more);
    assert(WebAdmin::classify_protocol(
        "GET /webadmin HTTP/1.1\r\n") == ProtocolProbe::http);
    assert(WebAdmin::classify_protocol(
        "GET broken\r\n") == ProtocolProbe::adc);

    const auto complete = request("GET", "/webadmin");
    assert(WebAdmin::request_state(complete, 4096U) ==
           HttpRequestState::complete);
    assert(WebAdmin::request_state(complete.substr(0, complete.size() - 1U),
                                   4096U) == HttpRequestState::incomplete);
    assert(WebAdmin::request_state(std::string(4097U, 'X'), 4096U) ==
           HttpRequestState::too_large);
    const auto long_request = request(
        "GET", "/" + std::string(1100U, 'a'));
    assert(WebAdmin::request_state(long_request, 4096U) ==
           HttpRequestState::too_large);
    assert(WebAdmin::request_state(
        "GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
        4096U) == HttpRequestState::invalid);

    Config config;
    config.webadmin.enabled = true;
    config.webadmin.loopback_only = true;
    config.webadmin.token =
        "0123456789abcdef0123456789abcdef0123456789abcdef";
    WebAdmin webadmin(config);
    std::vector<std::pair<std::string, std::string>> settings{
        {"key.nick.length.minimum", "3"},
        {"key.nick.prefix", ""}};
    bool audited = false;
    WebAdminRuntime runtime;
    runtime.online_clients = 7U;
    runtime.maximum_clients = 100U;
    runtime.settings = [&] { return settings; };
    runtime.update_setting = [&](std::string_view key,
                                 std::string_view value) {
        for (auto& setting : settings) {
            if (key != setting.first) continue;
            setting.second = value;
            return true;
        }
        return false;
    };
    runtime.audit = [&](std::string_view address,
                        std::string_view target,
                        bool success) {
        audited = address == "127.0.0.1" &&
            target == "key.nick.length.minimum" && success;
    };

    const auto dashboard = webadmin.handle(
        request("GET", "/webadmin"), "127.0.0.1", false, runtime);
    assert(dashboard.starts_with("HTTP/1.1 200 OK\r\n"));
    assert(dashboard.find("dc24h.eu WebAdmin") != std::string::npos);
    const auto forbidden = webadmin.handle(
        request("GET", "/webadmin"), "192.0.2.1", false, runtime);
    assert(forbidden.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    const auto unauthorized = webadmin.handle(
        request("GET", "/webadmin/api/v1/status"),
        "127.0.0.1", false, runtime);
    assert(unauthorized.starts_with("HTTP/1.1 401 Unauthorized\r\n"));

    const auto status = webadmin.handle(
        request("GET", "/webadmin/api/v1/status", config.webadmin.token),
        "127.0.0.1", true, runtime);
    assert(status.starts_with("HTTP/1.1 200 OK\r\n"));
    assert(status.find("Strict-Transport-Security") != std::string::npos);
    assert(status.find("\"online_clients\":7") != std::string::npos);
    const auto listed = webadmin.handle(
        request("GET", "/webadmin/api/v1/settings", config.webadmin.token),
        "127.0.0.1", false, runtime);
    assert(listed.find("key.nick.length.minimum") != std::string::npos);

    settings.clear();
    for (int index = 0; index < 30; ++index) {
        settings.emplace_back(
            "key.test." + std::to_string(index), std::string(48U, 'x'));
    }
    const std::locale previous_locale = std::locale();
    try {
        std::locale::global(std::locale("en_US.UTF-8"));
    } catch (const std::exception&) {
        std::locale::global(previous_locale);
    }
    const auto large_list = webadmin.handle(
        request("GET", "/webadmin/api/v1/settings", config.webadmin.token),
        "127.0.0.1", false, runtime);
    std::locale::global(previous_locale);
    assert(large_list.size() > 1000U);
    assert(large_list.find("Content-Length: 1,") == std::string::npos);
    settings = {{"key.nick.length.minimum", "3"}, {"key.nick.prefix", ""}};

    const auto updated = webadmin.handle(
        request("PUT", "/webadmin/api/v1/settings", config.webadmin.token,
                "key.nick.length.minimum\n4"),
        "127.0.0.1", false, runtime);
    assert(updated.starts_with("HTTP/1.1 200 OK\r\n"));
    assert(settings[0].second == "4");
    assert(audited);

    const auto empty_value = webadmin.handle(
        request("PUT", "/webadmin/api/v1/settings", config.webadmin.token,
                "key.nick.prefix\n"),
        "127.0.0.1", false, runtime);
    assert(empty_value.starts_with("HTTP/1.1 200 OK\r\n"));
    assert(settings[1].second.empty());

    const auto missing = webadmin.handle(
        request("PUT", "/webadmin/api/v1/settings", config.webadmin.token,
                "key.unknown\nvalue"),
        "127.0.0.1", false, runtime);
    assert(missing.starts_with("HTTP/1.1 404 Not Found\r\n"));
    return 0;
}

}  // namespace dc24h::tests

int main() {
    return dc24h::tests::run_webadmin_tests();
}
