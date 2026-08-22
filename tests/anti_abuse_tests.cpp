/*
    anti_abuse_tests.cpp

    v0.0.13:
        - verify eBT_FLOOD and eBT_PASSW typed temporary bans
        - verify the per-IP sliding protocol command-rate limit

    v0.0.11:
        - verify password temporary bans and independent account/IP counters
        - verify authorization IP, connection limits and reconnect throttling
        - verify configurable clone detection and release accounting

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#include "anti_abuse_tests.hpp"

#include "anti_abuse.hpp"

#include <cassert>
#include <chrono>
#include <iostream>

namespace dc24h::tests {

void run_anti_abuse_tests() {
    using namespace std::chrono_literals;
    const auto start = AntiAbuse::TimePoint{} + 1000s;

    assert(mAuthIP("", "192.0.2.10"));
    assert(mAuthIP("192.0.2.10", "192.0.2.10"));
    assert(!mAuthIP("192.0.2.10", "192.0.2.11"));

    AntiAbuseSettings limits;
    limits.max_users_from_ip = 2;
    limits.reconnect_min_interval = 3;
    limits.password_failure_limit = 3;
    limits.password_failure_window = 60;
    limits.pwd_tmpban = 30;
    limits.clone_detect_count = 2;
    limits.clone_det_tban_time = 60;
    limits.clone_ip_tban_time = 20;
    limits.protocol_flood_limit = 3;
    limits.protocol_flood_window = 10;
    limits.protocol_flood_tmpban = 15;
    AntiAbuse guard(limits);

    assert(!guard.AdmitConnection("192.0.2.10", start).has_value());
    assert(!guard.AdmitConnection("192.0.2.10", start).has_value());
    assert(guard.CntConnIP("192.0.2.10") == 2U);
    const auto connection_limit =
        guard.AdmitConnection("192.0.2.10", start);
    assert(connection_limit.has_value());
    assert(connection_limit->reason == "Too many connections from this IP");

    guard.RecordDisconnect("192.0.2.10", {}, start + 1s);
    const auto reconnect =
        guard.AdmitConnection("192.0.2.10", start + 2s);
    assert(reconnect.has_value());
    assert(reconnect->reason == "Reconnecting too fast");

    assert(!guard.LoginError("198.51.100.2", "alice", start));
    assert(!guard.LoginError("198.51.100.2", "alice", start + 1s));
    assert(guard.LoginError("198.51.100.2", "alice", start + 2s));
    const auto password_ban =
        guard.ActiveTempBan("198.51.100.2", start + 3s);
    assert(password_ban.has_value());
    assert(password_ban->reason == "Too many authentication failures");
    assert(password_ban->type == eBT_PASSW);
    guard.LoginSuccess("198.51.100.2", "alice");

    assert(!guard.CheckUserClone(
        "203.0.113.4", "AP=ncdc;VE=1.23.1;", start));
    assert(!guard.CheckUserClone(
        "203.0.113.4", "AP=ncdc;VE=1.23.1;", start + 1s));
    assert(guard.CheckUserClone(
        "203.0.113.4", "AP=ncdc;VE=1.23.1;", start + 2s));
    const auto clone_ban = guard.ActiveTempBan("203.0.113.4", start + 3s);
    assert(clone_ban.has_value());
    assert(clone_ban->reason == "Clone detection limit exceeded");
    assert(clone_ban->type == eBT_CLONE);

    assert(!guard.CheckProtocolFlood("203.0.113.9", start));
    assert(!guard.CheckProtocolFlood("203.0.113.9", start + 1s));
    assert(!guard.CheckProtocolFlood("203.0.113.9", start + 2s));
    assert(guard.CheckProtocolFlood("203.0.113.9", start + 3s));
    const auto flood_ban = guard.ActiveTempBan("203.0.113.9", start + 4s);
    assert(flood_ban.has_value());
    assert(flood_ban->reason == "Protocol flood limit exceeded");
    assert(flood_ban->type == eBT_FLOOD);

    guard.AddIPTempBan("203.0.113.6", 10, eBT_FLOOD, start);
    const auto typed_ban = guard.ActiveTempBan("203.0.113.6", start + 1s);
    assert(typed_ban.has_value());
    assert(typed_ban->type == eBT_FLOOD);

    guard.AddIPTempBan("203.0.113.5", 10, "manual test", start);
    assert(guard.ActiveTempBan("203.0.113.5", start + 9s).has_value());
    assert(!guard.ActiveTempBan("203.0.113.5", start + 10s).has_value());
}

}  // namespace dc24h::tests

int main() {
    dc24h::tests::run_anti_abuse_tests();
    std::cout << "anti-abuse tests passed\n";
    return 0;
}
