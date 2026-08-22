/*
    anti_abuse.hpp

    v0.0.11:
        - declare temporary IP bans and password-failure throttling
        - declare per-IP connection, reconnect and clone protections
        - expose mAuthIP for account-to-address authorization

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace dc24h {

struct AntiAbuseSettings {
    std::uint32_t pwd_tmpban{900};
    std::uint32_t password_failure_limit{5};
    std::uint32_t password_failure_window{300};
    std::size_t max_users_from_ip{10};
    std::uint32_t reconnect_min_interval{2};
    std::size_t clone_detect_count{3};
    std::uint32_t clone_det_tban_time{600};
    std::uint32_t clone_ip_tban_time{900};
};

struct AdmissionDenial {
    std::string reason;
    std::uint32_t retry_after_seconds{0};
};

bool mAuthIP(std::string_view authorized_ip,
             std::string_view remote_ip) noexcept;

class AntiAbuse {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    explicit AntiAbuse(AntiAbuseSettings settings);

    void AddIPTempBan(std::string_view address,
                      std::uint32_t seconds,
                      std::string_view reason,
                      TimePoint now = Clock::now());
    bool LoginError(std::string_view address,
                    std::string_view username,
                    TimePoint now = Clock::now());
    void LoginSuccess(std::string_view address, std::string_view username);

    std::size_t CntConnIP(std::string_view address) const;
    std::optional<AdmissionDenial> AdmitConnection(
        std::string_view address,
        TimePoint now = Clock::now());
    void RecordDisconnect(std::string_view address,
                          std::string_view clone_fingerprint = {},
                          TimePoint now = Clock::now());

    bool CheckUserClone(std::string_view address,
                        std::string_view clone_fingerprint,
                        TimePoint now = Clock::now());

    std::optional<AdmissionDenial> ActiveTempBan(
        std::string_view address,
        TimePoint now = Clock::now());

private:
    struct TempBan {
        TimePoint expires_at;
        std::string reason;
    };

    void cleanup_failures_locked(std::deque<TimePoint>& failures,
                                 TimePoint now) const;
    void cleanup_locked(TimePoint now);
    void add_ip_temp_ban_locked(std::string_view address,
                                std::uint32_t seconds,
                                std::string_view reason,
                                TimePoint now);
    static std::string clone_key(std::string_view address,
                                 std::string_view fingerprint);

    AntiAbuseSettings settings_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, TempBan> temp_bans_;
    std::unordered_map<std::string, std::deque<TimePoint>> ip_failures_;
    std::unordered_map<std::string, std::deque<TimePoint>> account_failures_;
    std::unordered_map<std::string, std::size_t> connections_by_ip_;
    std::unordered_map<std::string, std::size_t> clones_;
    std::unordered_map<std::string, TimePoint> clone_last_seen_;
    std::unordered_map<std::string, TimePoint> last_disconnect_;
};

}  // namespace dc24h
