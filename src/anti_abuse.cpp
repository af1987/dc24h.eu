/*
    anti_abuse.cpp

    v0.0.11:
        - implement AddIPTempBan(), pwd_tmpban and LoginError() protection
        - implement max_users_from_ip, CntConnIP() and reconnect throttling
        - implement configurable CheckUserClone() anti-abuse enforcement

    Author: gpt-5.6-sol
    Date: 2026-08-22
*/

// ----------------------------------// DECLARATION //--

#include "anti_abuse.hpp"

#include <algorithm>
#include <stdexcept>

namespace dc24h {

bool mAuthIP(std::string_view authorized_ip,
             std::string_view remote_ip) noexcept {
    return authorized_ip.empty() || authorized_ip == remote_ip;
}

AntiAbuse::AntiAbuse(AntiAbuseSettings settings) : settings_(settings) {
    if (settings_.pwd_tmpban == 0U ||
        settings_.password_failure_limit == 0U ||
        settings_.password_failure_window == 0U ||
        settings_.max_users_from_ip == 0U ||
        settings_.reconnect_min_interval == 0U ||
        settings_.clone_det_tban_time == 0U ||
        settings_.clone_ip_tban_time == 0U) {
        throw std::invalid_argument("anti-abuse limits must be greater than zero");
    }
}

void AntiAbuse::add_ip_temp_ban_locked(std::string_view address,
                                       std::uint32_t seconds,
                                       std::string_view reason,
                                       TimePoint now) {
    const auto expiry = now + std::chrono::seconds(seconds);
    auto& ban = temp_bans_[std::string(address)];
    if (ban.expires_at < expiry) ban.expires_at = expiry;
    ban.reason = std::string(reason);
}

void AntiAbuse::AddIPTempBan(std::string_view address,
                             std::uint32_t seconds,
                             std::string_view reason,
                             TimePoint now) {
    if (address.empty() || seconds == 0U || reason.empty()) {
        throw std::invalid_argument("temporary IP ban requires address, duration and reason");
    }
    std::lock_guard lock(mutex_);
    cleanup_locked(now);
    add_ip_temp_ban_locked(address, seconds, reason, now);
}

void AntiAbuse::cleanup_failures_locked(std::deque<TimePoint>& failures,
                                        TimePoint now) const {
    const auto cutoff = now -
        std::chrono::seconds(settings_.password_failure_window);
    while (!failures.empty() && failures.front() <= cutoff) {
        failures.pop_front();
    }
}

void AntiAbuse::cleanup_locked(TimePoint now) {
    std::erase_if(temp_bans_, [now](const auto& entry) {
        return entry.second.expires_at <= now;
    });
    const auto clone_cutoff = now -
        std::chrono::seconds(settings_.clone_det_tban_time);
    for (auto it = clone_last_seen_.begin(); it != clone_last_seen_.end();) {
        if (it->second <= clone_cutoff && !clones_.contains(it->first)) {
            it = clone_last_seen_.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = ip_failures_.begin(); it != ip_failures_.end();) {
        cleanup_failures_locked(it->second, now);
        if (it->second.empty()) it = ip_failures_.erase(it);
        else ++it;
    }
    for (auto it = account_failures_.begin();
         it != account_failures_.end();) {
        cleanup_failures_locked(it->second, now);
        if (it->second.empty()) it = account_failures_.erase(it);
        else ++it;
    }
}

bool AntiAbuse::LoginError(std::string_view address,
                           std::string_view username,
                           TimePoint now) {
    if (address.empty() || username.empty()) return false;
    std::lock_guard lock(mutex_);
    cleanup_locked(now);
    constexpr std::size_t maximum_failure_keys = 65536U;
    if (!ip_failures_.contains(std::string(address)) &&
        ip_failures_.size() >= maximum_failure_keys) {
        ip_failures_.erase(ip_failures_.begin());
    }
    if (!account_failures_.contains(std::string(username)) &&
        account_failures_.size() >= maximum_failure_keys) {
        account_failures_.erase(account_failures_.begin());
    }
    auto& ip = ip_failures_[std::string(address)];
    auto& account = account_failures_[std::string(username)];
    cleanup_failures_locked(ip, now);
    cleanup_failures_locked(account, now);
    ip.push_back(now);
    account.push_back(now);
    if (ip.size() < settings_.password_failure_limit &&
        account.size() < settings_.password_failure_limit) {
        return false;
    }
    add_ip_temp_ban_locked(
        address, settings_.pwd_tmpban, "Too many failed password attempts", now);
    ip.clear();
    return true;
}

void AntiAbuse::LoginSuccess(std::string_view address,
                             std::string_view username) {
    std::lock_guard lock(mutex_);
    ip_failures_.erase(std::string(address));
    account_failures_.erase(std::string(username));
}

std::size_t AntiAbuse::CntConnIP(std::string_view address) const {
    std::lock_guard lock(mutex_);
    const auto it = connections_by_ip_.find(std::string(address));
    return it == connections_by_ip_.end() ? 0U : it->second;
}

std::optional<AdmissionDenial> AntiAbuse::ActiveTempBan(
    std::string_view address,
    TimePoint now) {
    std::lock_guard lock(mutex_);
    cleanup_locked(now);
    const auto it = temp_bans_.find(std::string(address));
    if (it == temp_bans_.end()) return std::nullopt;
    const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
        it->second.expires_at - now);
    return AdmissionDenial{
        it->second.reason,
        static_cast<std::uint32_t>(std::max<std::int64_t>(1, remaining.count()))};
}

std::optional<AdmissionDenial> AntiAbuse::AdmitConnection(
    std::string_view address,
    TimePoint now) {
    std::lock_guard lock(mutex_);
    cleanup_locked(now);

    const auto ban = temp_bans_.find(std::string(address));
    if (ban != temp_bans_.end()) {
        const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
            ban->second.expires_at - now);
        return AdmissionDenial{
            ban->second.reason,
            static_cast<std::uint32_t>(std::max<std::int64_t>(1, remaining.count()))};
    }

    const auto disconnected = last_disconnect_.find(std::string(address));
    if (disconnected != last_disconnect_.end() &&
        now - disconnected->second <
            std::chrono::seconds(settings_.reconnect_min_interval)) {
        add_ip_temp_ban_locked(address,
                               settings_.reconnect_min_interval,
                               "Reconnecting too fast",
                               now);
        return AdmissionDenial{
            "Reconnecting too fast", settings_.reconnect_min_interval};
    }

    auto& count = connections_by_ip_[std::string(address)];
    if (count >= settings_.max_users_from_ip) {
        return AdmissionDenial{"Too many connections from this IP", 0U};
    }
    ++count;
    return std::nullopt;
}

std::string AntiAbuse::clone_key(std::string_view address,
                                 std::string_view fingerprint) {
    return std::string(address) + "\n" + std::string(fingerprint);
}

bool AntiAbuse::CheckUserClone(std::string_view address,
                               std::string_view clone_fingerprint,
                               TimePoint now) {
    if (settings_.clone_detect_count == 0U || clone_fingerprint.empty()) {
        return false;
    }
    std::lock_guard lock(mutex_);
    cleanup_locked(now);
    const auto key = clone_key(address, clone_fingerprint);
    auto& count = clones_[key];
    if (count >= settings_.clone_detect_count) {
        add_ip_temp_ban_locked(address,
                               settings_.clone_ip_tban_time,
                               "Clone detection limit exceeded",
                               now);
        return true;
    }
    ++count;
    clone_last_seen_[key] = now;
    return false;
}

void AntiAbuse::RecordDisconnect(std::string_view address,
                                 std::string_view clone_fingerprint,
                                 TimePoint now) {
    std::lock_guard lock(mutex_);
    const auto address_key = std::string(address);
    const auto connection = connections_by_ip_.find(address_key);
    if (connection != connections_by_ip_.end()) {
        if (connection->second > 1U) --connection->second;
        else connections_by_ip_.erase(connection);
    }
    if (!clone_fingerprint.empty()) {
        const auto key = clone_key(address, clone_fingerprint);
        const auto clone = clones_.find(key);
        if (clone != clones_.end()) {
            if (clone->second > 1U) --clone->second;
            else clones_.erase(clone);
        }
        clone_last_seen_[key] = now;
    }
    last_disconnect_[address_key] = now;
}

}  // namespace dc24h
