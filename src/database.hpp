/*
    database.hpp

    - MariaDB persistence API

        v0.0.09:
            - expose validated hub-setting list/read operations for the local editor
            - make setting updates transaction-safe across daemon and CLI processes

        v0.0.08:
            - persist auditable kick and ban entries
            - expose filtered admission matching, listing and soft-revocation APIs
            - persist key.kicks and key.bans duration controls

        v0.0.07:
            - persist hub class, nickname and auto-registration settings
            - add account IP, email, public-note and kick-message controls
            - add password-setup state and login/logout telemetry

        v0.0.06:
            - add persistent moderation attributes and account notes
            - add expiring restrictions and delegated privileges
            - expose runtime policy snapshots for ADC routing enforcement

        v0.0.05:
            - add complete registered-user administration operations
            - expose account details and password reset state
            - protect the last enabled Master from deletion or disabling

        v0.0.04:
            - allow accounts without an initial password
            - add add-password-if-missing result model
            - add user listing by numeric class

        v0.0.03:
            - add persistent numeric user classes to account operations
            - add account creation, password update, class lookup and bootstrap checks

        v0.0.01:
            - add MariaDB connection lifecycle
            - add schema bootstrap and connection event persistence
            - serialize access to the MariaDB C connection

    Author: gpt-5.6-sol
    Date: 2026-08-21
*/

// ----------------------------------// DECLARATION //--

#pragma once

#include "config.hpp"
#include "hub_settings.hpp"
#include "moderation.hpp"
#include "user.hpp"

#include <mysql.h>

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dc24h {

enum class AddPasswordResult {
    added,
    already_set,
    user_not_found
};

enum class AccountChangeResult {
    changed,
    user_not_found,
    last_master
};

struct UserListEntry {
    std::uint64_t id{0};
    std::string username;
    UserClass user_class{UserClass::regular};
    bool enabled{true};
    bool has_password{false};
};

struct UserDetails {
    std::uint64_t id{0};
    std::string username;
    UserClass user_class{UserClass::regular};
    bool enabled{true};
    bool has_password{false};
    std::string created_at;
    std::string updated_at;
    std::int16_t kick_protect_class{-2};
    bool hide_share{false};
    bool hide_operator_key{false};
    std::int16_t hide_from_class{-1};
    std::string note;
    std::string registered_by;
    bool password_change_required{false};
    std::string last_login_at;
    std::string last_logout_at;
    std::uint64_t login_count{0};
    std::string last_login_ip;
    std::string auth_ip;
    std::string email;
    std::string public_note;
    bool hide_kick{false};
    std::int16_t hide_kick_through_class{-2};
};

struct TimedPolicyEntry {
    std::string policy_key;
    std::int64_t expires_at{0};
};

struct RuntimeUserPolicy {
    bool registered{false};
    bool enabled{false};
    UserClass user_class{UserClass::regular};
    std::int16_t kick_protect_class{-2};
    bool hide_share{false};
    bool hide_operator_key{false};
    std::int16_t hide_from_class{-1};
    std::string auth_ip;
    bool password_change_required{false};
    bool hide_kick{false};
    std::int16_t hide_kick_through_class{-2};
    std::vector<TimedPolicyEntry> timed_policies;
};

class Database {
public:
    explicit Database(const Config& config);
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    void connect();
    void initialize_schema();
    void record_event(std::string_view sid,
                      std::string_view event,
                      std::string_view remote_address);

    std::uint64_t create_user(std::string_view username,
                              UserClass user_class,
                              std::string_view password_hash,
                              std::string_view registered_by = {});
    std::uint64_t create_user_without_password(std::string_view username,
                                               UserClass user_class,
                                               std::string_view registered_by = {});
    bool update_user_password_by_id(std::uint64_t user_id,
                                    std::string_view password_hash);
    bool update_user_password_by_username(
        std::string_view username,
        const std::optional<std::string>& password_hash);
    AddPasswordResult add_user_password_if_missing(
        std::uint64_t user_id,
        std::string_view password_hash);
    AddPasswordResult add_user_password_if_missing(
        std::string_view username,
        std::string_view password_hash);
    std::vector<UserListEntry> users_by_class(UserClass user_class);
    std::optional<UserDetails> user_details(std::string_view username);
    AccountChangeResult remove_user(std::string_view username);
    AccountChangeResult set_user_enabled(std::string_view username,
                                         bool enabled);
    AccountChangeResult set_user_class(std::string_view username,
                                       UserClass user_class);
    bool set_kick_protect_class(std::string_view username,
                                std::int16_t protected_through_class);
    bool set_hide_share(std::string_view username, bool hidden);
    bool set_hide_operator_key(std::string_view username, bool hidden);
    bool set_user_note(std::string_view username, std::string_view note);
    bool set_user_auth_ip(std::string_view username,
                          const std::optional<std::string>& address);
    bool set_user_email(std::string_view username, std::string_view email);
    bool set_user_public_note(std::string_view username, std::string_view note);
    bool set_hide_kick(std::string_view username, bool hidden);
    bool set_hide_kick_through_class(std::string_view username,
                                     std::int16_t hidden_through_class);
    bool set_hide_from_class(std::string_view username,
                             std::int16_t minimum_visible_class);
    bool set_timed_policy(std::string_view username,
                          std::string_view policy_key,
                          std::uint64_t duration_seconds);
    bool remove_timed_policy(std::string_view username,
                             std::string_view policy_key);
    RuntimeUserPolicy runtime_policy(std::string_view username);
    HubSettings hub_settings();
    std::vector<std::pair<std::string, std::string>> hub_setting_entries();
    bool set_hub_setting(std::string_view key, std::string_view value);
    std::uint64_t add_moderation_entry(
        ModerationAction action,
        const ModerationTarget& target,
        std::string_view reason,
        std::string_view created_by,
        std::uint64_t duration_seconds);
    std::optional<ModerationEntry> active_moderation_match(
        std::string_view nickname,
        std::string_view cid,
        std::string_view ipv4,
        std::optional<std::uint64_t> share_size);
    std::optional<ModerationEntry> moderation_entry(std::uint64_t id);
    std::vector<ModerationEntry> moderation_entries(
        ModerationAction action,
        std::uint16_t limit);
    bool revoke_moderation_entry(std::uint64_t id,
                                 ModerationAction action,
                                 std::string_view revoked_by,
                                 std::string_view reason);
    void record_account_login(std::string_view username,
                              std::string_view remote_address);
    void record_account_logout(std::string_view username);
    std::optional<UserClass> user_class_for_username(
        std::string_view username);
    bool has_any_enabled_users();

private:
    std::string escape_locked(std::string_view value);
    void execute_locked(const std::string& sql);

    const Config& config_;
    MYSQL* connection_{nullptr};
    std::mutex mutex_;
};

}  // namespace dc24h
