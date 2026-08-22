/*
    database.cpp

    - MariaDB persistence implementation

        v0.0.10:
            - migrate moderation constraints for exact/wildcard host bans
            - filter and match active hostname targets during admission

        v0.0.09:
            - list validated hub settings for the local administration tool
            - validate complete setting snapshots inside row-locking transactions
            - preserve cross-setting invariants during concurrent updates

        v0.0.08:
            - create and query auditable kick and ban entries
            - add symmetric soft-revocation and indexed admission matching
            - seed and cross-validate key.kicks and key.bans
            - force the MariaDB session to UTC for expiry correctness

        v0.0.07:
            - migrate account controls and authentication telemetry
            - seed and load validated hub settings
            - persist auto-registration and account profile updates

        v0.0.06:
            - persist moderation attributes and private account notes
            - add expiring restriction/privilege rows with validated policy keys
            - expose runtime policy snapshots for routing enforcement

        v0.0.05:
            - list enabled and disabled users with password state
            - add account lookup, removal, enable/disable and class changes
            - add password reset and first-password assignment by username
            - prevent removal, disabling or demotion of the last enabled Master

        v0.0.04:
            - make account password_hash nullable for passwordless registrations
            - add conditional password insertion that never overwrites an existing password
            - add enabled-user listing filtered by numeric class

        v0.0.03:
            - extend accounts with validated numeric user_class values
            - add account creation and password changes by database id
            - add class lookup and empty-account bootstrap check for protected !set commands

        v0.0.01:
            - connect to MariaDB using utf8mb4
            - create initial operational tables
            - record connect/disconnect events with escaped values

    Author: gpt-5.6-sol
    Date: 2026-08-21
*/

// ----------------------------------// DECLARATION //--

#include "database.hpp"

#include <array>
#include <charconv>
#include <ctime>
#include <limits>
#include <stdexcept>
#include <vector>

namespace dc24h {
namespace {

bool valid_policy_key(std::string_view key) noexcept {
    constexpr std::array<std::string_view, 9> keys{
        "gag", "no_download", "no_chat", "no_pm", "no_search",
        "can_kick", "hide_share", "can_register", "opchat"};
    for (const auto candidate : keys) {
        if (candidate == key) return true;
    }
    return false;
}

template <typename T>
T database_number(const char* value, std::string_view field) {
    if (value == nullptr) {
        throw std::runtime_error(
            "NULL moderation field stored for " + std::string(field));
    }
    const std::string_view text(value);
    T parsed{};
    const auto result = std::from_chars(
        text.data(), text.data() + text.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        throw std::runtime_error(
            "invalid moderation field stored for " + std::string(field));
    }
    return parsed;
}

ModerationEntry moderation_entry_from_row(MYSQL_ROW row) {
    if (row == nullptr) {
        throw std::runtime_error("missing moderation row");
    }
    const auto action = row[1] == nullptr
        ? std::nullopt
        : moderation_action_from_name(row[1]);
    const auto target_kind = row[2] == nullptr
        ? std::nullopt
        : moderation_target_kind_from_name(row[2]);
    if (!action.has_value() || !target_kind.has_value()) {
        throw std::runtime_error("invalid moderation type stored in database");
    }

    ModerationEntry entry;
    entry.id = database_number<std::uint64_t>(row[0], "id");
    entry.action = *action;
    entry.target.kind = *target_kind;
    entry.target.value = row[3] == nullptr ? std::string{} : std::string(row[3]);
    entry.target.secondary_value =
        row[4] == nullptr ? std::string{} : std::string(row[4]);
    entry.reason = row[5] == nullptr ? std::string{} : std::string(row[5]);
    entry.created_by = row[6] == nullptr ? std::string{} : std::string(row[6]);
    entry.created_at = database_number<std::int64_t>(row[7], "created_at");
    entry.expires_at = database_number<std::int64_t>(row[8], "expires_at");
    entry.revoked_at = database_number<std::int64_t>(row[9], "revoked_at");
    entry.revoked_by = row[10] == nullptr ? std::string{} : std::string(row[10]);
    entry.revoke_reason =
        row[11] == nullptr ? std::string{} : std::string(row[11]);
    return entry;
}

constexpr std::string_view moderation_select_columns =
    "id,action_type,target_type,target_value,secondary_value,reason,created_by,"
    "CAST(UNIX_TIMESTAMP(created_at) AS SIGNED),"
    "COALESCE(CAST(UNIX_TIMESTAMP(expires_at) AS SIGNED),0),"
    "COALESCE(CAST(UNIX_TIMESTAMP(revoked_at) AS SIGNED),0),"
    "COALESCE(revoked_by,''),"
    "COALESCE(revoke_reason,'')";

constexpr std::string_view hub_settings_where =
    "setting_key IN ('key.kicks','key.bans') "
    "OR setting_key LIKE 'key.class.%' "
    "OR setting_key LIKE 'key.nick.%' "
    "OR setting_key LIKE 'key.user.autoreg.%' "
    "OR setting_key='key.user.password.minimum.length' "
    "OR setting_key='key.user.password.initial.timeout'";

constexpr std::size_t canonical_hub_setting_count = 30U;

struct HubSettingsSnapshot {
    HubSettings settings;
    std::vector<std::pair<std::string, std::string>> entries;
};

HubSettingsSnapshot validated_hub_settings(
    MYSQL_RES* result,
    std::optional<std::pair<std::string_view, std::string_view>> replacement =
        std::nullopt) {
    if (result == nullptr) {
        throw std::invalid_argument("missing MariaDB settings result");
    }
    HubSettingsSnapshot snapshot;
    bool replaced = false;
    while (MYSQL_ROW row = mysql_fetch_row(result)) {
        if (row[0] == nullptr || row[1] == nullptr) continue;
        const std::string_view key(row[0]);
        const std::string_view value =
            replacement.has_value() && replacement->first == key
                ? (replaced = true, replacement->second)
                : std::string_view(row[1]);
        std::string error;
        const auto normalized = normalize_hub_setting(key, value, error);
        if (!normalized.has_value() ||
            !apply_hub_setting(snapshot.settings, key, *normalized)) {
            throw std::runtime_error(
                "invalid hub setting stored for " + std::string(key));
        }
        snapshot.entries.emplace_back(key, *normalized);
    }
    if (replacement.has_value() && !replaced) {
        if (!apply_hub_setting(snapshot.settings,
                               replacement->first,
                               replacement->second)) {
            throw std::runtime_error("invalid replacement hub setting");
        }
        snapshot.entries.emplace_back(
            replacement->first, replacement->second);
    }
    if (snapshot.entries.size() != canonical_hub_setting_count) {
        throw std::runtime_error(
            "expected 30 canonical hub settings, found " +
            std::to_string(snapshot.entries.size()));
    }
    if (snapshot.settings.nick_length_minimum >
        snapshot.settings.nick_length_maximum) {
        throw std::runtime_error(
            "nickname minimum length exceeds maximum length");
    }
    if (snapshot.settings.kick_rejoin_delay_seconds >
        snapshot.settings.maximum_temporary_ban_seconds) {
        throw std::runtime_error(
            "kick rejoin delay exceeds temporary ban maximum");
    }
    return snapshot;
}

}  // namespace

Database::Database(const Config& config) : config_(config) {}

Database::~Database() {
    std::lock_guard lock(mutex_);
    if (connection_ != nullptr) {
        mysql_close(connection_);
        connection_ = nullptr;
    }
}

void Database::connect() {
    std::lock_guard lock(mutex_);

    connection_ = mysql_init(nullptr);
    if (connection_ == nullptr) {
        throw std::runtime_error("mysql_init failed");
    }

    unsigned int timeout_seconds = 5;
    mysql_options(connection_, MYSQL_OPT_CONNECT_TIMEOUT, &timeout_seconds);

    const bool option_file = !config_.database_config_path.empty();
    if (option_file) {
        if (mysql_options(connection_,
                          MYSQL_READ_DEFAULT_FILE,
                          config_.database_config_path.c_str()) != 0 ||
            mysql_options(connection_, MYSQL_READ_DEFAULT_GROUP, "client") != 0) {
            throw std::runtime_error(
                "Unable to load MariaDB client options from " +
                config_.database_config_path);
        }
    }

    if (mysql_real_connect(connection_,
                           option_file ? nullptr : config_.database_host.c_str(),
                           option_file ? nullptr : config_.database_user.c_str(),
                           option_file ? nullptr : config_.database_password.c_str(),
                           option_file ? nullptr : config_.database_name.c_str(),
                           option_file ? 0U : config_.database_port,
                           nullptr,
                           0) == nullptr) {
        const std::string error = mysql_error(connection_);
        mysql_close(connection_);
        connection_ = nullptr;
        throw std::runtime_error("MariaDB connection failed: " + error);
    }

    if (mysql_set_character_set(connection_, "utf8mb4") != 0) {
        throw std::runtime_error(
            "Unable to select utf8mb4: " +
            std::string(mysql_error(connection_)));
    }
    execute_locked("SET time_zone='+00:00'");
}

void Database::initialize_schema() {
    std::lock_guard lock(mutex_);

    execute_locked(
        "CREATE TABLE IF NOT EXISTS connection_events ("
        "id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        "sid VARCHAR(4) NOT NULL,"
        "event_type VARCHAR(32) NOT NULL,"
        "remote_address VARCHAR(64) NOT NULL,"
        "created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),"
        "INDEX idx_connection_events_created_at (created_at),"
        "INDEX idx_connection_events_sid (sid)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    execute_locked(
        "CREATE TABLE IF NOT EXISTS accounts ("
        "id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        "nick VARCHAR(64) NOT NULL UNIQUE,"
        "password_hash VARCHAR(255) NULL,"
        "role ENUM('user','operator','admin') NOT NULL DEFAULT 'user',"
        "user_class SMALLINT NOT NULL DEFAULT 0,"
        "enabled BOOLEAN NOT NULL DEFAULT TRUE,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP "
        "ON UPDATE CURRENT_TIMESTAMP,"
        "kick_protect_class SMALLINT NOT NULL DEFAULT -2,"
        "hide_share BOOLEAN NOT NULL DEFAULT FALSE,"
        "hide_operator_key BOOLEAN NOT NULL DEFAULT FALSE,"
        "hide_from_class SMALLINT NOT NULL DEFAULT -1,"
        "account_note TEXT NULL,"
        "registered_by VARCHAR(64) NULL,"
        "password_change_required BOOLEAN NOT NULL DEFAULT FALSE,"
        "last_login_at TIMESTAMP NULL,"
        "last_logout_at TIMESTAMP NULL,"
        "login_count BIGINT UNSIGNED NOT NULL DEFAULT 0,"
        "last_login_ip VARCHAR(45) NULL,"
        "auth_ip VARCHAR(45) NULL,"
        "email VARCHAR(254) NULL,"
        "public_note TEXT NULL,"
        "hide_kick BOOLEAN NOT NULL DEFAULT FALSE,"
        "hide_kick_through_class SMALLINT NOT NULL DEFAULT -2,"
        "INDEX idx_accounts_user_class (user_class)"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    execute_locked(
        "ALTER TABLE accounts "
        "ADD COLUMN IF NOT EXISTS user_class SMALLINT NOT NULL DEFAULT 0");

    execute_locked(
        "ALTER TABLE accounts "
        "MODIFY COLUMN password_hash VARCHAR(255) NULL");

    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS updated_at "
        "TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP "
        "ON UPDATE CURRENT_TIMESTAMP");

    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS kick_protect_class "
        "SMALLINT NOT NULL DEFAULT -2");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS hide_share "
        "BOOLEAN NOT NULL DEFAULT FALSE");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS hide_operator_key "
        "BOOLEAN NOT NULL DEFAULT FALSE");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS hide_from_class "
        "SMALLINT NOT NULL DEFAULT -1");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS account_note TEXT NULL");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS registered_by VARCHAR(64) NULL");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS password_change_required "
        "BOOLEAN NOT NULL DEFAULT FALSE");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP NULL");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS last_logout_at TIMESTAMP NULL");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS login_count "
        "BIGINT UNSIGNED NOT NULL DEFAULT 0");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR(45) NULL");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS auth_ip VARCHAR(45) NULL");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS email VARCHAR(254) NULL");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS public_note TEXT NULL");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS hide_kick "
        "BOOLEAN NOT NULL DEFAULT FALSE");
    execute_locked(
        "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS hide_kick_through_class "
        "SMALLINT NOT NULL DEFAULT -2");

    execute_locked(
        "CREATE TABLE IF NOT EXISTS user_timed_policies ("
        "account_id BIGINT UNSIGNED NOT NULL,"
        "policy_key VARCHAR(32) NOT NULL,"
        "expires_at TIMESTAMP(6) NOT NULL,"
        "created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),"
        "updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) "
        "ON UPDATE CURRENT_TIMESTAMP(6),"
        "PRIMARY KEY(account_id,policy_key),"
        "INDEX idx_user_timed_policies_expiry(expires_at),"
        "CONSTRAINT fk_user_timed_policies_account FOREIGN KEY(account_id) "
        "REFERENCES accounts(id) ON DELETE CASCADE"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    execute_locked(
        "CREATE TABLE IF NOT EXISTS moderation_entries ("
        "id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,"
        "action_type VARCHAR(8) NOT NULL,"
        "target_type VARCHAR(16) NOT NULL,"
        "target_value VARCHAR(255) NOT NULL,"
        "secondary_value VARCHAR(255) NOT NULL DEFAULT '',"
        "reason VARCHAR(1000) NOT NULL,"
        "created_by VARCHAR(64) NOT NULL,"
        "created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),"
        "expires_at TIMESTAMP(6) NULL,"
        "revoked_at TIMESTAMP(6) NULL,"
        "revoked_by VARCHAR(64) NULL,"
        "revoke_reason VARCHAR(1000) NULL,"
        "INDEX idx_moderation_active(revoked_at,expires_at,action_type),"
        "INDEX idx_moderation_target"
        "(target_type,target_value,revoked_at,expires_at),"
        "INDEX idx_moderation_secondary"
        "(target_type,secondary_value,revoked_at,expires_at),"
        "INDEX idx_moderation_action(action_type,id),"
        "CONSTRAINT chk_moderation_action CHECK "
        "(action_type IN ('kick','ban')),"
        "CONSTRAINT chk_moderation_target CHECK "
        "(target_type IN "
        "('identity','nick','cid','ip','range','host','prefix','share'))"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    execute_locked(
        "ALTER TABLE moderation_entries "
        "DROP CONSTRAINT IF EXISTS chk_moderation_target");
    execute_locked(
        "ALTER TABLE moderation_entries "
        "ADD CONSTRAINT chk_moderation_target CHECK "
        "(target_type IN "
        "('identity','nick','cid','ip','range','host','prefix','share'))");

    execute_locked(
        "CREATE TABLE IF NOT EXISTS settings ("
        "setting_key VARCHAR(128) NOT NULL PRIMARY KEY,"
        "setting_value TEXT NOT NULL,"
        "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP "
        "ON UPDATE CURRENT_TIMESTAMP"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    constexpr std::array<std::pair<std::string_view, std::string_view>, 30>
        defaults{{
            {"key.kicks", "300"},
            {"key.bans", "31536000"},
            {"key.class.permission.register.difference", "2"},
            {"key.class.permission.kick.difference", "0"},
            {"key.class.permission.pm.difference", "10"},
            {"key.class.permission.download.difference", "10"},
            {"key.class.minimum.usehub", "0"},
            {"key.class.minimum.usehub.passive", "0"},
            {"key.class.minimum.register", "3"},
            {"key.class.minimum.redirect", "3"},
            {"key.class.minimum.broadcast", "3"},
            {"key.class.minimum.broadcast.guests", "3"},
            {"key.class.minimum.broadcast.registered", "3"},
            {"key.class.minimum.broadcast.vip", "3"},
            {"key.class.minimum.plugin.modify", "5"},
            {"key.class.minimum.topic.modify", "5"},
            {"key.class.minimum.trigger.modify", "5"},
            {"key.nick.length.maximum", "64"},
            {"key.nick.length.minimum", "3"},
            {"key.nick.characters.allowed", ""},
            {"key.nick.prefix", ""},
            {"key.nick.prefix.nocase", "0"},
            {"key.nick.prefix.autoreg", ""},
            {"key.nick.prefix.country", ""},
            {"key.user.autoreg.class", "-1"},
            {"key.user.autoreg.minimum.share.registered", "0"},
            {"key.user.autoreg.minimum.share.vip", "0"},
            {"key.user.autoreg.minimum.share.operator", "0"},
            {"key.user.password.minimum.length", "8"},
            {"key.user.password.initial.timeout", "300"}
        }};
    for (const auto& [key, value] : defaults) {
        execute_locked(
            "INSERT IGNORE INTO settings(setting_key,setting_value) VALUES('" +
            escape_locked(key) + "','" + escape_locked(value) + "')");
    }
}

void Database::record_event(std::string_view sid,
                            std::string_view event,
                            std::string_view remote_address) {
    std::lock_guard lock(mutex_);
    const auto sid_sql = escape_locked(sid);
    const auto event_sql = escape_locked(event);
    const auto remote_sql = escape_locked(remote_address);

    execute_locked(
        "INSERT INTO connection_events(sid,event_type,remote_address) VALUES('" +
        sid_sql + "','" + event_sql + "','" + remote_sql + "')");
}

std::uint64_t Database::create_user(std::string_view username,
                                    UserClass user_class,
                                    std::string_view password_hash,
                                    std::string_view registered_by) {
    const auto class_value = static_cast<std::int16_t>(user_class);
    if (!is_valid_user_class(class_value)) {
        throw std::invalid_argument("invalid user class");
    }

    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    const auto password_sql = escape_locked(password_hash);
    const auto registered_by_sql = escape_locked(registered_by);

    if (mysql_query(
            connection_,
            ("INSERT INTO accounts(nick,password_hash,user_class,enabled,"
             "registered_by,password_change_required) VALUES('" + username_sql +
             "','" + password_sql + "'," + std::to_string(class_value) +
             ",TRUE," + (registered_by.empty()
                 ? std::string("NULL")
                 : "'" + registered_by_sql + "'") + ",FALSE)")
                .c_str()) != 0) {
        const auto error_number = mysql_errno(connection_);
        if (error_number == 1062U) {
            throw std::runtime_error("username already exists");
        }
        throw std::runtime_error(
            "MariaDB query failed: " +
            std::string(mysql_error(connection_)));
    }

    return static_cast<std::uint64_t>(mysql_insert_id(connection_));
}

std::uint64_t Database::create_user_without_password(
    std::string_view username,
    UserClass user_class,
    std::string_view registered_by) {
    const auto class_value = static_cast<std::int16_t>(user_class);
    if (!is_valid_user_class(class_value)) {
        throw std::invalid_argument("invalid user class");
    }

    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    const auto registered_by_sql = escape_locked(registered_by);

    if (mysql_query(
            connection_,
            ("INSERT INTO accounts(nick,password_hash,user_class,enabled,"
             "registered_by,password_change_required) VALUES('" + username_sql +
             "',NULL," + std::to_string(class_value) + ",TRUE," +
             (registered_by.empty() ? std::string("NULL")
                                    : "'" + registered_by_sql + "'") +
             ",TRUE)")
                .c_str()) != 0) {
        const auto error_number = mysql_errno(connection_);
        if (error_number == 1062U) {
            throw std::runtime_error("username already exists");
        }
        throw std::runtime_error(
            "MariaDB query failed: " +
            std::string(mysql_error(connection_)));
    }

    return static_cast<std::uint64_t>(mysql_insert_id(connection_));
}

bool Database::update_user_password_by_id(
    std::uint64_t user_id,
    std::string_view password_hash) {
    if (user_id == 0U) return false;

    std::lock_guard lock(mutex_);
    const auto password_sql = escape_locked(password_hash);

    execute_locked(
        "UPDATE accounts SET password_hash='" + password_sql +
        "',password_change_required=FALSE WHERE id=" +
        std::to_string(user_id) + " AND enabled=TRUE");

    return mysql_affected_rows(connection_) == 1;
}

bool Database::update_user_password_by_username(
    std::string_view username,
    const std::optional<std::string>& password_hash) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    const auto password_sql = password_hash.has_value()
        ? "'" + escape_locked(*password_hash) + "'"
        : "NULL";

    execute_locked(
        "UPDATE accounts SET password_hash=" + password_sql +
        ",password_change_required=" +
        std::string(password_hash.has_value() ? "FALSE" : "TRUE") +
        " WHERE nick='" + username_sql + "'");

    if (mysql_affected_rows(connection_) == 1) return true;

    execute_locked(
        "SELECT 1 FROM accounts WHERE nick='" + username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

AddPasswordResult Database::add_user_password_if_missing(
    std::uint64_t user_id,
    std::string_view password_hash) {
    if (user_id == 0U) return AddPasswordResult::user_not_found;

    std::lock_guard lock(mutex_);
    const auto password_sql = escape_locked(password_hash);

    execute_locked(
        "UPDATE accounts SET password_hash='" + password_sql +
        "',password_change_required=FALSE WHERE id=" + std::to_string(user_id) +
        " AND enabled=TRUE AND (password_hash IS NULL OR password_hash='')");

    if (mysql_affected_rows(connection_) == 1) {
        return AddPasswordResult::added;
    }

    execute_locked(
        "SELECT password_hash FROM accounts WHERE id=" +
        std::to_string(user_id) + " AND enabled=TRUE LIMIT 1");

    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        if (mysql_field_count(connection_) == 0U) {
            return AddPasswordResult::user_not_found;
        }
        throw std::runtime_error(
            "MariaDB result failed: " +
            std::string(mysql_error(connection_)));
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    if (row == nullptr) {
        mysql_free_result(result);
        return AddPasswordResult::user_not_found;
    }

    mysql_free_result(result);
    return AddPasswordResult::already_set;
}

AddPasswordResult Database::add_user_password_if_missing(
    std::string_view username,
    std::string_view password_hash) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    const auto password_sql = escape_locked(password_hash);

    execute_locked(
        "UPDATE accounts SET password_hash='" + password_sql +
        "',password_change_required=FALSE WHERE nick='" + username_sql +
        "' AND enabled=TRUE AND (password_hash IS NULL OR password_hash='')");

    if (mysql_affected_rows(connection_) == 1) {
        return AddPasswordResult::added;
    }

    execute_locked(
        "SELECT password_hash FROM accounts WHERE nick='" + username_sql +
        "' AND enabled=TRUE LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }

    const MYSQL_ROW row = mysql_fetch_row(result);
    const auto outcome = row == nullptr
        ? AddPasswordResult::user_not_found
        : AddPasswordResult::already_set;
    mysql_free_result(result);
    return outcome;
}

bool Database::verify_user_password(std::string_view username,
                                    std::string_view password) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    execute_locked(
        "SELECT COALESCE(password_hash,'') FROM accounts WHERE nick='" +
        username_sql + "' AND enabled=TRUE LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const MYSQL_ROW row = mysql_fetch_row(result);
    const std::string encoded =
        row != nullptr && row[0] != nullptr ? row[0] : std::string{};
    mysql_free_result(result);
    return !encoded.empty() && verify_password(password, encoded);
}

std::vector<UserListEntry> Database::users_by_class(UserClass user_class) {
    const auto class_value = static_cast<std::int16_t>(user_class);
    if (!is_valid_user_class(class_value)) {
        throw std::invalid_argument("invalid user class");
    }

    std::lock_guard lock(mutex_);
    execute_locked(
        "SELECT id,nick,enabled,password_hash IS NOT NULL AND password_hash<>'' "
        "FROM accounts WHERE user_class=" +
        std::to_string(class_value) + " ORDER BY id");

    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " +
            std::string(mysql_error(connection_)));
    }

    std::vector<UserListEntry> users;
    while (MYSQL_ROW row = mysql_fetch_row(result)) {
        if (row[0] == nullptr || row[1] == nullptr) continue;

        std::uint64_t id = 0;
        try {
            id = static_cast<std::uint64_t>(std::stoull(row[0]));
        } catch (...) {
            mysql_free_result(result);
            throw std::runtime_error("invalid account id stored in database");
        }

        users.push_back(UserListEntry{
            id,
            std::string(row[1]),
            user_class,
            row[2] != nullptr && std::string_view(row[2]) == "1",
            row[3] != nullptr && std::string_view(row[3]) == "1"
        });
    }

    mysql_free_result(result);
    return users;
}

std::optional<UserDetails> Database::user_details(
    std::string_view username) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);

    execute_locked(
        "SELECT id,nick,user_class,enabled,"
        "password_hash IS NOT NULL AND password_hash<>'',created_at,updated_at,"
        "kick_protect_class,hide_share,hide_operator_key,hide_from_class,"
        "COALESCE(account_note,''),COALESCE(registered_by,''),"
        "password_change_required,COALESCE(last_login_at,''),"
        "COALESCE(last_logout_at,''),login_count,COALESCE(last_login_ip,''),"
        "COALESCE(auth_ip,''),COALESCE(email,''),COALESCE(public_note,''),"
        "hide_kick,hide_kick_through_class "
        "FROM accounts WHERE nick='" + username_sql + "' LIMIT 1");

    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }

    const MYSQL_ROW row = mysql_fetch_row(result);
    if (row == nullptr) {
        mysql_free_result(result);
        return std::nullopt;
    }

    int class_value = 0;
    int protect_class = -2;
    int hide_from_class = -1;
    int hide_kick_through_class = -2;
    std::uint64_t id = 0;
    std::uint64_t login_count = 0;
    try {
        id = static_cast<std::uint64_t>(std::stoull(row[0]));
        class_value = std::stoi(row[2]);
        if (row[7] != nullptr) protect_class = std::stoi(row[7]);
        if (row[10] != nullptr) hide_from_class = std::stoi(row[10]);
        if (row[16] != nullptr) login_count = std::stoull(row[16]);
        if (row[22] != nullptr) hide_kick_through_class = std::stoi(row[22]);
    } catch (...) {
        mysql_free_result(result);
        throw std::runtime_error("invalid account data stored in database");
    }

    if (class_value < std::numeric_limits<std::int16_t>::min() ||
        class_value > std::numeric_limits<std::int16_t>::max() ||
        protect_class < std::numeric_limits<std::int16_t>::min() ||
        protect_class > std::numeric_limits<std::int16_t>::max() ||
        hide_from_class < std::numeric_limits<std::int16_t>::min() ||
        hide_from_class > std::numeric_limits<std::int16_t>::max() ||
        hide_kick_through_class < std::numeric_limits<std::int16_t>::min() ||
        hide_kick_through_class > std::numeric_limits<std::int16_t>::max()) {
        mysql_free_result(result);
        throw std::runtime_error("user_class is outside SMALLINT range");
    }
    const auto parsed_class =
        user_class_from_int(static_cast<std::int16_t>(class_value));
    if (!parsed_class.has_value()) {
        mysql_free_result(result);
        throw std::runtime_error("unsupported user_class stored in database");
    }

    UserDetails details;
    details.id = id;
    details.username = row[1] == nullptr ? std::string{} : std::string(row[1]);
    details.user_class = *parsed_class;
    details.enabled = row[3] != nullptr && std::string_view(row[3]) == "1";
    details.has_password = row[4] != nullptr && std::string_view(row[4]) == "1";
    details.created_at = row[5] == nullptr ? std::string{} : std::string(row[5]);
    details.updated_at = row[6] == nullptr ? std::string{} : std::string(row[6]);
    details.kick_protect_class = static_cast<std::int16_t>(protect_class);
    details.hide_share = row[8] != nullptr && std::string_view(row[8]) == "1";
    details.hide_operator_key = row[9] != nullptr && std::string_view(row[9]) == "1";
    details.hide_from_class = static_cast<std::int16_t>(hide_from_class);
    details.note = row[11] == nullptr ? std::string{} : std::string(row[11]);
    details.registered_by = row[12] == nullptr ? std::string{} : std::string(row[12]);
    details.password_change_required =
        row[13] != nullptr && std::string_view(row[13]) == "1";
    details.last_login_at = row[14] == nullptr ? std::string{} : std::string(row[14]);
    details.last_logout_at = row[15] == nullptr ? std::string{} : std::string(row[15]);
    details.login_count = login_count;
    details.last_login_ip = row[17] == nullptr ? std::string{} : std::string(row[17]);
    details.auth_ip = row[18] == nullptr ? std::string{} : std::string(row[18]);
    details.email = row[19] == nullptr ? std::string{} : std::string(row[19]);
    details.public_note = row[20] == nullptr ? std::string{} : std::string(row[20]);
    details.hide_kick = row[21] != nullptr && std::string_view(row[21]) == "1";
    details.hide_kick_through_class =
        static_cast<std::int16_t>(hide_kick_through_class);
    mysql_free_result(result);
    return details;
}

AccountChangeResult Database::remove_user(std::string_view username) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);

    execute_locked(
        "SELECT user_class,enabled FROM accounts WHERE nick='" +
        username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const MYSQL_ROW row = mysql_fetch_row(result);
    if (row == nullptr) {
        mysql_free_result(result);
        return AccountChangeResult::user_not_found;
    }
    const bool protected_master = row[0] != nullptr &&
        std::string_view(row[0]) == "10" && row[1] != nullptr &&
        std::string_view(row[1]) == "1";
    mysql_free_result(result);

    if (protected_master) {
        execute_locked(
            "SELECT COUNT(*) FROM accounts WHERE user_class=10 AND enabled=TRUE");
        result = mysql_store_result(connection_);
        if (result == nullptr) {
            throw std::runtime_error(
                "MariaDB result failed: " +
                std::string(mysql_error(connection_)));
        }
        const MYSQL_ROW count_row = mysql_fetch_row(result);
        const bool last = count_row != nullptr && count_row[0] != nullptr &&
            std::string_view(count_row[0]) == "1";
        mysql_free_result(result);
        if (last) return AccountChangeResult::last_master;
    }

    execute_locked("DELETE FROM accounts WHERE nick='" + username_sql + "'");
    return mysql_affected_rows(connection_) == 1
        ? AccountChangeResult::changed
        : AccountChangeResult::user_not_found;
}

AccountChangeResult Database::set_user_enabled(std::string_view username,
                                               bool enabled) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);

    if (!enabled) {
        execute_locked(
            "SELECT user_class,enabled FROM accounts WHERE nick='" +
            username_sql + "' LIMIT 1");
        MYSQL_RES* result = mysql_store_result(connection_);
        if (result == nullptr) {
            throw std::runtime_error(
                "MariaDB result failed: " +
                std::string(mysql_error(connection_)));
        }
        const MYSQL_ROW row = mysql_fetch_row(result);
        if (row == nullptr) {
            mysql_free_result(result);
            return AccountChangeResult::user_not_found;
        }
        const bool protected_master = row[0] != nullptr &&
            std::string_view(row[0]) == "10" && row[1] != nullptr &&
            std::string_view(row[1]) == "1";
        mysql_free_result(result);
        if (protected_master) {
            execute_locked(
                "SELECT COUNT(*) FROM accounts "
                "WHERE user_class=10 AND enabled=TRUE");
            result = mysql_store_result(connection_);
            if (result == nullptr) {
                throw std::runtime_error(
                    "MariaDB result failed: " +
                    std::string(mysql_error(connection_)));
            }
            const MYSQL_ROW count_row = mysql_fetch_row(result);
            const bool last = count_row != nullptr && count_row[0] != nullptr &&
                std::string_view(count_row[0]) == "1";
            mysql_free_result(result);
            if (last) return AccountChangeResult::last_master;
        }
    }

    execute_locked(
        "UPDATE accounts SET enabled=" + std::string(enabled ? "TRUE" : "FALSE") +
        " WHERE nick='" + username_sql + "'");
    if (mysql_affected_rows(connection_) == 1) return AccountChangeResult::changed;

    execute_locked(
        "SELECT 1 FROM accounts WHERE nick='" + username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found ? AccountChangeResult::changed
                 : AccountChangeResult::user_not_found;
}

AccountChangeResult Database::set_user_class(std::string_view username,
                                             UserClass user_class) {
    const auto class_value = static_cast<std::int16_t>(user_class);
    if (!is_valid_user_class(class_value)) {
        throw std::invalid_argument("invalid user class");
    }

    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    execute_locked(
        "SELECT user_class,enabled FROM accounts WHERE nick='" +
        username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const MYSQL_ROW row = mysql_fetch_row(result);
    if (row == nullptr) {
        mysql_free_result(result);
        return AccountChangeResult::user_not_found;
    }
    const bool demoting_master = class_value != 10 && row[0] != nullptr &&
        std::string_view(row[0]) == "10" && row[1] != nullptr &&
        std::string_view(row[1]) == "1";
    mysql_free_result(result);

    if (demoting_master) {
        execute_locked(
            "SELECT COUNT(*) FROM accounts WHERE user_class=10 AND enabled=TRUE");
        result = mysql_store_result(connection_);
        if (result == nullptr) {
            throw std::runtime_error(
                "MariaDB result failed: " +
                std::string(mysql_error(connection_)));
        }
        const MYSQL_ROW count_row = mysql_fetch_row(result);
        const bool last = count_row != nullptr && count_row[0] != nullptr &&
            std::string_view(count_row[0]) == "1";
        mysql_free_result(result);
        if (last) return AccountChangeResult::last_master;
    }

    execute_locked(
        "UPDATE accounts SET user_class=" + std::to_string(class_value) +
        " WHERE nick='" + username_sql + "'");
    return AccountChangeResult::changed;
}

bool Database::set_kick_protect_class(
    std::string_view username,
    std::int16_t protected_through_class) {
    if (protected_through_class != -2 &&
        !is_valid_user_class(protected_through_class)) {
        throw std::invalid_argument("invalid protection class");
    }
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    execute_locked(
        "UPDATE accounts SET kick_protect_class=" +
        std::to_string(protected_through_class) + " WHERE nick='" +
        username_sql + "'");
    if (mysql_affected_rows(connection_) == 1) return true;
    execute_locked(
        "SELECT 1 FROM accounts WHERE nick='" + username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

bool Database::set_hide_share(std::string_view username, bool hidden) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    execute_locked(
        "UPDATE accounts SET hide_share=" +
        std::string(hidden ? "TRUE" : "FALSE") + " WHERE nick='" +
        username_sql + "'");
    if (mysql_affected_rows(connection_) == 1) return true;
    execute_locked(
        "SELECT 1 FROM accounts WHERE nick='" + username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

bool Database::set_hide_operator_key(std::string_view username, bool hidden) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    execute_locked(
        "UPDATE accounts SET hide_operator_key=" +
        std::string(hidden ? "TRUE" : "FALSE") + " WHERE nick='" +
        username_sql + "'");
    if (mysql_affected_rows(connection_) == 1) return true;
    execute_locked(
        "SELECT 1 FROM accounts WHERE nick='" + username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

bool Database::set_user_note(std::string_view username,
                             std::string_view note) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    const auto note_sql = escape_locked(note);
    execute_locked(
        "UPDATE accounts SET account_note=" +
        (note.empty() ? std::string("NULL") : "'" + note_sql + "'") +
        " WHERE nick='" + username_sql + "'");
    if (mysql_affected_rows(connection_) == 1) return true;
    execute_locked(
        "SELECT 1 FROM accounts WHERE nick='" + username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

bool Database::set_user_auth_ip(
    std::string_view username,
    const std::optional<std::string>& address) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    const auto address_sql = address.has_value()
        ? "'" + escape_locked(*address) + "'"
        : std::string("NULL");
    execute_locked(
        "UPDATE accounts SET auth_ip=" + address_sql + " WHERE nick='" +
        username_sql + "'");
    if (mysql_affected_rows(connection_) == 1) return true;
    execute_locked(
        "SELECT 1 FROM accounts WHERE nick='" + username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) throw std::runtime_error(
        "MariaDB result failed: " + std::string(mysql_error(connection_)));
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

bool Database::set_user_email(std::string_view username,
                              std::string_view email) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    const auto email_sql = escape_locked(email);
    execute_locked(
        "UPDATE accounts SET email=" +
        (email.empty() ? std::string("NULL") : "'" + email_sql + "'") +
        " WHERE nick='" + username_sql + "'");
    if (mysql_affected_rows(connection_) == 1) return true;
    execute_locked(
        "SELECT 1 FROM accounts WHERE nick='" + username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) throw std::runtime_error(
        "MariaDB result failed: " + std::string(mysql_error(connection_)));
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

bool Database::set_user_public_note(std::string_view username,
                                    std::string_view note) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    const auto note_sql = escape_locked(note);
    execute_locked(
        "UPDATE accounts SET public_note=" +
        (note.empty() ? std::string("NULL") : "'" + note_sql + "'") +
        " WHERE nick='" + username_sql + "'");
    if (mysql_affected_rows(connection_) == 1) return true;
    execute_locked(
        "SELECT 1 FROM accounts WHERE nick='" + username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) throw std::runtime_error(
        "MariaDB result failed: " + std::string(mysql_error(connection_)));
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

bool Database::set_hide_kick(std::string_view username, bool hidden) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    execute_locked(
        "UPDATE accounts SET hide_kick=" +
        std::string(hidden ? "TRUE" : "FALSE") + " WHERE nick='" +
        username_sql + "'");
    if (mysql_affected_rows(connection_) == 1) return true;
    execute_locked(
        "SELECT 1 FROM accounts WHERE nick='" + username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) throw std::runtime_error(
        "MariaDB result failed: " + std::string(mysql_error(connection_)));
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

bool Database::set_hide_kick_through_class(
    std::string_view username,
    std::int16_t hidden_through_class) {
    if (!is_valid_user_class(hidden_through_class)) {
        throw std::invalid_argument("invalid kick-message class");
    }
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    execute_locked(
        "UPDATE accounts SET hide_kick_through_class=" +
        std::to_string(hidden_through_class) + " WHERE nick='" +
        username_sql + "'");
    if (mysql_affected_rows(connection_) == 1) return true;
    execute_locked(
        "SELECT 1 FROM accounts WHERE nick='" + username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) throw std::runtime_error(
        "MariaDB result failed: " + std::string(mysql_error(connection_)));
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

bool Database::set_hide_from_class(
    std::string_view username,
    std::int16_t minimum_visible_class) {
    if (!is_valid_user_class(minimum_visible_class)) {
        throw std::invalid_argument("invalid visibility class");
    }
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    execute_locked(
        "UPDATE accounts SET hide_from_class=" +
        std::to_string(minimum_visible_class) + " WHERE nick='" +
        username_sql + "' AND enabled=TRUE");
    if (mysql_affected_rows(connection_) == 1) return true;
    execute_locked(
        "SELECT 1 FROM accounts WHERE nick='" + username_sql +
        "' AND enabled=TRUE LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

bool Database::set_timed_policy(std::string_view username,
                                std::string_view policy_key,
                                std::uint64_t duration_seconds) {
    constexpr std::uint64_t maximum_duration = 365U * 24U * 60U * 60U;
    if (!valid_policy_key(policy_key) || duration_seconds < 60U ||
        duration_seconds > maximum_duration) {
        throw std::invalid_argument("invalid timed policy or duration");
    }

    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    const auto policy_sql = escape_locked(policy_key);
    execute_locked(
        "INSERT INTO user_timed_policies(account_id,policy_key,expires_at) "
        "SELECT id,'" + policy_sql + "',TIMESTAMPADD(SECOND," +
        std::to_string(duration_seconds) + ",UTC_TIMESTAMP(6)) "
        "FROM accounts WHERE nick='" + username_sql + "' AND enabled=TRUE "
        "ON DUPLICATE KEY UPDATE expires_at=VALUES(expires_at)");
    return mysql_affected_rows(connection_) >= 1;
}

bool Database::remove_timed_policy(std::string_view username,
                                   std::string_view policy_key) {
    if (!valid_policy_key(policy_key)) {
        throw std::invalid_argument("invalid timed policy");
    }
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    const auto policy_sql = escape_locked(policy_key);
    execute_locked(
        "DELETE p FROM user_timed_policies p JOIN accounts a ON a.id=p.account_id "
        "WHERE a.nick='" + username_sql + "' AND p.policy_key='" +
        policy_sql + "'");
    if (mysql_affected_rows(connection_) == 1) return true;

    execute_locked(
        "SELECT 1 FROM accounts WHERE nick='" + username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

RuntimeUserPolicy Database::runtime_policy(std::string_view username) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    execute_locked(
        "SELECT id,user_class,enabled,kick_protect_class,hide_share,"
        "hide_operator_key,hide_from_class,COALESCE(auth_ip,''),"
        "password_change_required,hide_kick,hide_kick_through_class "
        "FROM accounts WHERE nick='" +
        username_sql + "' LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const MYSQL_ROW row = mysql_fetch_row(result);
    if (row == nullptr) {
        mysql_free_result(result);
        return {};
    }

    std::uint64_t account_id = 0;
    int class_value = 0;
    int protect_class = -2;
    int hide_from_class = -1;
    int hide_kick_through_class = -2;
    try {
        account_id = static_cast<std::uint64_t>(std::stoull(row[0]));
        class_value = std::stoi(row[1]);
        protect_class = std::stoi(row[3]);
        hide_from_class = std::stoi(row[6]);
        hide_kick_through_class = std::stoi(row[10]);
    } catch (...) {
        mysql_free_result(result);
        throw std::runtime_error("invalid runtime policy stored in database");
    }
    const auto parsed_class = class_value >= std::numeric_limits<std::int16_t>::min() &&
        class_value <= std::numeric_limits<std::int16_t>::max()
        ? user_class_from_int(static_cast<std::int16_t>(class_value))
        : std::nullopt;
    if (!parsed_class.has_value() ||
        protect_class < std::numeric_limits<std::int16_t>::min() ||
        protect_class > std::numeric_limits<std::int16_t>::max() ||
        hide_from_class < std::numeric_limits<std::int16_t>::min() ||
        hide_from_class > std::numeric_limits<std::int16_t>::max() ||
        hide_kick_through_class < std::numeric_limits<std::int16_t>::min() ||
        hide_kick_through_class > std::numeric_limits<std::int16_t>::max()) {
        mysql_free_result(result);
        throw std::runtime_error("unsupported runtime user class");
    }

    RuntimeUserPolicy policy;
    policy.registered = true;
    policy.enabled = row[2] != nullptr && std::string_view(row[2]) == "1";
    policy.user_class = *parsed_class;
    policy.kick_protect_class = static_cast<std::int16_t>(protect_class);
    policy.hide_share = row[4] != nullptr && std::string_view(row[4]) == "1";
    policy.hide_operator_key =
        row[5] != nullptr && std::string_view(row[5]) == "1";
    policy.hide_from_class = static_cast<std::int16_t>(hide_from_class);
    policy.auth_ip = row[7] == nullptr ? std::string{} : std::string(row[7]);
    policy.password_change_required =
        row[8] != nullptr && std::string_view(row[8]) == "1";
    policy.hide_kick = row[9] != nullptr && std::string_view(row[9]) == "1";
    policy.hide_kick_through_class =
        static_cast<std::int16_t>(hide_kick_through_class);
    mysql_free_result(result);

    execute_locked(
        "SELECT policy_key,UNIX_TIMESTAMP(expires_at) "
        "FROM user_timed_policies WHERE account_id=" +
        std::to_string(account_id) + " AND expires_at>UTC_TIMESTAMP(6) "
        "ORDER BY policy_key");
    result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    while (MYSQL_ROW policy_row = mysql_fetch_row(result)) {
        if (policy_row[0] == nullptr || policy_row[1] == nullptr) continue;
        try {
            policy.timed_policies.push_back({
                policy_row[0],
                static_cast<std::int64_t>(std::stoll(policy_row[1]))});
        } catch (...) {
            mysql_free_result(result);
            throw std::runtime_error("invalid timed policy expiry in database");
        }
    }
    mysql_free_result(result);
    return policy;
}

HubSettings Database::hub_settings() {
    std::lock_guard lock(mutex_);
    execute_locked(
        "SELECT setting_key,setting_value FROM settings "
        "WHERE " + std::string(hub_settings_where) + " ORDER BY setting_key");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) throw std::runtime_error(
        "MariaDB result failed: " + std::string(mysql_error(connection_)));
    try {
        auto snapshot = validated_hub_settings(result);
        mysql_free_result(result);
        return snapshot.settings;
    } catch (...) {
        mysql_free_result(result);
        throw;
    }
}

std::vector<std::pair<std::string, std::string>>
Database::hub_setting_entries() {
    std::lock_guard lock(mutex_);
    execute_locked(
        "SELECT setting_key,setting_value FROM settings WHERE " +
        std::string(hub_settings_where) + " ORDER BY setting_key");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) throw std::runtime_error(
        "MariaDB result failed: " + std::string(mysql_error(connection_)));

    try {
        auto snapshot = validated_hub_settings(result);
        mysql_free_result(result);
        return snapshot.entries;
    } catch (...) {
        mysql_free_result(result);
        throw;
    }
}

bool Database::set_hub_setting(std::string_view key,
                               std::string_view value) {
    std::string error;
    const auto normalized = normalize_hub_setting(key, value, error);
    if (!normalized.has_value()) return false;
    const std::string canonical_key =
        key == "key.account.password.setup.timeout"
            ? "key.user.password.initial.timeout"
            : std::string(key);
    std::lock_guard lock(mutex_);
    const auto key_sql = escape_locked(canonical_key);
    const auto value_sql = escape_locked(*normalized);
    execute_locked("START TRANSACTION");
    try {
        execute_locked(
            "SELECT setting_key,setting_value FROM settings WHERE " +
            std::string(hub_settings_where) +
            " ORDER BY setting_key FOR UPDATE");
        MYSQL_RES* result = mysql_store_result(connection_);
        if (result == nullptr) throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));

        HubSettings settings;
        try {
            settings = validated_hub_settings(
                result,
                std::pair<std::string_view, std::string_view>{
                    canonical_key, *normalized}).settings;
            mysql_free_result(result);
        } catch (...) {
            mysql_free_result(result);
            throw;
        }
        if (!apply_hub_setting(settings, canonical_key, *normalized) ||
            settings.nick_length_minimum > settings.nick_length_maximum ||
            settings.kick_rejoin_delay_seconds >
                settings.maximum_temporary_ban_seconds) {
            execute_locked("ROLLBACK");
            return false;
        }

        execute_locked(
            "INSERT INTO settings(setting_key,setting_value) VALUES('" + key_sql +
            "','" + value_sql + "') ON DUPLICATE KEY UPDATE "
            "setting_value=VALUES(setting_value)");
        execute_locked("COMMIT");
        return true;
    } catch (...) {
        mysql_query(connection_, "ROLLBACK");
        throw;
    }
}

std::uint64_t Database::add_moderation_entry(
    ModerationAction action,
    const ModerationTarget& target,
    std::string_view reason,
    std::string_view created_by,
    std::uint64_t duration_seconds) {
    if (!valid_moderation_reason(reason)) {
        throw std::invalid_argument(
            "moderation reason must be 1..1000 printable UTF-8 characters");
    }
    if (!valid_moderation_nickname(created_by)) {
        throw std::invalid_argument(
            "moderation actor must be 1..64 printable UTF-8 characters");
    }
    if (target.value.empty() || target.value.size() > 1020U ||
        target.secondary_value.size() > 1020U) {
        throw std::invalid_argument("invalid moderation target length");
    }
    if ((action == ModerationAction::kick &&
         target.kind != ModerationTargetKind::identity) ||
        (action == ModerationAction::ban &&
         target.kind == ModerationTargetKind::identity)) {
        throw std::invalid_argument("invalid target kind for moderation action");
    }

    std::lock_guard lock(mutex_);
    const auto target_sql = escape_locked(target.value);
    const auto secondary_sql = escape_locked(target.secondary_value);
    const auto reason_sql = escape_locked(reason);
    const auto actor_sql = escape_locked(created_by);
    const std::string expiry_sql = duration_seconds == 0U
        ? "NULL"
        : "DATE_ADD(UTC_TIMESTAMP(6),INTERVAL " +
            std::to_string(duration_seconds) + " SECOND)";

    execute_locked(
        "INSERT INTO moderation_entries("
        "action_type,target_type,target_value,secondary_value,reason,created_by,"
        "expires_at) VALUES('" +
        std::string(moderation_action_name(action)) + "','" +
        std::string(moderation_target_kind_name(target.kind)) + "','" +
        target_sql + "','" + secondary_sql + "','" + reason_sql + "','" +
        actor_sql + "'," + expiry_sql + ")");
    return static_cast<std::uint64_t>(mysql_insert_id(connection_));
}

std::optional<ModerationEntry> Database::active_moderation_match(
    std::string_view nickname,
    std::string_view cid,
    std::string_view ipv4,
    std::optional<std::uint64_t> share_size,
    std::string_view hostname) {
    std::lock_guard lock(mutex_);
    std::vector<std::string> target_clauses;
    std::vector<std::string> identity_clauses;
    if (!nickname.empty()) {
        const auto nickname_sql = escape_locked(nickname);
        target_clauses.push_back(
            "(target_type='nick' AND target_value='" + nickname_sql + "')");
        target_clauses.emplace_back("target_type='prefix'");
        identity_clauses.push_back("target_value='" + nickname_sql + "'");
    }
    if (!cid.empty()) {
        const auto cid_sql = escape_locked(cid);
        target_clauses.push_back(
            "(target_type='cid' AND target_value='" + cid_sql + "')");
        identity_clauses.push_back("secondary_value='" + cid_sql + "'");
    }
    if (!identity_clauses.empty()) {
        std::string identity = "(target_type='identity' AND (";
        for (std::size_t index = 0; index < identity_clauses.size(); ++index) {
            if (index != 0U) identity += " OR ";
            identity += identity_clauses[index];
        }
        identity += "))";
        target_clauses.push_back(std::move(identity));
    }
    if (!ipv4.empty()) {
        const auto ipv4_sql = escape_locked(ipv4);
        target_clauses.push_back(
            "(target_type='ip' AND target_value='" + ipv4_sql + "')");
        target_clauses.emplace_back("target_type='range'");
    }
    if (share_size.has_value()) {
        target_clauses.push_back(
            "(target_type='share' AND target_value='" +
            std::to_string(*share_size) + "')");
    }
    if (!hostname.empty()) {
        target_clauses.emplace_back("target_type='host'");
    }
    if (target_clauses.empty()) return std::nullopt;

    std::string target_filter;
    for (std::size_t index = 0; index < target_clauses.size(); ++index) {
        if (index != 0U) target_filter += " OR ";
        target_filter += target_clauses[index];
    }
    execute_locked(
        "SELECT " + std::string(moderation_select_columns) +
        " FROM moderation_entries WHERE revoked_at IS NULL "
        "AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP(6)) "
        "AND (" + target_filter + ") "
        "ORDER BY (action_type='ban') DESC,id DESC");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }

    try {
        while (MYSQL_ROW row = mysql_fetch_row(result)) {
            auto entry = moderation_entry_from_row(row);
            if (moderation_target_matches(
                    entry.target, nickname, cid, ipv4, share_size, hostname)) {
                mysql_free_result(result);
                return entry;
            }
        }
    } catch (...) {
        mysql_free_result(result);
        throw;
    }
    mysql_free_result(result);
    return std::nullopt;
}

bool Database::has_active_hostname_bans() {
    std::lock_guard lock(mutex_);
    execute_locked(
        "SELECT 1 FROM moderation_entries WHERE action_type='ban' "
        "AND target_type='host' AND revoked_at IS NULL "
        "AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP(6)) LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

std::optional<ModerationEntry> Database::moderation_entry(std::uint64_t id) {
    if (id == 0U) return std::nullopt;
    std::lock_guard lock(mutex_);
    execute_locked(
        "SELECT " + std::string(moderation_select_columns) +
        " FROM moderation_entries WHERE id=" + std::to_string(id) +
        " LIMIT 1");
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }
    const MYSQL_ROW row = mysql_fetch_row(result);
    if (row == nullptr) {
        mysql_free_result(result);
        return std::nullopt;
    }
    try {
        auto entry = moderation_entry_from_row(row);
        mysql_free_result(result);
        return entry;
    } catch (...) {
        mysql_free_result(result);
        throw;
    }
}

std::vector<ModerationEntry> Database::moderation_entries(
    ModerationAction action,
    std::uint16_t limit) {
    if (limit == 0U || limit > 50U) {
        throw std::invalid_argument("moderation list limit must be 1..50");
    }
    std::lock_guard lock(mutex_);
    execute_locked(
        "SELECT " + std::string(moderation_select_columns) +
        " FROM moderation_entries WHERE action_type='" +
        std::string(moderation_action_name(action)) +
        "' ORDER BY id DESC LIMIT " + std::to_string(limit));
    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        throw std::runtime_error(
            "MariaDB result failed: " + std::string(mysql_error(connection_)));
    }

    std::vector<ModerationEntry> entries;
    try {
        while (MYSQL_ROW row = mysql_fetch_row(result)) {
            entries.push_back(moderation_entry_from_row(row));
        }
    } catch (...) {
        mysql_free_result(result);
        throw;
    }
    mysql_free_result(result);
    return entries;
}

bool Database::revoke_moderation_entry(
    std::uint64_t id,
    ModerationAction action,
    std::string_view revoked_by,
    std::string_view reason) {
    if (id == 0U || !valid_moderation_reason(reason) ||
        !valid_moderation_nickname(revoked_by)) {
        throw std::invalid_argument("invalid moderation revocation");
    }
    std::lock_guard lock(mutex_);
    const auto actor_sql = escape_locked(revoked_by);
    const auto reason_sql = escape_locked(reason);
    execute_locked(
        "UPDATE moderation_entries SET revoked_at=UTC_TIMESTAMP(6),"
        "revoked_by='" + actor_sql + "',revoke_reason='" + reason_sql +
        "' WHERE id=" + std::to_string(id) +
        " AND action_type='" + std::string(moderation_action_name(action)) +
        "' AND revoked_at IS NULL "
        "AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP(6))");
    return mysql_affected_rows(connection_) == 1U;
}

void Database::record_account_login(std::string_view username,
                                    std::string_view remote_address) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    const auto address_sql = escape_locked(remote_address);
    execute_locked(
        "UPDATE accounts SET last_login_at=UTC_TIMESTAMP(),login_count=login_count+1,"
        "last_login_ip='" + address_sql + "' WHERE nick='" + username_sql + "'");
}

void Database::record_account_logout(std::string_view username) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);
    execute_locked(
        "UPDATE accounts SET last_logout_at=UTC_TIMESTAMP() WHERE nick='" +
        username_sql + "'");
}

std::optional<UserClass> Database::user_class_for_username(
    std::string_view username) {
    std::lock_guard lock(mutex_);
    const auto username_sql = escape_locked(username);

    execute_locked(
        "SELECT user_class FROM accounts WHERE nick='" +
        username_sql + "' AND enabled=TRUE LIMIT 1");

    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        if (mysql_field_count(connection_) == 0U) {
            return std::nullopt;
        }
        throw std::runtime_error(
            "MariaDB result failed: " +
            std::string(mysql_error(connection_)));
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    if (row == nullptr || row[0] == nullptr) {
        mysql_free_result(result);
        return std::nullopt;
    }

    int parsed = 0;
    try {
        parsed = std::stoi(row[0]);
    } catch (...) {
        mysql_free_result(result);
        throw std::runtime_error("invalid user_class stored in database");
    }

    mysql_free_result(result);

    if (parsed < std::numeric_limits<std::int16_t>::min() ||
        parsed > std::numeric_limits<std::int16_t>::max()) {
        throw std::runtime_error("user_class is outside SMALLINT range");
    }

    const auto result_class =
        user_class_from_int(static_cast<std::int16_t>(parsed));
    if (!result_class.has_value()) {
        throw std::runtime_error("unsupported user_class stored in database");
    }
    return result_class;
}

bool Database::has_any_enabled_users() {
    std::lock_guard lock(mutex_);

    execute_locked("SELECT 1 FROM accounts WHERE enabled=TRUE LIMIT 1");

    MYSQL_RES* result = mysql_store_result(connection_);
    if (result == nullptr) {
        if (mysql_field_count(connection_) == 0U) {
            return false;
        }
        throw std::runtime_error(
            "MariaDB result failed: " +
            std::string(mysql_error(connection_)));
    }

    const bool found = mysql_fetch_row(result) != nullptr;
    mysql_free_result(result);
    return found;
}

std::string Database::escape_locked(std::string_view value) {
    if (connection_ == nullptr) {
        throw std::runtime_error("MariaDB is not connected");
    }

    std::vector<char> output(value.size() * 2 + 1);
    const auto length = mysql_real_escape_string(
        connection_,
        output.data(),
        value.data(),
        static_cast<unsigned long>(value.size()));
    return std::string(output.data(), length);
}

void Database::execute_locked(const std::string& sql) {
    if (connection_ == nullptr) {
        throw std::runtime_error("MariaDB is not connected");
    }
    if (mysql_query(connection_, sql.c_str()) != 0) {
        throw std::runtime_error(
            "MariaDB query failed: " +
            std::string(mysql_error(connection_)));
    }
}

}  // namespace dc24h
