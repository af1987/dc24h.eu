-- schema.sql
--
-- v0.0.10:
--   - allow exact and wildcard hostname targets in persistent ban entries
--   - retain indexed active ban matching and migration-safe constraints
--
-- v0.0.08:
--   - add auditable kick and ban entries with expiry and soft revocation
--   - seed key.kicks rejoin delay and key.bans temporary maximum
--   - index active target, secondary identity and action lookups
--
-- v0.0.07:
--   - add account binding, profile, kick visibility and login telemetry columns
--   - seed class, nickname, auto-registration and password policy settings
--
-- v0.0.06:
--   - add persistent moderation and visibility attributes to accounts
--   - add expiring restrictions and delegated privileges table
--
-- v0.0.05:
--   - add account updated_at metadata for complete user information
--   - support complete registered-user lifecycle administration
--
-- v0.0.04:
--   - allow NULL password_hash for accounts created without a password
--   - preserve conditional password assignment semantics for new.id.password
--   - keep numeric user_class index and supported class set
--
-- v0.0.03:
--   - add numeric user_class values to accounts
--   - preserve legacy role column for migration compatibility
--   - document supported account class values
--
-- v0.0.01:
--   - create dc24h database using utf8mb4
--   - add accounts, settings and connection event tables
--
-- Author: gpt-5.6-sol
-- Date: 2026-08-21

CREATE DATABASE IF NOT EXISTS dc24h
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE dc24h;

CREATE TABLE IF NOT EXISTS connection_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sid VARCHAR(4) NOT NULL,
    event_type VARCHAR(32) NOT NULL,
    remote_address VARCHAR(64) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_connection_events_created_at (created_at),
    INDEX idx_connection_events_sid (sid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS accounts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    nick VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NULL,
    role ENUM('user','operator','admin') NOT NULL DEFAULT 'user',
    user_class SMALLINT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    kick_protect_class SMALLINT NOT NULL DEFAULT -2,
    hide_share BOOLEAN NOT NULL DEFAULT FALSE,
    hide_operator_key BOOLEAN NOT NULL DEFAULT FALSE,
    hide_from_class SMALLINT NOT NULL DEFAULT -1,
    account_note TEXT NULL,
    registered_by VARCHAR(64) NULL,
    password_change_required BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at TIMESTAMP NULL,
    last_logout_at TIMESTAMP NULL,
    login_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
    last_login_ip VARCHAR(45) NULL,
    auth_ip VARCHAR(45) NULL,
    email VARCHAR(254) NULL,
    public_note TEXT NULL,
    hide_kick BOOLEAN NOT NULL DEFAULT FALSE,
    hide_kick_through_class SMALLINT NOT NULL DEFAULT -2,
    INDEX idx_accounts_user_class (user_class),
    CONSTRAINT chk_accounts_user_class
        CHECK (user_class IN (-1, 0, 1, 2, 3, 4, 5, 10))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS user_class SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE accounts
    MODIFY COLUMN password_hash VARCHAR(255) NULL;

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL
        DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS kick_protect_class SMALLINT NOT NULL DEFAULT -2,
    ADD COLUMN IF NOT EXISTS hide_share BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS hide_operator_key BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS hide_from_class SMALLINT NOT NULL DEFAULT -1,
    ADD COLUMN IF NOT EXISTS account_note TEXT NULL;

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS registered_by VARCHAR(64) NULL,
    ADD COLUMN IF NOT EXISTS password_change_required BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP NULL,
    ADD COLUMN IF NOT EXISTS last_logout_at TIMESTAMP NULL,
    ADD COLUMN IF NOT EXISTS login_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR(45) NULL,
    ADD COLUMN IF NOT EXISTS auth_ip VARCHAR(45) NULL,
    ADD COLUMN IF NOT EXISTS email VARCHAR(254) NULL,
    ADD COLUMN IF NOT EXISTS public_note TEXT NULL,
    ADD COLUMN IF NOT EXISTS hide_kick BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS hide_kick_through_class SMALLINT NOT NULL DEFAULT -2;

CREATE TABLE IF NOT EXISTS user_timed_policies (
    account_id BIGINT UNSIGNED NOT NULL,
    policy_key VARCHAR(32) NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (account_id, policy_key),
    INDEX idx_user_timed_policies_expiry (expires_at),
    CONSTRAINT fk_user_timed_policies_account
        FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS moderation_entries (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    action_type VARCHAR(8) NOT NULL,
    target_type VARCHAR(16) NOT NULL,
    target_value VARCHAR(255) NOT NULL,
    secondary_value VARCHAR(255) NOT NULL DEFAULT '',
    reason VARCHAR(1000) NOT NULL,
    created_by VARCHAR(64) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at TIMESTAMP(6) NULL,
    revoked_at TIMESTAMP(6) NULL,
    revoked_by VARCHAR(64) NULL,
    revoke_reason VARCHAR(1000) NULL,
    INDEX idx_moderation_active (revoked_at, expires_at, action_type),
    INDEX idx_moderation_target
        (target_type, target_value, revoked_at, expires_at),
    INDEX idx_moderation_secondary
        (target_type, secondary_value, revoked_at, expires_at),
    INDEX idx_moderation_action (action_type, id),
    CONSTRAINT chk_moderation_action
        CHECK (action_type IN ('kick', 'ban')),
    CONSTRAINT chk_moderation_target
        CHECK (target_type IN
            ('identity', 'nick', 'cid', 'ip', 'range', 'host', 'prefix', 'share'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE moderation_entries
    DROP CONSTRAINT IF EXISTS chk_moderation_target;

ALTER TABLE moderation_entries
    ADD CONSTRAINT chk_moderation_target
        CHECK (target_type IN
            ('identity', 'nick', 'cid', 'ip', 'range', 'host', 'prefix', 'share'));

CREATE TABLE IF NOT EXISTS settings (
    setting_key VARCHAR(128) NOT NULL PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO settings(setting_key, setting_value) VALUES
    ('key.kicks', '300'),
    ('key.bans', '31536000'),
    ('key.class.permission.register.difference', '2'),
    ('key.class.permission.kick.difference', '0'),
    ('key.class.permission.pm.difference', '10'),
    ('key.class.permission.download.difference', '10'),
    ('key.class.minimum.usehub', '0'),
    ('key.class.minimum.usehub.passive', '0'),
    ('key.class.minimum.register', '3'),
    ('key.class.minimum.redirect', '3'),
    ('key.class.minimum.broadcast', '3'),
    ('key.class.minimum.broadcast.guests', '3'),
    ('key.class.minimum.broadcast.registered', '3'),
    ('key.class.minimum.broadcast.vip', '3'),
    ('key.class.minimum.plugin.modify', '5'),
    ('key.class.minimum.topic.modify', '5'),
    ('key.class.minimum.trigger.modify', '5'),
    ('key.nick.length.maximum', '64'),
    ('key.nick.length.minimum', '3'),
    ('key.nick.characters.allowed', ''),
    ('key.nick.prefix', ''),
    ('key.nick.prefix.nocase', '0'),
    ('key.nick.prefix.autoreg', ''),
    ('key.nick.prefix.country', ''),
    ('key.user.autoreg.class', '-1'),
    ('key.user.autoreg.minimum.share.registered', '0'),
    ('key.user.autoreg.minimum.share.vip', '0'),
    ('key.user.autoreg.minimum.share.operator', '0'),
    ('key.user.password.minimum.length', '8'),
    ('key.user.password.initial.timeout', '300');

-- user_class values:
-- -1 = Hublist pingers
--  0 = Regular users
--  1 = Registered users
--  2 = VIP users
--  3 = Operator user
--  4 = Cheef user
--  5 = Admin user
-- 10 = Master user
