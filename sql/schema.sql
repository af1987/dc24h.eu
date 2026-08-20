-- schema.sql
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
-- Date: 2026-08-19

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
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user','operator','admin') NOT NULL DEFAULT 'user',
    user_class SMALLINT NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_accounts_user_class (user_class),
    CONSTRAINT chk_accounts_user_class
        CHECK (user_class IN (-1, 0, 1, 2, 3, 4, 5, 10))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS user_class SMALLINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS settings (
    setting_key VARCHAR(128) NOT NULL PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- user_class values:
-- -1 = Hublist pingers
--  0 = Regular users
--  1 = Registered users
--  2 = VIP users
--  3 = Operator user
--  4 = Cheef user
--  5 = Admin user
-- 10 = Master user
