-- schema.sql
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
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS settings (
    setting_key VARCHAR(128) NOT NULL PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
