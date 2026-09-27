-- 001_init.sql
-- Initial schema for the CLI login system.
-- Applied automatically at startup by internal/db.

PRAGMA foreign_keys = ON;

-- users holds account, credential, 2FA and lockout state for every user.
CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    totp_secret         TEXT,               -- base32 TOTP secret; NULL until 2FA is enabled
    totp_enabled        INTEGER NOT NULL DEFAULT 0, -- 0 = disabled, 1 = enabled
    failed_attempts     INTEGER NOT NULL DEFAULT 0, -- consecutive failed login attempts
    locked_until        DATETIME,           -- NULL if not locked, else lockout expiry
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at       DATETIME            -- NULL until the user has logged in at least once
);

-- sessions holds active login sessions with an explicit, configurable expiry.
CREATE TABLE IF NOT EXISTS sessions (
    id                  TEXT PRIMARY KEY,   -- random UUID session token
    user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
