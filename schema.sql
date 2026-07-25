-- ============================================================
-- VibraNet - Schéma D1
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,                -- uuid v4
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,        -- format: pbkdf2$iterations$saltHex$hashHex
    force_password_change INTEGER NOT NULL DEFAULT 0,

    permissions INTEGER NOT NULL DEFAULT 0,   -- bitmask, JAMAIS exposé au client

    oauth2_enabled INTEGER NOT NULL DEFAULT 0,
    oauth2_secret TEXT,                 -- secret TOTP actif (base32), NULL si désactivé
    oauth2_secret_pending TEXT,         -- secret en attente de confirmation

    banned INTEGER NOT NULL DEFAULT 0,
    ban_reason TEXT,
    timeout_until INTEGER,              -- timestamp unix, NULL si pas de timeout

    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,        -- SHA-256 du net-token, jamais le token en clair
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip TEXT,
    user_agent TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes(user_id);

CREATE TABLE IF NOT EXISTS banned_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    banned_by TEXT,
    banned_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id TEXT PRIMARY KEY,
    identifier TEXT NOT NULL,           -- email ou IP
    attempted_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_identifier ON login_attempts(identifier, attempted_at);
