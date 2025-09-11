-- Migration: Create keyshares table
-- This table stores FROST key shares for each MPC server

CREATE TABLE IF NOT EXISTS keyshares (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Index for faster lookups by user_id
CREATE INDEX IF NOT EXISTS idx_keyshares_user_id ON keyshares(user_id);

-- Index for faster lookups by public_key
CREATE INDEX IF NOT EXISTS idx_keyshares_public_key ON keyshares(public_key);
