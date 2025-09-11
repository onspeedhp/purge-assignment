-- Initial schema for MPC key shares
CREATE TABLE IF NOT EXISTS keyshares (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_keyshares_user_id ON keyshares(user_id);
CREATE INDEX IF NOT EXISTS idx_keyshares_public_key ON keyshares(public_key);
