-- Add MPC wallet public key to users table
ALTER TABLE users 
ADD COLUMN mpc_wallet_pubkey TEXT;

-- Create index on mpc_wallet_pubkey for faster lookups
CREATE INDEX idx_users_mpc_wallet_pubkey ON users(mpc_wallet_pubkey);
