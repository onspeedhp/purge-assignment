-- Add MPC wallet metadata to store threshold and pubkey package
ALTER TABLE users 
ADD COLUMN mpc_threshold INTEGER,
ADD COLUMN mpc_pubkey_package TEXT;

-- Create index for faster lookups
CREATE INDEX idx_users_mpc_metadata ON users(mpc_wallet_pubkey) WHERE mpc_wallet_pubkey IS NOT NULL;
