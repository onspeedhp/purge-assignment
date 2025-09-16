-- Create assets table to track token metadata
CREATE TABLE assets (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    mint_address TEXT UNIQUE NOT NULL,
    symbol TEXT NOT NULL,
    name TEXT NOT NULL,
    decimals INTEGER NOT NULL,
    logo_url TEXT,
    is_native BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create user_assets table to track user's token holdings (M-M relationship)
CREATE TABLE user_assets (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    user_id VARCHAR(36) NOT NULL,
    asset_id VARCHAR(36) NOT NULL,
    wallet_address TEXT NOT NULL,
    balance BIGINT NOT NULL DEFAULT 0, -- stored in smallest unit (lamports/token units)
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, asset_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

-- Create account_subscriptions table to track which accounts we're monitoring
CREATE TABLE account_subscriptions (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    user_id VARCHAR(36) NOT NULL,
    wallet_address TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    subscribed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_processed_slot BIGINT DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, wallet_address)
);

-- Create indexes for better performance
CREATE INDEX idx_assets_mint_address ON assets(mint_address);
CREATE INDEX idx_user_assets_user_id ON user_assets(user_id);
CREATE INDEX idx_user_assets_asset_id ON user_assets(asset_id);
CREATE INDEX idx_user_assets_wallet_address ON user_assets(wallet_address);
CREATE INDEX idx_account_subscriptions_user_id ON account_subscriptions(user_id);
CREATE INDEX idx_account_subscriptions_wallet_address ON account_subscriptions(wallet_address);
CREATE INDEX idx_account_subscriptions_active ON account_subscriptions(is_active) WHERE is_active = TRUE;

-- Insert SOL as native asset
INSERT INTO assets (mint_address, symbol, name, decimals, is_native, logo_url) 
VALUES ('So11111111111111111111111111111111111111112', 'SOL', 'Solana', 9, TRUE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/So11111111111111111111111111111111111111112/logo.png')
ON CONFLICT (mint_address) DO NOTHING;

-- Insert USDC as common token
INSERT INTO assets (mint_address, symbol, name, decimals, is_native, logo_url) 
VALUES ('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', 'USDC', 'USD Coin', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/logo.png')
ON CONFLICT (mint_address) DO NOTHING;
