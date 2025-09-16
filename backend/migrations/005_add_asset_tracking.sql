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

-- Insert popular Solana tokens
INSERT INTO assets (mint_address, symbol, name, decimals, is_native, logo_url) VALUES
-- Stablecoins
('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', 'USDC', 'USD Coin', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/logo.png'),
('Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', 'USDT', 'Tether USD', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB/logo.png'),

-- Liquid Staking Tokens
('mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So', 'mSOL', 'Marinade Staked SOL', 9, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So/logo.png'),
('bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1', 'bSOL', 'BlazeStake Staked SOL', 9, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1/logo.png'),
('7dHbWXmci3dT8UFYWYZweBLXgycu7Y3iL6trKn1Y7ARj', 'stSOL', 'Lido Staked SOL', 9, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/7dHbWXmci3dT8UFYWYZweBLXgycu7Y3iL6trKn1Y7ARj/logo.png'),
('5oVNBeEEQvYi1cX3ir8Dx5n1P7pdxydbGF2X4TxVusJm', 'scnSOL', 'Socean Staked SOL', 9, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/5oVNBeEEQvYi1cX3ir8Dx5n1P7pdxydbGF2X4TxVusJm/logo.png'),

-- Popular DeFi Tokens
('DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263', 'BONK', 'Bonk', 5, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263/logo.png'),
('JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN', 'JUP', 'Jupiter', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN/logo.png'),
('So11111111111111111111111111111111111111112', 'SOL', 'Solana', 9, TRUE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/So11111111111111111111111111111111111111112/logo.png'),

-- Raydium Tokens
('4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R', 'RAY', 'Raydium', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R/logo.png'),

-- Orca Tokens
('orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE', 'ORCA', 'Orca', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/orcaEKTdK7LKz57vaAYr9QeNsVEPfiu6QeMU1kektZE/logo.png'),

-- Serum Tokens
('SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt', 'SRM', 'Serum', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt/logo.png'),

-- Mango Tokens
('MangoCzJ36AjZyKwVj3VnYU4gOnJw6mFZRkAz3RgDc6', 'MNGO', 'Mango', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/MangoCzJ36AjZyKwVj3VnYU4gOnJw6mFZRkAz3RgDc6/logo.png'),

-- Step Finance
('StepAscQoEioFxxWGnh2sLBDFp9d8rvKz2Yp39iDpyT', 'STEP', 'Step', 9, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/StepAscQoEioFxxWGnh2sLBDFp9d8rvKz2Yp39iDpyT/logo.png'),

-- COPE
('8HGyAAB1yoM1ttS7pXjHMa3dukTFGQggnFFH3hJZgzQh', 'COPE', 'COPE', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/8HGyAAB1yoM1ttS7pXjHMa3dukTFGQggnFFH3hJZgzQh/logo.png'),

-- FIDA
('EchesyfXePKdLtoiZSL8pBE8bPKxS3Yj1Y2SbFj3r6c', 'FIDA', 'Bonfida', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/EchesyfXePKdLtoiZSL8pBE8bPKxS3Yj1Y2SbFj3r6c/logo.png'),

-- KIN
('kinXdEcpDQeHPEuQnqmUgtYykqKGVFq6CeVX5iAHJq6', 'KIN', 'Kin', 5, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/kinXdEcpDQeHPEuQnqmUgtYykqKGVFq6CeVX5iAHJq6/logo.png'),

-- MAPS
('MAPS41MDahZ9QdKXhVa4dWB9PuyfzLTWq3HB7eR9Gc', 'MAPS', 'Maps', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/MAPS41MDahZ9QdKXhVa4dWB9PuyfzLTWq3HB7eR9Gc/logo.png'),

-- OXY
('z3dn17yLaGMKffVzFHGBDn7YAPmWtJ1TZvJSYr3M6W', 'OXY', 'Oxygen', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/z3dn17yLaGMKffVzFHGBDn7YAPmWtJ1TZvJSYr3M6W/logo.png'),

-- PORT
('PoRTjZMPXb9T7dyU7tpLEZRQj7e6ssfAE62j2oQucv', 'PORT', 'Port Finance', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/PoRTjZMPXb9T7dyU7tpLEZRQj7e6ssfAE62j2oQucv/logo.png'),

-- RAY
('4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R', 'RAY', 'Raydium', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R/logo.png'),

-- ROPE
('8PMHT4swUMtBzgHnh5U564N5sj2iL7A8t3h7uRjVqN1', 'ROPE', 'Rope', 9, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/8PMHT4swUMtBzgHnh5U564N5sj2iL7A8t3h7uRjVqN1/logo.png'),

-- SAMO
('7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU', 'SAMO', 'Samoyedcoin', 9, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU/logo.png'),

-- SLIM
('xxxxa1sKNGwFtw2kFn8XauW9xq8hBZ5kVtcSesTT9fW', 'SLIM', 'Solanium', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/xxxxa1sKNGwFtw2kFn8XauW9xq8hBZ5kVtcSesTT9fW/logo.png'),

-- SNY
('4dmKkXNHdgYsXqBHCuMikNQWwVomZURhYvkkX5c4pQ7y', 'SNY', 'Synthetify', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/4dmKkXNHdgYsXqBHCuMikNQWwVomZURhYvkkX5c4pQ7y/logo.png'),

-- TULIP
('TuLipcqtGVXP9XR62wM8WWCm6a9vhLs7T1uoWBk6FDs', 'TULIP', 'Tulip Protocol', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/TuLipcqtGVXP9XR62wM8WWCm6a9vhLs7T1uoWBk6FDs/logo.png'),

-- WOOF
('9nEqaUcb16sQ3Tn1psbkWqyhPdL8HWXcpv73wRK1L7L', 'WOOF', 'Woof', 6, FALSE, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/9nEqaUcb16sQ3Tn1psbkWqyhPdL8HWXcpv73wRK1L7L/logo.png')
ON CONFLICT (mint_address) DO NOTHING;
