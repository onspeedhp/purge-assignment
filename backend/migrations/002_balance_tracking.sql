-- Create user_tokens table to track which tokens a user's wallet has ever held
CREATE TABLE user_tokens (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    user_id VARCHAR(36) NOT NULL,
    wallet_address TEXT NOT NULL,
    token_mint TEXT NOT NULL,
    first_seen_at TIMESTAMP DEFAULT NOW(),
    last_seen_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, token_mint),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create token_metadata table to cache token information
CREATE TABLE token_metadata (
    mint_address TEXT PRIMARY KEY,
    symbol TEXT NOT NULL,
    name TEXT NOT NULL,
    decimals INTEGER NOT NULL,
    logo_url TEXT,
    last_updated TIMESTAMP DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX idx_user_tokens_user_id ON user_tokens(user_id);
CREATE INDEX idx_user_tokens_wallet_address ON user_tokens(wallet_address);
CREATE INDEX idx_user_tokens_token_mint ON user_tokens(token_mint);
CREATE INDEX idx_token_metadata_mint_address ON token_metadata(mint_address);

-- Insert SOL token metadata (native Solana token)
INSERT INTO token_metadata (mint_address, symbol, name, decimals, logo_url) 
VALUES ('So11111111111111111111111111111111111111112', 'SOL', 'Solana', 9, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/So11111111111111111111111111111111111111112/logo.png')
ON CONFLICT (mint_address) DO NOTHING;

-- Insert USDC token metadata (common token)
INSERT INTO token_metadata (mint_address, symbol, name, decimals, logo_url) 
VALUES ('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', 'USDC', 'USD Coin', 6, 'https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/logo.png')
ON CONFLICT (mint_address) DO NOTHING;
