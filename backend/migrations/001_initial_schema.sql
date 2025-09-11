-- Create users table
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,  -- UUID as string
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create index on email for faster lookups
CREATE INDEX idx_users_email ON users(email);

-- Create index on created_at for potential queries
CREATE INDEX idx_users_created_at ON users(created_at);
