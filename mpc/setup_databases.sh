#!/bin/bash

# Setup SQLite databases for FROST MPC servers
echo "Setting up SQLite databases..."

# Create data directory if it doesn't exist
mkdir -p data

# Create databases for each server
for port in 8081 8082 8083; do
    db_file="data/mpc${port}.db"
    echo "Creating database: $db_file"
    
    # Create the database file
    touch "$db_file"
    
    # Apply the migration
    if [ -f "migrations/001_create_keyshares.sql" ]; then
        sqlite3 "$db_file" < migrations/001_create_keyshares.sql
        echo "  Applied migration to $db_file"
    else
        echo "  Warning: Migration file not found, creating basic schema"
        sqlite3 "$db_file" <<EOF
CREATE TABLE IF NOT EXISTS keyshares (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_keyshares_user_id ON keyshares(user_id);
EOF
    fi
done

echo "✅ Databases created successfully"
