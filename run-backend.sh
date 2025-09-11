#!/bin/bash

# Set environment variables for logging
export RUST_LOG="backend=debug,sqlx=debug,actix_web=info"

echo "Starting backend with enhanced logging..."
echo "Database URL: $DATABASE_URL"
echo "Log Level: $RUST_LOG"
echo ""

cd backend && cargo run
