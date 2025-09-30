# Environment Variables Templates

## Backend (.env)

Create `backend/.env` with the following content:

```bash
# Backend Environment Variables

# Database Configuration
DATABASE_URL=postgresql://postgres:password@localhost/purge_assignment

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# Redis Configuration
REDIS_URL=redis://127.0.0.1:6379/

# Indexer Service URL
INDEXER_URL=http://127.0.0.1:8090

# Solana RPC Configuration
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com

# MPC Server Configuration
MPC_SERVER_1_URL=http://127.0.0.1:8081
MPC_SERVER_2_URL=http://127.0.0.1:8082
MPC_SERVER_3_URL=http://127.0.0.1:8083

# Jupiter API Configuration
JUPITER_API_URL=https://lite-api.jup.ag

# Server Configuration
PORT=8080
HOST=127.0.0.1

# Logging Configuration
RUST_LOG=backend=debug,sqlx=debug,actix_web=info
```

## Indexer (.env)

Create `indexer/.env` with the following content:

```bash
# Indexer Environment Variables

# Database Configuration
DATABASE_URL=postgresql://postgres:password@localhost/purge_assignment

# Yellowstone gRPC Configuration
GEYSER_GRPC_ENDPOINT=https://api.mainnet-beta.solana.com

# Alternative gRPC endpoints (if main one fails)
# GEYSER_GRPC_ENDPOINT=grpc://api.devnet.solana.com:10000
# GEYSER_GRPC_ENDPOINT=grpc://api.testnet.solana.com:10000

# Server Configuration
PORT=8090
HOST=127.0.0.1

# Logging Configuration
RUST_LOG=indexer=debug,sqlx=debug

# Subscription Configuration
MAX_RETRY_ATTEMPTS=5
RETRY_DELAY_SECONDS=2
SUBSCRIPTION_TIMEOUT_SECONDS=300
```

## MPC (.env)

Create `mpc/.env` with the following content:

```bash
# MPC Environment Variables

# Database Configuration (SQLite)
DATABASE_URL=sqlite:data/mpc.db

# Server Configuration
PORT=8081
HOST=127.0.0.1

# Participant ID (1, 2, or 3)
PARTICIPANT_ID=1

# Logging Configuration
RUST_LOG=mpc=debug
```

## Setup Commands

```bash
# Create backend .env
cp env-templates.md backend/.env
# Edit backend/.env with the content above

# Create indexer .env
cp env-templates.md indexer/.env
# Edit indexer/.env with the content above

# Create mpc .env
cp env-templates.md mpc/.env
# Edit mpc/.env with the content above
```
