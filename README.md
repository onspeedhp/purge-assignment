# Solana MPC Wallet System

A complete Solana MPC (Multi-Party Computation) wallet system with real-time balance indexing, built with Rust and FROST-ed25519 protocol.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Backend API   │    │  Indexer Service│    │   MPC Servers   │
│   (Port 8080)   │    │   (Port 8090)   │    │ (8081,8082,8083)│
│                 │    │                 │    │                 │
│ • Authentication│    │ • Real-time     │    │ • FROST Protocol│
│ • MPC Integration│    │   monitoring    │    │ • Key Management│
│ • Solana Ops    │    │ • Balance track │    │ • Distributed   │
│ • Jupiter DEX   │    │ • gRPC streams  │    │   signing       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Data Layer    │
                    │                 │
                    │ • PostgreSQL    │
                    │ • Redis Cache   │
                    │ • SQLite (MPC)  │
                    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- **Rust 1.70+**
- **Docker & Docker Compose**
- **Homebrew** (for Redis)
- **Solana CLI tools**

### 1. Clone and Setup

```bash
git clone <your-repo-url>
cd purge-assignment
```

### 2. Environment Setup

```bash
# Setup environment variables
./setup-env.sh

# Or manually create .env files in backend/, indexer/, mpc/
```

### 3. Start All Services

```bash
# One command to start everything
make start-all

# Or start individually:
make start-db      # PostgreSQL
make start-redis   # Redis  
make start-mpc     # 3 MPC servers
make start-backend # Backend API
make start-indexer # Indexer service
```

### 4. Test the System

```bash
# Test authentication
make test-auth

# Check service status
make status

# View logs
make logs-backend
make logs-indexer
```

## 📋 Available Commands

| Command | Description |
|---------|-------------|
| `make start-all` | Start all services (DB, Redis, MPC, Backend, Indexer) |
| `make stop-all` | Stop all services |
| `make status` | Check status of all services |
| `make test-auth` | Test authentication endpoints |
| `make help` | Show all available commands |

## 🔧 Manual Setup (Alternative)

### 1. Start PostgreSQL

```bash
# Using Docker (Recommended)
docker run --name postgres-purge \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=purge_assignment \
  -p 5432:5432 \
  -d postgres:14

# Or using Homebrew
brew install postgresql@14
brew services start postgresql@14
createdb purge_assignment
```

### 2. Start Redis

```bash
brew install redis
brew services start redis
```

### 3. Run Database Migrations

```bash
cd backend
sqlx migrate run
```

### 4. Start MPC Servers

```bash
# Terminal 1
cd mpc && cargo run -- --port 8081

# Terminal 2  
cd mpc && cargo run -- --port 8082

# Terminal 3
cd mpc && cargo run -- --port 8083
```

### 5. Start Backend API

```bash
cd backend
cargo run
```

### 6. Start Indexer Service

```bash
cd indexer
cargo run
```

## 🧪 Testing

### 1. Test Authentication Flow

```bash
# 1. Signup (creates user + MPC wallet)
curl -X POST http://localhost:8080/api/v1/signup \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test@example.com",
    "password": "password123"
  }'

# Response:
# {
#   "message": "User created successfully with MPC wallet",
#   "user": {
#     "email": "test@example.com",
#     "wallet_address": "ABC123...",
#     "public_key": "def456...",
#     "wallet_created_at": "2025-09-30T16:44:00Z"
#   }
# }

# 2. Signin (get JWT token)
curl -X POST http://localhost:8080/api/v1/signin \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test@example.com", 
    "password": "password123"
  }'

# Response:
# {
#   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
#   "user": { ... }
# }
```

### 2. Test Protected Endpoints

```bash
# Replace TOKEN with actual JWT from signin response

# Get user profile
curl -X GET http://localhost:8080/api/v1/user \
  -H "Authorization: Bearer TOKEN"

# Get SOL balance
curl -X GET http://localhost:8080/api/v1/balance/sol \
  -H "Authorization: Bearer TOKEN"

# Get token balances
curl -X GET http://localhost:8080/api/v1/balance/tokens \
  -H "Authorization: Bearer TOKEN"
```

### 3. Test MPC Operations

```bash
# Check MPC server health
curl http://localhost:8081/health
curl http://localhost:8082/health  
curl http://localhost:8083/health

# Check MPC server status
curl http://localhost:8081/status
```

### 4. Test Jupiter Integration

```bash
# Get swap quote
curl -X POST http://localhost:8080/api/v1/quote \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "inputMint": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
    "outputMint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "inAmount": 100000000
  }'

# Execute swap (using quote ID)
curl -X POST http://localhost:8080/api/v1/swap \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "quote-uuid-from-previous-response"
  }'
```

## 📊 API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/signup` | User registration + MPC wallet creation | ❌ |
| `POST` | `/api/v1/signin` | User authentication (returns JWT) | ❌ |
| `GET` | `/api/v1/user` | Get user profile and wallet info | ✅ |

### Solana Operation Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/quote` | Get swap quote from Jupiter | ✅ |
| `POST` | `/api/v1/swap` | Execute swap transaction | ✅ |
| `POST` | `/api/v1/send` | Send SOL or tokens | ✅ |
| `GET` | `/api/v1/balance/sol` | Get SOL balance | ✅ |
| `GET` | `/api/v1/balance/tokens` | Get token balances | ✅ |

### Indexer Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/subscribe` | Subscribe wallet to monitoring | ❌ |
| `POST` | `/api/v1/unsubscribe` | Unsubscribe wallet from monitoring | ❌ |

### MPC Server Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/frost/keygen-with-package` | Generate key shares | ❌ |
| `POST` | `/frost/round1` | FROST Round 1 (nonces) | ❌ |
| `POST` | `/frost/round2` | FROST Round 2 (signature shares) | ❌ |
| `POST` | `/frost/aggregate` | Aggregate signature shares | ❌ |
| `GET` | `/frost/key-share/{user_id}` | Get key share | ❌ |
| `GET` | `/health` | Health check | ❌ |
| `GET` | `/status` | Server status | ❌ |

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    mpc_wallet_pubkey TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### Assets Table
```sql
CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    mint_address VARCHAR(44) UNIQUE NOT NULL,
    symbol VARCHAR(20) NOT NULL,
    name VARCHAR(100),
    decimals INTEGER NOT NULL,
    logo_url TEXT,
    is_native BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### User Assets Table
```sql
CREATE TABLE user_assets (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    asset_id VARCHAR(36) NOT NULL,
    wallet_address VARCHAR(44) NOT NULL,
    balance BIGINT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, asset_id)
);
```

### Account Subscriptions Table
```sql
CREATE TABLE account_subscriptions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    wallet_address VARCHAR(44) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    subscribed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_processed_slot BIGINT NOT NULL DEFAULT 0,
    UNIQUE(user_id, wallet_address)
);
```

## 🔍 Project Structure

```
purge-assignment/
├── backend/                 # Main API server
│   ├── src/
│   │   ├── main.rs         # Server entry point
│   │   ├── auth.rs         # JWT authentication middleware
│   │   ├── solana_client.rs # Solana RPC client
│   │   └── routes/
│   │       ├── mod.rs      # Route module
│   │       ├── user.rs     # User authentication routes
│   │       └── solana.rs   # Solana operation routes
│   ├── migrations/         # Database migrations
│   └── .env               # Environment variables
├── indexer/               # Real-time balance monitoring
│   ├── src/
│   │   ├── main.rs        # Indexer entry point
│   │   ├── database.rs    # Database operations
│   │   ├── handlers.rs    # HTTP request handlers
│   │   ├── models.rs      # Data models
│   │   ├── subscription.rs # gRPC subscription management
│   │   └── yellowstone_client.rs # Yellowstone gRPC client
│   └── .env              # Environment variables
├── mpc/                  # MPC servers
│   ├── src/
│   │   ├── main.rs       # MPC server entry point
│   │   ├── database.rs   # Key share storage
│   │   ├── distributed_mpc.rs # FROST protocol implementation
│   │   ├── error.rs      # Error handling
│   │   └── solana.rs     # Solana-specific operations
│   ├── data/            # SQLite databases
│   └── .env            # Environment variables
├── store/               # Shared data layer
│   ├── src/
│   │   ├── lib.rs      # Store module
│   │   ├── user.rs     # User operations
│   │   ├── asset.rs    # Asset management
│   │   └── redis.rs    # Redis operations
├── logs/               # Application logs
├── Makefile           # Build and run commands
├── setup-env.sh       # Environment setup script
└── README.md          # This file
```

## 🔧 Environment Variables

### Backend (.env)
```bash
DATABASE_URL=postgresql://postgres:password@localhost/purge_assignment
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
REDIS_URL=redis://127.0.0.1:6379/
INDEXER_URL=http://127.0.0.1:8090
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
MPC_SERVER_1_URL=http://127.0.0.1:8081
MPC_SERVER_2_URL=http://127.0.0.1:8082
MPC_SERVER_3_URL=http://127.0.0.1:8083
JUPITER_API_URL=https://lite-api.jup.ag
PORT=8080
HOST=127.0.0.1
RUST_LOG=backend=debug,sqlx=debug,actix_web=info
```

### Indexer (.env)
```bash
DATABASE_URL=postgresql://postgres:password@localhost/purge_assignment
GEYSER_GRPC_ENDPOINT=https://api.mainnet-beta.solana.com
PORT=8090
HOST=127.0.0.1
RUST_LOG=indexer=debug,sqlx=debug
MAX_RETRY_ATTEMPTS=5
RETRY_DELAY_SECONDS=2
SUBSCRIPTION_TIMEOUT_SECONDS=300
```

### MPC (.env)
```bash
DATABASE_URL=sqlite:data/mpc.db
PORT=8081
HOST=127.0.0.1
PARTICIPANT_ID=1
RUST_LOG=mpc=debug
```

## 🐳 Docker Commands

### Start PostgreSQL
```bash
docker run --name postgres-purge \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=purge_assignment \
  -p 5432:5432 \
  -d postgres:14
```

### Start Redis (Alternative)
```bash
docker run --name redis-purge \
  -p 6379:6379 \
  -d redis:7-alpine
```

### Stop and Remove Containers
```bash
docker stop postgres-purge redis-purge
docker rm postgres-purge redis-purge
```

## 🔍 Troubleshooting

### Common Issues

1. **Database Connection Error**
   ```bash
   # Check if PostgreSQL is running
   docker ps | grep postgres
   
   # Check database URL
   echo $DATABASE_URL
   ```

2. **Redis Connection Error**
   ```bash
   # Check if Redis is running
   brew services list | grep redis
   
   # Test Redis connection
   redis-cli ping
   ```

3. **MPC Server Errors**
   ```bash
   # Check if all MPC servers are running
   curl http://localhost:8081/health
   curl http://localhost:8082/health
   curl http://localhost:8083/health
   ```

4. **Port Conflicts**
   ```bash
   # Check what's using the ports
   lsof -i :8080  # Backend
   lsof -i :8081  # MPC Server 1
   lsof -i :8082  # MPC Server 2
   lsof -i :8083  # MPC Server 3
   lsof -i :8090  # Indexer
   lsof -i :5432  # PostgreSQL
   lsof -i :6379  # Redis
   ```

### Logs

```bash
# View logs for each service
tail -f logs/backend.log
tail -f logs/indexer.log
tail -f logs/mpc1.log
tail -f logs/mpc2.log
tail -f logs/mpc3.log
```

## 🧪 Development

### Running Tests

```bash
# Run all tests
make test

# Run specific service tests
cd backend && cargo test
cd indexer && cargo test
cd mpc && cargo test
cd store && cargo test
```

### Adding New Features

1. **Database Changes**: Create migration in `backend/migrations/`
2. **API Endpoints**: Add routes in `backend/src/routes/`
3. **MPC Operations**: Extend `mpc/src/distributed_mpc.rs`
4. **Indexer Features**: Modify `indexer/src/subscription.rs`

### Code Style

- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Follow Rust naming conventions
- Add documentation for public APIs

## 📚 Additional Resources

- [FROST-ed25519 Documentation](https://github.com/ZcashFoundation/frost)
- [Solana Documentation](https://docs.solana.com/)
- [Jupiter API Documentation](https://docs.jup.ag/)
- [Yellowstone gRPC Documentation](https://github.com/rpcpool/yellowstone-grpc)
- [Actix-web Documentation](https://actix.rs/)
- [SQLx Documentation](https://docs.rs/sqlx/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

If you encounter any issues or have questions:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review the logs in the `logs/` directory
3. Open an issue on GitHub
4. Check the service status with `make status`

---

**Happy coding! 🚀**