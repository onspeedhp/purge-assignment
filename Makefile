# Solana MPC Wallet Makefile

.PHONY: help start-all stop-all status test-auth start-db start-mpc start-backend start-indexer start-docker

help: ## Show commands
	@echo "Commands:"
	@echo "  start-docker  - Start Docker daemon"
	@echo "  start-all     - Start all services"
	@echo "  start-db      - Start PostgreSQL"
	@echo "  start-mpc     - Start MPC servers"
	@echo "  start-backend - Start backend API"
	@echo "  start-indexer - Start indexer service"
	@echo "  stop-all      - Stop all services" 
	@echo "  status        - Check status"
	@echo "  test-auth     - Test authentication"

start-docker: ## Start Docker daemon
	@echo "🐳 Starting Docker daemon..."
	@open -a Docker
	@echo "⏳ Waiting for Docker to start..."
	@while ! docker ps > /dev/null 2>&1; do sleep 2; done
	@echo "✅ Docker daemon started!"

start-all: start-docker start-db start-mpc start-backend start-indexer ## Start all services

start-db: ## Start PostgreSQL database
	@echo "🐳 Starting PostgreSQL..."
	@if ! docker ps | grep postgres-purge > /dev/null; then \
		echo "Starting PostgreSQL..."; \
		docker start postgres-purge 2>/dev/null || docker run --name postgres-purge -e POSTGRES_PASSWORD=password -e POSTGRES_DB=purge_assignment -p 5432:5432 -d postgres:14; \
	else \
		echo "PostgreSQL already running"; \
	fi
	@brew services start redis 2>/dev/null || echo "Redis already running"
	@sleep 3
	@cd backend && sqlx migrate run
	@echo "✅ Database services started!"

start-mpc: ## Start MPC servers
	@echo "🔐 Starting MPC servers..."
	@mkdir -p logs
	@mkdir -p mpc/data
	@chmod 666 mpc/data/*.db 2>/dev/null || true
	@echo "Starting MPC Server 1 (port 8081)..."
	@cd mpc && DATABASE_URL="sqlite:data/mpc8081.db" nohup cargo run --bin frost-mpc -- --port 8081 > ../logs/mpc1.log 2>&1 &
	@sleep 3
	@echo "Starting MPC Server 2 (port 8082)..."
	@cd mpc && DATABASE_URL="sqlite:data/mpc8082.db" nohup cargo run --bin frost-mpc -- --port 8082 > ../logs/mpc2.log 2>&1 &
	@sleep 3
	@echo "Starting MPC Server 3 (port 8083)..."
	@cd mpc && DATABASE_URL="sqlite:data/mpc8083.db" nohup cargo run --bin frost-mpc -- --port 8083 > ../logs/mpc3.log 2>&1 &
	@sleep 5
	@echo "✅ MPC servers started!"

start-backend: ## Start backend API
	@echo "🚀 Starting Backend API..."
	@cd backend && nohup cargo run > ../logs/backend.log 2>&1 &
	@sleep 3
	@echo "✅ Backend API started!"

start-indexer: ## Start indexer service
	@echo "📊 Starting Indexer Service..."
	@cd indexer && nohup cargo run > ../logs/indexer.log 2>&1 &
	@sleep 3
	@echo "✅ Indexer Service started!"

stop-all: ## Stop all services
	@echo "🛑 Stopping all services..."
	@if docker ps -q --filter "name=postgres-purge" | grep -q .; then \
		echo "Stopping PostgreSQL container..."; \
		docker stop postgres-purge 2>/dev/null || true; \
	else \
		echo "PostgreSQL container not running"; \
	fi
	@pkill -f "frost-mpc" 2>/dev/null || true
	@pkill -f "backend" 2>/dev/null || true
	@pkill -f "indexer" 2>/dev/null || true
	@pkill -f "cargo run" 2>/dev/null || true
	@killall -9 frost-mpc 2>/dev/null || true
	@echo "✅ All services stopped!"

status: ## Check status
	@echo "📊 Service Status:"
	@echo "PostgreSQL: $$(docker ps | grep postgres-purge | wc -l | tr -d ' ') running"
	@echo "Backend: $$(curl -s http://localhost:8080/health > /dev/null && echo "running" || echo "not running")"
	@echo "MPC 1: $$(curl -s http://localhost:8081/health > /dev/null && echo "running" || echo "not running")"
	@echo "MPC 2: $$(curl -s http://localhost:8082/health > /dev/null && echo "running" || echo "not running")"
	@echo "MPC 3: $$(curl -s http://localhost:8083/health > /dev/null && echo "running" || echo "not running")"
	@echo "Indexer: $$(curl -s http://localhost:8090/health > /dev/null && echo "running" || echo "not running")"

test-auth: ## Test authentication
	@echo "🧪 Testing authentication..."
	@curl -X POST http://localhost:8080/api/v1/signup \
		-H "Content-Type: application/json" \
		-d '{"username": "test@example.com", "password": "password123"}' || echo "Backend not running"
