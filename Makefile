# Solana MPC Wallet Makefile

.PHONY: help start-all stop-all status test-auth

help: ## Show commands
	@echo "Commands:"
	@echo "  start-all  - Start all services"
	@echo "  stop-all   - Stop all services" 
	@echo "  status     - Check status"
	@echo "  test-auth  - Test authentication"

start-all: ## Start all services
	@echo "🚀 Starting all services..."
	@docker run --name postgres-purge -e POSTGRES_PASSWORD=password -e POSTGRES_DB=purge_assignment -p 5432:5432 -d postgres:14 2>/dev/null || echo "PostgreSQL already running"
	@brew services start redis 2>/dev/null || echo "Redis already running"
	@sleep 3
	@cd backend && sqlx migrate run
	@mkdir -p logs
	@cd mpc && cargo run --bin frost-mpc -- --port 8081 > ../logs/mpc1.log 2>&1 &
	@cd mpc && cargo run --bin frost-mpc -- --port 8082 > ../logs/mpc2.log 2>&1 &
	@cd mpc && cargo run --bin frost-mpc -- --port 8083 > ../logs/mpc3.log 2>&1 &
	@sleep 3
	@cd backend && cargo run > ../logs/backend.log 2>&1 &
	@cd indexer && cargo run > ../logs/indexer.log 2>&1 &
	@sleep 3
	@echo "✅ All services started!"

stop-all: ## Stop all services
	@echo "🛑 Stopping all services..."
	@docker stop postgres-purge 2>/dev/null || true
	@pkill -f "cargo run" 2>/dev/null || true
	@echo "✅ All services stopped!"

status: ## Check status
	@echo "📊 Service Status:"
	@echo "PostgreSQL: $$(docker ps | grep postgres-purge | wc -l | tr -d ' ') running"
	@echo "Backend: $$(curl -s http://localhost:8080/health > /dev/null && echo "running" || echo "not running")"
	@echo "MPC 1: $$(curl -s http://localhost:8081/health > /dev/null && echo "running" || echo "not running")"

test-auth: ## Test authentication
	@echo "🧪 Testing authentication..."
	@curl -X POST http://localhost:8080/api/v1/signup \
		-H "Content-Type: application/json" \
		-d '{"username": "test@example.com", "password": "password123"}' || echo "Backend not running"
