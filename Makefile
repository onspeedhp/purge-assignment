# Makefile for Migration Management

# Variables
DATABASE_URL ?= postgresql://username:password@localhost:5432/purge_assignment

# Colors for output
GREEN = \033[0;32m
YELLOW = \033[1;33m
RED = \033[0;31m
NC = \033[0m # No Color

.PHONY: help migrate migrate-up migrate-down migrate-status migrate-new

# Default target
help: ## Show this help message
	@echo "$(GREEN)Available migration commands:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Migration commands
migrate: migrate-up ## Run all pending migrations (alias for migrate-up)

migrate-up: ## Run all pending migrations
	@echo "$(GREEN)Running migrations...$(NC)"
	@cd backend && DATABASE_URL="$(DATABASE_URL)" sqlx migrate run
	@echo "$(GREEN)Migrations completed!$(NC)"

migrate-down: ## Rollback the last migration
	@echo "$(YELLOW)Rolling back last migration...$(NC)"
	@cd backend && DATABASE_URL="$(DATABASE_URL)" sqlx migrate revert
	@echo "$(GREEN)Migration rolled back!$(NC)"

migrate-status: ## Show migration status
	@echo "$(GREEN)Migration status:$(NC)"
	@cd backend && DATABASE_URL="$(DATABASE_URL)" sqlx migrate info

migrate-new: ## Create a new migration (usage: make migrate-new NAME=migration_name)
	@if [ -z "$(NAME)" ]; then \
		echo "$(RED)Error: Please provide a migration name$(NC)"; \
		echo "Usage: make migrate-new NAME=add_user_table"; \
		exit 1; \
	fi
	@echo "$(GREEN)Creating new migration: $(NAME)$(NC)"
	@cd backend && sqlx migrate add $(NAME)
