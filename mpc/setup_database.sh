#!/bin/bash

# Script to setup SQLite databases for MPC instances

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🗄️  Setting up MPC databases...${NC}"
echo "=================================="

# Create database files
echo -e "${YELLOW}Creating database files...${NC}"

# Create MPC1 database
echo -e "${GREEN}Creating mpc1.db...${NC}"
sqlite3 mpc1.db < migrations/001_initial_schema.sql

# Create MPC2 database  
echo -e "${GREEN}Creating mpc2.db...${NC}"
sqlite3 mpc2.db < migrations/001_initial_schema.sql

# Create MPC3 database
echo -e "${GREEN}Creating mpc3.db...${NC}"
sqlite3 mpc3.db < migrations/001_initial_schema.sql

echo ""
echo -e "${GREEN}✅ All databases created successfully!${NC}"
echo "=================================="
echo -e "${BLUE}Database files:${NC}"
echo "- mpc1.db (for MPC1 instance)"
echo "- mpc2.db (for MPC2 instance)"
echo "- mpc3.db (for MPC3 instance)"
echo ""
echo -e "${YELLOW}To verify databases, run:${NC}"
echo "sqlite3 mpc1.db '.schema'"
echo "sqlite3 mpc2.db '.schema'"
echo "sqlite3 mpc3.db '.schema'"
