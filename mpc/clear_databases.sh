#!/bin/bash

# Script to clear all MPC databases

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🗑️  Clearing MPC databases...${NC}"
echo "=================================="

# Check if databases exist
if [ ! -f "mpc1.db" ] && [ ! -f "mpc2.db" ] && [ ! -f "mpc3.db" ]; then
    echo -e "${YELLOW}No database files found to clear${NC}"
    exit 0
fi

# Show current database sizes
echo -e "${YELLOW}Current database files:${NC}"
if [ -f "mpc1.db" ]; then
    size1=$(du -h mpc1.db | cut -f1)
    echo -e "  mpc1.db: $size1"
fi
if [ -f "mpc2.db" ]; then
    size2=$(du -h mpc2.db | cut -f1)
    echo -e "  mpc2.db: $size2"
fi
if [ -f "mpc3.db" ]; then
    size3=$(du -h mpc3.db | cut -f1)
    echo -e "  mpc3.db: $size3"
fi

echo ""

# Ask for confirmation
read -p "Are you sure you want to clear all databases? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Operation cancelled${NC}"
    exit 0
fi

# Clear databases
echo -e "${YELLOW}Clearing database files...${NC}"
rm -f mpc1.db mpc2.db mpc3.db

echo -e "${GREEN}✅ All database files cleared${NC}"
echo ""
echo -e "${BLUE}To recreate databases, run:${NC}"
echo "./setup_database.sh"
