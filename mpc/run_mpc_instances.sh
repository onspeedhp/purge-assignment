#!/bin/bash

# Script to run 3 MPC instances for TSS testing
# Each instance runs on a different port with its own database

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MPC1_PORT=8080
MPC2_PORT=8081
MPC3_PORT=8082

echo -e "${BLUE}🚀 Starting 3 MPC instances for TSS testing${NC}"
echo "=============================================="

# Function to start MPC instance
start_mpc() {
    local port=$1
    local name=$2
    local db_name=$3
    
    echo -e "${YELLOW}Starting $name on port $port with database $db_name...${NC}"
    
    # Set environment variables
    export PORT=$port
    export DATABASE_URL="sqlite:$(pwd)/$db_name"
    
    # Convert name to lowercase for file names
    local name_lower=$(echo "$name" | tr '[:upper:]' '[:lower:]')
    
    # Start the MPC instance in background
    cargo run --bin solana-mpc-tss > "logs/${name_lower}.log" 2>&1 &
    local pid=$!
    
    # Store PID for cleanup
    echo $pid > "pids/${name_lower}.pid"
    
    echo -e "${GREEN}✅ $name started with PID $pid${NC}"
    
    # Wait a bit for the server to start
    sleep 3
    
    # Check if server is responding
    if curl -s "http://127.0.0.1:$port/health" | grep -q "healthy"; then
        echo -e "${GREEN}✅ $name is responding to health checks${NC}"
    else
        echo -e "${RED}❌ $name is not responding to health checks${NC}"
        echo -e "${YELLOW}Check logs: logs/${name_lower}.log${NC}"
        return 1
    fi
}

# Create necessary directories
mkdir -p logs pids

# Clean up any existing processes
echo -e "${YELLOW}Cleaning up any existing MPC processes...${NC}"
pkill -f "solana-mpc-tss" || true
rm -f pids/*.pid logs/*.log

# Check if databases exist
if [ ! -f "mpc1.db" ] || [ ! -f "mpc2.db" ] || [ ! -f "mpc3.db" ]; then
    echo -e "${YELLOW}Database files not found. Running setup...${NC}"
    ./setup_database.sh
fi

# Start all 3 MPC instances
echo -e "${BLUE}📋 Starting MPC instances...${NC}"

start_mpc $MPC1_PORT "MPC1" "mpc1.db"
start_mpc $MPC2_PORT "MPC2" "mpc2.db"
start_mpc $MPC3_PORT "MPC3" "mpc3.db"

echo ""
echo -e "${GREEN}🎉 All MPC instances started successfully!${NC}"
echo "=============================================="
echo -e "${BLUE}Instance Details:${NC}"
echo "- MPC1: http://127.0.0.1:$MPC1_PORT (Database: mpc1.db)"
echo "- MPC2: http://127.0.0.1:$MPC2_PORT (Database: mpc2.db)"
echo "- MPC3: http://127.0.0.1:$MPC3_PORT (Database: mpc3.db)"
echo ""
echo -e "${YELLOW}Available endpoints on each instance:${NC}"
echo "- POST /generate"
echo "- POST /send-single"
echo "- POST /aggregate-keys"
echo "- POST /agg-send-step1"
echo "- POST /agg-send-step2"
echo "- POST /aggregate-signatures-broadcast"
echo "- GET /health"
echo ""
echo -e "${BLUE}To test the TSS workflow, run:${NC}"
echo "./test_tss_workflow.sh"
echo ""
echo -e "${YELLOW}To stop all instances, run:${NC}"
echo "./stop_mpc_instances.sh"
echo ""
echo -e "${GREEN}Logs are available in the 'logs/' directory${NC}"
echo -e "${GREEN}PIDs are stored in the 'pids/' directory${NC}"

# Keep script running and show logs
echo -e "${BLUE}📊 Monitoring logs (Press Ctrl+C to stop all instances)...${NC}"
echo "=============================================="

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}Stopping all MPC instances...${NC}"
    pkill -f "solana-mpc-tss" || true
    rm -f pids/*.pid
    echo -e "${GREEN}✅ All instances stopped${NC}"
    exit 0
}

# Set trap for cleanup
trap cleanup SIGINT SIGTERM

# Monitor logs
tail -f logs/*.log
