#!/bin/bash

# FROST MPC Servers Startup Script
# This script starts 3 MPC servers on ports 8081, 8082, and 8083

echo "Starting FROST MPC servers..."
echo "================================"

# Function to cleanup background processes on script exit
cleanup() {
    echo ""
    echo "Shutting down MPC servers..."
    kill $(jobs -p) 2>/dev/null
    exit
}

# Set up signal handlers for cleanup
trap cleanup SIGINT SIGTERM

# Start server 1 on port 8081
echo "Starting MPC Server 1 on port 8081..."
cargo run --bin frost-mpc -- --port 8081 &
SERVER1_PID=$!

# Start server 2 on port 8082
echo "Starting MPC Server 2 on port 8082..."
cargo run --bin frost-mpc -- --port 8082 &
SERVER2_PID=$!

# Start server 3 on port 8083
echo "Starting MPC Server 3 on port 8083..."
cargo run --bin frost-mpc -- --port 8083 &
SERVER3_PID=$!

echo ""
echo "All MPC servers are starting up..."
echo "Server 1 (PID: $SERVER1_PID) - Port 8081"
echo "Server 2 (PID: $SERVER2_PID) - Port 8082" 
echo "Server 3 (PID: $SERVER3_PID) - Port 8083"
echo ""
echo "Press Ctrl+C to stop all servers"
echo "================================"

# Wait for all background processes
wait
