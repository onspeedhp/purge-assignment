#!/bin/bash
echo "🔐 Starting MPC Servers..."

# Create data directory and set permissions
mkdir -p mpc/data
chmod 666 mpc/data/*.db 2>/dev/null || true

# Start MPC Server 1
echo "Starting MPC Server 1 (port 8081)..."
cd mpc
nohup cargo run --bin frost-mpc -- --port 8081 > ../logs/mpc1.log 2>&1 &
MPC1_PID=$!
echo "MPC Server 1 PID: $MPC1_PID"
cd ..

sleep 3

# Start MPC Server 2
echo "Starting MPC Server 2 (port 8082)..."
cd mpc
nohup cargo run --bin frost-mpc -- --port 8082 > ../logs/mpc2.log 2>&1 &
MPC2_PID=$!
echo "MPC Server 2 PID: $MPC2_PID"
cd ..

sleep 3

# Start MPC Server 3
echo "Starting MPC Server 3 (port 8083)..."
cd mpc
nohup cargo run --bin frost-mpc -- --port 8083 > ../logs/mpc3.log 2>&1 &
MPC3_PID=$!
echo "MPC Server 3 PID: $MPC3_PID"
cd ..

sleep 5

# Check if servers are running
echo "Checking MPC servers..."
for port in 8081 8082 8083; do
    if curl -s http://localhost:$port/health > /dev/null; then
        echo "✅ MPC Server $port: running"
    else
        echo "❌ MPC Server $port: not running"
    fi
done

echo "MPC servers startup completed!"
