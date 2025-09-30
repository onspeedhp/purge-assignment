#!/bin/bash
echo "🔧 Setting up environment..."
mkdir -p logs
cat > backend/.env << 'ENVEOF'
DATABASE_URL=postgresql://postgres:password@localhost/purge_assignment
JWT_SECRET=your-super-secret-jwt-key
REDIS_URL=redis://127.0.0.1:6379/
INDEXER_URL=http://127.0.0.1:8090
ENVEOF
cat > indexer/.env << 'ENVEOF'
DATABASE_URL=postgresql://postgres:password@localhost/purge_assignment
GEYSER_GRPC_ENDPOINT=https://api.mainnet-beta.solana.com
ENVEOF
echo "✅ Environment setup complete!"
