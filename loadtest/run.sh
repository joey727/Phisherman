#!/bin/bash
set -e

echo "Starting Phisherman Load Test Pipeline..."

# 1. Build the backend
echo "Building backend..."
npm run build

# 2. Start the backend in the background
echo "Starting backend in cluster mode..."
export ENABLE_WORKER=false
export ENABLE_FEEDS=false
export MAX_INFLIGHT_REQUESTS=200
export WEB_CONCURRENCY=4
node dist/index.js &
BACKEND_PID=$!

cleanup() {
  echo "Cleaning up..."
  kill "$BACKEND_PID" 2>/dev/null || true
}

trap cleanup EXIT

# Wait for backend to be ready
echo "Waiting for backend to initialize..."
sleep 5

# Ensure artillery is available globally or using npx
# We use npx to run artillery without forcing a global installation
echo "Running smoke test..."
npx artillery run -e smoke loadtest/artillery.yml

echo "Running full load test..."
npx artillery run -e load loadtest/artillery.yml

echo "Running stress test..."
npx artillery run -e stress loadtest/artillery.yml

echo "Load test pipeline completed."
