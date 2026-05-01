#!/usr/bin/env bash
# Run the NovaNet echo demo: start a server, run a client, verify the echo.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

SERVER_PORT="${NOVANET_PORT:-9999}"
SERVER_ADDR="127.0.0.1:${SERVER_PORT}"
CLIENT_BIND="127.0.0.1:0"
MESSAGE="${1:-Hello from NovaNet!}"

echo "=== NovaNet Echo Demo ==="
echo "Server: $SERVER_ADDR"
echo "Message: $MESSAGE"
echo ""

# Build if needed
echo "Building..."
cargo build --bin echo-server --bin echo-client -q

# Start the server in the background
echo "Starting echo-server on $SERVER_ADDR ..."
cargo run --bin echo-server -q -- --addr "$SERVER_ADDR" --log info &
SERVER_PID=$!

# Ensure server is killed on exit
trap 'echo "Stopping server (PID $SERVER_PID)..."; kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; echo "Done."' EXIT

# Give the server a moment to bind
sleep 0.2

# Run the client
echo "Running echo-client..."
echo ""
cargo run --bin echo-client -q -- \
    --server "$SERVER_ADDR" \
    --local "$CLIENT_BIND" \
    --message "$MESSAGE" \
    --log info \
    --timeout-ms 2000

echo ""
echo "=== Demo complete ==="
