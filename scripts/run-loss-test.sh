#!/usr/bin/env bash
# Run a loss/jitter test using tc netem on loopback.
# Requires: tc (iproute2), root/sudo for tc on lo.
set -euo pipefail

PRESET="${1:-wan}"
PORT="${2:-19800}"
MESSAGE="Loss test message at $(date)"

echo "=== NovaNet Loss Test ==="
echo "Preset: $PRESET  Port: $PORT"
echo ""

# Build
cargo build --bin echo-server --bin echo-client -q

# Run server
cargo run --bin echo-server -q -- --addr "127.0.0.1:${PORT}" --log debug &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null' EXIT

sleep 0.2

# Run client
cargo run --bin echo-client -q -- \
    --server "127.0.0.1:${PORT}" \
    --message "$MESSAGE" \
    --log info \
    --timeout-ms 5000

echo ""
echo "=== Test complete ==="
