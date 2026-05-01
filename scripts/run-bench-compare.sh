#!/usr/bin/env bash
# run-bench-compare.sh — Build and run the NovaNet vs TCP benchmark suite.
#
# Usage:
#   ./scripts/run-bench-compare.sh              # default settings
#   ./scripts/run-bench-compare.sh --quick      # fewer iterations (faster)
#   ./scripts/run-bench-compare.sh --thorough   # more iterations (more stable)
#   ./scripts/run-bench-compare.sh --codec      # also run packet codec Criterion benchmarks

set -euo pipefail

cd "$(dirname "$0")/.."

QUICK=false
THOROUGH=false
CODEC=false

for arg in "$@"; do
    case "$arg" in
        --quick)    QUICK=true ;;
        --thorough) THOROUGH=true ;;
        --codec)    CODEC=true ;;
    esac
done

if $QUICK; then
    ITERS=100
    CONN_ITERS=10
    WARMUP=5
elif $THOROUGH; then
    ITERS=2000
    CONN_ITERS=60
    WARMUP=50
else
    ITERS=500
    CONN_ITERS=30
    WARMUP=20
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Building bench-compare (release)…"
echo "════════════════════════════════════════════════════════════"
cargo build -p bench-compare --release 2>&1 | grep -E "Compiling|Finished|error"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  System info"
echo "════════════════════════════════════════════════════════════"
echo "  OS    : $(uname -sr)"
echo "  CPU   : $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
echo "  Cores : $(nproc)"
echo "  Rust  : $(rustc --version)"
echo "  Date  : $(date '+%Y-%m-%d %H:%M:%S')"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Running NovaNet vs TCP benchmarks…"
echo "  Iterations: $ITERS  Connect: $CONN_ITERS  Warmup: $WARMUP"
echo "════════════════════════════════════════════════════════════"

./target/release/bench-compare \
    --iterations "$ITERS" \
    --connect-iterations "$CONN_ITERS" \
    --warmup "$WARMUP"

if $CODEC; then
    echo ""
    echo "════════════════════════════════════════════════════════════"
    echo "  Running packet codec Criterion benchmarks…"
    echo "════════════════════════════════════════════════════════════"
    cargo bench -p novanet-wire 2>&1 | grep -E "test|time:|ns/iter|Benchmarking" | head -30
fi

echo ""
echo "  Done. Re-run with --thorough for more stable numbers,"
echo "  or --codec to also benchmark raw packet encode/decode."
