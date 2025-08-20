#!/bin/sh

set -eu

PORT=${1?usage: bench/benchmark.sh <port>}
cd "$(dirname "$0")"

command -v wrk >/dev/null 2>&1 || { echo "missing wrk" >&2; exit 1; }

echo "=== small ==="
wrk --latency -t4 -c256 -d10s "http://127.0.0.1:$PORT/small" 2>/dev/null
echo
echo "=== medium ==="
wrk --latency -t4 -c256 -d10s "http://127.0.0.1:$PORT/medium" 2>/dev/null
echo
echo "=== big ==="
wrk --latency -t2 -c64 -d10s "http://127.0.0.1:$PORT/big" 2>/dev/null
echo
echo "=== mixed ==="
wrk --latency -t4 -c256 -d10s -s mixed.lua "http://127.0.0.1:$PORT/" 2>/dev/null
