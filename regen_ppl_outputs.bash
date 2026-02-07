#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT_DIR/decoder/build/mingw"
TESTS_DIR="$ROOT_DIR/decoder/tests"
BIN_DIR="$TESTS_DIR/bin/mingw64/rel/"

echo "==> Building OpenCSD libs and test tools (mingw64/rel)"
cd "$BUILD_DIR"
make -f makefile.dev -j$(nproc)

echo "==> Regenerating .ppl outputs into decoder/tests/results"
cd "$TESTS_DIR"
./run_pkt_decode_tests.bash -bindir "$BIN_DIR"

echo "==> Done. Results in: $TESTS_DIR/results"