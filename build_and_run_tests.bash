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

echo "==> Running ETE tests"
./run_pkt_decode_tests-ete.bash -bindir "$BIN_DIR"
echo "==> Done. Results in: $TESTS_DIR/results-ete"

echo "==> Generating snapshot parsed dumps"
for ss_dir in snapshots/*; do
	if [[ -d "$ss_dir" && -f "$ss_dir/snapshot.ini" ]]; then
		name="$(basename "$ss_dir")"
		"$BIN_DIR/snapshot_parse_dump.exe" -ss_dir "$ss_dir" -o "results/${name}.snapshot_parsed.txt"
	fi
done
for ss_dir in snapshots-ete/*; do
	if [[ -d "$ss_dir" && -f "$ss_dir/snapshot.ini" ]]; then
		name="$(basename "$ss_dir")"
		"$BIN_DIR/snapshot_parse_dump.exe" -ss_dir "$ss_dir" -o "results-ete/${name}.snapshot_parsed.txt"
	fi
done
echo "==> Done. Snapshot parsed dumps in: $TESTS_DIR/results and $TESTS_DIR/results-ete"
