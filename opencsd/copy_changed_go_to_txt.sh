#!/usr/bin/env bash
set -euo pipefail

# Copy changed (modified) and untracked .go files to path-prefixed .txt names.
# Place this script next to `go.mod` (module root). It operates relative to the
# script location, so you can run it from anywhere.
# Example: internal/stm/stm_test.go -> internal/stm/internal_stm__stm_test.go.txt
# Usage:
#   chmod +x copy_changed_go_to_txt.sh
#   ./copy_changed_go_to_txt.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f go.mod ]; then
  echo "Error: go.mod not found in $SCRIPT_DIR. Place this script next to go.mod." >&2
  exit 2
fi

# Gather modified and untracked .go files (null-separated)
mapfile -d '' -t files < <(git ls-files -m -o --exclude-standard -z -- "*.go" || true)

if [ "${#files[@]}" -eq 0 ]; then
  echo "No changed/untracked .go files found."
  exit 0
fi

created=0
skipped=0

for f in "${files[@]}"; do
  [ -z "$f" ] && continue
  file="$f"
  dir=$(dirname -- "$file")
  base=$(basename -- "$file")

  if [ "$dir" = "." ] || [ "$dir" = "" ]; then
    dest="opencsd_${base}.txt"
  else
    rel=${dir//\//_}
    dest="$dir/opencsd_${rel}__${base}.txt"
  fi

  if [ -e "$dest" ]; then
    echo "Skipping existing: $dest"
    skipped=$((skipped+1))
  else
    mkdir -p -- "$(dirname -- "$dest")"
    cp -p -- "$file" "$dest"
    echo "Copied: $file -> $dest"
    created=$((created+1))
  fi
done

echo "Created=$created Skipped=$skipped"
