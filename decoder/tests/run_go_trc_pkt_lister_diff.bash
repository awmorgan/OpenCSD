#!/bin/bash
set -euo pipefail

OUT_DIR=./results-go
SNAPSHOT_DIR=./snapshots
GOLDEN_DIR=./results
GO_TOOL_DIR=../../opencsd

mkdir -p "${OUT_DIR}"

# snapshot_name source_name extra_args
cases=(
  "trace_cov_a15 PTM_0_2 -decode -no_time_print"
  "TC2 ETB_0 -decode -no_time_print"
  "itm_only_raw ETB_1 -decode -no_time_print"
  "stm_only ETB_1 -decode -no_time_print"
)

normalize() {
  local in_file="$1"
  local out_file="$2"
  awk '
    BEGIN { skip_cmd=0 }
    /^Test Command Line:-$/ { skip_cmd=1; next }
    skip_cmd==1 {
      if ($0 ~ /^$/) { skip_cmd=0; next }
      next
    }
    /^Trace Packet Lister : reading snapshot from path / { next }
    /^Filename=/ { next }
    /^Gen_Info : FileAcc; Range::/ { next }
    /^Idx:/ {
      if (index($0, "OCSD_GEN_TRC_ELEM_") > 0) {
        if (match($0, /OCSD_GEN_TRC_ELEM_[A-Z_]+/)) {
          print substr($0, 1, RSTART+RLENGTH-1)
          next
        }
      }
      next
    }
    /^ID:[0-9a-fA-F]+[ 	]+END OF TRACE DATA$/ {
      line=$0
      gsub(/[ 	]+/, " ", line)
      print line
      next
    }
    { print }
  ' "$in_file" > "$out_file"
}

rc=0

for item in "${cases[@]}"; do
  set -- $item
  name="$1"
  source="$2"
  shift 2
  extra=("$@")

  echo "[go-trc-pkt-lister] Running ${name} (${source})"
  out_file="${OUT_DIR}/${name}.ppl"
  golden_file="${GOLDEN_DIR}/${name}.ppl"

  (
    cd "${GO_TOOL_DIR}"
    go run ./cmd/trc_pkt_lister \
      -ss_dir "../decoder/tests/${SNAPSHOT_DIR}/${name}" \
      -src_name "${source}" \
      "${extra[@]}" \
      -logfilename "../decoder/tests/${out_file}"
  )

  if [[ ! -f "${golden_file}" ]]; then
    echo "[go-trc-pkt-lister] Missing golden: ${golden_file}"
    rc=1
    continue
  fi

  norm_out="${OUT_DIR}/${name}.norm"
  norm_golden="${OUT_DIR}/${name}.golden.norm"
  normalize "${out_file}" "${norm_out}"
  normalize "${golden_file}" "${norm_golden}"

  if ! diff -u "${norm_golden}" "${norm_out}" > "${OUT_DIR}/${name}.diff"; then
    echo "[go-trc-pkt-lister] DIFF FAIL: ${name} (see ${OUT_DIR}/${name}.diff)"
    rc=1
  else
    echo "[go-trc-pkt-lister] DIFF PASS: ${name}"
    rm -f "${OUT_DIR}/${name}.diff"
  fi
done

exit $rc
