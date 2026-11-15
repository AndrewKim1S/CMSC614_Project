#!/bin/bash
# Precompute Ghidra exports (once per binary) for Our System's reconstruction.
#   srun -p mc2 --account=mc2 --qos=default -c 4 --mem=16G -t 02:00:00 \
#       harness/run_ghidra.sh CVE-2017-12067 CVE-2022-44081
# Output: analysis/<entry>/<binary>/{functions.jsonl,meta.json,ghidra.log}
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SIF=${GHIDRA_SIF:-/fs/nexus-scratch/$USER/cmsc614/images/ghidra.sif}
HOST_TMP=$(mktemp -d /tmp/cmsc614-ghidra-XXXXXX)
trap 'rm -rf "$HOST_TMP"' EXIT
mkdir -p "$HOST_TMP/home"
args=()
for t in "$@"; do args+=(--target "$t"); done
# Ghidra keeps settings and compiled scripts under $HOME, so give it a real one.
# Heap: analyzeHeadless defaults to 2G; keep it below the job's memory.
apptainer exec --containall --cleanenv --home "$HOST_TMP/home" --bind "$ROOT":/work \
    --bind "$HOST_TMP":/tmp --env GHIDRA_HEADLESS_MAXMEM="${GHIDRA_HEADLESS_MAXMEM:-12G}" \
    --pwd /work "$SIF" python3 -m fuzzer.reconstruct export "${args[@]}"
