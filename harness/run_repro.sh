#!/bin/bash
# Replay every dataset PoC inside the shared image and write a summary.
#   srun -p mc2 --account=mc2 --qos=default -c 2 --mem=8G -t 00:30:00 harness/run_repro.sh
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SIF=${SIF:-/fs/nexus-scratch/$USER/cmsc614/images/fuzz.sif}
OUT_REL=results/repro-$(date +%Y%m%d-%H%M%S)
echo "node=$(hostname) sif=$SIF out=$ROOT/$OUT_REL"
apptainer exec --containall --cleanenv --bind "$ROOT":/work --pwd /work "$SIF" \
    python3 harness/repro.py --dataset dataset --targets harness/targets.json --out "$OUT_REL"
