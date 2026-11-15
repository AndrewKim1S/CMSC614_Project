#!/bin/bash
# Build an Apptainer image on a compute node (not the login node).
#   srun -p mc2 --account=mc2 --qos=default -c 4 --mem=16G -t 01:00:00 env/build_image.sh            # fuzz.sif
#   srun -p mc2 --account=mc2 --qos=default -c 4 --mem=16G -t 01:00:00 env/build_image.sh ghidra     # ghidra.sif
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
NAME=${1:-fuzz}
DEST=${DEST:-/fs/nexus-scratch/$USER/cmsc614/images/$NAME.sif}
mkdir -p "$(dirname "$DEST")"
export APPTAINER_CACHEDIR=${APPTAINER_CACHEDIR:-/fs/nexus-scratch/$USER/.apptainer-cache}
# Unprivileged (fakeroot) builds break on NFS, so build in node-local /tmp.
export APPTAINER_TMPDIR=$(mktemp -d /tmp/apptainer-build-XXXXXX)
trap 'rm -rf "$APPTAINER_TMPDIR"' EXIT
echo "node=$(hostname) dest=$DEST tmp=$APPTAINER_TMPDIR ($(df -h /tmp | awk 'NR==2{print $4}') free)"
apptainer build --fakeroot --force "$DEST" "$ROOT/env/$NAME.def"
ls -la "$DEST"
