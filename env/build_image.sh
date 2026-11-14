#!/bin/bash
# Build the shared Apptainer image on a compute node (not the login node).
#   srun -p mc2 --account=mc2 --qos=default -c 8 --mem=16G -t 01:00:00 env/build_image.sh
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST=${DEST:-/fs/nexus-scratch/$USER/cmsc614/images/fuzz.sif}
mkdir -p "$(dirname "$DEST")"
export APPTAINER_CACHEDIR=${APPTAINER_CACHEDIR:-/fs/nexus-scratch/$USER/.apptainer-cache}
# Unprivileged (fakeroot) builds break on NFS, so build in node-local /tmp.
export APPTAINER_TMPDIR=$(mktemp -d /tmp/apptainer-build-XXXXXX)
trap 'rm -rf "$APPTAINER_TMPDIR"' EXIT
echo "node=$(hostname) dest=$DEST tmp=$APPTAINER_TMPDIR ($(df -h /tmp | awk 'NR==2{print $4}') free)"
apptainer build --fakeroot --force "$DEST" "$ROOT/env/fuzz.def"
ls -la "$DEST"
