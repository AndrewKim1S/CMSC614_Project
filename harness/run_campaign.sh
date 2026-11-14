#!/bin/bash
# Run one campaign inside the shared image; extra arguments go to fuzzer.campaign.
#   srun -p mc2 --account=mc2 --qos=default -c 2 --mem=8G -t 01:00:00 \
#       harness/run_campaign.sh --target CVE-2017-12067 --max-llm-calls 20
# LLM_URL defaults to the endpoint written by the vLLM serving job.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SIF=${SIF:-/fs/nexus-scratch/$USER/cmsc614/images/fuzz.sif}
LLM_URL=${LLM_URL:-$(cat /fs/nexus-scratch/$USER/poc-gen/serve_endpoint.txt)}
# Node-local scratch for per-execution directories (the container's own /tmp is small).
HOST_TMP=$(mktemp -d /tmp/cmsc614-XXXXXX)
trap 'rm -rf "$HOST_TMP"' EXIT
apptainer exec --containall --cleanenv --bind "$ROOT":/work --bind "$HOST_TMP":/tmp \
    --pwd /work "$SIF" python3 -m fuzzer.campaign --llm-url "$LLM_URL" "$@"
