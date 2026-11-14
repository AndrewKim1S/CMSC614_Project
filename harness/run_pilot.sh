#!/bin/bash
# Pilot: Our System on several targets in parallel inside one job.
#   srun -p mc2 --account=mc2 --qos=default -c 4 --mem=16G -t 02:00:00 \
#       harness/run_pilot.sh --max-llm-calls 20
# Override the target list with TARGETS="id1 id2 ...". Extra args go to every campaign.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGETS=${TARGETS:-"CVE-2017-12067 CVE-2022-44081 CVE-2021-46023 CVE-2017-11654 CVE-2026-3389"}
mkdir -p "$ROOT/logs"
for t in $TARGETS; do
    "$ROOT/harness/run_campaign.sh" --target "$t" "$@" > "$ROOT/logs/pilot-${t//#/_}.log" 2>&1 &
done
wait
for t in $TARGETS; do
    echo "=== $t"; tail -n 4 "$ROOT/logs/pilot-${t//#/_}.log"
done
