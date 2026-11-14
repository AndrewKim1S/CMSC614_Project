#!/usr/bin/env python3
"""Turn a PoC replay (harness/repro.py output) into the crash ground truth
used by fuzzer/triage.py: {case id: {signal, func, src}} for crashing cases."""
import json
import sys
from pathlib import Path

results, out = Path(sys.argv[1]), Path(sys.argv[2])
expected = {}
for line in results.read_text().splitlines():
    r = json.loads(line)
    if r["status"].startswith("crash:"):
        expected[r["id"]] = {"signal": r["status"].split(":", 1)[1],
                             "func": r["crash_func"], "src": r["crash_src"]}
out.write_text(json.dumps(expected, indent=1) + "\n")
print(f"{len(expected)} expected crash sites -> {out}")
