#!/usr/bin/env python3
"""Turn a PoC replay (harness/repro.py output) into the crash ground truth
used by fuzzer/triage.py: {case id: {signal, func, src, stack}} for crashing
cases. `stack` lists the program frames of the PoC crash, innermost first
(WhiteFox's vuln mode picks its target from it)."""
import json
import sys
from pathlib import Path

LIBC = {"raise", "abort", "pthread_kill", "__pthread_kill_implementation", "__GI_raise",
        "__GI_abort", "__libc_start_main", "__libc_start_call_main", "_start", "??"}

results, out = Path(sys.argv[1]), Path(sys.argv[2])
expected = {}
for line in results.read_text().splitlines():
    r = json.loads(line)
    if r["status"].startswith("crash:"):
        stack = []
        for f in r["frames"]:
            name = f["func"].split("(")[0]
            if name not in LIBC and name not in stack:
                stack.append(name)
        expected[r["id"]] = {"signal": r["status"].split(":", 1)[1],
                             "func": r["crash_func"], "src": r["crash_src"], "stack": stack}
out.write_text(json.dumps(expected, indent=1) + "\n")
print(f"{len(expected)} expected crash sites -> {out}")
