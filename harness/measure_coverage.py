#!/usr/bin/env python3
"""Measure the function coverage of every input each run executed, the same
way for every configuration (and for any other tool's inputs placed in a run's
inputs/ directory): replay on the debug build with one-shot breakpoints on all
of its functions. Writes coverage.json next to each run's summary.json, with
the coverage curve over LLM calls and time.

    PYTHONPATH=. python3 harness/measure_coverage.py runs/exp1 [--jobs 4]   # in fuzz.sif
"""
import argparse
import json
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fuzzer.coverage import FunctionCoverage  # noqa: E402
from fuzzer.sources import symbols  # noqa: E402
from fuzzer.target import load_targets  # noqa: E402


def measure(run_dir):
    run = Path(run_dir)
    out = run / "coverage.json"
    if out.exists():
        return run_dir, json.loads(out.read_text())["covered"], "cached"
    cfg = json.loads((run / "config.json").read_text())
    t = load_targets(ROOT / cfg["targets"], ROOT / cfg["dataset"])[cfg["target"]]
    funcs = symbols(t.original_binary)
    cov = FunctionCoverage(t, t.original_binary, funcs, tempfile.mkdtemp(prefix="mcov-"))
    covered, curve, calls, per_input = set(), [], 0, {}
    for line in (run / "events.jsonl").read_text().splitlines():
        e = json.loads(line)
        if e["event"] == "llm":
            calls = e["call"]
        elif e["event"] == "exec":
            f = run / "inputs" / f"{e['sha1'][:16]}{t.suffix}"
            if not f.exists():
                continue
            got = cov.run(f.read_bytes())
            per_input[e["sha1"][:16]] = len(got)
            if got - covered:
                covered |= got
                curve.append({"t": e["t"], "llm_calls": calls, "covered": len(covered)})
    result = {"target": cfg["target"], "functions": len(cov.entries), "covered": len(covered),
              "curve": curve, "per_input": per_input,
              "method": "function entry, gdb one-shot breakpoints, debug build"}
    out.write_text(json.dumps(result, indent=1) + "\n")
    return run_dir, len(covered), "measured"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root", help="experiment directory (searched for */summary.json)")
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()
    runs = sorted(str(p.parent) for p in Path(args.root).rglob("summary.json"))
    print(f"{len(runs)} runs", flush=True)
    with ProcessPoolExecutor(args.jobs) as pool:
        for run, covered, how in pool.map(measure, runs):
            print(f"{run}: {covered} functions ({how})", flush=True)


if __name__ == "__main__":
    main()
