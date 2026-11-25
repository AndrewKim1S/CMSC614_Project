#!/usr/bin/env python3
"""Run an experiment grid: targets x configurations x trials, with a
concurrency limit, fixed seeds, and resume (runs with a summary.json are
skipped). Each run goes through harness/run_campaign.sh.

    python3 harness/run_experiment.py --name exp1 --configs whitefox-parsing whitefox-vuln \
        --trials 3 --max-llm-calls 30 --jobs 5 [--targets ID ...]
    python3 harness/run_experiment.py --name exp1 --report      # results table only

Configurations:
  L0 .. L6                              information ladder: one engine, one LLM, only the
                                        information grows (each level includes the previous)
  whitefox-parsing, whitefox-vuln       WhiteFox (white-box + LLM), reference point
  ours, ours-recon                      older names for L3 and L4
"""
import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_L3 = ["--system", "ours", "--feedback", "full", "--strace", "--ltrace"]
CONFIGS = {
    # Information ladder (fuzzer/README.md): what the LLM sees grows one step at a time.
    # L0 also hides the binary name (identity is what L1 adds); the command-line
    # options stay, since the LLM must know how the input file is passed.
    "L0": ["--system", "ours", "--no-identify", "--anonymize", "--feedback", "crash"],
    "L1": ["--system", "ours", "--feedback", "crash"],                    # + program identity
    "L2": ["--system", "ours", "--feedback", "output"],                   # + exit status, output
    "L3": _L3,                                                  # + syscalls, lib calls, instr count
    "L4": _L3 + ["--recon", "linked"],                          # + decompiled code
    "L5": _L3 + ["--recon", "linked", "--coverage"],            # + function coverage
    "L6": _L3 + ["--recon", "linked", "--coverage", "--source"],  # + source code
    "whitefox-parsing": ["--system", "whitefox", "--wf-mode", "parsing"],
    "whitefox-vuln": ["--system", "whitefox", "--wf-mode", "vuln"],
    "ours": _L3,
    "ours-recon": _L3 + ["--recon", "linked"],
}


def default_targets():
    """One case per binary; cases without a reproducible crash are kept (they
    still produce coverage/behavior data) but have no target oracle."""
    cases = json.loads((ROOT / "harness/targets.json").read_text())
    seen, out = set(), []
    for c in cases:
        key = (c["dir"], Path(c["argv"][0]).name)
        if key not in seen:
            seen.add(key)
            out.append(c["id"])
    return out


def run_dir(name, target, config, trial):
    return ROOT / "runs" / name / target.replace("#", "_") / config / f"trial{trial}"


def run_one(job):
    name, target, config, trial, extra, llm_url = job
    out = run_dir(name, target, config, trial)
    summary = out / "summary.json"
    if summary.exists():
        if not json.loads(summary.read_text()).get("error"):
            return job, "skipped"
        # Failed run (e.g. the LLM server went away): keep it for the record, redo it.
        n = 1
        while out.with_name(f"{out.name}.failed{n}").exists():
            n += 1
        out.rename(out.with_name(f"{out.name}.failed{n}"))
    out.parent.mkdir(parents=True, exist_ok=True)
    log = out.parent / f"trial{trial}.log"
    argv = [str(ROOT / "harness/run_campaign.sh"), "--target", target, *CONFIGS[config],
            "--seed", str(trial), "--out", str(out.relative_to(ROOT)), *extra]
    env = dict(os.environ, **({"LLM_URL": llm_url} if llm_url else {}))
    with open(log, "w") as fh:
        fh.write(f"# llm_url={llm_url or os.environ.get('LLM_URL', '(default)')}\n")
        fh.flush()
        rc = subprocess.run(argv, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT,
                            env=env).returncode
    return job, f"rc={rc}"


def report(name):
    rows = []
    for s in sorted((ROOT / "runs" / name).glob("*/*/trial*/summary.json")):
        if ".failed" in s.parent.name:      # superseded by a rerun
            continue
        d = json.loads(s.read_text())
        target, config, trial = s.parts[-4], s.parts[-3], s.parts[-2]
        hit = d.get("target_hit")
        cov = s.parent / "coverage.json"
        rows.append({"target": target, "config": config, "trial": trial,
                     "llm_calls": d["llm_calls"], "execs": d["execs"],
                     "behaviors": d["behaviors"], "crash_sites": d["crash_sites"],
                     "hit_calls": hit["llm_calls"] if hit else None,
                     "hit_seconds": hit["time"] if hit else None, "error": bool(d["error"]),
                     "covered": json.loads(cov.read_text())["covered"] if cov.exists() else None})
    (ROOT / "runs" / name / "results.json").write_text(json.dumps(rows, indent=1) + "\n")
    by = {}
    for r in rows:
        by.setdefault((r["target"], r["config"]), []).append(r)
    configs = sorted({r["config"] for r in rows})
    print("| target | " + " | ".join(configs) + " |")
    print("|---|" + "---|" * len(configs))
    for target in sorted({r["target"] for r in rows}):
        cells = []
        for cfg in configs:
            rs = by.get((target, cfg), [])
            hits = [r["hit_calls"] for r in rs if r["hit_calls"] is not None]
            cells.append(f"{len(hits)}/{len(rs)}" + (f" (calls {sorted(hits)})" if hits else "")
                         + (" ERR" if any(r["error"] for r in rs) else ""))
        print(f"| {target} | " + " | ".join(cells) + " |")
    for cfg in configs:
        rs = [r for r in rows if r["config"] == cfg]
        hits = sum(r["hit_calls"] is not None for r in rs)
        covs = [r["covered"] for r in rs if r["covered"] is not None]
        cov = f", mean functions covered {sum(covs) / len(covs):.0f} ({len(covs)} measured)" \
            if covs else ""
        print(f"{cfg}: target reproduced in {hits}/{len(rs)} runs{cov}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--name", required=True)
    ap.add_argument("--configs", nargs="+", choices=sorted(CONFIGS), default=["whitefox-parsing"])
    ap.add_argument("--targets", nargs="+", default=None)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--jobs", type=int, default=4, help="campaigns running at once")
    ap.add_argument("--only-trial", type=int, default=None,
                    help="run just this trial number (to split an experiment over Slurm jobs)")
    ap.add_argument("--llm-urls", nargs="+", default=None,
                    help="several LLM servers; runs are spread so that no configuration "
                         "sits on one server")
    ap.add_argument("--report", action="store_true")
    args, extra = ap.parse_known_args()      # e.g. --minutes 90 --stop-on-target
    if args.report:
        return report(args.name)
    targets = args.targets or default_targets()
    trials = [args.only_trial] if args.only_trial else range(1, args.trials + 1)
    all_targets = args.targets or default_targets()
    urls = args.llm_urls or [None]

    def url_for(t, c, k):   # rotate over (target, config, trial) so servers mix evenly
        # stable per-target offset, so jobs that each get one target still mix servers
        offset = sum(map(ord, t))
        return urls[(offset + args.configs.index(c) + k) % len(urls)]
    grid = [(args.name, t, c, k, extra, url_for(t, c, k)) for k in trials
            for t in targets for c in args.configs]
    (ROOT / "runs" / args.name).mkdir(parents=True, exist_ok=True)
    (ROOT / "runs" / args.name / f"plan-{len(grid)}.json").write_text(
        json.dumps({"configs": args.configs, "targets": targets, "trials": args.trials,
                    "extra": extra}, indent=1) + "\n")
    print(f"{len(grid)} runs, {args.jobs} at a time", flush=True)
    with ThreadPoolExecutor(args.jobs) as pool:
        for (name, t, c, k, _, url), status in pool.map(run_one, grid):
            print(f"{t} {c} trial{k}: {status}", flush=True)
    report(args.name)


if __name__ == "__main__":
    sys.exit(main())
