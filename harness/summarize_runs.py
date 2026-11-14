#!/usr/bin/env python3
"""Summarize campaign run directories: per-round script outcomes, behaviors, crashes.

    python3 harness/summarize_runs.py 'runs/pilot-v1/*'
"""
import collections
import glob
import json
import sys
from pathlib import Path


def kind(err):
    if not err:
        return "ok"
    for key, label in (("SyntaxError", "syntax"), ("IndentationError", "syntax"),
                       ("no files", "nofiles"), ("timed out", "timeout"), ("code block", "nocode"),
                       ("some files may have failed", "partial")):
        if key in err:
            return label
    return "runtime"


for run in sorted(glob.glob(sys.argv[1] if len(sys.argv) > 1 else "runs/*/*")):
    ev = Path(run) / "events.jsonl"
    if not ev.exists():
        continue
    rounds, outcomes, lat, repairs = [], collections.Counter(), [], []
    for line in ev.read_text().splitlines():
        e = json.loads(line)
        if e["event"] == "round":
            rounds.append(f"{e['iteration']}:{e.get('files', 0)}f/{e.get('new', 0)}n/{kind(e.get('error'))}")
        elif e["event"] == "exec":
            outcomes[e["status"]] += 1
        elif e["event"] == "llm":
            lat.append(e["latency"])
        elif e["event"] == "repair":
            repairs.append(e["fixed"])
    s = json.loads((Path(run) / "summary.json").read_text()) if (Path(run) / "summary.json").exists() else {}
    hit = s.get("target_hit")
    print(f"== {run}")
    print(f"   calls={s.get('llm_calls')} execs={s.get('execs')} behaviors={s.get('behaviors')} "
          f"crash_sites={s.get('crash_sites')} target_hit={(hit['match'], hit['llm_calls'], hit['time']) if hit else None}")
    print(f"   llm latency avg {sum(lat) / max(len(lat), 1):.0f}s; repairs {sum(repairs)}/{len(repairs)} fixed")
    print("   rounds (files/new/status):", " ".join(rounds))
    print("   exec outcomes:", dict(outcomes))
