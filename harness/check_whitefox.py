#!/usr/bin/env python3
"""Check that WhiteFox can run on every dataset binary, without any LLM call:
target functions are found and located in the upstream source (both modes),
and in vuln mode the known PoC reaches the target while an empty input does not.
Run inside the shared image; prints one block per binary and a summary table.

    PYTHONPATH=. python3 harness/check_whitefox.py [case ids...]
"""
import json
import sys
import tempfile
import types
from pathlib import Path

from fuzzer.sources import Reacher, SourceIndex
from fuzzer.target import load_targets, prepare_binary
from fuzzer.triage import Triage
from fuzzer.whitefox import WhiteFoxStrategy

cases = json.loads(Path("harness/targets.json").read_text())
targets = load_targets("harness/targets.json", "dataset")
poc_of = {c["id"]: next(a for a in c["argv"][1:] if (Path("dataset") / c["dir"] / a).is_file())
          for c in cases}

seen, wanted = set(), sys.argv[1:]
rows = []
for c in cases:
    t = targets[c["id"]]
    key = (t.entry_dir, t.binary)
    if (wanted and c["id"] not in wanted) or (not wanted and key in seen):
        continue
    seen.add(key)
    w = Path(tempfile.mkdtemp())
    binary = prepare_binary(t, w / "bin", strip=False)
    row = {"case": c["id"], "binary": t.binary}
    try:
        idx = SourceIndex(binary, Path("sources") / t.entry_dir.name)
        row["symbols"] = len(idx.syms)
        if not idx.syms:
            row["status"] = "unsupported: no symbols (stripped binary)"
            rows.append(row)
            print(f"== {c['id']}: {row['status']}", flush=True)
            continue
        tri = Triage(t, "harness/expected_crashes.json", w)
        for mode in ("vuln", "parsing"):
            s = WhiteFoxStrategy(mode=mode, k=4)
            s.index = idx
            ctx = types.SimpleNamespace(target=t, binary_path=binary, triage=tri, workroot=w)
            s.c = ctx
            static = s._static(ctx)
            try:
                names = [n for n in dict.fromkeys(s._candidates(ctx, static)) if n]
            except FileNotFoundError as e:
                names, row[f"{mode}_error"] = [], str(e)
            idx.prefetch(names[:16])
            if mode == "vuln" and names:
                names, row["vuln_why"] = s._vuln_pick(names)
            located = [idx.function(n) for n in names[:16]]
            located = [f for f in located if f][:4]
            row[mode] = [(f["name"], f["file"], f["located_by"]) for f in located]
            if mode == "vuln" and located:
                r = Reacher(t, binary, [located[0]["name"]], w)
                poc = (t.entry_dir / poc_of[c["id"]]).read_bytes()
                row["poc_reaches"] = bool(r.reached(poc))
                row["empty_reaches"] = bool(r.reached(b""))
        ok_v, ok_p = bool(row.get("vuln")), bool(row.get("parsing"))
        row["status"] = ("ok" if ok_v and ok_p else
                         f"partial: vuln={'ok' if ok_v else 'none'} parsing={'ok' if ok_p else 'none'}")
    except Exception as e:                       # report and continue with the next binary
        row["status"] = f"error: {type(e).__name__}: {e}"
    rows.append(row)
    print(f"== {c['id']} ({t.binary}): {row['status']}\n   vuln={row.get('vuln')} "
          f"poc_reaches={row.get('poc_reaches')} empty_reaches={row.get('empty_reaches')}\n"
          f"   parsing={row.get('parsing')}", flush=True)

Path("results").mkdir(exist_ok=True)
Path("results/whitefox_check.json").write_text(json.dumps(rows, indent=1) + "\n")
print("\n| case | binary | status | vuln target | PoC reaches | empty reaches | parsing targets |")
print("|---|---|---|---|---|---|---|")
for r in rows:
    v = r.get("vuln") or []
    print(f"| {r['case']} | {r['binary']} | {r['status']} | {v[0][0] if v else '-'} | "
          f"{r.get('poc_reaches', '-')} | {r.get('empty_reaches', '-')} | "
          f"{len(r.get('parsing') or [])} |")
