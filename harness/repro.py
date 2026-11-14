#!/usr/bin/env python3
"""Replay each dataset PoC and record whether it crashes, and where.

Meant to run inside the shared Apptainer image (env/fuzz.def). Every run uses a
fresh copy of the entry directory, so PoCs that write output files or edit
their input in place (nasm, lame, strip, ...) never modify the dataset.
Crashing cases are re-run under gdb to capture a backtrace.
"""
import argparse
import json
import re
import resource
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

FRAME_RE = re.compile(r"^#(\d+)\s+(?:0x[0-9a-f]+ in )?(\S+) \(.*?\)(?: at (\S+))?")


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(argv, src_dir, timeout):
    with tempfile.TemporaryDirectory(prefix="repro-") as tmp:
        work = Path(tmp) / "case"
        shutil.copytree(src_dir, work, symlinks=True)
        start = time.monotonic()
        try:
            p = subprocess.run(argv, cwd=work, capture_output=True,
                               timeout=timeout, preexec_fn=no_core)
            rc, out, err, timed_out = p.returncode, p.stdout, p.stderr, False
        except subprocess.TimeoutExpired as e:
            rc, out, err, timed_out = None, e.stdout or b"", e.stderr or b"", True
        return rc, out, err, timed_out, time.monotonic() - start


def first_program_frame(frames):
    """Innermost frame with source info, i.e. skip libc's raise/abort frames."""
    for f in frames:
        if f["src"]:
            return f
    return frames[0] if frames else None


def backtrace(argv, src_dir, timeout):
    gdb = ["gdb", "-q", "-nx", "-batch", "-ex", "run", "-ex", "bt 12", "--args", *argv]
    _, out, err, _, _ = run(gdb, src_dir, timeout)
    frames = []
    for line in (out + err).decode(errors="replace").splitlines():
        m = FRAME_RE.match(line.strip())
        if m:
            frames.append({"n": int(m[1]), "func": m[2], "src": m[3]})
    return frames


def classify(rc, timed_out, err):
    if timed_out:
        return "timeout"
    if rc is not None and rc < 0:
        return "crash:" + signal.Signals(-rc).name
    text = err.decode(errors="replace")
    if "error while loading shared libraries" in text or "GLIBC_" in text:
        return "env-error"
    return f"exit:{rc}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="dataset")
    ap.add_argument("--targets", default="harness/targets.json")
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=float, default=30)
    args = ap.parse_args()

    dataset = Path(args.dataset)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    cases = json.loads(Path(args.targets).read_text())

    rows = []
    with open(out_dir / "results.jsonl", "w") as fh:
        for case in cases:
            src = dataset / case["dir"]
            rc, out, err, timed_out, secs = run(case["argv"], src, args.timeout)
            status = classify(rc, timed_out, err)
            frames = backtrace(case["argv"], src, args.timeout * 2) if status.startswith("crash") else []
            top = first_program_frame(frames)
            row = {
                **case,
                "status": status,
                "returncode": rc,
                "seconds": round(secs, 2),
                "crash_func": top["func"] if top else None,
                "crash_src": top["src"] if top else None,
                "frames": frames,
                "stdout_tail": out.decode(errors="replace")[-600:],
                "stderr_tail": err.decode(errors="replace")[-600:],
            }
            fh.write(json.dumps(row) + "\n")
            fh.flush()
            rows.append(row)
            print(f"{case['id']:22} {status:16} {row['crash_func'] or ''} {row['crash_src'] or ''}", flush=True)

    with open(out_dir / "summary.md", "w") as fh:
        fh.write("| case | cmd from | status | crash site |\n|---|---|---|---|\n")
        for r in rows:
            site = f"`{r['crash_func']}` {r['crash_src'] or ''}" if r["crash_func"] else ""
            fh.write(f"| {r['id']} | {r['cmd_from']} | {r['status']} | {site} |\n")
    crashed = sum(r["status"].startswith("crash") for r in rows)
    print(f"\n{crashed}/{len(rows)} cases crashed; details in {out_dir}")


if __name__ == "__main__":
    main()
