"""Crash triage against the ground truth from the PoC replay.

Crashing inputs are re-run on the ORIGINAL debug build under gdb (never shown
to the strategy) to find the crash site, which is compared with the sites the
dataset PoCs crash at (harness/expected_crashes.json).
"""
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

FRAME_RE = re.compile(r"^#(\d+)\s+(?:0x[0-9a-f]+ in )?(\S+) \(.*?\)(?: at (\S+))?")
SIGNAL_RE = re.compile(r"Program received signal (SIG\w+)")


def parse_frames(text):
    frames = []
    for line in text.splitlines():
        m = FRAME_RE.match(line.strip())
        if m:
            frames.append({"n": int(m[1]), "func": m[2], "src": m[3]})
    return frames


def first_program_frame(frames):
    """Innermost frame with source info, i.e. skip libc's raise/abort frames."""
    for f in frames:
        if f["src"]:
            return f
    return frames[0] if frames else None


class Triage:
    def __init__(self, target, expected_json, workroot, timeout=60):
        self.target = target
        self.workroot = Path(workroot)
        self.timeout = timeout
        expected = json.loads(Path(expected_json).read_text()) if expected_json else {}
        # Any PoC case on the same binary counts as a hit (e.g. jhead has two).
        self.expected = {cid: expected[cid] for cid in target.sibling_ids if cid in expected}

    def site(self, data):
        d = Path(tempfile.mkdtemp(prefix="triage-", dir=self.workroot))
        try:
            name = "input" + self.target.suffix
            (d / name).write_bytes(data)
            argv = self.target.argv_for(self.target.original_binary.resolve(), name)
            gdb = ["gdb", "-q", "-nx", "-batch", "-ex", "run", "-ex", "bt 12", "--args", *argv]
            try:
                p = subprocess.run(gdb, cwd=d, capture_output=True, timeout=self.timeout,
                                   stdin=subprocess.DEVNULL)
                text = (p.stdout + p.stderr).decode(errors="replace")
            except subprocess.TimeoutExpired:
                return {"signal": None, "func": None, "src": None, "frames": []}
            frames = parse_frames(text)
            top = first_program_frame(frames)
            sig = SIGNAL_RE.search(text)
            return {"signal": sig[1] if sig else None,
                    "func": top["func"] if top else None,
                    "src": top["src"] if top else None,
                    "frames": frames[:8]}
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def match(self, site):
        """Return the matching case id, or None. Stripped originals (func '??')
        can only be matched on the signal, which is reported as weak."""
        for cid, exp in self.expected.items():
            if exp["func"] and exp["func"] != "??":
                if site["func"] == exp["func"]:
                    return cid
            elif site["signal"] == exp["signal"]:
                return cid + " (weak: signal only)"
        return None
