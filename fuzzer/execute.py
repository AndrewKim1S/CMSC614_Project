"""Run a target on one input and collect black-box observations.

Observations: exit status / signal, stdout and stderr (head only), wall time,
user-space instruction count (perf), and optional strace/ltrace call summaries.
Each observation pass runs in a fresh directory with a fresh copy of the input,
because some targets rewrite their input or drop output files next to it.
"""
import math
import os
import re
import resource
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

HEAD = 400


def _limits():
    os.setsid()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
    resource.setrlimit(resource.RLIMIT_AS, (4 << 30, 4 << 30))


def _run(argv, cwd, timeout):
    """Run argv with output going to files; returns (rc, timed_out, seconds)."""
    with open(cwd / ".stdout", "wb") as out, open(cwd / ".stderr", "wb") as err:
        start = time.monotonic()
        p = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out,
                             stderr=err, preexec_fn=_limits)
        try:
            rc = p.wait(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            rc = p.wait()
            timed_out = True
    return rc, timed_out, time.monotonic() - start


def _head(path, n=HEAD):
    with open(path, "rb") as f:
        return f.read(n).decode(errors="replace")


@dataclass
class ExecResult:
    status: str                    # "exit:N", "crash:SIGSEGV", "timeout"
    returncode: int
    seconds: float
    stdout: str
    stderr: str
    instructions: int = None
    syscalls: dict = field(default=None)
    libcalls: dict = field(default=None)

    @property
    def crashed(self):
        return self.status.startswith("crash:")


def _status(rc, timed_out):
    if timed_out:
        return "timeout"
    if rc < 0:
        return "crash:" + signal.Signals(-rc).name
    return f"exit:{rc}"


_SUMMARY_ROW = re.compile(r"^\s*[\d.]+\s+[\d.]+\s+\d+\s+(\d+)\s+(?:\d+\s+)?(\S+)\s*$")


def _parse_call_summary(path):
    """Parse `strace -c` / `ltrace -c` tables into {name: calls}."""
    calls = {}
    if not path.exists():
        return None
    for line in path.read_text(errors="replace").splitlines():
        m = _SUMMARY_ROW.match(line)
        if m and m[2] not in ("total", "syscall", "function"):
            calls[m[2]] = int(m[1])
    return calls


class Executor:
    def __init__(self, target, binary_path, workroot, timeout=10.0,
                 perf=True, strace=False, ltrace=False):
        self.target = target
        self.binary_path = Path(binary_path).resolve()
        self.workroot = Path(workroot)
        self.workroot.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.perf = perf
        self.strace = strace
        self.ltrace = ltrace
        self.input_name = "input" + target.suffix

    def _fresh(self, data):
        # Run as ./<name> next to the input so messages that echo argv[0] or
        # the input path look the same on every run.
        d = Path(tempfile.mkdtemp(dir=self.workroot))
        (d / self.input_name).write_bytes(data)
        os.symlink(self.binary_path, d / self.binary_path.name)
        return d

    def _pass(self, data, prefix):
        d = self._fresh(data)
        try:
            argv = prefix(d) + self.target.argv_for("./" + self.binary_path.name, self.input_name)
            rc, timed_out, secs = _run(argv, d, self.timeout * (3 if prefix(d) else 1))
            return d, rc, timed_out, secs
        except BaseException:
            shutil.rmtree(d, ignore_errors=True)
            raise

    def run(self, data):
        d, rc, timed_out, secs = self._pass(data, lambda d: [])
        try:
            res = ExecResult(_status(rc, timed_out), rc, round(secs, 3),
                             _head(d / ".stdout"), _head(d / ".stderr"))
        finally:
            shutil.rmtree(d, ignore_errors=True)
        if self.perf and not timed_out:
            d, *_ = self._pass(data, lambda d: ["perf", "stat", "-x,", "-e", "instructions:u",
                                                "-o", str(d / ".perf"), "--"])
            try:
                for line in (d / ".perf").read_text().splitlines():
                    parts = line.split(",")
                    if len(parts) > 2 and parts[2].startswith("instructions") and parts[0].isdigit():
                        res.instructions = int(parts[0])
            except FileNotFoundError:
                pass
            finally:
                shutil.rmtree(d, ignore_errors=True)
        for enabled, tool, attr in ((self.strace, "strace", "syscalls"),
                                    (self.ltrace, "ltrace", "libcalls")):
            if enabled and not timed_out:
                d, *_ = self._pass(data, lambda d, tool=tool: [tool, "-f", "-c", "-o", str(d / ".calls")]
                                   + (["-qq"] if tool == "strace" else []))
                try:
                    setattr(res, attr, _parse_call_summary(d / ".calls"))
                finally:
                    shutil.rmtree(d, ignore_errors=True)
        return res


_NOISE = re.compile(r"0x[0-9a-f]+|\d+|'[^']*'|\"[^\"]*\"|input\.\w*|input", re.I)


def first_line(res):
    for text in (res.stderr, res.stdout):
        for line in text.splitlines():
            if line.strip():
                return line.strip()[:160]
    return ""


def signature(res):
    """Coarse behavior signature used to decide whether an input is new.

    Without coverage we approximate "new path" by: outcome class, a log-scale
    bucket of the instruction count (~19% wide), the normalized first message,
    and the set of syscalls/library calls when traced.
    """
    bucket = int(math.log2(res.instructions) * 4) if res.instructions else -1
    msg = _NOISE.sub("N", first_line(res).lower())[:80]
    calls = tuple(sorted(set(res.syscalls or ()) | set(res.libcalls or ())))
    return (res.status, bucket, msg, calls)
