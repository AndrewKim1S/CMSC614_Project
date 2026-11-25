"""Function-level coverage of one execution, via gdb one-shot breakpoints.

Used two ways:
  - as L5 feedback for Our System: which functions of the stripped binary an
    input executed, by entry address (from the Ghidra export);
  - offline, to measure every run's inputs on the same footing regardless of
    configuration (harness/measure_coverage.py, on the debug build).

Function entry, not edge, coverage: coarser than AFL's, but it needs no
instrumented build and works on any binary gdb can run.
"""
import os
import resource
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path

MEMORY_CAP = 6 << 30


def _limits():
    os.setsid()
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_CAP, MEMORY_CAP))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def norm(entry):
    """Ghidra prints entries as 8+ hex digits; use one spelling everywhere."""
    return f"{int(entry, 16) if isinstance(entry, str) else int(entry):08x}"


class FunctionCoverage:
    def __init__(self, target, binary_path, entries, workroot, timeout=120):
        self.target = target
        self.binary = Path(binary_path).resolve()
        self.entries = sorted({norm(e) for e in entries})
        self.workroot = Path(workroot)
        self.timeout = timeout
        # always-inserted: otherwise gdb removes and re-inserts every breakpoint
        # at each stop, which is quadratic with thousands of functions.
        lines = ["set pagination off", "set confirm off", "set breakpoint always-inserted on"]
        for e in self.entries:
            lines += [f"tbreak *0x{e}", "commands", "silent", f"echo COV {e}\\n", "continue", "end"]
        lines.append("run")
        self.script = "\n".join(lines) + "\n"

    def run(self, data):
        d = Path(tempfile.mkdtemp(prefix="cov-", dir=self.workroot))
        try:
            name = "input" + self.target.suffix
            (d / name).write_bytes(data)
            os.symlink(self.binary, d / self.binary.name)
            (d / "cov.gdb").write_text(self.script)
            argv = ["gdb", "-q", "-nx", "-batch", "-x", "cov.gdb", "--args",
                    *self.target.argv_for("./" + self.binary.name, name)]
            # Own process group and a memory cap that gdb and the target inherit:
            # without it, one memory-hungry input (an mruby script) OOM-killed the job.
            p = subprocess.Popen(argv, cwd=d, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 stdin=subprocess.DEVNULL, preexec_fn=_limits)
            try:
                out, _ = p.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                out, _ = p.communicate()
            return {line.split()[1] for line in out.decode(errors="replace").splitlines()
                    if line.startswith("COV ")}
        finally:
            shutil.rmtree(d, ignore_errors=True)
