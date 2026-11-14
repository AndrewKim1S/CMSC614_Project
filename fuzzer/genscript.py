"""Run an LLM-written input generator script in a sandbox.

The script receives an output directory as sys.argv[1] and writes test inputs
there. It runs without network access (unshare -rn), with CPU/memory/file-size
limits and a wall-clock timeout, and only the files it writes are kept.
"""
import os
import re
import resource
import shutil
import subprocess
import tempfile
from pathlib import Path

CODE_BLOCK = re.compile(r"```[\w+-]*[ \t]*\n(.*?)```", re.S)
FENCE_OPEN = re.compile(r"^```[\w+-]*[ \t]*$", re.M)
_HAS_UNSHARE = shutil.which("unshare") is not None


def extract_code(text):
    blocks = CODE_BLOCK.findall(text)
    if blocks:
        return max(blocks, key=len)
    # Qwen often opens a fence and ends its reply without closing it.
    m = FENCE_OPEN.search(text)
    if m:
        return text[m.end():].strip("\n")
    return text if "import" in text or "def " in text else None


def syntax_error(code):
    """Return a one-line description of the first syntax error, or None."""
    try:
        compile(code, "gen.py", "exec")
    except SyntaxError as e:
        return f"{e.msg} at line {e.lineno}: {(e.text or '').strip()}"
    return None


def _limits():
    os.setsid()
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 << 20, 8 << 20))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_generator(code, workroot, timeout=60, max_files=8, max_bytes=2 << 20):
    """Returns (files, error): files is a list of (name, bytes)."""
    d = Path(tempfile.mkdtemp(prefix="gen-", dir=workroot))
    try:
        out = d / "out"
        out.mkdir()
        (d / "gen.py").write_text(code)
        argv = ["python3", "-I", "gen.py", str(out)]
        if _HAS_UNSHARE:
            argv = ["unshare", "-rn"] + argv
        try:
            p = subprocess.run(argv, cwd=d, capture_output=True, timeout=timeout,
                               preexec_fn=_limits, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return [], f"script timed out after {timeout}s"
        files = []
        for f in sorted(out.rglob("*")):
            if f.is_file() and f.stat().st_size <= max_bytes:
                files.append((f.name, f.read_bytes()))
            if len(files) == max_files:
                break
        stderr = p.stderr.decode(errors="replace").strip()
        err = None
        if p.returncode != 0:
            err = f"script exited with {p.returncode}: " + stderr[-800:]
        elif not files:
            err = "script ran but wrote no files into sys.argv[1]" + (
                f"; its stderr: {stderr[-800:]}" if stderr else "")
        elif stderr:
            err = "some files may have failed; the script's stderr: " + stderr[-600:]
        return files, err
    finally:
        shutil.rmtree(d, ignore_errors=True)
