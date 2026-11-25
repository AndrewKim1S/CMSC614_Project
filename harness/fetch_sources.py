#!/usr/bin/env python3
"""Fetch upstream sources listed in harness/sources.json into sources/<entry>/.

    python3 harness/fetch_sources.py                 # every entry
    python3 harness/fetch_sources.py CVE-2017-12067  # selected entries
"""
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

spec = json.loads(Path("harness/sources.json").read_text())
wanted = sys.argv[1:] or [k for k in spec if not k.startswith("_")]
failed = []
for entry in wanted:
    s, dest = spec[entry], Path("sources") / entry
    if dest.exists():
        print(f"{entry}: already present")
        continue
    dest.parent.mkdir(exist_ok=True)
    try:
        if "git" in s:
            subprocess.run(["git", "clone", "-q", "--filter=blob:none", s["git"], str(dest)],
                           check=True)
            if s.get("commit"):
                subprocess.run(["git", "-C", str(dest), "checkout", "-q", s["commit"]], check=True)
        else:
            with tempfile.TemporaryDirectory() as tmp:
                archive = Path(tmp) / "src.archive"
                req = urllib.request.Request(s["tar"], headers={"User-Agent": "curl/8"})
                with urllib.request.urlopen(req, timeout=300) as r, open(archive, "wb") as f:
                    shutil.copyfileobj(r, f)
                with tarfile.open(archive) as t:          # gz, bz2 or xz
                    if sys.version_info >= (3, 12):
                        t.extractall(tmp, filter="data")
                    else:
                        t.extractall(tmp)
                tops = [p for p in Path(tmp).iterdir() if p.is_dir()]
                shutil.copytree(tops[0] if len(tops) == 1 else tmp, dest)
    except Exception as e:          # keep going; report at the end
        shutil.rmtree(dest, ignore_errors=True)
        failed.append(entry)
        print(f"{entry}: FAILED ({type(e).__name__}: {e})")
        continue
    n = sum(1 for p in dest.rglob("*") if p.suffix in (".c", ".cc", ".cpp", ".h", ".hpp", ".y"))
    note = " (unpinned: default branch, may not match the binary)" if s.get("unpinned") else ""
    print(f"{entry}: {n} C/C++ files in {dest}{note}")
if failed:
    print("failed:", " ".join(failed))
    sys.exit(1)
