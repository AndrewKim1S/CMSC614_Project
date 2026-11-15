"""Static reconstruction for Our System from Ghidra's decompilation.

  export     (Ghidra image, once per binary) strip the binary exactly as the
             fuzzer does, run Ghidra headless with ghidra/ExportForLLM.java and
             cache functions.jsonl + meta.json under analysis/<entry>/<binary>/.
  select     pick the input-processing functions: those calling input APIs,
             then their callees and callers, within a character budget.
  summarize  the LLM turns the selected decompiled code into a description of
             the input format as this binary parses it (counts against budget).
  link       map a message the target printed back to the functions that
             reference that string, so feedback can show the code behind it.

    python3 -m fuzzer.reconstruct export --target CVE-2017-12067   # ghidra.sif
    python3 -m fuzzer.reconstruct show --target CVE-2017-12067     # inspect selection
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from pathlib import Path

from .target import INSTRUMENTATION, load_targets, prepare_binary

GHIDRA = Path("/opt/ghidra")
SCRIPT_DIR = Path(__file__).resolve().parent.parent / "ghidra"

INPUT_API = re.compile(
    r"^(fread|fread_unlocked|fgetc|getc|_IO_getc|getc_unlocked|fgets|fscanf|__isoc99_fscanf|"
    r"read|pread|pread64|mmap|mmap64|getline|getdelim|ungetc|fopen|fopen64|open|open64|"
    r"gzread|gzopen)$|istream|ifstream|streambuf")
FMT = re.compile(r"%[-+ #0-9.*lhzjt]*[a-zA-Z]")


def sha1_file(path):
    return hashlib.sha1(Path(path).read_bytes()).hexdigest()


def analysis_dir(root, target):
    return Path(root) / target.entry_dir.name / target.binary


# -- export (runs inside ghidra.sif) -----------------------------------------
def export(target, root, timeout=30, max_size=20000):
    out = analysis_dir(root, target)
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="ghidra-"))
    try:
        binary = prepare_binary(target, work / "bin")
        (work / "proj").mkdir()
        cmd = [str(GHIDRA / "support/analyzeHeadless"), str(work / "proj"), "p",
               "-import", str(binary), "-scriptPath", str(SCRIPT_DIR),
               "-postScript", "ExportForLLM.java", str(out / "functions.jsonl"), str(timeout),
               str(max_size), "-deleteProject", "-analysisTimeoutPerFile", "3600"]
        start = time.monotonic()
        p = subprocess.run(cmd, capture_output=True, text=True)
        secs = time.monotonic() - start
        (out / "ghidra.log").write_text(p.stdout[-30000:] + "\n" + p.stderr[-30000:])
        funcs = _read(out / "functions.jsonl")
        props = (GHIDRA / "Ghidra/application.properties").read_text()
        meta = {"target": target.id, "binary": target.binary, "sha1": sha1_file(binary),
                "seconds": round(secs, 1), "returncode": p.returncode,
                "functions": len(funcs), "decompiled": sum(f["code"] is not None for f in funcs),
                "ghidra": re.search(r"application.version=(\S+)", props)[1]}
        (out / "meta.json").write_text(json.dumps(meta, indent=1) + "\n")
        return meta
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _read(path):
    if not Path(path).exists():
        return []
    return [json.loads(line) for line in open(path) if line.strip()]


# -- load / select ------------------------------------------------------------
class Analysis:
    def __init__(self, funcs, meta):
        self.meta = meta
        # Functions containing the dataset's crash instrumentation would show
        # the LLM the exact bug condition; drop them from everything it sees.
        self.hidden = {f["entry"] for f in funcs
                       if any(INSTRUMENTATION.search(s) for s in f["strings"])}
        for f in funcs:
            if f["entry"] in self.hidden:
                f["code"] = None
        self.funcs = {f["entry"]: f for f in funcs}
        self.by_string = {}
        for f in funcs:
            for s in f["strings"]:
                self.by_string.setdefault(s, []).append(f["entry"])


def load(target, root, binary_path=None):
    d = analysis_dir(root, target)
    if not (d / "meta.json").exists():
        raise FileNotFoundError(f"no Ghidra analysis in {d}; run harness/run_ghidra.sh {target.id}")
    meta = json.loads((d / "meta.json").read_text())
    if binary_path is not None and meta["sha1"] != sha1_file(binary_path):
        raise RuntimeError(f"{d} was made from a different binary; rerun harness/run_ghidra.sh")
    return Analysis(_read(d / "functions.jsonl"), meta)


CONST_CMP = re.compile(r"(?:==|!=|<=|>=|<|>)\s*(?:0x[0-9a-fA-F]+|\d+|'.')")
ERROR_STRING = re.compile(r"invalid|error|cannot|can't|bad |unsupported|corrupt|unexpected|"
                          r"too (?:large|many|small|big|long|short)|missing|wrong|illegal|"
                          r"unknown|truncat|premature|expected|exceed|mismatch|not ", re.I)
MAGIC_STRING = re.compile(r"^[A-Za-z0-9 _.\-]{2,8}$")
OUTPUT_API = re.compile(r"printf|puts|fputs|fwrite|operator<<|putchar|fputc")
# Short literals (chunk names, magic bytes) are often not defined as string data
# by Ghidra, but they do appear inline in the decompiled code.
CODE_LITERAL = re.compile(r'"((?:[^"\\\n]|\\.){2,60})"')
DECL_LINE = re.compile(r"^\s+[\w\s\*:<>,]+?\s\**\w+(?:\s*\[\d*\])*;\s*$")
WARNING_LINE = re.compile(r"^\s*/\* WARNING:.*\*/\s*$")


def compact(code):
    """Drop Ghidra warnings and the local-variable declaration block, which
    carry no logic but take a large share of the character budget."""
    out, in_decls, opened = [], False, False
    for line in code.splitlines():
        if WARNING_LINE.match(line):
            continue
        if not opened and line.strip() == "{":
            opened = in_decls = True
            out.append(line)
            continue
        if in_decls:
            if DECL_LINE.match(line):
                continue
            in_decls = False
        out.append(line)
    return "\n".join(l for l in out).strip()


def strings_of(f):
    return set(f["strings"]) | set(CODE_LITERAL.findall(f["code"] or ""))


def _walk(a, start, edge, depth):
    seen = set(start)
    frontier = list(start)
    for _ in range(depth):
        nxt = [n for e in frontier for n in a.funcs[e][edge] if n in a.funcs and n not in seen]
        seen.update(nxt)
        frontier = nxt
    return seen


def _score(f):
    """How much a function looks like input parsing: error messages and short
    magic tokens it references, comparisons with constants, input reads.
    Functions that mostly print (report formatting) get no credit for strings."""
    strings = strings_of(f)
    errors = sum(bool(ERROR_STRING.search(s)) for s in strings)
    magic = sum(bool(MAGIC_STRING.match(s)) for s in strings)
    cmps = len(CONST_CMP.findall(f["code"] or ""))
    reads = any(INPUT_API.search(i) for i in f["imports"])
    printer = any(OUTPUT_API.search(i) for i in f["imports"]) and not errors
    return (0 if printer else 3 * min(errors, 6) + 2 * min(magic, 6)) + min(cmps, 25) \
        + (3 if reads else 0)


def select(a, max_chars=24000, per_func=3500):
    """Input-processing functions for the reconstruction prompt.

    Many targets read the whole file into memory and parse the buffer later,
    so the parser is not near the input calls in the call graph. The region
    is therefore everything reachable (6 levels down) from the callers (up to
    3 levels up) of the input-reading functions, ranked by _score."""
    readers = {e for e, f in a.funcs.items() if any(INPUT_API.search(i) for i in f["imports"])}
    roots = _walk(a, readers, "callers", 3)
    region = _walk(a, roots, "callees", 6)
    order = sorted((e for e in region if a.funcs[e]["code"]),
                   key=lambda e: (-_score(a.funcs[e]), a.funcs[e]["size"]))
    chosen, total = [], 0
    for e in order:
        if _score(a.funcs[e]) == 0:
            break
        code = compact(a.funcs[e]["code"])
        if len(code) > per_func:
            code = code[:per_func] + "\n/* ... truncated ... */"
        if total + len(code) > max_chars:
            continue
        chosen.append((e, code))
        total += len(code)
    return chosen


# -- summarize (LLM) ----------------------------------------------------------
ROLE = ("You are an expert reverse engineer helping with robustness testing (fuzzing) of a "
        "stripped command-line program for a research project.")


def summarize(c, identification, chosen, chunk_chars=12000):
    chunks, cur, size = [], [], 0
    for _, code in chosen:
        if cur and size + len(code) > chunk_chars:
            chunks.append(cur)
            cur, size = [], 0
        cur.append(code)
        size += len(code)
    if cur:
        chunks.append(cur)
    notes = []
    for i, chunk in enumerate(chunks, 1):
        if not c.budget_left():
            break
        prompt = (
            f"What we already believe about the program:\n{identification}\n\n"
            "Below is Ghidra's decompiled C for functions of the binary that read or process its "
            "input file (names like FUN_00401a20 are addresses; the binary is stripped).\n\n"
            + "\n\n".join(chunk) +
            "\n\nFor the functions that matter for input parsing, describe concisely: which input "
            "bytes or fields they read (offsets, sizes, endianness, syntax), the exact checks they "
            "apply (constants, ranges, relations between fields), what happens when a check fails "
            "(error message or return value), and which branches lead to further processing. "
            "Refer to functions by their FUN_ names. Skip unrelated functions. At most 400 words.")
        text, _ = c.ask([{"role": "system", "content": ROLE}, {"role": "user", "content": prompt}],
                        kind=f"recon{i}", max_tokens=2000)
        notes.append(text)
    if len(notes) <= 1 or not c.budget_left():
        return "\n\n".join(notes)
    prompt = ("Combine these notes, written from different parts of the same binary's decompiled "
              "code, into one description of the input format as this program parses it: overall "
              "structure, per-field constraints with exact values, the order of checks, the "
              "features or branches that lead to deeper processing, and the error message tied to "
              "each failed check. At most 600 words.\n\n"
              + "\n\n---\n\n".join(notes))
    text, _ = c.ask([{"role": "system", "content": ROLE}, {"role": "user", "content": prompt}],
                    kind="recon-merge", max_tokens=2500)
    return text


# -- link ---------------------------------------------------------------------
def link(a, message, min_chars=8):
    """(entry, string) pairs for functions referencing a string printed in
    `message`. Plain literals (likely the failing check itself) rank before
    format strings (likely a generic error printer)."""
    hits = []
    for s, entries in a.by_string.items():
        frags = [x.strip() for x in FMT.split(s) if len(x.strip()) >= 5]
        if not frags or sum(map(len, frags)) < min_chars or not all(x in message for x in frags):
            continue
        hits.append((bool(FMT.search(s)), -sum(map(len, frags)), s, entries))
    hits.sort(key=lambda h: h[:2])
    out = []
    for _, _, s, entries in hits:
        for e in entries:
            if e not in a.hidden and e not in (x[0] for x in out):
                out.append((e, s))
    return out


def linked_code(a, batch, max_funcs=2, per_func=3000):
    """Markdown section showing the code behind the most frequent messages."""
    counts = Counter(b["message"] for b in batch if not b.get("duplicate") and b.get("message"))
    parts, shown = [], []
    for msg, _ in counts.most_common():
        for entry, s in link(a, msg):
            if entry in shown or not a.funcs[entry]["code"]:
                continue
            code = compact(a.funcs[entry]["code"])
            if len(code) > per_func:
                code = code[:per_func] + "\n/* ... truncated ... */"
            parts.append(f"Output {msg!r} matches the string {s!r}, used in "
                         f"{a.funcs[entry]['name']}:\n```c\n{code}\n```")
            shown.append(entry)
            break
        if len(shown) >= max_funcs:
            break
    if not parts:
        return ""
    return "## Decompiled code behind these outputs\n" + "\n\n".join(parts) + "\n"


# -- CLI ----------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Ghidra-based reconstruction utilities")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("export", "show"):
        p = sub.add_parser(name)
        p.add_argument("--target", action="append", required=True)
        p.add_argument("--targets", default="harness/targets.json")
        p.add_argument("--dataset", default="dataset")
        p.add_argument("--analysis-dir", default="analysis")
    args = ap.parse_args()
    targets = load_targets(args.targets, args.dataset)
    for tid in args.target:
        t = targets[tid]
        if args.cmd == "export":
            print(json.dumps(export(t, args.analysis_dir)), flush=True)
        else:
            a = load(t, args.analysis_dir)
            chosen = select(a)
            print(f"== {tid}: {a.meta['decompiled']}/{a.meta['functions']} functions decompiled "
                  f"in {a.meta['seconds']}s; selected {len(chosen)} "
                  f"({sum(len(x[1]) for x in chosen)} chars)")
            for e, code in chosen:
                f = a.funcs[e]
                print(f"   {f['name']:16} score={_score(f):3} size={f['size']:5} "
                      f"imports={f['imports'][:4]} strings={[s[:24] for s in f['strings'][:4]]}")


if __name__ == "__main__":
    main()
