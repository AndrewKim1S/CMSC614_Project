"""Our System: black-box LLM fuzzing with program identification and
behavioral feedback.

Stages implemented here (minimal version):
  1. Identification - probe the stripped binary (file type, linked libraries,
     imported functions, filtered strings, --help/-h/--version output) and ask
     the LLM what the program is and what input format it expects.
  2. Seed generation - the LLM writes a generator script for an initial set.
  3. Reconstruction (optional) - summarize Ghidra's decompilation of the
     input-processing functions into a description of the parsed format
     (fuzzer/reconstruct.py; the Ghidra export is precomputed).
  4. Feedback loop - each round shows the LLM what its inputs did (outcome,
     first output line, instruction count, optional strace/ltrace summaries,
     and which inputs produced new behavior) and asks for a new script. With
     recon=linked, it also shows the decompiled function behind each output.

Ablation switches: identify on/off, feedback none/output/full,
recon none/summary/linked.
"""
import re
import subprocess
import tempfile
from pathlib import Path

from . import reconstruct
from .execute import first_line, signature
from .target import INSTRUMENTATION as MARKER

NOISE = re.compile(r"^(GCC:|GLIBC|GLIBCXX|CXXABI|_ITM_|__gmon|_Z|\.)|\.so(\.\d+)*$")
PLATEAU = 3   # rounds without new behavior before asking for a change of direction

ROLE = ("You are an expert in binary analysis and file-format parsing, assisting with "
        "robustness testing (fuzzing) of a command-line program for a research project. "
        "You can only observe the program as a black box.")

GEN_RULES = """You write Python 3 scripts that generate test input files for the program.
Rules:
- Reply with exactly one ```python code block.
- Use only the Python standard library. No network access, no subprocesses.
- Write between 1 and 8 files into the directory given as sys.argv[1]. Give each file a short descriptive name such as "03_large_width.bmp".
- Each file must be smaller than 1 MB; writes beyond 8 MB are killed.
- Build and write each file inside its own try/except block, so one bug does not stop the other files from being written; in each except block call traceback.print_exc() so the error is reported.
- Keep the script short (under about 150 lines) and double-check the syntax."""


def _sh(argv, timeout=10):
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return (p.stdout + p.stderr).decode(errors="replace")
    except subprocess.TimeoutExpired:
        return ""


def _strings(binary, limit_chars=6000):
    seen, msgs, other = set(), [], []
    for s in _sh(["strings", "-n", "6", str(binary)], timeout=30).splitlines():
        s = s.strip()
        if s in seen or MARKER.search(s) or NOISE.search(s):
            continue
        if sum(c.isalpha() for c in s) < 0.5 * len(s):
            continue
        seen.add(s)
        (msgs if (" " in s or "%" in s) else other).append(s[:160])
    out, total = [], 0
    for s in msgs + other:        # messages and format strings first
        if total + len(s) > limit_chars:
            break
        out.append(s)
        total += len(s) + 1
    return out


def _imports(binary, limit=200):
    names = []
    for line in _sh(["objdump", "-T", str(binary)]).splitlines():
        if "*UND*" in line:
            name = line.split()[-1]
            if name not in names and not name.startswith("_"):
                names.append(name)
    return names[:limit]


def _needed(binary):
    return [l.split()[-1] for l in _sh(["objdump", "-p", str(binary)]).splitlines()
            if l.strip().startswith("NEEDED")]


def _probe_runs(binary, name):
    """Outputs of harmless invocations (no input file)."""
    outs, seen = [], set()
    with tempfile.TemporaryDirectory() as d:
        link = Path(d) / name
        link.symlink_to(binary)
        for args in (["--help"], ["-h"], ["--version"], []):
            try:
                p = subprocess.run([f"./{name}", *args], cwd=d, capture_output=True, timeout=3,
                                   stdin=subprocess.DEVNULL)
                text = (p.stdout + p.stderr).decode(errors="replace").strip()[:1500]
            except subprocess.TimeoutExpired:
                text = "(no output within 3s; possibly waiting for input)"
            if text and text not in seen:
                seen.add(text)
                outs.append((" ".join([f"./{name}", *args]), text))
    return outs


def _preview(data, n=48):
    head = data[:n]
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in head)
    if head and printable / len(head) > 0.9:
        return "text: " + repr(head.decode("latin1"))
    return "hex: " + head.hex(" ")


def _human(n):
    if n is None:
        return "n/a"
    for unit, size in (("G", 1e9), ("M", 1e6), ("k", 1e3)):
        if n >= size:
            return f"{n / size:.1f}{unit}"
    return str(n)


class OursStrategy:
    name = "ours"

    def __init__(self, identify=True, feedback="full", recon="none", analysis_dir="analysis"):
        assert feedback in ("none", "output", "full")
        assert recon in ("none", "summary", "linked")
        self.identify = identify
        self.feedback = feedback
        self.recon = recon
        self.analysis_dir = analysis_dir
        self.static = None           # reconstruct.Analysis
        self.reconstruction = None   # LLM summary of the decompiled parsing code
        self.analysis = None
        self.evidence = None
        self.last = None          # (code, error, batch) of the previous round
        self.new_per_round = []   # new behaviors found by each round that ran inputs

    # -- setup -------------------------------------------------------------
    def setup(self, c):
        self.c = c
        name = c.binary_path.name
        self.cmd = " ".join([f"./{name}"] + c.target.argv[1:])
        if self.identify:
            self._identify(c, name)
        else:
            self.analysis = "(no analysis available)"
        if self.recon != "none":
            self.static = reconstruct.load(c.target, self.analysis_dir, c.binary_path)
            chosen = reconstruct.select(self.static)
            c.log(event="recon-select", functions=len(chosen),
                  chars=sum(len(code) for _, code in chosen),
                  ghidra_seconds=self.static.meta["seconds"])
            self.reconstruction = reconstruct.summarize(c, self.analysis, chosen)

    def _identify(self, c, name):
        probes = "\n".join(f"$ {cmd}\n{out}\n" for cmd, out in _probe_runs(c.binary_path, name))
        self.evidence = (
            f"`file` output: {_sh(['file', '-b', str(c.binary_path)]).strip()}\n"
            f"Shared libraries: {', '.join(_needed(c.binary_path)) or '(none)'}\n"
            f"Imported functions: {', '.join(_imports(c.binary_path))}\n\n"
            f"Probe runs:\n{probes}\n"
            "Printable strings (filtered):\n" + "\n".join(_strings(c.binary_path)))
        prompt = (
            f"We are fuzzing a stripped x86-64 Linux binary. It is invoked as:\n    {self.cmd}\n"
            "where @@ is replaced by the path of a generated input file.\n\n"
            f"{self.evidence}\n\n"
            "Based on this evidence, write a concise analysis (at most 350 words) covering:\n"
            "1. What program this most likely is and what it does.\n"
            "2. The input format it expects for the @@ argument, with concrete structural details "
            "(magic bytes, header fields and sizes, sections, syntax).\n"
            "3. How the other command-line options affect what gets parsed.\n"
            "4. Parts of the format or processing that look complex or rarely exercised and are "
            "worth targeting.")
        self.analysis, _ = c.ask([{"role": "system", "content": ROLE},
                                  {"role": "user", "content": prompt}],
                                 kind="identify", max_tokens=1200)

    def signature(self, res):
        sig = signature(res)
        if self.feedback == "full":
            return sig
        return (sig[0], sig[2])   # outcome + message only

    # -- prompting ---------------------------------------------------------
    def messages(self):
        parts = [f"## Program\nInvocation: {self.cmd}  (@@ = path of the generated file)\n"
                 f"Analysis:\n{self.analysis}\n"]
        if self.reconstruction:
            parts.append(f"Reconstruction of the input parsing from decompiled code:\n"
                         f"{self.reconstruction}\n")
        if self.last is None:
            parts.append(
                "## Task\nWrite a script that produces an initial set of diverse inputs: mostly "
                "well-formed files exercising different features of the format, plus a few edge "
                "cases (boundary values in size/length/count fields, truncation, unusual but legal "
                "combinations).")
        elif self.feedback == "none":
            parts.append(self._previous_script())
            parts.append("## Task\nWrite a new script that produces inputs different from the "
                         "previous ones, exercising other features and edge cases of the format.")
        else:
            parts += [self._progress(), self._last_batch(), self._previous_script()]
            if self.plateaued():
                parts.append(
                    f"## Task\nThe last {PLATEAU} rounds found no new behavior, so the current "
                    "line of variation is exhausted. Write a new script that switches to a "
                    "different feature, structure or processing path of the format (see the "
                    "analysis) that none of the inputs so far has exercised, instead of varying "
                    "the same fields again.")
            else:
                parts.append(
                    "## Task\nWrite a new script. Inputs marked NEW reached behavior no earlier "
                    "input reached" + (", and higher instruction counts usually mean deeper "
                                       "processing" if self.feedback == "full" else "") +
                    ". Build on those with targeted variations (change one field at a time, push "
                    "length/count/offset fields to boundaries, combine features). Do not repeat "
                    "variations that only produced behavior already seen.")
        return [{"role": "system", "content": ROLE + "\n\n" + GEN_RULES},
                {"role": "user", "content": "\n".join(parts)}]

    def _fmt(self, b):
        s = b["status"]
        if self.feedback == "full":
            s += f", {_human(b['instructions'])} instr"
            if b.get("new_calls"):
                s += ", new calls: " + ", ".join(b["new_calls"][:8])
        return s

    def _progress(self):
        c = self.c
        lines = [f"## Progress\nAfter {c.iteration} rounds: {c.execs} inputs executed, "
                 f"{len(c.behaviors)} distinct behaviors, {len(c.crashes)} crashing inputs.\n",
                 "Distinct behaviors (most recent first): outcome | first output line | times seen"]
        for b in list(c.behaviors.values())[::-1][:20]:
            lines.append(f"- {self._fmt(b)} | {b['message']!r} | x{b['count']}")
        if self.feedback == "full":
            top = sorted(c.corpus, key=lambda e: e["instructions"] or 0, reverse=True)[:3]
            if top:
                lines.append("\nInputs with the highest instruction counts:")
                for e in top:
                    lines.append(f"- {e['name']} ({e['size']} B, round {e['iteration']}): "
                                 f"{self._fmt(e)}; {_preview(e['data'])}")
        return "\n".join(lines) + "\n"

    def _last_batch(self):
        code, err, batch = self.last
        lines = ["## Results of your previous script"]
        if err:
            lines.append(f"The script had a problem: {err}")
        for b in batch:
            if b.get("duplicate"):
                lines.append(f"- {b['name']}: identical to an earlier input, skipped")
                continue
            tag = "NEW" if b["novel"] else "seen before"
            lines.append(f"- {b['name']} ({b['size']} B): {self._fmt(b)}, {tag}; "
                         f"output: {b['message']!r}")
        text = "\n".join(lines) + "\n"
        if self.recon == "linked" and self.static is not None:
            text += "\n" + reconstruct.linked_code(self.static, batch)
        return text

    def _previous_script(self):
        code = self.last[0] or ""
        if len(code) > 4000:
            code = code[:4000] + "\n# ... (truncated)"
        return f"Previous script:\n```python\n{code}\n```\n"

    def plateaued(self):
        recent = self.new_per_round[-PLATEAU:]
        return len(recent) == PLATEAU and not any(recent)

    def observe(self, code, err, batch):
        self.last = (code, err, batch)
        executed = [b for b in batch if not b.get("duplicate")]
        if executed:   # rounds whose script produced nothing do not count toward a plateau
            self.new_per_round.append(sum(b["novel"] for b in executed))
