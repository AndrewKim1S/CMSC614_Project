"""WhiteFox (Yang et al., OOPSLA 2024) adapted to file-input programs:
the white-box + LLM baseline.

Original                                 This adaptation
- target: one compiler optimization      - target: one function of the program
- analysis LLM reads the optimization's  - analysis LLM reads the function's (and its
  source and writes input requirements     callers') upstream source and writes
                                           requirements on the input file
- generation LLM writes test programs    - generation LLM writes an input generator
- instrumentation reports whether the    - gdb one-shot breakpoints on the debug build
  optimization fired                       report whether the function executed
- tests that fired the optimization      - generator scripts whose inputs reached the
  become few-shot examples, chosen by      function become few-shot examples, chosen
  Thompson sampling                        by Thompson sampling
- GPT-4 (analysis) + StarCoder (gen)     - the same Qwen model for both

Target choice: "parsing" ranks the input-processing functions with the same
static selection Our System uses (no knowledge of the bug); "vuln" targets the
function the known PoC crashes in, an upper bound that is reported separately.
"""
import random
from collections import Counter
from pathlib import Path

from . import reconstruct
from .ours import GEN_RULES
from .sources import Reacher, SourceIndex

ROLE = ("You are an expert C/C++ programmer and file-format specialist helping with white-box "
        "testing (fuzzing) of a program for a research project. You can read its source code.")
RETIRE_AFTER = 3   # consecutive rounds that miss a target before it is set aside


class WhiteFoxStrategy:
    name = "whitefox"

    def __init__(self, mode="parsing", k=4, sources_dir="sources", analysis_dir="analysis",
                 n_examples=2, seed=0):
        assert mode in ("parsing", "vuln")
        self.mode = mode
        self.k = k
        self.sources_dir = Path(sources_dir)
        self.analysis_dir = analysis_dir
        self.n_examples = n_examples
        self.rng = random.Random(seed)
        self.targets = []
        self.pool = {}               # target name -> [{"code", "s", "f"}]
        self.reach_count = Counter()
        self.attempts = Counter()
        self.misses = Counter()      # consecutive rounds that did not reach the target
        self.current = None
        self.current_examples = []
        self.last_error = None

    # -- setup -------------------------------------------------------------
    def _static(self, c):
        try:
            return reconstruct.load(c.target, self.analysis_dir, hide=False)
        except FileNotFoundError:
            return None

    def _candidates(self, c, static):
        if self.mode == "vuln":
            # Frames of the PoC crash, innermost first (older ground truth: top frame only).
            names = []
            for e in c.triage.expected.values():
                names += e.get("stack") or [e["func"]]
            return [n.split("(")[0] for n in names if n and n != "??"]
        names = []
        if static is not None:
            names = [self.index.name_at(e) for e, _ in reconstruct.select(static, max_chars=10 ** 9)]
        located = [n for n in names[: self.k * 4] if n and self.index.function(n)]
        if len(located) < self.k:
            # Ghidra may find few functions in a stripped binary (md2html: 50);
            # fall back to scoring the source of every function in the debug build.
            names += self._source_candidates()
        return names

    def _source_candidates(self, limit=600):
        skip = ("_", ".", "frame_dummy", "register_tm_clones", "deregister_tm_clones")
        names = [n for n in self.index.by_name if not n.startswith(skip)][:limit]
        self.index.prefetch(names)
        scored = []
        for n in names:
            f = self.index.function(n)
            if f:
                pseudo = {"strings": [], "code": f["code"], "imports": []}
                scored.append((reconstruct._score(pseudo), n))
        return [n for s, n in sorted(scored, reverse=True) if s > 0]

    def _vuln_pick(self, names):
        """Innermost crash-stack function that a trivial (empty) input does not
        reach; helpers every input executes (mrb_type, main) make no target."""
        # Only functions defined in the binary (the stack also holds fread, __assert_fail...).
        located = [n for n in names if n in self.index.by_name and self.index.function(n)]
        for n in located:
            if not Reacher(self.c.target, self.c.binary_path, [n], self.c.workroot).reached(b""):
                return [n], "innermost crash frame not reached by an empty input"
        return located[:1], "every crash frame is reached by an empty input; using the innermost"

    def _callers(self, static, name, limit=2):
        if static is None or name not in self.index.by_name:
            return []
        entry = f"{self.index.by_name[name]:08x}"
        f = static.funcs.get(entry)
        return [self.index.name_at(e) for e in (f["callers"] if f else [])][:limit]

    def setup(self, c):
        self.c = c
        t = c.target
        self.cmd = " ".join([f"./{c.binary_path.name}"] + t.argv[1:])
        src = self.sources_dir / t.entry_dir.name
        if not src.exists():
            raise FileNotFoundError(f"no source tree in {src}; run harness/fetch_sources.py")
        self.index = SourceIndex(c.binary_path, src)
        self.readme = self._readme(src)
        static = self._static(c)
        names = [n for n in dict.fromkeys(self._candidates(c, static)) if n]
        self.index.prefetch(names[: self.k * 4])
        why = "top-ranked input-processing functions"
        if self.mode == "vuln":
            names, why = self._vuln_pick(names)
        for name in names:
            info = self.index.function(name)
            if info and len(self.targets) < self.k:
                self.targets.append(dict(info, callers=self._callers(static, name)))
        if not self.targets:
            raise RuntimeError("no target function could be located in the source tree")
        c.log(event="wf-targets", mode=self.mode, why=why,
              targets=[(x["name"], x["file"], x["line"], x["located_by"]) for x in self.targets])
        for x in self.targets:
            self.pool[x["name"]] = []
            if c.budget_left():
                x["requirements"] = self._analyze(x)
            else:
                x["requirements"] = "(no analysis: LLM budget exhausted)"
        self.reacher = Reacher(t, c.binary_path, [x["name"] for x in self.targets], c.workroot)

    @staticmethod
    def _readme(src, limit=1500):
        """Project README excerpt. The original WhiteFox targets compilers whose
        input language is known up front; here the target function alone does
        not say what kind of file reaches it (pilot: regex code in a scripting
        language led to JavaScript-style inputs), and a white-box tester would
        know the project anyway."""
        for p in sorted(src.iterdir()):
            if p.is_file() and p.name.lower().startswith("readme") and "win" not in p.name.lower():
                return p.read_text(errors="replace")[:limit].strip()
        return ""

    def _analyze(self, x):
        callers = [self.index.function(n) for n in x["callers"]]
        caller_src = "\n\n".join(f"// {f['file']}\n{f['code'][:2500]}" for f in callers if f)
        prompt = (
            (f"Project README (excerpt):\n{self.readme}\n\n" if self.readme else "") +
            f"The program is invoked as `{self.cmd}`, where @@ is the path of an input file.\n\n"
            f"Target function `{x['name']}` ({x['file']}):\n```c\n{x['code']}\n```\n"
            + (f"\nIts callers:\n```c\n{caller_src}\n```\n" if caller_src else "") +
            f"\nDescribe the input files that make the program execute `{x['name']}` and that "
            "exercise its different branches:\n"
            "1. Requirements: a numbered list of concrete conditions the input file must satisfy "
            "(format, header fields, values, sizes), including what must hold on the path from "
            "reading the file to this function.\n"
            "2. Pseudo-code that constructs such an input.\nAt most 350 words.")
        text, _ = self.c.ask([{"role": "system", "content": ROLE},
                              {"role": "user", "content": prompt}],
                             kind=f"wf-analysis-{x['name'][:40]}", max_tokens=1500)
        return text

    # -- generation --------------------------------------------------------
    def _pick_target(self):
        """Least-reached target first, but a target that 3 rounds in a row failed
        to reach is retired (it may be unreachable from this command line, e.g.
        an encoder in a decoding tool); like WhiteFox's fixed per-optimization
        budget, this keeps one target from absorbing the whole budget."""
        live = [x for x in self.targets if self.misses[x["name"]] < RETIRE_AFTER] or self.targets
        t = min(live, key=lambda x: (self.reach_count[x["name"]] + 0.5 * self.attempts[x["name"]]))
        self.attempts[t["name"]] += 1
        return t

    def _pick_examples(self, name):
        scored = [(self.rng.betavariate(1 + e["s"], 1 + e["f"]), i)
                  for i, e in enumerate(self.pool[name])]
        return [self.pool[name][i] for _, i in sorted(scored, reverse=True)[: self.n_examples]]

    def messages(self):
        t = self.current = self._pick_target()
        ex = self.current_examples = self._pick_examples(t["name"])
        parts = [f"## Program\nInvocation: {self.cmd}  (@@ = path of the generated file)\n",
                 f"## Target\nFunction `{t['name']}` in {t['file']}. Requirements for inputs "
                 f"that make the program execute it:\n{t['requirements']}\n"]
        if ex:
            parts.append("## Examples\nScripts whose inputs reached this function before:\n"
                         + "\n".join(f"```python\n{e['code'][:3000]}\n```" for e in ex))
        if self.last_error:
            parts.append(f"Note: the previous script had a problem: {self.last_error}\n")
        parts.append(f"## Task\nWrite a new script that writes 8 different input files that meet "
                     f"the requirements, each varying a different aspect so that different "
                     f"branches of `{t['name']}` execute.")
        return [{"role": "system", "content": ROLE + "\n\n" + GEN_RULES},
                {"role": "user", "content": "\n".join(parts)}]

    # -- feedback ----------------------------------------------------------
    def inspect(self, data, res):
        return {"reached": sorted(self.reacher.reached(data))}

    def signature(self, res, extra=None):
        return (res.status, tuple((extra or {}).get("reached", ())))

    def observe(self, code, err, batch):
        self.last_error = err
        if self.current is None or code is None:
            return
        name = self.current["name"]
        executed = [b for b in batch if not b.get("duplicate")]
        for b in executed:
            self.reach_count.update(b.get("reached", []))
        hit = any(name in b.get("reached", []) for b in executed)
        self.misses[name] = 0 if hit else self.misses[name] + 1
        for e in self.current_examples:
            e["s" if hit else "f"] += 1
        if hit and all(e["code"] != code for e in self.pool[name]):
            self.pool[name].append({"code": code, "s": 1, "f": 0})
        self.c.log(event="wf-round", target=name, hit=hit,
                   reach_count=dict(self.reach_count), pool=len(self.pool[name]))
