"""Generate -> run -> feedback loop shared by every LLM-based system.

A strategy decides what the LLM sees (setup, messages, signature, observe);
the campaign owns the budget, execution, corpus, crash triage and logging.
"""
import hashlib
import json
import time
import traceback
from pathlib import Path

from .execute import first_line
from .genscript import extract_code, run_generator, syntax_error

REPAIR_SYSTEM = ("You fix Python 3 scripts. Reply with the corrected complete script in exactly "
                 "one ```python code block, changing nothing except what is needed for it to run.")


class Campaign:
    def __init__(self, target, strategy, llm, executor, triage, out_dir, workroot,
                 max_llm_calls=30, max_minutes=30, stop_on_target=True, max_triage=50):
        self.target = target
        self.strategy = strategy
        self.llm = llm
        self.executor = executor
        self.binary_path = executor.binary_path
        self.triage = triage
        self.out = Path(out_dir)
        self.workroot = Path(workroot)
        self.max_llm_calls = max_llm_calls
        self.max_seconds = max_minutes * 60
        self.stop_on_target = stop_on_target
        self.max_triage = max_triage

        self.iteration = 0
        self.execs = 0
        self.behaviors = {}      # signature -> first occurrence + count
        self.corpus = []         # inputs that produced a new behavior
        self.crashes = []
        self.seen = set()        # sha1 of every executed input
        self.calls_seen = set()  # syscalls / library calls observed so far
        self.target_hit = None
        self.error = None
        for sub in ("llm", "scripts", "corpus", "crashes"):
            (self.out / sub).mkdir(parents=True, exist_ok=True)
        self.events = open(self.out / "events.jsonl", "w")

    # -- helpers -------------------------------------------------------------
    def elapsed(self):
        return time.monotonic() - self.start

    def log(self, **event):
        event["t"] = round(self.elapsed(), 2)
        self.events.write(json.dumps(event) + "\n")
        self.events.flush()

    def ask(self, messages, kind, max_tokens=None):
        text, meta = self.llm.chat(messages, max_tokens=max_tokens)
        n = self.llm.calls
        (self.out / "llm" / f"{n:03d}_{kind}.txt").write_text(
            "\n\n".join(f"===== {m['role'].upper()} =====\n{m['content']}" for m in messages)
            + f"\n\n===== RESPONSE =====\n{text}\n")
        self.log(event="llm", kind=kind, call=n, **meta)
        return text, meta

    def budget_left(self):
        return self.llm.calls < self.max_llm_calls and self.elapsed() < self.max_seconds

    # -- main loop -----------------------------------------------------------
    def run(self):
        self.start = time.monotonic()
        try:
            self.strategy.setup(self)
            while self.budget_left() and not (self.stop_on_target and self.target_hit):
                self.round()
        except Exception:
            self.error = traceback.format_exc()
            self.log(event="error", error=self.error)
        return self.finish()

    def round(self):
        self.iteration += 1
        text, meta = self.ask(self.strategy.messages(), kind=f"gen{self.iteration:03d}")
        if meta["finish_reason"] == "length":
            # A truncated script cannot be repaired by asking for it again in full.
            msg = ("the reply hit the output length limit and was cut off; write a shorter "
                   "script (fewer files, compact helpers, no long literal data)")
            self.strategy.observe(None, msg, [])
            self.log(event="round", iteration=self.iteration, error=msg)
            return
        code = extract_code(text)
        if code is None:
            self.strategy.observe(None, "the reply contained no ```python code block", [])
            self.log(event="round", iteration=self.iteration, error="no code block")
            return
        code = self.repair(code)
        (self.out / "scripts" / f"round{self.iteration:03d}.py").write_text(code)
        files, err = run_generator(code, self.workroot)
        batch = [self.execute(name, data) for name, data in files]
        self.strategy.observe(code, err, batch)
        self.log(event="round", iteration=self.iteration, files=len(files), error=err,
                 new=sum(b.get("novel", False) for b in batch), behaviors=len(self.behaviors),
                 crashes=len(self.crashes))

    def repair(self, code):
        """One short fix-up call for a script that does not even compile.
        Cheaper than losing the round; it counts against the LLM budget."""
        err = syntax_error(code)
        if not err or not self.budget_left():
            return code
        text, _ = self.ask([{"role": "system", "content": REPAIR_SYSTEM},
                            {"role": "user", "content": f"This script fails with SyntaxError: {err}\n\n"
                                                        f"```python\n{code}\n```"}],
                           kind=f"fix{self.iteration:03d}")
        fixed = extract_code(text)
        ok = bool(fixed) and syntax_error(fixed) is None
        self.log(event="repair", iteration=self.iteration, error=err, fixed=ok)
        return fixed if ok else code

    def execute(self, name, data):
        h = hashlib.sha1(data).hexdigest()
        if h in self.seen:
            return {"name": name, "size": len(data), "duplicate": True}
        self.seen.add(h)
        res = self.executor.run(data)
        self.execs += 1

        calls = set(res.syscalls or ()) | set(res.libcalls or ())
        new_calls = sorted(calls - self.calls_seen) if self.calls_seen else []
        self.calls_seen |= calls
        sig = self.strategy.signature(res)
        novel = sig not in self.behaviors
        item = {"name": name, "size": len(data), "status": res.status,
                "instructions": res.instructions, "message": first_line(res),
                "novel": novel, "new_calls": new_calls}
        if novel:
            fname = f"{h[:12]}{self.target.suffix}"
            (self.out / "corpus" / fname).write_bytes(data)
            self.behaviors[sig] = {**item, "count": 0, "iteration": self.iteration}
            self.corpus.append({**item, "iteration": self.iteration, "data": data, "file": fname})
        self.behaviors[sig]["count"] += 1
        self.log(event="exec", iteration=self.iteration, sha1=h, seconds=res.seconds,
                 **{k: v for k, v in item.items() if k != "new_calls"})
        if res.crashed:
            self.crash(item, data, h)
        return item

    def crash(self, item, data, h):
        fname = f"{h[:12]}{self.target.suffix}"
        (self.out / "crashes" / fname).write_bytes(data)
        site = match = None
        if self.triage and len(self.crashes) < self.max_triage:
            site = self.triage.site(data)
            match = self.triage.match(site)
        rec = {"time": round(self.elapsed(), 2), "iteration": self.iteration,
               "llm_calls": self.llm.calls, "execs": self.execs, "name": item["name"],
               "file": fname, "status": item["status"], "match": match,
               "site": site and {k: site[k] for k in ("signal", "func", "src")}}
        self.crashes.append(rec)
        self.log(event="crash", **rec)
        if match and not self.target_hit:
            self.target_hit = rec

    def finish(self):
        sites = {(c["site"] or {}).get("func") for c in self.crashes if c["site"]}
        summary = {
            "target": self.target.id,
            "strategy": self.strategy.name,
            "elapsed": round(self.elapsed(), 1),
            "llm_calls": self.llm.calls,
            "prompt_tokens": self.llm.prompt_tokens,
            "completion_tokens": self.llm.completion_tokens,
            "rounds": self.iteration,
            "execs": self.execs,
            "behaviors": len(self.behaviors),
            "crashing_inputs": len(self.crashes),
            "crash_sites": sorted(s for s in sites if s),
            "first_crash": self.crashes[0] if self.crashes else None,
            "target_hit": self.target_hit,
            "error": self.error,
        }
        (self.out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
        self.events.close()
        return summary
