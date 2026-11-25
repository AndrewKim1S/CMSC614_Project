"""Run one LLM fuzzing campaign on one target.

    python3 -m fuzzer.campaign --target CVE-2017-12067 --llm-url http://tron52:8000/v1

Use harness/run_campaign.sh to run it inside the shared image on Nexus.
"""
import argparse
import json
import shutil
import tempfile
import time
from pathlib import Path

from .engine import Campaign
from .execute import Executor
from .llm import LLM
from .ours import OursStrategy
from .target import load_targets, prepare_binary
from .triage import Triage
from .whitefox import WhiteFoxStrategy


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", required=True, help="case id from harness/targets.json")
    ap.add_argument("--system", choices=["ours", "whitefox"], default="ours")
    ap.add_argument("--wf-mode", choices=["parsing", "vuln"], default="parsing",
                    help="WhiteFox targets: input-processing functions, or the known crash "
                         "function (upper bound)")
    ap.add_argument("--wf-targets", type=int, default=4, help="WhiteFox: number of target functions")
    ap.add_argument("--sources-dir", default="sources")
    ap.add_argument("--targets", default="harness/targets.json")
    ap.add_argument("--dataset", default="dataset")
    ap.add_argument("--expected", default="harness/expected_crashes.json")
    ap.add_argument("--llm-url", required=True)
    ap.add_argument("--model", default="Qwen/Qwen3.8-27B")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--max-tokens", type=int, default=8192, help="per reply (context is 24,576)")
    ap.add_argument("--thinking", action="store_true", help="enable Qwen thinking mode")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--minutes", "--max-minutes", dest="max_minutes", type=float, default=60,
                    help="time budget of the run (wall clock, includes identification/reconstruction)")
    ap.add_argument("--max-llm-calls", type=int, default=0,
                    help="optional cap on LLM calls (0 = none; time is the budget)")
    ap.add_argument("--exec-timeout", type=float, default=10)
    ap.add_argument("--feedback", choices=["none", "crash", "output", "full"], default="full",
                    help="none: no results; crash: crashed or not; output: + exit status and "
                         "output; full: + instruction count (and --strace/--ltrace)")
    ap.add_argument("--coverage", action="store_true",
                    help="L5: function coverage of each input as feedback (needs the Ghidra export)")
    ap.add_argument("--source", action="store_true",
                    help="L6: upstream source instead of decompiled code in the reconstruction "
                         "(needs --recon and harness/fetch_sources.py)")
    ap.add_argument("--no-identify", action="store_true", help="skip the identification stage")
    ap.add_argument("--recon", choices=["none", "summary", "linked"], default="none",
                    help="Ghidra reconstruction: none, summary in prompts, or summary plus "
                         "decompiled code linked to each output (needs harness/run_ghidra.sh)")
    ap.add_argument("--analysis-dir", default="analysis")
    ap.add_argument("--strace", action="store_true", help="add strace syscall summaries (full feedback)")
    ap.add_argument("--ltrace", action="store_true", help="add ltrace library-call summaries (full feedback)")
    ap.add_argument("--no-strip", action="store_true", help="give the LLM side the unstripped binary")
    ap.add_argument("--anonymize", action="store_true", help="rename the binary to 'target'")
    ap.add_argument("--stop-on-target", action="store_true",
                    help="stop as soon as the target CVE is reproduced (default: run for the "
                         "whole time budget and record when it was first reproduced)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    target = load_targets(args.targets, args.dataset)[args.target]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if args.system == "whitefox":
        label = f"whitefox-{args.wf_mode}"
    else:
        label = (f"ours-{args.feedback}" + ("" if args.recon == "none" else f"-recon-{args.recon}")
                 + ("-cov" if args.coverage else "") + ("-src" if args.source else ""))
    out = Path(args.out or f"runs/{target.id.replace('#', '_')}/{stamp}-{label}")
    out.mkdir(parents=True, exist_ok=True)
    (out / "config.json").write_text(json.dumps(vars(args), indent=1) + "\n")

    workroot = Path(tempfile.mkdtemp(prefix="cmsc614-"))
    try:
        whitefox = args.system == "whitefox"
        # White-box: WhiteFox runs (and sets breakpoints in) the debug build.
        binary = prepare_binary(target, workroot / "bin", strip=not (args.no_strip or whitefox),
                                name="target" if args.anonymize else None)
        full = args.feedback == "full" and not whitefox
        executor = Executor(target, binary, workroot / "runs", timeout=args.exec_timeout,
                            perf=full, strace=full and args.strace, ltrace=full and args.ltrace)
        expected = args.expected if Path(args.expected).exists() else None
        triage = Triage(target, expected, workroot)
        llm = LLM(args.llm_url, args.model, temperature=args.temperature,
                  max_tokens=args.max_tokens, thinking=args.thinking, seed=args.seed)
        if whitefox:
            strategy = WhiteFoxStrategy(mode=args.wf_mode, k=args.wf_targets,
                                        sources_dir=args.sources_dir,
                                        analysis_dir=args.analysis_dir, seed=args.seed or 0)
        else:
            strategy = OursStrategy(identify=not args.no_identify, feedback=args.feedback,
                                    recon=args.recon, analysis_dir=args.analysis_dir,
                                    coverage=args.coverage, source=args.source,
                                    sources_dir=args.sources_dir)
        summary = Campaign(target, strategy, llm, executor, triage, out, workroot,
                           max_llm_calls=args.max_llm_calls, max_minutes=args.max_minutes,
                           stop_on_target=args.stop_on_target).run()
    finally:
        shutil.rmtree(workroot, ignore_errors=True)
    print(json.dumps(summary, indent=1))
    print(f"run directory: {out}")


if __name__ == "__main__":
    main()
