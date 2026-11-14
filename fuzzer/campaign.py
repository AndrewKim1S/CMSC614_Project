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


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", required=True, help="case id from harness/targets.json")
    ap.add_argument("--targets", default="harness/targets.json")
    ap.add_argument("--dataset", default="dataset")
    ap.add_argument("--expected", default="harness/expected_crashes.json")
    ap.add_argument("--llm-url", required=True)
    ap.add_argument("--model", default="Qwen/Qwen3.8-27B")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--max-tokens", type=int, default=8192, help="per reply (context is 24,576)")
    ap.add_argument("--thinking", action="store_true", help="enable Qwen thinking mode")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--max-llm-calls", type=int, default=30)
    ap.add_argument("--max-minutes", type=float, default=30)
    ap.add_argument("--exec-timeout", type=float, default=10)
    ap.add_argument("--feedback", choices=["none", "output", "full"], default="full")
    ap.add_argument("--no-identify", action="store_true", help="skip the identification stage")
    ap.add_argument("--strace", action="store_true", help="add strace syscall summaries (full feedback)")
    ap.add_argument("--ltrace", action="store_true", help="add ltrace library-call summaries (full feedback)")
    ap.add_argument("--no-strip", action="store_true", help="give the LLM side the unstripped binary")
    ap.add_argument("--anonymize", action="store_true", help="rename the binary to 'target'")
    ap.add_argument("--keep-going", action="store_true", help="continue after the target crash is found")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    target = load_targets(args.targets, args.dataset)[args.target]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = Path(args.out or f"runs/{target.id.replace('#', '_')}/{stamp}-ours-{args.feedback}")
    out.mkdir(parents=True, exist_ok=True)
    (out / "config.json").write_text(json.dumps(vars(args), indent=1) + "\n")

    workroot = Path(tempfile.mkdtemp(prefix="cmsc614-"))
    try:
        binary = prepare_binary(target, workroot / "bin", strip=not args.no_strip,
                                name="target" if args.anonymize else None)
        full = args.feedback == "full"
        executor = Executor(target, binary, workroot / "runs", timeout=args.exec_timeout,
                            perf=full, strace=full and args.strace, ltrace=full and args.ltrace)
        expected = args.expected if Path(args.expected).exists() else None
        triage = Triage(target, expected, workroot)
        llm = LLM(args.llm_url, args.model, temperature=args.temperature,
                  max_tokens=args.max_tokens, thinking=args.thinking, seed=args.seed)
        strategy = OursStrategy(identify=not args.no_identify, feedback=args.feedback)
        summary = Campaign(target, strategy, llm, executor, triage, out, workroot,
                           max_llm_calls=args.max_llm_calls, max_minutes=args.max_minutes,
                           stop_on_target=not args.keep_going).run()
    finally:
        shutil.rmtree(workroot, ignore_errors=True)
    print(json.dumps(summary, indent=1))
    print(f"run directory: {out}")


if __name__ == "__main__":
    main()
