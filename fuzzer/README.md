# LLM fuzzing engine

One loop shared by every LLM-based system in the project: the LLM writes a Python
script that generates test inputs, the inputs run against the target, and the
observations go back into the next prompt. A *strategy* decides what the LLM
sees; the *campaign* owns the budget, execution, corpus, crash triage and logs.

| file | role |
|---|---|
| `campaign.py` | CLI entry point for one run on one target |
| `engine.py` | the generate, run, feedback loop; syntax repair; corpus and crash bookkeeping |
| `ours.py` | Our System: identification, seed generation, behavioral feedback, plateau handling |
| `execute.py` | runs the target and collects exit status, output, instruction count (perf), strace/ltrace summaries; behavior signatures |
| `genscript.py` | runs LLM-written generator scripts without network and with resource limits |
| `triage.py` | re-runs crashes on the original debug build under gdb and matches them to `harness/expected_crashes.json` |
| `target.py` | targets from `harness/targets.json` (PoC argument replaced by `@@`), stripped binary copies |
| `llm.py` | client for the vLLM OpenAI-compatible endpoint |

The strategy only ever sees a stripped copy of the binary. The PoC, the README and
the debug build are used only by the replay harness and by triage.

## Running on Nexus

Everything runs inside the shared image (`env/fuzz.def`, built with `env/build_image.sh`).

```bash
# one campaign
srun -p mc2 --account=mc2 --qos=default -c 2 --mem=8G -t 01:00:00 \
    harness/run_campaign.sh --target CVE-2017-12067 --max-llm-calls 20 --strace --ltrace

# several targets in parallel (TARGETS="id1 id2" to override the list)
sbatch -p mc2 --account=mc2 --qos=default -c 4 --mem=16G -t 01:10:00 \
    --wrap "harness/run_pilot.sh --max-llm-calls 15 --strace --ltrace"

python3 harness/summarize_runs.py 'runs/*/*'
```

`LLM_URL` defaults to the endpoint file written by the vLLM serving job.
Ablation switches: `--feedback none|output|full`, `--no-identify`, `--no-strip`, `--anonymize`.

Each run directory holds `config.json`, `summary.json`, `events.jsonl` (every LLM
call, execution, crash), `llm/` (full prompts and responses), `scripts/`,
`corpus/` (inputs with new behavior) and `crashes/`.

## Not implemented yet

- Program reconstruction from decompilation (Ghidra) for Our System
- LLM + AFL++ (seeding AFL++ through `-F`)
- WhiteFox strategy (source analysis, target-function feedback)
- Coverage measurement by replaying corpora on a coverage build
