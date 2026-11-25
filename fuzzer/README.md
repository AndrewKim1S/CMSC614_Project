# LLM fuzzing engine

One loop shared by every LLM-based system in the project: the LLM writes a Python
script that generates test inputs, the inputs run against the target, and the
observations go back into the next prompt. A *strategy* decides what the LLM
sees; the *campaign* owns the budget, execution, corpus, crash triage and logs.

| file | role |
|---|---|
| `campaign.py` | CLI entry point for one run on one target |
| `engine.py` | the generate, run, feedback loop; syntax repair; corpus and crash bookkeeping |
| `ours.py` | Our System: identification, reconstruction, seed generation, behavioral feedback, plateau handling |
| `reconstruct.py` | Ghidra export (via `ghidra/ExportForLLM.java`), selection of input-processing functions, LLM summary, message-to-code linking |
| `whitefox.py` | WhiteFox baseline (white-box + LLM): per-function source analysis, generation with Thompson-sampled examples of scripts that reached the function |
| `sources.py` | upstream source lookup through the debug build's DWARF info, gdb one-shot breakpoints for function reach |
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
Ablation switches: `--feedback none|output|full`, `--recon none|summary|linked`,
`--no-identify`, `--no-strip`, `--anonymize`.

### Ghidra reconstruction

`--recon` needs a Ghidra export of the target's stripped binary, computed once
with the separate Ghidra image (`env/ghidra.def`, `env/build_image.sh ghidra`):

```bash
srun -p mc2 --account=mc2 --qos=default -c 4 --mem=16G -t 02:00:00 \
    harness/run_ghidra.sh CVE-2017-12067 CVE-2022-44081
python3 -m fuzzer.reconstruct show --target CVE-2017-12067   # which functions get selected
```

The export lands in `analysis/<entry>/<binary>/` with the binary's SHA-1, and a
campaign refuses to use an export made from a different binary. `summary` adds
an LLM summary of the selected decompiled code to every prompt (2-3 extra LLM
calls at setup); `linked` also shows, after each round, the decompiled function
that references the string the target printed.

Each run directory holds `config.json`, `summary.json`, `events.jsonl` (every LLM
call, execution, crash), `llm/` (full prompts and responses), `scripts/`,
`corpus/` (inputs with new behavior) and `crashes/`.

### WhiteFox (white-box + LLM baseline)

```bash
python3 harness/fetch_sources.py                     # upstream sources from harness/sources.json
harness/run_campaign.sh --target CVE-2017-12067 --system whitefox --wf-mode parsing
```

WhiteFox runs the debug build. For each target function it asks the LLM once
for the input requirements (from the function's and its callers' upstream
source), then generates inputs for the least-reached target, with up to two
earlier scripts that reached it as examples (Thompson sampling). gdb one-shot
breakpoints decide whether an input reached a target.

- `--wf-mode parsing` (default): the top `--wf-targets` input-processing
  functions from the same static selection Our System uses; needs the Ghidra
  export. No knowledge of the bug.
- `--wf-mode vuln`: the function the known PoC crashes in. An upper bound,
  report separately. Not meaningful when that function is a helper every input
  reaches (e.g. `mrb_type` for CVE-2021-46023).

Sources come from the README's pinned versions, unmodified, so the dataset's
crash instrumentation is not visible (`harness/sources.json`; CVE-2022-44321
has no pinned version, so its source is the default branch).
`harness/check_whitefox.py` verifies, without LLM calls, that every binary's
targets are found in the source and that the PoC reaches the vuln-mode target.

Known limits: for yara (CVE-2017-5924), bison, mruby, wvunpack and rtf2html
every function on the PoC's crash stack also runs on an empty input, so the
vuln-mode target does not single out the bug; CVE-2025-1377 has no
reproducible crash, so no target oracle.

### Rebuilt binaries

The dataset's sam2p (CVE-2020-19491) and mujs-pp (CVE-2022-30975) were fully
stripped. `harness/rebuild_debug.sh` (in `env/build.def`, gcc-14) rebuilds
them from the README's commit and flags without stripping; `harness/targets.json`
points both cases at `rebuilt/<entry>/` for every system. Both PoCs still crash
with SIGSEGV, now at `CGIF::AddExtensionBlock` and `jsP_dumpsyntax` (the
function named in CVE-2022-30975). Stripped sizes differ from the dataset
binaries by 0.9% (sam2p) and 5.5% (mujs-pp), so the builds are close to but
not byte-identical with the originals.

## Information ladder

The main experiment asks whether more information makes the fuzzer better.
The algorithm (this engine, one LLM) is fixed; only what the LLM sees grows,
each level including the previous one (`harness/run_experiment.py` configs):

| level | adds | flags |
|---|---|---|
| L0 | crashed or not (binary renamed to `target`) | `--no-identify --anonymize --feedback crash` |
| L1 | program identity: strings, imports, `--help` | `--feedback crash` |
| L2 | exit status, first output line | `--feedback output` |
| L3 | syscall / library-call summaries, instruction count | `--feedback full --strace --ltrace` |
| L4 | decompiled code: reconstruction summary, code behind each message | `--recon linked` |
| L5 | function coverage of each input (stripped binary, gdb) | `--coverage` |
| L6 | upstream source instead of decompiled code (same functions as L4) | `--source` |

All LLM calls, including identification and reconstruction, count against the
same budget. Coverage for comparison across levels (and other tools) is
measured afterwards by `harness/measure_coverage.py` on the debug build, from
the `inputs/` every run keeps.

## Threats to validity and fixed mistakes

- Prompt hint (fixed 2026-11-15): the generation rules used the example file
  name "03_large_width.bmp", which names a format and a field. L0 (no
  information at all) then wrote BMP files, one with zero width, and hit the
  mkbitmap bug in one call. Every pilot before the fix (Our System v1-v4,
  WhiteFox v1-v2) used this text, so their mkbitmap results are biased.
- Code-block extraction (fixed): Qwen often leaves a code fence open; early
  pilots counted those replies as syntax errors.
- Instrumented targets: 10 binaries contain the dataset's `printf` + `abort`
  checks. Functions containing them are hidden from decompiled code (L4/L5);
  sources are unmodified upstream code (L6, WhiteFox).
- L0 still shows the command-line options (e.g. `-zR3`), which can hint at the
  program.
- mkbitmap's instrumented condition (zero width or height) is an easy edge case
  for any LLM; treat it as a sanity target, not evidence.
- Memorization: the LLM may know these programs and CVEs; report results split
  by CVE date relative to the model's training data.
- Rebuilt sam2p and mujs-pp are close to, not identical with, the dataset
  binaries; picoc's source is unpinned.
- Function-entry coverage is coarser than AFL's edge coverage.

## Experiments

```bash
python3 harness/run_experiment.py --name exp1 --configs whitefox-parsing ours-recon \
    --trials 3 --jobs 6 --max-llm-calls 30 --max-minutes 60
python3 harness/run_experiment.py --name exp1 --report
```

One case per binary (28), fixed seeds per trial, finished runs are skipped on
restart. Results land in `runs/<name>/<target>/<config>/trial<k>/`.

## Not implemented yet

- LLM + AFL++ (seeding AFL++ through `-F`)
- Coverage measurement by replaying corpora on a coverage build
