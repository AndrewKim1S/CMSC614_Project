#!/usr/bin/env python3
"""M3 figure from the time-budget pilot (runs/time-pilot, pulled to results/time-pilot).

Every run had the same wall-clock budget (T minutes, one LLM server, 35 runs at once) and
kept going after the first target crash. Runs overrun T by up to one LLM call, so all
numbers are cut at exactly T from the per-input timestamps:
  coverage(T) = functions covered by inputs executed at t <= T (coverage.json curve)
  reproduced(T) = first target-crash time <= T (summary.json target_hit)
Writes figure_time.pdf/png and table_time.tex next to this script.

    python3 report/m3/make_time_figure.py [--minutes 90] [--trials 2 3 4 5 6] [--curve-target CVE-2021-46023]
"""
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = Path(__file__).resolve().parent
DATA = HERE.parent.parent / "results" / "time-pilot"
LEVELS = ["L0", "L1", "L2", "L3", "L4", "L5", "L6"]
LEVEL_TEXT = ["crash\nonly", "+ program\nidentity", "+ exit code,\noutput",
              "+ syscalls,\ninstr. count", "+ decompiled\ncode", "+ function\ncoverage",
              "+ source\ncode"]
TARGETS = [("CVE-2017-12067", "mkbitmap"), ("CVE-2017-11654", "sipdump"),
           ("CVE-2022-44081", "pngdetail"), ("CVE-2026-3389", "sq"),
           ("CVE-2021-46023", "mruby")]
# categorical slots 1-5 (validated light palette; relief: markers + table)
COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
MARKERS = ["o", "s", "^", "D", "v"]
# ordinal ramp for L0..L6, light yellow-green -> dark purple (viridis, end trimmed for contrast
# on white): still "darker = more information", but adjacent levels differ in hue, not only shade
RAMP = [matplotlib.colors.to_hex(matplotlib.colormaps["viridis"](v))
        for v in (0.80, 0.67, 0.54, 0.41, 0.28, 0.14, 0.0)]
INK, INK2, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e6e5e1", "#fcfcfb"


def load_run(d, T):
    s = json.loads((d / "summary.json").read_text())
    cov = json.loads((d / "coverage.json").read_text()) if (d / "coverage.json").exists() else None
    curve = [p for p in (cov or {}).get("curve", []) if p["t"] <= T]
    calls = 0
    if (d / "events.jsonl").exists():
        for line in (d / "events.jsonl").read_text().splitlines():
            e = json.loads(line)
            if e["event"] == "llm" and e["t"] <= T:
                calls = e["call"]
    hit = s.get("target_hit")
    return {"covered": curve[-1]["covered"] if curve else 0, "measured": cov is not None,
            "curve": curve, "hit": hit["time"] if hit and hit["time"] <= T else None,
            "calls": calls, "error": bool(s.get("error"))}


def collect(T, trials):
    runs = {}
    for cve, _ in TARGETS:
        for lvl in LEVELS:
            for d in sorted((DATA / cve / lvl).glob("trial[0-9]")):
                if int(d.name[5:]) not in trials:
                    continue
                if (d / "summary.json").exists():
                    runs.setdefault((cve, lvl), []).append(load_run(d, T))
    return runs


def style(ax):
    ax.set_facecolor(SURFACE)
    ax.yaxis.grid(True, color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(MUTED)
    ax.tick_params(length=0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=90)
    ap.add_argument("--curve-target", default="CVE-2021-46023",
                    help="target for panel (b): mruby, the largest target, so its levels separate most")
    ap.add_argument("--trials", type=int, nargs="+", default=[2, 3, 4, 5, 6],
                    help="trial 1 ran before the LLM-timeout fix, so it is reported separately")
    ap.add_argument("--suffix", default="")
    args = ap.parse_args()
    T = args.minutes * 60
    runs = collect(T, set(args.trials))
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8.5,
                         "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2})
    fig = plt.figure(figsize=(6.9, 5.9), dpi=200, layout="constrained")
    fig.patch.set_facecolor("white")
    top, bottom = fig.subfigures(2, 1, height_ratios=[1.2, 1], hspace=0.04)
    for sf in (top, bottom):
        sf.set_facecolor("white")
    ax = top.subplots()

    # (a) coverage at T, per target normalized to its best run
    x = list(range(len(LEVELS)))
    stacked = {}    # level -> stars already drawn there, so two targets' stars do not overlap
    for (cve, name), color, marker in zip(TARGETS, COLORS, MARKERS):
        cells = [runs.get((cve, l), []) for l in LEVELS]
        best = max((r["covered"] for c in cells for r in c), default=0) or 1
        mean = [sum(r["covered"] for r in c) / len(c) / best if c else float("nan") for c in cells]
        lo = [min(r["covered"] for r in c) / best if c else float("nan") for c in cells]
        hi = [max(r["covered"] for r in c) / best if c else float("nan") for c in cells]
        ax.fill_between(x, lo, hi, color=color, alpha=0.15, lw=0)
        ax.plot(x, mean, color=color, lw=2, marker=marker, ms=6, mec=SURFACE, mew=1.1,
                label=f"{name} (best {best} functions)", zorder=3)
        for i, c in enumerate(cells):
            n = sum(r["hit"] is not None for r in c)
            if n:
                y = 1.06 + 0.075 * stacked.get(i, 0)
                stacked[i] = stacked.get(i, 0) + 1
                ax.scatter([i], [y], marker="*", s=95, color=color, edgecolors=INK,
                           linewidths=0.7, zorder=4)
                ax.annotate(f"{n}/{len(c)}", (i, y), xytext=(5, -3),
                            textcoords="offset points", fontsize=6.5, color=INK2)
    ax.scatter([], [], marker="*", s=95, color="white", edgecolors=INK, linewidths=0.7,
               label="target CVE reproduced (runs/trials; star in the target's color)")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{l}\n{t}" for l, t in zip(LEVELS, LEVEL_TEXT)], fontsize=7)
    ax.set_ylim(0, 1.24)
    ax.set_ylabel(f"Functions covered at {args.minutes:.0f} min\n(fraction of the target's best run)")
    ax.set_title(f"(a) Coverage after {args.minutes:.0f} minutes, mean of trials (band: min-max)",
                 fontsize=9, color=INK, loc="left")
    style(ax)
    leg = ax.legend(loc="lower right", fontsize=6.5, frameon=True, framealpha=0.95,
                    edgecolor=GRID, labelcolor=INK)
    leg.get_frame().set_facecolor("white")

    # (b) coverage over time for one target, per level (mean of trials, step curves)
    cve = args.curve_target
    name = dict(TARGETS)[cve]
    bx = bottom.subplots()
    grid_t = [i * 30 for i in range(int(T // 30) + 1)]
    for lvl, color in zip(LEVELS, RAMP):
        rs = runs.get((cve, lvl), [])
        if not rs:
            continue
        ys = []
        for t in grid_t:
            vals = [max([p["covered"] for p in r["curve"] if p["t"] <= t] or [0]) for r in rs]
            ys.append(sum(vals) / len(vals))
        bx.step([t / 60 for t in grid_t], ys, where="post", color=color, lw=2, label=lvl)
    bx.set_xlim(0, args.minutes)
    bx.set_ylim(bottom=0)
    bx.set_xlabel("Minutes into the run (includes identification and reconstruction)")
    bx.set_ylabel("Functions covered (mean of trials)")
    bx.set_title(f"(b) {name}: coverage over time by level", fontsize=9, color=INK, loc="left")
    style(bx)
    leg = bx.legend(loc="lower right", fontsize=7, ncol=2, frameon=True, framealpha=0.95,
                    edgecolor=GRID, labelcolor=INK, title="level (darker = more information)",
                    title_fontsize=6.5)
    leg.get_frame().set_facecolor("white")
    fig.savefig(HERE / f"figure_time{args.suffix}.pdf")
    fig.savefig(HERE / f"figure_time{args.suffix}.png")

    # table: per target x level -> coverage per trial, reproductions, LLM calls by T
    lines = [r"\begin{tabular}{l" + "c" * len(LEVELS) + "}", r"\toprule",
             "Target & " + " & ".join(LEVELS) + r" \\", r"\midrule"]
    for cve, name in TARGETS:
        cells = []
        for l in LEVELS:
            rs = runs.get((cve, l), [])
            vals = sorted(r["covered"] for r in rs)
            if len(vals) > 2:    # median (min-max); a cell cannot hold five numbers
                mid = vals[len(vals) // 2] if len(vals) % 2 else \
                    (vals[len(vals) // 2 - 1] + vals[len(vals) // 2]) / 2
                cov = f"{mid:g} ({vals[0]}--{vals[-1]})"
            else:
                cov = "/".join(str(r["covered"]) for r in rs) or "--"
            n = sum(r["hit"] is not None for r in rs)
            cells.append(cov + (rf"$^{{\star{n}}}$" if n else ""))
        lines.append(f"{name} & " + " & ".join(cells) + r" \\")
    calls = []
    for l in LEVELS:
        rs = [r for cve, _ in TARGETS for r in runs.get((cve, l), [])]
        calls.append(f"{sum(r['calls'] for r in rs) / max(len(rs), 1):.1f}")
    lines += [r"\midrule", r"LLM calls (mean) & " + " & ".join(calls) + r" \\",
              r"\bottomrule", r"\end{tabular}"]
    (HERE / f"table_time{args.suffix}.tex").write_text("\n".join(lines) + "\n")
    missing = [(c, l) for (c, l), rs in runs.items() for r in rs if not r["measured"]]
    errors = [(c, l) for (c, l), rs in runs.items() for r in rs if r["error"]]
    print(f"runs: {sum(len(v) for v in runs.values())}; unmeasured: {len(missing)}; errors: {errors}")


if __name__ == "__main__":
    main()
