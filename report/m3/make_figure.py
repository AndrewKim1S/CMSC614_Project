#!/usr/bin/env python3
"""M3 Figure 1: function coverage across the information ladder (pilot).

Reads results/ladder-pilot/ (pulled from runs/ladder-pilot on Nexus) and writes
figure1.pdf / figure1.png and table1.tex next to this script.
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = Path(__file__).resolve().parent
DATA = HERE.parent.parent / "results" / "ladder-pilot"

LEVELS = ["L0", "L1", "L2", "L3", "L4", "L5", "L6"]
LEVEL_TEXT = ["crash\nonly", "+ program\nidentity", "+ exit code,\noutput",
              "+ syscalls,\ninstr. count", "+ decompiled\ncode", "+ function\ncoverage",
              "+ source\ncode"]
# Target order = categorical slot order (dataviz reference palette, light mode,
# validated: CVD and normal-vision separation pass; contrast relief = markers + table).
TARGETS = [("CVE-2017-12067", "mkbitmap"), ("CVE-2017-11654", "sipdump"),
           ("CVE-2022-44081", "pngdetail"), ("CVE-2026-3389", "sq"),
           ("CVE-2021-46023", "mruby")]
COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
MARKERS = ["o", "s", "^", "D", "v"]
INK, INK2, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e6e5e1", "#fcfcfb"


def load():
    rows = json.loads((DATA / "results.json").read_text())
    return {(r["target"], r["config"]): r for r in rows}


def main():
    by = load()
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8.5,
                         "axes.edgecolor": MUTED, "axes.labelcolor": INK2,
                         "xtick.color": INK2, "ytick.color": INK2})
    fig, ax = plt.subplots(figsize=(6.6, 3.5), dpi=200)
    fig.patch.set_facecolor("white")
    ax.set_facecolor(SURFACE)
    x = range(len(LEVELS))
    for (cve, name), color, marker in zip(TARGETS, COLORS, MARKERS):
        cov = [by[(cve, lvl)]["covered"] for lvl in LEVELS]
        best = max(cov)
        rel = [c / best for c in cov]
        ax.plot(x, rel, color=color, lw=2, marker=marker, ms=6.5, mec=SURFACE, mew=1.2,
                label=f"{name} ({cve}, max {best} functions)", zorder=3)
        hits = [i for i, lvl in enumerate(LEVELS) if by[(cve, lvl)]["hit_calls"] is not None]
        if hits:
            ax.scatter([x[i] for i in hits], [rel[i] + 0.055 for i in hits], marker="*", s=70,
                       color=INK, zorder=4)
    ax.scatter([], [], marker="*", s=70, color=INK, label="target CVE reproduced in that run")
    ax.set_xticks(list(x))
    ax.set_xticklabels([f"{l}\n{t}" for l, t in zip(LEVELS, LEVEL_TEXT)], fontsize=7.5)
    ax.set_ylim(0, 1.12)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_ylabel("Functions covered\n(fraction of the target's best level)")
    ax.yaxis.grid(True, color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.spines["left"].set_color(MUTED)
    ax.spines["bottom"].set_color(MUTED)
    ax.tick_params(length=0)
    ax.set_xlabel("Information available to the LLM fuzzer (each level includes the previous)",
                  color=INK2, labelpad=6)
    leg = ax.legend(loc="lower right", fontsize=7, frameon=True, framealpha=0.95,
                    edgecolor=GRID, labelcolor=INK)
    leg.get_frame().set_facecolor("white")
    fig.tight_layout()
    fig.savefig(HERE / "figure1.pdf")
    fig.savefig(HERE / "figure1.png")

    # Table with the absolute numbers (the relief for low-contrast hues, and the data itself).
    lines = [r"\begin{tabular}{l" + "r" * len(LEVELS) + "}", r"\toprule",
             "Target & " + " & ".join(LEVELS) + r" \\", r"\midrule"]
    for cve, name in TARGETS:
        cells = []
        for lvl in LEVELS:
            r = by[(cve, lvl)]
            cell = str(r["covered"])
            if r["hit_calls"] is not None:
                cell += rf"$^{{\star{r['hit_calls']}}}$"
            cells.append(cell)
        lines.append(f"{name} & " + " & ".join(cells) + r" \\")
    rounds = []
    for lvl in LEVELS:
        rs = [json.loads((DATA / cve / lvl / "trial1" / "summary.json").read_text())["rounds"]
              for cve, _ in TARGETS]
        rounds.append(f"{sum(rs) / len(rs):.1f}")
    lines += [r"\midrule", "Generation rounds (mean) & " + " & ".join(rounds) + r" \\",
              r"\bottomrule", r"\end{tabular}"]
    (HERE / "table1.tex").write_text("\n".join(lines) + "\n")
    print("wrote", HERE / "figure1.pdf", HERE / "table1.tex")


if __name__ == "__main__":
    main()
