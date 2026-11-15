"""Fuzz targets derived from harness/targets.json.

A target is one binary plus its command line, with the PoC argument replaced by
the placeholder @@ (AFL convention). The PoC itself is never exposed to a
fuzzing strategy; it is only used by the replay harness.
"""
import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

PLACEHOLDER = "@@"

# Messages printed by the crash checks the dataset authors added to some
# targets (printf + abort at the bug site). A real binary would not contain
# them, and they reveal the bug, so the LLM side must never see them.
INSTRUMENTATION = re.compile(r"\[\*\]|\[!\]|(?-i:\bCVE\b)|conditions? for|heap overflow|"
                             r"overflow detected|out-of-bounds detected|double free|triggering",
                             re.I)


@dataclass
class Target:
    id: str
    entry_dir: Path          # dataset entry (holds the original debug binary)
    binary: str              # file name of the binary inside entry_dir
    argv: list               # command line with PLACEHOLDER for the input file
    suffix: str              # extension of the original PoC (some tools look at it)
    sibling_ids: list = field(default_factory=list)  # cases sharing this binary

    @property
    def original_binary(self):
        return self.entry_dir / self.binary

    def argv_for(self, binary_path, input_path):
        """Concrete argv: the binary at binary_path, the input at input_path."""
        out = [str(binary_path)]
        for a in self.argv[1:]:
            out.append(str(input_path) if a == PLACEHOLDER else a)
        return out


def load_targets(targets_json, dataset):
    dataset = Path(dataset)
    cases = json.loads(Path(targets_json).read_text())
    targets = {}
    for c in cases:
        entry = dataset / c["dir"]
        argv = list(c["argv"])
        binary = Path(argv[0]).name
        idx = next(i for i, a in enumerate(argv[1:], 1)
                   if (entry / a).is_file() and a != argv[0])
        suffix = Path(argv[idx]).suffix
        argv[idx] = PLACEHOLDER
        targets[c["id"]] = Target(c["id"], entry, binary, argv, suffix)
    for t in targets.values():
        t.sibling_ids = [o.id for o in targets.values()
                         if o.entry_dir == t.entry_dir and o.binary == t.binary]
    return targets


def prepare_binary(target, dest_dir, strip=True, name=None):
    """Copy the target binary into dest_dir, stripped of symbols/debug info.

    Our System sees only this copy. The dataset binaries carry DWARF info that
    would leak source-level structure, so stripping is on by default.
    """
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / (name or target.binary)
    shutil.copy2(target.original_binary, dest)
    if strip:
        # Absolute path: one dataset entry ships its own (vulnerable) ./strip.
        subprocess.run(["/usr/bin/strip", "--strip-all", str(dest)], check=True)
    dest.chmod(0o755)
    return dest
