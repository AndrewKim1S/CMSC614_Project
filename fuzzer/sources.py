"""Source-level access for white-box strategies (WhiteFox).

Function locations come from the dataset's debug build (DWARF, via gdb
`info line`); bodies are cut from the unmodified upstream source tree
(harness/sources.json), so the crash checks the dataset authors added to the
binaries never show up. Reach detection also uses the debug build: one-shot
gdb breakpoints report which target functions an input executes.
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

LINE_RE = re.compile(r'Line (\d+) of "([^"]+)"')
STRIP_LITERALS = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//.*')
SOURCE_EXT = (".c", ".cc", ".cpp", ".cxx", ".y", ".h", ".hh", ".hpp")


def symbols(binary):
    """{address: name} for functions defined in the (unstripped) binary."""
    out = subprocess.run(["nm", "--defined-only", "-C", str(binary)],
                         capture_output=True, text=True).stdout
    syms = {}
    for line in out.splitlines():
        parts = line.split(" ", 2)
        # T/t: text symbols; W/w: weak definitions (C++ templates and inline
        # functions, most of a C++ program's functions).
        if len(parts) == 3 and parts[1] in "TtWw" and int(parts[0], 16):
            # Drop the parameter list and ABI tags: gdb linespecs and source
            # definitions use the plain (qualified) name.
            name = parts[2].split("(")[0].replace("[abi:cxx11]", "")
            syms.setdefault(int(parts[0], 16), name)
    return syms


def resolve(src_root, gdb_path):
    """Map a DWARF file path (often relative to the original build dir) to a
    file in our checkout: same basename, longest matching path suffix."""
    parts = Path(gdb_path).parts
    cands = list(Path(src_root).rglob(parts[-1]))
    if not cands:
        return None

    def suffix_len(c):
        k = 0
        while k < min(len(c.parts), len(parts)) and c.parts[-1 - k] == parts[-1 - k]:
            k += 1
        return k
    return max(cands, key=suffix_len)


def extract(path, line, name, max_chars=6000):
    """Function body around `line`: back up to the signature, then match braces."""
    lines = Path(path).read_text(errors="replace").splitlines()
    simple = re.escape(name.split("::")[-1])
    start = max(0, min(line, len(lines)) - 1)
    for i in range(start, max(0, line - 40) - 1, -1):
        if re.search(rf"\b{simple}\s*\(", lines[i]):
            start = i
            break
    # K&R / GNU style puts the return type on the line above the (qualified) name.
    if (start > 0 and re.match(rf"(?:[\w~<>]+::)*{simple}\b", lines[start].lstrip())
            and lines[start - 1].strip()
            and not lines[start - 1].rstrip().endswith((";", "}", "*/", "{"))):
        start -= 1
    depth, opened, end = 0, False, min(len(lines) - 1, start + 80)
    for j in range(start, len(lines)):
        code = STRIP_LITERALS.sub("", lines[j])
        depth += code.count("{") - code.count("}")
        opened = opened or "{" in code
        if opened and depth <= 0:
            end = j
            break
    body = "\n".join(lines[start:end + 1])
    if len(body) > max_chars:
        body = body[:max_chars] + "\n/* ... truncated ... */"
    return body


class SourceIndex:
    def __init__(self, binary, src_root):
        self.binary = Path(binary)
        self.root = Path(src_root)
        self.syms = symbols(binary)
        self.by_name = {}
        for addr, name in self.syms.items():
            self.by_name.setdefault(name, addr)
        self.cache = {}

    def name_at(self, entry_hex):
        return self.syms.get(int(entry_hex, 16))

    def prefetch(self, names):
        names = [n for n in dict.fromkeys(names) if n and n not in self.cache]
        if not names:
            return
        cmds = []
        for n in names:
            cmds += ["-ex", f"echo @@{n}\\n", "-ex", f"info line {n}"]
        out = subprocess.run(["gdb", "-q", "-nx", "-batch", *cmds, str(self.binary)],
                             capture_output=True, text=True, timeout=300).stdout
        for chunk in out.split("@@")[1:]:
            name, _, rest = chunk.partition("\n")
            m = LINE_RE.search(rest)
            path = resolve(self.root, m[2]) if m else None
            if path is not None:
                loc = (path, int(m[1]), "dwarf")
            else:
                loc = self._grep_definition(name)
            self.cache[name] = None if loc is None else {
                "name": name, "file": str(loc[0].relative_to(self.root)), "line": loc[1],
                "located_by": loc[2], "code": extract(loc[0], loc[1], name)}

    def _grep_definition(self, name):
        """Fallback when the binary has symbols but no line info (e.g. mp4encrypt):
        a definition starts at column 0 with the (qualified) name followed by '('
        and is not a declaration. Implementation files win over headers."""
        if not hasattr(self, "_files"):
            self._files = sorted((p for p in self.root.rglob("*")
                                  if p.suffix in SOURCE_EXT and p.is_file()),
                                 key=lambda p: (p.suffix in (".h", ".hh", ".hpp"), str(p)))
        pat = re.compile(rf"^(?:[\w\*&<>,:~]+\s+)*\**{re.escape(name)}\s*\([^;]*$")
        hits = []
        for p in self._files:
            try:
                lines = p.read_text(errors="replace").splitlines()
            except OSError:
                continue
            hits += [(p, i + 1) for i, line in enumerate(lines)
                     if name.split("::")[-1] in line and pat.match(line)]
        if not hits:
            return None
        # Several definitions (every app in Bento4 has a main): prefer the file
        # named like the binary, e.g. Mp4Encrypt.cpp for mp4encrypt.
        stem = self.binary.name.lower()
        best = next((h for h in hits if stem in str(h[0]).lower()), hits[0])
        return (best[0], best[1], "grep" if len(hits) == 1 or stem in str(best[0]).lower()
                else "grep-ambiguous")

    def function(self, name):
        self.prefetch([name])
        return self.cache.get(name)


class Reacher:
    """Which of the target functions an input executes (gdb one-shot breakpoints
    on the debug build)."""

    def __init__(self, target, binary_path, functions, workroot, timeout=30):
        self.target = target
        self.binary = Path(binary_path).resolve()
        self.functions = list(functions)
        self.workroot = Path(workroot)
        self.timeout = timeout
        self.script = "set pagination off\nset confirm off\n" + "".join(
            f"tbreak {f}\ncommands\nsilent\necho REACHED {f}\\n\ncontinue\nend\n"
            for f in self.functions) + "run\n"

    def reached(self, data):
        d = Path(tempfile.mkdtemp(prefix="reach-", dir=self.workroot))
        try:
            name = "input" + self.target.suffix
            (d / name).write_bytes(data)
            os.symlink(self.binary, d / self.binary.name)
            (d / "reach.gdb").write_text(self.script)
            argv = ["gdb", "-q", "-nx", "-batch", "-x", "reach.gdb", "--args",
                    *self.target.argv_for("./" + self.binary.name, name)]
            try:
                out = subprocess.run(argv, cwd=d, capture_output=True, timeout=self.timeout,
                                     stdin=subprocess.DEVNULL).stdout.decode(errors="replace")
            except subprocess.TimeoutExpired as e:
                out = (e.stdout or b"").decode(errors="replace")
            return {line.split(" ", 1)[1].strip() for line in out.splitlines()
                    if line.startswith("REACHED ")}
        finally:
            shutil.rmtree(d, ignore_errors=True)
