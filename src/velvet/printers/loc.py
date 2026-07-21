"""``loc`` printer — line counts split by file role.

Spec: spec/printers-and-tools.md §A.10.  Counts LOC (total lines), SLOC
(non-empty, non-comment lines) and CLOC (comment lines), each split into
SRC (project sources), DEP (dependencies) and TEST (test files).

Original clean-room implementation.
"""

from __future__ import annotations

from dataclasses import dataclass

from velvet.compile.artifacts import is_dependency_path
from velvet.printers._utils import is_test_path, render_table
from velvet.printers.base import Printer


@dataclass
class _Counts:
    loc: int = 0
    sloc: int = 0
    cloc: int = 0


def count_lines(source: str) -> _Counts:
    """Count LOC/SLOC/CLOC of one Solidity source text.

    A line carrying both code and a comment counts as SLOC; comment-only
    lines count as CLOC; blank lines are neither.  Handles ``//`` line
    comments and ``/* ... */`` block comments (including multi-line blocks).
    String literals containing comment markers are a known approximation.
    """
    counts = _Counts()
    in_block = False
    for raw_line in source.splitlines():
        counts.loc += 1
        has_code = False
        has_comment = in_block  # continuation lines of a block comment
        i = 0
        line = raw_line
        while i < len(line):
            if in_block:
                end = line.find("*/", i)
                if end == -1:
                    i = len(line)
                else:
                    in_block = False
                    i = end + 2
                continue
            if line.startswith("//", i):
                has_comment = True
                break
            if line.startswith("/*", i):
                has_comment = True
                in_block = True
                i += 2
                continue
            if not line[i].isspace():
                has_code = True
            i += 1
        if has_code:
            counts.sloc += 1
        elif has_comment:
            counts.cloc += 1
    return counts


class LocPrinter(Printer):
    RULE = "loc"
    TITLE = "Line counts (LOC/SLOC/CLOC) split by source/dependency/test"

    def output(self) -> None:
        roles = {"SRC": _Counts(), "DEP": _Counts(), "TEST": _Counts()}
        for info in self.compilation_unit.compilation.source_units.values():
            path = info.filename.absolute
            if is_dependency_path(path):
                role = "DEP"
            elif is_test_path(path):
                role = "TEST"
            else:
                role = "SRC"
            counted = count_lines(info.source)
            bucket = roles[role]
            bucket.loc += counted.loc
            bucket.sloc += counted.sloc
            bucket.cloc += counted.cloc
        rows = [
            ["LOC", roles["SRC"].loc, roles["DEP"].loc, roles["TEST"].loc],
            ["SLOC", roles["SRC"].sloc, roles["DEP"].sloc, roles["TEST"].sloc],
            ["CLOC", roles["SRC"].cloc, roles["DEP"].cloc, roles["TEST"].cloc],
        ]
        self.info(render_table(["", "SRC", "DEP", "TEST"], rows))
        total = roles["SRC"].loc + roles["DEP"].loc + roles["TEST"].loc
        self.info(f"Total LOC: {total}")
