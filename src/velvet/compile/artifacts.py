"""Compilation artifacts — the contract between velvet.compile and velvet core.

Original clean-room implementation per spec/architecture.md §3.3.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class Filename:
    """Normalized path forms for one source file."""

    absolute: str
    used: str  # path as referenced by the compiler (import path)
    relative: str = ""
    short: str = ""

    def __post_init__(self) -> None:
        if not self.relative:
            object.__setattr__(self, "relative", self.absolute)
        if not self.short:
            object.__setattr__(self, "short", Path(self.absolute).name)


@dataclass
class SourceUnitInfo:
    """One compiled source unit (one .sol file)."""

    source_id: int
    filename: Filename
    ast: dict[str, Any]
    source: str

    @property
    def is_dependency(self) -> bool:
        return is_dependency_path(self.filename.absolute)


_DEPENDENCY_MARKERS = ("node_modules", "/lib/", ".brownie/packages", "vendor/")


def is_dependency_path(path: str) -> bool:
    """True when the path lives under a dependency directory."""
    norm = path.replace("\\", "/")
    if "node_modules" in norm:
        return True
    if "/lib/" in norm or norm.startswith("lib/"):
        return True
    for marker in _DEPENDENCY_MARKERS[2:]:
        if marker in norm:
            return True
    return False


@dataclass
class CompilationArtifacts:
    """Everything produced by compiling one batch of sources."""

    source_units: dict[int, SourceUnitInfo] = field(default_factory=dict)
    compiler_version: str = ""
    abis: dict[str, list] = field(default_factory=dict)
    bytecode: dict[str, dict[str, str]] = field(default_factory=dict)  # name -> {init, deployed}
    remappings: list[str] = field(default_factory=list)
    libraries: dict[str, str] = field(default_factory=dict)
    working_dir: str = ""

    # ------------------------------------------------------------------
    def filename_lookup(self, used_path: str) -> Optional[Filename]:
        """Resolve a path used by the compiler to its normalized Filename."""
        for info in self.source_units.values():
            f = info.filename
            if used_path in (f.used, f.absolute, f.relative, f.short):
                return f
        # Fall back to suffix matching (compiler may prefix paths differently)
        for info in self.source_units.values():
            if info.filename.absolute.endswith(used_path) or used_path.endswith(
                info.filename.used
            ):
                return info.filename
        return None

    def source_of(self, source_id: int) -> str:
        return self.source_units[source_id].source

    def export(self, export_dir: str | Path) -> Path:
        """Write a reproducible artifacts bundle (AST/ABI/bytecode)."""
        out = Path(export_dir) / "velvet-export"
        out.mkdir(parents=True, exist_ok=True)
        bundle = {
            "compiler_version": self.compiler_version,
            "source_units": {
                str(sid): {
                    "filename": {
                        "absolute": i.filename.absolute,
                        "used": i.filename.used,
                        "relative": i.filename.relative,
                        "short": i.filename.short,
                    },
                    "ast": i.ast,
                    "source": i.source,
                }
                for sid, i in self.source_units.items()
            },
            "abis": self.abis,
            "bytecode": self.bytecode,
            "remappings": self.remappings,
            "libraries": self.libraries,
        }
        path = out / "artifacts.json"
        path.write_text(json.dumps(bundle, indent=2, sort_keys=True))
        return path


def convert_offset_to_line_column(
    source: str, start: int, length: int
) -> tuple[list[int], int, int]:
    """Convert a byte-offset span into 1-based (lines, starting_col, ending_col).

    Offsets in solc `src` fields are byte offsets; sources are handled as text
    here (Solidity sources are overwhelmingly ASCII/UTF-8 without exotic
    multi-byte identifiers in practice).
    """
    end = start + max(length, 0)
    start = max(0, min(start, len(source)))
    end = max(start, min(end, len(source)))

    line_starts = [0]
    for idx, ch in enumerate(source):
        if ch == "\n":
            line_starts.append(idx + 1)

    def line_col(pos: int) -> tuple[int, int]:
        # binary search for the line containing pos
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, pos - line_starts[lo] + 1

    start_line, start_col = line_col(start)
    # `end` is exclusive: the ending LINE is that of the last covered char
    # (end-1), while the ending COLUMN is exclusive (points past the span).
    end_line, _ = line_col(max(start, end - 1) if length > 0 else end)
    _, end_col = line_col(end)
    lines = list(range(start_line, end_line + 1))
    return lines, start_col, end_col
