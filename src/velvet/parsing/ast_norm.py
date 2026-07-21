"""AST normalization and src-span decoding.

solc's compact AST (>= 0.8) uses `nodeType`; older legacy ASTs use
`name`/`children`. We normalize onto the compact dialect and reject legacy
trees cleanly (spec robustness requirement: degrade, don't crash).

Original clean-room implementation.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from velvet.compile.artifacts import (
    CompilationArtifacts,
    convert_offset_to_line_column,
)
from velvet.core.source_mapping import SourceRange
from velvet.exceptions import ParsingError

_SRC_RE = re.compile(r"^(-?\d+):(-?\d+):(-?\d+)$")


def is_compact_ast(ast: dict[str, Any]) -> bool:
    return "nodeType" in ast


def normalize_ast(ast: dict[str, Any]) -> dict[str, Any]:
    """Return the AST in compact dialect or raise ParsingError."""
    if is_compact_ast(ast):
        return ast
    if "name" in ast and "children" in ast:
        raise ParsingError(
            "Legacy solc AST format detected (pre-0.5 style). "
            "Velvet requires the compact AST; compile with solc >= 0.5 "
            "or provide standard-JSON output."
        )
    raise ParsingError("Unrecognized AST document (missing nodeType).")


def parse_src(src: str) -> tuple[int, int, int]:
    """Decode a solc `src` string 'offset:length:sourceId'."""
    match = _SRC_RE.match(src or "")
    if not match:
        return -1, -1, -1
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def source_range_for(
    artifacts: CompilationArtifacts, src: str
) -> Optional[SourceRange]:
    """Build a SourceRange from a solc src span against the artifacts."""
    start, length, source_id = parse_src(src)
    if start < 0 or length < 0 or source_id < 0:
        return None
    info = artifacts.source_units.get(source_id)
    if info is None:
        return None
    lines, scol, ecol = convert_offset_to_line_column(info.source, start, length)
    return SourceRange(
        start=start,
        length=length,
        filename=info.filename,
        lines=lines,
        starting_column=scol,
        ending_column=ecol,
        content=info.source[start : start + length],
    )


def attach_source(obj: Any, artifacts: CompilationArtifacts, src: str) -> None:
    """Attach a SourceRange to a SourceMapping model object (best effort)."""
    sr = source_range_for(artifacts, src)
    if sr is not None and hasattr(obj, "set_source_mapping"):
        obj.set_source_mapping(sr)


def children_of(node: dict[str, Any]) -> list[dict[str, Any]]:
    """Child nodes of a compact-AST node (the `nodes` member)."""
    return node.get("nodes", []) or []
