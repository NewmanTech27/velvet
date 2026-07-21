"""Source mapping — every model object knows where it was defined.

Original clean-room implementation (spec/architecture.md §4, §10.2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from velvet.compile.artifacts import Filename


@dataclass
class SourceRange:
    """A span of source code (byte offsets + 1-based lines/columns)."""

    start: int = 0
    length: int = 0
    filename: Optional[Filename] = None
    lines: list[int] = field(default_factory=list)
    starting_column: int = 0
    ending_column: int = 0
    content: str = ""

    def to_dict(self) -> dict[str, Any]:
        """JSON schema per spec/architecture.md §10.2."""
        return {
            "start": self.start,
            "length": self.length,
            "filename_relative": self.filename.relative if self.filename else "",
            "filename_absolute": self.filename.absolute if self.filename else "",
            "filename_short": self.filename.short if self.filename else "",
            "filename_used": self.filename.used if self.filename else "",
            "lines": self.lines,
            "starting_column": self.starting_column,
            "ending_column": self.ending_column,
        }

    def __str__(self) -> str:
        if not self.filename:
            return "<unknown>"
        if len(self.lines) > 1:
            return f"{self.filename.relative}#L{self.lines[0]}-L{self.lines[-1]}"
        if self.lines:
            return f"{self.filename.relative}#L{self.lines[0]}"
        return self.filename.relative


class SourceMapping:
    """Mixin: objects attached to a SourceRange."""

    def __init__(self) -> None:
        self._source_mapping = SourceRange()

    @property
    def source_mapping(self) -> SourceRange:
        return self._source_mapping

    def set_source_mapping(self, source_range: SourceRange) -> None:
        self._source_mapping = source_range
