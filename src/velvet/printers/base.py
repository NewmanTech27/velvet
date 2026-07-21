"""Printer framework contract (spec/api-surface.md §6, architecture.md §9).

A printer is a read-only plugin: it reports/visualizes model information,
emits no findings, writes text through the provided console sink and/or
emits files (e.g. Graphviz dot).  Printers run only when requested.

Original clean-room implementation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from velvet.core.compilation_unit import CompilationUnit

logger = logging.getLogger("velvet.printers")


class Printer:
    """Base class for printers.

    Subclasses define ``RULE`` (CLI name for ``--print <id>``) and
    ``TITLE`` (help text), and override :meth:`output`.  One instance is
    created per compilation unit.
    """

    RULE: str = ""
    TITLE: str = ""

    def __init__(self, compilation_unit: CompilationUnit, session: Any) -> None:
        self.compilation_unit = compilation_unit
        self.session = session
        self.logger = logging.getLogger(f"velvet.printers.{self.RULE or 'printer'}")
        if not self.RULE:
            raise ValueError(f"{type(self).__name__} must define RULE")

    # ------------------------------------------------------------- contract
    def output(self) -> None:
        """Produce the printer's output; must be overridden."""
        raise NotImplementedError

    # ---------------------------------------------------------------- sinks
    def info(self, *args: Any) -> None:
        """Console sink: forward text to the session's output."""
        text = " ".join(str(a) for a in args)
        sink = getattr(self.session, "printer_output_sink", None)
        if callable(sink):
            sink(text)
        else:
            print(text)

    def emit_file(
        self, filename: str, content: str, *, export_dir: Optional[str] = None
    ) -> Path:
        """Write an output file (dot graphs, exports) and return its path."""
        base = Path(export_dir or getattr(self.session, "export_dir", "."))
        base.mkdir(parents=True, exist_ok=True)
        path = base / filename
        path.write_text(content)
        self.logger.info("Wrote %s", path)
        return path

    def __str__(self) -> str:
        return self.RULE

    def __repr__(self) -> str:
        return f"{type(self).__name__}(rule={self.RULE!r})"
