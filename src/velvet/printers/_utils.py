"""Shared helpers for the v1 printer batch (tables, dot text, paths).

Original clean-room implementation (spec/printers-and-tools.md §A).
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

# ------------------------------------------------------------------ tables


def render_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Render an ASCII pretty table (``+---+`` grid style).

    Cell values are stringified; embedded newlines produce multi-line cells.
    """
    str_rows = [[str(cell) for cell in row] for row in rows]
    str_headers = [str(h) for h in headers]
    ncols = len(str_headers)
    widths = [len(h) for h in str_headers]
    for row in str_rows:
        for i in range(ncols):
            cell = row[i] if i < len(row) else ""
            for line in cell.split("\n"):
                widths[i] = max(widths[i], len(line))

    def border() -> str:
        return "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def render_row(cells: Sequence[str]) -> list[str]:
        split = [
            (cells[i] if i < len(cells) else "").split("\n") for i in range(ncols)
        ]
        height = max(len(s) for s in split)
        lines = []
        for n in range(height):
            parts = []
            for i in range(ncols):
                text = split[i][n] if n < len(split[i]) else ""
                parts.append(f" {text:<{widths[i]}} ")
            lines.append("|" + "|".join(parts) + "|")
        return lines

    out = [border()]
    out.extend(render_row(str_headers))
    out.append(border())
    for row in str_rows:
        out.extend(render_row(row))
    out.append(border())
    return "\n".join(out)


# --------------------------------------------------------------------- dot


def dot_quote(text: Any) -> str:
    """Escape a string for use inside a double-quoted dot token."""
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def html_escape(text: Any) -> str:
    """Escape a string for use inside an HTML-like dot label."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def sanitize_filename(name: str) -> str:
    """Keep a conservative filename alphabet; replace the rest with ``_``."""
    return "".join(ch if (ch.isalnum() or ch in "._-") else "_" for ch in name)


# ------------------------------------------------------------------ naming


def function_label(function: Any) -> str:
    """Display name for a function node: constructors stay ``constructor``."""
    if getattr(function, "is_constructor", False):
        return "constructor"
    return function.signature


def value_name(value: Any) -> str:
    """Best-effort surface name for an IR value / call destination."""
    name = getattr(value, "name", None)
    if isinstance(name, str) and name:
        return name
    return str(value)


# -------------------------------------------------------------------- paths

_TEST_DIR_NAMES = {"test", "tests"}


def is_test_path(path: str) -> bool:
    """Heuristic: a file living under a test directory or a ``*.t.sol`` file."""
    norm = path.replace("\\", "/")
    parts = [p for p in norm.split("/") if p]
    if any(part.lower() in _TEST_DIR_NAMES for part in parts[:-1]):
        return True
    base = parts[-1].lower() if parts else ""
    return base.endswith(".t.sol")


def unique_preserve_order(values: Iterable[Any]) -> list[Any]:
    result: list[Any] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
