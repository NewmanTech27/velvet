"""Console rendering of findings (spec/architecture.md §10.1).

Human-readable, colorized by impact (red = high, yellow = medium,
green = low/informational/optimization), one finding per block with
nested source locations rendered ``file.sol#Lstart-Lend`` (line prefix
configurable via ``change_line_prefix``).  ``--disable-color`` strips
all ANSI codes for CI logs.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.detectors.base import Finding, Impact, element_name

_COLORS = {
    Impact.HIGH: "\033[91m",  # bright red
    Impact.MEDIUM: "\033[93m",  # yellow
    Impact.LOW: "\033[92m",  # green
    Impact.INFORMATIONAL: "\033[92m",
    Impact.OPTIMIZATION: "\033[92m",
}
_BOLD = "\033[1m"
_RESET = "\033[0m"


def render_source_ref(element: Any, line_prefix: str = "#") -> str:
    """``file.sol#Lstart-Lend`` for one element (empty when unmapped)."""
    source_mapping = getattr(element, "source_mapping", None)
    if source_mapping is None or source_mapping.filename is None:
        return ""
    filename = source_mapping.filename.relative
    lines = source_mapping.lines
    if not lines:
        return filename
    if len(lines) > 1:
        return f"{filename}{line_prefix}L{lines[0]}-L{lines[-1]}"
    return f"{filename}{line_prefix}L{lines[0]}"


def render_finding_console(
    finding: Finding, *, disable_color: bool = False, line_prefix: str = "#"
) -> str:
    """Render one finding as a console block."""
    color = "" if disable_color else _COLORS.get(finding.impact, "")
    bold = "" if disable_color else _BOLD
    reset = "" if disable_color else _RESET
    header = f"{bold}{finding.check}{reset} ({finding.impact.value}/{finding.confidence.value})"
    if getattr(finding, "hidden", False):  # triage-hidden, --show-ignored-findings
        header += " [hidden by triage]"
    lines = [f"{color}{header}: {finding.description}{reset}"]
    for element in finding.elements:
        if isinstance(element, str):
            continue
        ref = render_source_ref(element, line_prefix)
        if ref:
            lines.append(f"    {element_name(element)} ({ref})")
    return "\n".join(lines)


def render_findings_console(
    findings: list[Finding], *, disable_color: bool = False, line_prefix: str = "#"
) -> str:
    """Render all findings; empty string when there are none."""
    blocks = [
        render_finding_console(f, disable_color=disable_color, line_prefix=line_prefix)
        for f in findings
    ]
    return "\n".join(blocks)
