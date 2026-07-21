"""Detector documentation wiki generation (spec/architecture.md §10.4,
spec/api-surface.md §7.2 ``--wiki``).

``--wiki DIR`` renders one Markdown page per registered detector from its
``DOCS`` block (title, impact/confidence, description, exploit scenario,
recommendation, and an example section when a detector carries one), plus an
``index.md`` grouping the detectors by impact as a numbered table (the
README detector-table style: ``#`` / check link / title / confidence).

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from velvet.detectors.base import Detector, Impact

#: Index page file name inside the wiki directory.
INDEX_PAGE = "index.md"

#: Impact groups in rendering order (most severe first).
_IMPACT_SECTIONS = (
    Impact.HIGH,
    Impact.MEDIUM,
    Impact.LOW,
    Impact.INFORMATIONAL,
    Impact.OPTIMIZATION,
)


def page_filename(rule: str) -> str:
    """Markdown page name for a detector rule."""
    return f"{rule}.md"


def render_detector_page(detector_class: type[Detector]) -> str:
    """Render one detector's documentation page from its DOCS block."""
    docs = detector_class.DOCS
    lines = [f"# {docs.title or detector_class.TITLE}", ""]
    lines.append("| | |")
    lines.append("| --- | --- |")
    lines.append(f"| **Rule** | `{detector_class.RULE}` |")
    lines.append(f"| **Impact** | {detector_class.IMPACT.value} |")
    lines.append(f"| **Confidence** | {detector_class.CONFIDENCE.value} |")
    if docs.url:
        lines.append(f"| **Reference** | <{docs.url}> |")
    lines.append("")

    lines.append("## Description")
    lines.append("")
    lines.append(docs.description or detector_class.TITLE)
    lines.append("")

    if docs.exploit_scenario:
        lines.append("## Exploit scenario")
        lines.append("")
        lines.append(docs.exploit_scenario)
        lines.append("")

    lines.append("## Recommendation")
    lines.append("")
    lines.append(docs.recommendation or "See the description above.")
    lines.append("")

    example = getattr(docs, "example", "")  # optional DOCS extension
    if example:
        lines.append("## Example")
        lines.append("")
        lines.append(str(example))
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"


def render_index(detector_classes: list[type[Detector]]) -> str:
    """Render the index page: detectors grouped by impact (README style)."""
    lines = ["# velvet detector documentation", ""]
    lines.append(f"{len(detector_classes)} detectors documented.")
    lines.append("")
    number = 0
    for impact in _IMPACT_SECTIONS:
        group = sorted(
            (d for d in detector_classes if d.IMPACT == impact),
            key=lambda d: d.RULE,
        )
        if not group:
            continue
        lines.append(f"## {impact.value}")
        lines.append("")
        lines.append("| # | Check | Title | Confidence |")
        lines.append("| --- | --- | --- | --- |")
        for detector_class in group:
            page = page_filename(detector_class.RULE)
            lines.append(
                f"| {number} | [{detector_class.RULE}]({page}) "
                f"| {detector_class.TITLE} | {detector_class.CONFIDENCE.value} |"
            )
            number += 1
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def write_wiki(detector_classes: list[type[Detector]], directory: Any) -> list[Path]:
    """Write the wiki pages + index into ``directory``; returns written paths."""
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for detector_class in sorted(detector_classes, key=lambda d: d.RULE):
        page = out_dir / page_filename(detector_class.RULE)
        page.write_text(render_detector_page(detector_class))
        written.append(page)
    index = out_dir / INDEX_PAGE
    index.write_text(render_index(detector_classes))
    written.append(index)
    return written
