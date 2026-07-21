"""Markdown checklist report (spec/architecture.md §10.4,
spec/printers-and-tools.md §C.4.4).

``--checklist`` prints a Markdown report to stdout: a summary table
(rule, count, impact) followed by one section per rule with ``- [ ]``
checkbox items (``- [ ] <rule>-<n>``) carrying a short description and a
linked source location.  ``--markdown-root <url>`` prefixes the locations
with a repository URL, normalized to ``.../blob/<ref>/`` form so links
resolve on GitHub; ``--checklist-limit N`` truncates the per-rule items.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Optional

from velvet.detectors.base import Finding


def normalize_markdown_root(root: Optional[str]) -> str:
    """Normalize a repository URL to the ``.../blob/<ref>/`` link-prefix form.

    - ``""``/``None`` stays empty (links are then relative);
    - an URL already containing ``/blob/`` is kept (trailing slash ensured);
    - ``.../tree/<ref>`` is rewritten to ``.../blob/<ref>/``;
    - a bare repository root gets ``/blob/HEAD/`` appended.
    """
    root = (root or "").strip().rstrip("/")
    if not root:
        return ""
    if "/blob/" in root:
        return f"{root}/"
    if "/tree/" in root:
        base, _, ref = root.partition("/tree/")
        return f"{base}/blob/{ref}/"
    return f"{root}/blob/HEAD/"


def _primary_location_ref(finding: Finding) -> Optional[str]:
    """``file.sol#Lstart[-Lend]`` ref of the finding's primary element."""
    element = finding.primary_element
    source_mapping = getattr(element, "source_mapping", None)
    if source_mapping is None or source_mapping.filename is None:
        return None
    ref = source_mapping.filename.relative
    lines = source_mapping.lines
    if lines:
        ref += f"#L{lines[0]}"
        if len(lines) > 1:
            ref += f"-L{lines[-1]}"
    return ref


def render_checklist(
    findings: list[Finding],
    *,
    markdown_root: Optional[str] = "",
    limit: Optional[int] = None,
) -> str:
    """Render the Markdown checklist report for the (surviving) findings."""
    root = normalize_markdown_root(markdown_root)
    if limit is not None:
        limit = max(int(limit), 0)
    lines = ["# velvet checklist", ""]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    # group by rule, preserving the impact-sorted finding order
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.check, []).append(finding)

    # summary table (rule, count, impact)
    lines.append("| Rule | Count | Impact |")
    lines.append("| --- | --- | --- |")
    for check, group in grouped.items():
        lines.append(f"| {check} | {len(group)} | {group[0].impact.value} |")
    lines.append("")

    # per-rule checkbox items with linked source locations
    for check, group in grouped.items():
        lines.append(f"## {check}")
        lines.append("")
        shown = group if limit is None else group[:limit]
        for index, finding in enumerate(shown, start=1):
            item = f"- [ ] {check}-{index}: {finding.description}"
            ref = _primary_location_ref(finding)
            if ref is not None:
                item += f" ([{ref}]({root}{ref}))"
            lines.append(item)
        truncated = len(group) - len(shown)
        if truncated > 0:
            lines.append(
                f"- ... and {truncated} more {check} finding(s) "
                "(truncated by --checklist-limit)"
            )
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"
