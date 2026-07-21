"""Filtering, suppression, and exit policy (spec/architecture.md §11).

Framework responsibilities (detectors never see suppressed findings):

- detector selection is handled by the CLI/session registries;
- **path filters** — ``--filter-paths`` drops findings whose locations are
  entirely under matching paths (substring or regex); ``--include-paths``
  inverts it;
- **dependency exclusion** — drops findings located only in dependencies;
- **inline suppressions** parsed from source text:
  ``// velvet-disable-next-line <rule>`` and
  ``// velvet-disable-start [rule]`` / ``// velvet-disable-end [rule]``
  regions;
- **fail-on policy** — ``pedantic|low|medium|high|none`` exit evaluation.

Original clean-room implementation.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from velvet.compile.artifacts import is_dependency_path
from velvet.detectors.base import Finding, Impact

if TYPE_CHECKING:
    from velvet.session import Velvet

logger = logging.getLogger("velvet.filtering")

# ------------------------------------------------------------ suppressions
_NEXT_LINE_RE = re.compile(r"velvet-disable-next-line(?:\s+([\w-]+))?")
_START_RE = re.compile(r"velvet-disable-start(?:\s+([\w-]+))?")
_END_RE = re.compile(r"velvet-disable-end(?:\s+([\w-]+))?")


@dataclass
class Suppressions:
    """Suppression records for one source file."""

    next_line_rules: dict[int, set[Optional[str]]] = field(default_factory=dict)
    # (start_line, end_line_exclusive, rule or None for "all rules")
    regions: list[tuple[int, int, Optional[str]]] = field(default_factory=list)

    def is_suppressed(self, rule: str, line: int) -> bool:
        for target_line, rules in self.next_line_rules.items():
            if line == target_line and (rule in rules or None in rules):
                return True
        for start, end, region_rule in self.regions:
            if start <= line < end and (region_rule is None or region_rule == rule):
                return True
        return False


def parse_suppressions(source: str) -> Suppressions:
    """Parse velvet suppression comments from one file's source text."""
    result = Suppressions()
    open_regions: list[tuple[int, Optional[str]]] = []
    for number, line in enumerate(source.splitlines(), start=1):
        match = _NEXT_LINE_RE.search(line)
        if match:
            result.next_line_rules.setdefault(number + 1, set()).add(match.group(1))
        match = _START_RE.search(line)
        if match:
            open_regions.append((number, match.group(1)))
            continue
        match = _END_RE.search(line)
        if match:
            rule = match.group(1)
            # close the most recent open region matching the rule
            for index in range(len(open_regions) - 1, -1, -1):
                start, start_rule = open_regions[index]
                if rule is None or start_rule is None or start_rule == rule:
                    result.regions.append((start, number, start_rule))
                    del open_regions[index]
                    break
    # unterminated regions extend to end of file (end is exclusive)
    last_line = len(source.splitlines()) + 1
    for start, rule in open_regions:
        result.regions.append((start, last_line, rule))
    return result


def _session_suppressions(session: Velvet) -> dict[str, Suppressions]:
    cache = getattr(session, "_suppressions_cache", None)
    if cache is None:
        cache = {}
        for unit in session.compilation_units:
            for info in unit.compilation.source_units.values():
                if info.filename.absolute not in cache:
                    cache[info.filename.absolute] = parse_suppressions(info.source)
        session._suppressions_cache = cache  # type: ignore[attr-defined]
    return cache


def _suppressed_by_comment(session: Velvet, finding: Finding) -> bool:
    """True when the finding's primary element sits on a suppressed line."""
    primary = finding.primary_element
    source_mapping = getattr(primary, "source_mapping", None)
    if source_mapping is None or source_mapping.filename is None:
        return False
    if not source_mapping.lines:
        return False
    suppressions = _session_suppressions(session).get(source_mapping.filename.absolute)
    if suppressions is None:
        return False
    return any(
        suppressions.is_suppressed(finding.check, line)
        for line in source_mapping.lines
    )


# ------------------------------------------------------------ path filters
def _matches_pattern(path: str, pattern: str) -> bool:
    """Substring match first; regex match as a fallback."""
    if pattern in path:
        return True
    try:
        return re.search(pattern, path) is not None
    except re.error:
        return False


def _finding_paths(finding: Finding) -> list[str]:
    paths: list[str] = []
    for element in finding.elements:
        source_mapping = getattr(element, "source_mapping", None)
        if source_mapping is not None and source_mapping.filename is not None:
            paths.append(source_mapping.filename.absolute)
    return paths


def _passes_path_filters(session: Velvet, finding: Finding) -> bool:
    paths = _finding_paths(finding)
    if not paths:
        # No locations: keep unless include_paths demands a location match.
        return not session.include_paths
    if session.filter_paths:
        if all(
            any(_matches_pattern(p, pat) for pat in session.filter_paths)
            for p in paths
        ):
            return False  # entirely under filtered paths
    if session.include_paths:
        if not any(
            _matches_pattern(p, pat) for p in paths for pat in session.include_paths
        ):
            return False
    return True


def _passes_dependency_filter(session: Velvet, finding: Finding) -> bool:
    if not session.exclude_dependencies:
        return True
    paths = _finding_paths(finding)
    if not paths:
        return True
    # drop findings located *only* in dependency paths
    return not all(is_dependency_path(p) for p in paths)


def result_in_scope(session: Velvet, finding: Finding) -> bool:
    """All framework filters for one finding (architecture.md §11)."""
    if not _passes_path_filters(session, finding):
        return False
    if not _passes_dependency_filter(session, finding):
        return False
    if _suppressed_by_comment(session, finding):
        return False
    return True


# ------------------------------------------------------------- fail policy
_FAIL_ON_ORDER = {
    "pedantic": None,  # any finding
    "low": {Impact.LOW, Impact.MEDIUM, Impact.HIGH},
    "medium": {Impact.MEDIUM, Impact.HIGH},
    "high": {Impact.HIGH},
    "none": set(),
}


def should_fail(findings: list[Finding], fail_on: str) -> bool:
    """Evaluate the ``--fail-on`` exit policy against surviving findings."""
    if fail_on not in _FAIL_ON_ORDER:
        raise ValueError(
            f"Invalid fail-on value {fail_on!r}; expected one of "
            f"{', '.join(sorted(_FAIL_ON_ORDER))}"
        )
    threshold = _FAIL_ON_ORDER[fail_on]
    if threshold is None:
        return bool(findings)
    return any(f.impact in threshold for f in findings)
