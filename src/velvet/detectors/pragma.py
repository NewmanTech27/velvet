"""`pragma` detector (spec/detectors-catalog.md §8.11 — normative).

Flags inconsistent ``pragma solidity`` version expressions across the
compilation unit's source files.  The catalog's detection condition is a
property of the whole compilation unit, so a mixed-pragma unit yields a
single finding (not one per file); per-file version spread *between*
compilation units of a multi-solc project is normal and does not fire.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class Pragma(Detector):
    """Detect inconsistent solidity pragmas across source files."""

    RULE = "pragma"
    TITLE = "Inconsistent pragma versions across source files"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#pragma",
        title="Inconsistent pragma directives",
        description=(
            "Different pragma solidity version constraints across the "
            "project's source files make the effective compiler set "
            "ambiguous and complicate builds and audits."
        ),
        exploit_scenario=(
            "File A requires ^0.8.0 while file B allows >=0.7.0 <0.9.0; "
            "the project accidentally compiles with an unintended version."
        ),
        recommendation=(
            "Standardize on a single pragma version (or a single "
            "consistent constraint) across all files."
        ),
    )

    def analyze(self) -> list[Finding]:
        pragmas = [p for p in self.compilation_unit.pragmas if p.name == "solidity"]
        distinct = sorted({p.version for p in pragmas})
        if len(distinct) <= 1:
            return []
        # The catalog's detection condition is per compilation unit ("more
        # than one distinct pragma solidity version expression across the
        # compilation unit's source files"), so the inconsistency is a
        # single finding — not one per file.  Elements after the first are
        # the conflicting directives, so patches can unify every one of them
        # to the anchor version.
        anchor = pragmas[0]
        others = [p for p in pragmas if p is not anchor and p.version != anchor.version]
        elements: list = [
            anchor,
            f" is inconsistent with {len(distinct) - 1} other pragma solidity "
            f"version expression(s) used across the compilation unit's source "
            f"files (distinct: {', '.join(distinct)}); conflicting directives follow",
        ]
        elements.extend(others)
        return [self.finding(elements)]
