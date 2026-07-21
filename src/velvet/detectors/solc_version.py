"""`solc-version` detector (spec/detectors-catalog.md §8.13 — normative).

Flags ``pragma solidity`` expressions that permit outdated compiler
versions (below the recommended 0.8.x floor) or overly complex compound
constraints.

Original clean-room implementation.
"""

from __future__ import annotations

import re

from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

_TOKEN_RE = re.compile(r"(>=|<=|\^|~|=|>|<)?\s*(\d+(?:\.\d+){0,2})")

#: Recommended deployment floor (spec/detectors-catalog.md §8.13).
RECOMMENDED_FLOOR = (0, 8, 0)


def _version_tuple(text: str) -> tuple[int, int, int]:
    parts = [int(p) for p in text.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])  # type: ignore[return-value]


class SolcVersion(Detector):
    """Detect pragma constraints allowing outdated/complex solc versions."""

    RULE = "solc-version"
    TITLE = "Pragma allows outdated or unpredictable solc versions"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#solc-version",
        title="Outdated or complex solc version pragma",
        description=(
            "Pragma constraints permitting compiler versions below the "
            "recommended floor miss security fixes; overly complex compound "
            "constraints make the deployed compiler unpredictable."
        ),
        exploit_scenario=(
            "pragma solidity >=0.4.22 <0.9.0 allows ancient, bug-affected "
            "compilers and is needlessly complex."
        ),
        recommendation=(
            "Pin or narrowly constrain to a recent solc (e.g. "
            "pragma solidity 0.8.24;) for deployment."
        ),
    )

    @staticmethod
    def _issues(version_expr: str) -> list[str]:
        """Reasons a pragma expression is problematic (empty when fine)."""
        tokens = _TOKEN_RE.findall(version_expr)
        issues: list[str] = []
        if not tokens:
            return issues
        versions = [_version_tuple(v) for _, v in tokens]
        if min(versions) < RECOMMENDED_FLOOR:
            issues.append(
                f"allows solc versions below the recommended "
                f"{'.'.join(str(p) for p in RECOMMENDED_FLOOR)} floor"
            )
        if len(tokens) > 1:
            issues.append("uses a complex compound version constraint")
        return issues

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen: set[int] = set()
        for pragma in self.compilation_unit.pragmas:
            if pragma.name != "solidity" or id(pragma) in seen:
                continue
            issues = self._issues(pragma.version)
            if issues:
                seen.add(id(pragma))
                results.append(
                    self.finding(
                        [
                            pragma,
                            f" ({'; '.join(issues)}); use a recent pinned solc",
                        ]
                    )
                )
        return results
