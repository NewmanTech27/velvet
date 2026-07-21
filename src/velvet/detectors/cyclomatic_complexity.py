"""`cyclomatic-complexity` detector (spec/detectors-catalog.md §8.4 —
normative).

Flags functions whose cyclomatic complexity exceeds the documented threshold
(> 11).  High complexity correlates with hidden branches and audit
difficulty; splitting the function into smaller subroutines reduces risk.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.function import Function
from velvet.detectors._batch_f_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

#: Functions above this cyclomatic complexity are reported (catalog §8.4).
CYCLOMATIC_THRESHOLD = 11


class CyclomaticComplexity(Detector):
    """Detect functions with excessive cyclomatic complexity."""

    RULE = "cyclomatic-complexity"
    TITLE = "High cyclomatic complexity"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#cyclomatic-complexity",
        title="High cyclomatic complexity",
        description=(
            "A function's cyclomatic complexity (decision points + 1) exceeds "
            "the threshold of 11. Highly complex functions hide branches and "
            "are hard to audit and test."
        ),
        exploit_scenario=(
            "route() grows into a 12-way dispatch with nested loops and "
            "ternaries; a reviewer misses the one path that skips the "
            "overflow check, which an attacker then drives."
        ),
        recommendation=(
            "Split the function into smaller subroutines; consider dispatch "
            "tables or libraries to flatten the branching."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            if not isinstance(function, Function):
                continue  # report on functions, not modifiers
            complexity = function.cyclomatic_complexity
            if complexity <= CYCLOMATIC_THRESHOLD:
                continue
            results.append(
                self.finding(
                    [
                        function,
                        " has a cyclomatic complexity of ",
                        str(complexity),
                        " (threshold ",
                        str(CYCLOMATIC_THRESHOLD),
                        "); consider splitting it",
                    ],
                    additional_fields={"cyclomatic_complexity": complexity},
                )
            )
        return results
