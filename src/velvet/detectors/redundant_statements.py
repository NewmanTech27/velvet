"""`redundant-statements` detector (spec/detectors-catalog.md §8.12 —
normative).

Flags expression statements with no side effects — a bare type name,
identifier or literal on its own line, or a pure expression whose value
has no consumer.  They compile to nothing and usually indicate
unfinished code.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.cfg_node import NodeKind
from velvet.detectors._batch_e_utils import unique_functions
from velvet.detectors._batch_h_utils import expression_has_side_effect
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class RedundantStatements(Detector):
    """Detect expression statements with no side effects."""

    RULE = "redundant-statements"
    TITLE = "Statement has no effect"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#redundant-statements",
        title="Statement has no effect",
        description=(
            "A statement consisting solely of an elementary type name, an "
            "identifier reference, a literal, or a pure expression with no "
            "side effects and no value consumer; it compiles to nothing "
            "and usually indicates unfinished code."
        ),
        exploit_scenario=(
            "Draft.f() contains the lines `uint256;` and `Draft;`: the "
            "author presumably meant to declare or initialize something "
            "but the statements are silently dropped by the compiler."
        ),
        recommendation=(
            "Remove the dead statements, or complete the intended "
            "expression."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            for node in function.nodes:
                if node.kind is not NodeKind.EXPRESSION:
                    continue
                expression = node.expression
                if expression is None:
                    continue
                if expression_has_side_effect(expression):
                    continue
                results.append(
                    self.finding(
                        [
                            node,
                            " is a statement with no side effects in ",
                            function,
                            "; it compiles to nothing",
                        ]
                    )
                )
        return results
