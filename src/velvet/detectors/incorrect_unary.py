"""`incorrect-unary` detector (spec/detectors-catalog.md §7.37 — normative).

Flags expressions like ``x =+ 1`` or ``x =- 1``, which parse as assignment
of a unary plus/minus value (``x = (+1)``), not increment/decrement
(``x += 1``).  Almost always a typo that silently replaces instead of
accumulating.

``x = -1`` and ``x =- 1`` are the same AST; only the *token sequence*
distinguishes the typo, so the assignment's source span is checked for the
adjacent ``=+`` / ``=-`` tokens (the AST check pins the shape: ``=`` whose
right operand is a prefix unary ``+``/``-``).

Original clean-room implementation.
"""

from __future__ import annotations

import re
from typing import Optional

from velvet.core.expressions import AssignmentOperation, UnaryOperation
from velvet.detectors._batch_e_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

#: Adjacent ``=+`` / ``=-`` not part of a compound/comparison operator.
_SUSPICIOUS_SEQUENCE_RE = re.compile(r"(?<![=!<>+\-*/%&|^])=[+-]")


def has_suspicious_unary_sequence(text: str) -> Optional[str]:
    """The matched ``=+``/``=-`` token sequence in ``text``, if any."""
    match = _SUSPICIOUS_SEQUENCE_RE.search(text)
    return match.group(0) if match else None


def _unary_assignment(expression: AssignmentOperation) -> bool:
    """True for ``x = <prefix unary +/->`` assignments."""
    if expression.operator != "=":
        return False
    right = expression.expression_right
    return (
        isinstance(right, UnaryOperation)
        and right.is_prefix
        and right.operator in ("+", "-")
    )


class IncorrectUnary(Detector):
    """Detect =+ / =- typos (assignment instead of += / -=)."""

    RULE = "incorrect-unary"
    TITLE = "Suspicious =+ / =- unary expression"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#incorrect-unary",
        title="Unary expression typo (=+ / =-)",
        description=(
            "An assignment whose right-hand side is a unary +/- expression "
            "forms the suspicious =+ / =- token sequence: x =+ 1 parses as "
            "x = (+1), replacing the value instead of accumulating."
        ),
        exploit_scenario=(
            "Tally.addOne() runs count =+ 1 intending count += 1; every "
            "call resets the counter to 1, silently corrupting the tally."
        ),
        recommendation="Replace with the compound assignment (+= / -=).",
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            for node in function.nodes:
                expression = node.expression
                if expression is None:
                    continue
                for candidate in expression.walk():
                    if not (
                        isinstance(candidate, AssignmentOperation)
                        and _unary_assignment(candidate)
                    ):
                        continue
                    content = candidate.source_mapping.content or ""
                    sequence = has_suspicious_unary_sequence(content)
                    if sequence is None:
                        # Spaced form (`x = -1`) or no source span: the AST
                        # shape alone is a legitimate assignment.
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                f" uses {sequence} in ",
                                function,
                                "; it parses as an assignment of a unary "
                                "value, not a compound assignment (+= / -=)",
                            ]
                        )
                    )
        return results
