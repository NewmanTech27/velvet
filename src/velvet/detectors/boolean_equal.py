"""`boolean-equal` detector (spec/detectors-catalog.md §8.3 — normative).

Flags comparisons of a boolean expression to a boolean literal
(``if (flag == true)``, ``require(ok == false)``).  Comparing against a
boolean literal is redundant noise that hurts readability; the expression
(``flag`` / ``!flag``) reads directly.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Optional

from velvet.core.expressions import BinaryOperation, Literal
from velvet.detectors._batch_f_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

_EQUALITY_OPS = ("==", "!=")
_BOOL_LITERALS = ("true", "false")


def _is_bool_literal(expression: Any) -> bool:
    return isinstance(expression, Literal) and str(expression.value).lower() in (
        _BOOL_LITERALS
    )


def _is_bool_typed(expression: Any) -> bool:
    type_ = getattr(expression, "type", None)
    return type_ is not None and str(type_).split()[0] == "bool"


class BooleanEqual(Detector):
    """Detect equality comparisons against a boolean literal."""

    RULE = "boolean-equal"
    TITLE = "Boolean compared to a boolean literal"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#boolean-equal",
        title="Boolean compared to a boolean literal",
        description=(
            "A boolean expression is compared to a boolean literal "
            "(flag == true, ok == false). The comparison is redundant noise; "
            "the expression (flag / !flag) reads directly."
        ),
        exploit_scenario=(
            "open() returns locked == false; a later refactor flips the "
            "literal during an edit and the guard silently inverts because "
            "the redundant form hid the intent."
        ),
        recommendation=(
            "Use the boolean expression directly (flag or !flag) instead of "
            "comparing against true/false."
        ),
    )

    @staticmethod
    def _offending_operand(expression: BinaryOperation) -> Optional[Any]:
        """The non-literal boolean operand of a bool-literal comparison."""
        left, right = expression.expression_left, expression.expression_right
        if _is_bool_literal(left) and _is_bool_typed(right):
            return right
        if _is_bool_literal(right) and _is_bool_typed(left):
            return left
        return None

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen: set[int] = set()
        for function in unique_functions(self.compilation_unit):
            for expression in function.all_expressions:
                for node in expression.walk():
                    if id(node) in seen:
                        continue
                    if not (
                        isinstance(node, BinaryOperation)
                        and node.operator in _EQUALITY_OPS
                    ):
                        continue
                    operand = self._offending_operand(node)
                    if operand is None:
                        continue
                    seen.add(id(node))
                    results.append(
                        self.finding(
                            [
                                node,
                                " compares a boolean to a boolean literal in ",
                                function,
                                "; use the boolean expression directly",
                            ]
                        )
                    )
        return results
