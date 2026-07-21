"""`tautological-compare` detector (spec/detectors-catalog.md §7.18 —
normative).

Flags comparisons whose two operands are syntactically identical
(``x == x``, ``amount <= amount``, ``a + b == a + b``).  The result is a
compile-time constant — ``==``/``>=``/``<=`` always true, ``!=``/``<``/``>``
always false — which almost always indicates a copy-paste or refactoring
bug.  Operands are compared structurally through their definition chains;
expressions with possible side effects (calls, dereferences) are not
considered identical.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_e_utils import (
    defining_ops,
    expression_key,
    unique_functions,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import Binary

_COMPARISONS = ("==", "!=", "<", ">", "<=", ">=")


class TautologicalCompare(Detector):
    """Detect comparisons with syntactically identical operands."""

    RULE = "tautological-compare"
    TITLE = "Comparison of identical expressions"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#tautological-compare",
        title="Tautological comparison",
        description=(
            "A comparison whose two operands are the same expression "
            "(x == x, x < x, ...); the result is a compile-time constant, "
            "which almost always indicates a copy-paste or refactoring bug."
        ),
        exploit_scenario=(
            "valid(amount, cap) returns amount <= amount — always true; "
            "the cap check the author meant to write never rejects "
            "anything."
        ),
        recommendation=(
            "Compare against the intended distinct operand, or remove the "
            "dead check."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            defs = defining_ops(function)
            for node in function.nodes:
                for op in node.ir_operations:
                    if not (isinstance(op, Binary) and op.operator in _COMPARISONS):
                        continue
                    left = expression_key(op.left, defs)
                    right = expression_key(op.right, defs)
                    if left is None or right is None or left != right:
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                f" compares an expression with itself "
                                f"({op.operator}) in ",
                                function,
                                "; the result is a compile-time constant",
                            ]
                        )
                    )
        return results
