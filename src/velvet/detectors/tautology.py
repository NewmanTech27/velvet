"""`tautology` detector (spec/detectors-catalog.md §7.19 — normative).

Flags comparisons whose outcome is fixed by the operand's type range:
``uint x >= 0`` (always true), ``uint8 y < 512`` (always true),
``int8 z > 200`` (always false).  Vacuous conditions are dead logic and
usually hide an intent bug (wrong constant or wrong type).  Constants are
resolved through a small folder, so computed bounds such as ``2**255``
are evaluated as well.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Optional

from velvet.core.types import ElementaryType
from velvet.core.variables import Variable
from velvet.detectors._batch_e_utils import (
    constant_value,
    defining_ops,
    integer_range,
    unique_functions,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import Binary, Operation

_ORDER_OPS = ("<", "<=", ">", ">=")
_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}


def _operand_range(variable: Any) -> Optional[tuple[int, int]]:
    """Type range of a compared operand (elementary integer types only)."""
    if not isinstance(variable, Variable):
        return None
    var_type = getattr(variable, "type", None)
    if not isinstance(var_type, ElementaryType):
        return None
    return integer_range(var_type)


def _fixed_outcome(operator: str, lo: int, hi: int, const: int) -> Optional[bool]:
    """True/False when ``x <op> const`` is constant for all x in [lo, hi]."""
    if operator == "<":
        if hi < const:
            return True
        if lo >= const:
            return False
    elif operator == "<=":
        if hi <= const:
            return True
        if lo > const:
            return False
    elif operator == ">":
        if lo > const:
            return True
        if hi <= const:
            return False
    elif operator == ">=":
        if lo >= const:
            return True
        if hi < const:
            return False
    elif operator == "==":
        if const < lo or const > hi:
            return False
    elif operator == "!=":
        if const < lo or const > hi:
            return True
    return None


class Tautology(Detector):
    """Detect comparisons fixed by the operand's type range."""

    RULE = "tautology"
    TITLE = "Comparison is a tautology or contradiction by type range"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#tautology",
        title="Tautology or contradiction in comparison",
        description=(
            "A comparison between an integer expression and a constant is "
            "always true or always false given the type's value range "
            "(e.g. uint256 >= 0, uint8 < 512); the check is dead logic."
        ),
        exploit_scenario=(
            "require(bid >= 0) is meant to reject bad bids but passes for "
            "every uint256; the intended minimum-bid check never runs."
        ),
        recommendation=(
            "Fix the comparison (change the type or the constant); delete "
            "vacuous checks."
        ),
    )

    def _check(self, op: Binary, defs: dict[int, Operation]) -> Optional[bool]:
        """Constant outcome of the comparison, if provable."""
        if op.operator not in _ORDER_OPS + ("==", "!="):
            return None
        left_const = constant_value(op.left, defs)
        right_const = constant_value(op.right, defs)
        # Exactly one side must be constant; both-constant is solc's job.
        if (left_const is None) == (right_const is None):
            return None
        if isinstance(left_const, bool) or isinstance(right_const, bool):
            return None
        if right_const is not None:
            variable, const, operator = op.left, right_const, op.operator
        else:
            variable, const, operator = op.right, left_const, _FLIP[op.operator]
        value_range = _operand_range(variable)
        if value_range is None:
            return None
        lo, hi = value_range
        return _fixed_outcome(operator, lo, hi, const)

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            defs = defining_ops(function)
            for node in function.nodes:
                for op in node.ir_operations:
                    if not isinstance(op, Binary):
                        continue
                    outcome = self._check(op, defs)
                    if outcome is None:
                        continue
                    verdict = "always true" if outcome else "always false"
                    results.append(
                        self.finding(
                            [
                                node,
                                f" is {verdict} for every value of the "
                                "operand's type in ",
                                function,
                                "; the comparison is dead logic",
                            ]
                        )
                    )
        return results
