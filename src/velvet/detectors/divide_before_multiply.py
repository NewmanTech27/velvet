"""`divide-before-multiply` detector (spec/detectors-catalog.md §7.22 —
normative).

Flags arithmetic that divides before multiplying: EVM integer division
truncates toward zero, so ``(a / b) * c`` loses precision that
``a * c / b`` would keep; when ``a < b`` the intermediate result is 0 and
the whole expression collapses.  The def-chain chase follows intermediate
variables and divisions performed in inline assembly (``x := div(a, b)``).

The round-down-to-a-multiple idiom ``(x / y) * y`` is recognized as
intentional truncation and is not reported; the exclusion applies only
when the product itself is the consumed value — a product that feeds
further arithmetic (``gcd - remainder * quotient``) loses precision
inside a larger computation and is reported.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.core.function import FunctionLike
from velvet.core.variables import Constant
from velvet.detectors._batch_b_utils import def_chain, defining_ops
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import Binary, Operation

_ARITHMETIC_OPERATORS = frozenset(
    ("+", "-", "*", "/", "%", "**", "<<", ">>", "|", "&", "^")
)


def _same_operand(a: Any, b: Any) -> bool:
    """Identity of two operands (constants compared by value)."""
    if a is b:
        return True
    if isinstance(a, Constant) and isinstance(b, Constant):
        return a.value == b.value
    return False


class DivideBeforeMultiply(Detector):
    """Detect multiplication of a division's (truncated) result."""

    RULE = "divide-before-multiply"
    TITLE = "Division before multiplication truncates precision"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#divide-before-multiply",
        title="Division before multiplication truncates precision",
        description=(
            "EVM integer division truncates toward zero; (a / b) * c loses "
            "precision that a * c / b would keep, and collapses to 0 when "
            "a < b."
        ),
        exploit_scenario=(
            "reward() returns (principal / 365) * daysStaked; for any "
            "principal below 365 the division truncates to 0 and no reward "
            "is ever paid."
        ),
        recommendation=(
            "Reorder to multiply before dividing (principal * daysStaked / "
            "365), minding overflow bounds; use fixed-point math libraries "
            "for rates."
        ),
    )

    def _division_feeds(
        self, function: FunctionLike, seed: Any, defs: dict[int, Operation]
    ) -> list[Binary]:
        """Divisions whose (truncated) result feeds ``seed``."""
        _, ops = def_chain(function, [seed], defs)
        return [
            chain_op
            for chain_op in ops
            if isinstance(chain_op, Binary) and chain_op.operator == "/"
        ]

    @staticmethod
    def _feeds_arithmetic(function: FunctionLike, multiply: Binary) -> bool:
        """True when the product is itself consumed by another arithmetic
        op — the truncation then propagates into a larger computation."""
        if multiply.lvalue is None:
            return False
        for node in function.all_nodes:
            for op in node.ir_operations:
                if op is multiply or not isinstance(op, Binary):
                    continue
                if op.operator not in _ARITHMETIC_OPERATORS:
                    continue
                if multiply.lvalue in (op.read or []):
                    return True
        return False

    def _is_intentional_truncation(
        self,
        function: FunctionLike,
        multiply: Binary,
        divisions: list[Binary],
        other_operand: Any,
    ) -> bool:
        """``(x / y) * y`` rounds x down to a multiple of y — intentional.

        Only when the multiplicand *is* the divisor and the product is the
        value actually consumed (not an intermediate of more arithmetic).
        """
        if self._feeds_arithmetic(function, multiply):
            return False
        return any(_same_operand(other_operand, division.right) for division in divisions)

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen_functions: set[int] = set()
        for contract in self.compilation_unit.contracts_derived:
            functions = list(contract.available_functions_from_inheritances())
            functions += list(contract.all_modifiers())
            for function in functions:
                if id(function) in seen_functions:
                    continue
                seen_functions.add(id(function))
                defs = defining_ops(function)
                for node in function.all_nodes:
                    flagged = False
                    for op in node.ir_operations:
                        if not (isinstance(op, Binary) and op.operator == "*"):
                            continue
                        left_divs = self._division_feeds(function, op.left, defs)
                        right_divs = self._division_feeds(function, op.right, defs)
                        if left_divs:
                            if not self._is_intentional_truncation(
                                function, op, left_divs, op.right
                            ):
                                flagged = True
                        if right_divs and not flagged:
                            if not self._is_intentional_truncation(
                                function, op, right_divs, op.left
                            ):
                                flagged = True
                        if flagged:
                            break
                    if flagged:
                        results.append(
                            self.finding(
                                [
                                    node,
                                    " multiplies the result of a division, "
                                    "losing precision, in ",
                                    function,
                                    "; multiply before dividing instead",
                                ]
                            )
                        )
        return results
