"""`incorrect-exp` detector (spec/detectors-catalog.md §7.9 — normative).

Flags the bitwise-XOR operator ``^`` used where exponentiation ``**`` was
intended (a common mistake by developers coming from languages where ``^``
is "power").  ``2^256`` is 258, not 2²⁵⁶, so limits and constants are
catastrophically wrong.  The trigger is a ``^`` operation that *looks* like
exponentiation: at least one operand is a decimal-notation literal
(``2^256``, ``10^18``, ``x ^ 2``) or both operands are compile-time
constants.  Hex literals (``x ^ 0xff`` — the bit-mask idiom) and purely
symbolic operands (``a ^ b``) are real XOR uses and are not flagged.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.expressions import (
    BinaryOperation,
    Expression,
    Literal,
    TupleExpression,
)
from velvet.detectors._batch_e_utils import unique_functions
from velvet.detectors._batch_g_utils import (
    fold_expression_int,
    iter_state_variable_initializers,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


def _is_decimal_literal(expression: Expression) -> bool:
    """True for a literal written in decimal notation (``18``, ``1e18``).

    Hex literals (``0x…``) are the bit-mask idiom, not mistaken
    exponentiation, so they do not count.  Redundant parentheses around the
    literal are unwrapped (``x ^ (2)`` still looks like exponentiation).
    """
    while isinstance(expression, TupleExpression):
        parts = [part for part in expression.expressions if part is not None]
        if len(parts) != 1:
            return False
        expression = parts[0]
    if not isinstance(expression, Literal):
        return False
    text = expression.value.strip().lower()
    return bool(text) and not text.startswith("0x")


def _suspicious_xor(expression: Expression) -> BinaryOperation | None:
    """The first ``^`` operation shaped like mistaken exponentiation.

    Matches when at least one operand is a decimal-notation literal (the
    exponent-looking shape, e.g. ``x ^ 2``, ``(3 * n) ^ 2``, ``10 ^ 18``)
    or when both operands are compile-time integer constants.
    """
    for node in expression.walk():
        if not (isinstance(node, BinaryOperation) and node.operator == "^"):
            continue
        if _is_decimal_literal(node.expression_left) or _is_decimal_literal(
            node.expression_right
        ):
            return node
        if (
            fold_expression_int(node.expression_left) is not None
            and fold_expression_int(node.expression_right) is not None
        ):
            return node
    return None


class IncorrectExp(Detector):
    """Detect ^ used between constant operands (likely meant **)."""

    RULE = "incorrect-exp"
    TITLE = "Bitwise XOR ^ used where exponentiation ** was intended"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#incorrect-exp",
        title="Incorrect exponentiation",
        description=(
            "The bitwise-XOR operator ^ is used between constant operands "
            "in a context that strongly suggests exponentiation (e.g. "
            "2^256, 10^18 in constant definitions or bounds). ^ is XOR, "
            "not power: 2^256 is 258."
        ),
        exploit_scenario=(
            "Sale declares uint256 public constant HARD_CAP = 1000 * 10^18, "
            "intending 1e21; the cap is actually 1000 * (10 xor 18) = "
            "24000, so the sale stops accepting funds almost immediately."
        ),
        recommendation="Use ** for exponentiation (10**18) or scientific notation (1e18).",
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        # State-variable initializers (constant definitions and bounds).
        for _contract, variable in iter_state_variable_initializers(self.compilation_unit):
            culprit = _suspicious_xor(variable.expression_initial)
            if culprit is None:
                continue
            results.append(
                self.finding(
                    [
                        variable,
                        f" is initialized with {culprit} (^ is bitwise XOR, "
                        "not exponentiation); use **",
                    ]
                )
            )
        # Function bodies.
        for function in unique_functions(self.compilation_unit):
            for node in function.nodes:
                if node.expression is None:
                    continue
                culprit = _suspicious_xor(node.expression)
                if culprit is None:
                    continue
                results.append(
                    self.finding(
                        [
                            node,
                            f" computes {culprit} (^ is bitwise XOR, not "
                            "exponentiation) in ",
                            function,
                            "; use **",
                        ]
                    )
                )
        return results
