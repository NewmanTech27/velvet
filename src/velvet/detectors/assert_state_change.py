"""`assert-state-change` detector (spec/detectors-catalog.md §8.2 — normative).

Flags ``assert(...)`` calls whose condition expression changes state: an
assignment, a ``++``/``--`` increment, or a mutating (non-view/non-pure)
call.  ``assert`` is meant for pure invariant checking; embedding side
effects is confusing and breaks under evaluation-order reasoning.

The argument *expression* of each ``assert`` Solidity call is walked, so
side effects hidden anywhere inside the condition are caught.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Optional

from velvet.core.expressions import (
    AssignmentOperation,
    CallExpression,
    Expression,
    Identifier,
    MemberAccess,
    UnaryOperation,
)
from velvet.core.function import Function
from velvet.detectors._batch_e_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import SolidityCall

#: Member-call names that always mutate state (Ether-moving / code-running).
_MUTATING_MEMBER_CALLS = ("call", "callcode", "delegatecall", "transfer", "send")


def _mutating_call(expression: CallExpression) -> bool:
    """True when ``expression`` calls something that may change state."""
    called = expression.called
    if isinstance(called, Identifier) and isinstance(called.value, Function):
        target = called.value
        return not (target.view or target.pure)
    if isinstance(called, MemberAccess):
        return called.member_name in _MUTATING_MEMBER_CALLS
    return False


def _side_effect_reason(expression: Expression) -> Optional[str]:
    """Reason string when ``expression`` contains a state-changing operation."""
    for node in expression.walk():
        if isinstance(node, AssignmentOperation):
            return f"an assignment ({node})"
        if isinstance(node, UnaryOperation) and node.operator in ("++", "--"):
            return f"an increment/decrement ({node})"
        if isinstance(node, CallExpression) and _mutating_call(node):
            return f"a state-changing call ({node})"
    return None


class AssertStateChange(Detector):
    """Detect assert conditions with side effects."""

    RULE = "assert-state-change"
    TITLE = "Assert condition modifies state"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#assert-state-change",
        title="Assert condition modifies the state",
        description=(
            "The argument expression of an assert contains a state-changing "
            "operation (an assignment, ++/--, or a mutating call). assert "
            "is meant for pure invariant checking; embedding side effects "
            "is confusing and error-prone."
        ),
        exploit_scenario=(
            "bump() runs assert((n += 1) > 0): the counter update is hidden "
            "inside the invariant check, so reviewers and tooling reason "
            "about the function as if it were side-effect free."
        ),
        recommendation=(
            "Perform the state change separately, then assert a "
            "side-effect-free invariant; use require when the check itself "
            "is part of the logic."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            for node in function.nodes:
                for op in node.ir_operations:
                    if not (
                        isinstance(op, SolidityCall) and op.function.name == "assert"
                    ):
                        continue
                    call_expr: Any = op.expression
                    if not isinstance(call_expr, CallExpression):
                        continue
                    reason: Optional[str] = None
                    for argument in call_expr.arguments:
                        reason = _side_effect_reason(argument)
                        if reason is not None:
                            break
                    if reason is None:
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                f" has an assert condition with {reason} in ",
                                function,
                                "; assert should check a side-effect-free "
                                "invariant",
                            ]
                        )
                    )
        return results
