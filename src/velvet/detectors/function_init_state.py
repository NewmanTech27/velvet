"""`function-init-state` detector (spec/detectors-catalog.md §8.6 —
normative).

Flags state variables initialized at declaration by calling a non-``pure``
function, or from another non-constant state variable.  State-variable
initializers run in declaration order before the constructor, so the called
function observes a partially initialized contract and the same call can
yield different results at different declaration positions.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Optional

from velvet.core.expressions import CallExpression, Expression, Identifier
from velvet.core.function import Function
from velvet.core.variables import StateVariable
from velvet.detectors._batch_g_utils import iter_state_variable_initializers
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


def _initializer_problem(expression: Expression) -> Optional[str]:
    """Reason string when an initializer calls non-pure code or reads state."""
    for node in expression.walk():
        if isinstance(node, CallExpression) and isinstance(node.called, Identifier):
            target = node.called.value
            if isinstance(target, Function) and not target.pure:
                return (
                    f"calls the non-pure function {target.canonical_name}, "
                    "which observes a partially initialized contract"
                )
        if isinstance(node, Identifier) and isinstance(node.value, StateVariable):
            variable = node.value
            if not variable.is_constant:
                return (
                    f"reads the non-constant state variable {variable.canonical_name}"
                )
    return None


class FunctionInitState(Detector):
    """Detect state variables initialized from non-pure calls or state reads."""

    RULE = "function-init-state"
    TITLE = "State variable initialized from a function call or state read"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#function-init-state",
        title="Function initializing state",
        description=(
            "A state variable is initialized at declaration by calling a "
            "function that is not pure, or from another non-constant state "
            "variable. Initializers run in declaration order before the "
            "constructor, so the call observes a partially initialized "
            "contract."
        ),
        exploit_scenario=(
            "Config declares uint256 public base = compute() before factor; "
            "compute() reads factor == 0 and returns 100, while the later "
            "scaled = compute() returns 100 * factor — same call, two "
            "different results."
        ),
        recommendation=(
            "Initialize dependent values inside the constructor (or use "
            "pure functions / literals for inline initialization)."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for _contract, variable in iter_state_variable_initializers(self.compilation_unit):
            problem = _initializer_problem(variable.expression_initial)
            if problem is None:
                continue
            results.append(
                self.finding(
                    [
                        variable,
                        f" is initialized at declaration: it {problem}",
                    ]
                )
            )
        return results
