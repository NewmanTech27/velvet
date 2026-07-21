"""`constable-states` detector (spec/detectors-catalog.md §9.3 — normative).

Flags state variables that are assigned once at declaration and never
modified afterwards.  Declaring them ``constant`` moves the value into
bytecode, removing storage reads entirely.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.core.expressions import (
    BinaryOperation,
    ConditionalExpression,
    ElementaryTypeNameExpression,
    Identifier,
    Literal,
    TupleExpression,
    TypeConversion,
    UnaryOperation,
)
from velvet.core.variables import Constant, StateVariable
from velvet.detectors._state_family import state_variable_writers_in_family
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


def is_compile_time_evaluable(expression: Any) -> bool:
    """True when an initializer expression only involves literals, constant
    variables and pure operations (usable in a ``constant`` declaration)."""
    if expression is None:
        return False
    evaluable_nodes = (
        Literal,
        UnaryOperation,
        BinaryOperation,
        ConditionalExpression,
        TypeConversion,
        ElementaryTypeNameExpression,
        TupleExpression,
    )
    for node in expression.walk():
        if isinstance(node, evaluable_nodes):
            continue
        if isinstance(node, Constant):
            continue
        if isinstance(node, Identifier):
            value = node.value
            if isinstance(value, StateVariable) and value.is_constant:
                continue
            if isinstance(value, Constant):
                continue
            return False
        return False
    return True


class ConstableStates(Detector):
    """Detect never-written state variables that should be constant."""

    RULE = "constable-states"
    TITLE = "State variables that could be declared constant"
    IMPACT = Impact.OPTIMIZATION
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#constable-states",
        title="State variables that could be declared constant",
        description=(
            "State variables assigned once at declaration and never "
            "modified afterwards should be declared constant: the value "
            "moves into bytecode, removing storage reads entirely."
        ),
        exploit_scenario=(
            "`uint256 public maxFeeBps = 500;` is never changed; every read "
            "pays an SLOAD that a `constant` declaration would eliminate."
        ),
        recommendation=(
            "Add the `constant` keyword to never-changing variables with "
            "literal initializers."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts:
            writers = state_variable_writers_in_family(contract)
            for var in contract.state_variables:
                if var.is_constant or var.is_immutable:
                    continue
                if not var.initialized:
                    continue
                if not is_compile_time_evaluable(var.expression_initial):
                    continue
                if id(var) in writers:
                    continue
                results.append(
                    self.finding(
                        [var, " is never modified and should be declared constant"],
                        additional_fields={"suggested_keyword": "constant"},
                    )
                )
        return results
