"""`events-maths` detector (spec/detectors-catalog.md §7.36 — normative).

Flags privileged setters that change economically significant numeric
parameters (fees, prices, rates, limits) without emitting an event, so
off-chain observers cannot track parameter changes.  A variable is
"economically significant" here when it is involved in arithmetic (used in
computations elsewhere); a function is "privileged" when it carries an
access-control modifier (a modifier that compares a state variable against
``msg.sender``).

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterator

from velvet.core.function import FunctionLike, Modifier
from velvet.core.variables import StateVariable
from velvet.detectors._batch_b_utils import def_chain, defining_ops
from velvet.detectors._batch_e_utils import (
    emits_event,
    state_variables_guarded_with_msg_sender,
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

#: Arithmetic operators marking a variable as used in computations.
_ARITHMETIC_OPERATORS = ("+", "-", "*", "/", "%", "**")


def variables_used_in_arithmetic(unit: Any) -> list[StateVariable]:
    """State variables that feed an arithmetic operation anywhere."""
    result: list[StateVariable] = []

    def add(var: Any) -> None:
        if isinstance(var, StateVariable) and not any(v is var for v in result):
            result.append(var)

    for function in unique_functions(unit):
        defs = defining_ops(function)
        for node in function.all_nodes:
            for op in node.ir_operations:
                if not (isinstance(op, Binary) and op.operator in _ARITHMETIC_OPERATORS):
                    continue
                variables, _ = def_chain(function, [op.left, op.right], defs)
                for var in variables:
                    add(var)
    return result


def _access_control_modifiers(unit: Any) -> Iterator[Modifier]:
    """Modifiers that guard a state variable against ``msg.sender``."""
    for function in unique_functions(unit):
        if isinstance(function, Modifier) and state_variables_guarded_with_msg_sender(
            function
        ):
            yield function


class EventsMaths(Detector):
    """Detect privileged numeric-parameter changes that emit no event."""

    RULE = "events-maths"
    TITLE = "Critical arithmetic parameter change emits no event"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#events-maths",
        title="Missing event for an arithmetic parameter change",
        description=(
            "A function protected by an access-control modifier assigns a "
            "state variable that is involved in arithmetic elsewhere "
            "(fees, prices, rates, limits) without emitting an event, so "
            "off-chain observers cannot track the parameter change."
        ),
        exploit_scenario=(
            "Shop.setPrice(p) rewrites priceWei overnight with no event; "
            "users monitoring the shop off-chain keep quoting the stale "
            "price and overpay."
        ),
        recommendation=(
            "Emit an event (e.g. PriceUpdated(old, new)) on every critical "
            "parameter change."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        access_modifiers = {id(mod) for mod in _access_control_modifiers(self.compilation_unit)}
        if not access_modifiers:
            return results
        arithmetic_vars = variables_used_in_arithmetic(self.compilation_unit)
        if not arithmetic_vars:
            return results
        for function in unique_functions(self.compilation_unit):
            if isinstance(function, Modifier) or not function.is_implemented:
                continue
            if not any(id(mod) in access_modifiers for mod in function.modifiers):
                continue
            if emits_event(function):
                continue
            written = function.state_variables_written_deep
            for var in arithmetic_vars:
                if not any(v is var for v in written):
                    continue
                results.append(
                    self.finding(
                        [
                            function,
                            " changes the arithmetic state variable ",
                            var,
                            " without emitting an event",
                        ]
                    )
                )
        return results
