"""Shared helpers for state-variable usage analysis across an inheritance
family (a contract plus its transitive derived contracts).

A state variable declared in contract ``C`` can only be read or written
directly by functions/modifiers declared in ``C`` or in contracts derived
from ``C`` (base contracts cannot see ``C``'s declarations).  The helpers
below collect exactly that function set, so detectors reason about reads
and writes "anywhere in the codebase" without re-walking the IR.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterator

from velvet.core.contract import Contract
from velvet.core.expressions import Identifier
from velvet.core.function import FunctionLike
from velvet.core.variables import StateVariable


def family_contracts(contract: Contract) -> list[Contract]:
    """``contract`` plus its transitive derived contracts (cycle-safe)."""
    result: list[Contract] = []
    seen: set[int] = set()
    stack = [contract]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        result.append(current)
        stack.extend(current.derived_contracts)
    return result


def family_functions(contract: Contract) -> list[FunctionLike]:
    """All functions and modifiers declared in the inheritance family."""
    result: list[FunctionLike] = []
    for member in family_contracts(contract):
        result.extend(member.functions)
        result.extend(member.modifiers)
    return result


def initializer_reads(contract: Contract) -> Iterator[StateVariable]:
    """State variables read by state-variable inline initializers in the family."""
    for member in family_contracts(contract):
        for var in member.state_variables:
            expr = var.expression_initial
            if expr is None:
                continue
            for node in expr.walk():
                if isinstance(node, Identifier) and isinstance(
                    node.value, StateVariable
                ):
                    yield node.value


def state_variables_read_in_family(contract: Contract) -> list[StateVariable]:
    """Every state variable read by family code (functions + initializers)."""
    read: list[StateVariable] = []

    def add(var: Any) -> None:
        if isinstance(var, StateVariable) and not any(v is var for v in read):
            read.append(var)

    for func in family_functions(contract):
        for var in func.state_variables_read:
            add(var)
    for var in initializer_reads(contract):
        add(var)
    return read


def state_variable_writers_in_family(
    contract: Contract,
) -> dict[int, tuple[StateVariable, list[FunctionLike]]]:
    """Map ``id(state_variable)`` to ``(variable, writing functions)`` over the family."""
    writers: dict[int, tuple[StateVariable, list[FunctionLike]]] = {}
    for func in family_functions(contract):
        for var in func.state_variables_written:
            entry = writers.setdefault(id(var), (var, []))
            if not any(f is func for f in entry[1]):
                entry[1].append(func)
    return writers
