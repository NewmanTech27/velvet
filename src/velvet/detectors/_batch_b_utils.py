"""Shared IR-level helpers for detector batch B (delegatecall, token,
best-practice and informational rules).

These helpers implement the small def-use queries the batch detectors need
on top of the plain SolIR of a function:

- :func:`defining_ops` — map a variable to the op that defines it;
- :func:`def_chain` — backward chase of the definition chain of a value;
- :func:`terminal_consumers` — forward chase to the ops that *consume* a
  value (condition, guard builtin, event, return, ...), skipping pure
  copy/forwarding operations;
- :func:`is_user_settable` — whether a state variable can be written by an
  unprotected external/public function (i.e. is caller-controlled state).

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from velvet.core.contract import Contract
from velvet.core.function import FunctionLike
from velvet.core.variables import StateVariable
from velvet.ir.operations import Operation


def defining_ops(function: FunctionLike) -> dict[int, Operation]:
    """Plain-IR ``id(variable) -> defining op`` map for one function.

    Includes the nodes of applied modifiers (``all_nodes``), so values
    produced by modifier bodies resolve as well.
    """
    defs: dict[int, Operation] = {}
    for node in function.all_nodes:
        for op in node.ir_operations:
            if op.lvalue is not None:
                defs[id(op.lvalue)] = op
    return defs


def def_chain(
    function: FunctionLike,
    seeds: Iterable[Any],
    defs: Optional[dict[int, Operation]] = None,
) -> tuple[list[Any], list[Operation]]:
    """Backward def-chain chase from ``seeds`` (function-local, plain IR).

    Returns ``(variables, ops)``: every variable the seeds transitively
    depend on and every operation participating in the chains.  Cycle-safe.
    """
    if defs is None:
        defs = defining_ops(function)
    seen_vars: set[int] = set()
    seen_ops: set[int] = set()
    variables: list[Any] = []
    ops: list[Operation] = []
    stack = [seed for seed in seeds if seed is not None]
    while stack:
        var = stack.pop()
        if id(var) in seen_vars:
            continue
        seen_vars.add(id(var))
        variables.append(var)
        op = defs.get(id(var))
        if op is not None and id(op) not in seen_ops:
            seen_ops.add(id(op))
            ops.append(op)
            stack.extend(op.read)
    return variables, ops


def terminal_consumers(
    function: FunctionLike, seeds: Iterable[Any]
) -> list[Operation]:
    """Forward use-chain chase: the non-copy ops that consume ``seeds``.

    Operations with an ``lvalue`` (assignments, unpack, conversions, other
    calls producing a value) only *forward* the value, so the chase
    continues through their result.  Operations without an ``lvalue``
    (:class:`Condition`, guard builtins such as ``require``/``assert``,
    :class:`EventCall`, :class:`Return`, ``TRANSFER`` ...) actually consume
    the value and are returned.
    """
    readers: dict[int, list[Operation]] = {}
    for node in function.all_nodes:
        for op in node.ir_operations:
            for read in op.read:
                readers.setdefault(id(read), []).append(op)

    consumers: list[Operation] = []
    seen_vars: set[int] = set()
    seen_ops: set[int] = set()
    stack = [seed for seed in seeds if seed is not None]
    while stack:
        var = stack.pop()
        if id(var) in seen_vars:
            continue
        seen_vars.add(id(var))
        for op in readers.get(id(var), ()):
            if id(op) in seen_ops:
                continue
            seen_ops.add(id(op))
            if op.lvalue is not None:
                stack.append(op.lvalue)
            else:
                consumers.append(op)
    return consumers


def is_user_settable(state_variable: StateVariable, contract: Contract) -> bool:
    """True when ``state_variable`` can be written through an unprotected
    external/public function of ``contract`` (caller-controlled state).

    Constant and immutable variables are fixed at construction time and are
    never user-settable.  Writes performed only from protected functions
    (``msg.sender`` guard / constructor, per the framework heuristic) are
    treated as trusted.
    """
    if state_variable.is_constant or state_variable.is_immutable:
        return False
    for func in contract.available_functions_from_inheritances():
        if func.visibility not in ("external", "public"):
            continue
        if func.is_constructor or func.is_protected:
            continue
        if any(v is state_variable for v in func.state_variables_written_deep):
            return True
    return False
