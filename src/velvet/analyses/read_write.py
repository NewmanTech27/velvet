"""Read/write sets at every granularity (spec/architecture.md §7.1).

Derived from the plain IR (``read``/``lvalue``) of each node, with filtered
views (state vs local) and transitive/deep variants across internal calls
(fixpoint with cycle guards).  Writes through a ``ReferenceVariable``
(``balances[x] = 1``) count as writes of the reference's root variable.

Original clean-room implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from velvet.core.cfg_node import CFGNode
from velvet.core.contract import Contract
from velvet.core.function import FunctionLike
from velvet.core.variables import LocalVariable, StateVariable, Variable
from velvet.ir.operations import InternalCall, InternalDynamicCall, LibraryCall, Member
from velvet.ir.variables import ReferenceVariable, root_base


@dataclass
class ReadWriteSets:
    """Read/write variables at one granularity."""

    variables_read: list[Any] = field(default_factory=list)
    variables_written: list[Any] = field(default_factory=list)
    state_variables_read: list[StateVariable] = field(default_factory=list)
    state_variables_written: list[StateVariable] = field(default_factory=list)
    local_variables_read: list[LocalVariable] = field(default_factory=list)
    local_variables_written: list[LocalVariable] = field(default_factory=list)


def _append_unique(target: list[Any], value: Any) -> None:
    if value is not None and not any(v is value for v in target):
        target.append(value)


def _read_candidates(var: Any) -> Iterable[Any]:
    """A read variable plus the root of a reference chain, if any."""
    yield var
    if isinstance(var, ReferenceVariable):
        root = root_base(var)
        if root is not var:
            yield root


def node_read_write(node: CFGNode) -> ReadWriteSets:
    """Compute the read/write sets of one CFG node from its plain IR."""
    sets = ReadWriteSets()
    for op in node.ir_operations:
        for var in op.read:
            for candidate in _read_candidates(var):
                _append_unique(sets.variables_read, candidate)
                if isinstance(candidate, StateVariable):
                    _append_unique(sets.state_variables_read, candidate)
                elif isinstance(candidate, LocalVariable):
                    _append_unique(sets.local_variables_read, candidate)
        lvalue = op.lvalue
        if lvalue is not None:
            _append_unique(sets.variables_written, lvalue)
            root = root_base(lvalue)
            if root is not lvalue:
                _append_unique(sets.variables_written, root)
            for candidate in {lvalue, root}:
                if isinstance(candidate, StateVariable):
                    _append_unique(sets.state_variables_written, candidate)
                elif isinstance(candidate, LocalVariable):
                    _append_unique(sets.local_variables_written, candidate)
    return sets


def function_read_write(function: FunctionLike) -> ReadWriteSets:
    """Union of the read/write sets of the function's nodes (incl. modifiers)."""
    sets = ReadWriteSets()
    for node in function.all_nodes:
        node_sets = node_read_write(node)
        for attr in (
            "variables_read",
            "variables_written",
            "state_variables_read",
            "state_variables_written",
            "local_variables_read",
            "local_variables_written",
        ):
            target = getattr(sets, attr)
            for var in getattr(node_sets, attr):
                _append_unique(target, var)
    return sets


def _resolve_dynamic_call_target(
    op: InternalDynamicCall, function: FunctionLike
) -> Any:
    """Best-effort resolution of an internal dynamic (function pointer) call.

    Returns the target function when the pointer directly aliases a function
    (``function fnVar = helper; fnVar(...)``) or a contract member reference
    (``Comparators.lt``); ``None`` when it cannot be resolved statically
    (e.g. a function-typed parameter passed in by callers).
    """
    defining: dict[int, Any] = {}
    for node in function.all_nodes:
        for other in node.ir_operations:
            if other.lvalue is not None:
                defining[id(other.lvalue)] = other

    seen: set[int] = set()
    stack: list[Any] = [op.function_variable]
    while stack:
        var = stack.pop()
        if var is None or id(var) in seen:
            continue
        seen.add(id(var))
        if isinstance(var, FunctionLike):
            return var
        origin = getattr(var, "non_ssa_version", None) or var
        defining_op = defining.get(id(var)) or defining.get(id(origin))
        if defining_op is None:
            continue
        if isinstance(defining_op, Member) and isinstance(defining_op.base, Contract):
            member = _find_contract_function(
                defining_op.base, defining_op.member_name, len(op.arguments)
            )
            if member is not None:
                return member
            continue
        stack.extend(defining_op.read)
    return None


def _find_contract_function(contract: Any, name: str, nargs: int) -> Any:
    """Name/arity lookup over a contract's callable functions."""
    matches = [
        f
        for f in contract.available_functions_from_inheritances()
        if f.name == name
    ]
    for func in matches:
        if len(func.parameters) == nargs:
            return func
    return matches[0] if matches else None


def internal_call_targets(function: FunctionLike) -> list[FunctionLike]:
    """Direct internal call targets (internal calls + library calls +
    resolvable internal dynamic calls + applied modifiers), in
    first-appearance order."""
    targets: list[FunctionLike] = []

    def add(target: Any) -> None:
        if isinstance(target, FunctionLike) and not any(t is target for t in targets):
            targets.append(target)

    for op in function.all_ir_operations:
        if isinstance(op, (InternalCall, LibraryCall)) and op.function is not None:
            add(op.function)
        elif isinstance(op, InternalDynamicCall):
            add(_resolve_dynamic_call_target(op, function))
    for modifier in function.modifiers:
        add(modifier)
    return targets


def deep_state_variables(function: FunctionLike, *, read: bool) -> list[StateVariable]:
    """Transitive state variables read (or written) across internal calls.

    Fixpoint over the internal call graph with a cycle guard (recursive
    calls terminate via the visited set).
    """
    attr = "state_variables_read" if read else "state_variables_written"
    result: list[StateVariable] = []
    visited: set[int] = set()

    def visit(func: FunctionLike) -> None:
        if id(func) in visited:
            return
        visited.add(id(func))
        for var in getattr(func._rw(), attr):
            _append_unique(result, var)
        for target in internal_call_targets(func):
            visit(target)

    visit(function)
    return result


def expand_read_variables(
    variables: Iterable[Any], function: FunctionLike
) -> list[Variable]:
    """Expand TMP/REF/TUPLE values to the source variables they derive from.

    IR variables are each defined by exactly one op in the function; this
    chases those definitions (cycle-safe) so callers see the "real"
    variables (state/local/builtin) behind a computed value.  Non-IR
    variables are returned as-is.  Used by the protected heuristic and by
    pattern detectors that need to know e.g. whether a ``require`` argument
    ultimately reads ``tx.origin``.
    """
    defining: dict[int, Any] = {}
    for node in function.all_nodes:
        for op in node.ir_operations:
            if op.lvalue is not None:
                defining[id(op.lvalue)] = op

    result: list[Variable] = []
    seen: set[int] = set()
    stack = list(variables)
    while stack:
        var = stack.pop()
        if var is None or id(var) in seen:
            continue
        seen.add(id(var))
        origin = getattr(var, "non_ssa_version", None) or var
        op = defining.get(id(var)) or defining.get(id(origin))
        if op is None:
            if isinstance(origin, Variable) and not any(v is origin for v in result):
                result.append(origin)
        else:
            stack.extend(op.read)
    return result
