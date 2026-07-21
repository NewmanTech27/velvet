"""Data dependency and taint (spec/architecture.md §7.3, api-surface.md §4).

- ``is_dependent(var, source, context)`` where ``context`` is a
  :class:`~velvet.core.function.FunctionLike` (function-local dependencies
  from the SSA def-use chains) or a :class:`~velvet.core.contract.Contract`
  (multi-transaction fixpoint: ``b`` depends on ``input_a`` when
  ``setA(x){ a = x }`` and ``setB(){ b = a }`` can run in separate
  transactions).
- ``is_tainted(var, context)``: the variable depends on a user-controlled
  input (function parameter or builtin such as ``msg.sender``/``msg.value``/
  ``tx.origin``).

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterable, Union

from velvet.core.contract import Contract
from velvet.core.function import FunctionLike
from velvet.core.variables import (
    LocalVariable,
    SolidityVariable,
    StateVariable,
    Variable,
)
from velvet.ir.operations import Operation
from velvet.ir.ssa import non_ssa_version_of
from velvet.ir.variables import ReferenceVariable, root_base

#: Builtins considered user-controlled taint sources.
TAINTED_BUILTINS = (
    "msg.sender",
    "msg.value",
    "msg.data",
    "msg.sig",
    "tx.origin",
    "tx.gasprice",
)

Context = Union[FunctionLike, Contract]


def _unversioned(var: Any) -> Any:
    return non_ssa_version_of(var)


# ------------------------------------------------------------- function-local
def _defining_ops(function: FunctionLike) -> dict[int, Operation]:
    """SSA variable id -> the op defining it (within one function)."""
    defs: dict[int, Operation] = {}
    for node in function.all_nodes:
        for op in node.ir_operations_ssa:
            if op.lvalue is not None:
                defs[id(op.lvalue)] = op
    return defs


def _direct_dependencies(function: FunctionLike) -> dict[int, set[Any]]:
    """Direct (one-step) dependencies of every variable in the function.

    Keys are unversioned variables; values are unversioned variables read
    directly by one of its defining ops.  Variables with no defining op
    (parameters, state variables, uninitialized locals) have no direct
    deps — they are sources (their own initial value).
    """
    defs = _defining_ops(function)
    direct: dict[int, set[Any]] = {}
    holders: dict[int, Any] = {}

    def holder(var: Any) -> Any:
        base = _unversioned(var)
        key = id(base)
        if key not in holders:
            holders[key] = base
            direct.setdefault(key, set())
        return holders[key]

    for op in defs.values():
        base = holder(op.lvalue)
        for read in op.read:
            dep = holder(read)
            if dep is not base:
                direct[id(base)].add(dep)
    # Writes through a REF update the root variable: the root depends on the
    # values involved in the write (compensates the documented SSA choice of
    # not versioning through-REF writes inline).
    for node in function.all_nodes:
        for op in node.ir_operations_ssa:
            lvalue = op.lvalue
            if isinstance(lvalue, ReferenceVariable):
                root = root_base(non_ssa_version_of(lvalue))
                if isinstance(root, (StateVariable, LocalVariable)):
                    base = holder(root)
                    for read in op.read:
                        dep = holder(read)
                        if dep is not base:
                            direct[id(base)].add(dep)
    return direct


def _closure(direct: dict[int, set[Any]], seeds: Iterable[Any]) -> set[Any]:
    """Transitive dependency closure over the direct-dependency graph."""
    result: set[Any] = set()
    seen: set[int] = set()
    stack = [s for s in seeds if s is not None]
    while stack:
        var = stack.pop()
        base = _unversioned(var)
        if base is None or id(base) in seen:
            continue
        seen.add(id(base))
        result.add(base)
        stack.extend(direct.get(id(base), ()))
    return result


def _same_var(a: Any, b: Any) -> bool:
    if a is b:
        return True
    return _unversioned(a) is _unversioned(b)


def _cached_direct(function: FunctionLike) -> dict[int, set[Any]]:
    cached = getattr(function, "_deps_direct_cache", None)
    if cached is None:
        cached = _direct_dependencies(function)
        function._deps_direct_cache = cached  # type: ignore[attr-defined]
    return cached


def _function_dependent(var: Any, source: Any, function: FunctionLike) -> bool:
    direct = _cached_direct(function)
    base_source = _unversioned(source)
    # A variable trivially depends on itself (its initial value).
    if _same_var(var, source):
        return True
    deps = _closure(direct, [_unversioned(var)])
    return any(_same_var(d, base_source) for d in deps if d is not _unversioned(var))


# ------------------------------------------------------------ contract-level
def _contract_functions(contract: Contract) -> list[FunctionLike]:
    return list(contract.available_functions_from_inheritances()) + list(
        contract.all_modifiers()
    )


def _contract_dependencies(contract: Contract) -> dict[int, set[Any]]:
    """Multi-transaction dependency sets for the contract's state variables.

    Fixpoint: a state variable written in a function depends on everything
    the written value depends on function-locally; state variables among
    those contribute their own (contract-level) dependencies — transactions
    may be sequenced arbitrarily.
    """
    deps: dict[int, set[Any]] = {}
    holders: dict[int, Any] = {}
    for var in contract.state_variables_ordered:
        holders[id(var)] = var
        deps[id(var)] = set()

    def holder(var: Any) -> Any:
        base = _unversioned(var)
        if id(base) not in holders:
            holders[id(base)] = base
            deps.setdefault(id(base), set())
        return holders[id(base)]

    # Seed: for every write to a state var, attach the function-local deps
    # of the written value.
    funcs = _contract_functions(contract)
    local_direct = {id(f): _cached_direct(f) for f in funcs}
    writes: list[tuple[Any, set[Any]]] = []
    for func in funcs:
        for node in func.all_nodes:
            for op in node.ir_operations:
                lvalue = op.lvalue
                if lvalue is None:
                    continue
                root = root_base(lvalue)
                if not isinstance(root, StateVariable):
                    continue
                values: set[Any] = set()
                for read in op.read:
                    base = _unversioned(read)
                    if base is not root:
                        values.add(base)
                # expand through function-local dependency chains
                values |= _closure(local_direct[id(func)], list(values))
                writes.append((root, values))

    changed = True
    while changed:
        changed = False
        for root, values in writes:
            target = deps[id(holder(root))]
            for value in values:
                held = holder(value)
                if held is root:
                    continue
                if held not in target:
                    target.add(held)
                    changed = True
                if isinstance(held, StateVariable):
                    for transitive in deps.get(id(held), ()):
                        if transitive is not root and transitive not in target:
                            target.add(transitive)
                            changed = True
    return deps


def _cached_contract_deps(contract: Contract) -> dict[int, set[Any]]:
    cached = getattr(contract, "_deps_contract_cache", None)
    if cached is None:
        cached = _contract_dependencies(contract)
        contract._deps_contract_cache = cached  # type: ignore[attr-defined]
    return cached


def _contract_dependent(var: Any, source: Any, contract: Contract) -> bool:
    if _same_var(var, source):
        return True
    deps = _cached_contract_deps(contract)
    base = _unversioned(var)
    if id(base) not in deps:
        return False
    seen: set[int] = set()
    stack = list(deps[id(base)])
    while stack:
        dep = stack.pop()
        if _same_var(dep, source):
            return True
        if isinstance(dep, StateVariable) and id(dep) not in seen:
            seen.add(id(dep))
            stack.extend(deps.get(id(dep), ()))
    return False


# ------------------------------------------------------------------- public
def is_dependent(var: Any, source: Any, context: Context) -> bool:
    """True when ``var`` depends on ``source`` in ``context``.

    ``context`` is a function (SSA def-use chains within the function) or a
    contract (multi-transaction fixpoint over all functions).
    """
    if isinstance(context, Contract):
        return _contract_dependent(var, source, context)
    return _function_dependent(var, source, context)


def taint_sources(context: Context) -> list[Variable]:
    """User-controlled inputs for ``context`` (params + tainted builtins)."""
    sources: list[Variable] = []
    functions: list[FunctionLike]
    if isinstance(context, Contract):
        functions = _contract_functions(context)
    else:
        functions = [context]
    for func in functions:
        for param in func.parameters:
            if not any(p is param for p in sources):
                sources.append(param)
    return sources


def is_tainted(var: Any, context: Context) -> bool:
    """True when ``var`` depends on a user-controlled input."""
    for source in taint_sources(context):
        if is_dependent(var, source, context):
            return True
    if isinstance(context, Contract):
        deps = _cached_contract_deps(context)
        base = _unversioned(var)
        for dep in deps.get(id(base), ()):
            if isinstance(dep, SolidityVariable) and dep.name in TAINTED_BUILTINS:
                return True
        return False
    direct = _cached_direct(context)
    for dep in _closure(direct, [_unversioned(var)]):
        if isinstance(dep, SolidityVariable) and dep.name in TAINTED_BUILTINS:
            return True
    return False
