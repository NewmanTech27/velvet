"""Shared IR-level helpers for detector batch E (loop/call, constant
condition, equality, write, token-interface and event rules).

Building on the plain/SSA SolIR of a function these helpers provide:

- :func:`unique_functions` — the deduplicated functions *and* modifiers of
  the most-derived contracts (each with its own nodes only);
- :func:`constant_value` — a small, guarded constant folder resolving a
  variable through its definition chain (literals, copies, conversions and
  integer arithmetic);
- :func:`expression_key` — a hashable structural key for the expression
  rooted at a variable (used to spot syntactically identical operands);
- :func:`integer_range` — value range of an integer elementary type;
- canonical parameter/return type strings and public-getter synthesis
  (self-contained duplicates of the tiny ``velvet.tools.common`` helpers,
  so detectors stay independent of the companion tools);
- :func:`emits_event` — transitive event-emission detection;
- :func:`balance_like_sources` — whether a value derives from an Ether or
  token balance expression.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterator, Optional

from velvet.core.contract import Contract
from velvet.core.declarations import Structure
from velvet.core.function import FunctionLike
from velvet.core.types import ArrayType, ElementaryType, MappingType, Type, UserDefinedType
from velvet.core.variables import Constant, SolidityVariable, StateVariable, Variable
from velvet.ir.operations import (
    Assignment,
    Binary,
    EventCall,
    HighLevelCall,
    Index,
    Member,
    Operation,
    TypeConversion,
    Unary,
)
from velvet.ir.variables import IRVariable

# ---------------------------------------------------------------- traversal


def unique_functions(unit: Any) -> Iterator[FunctionLike]:
    """Yield each function and modifier of the most-derived contracts once.

    Functions are iterated through ``available_functions_from_inheritances``
    and modifiers through ``all_modifiers``; identity-based dedup keeps
    shared inherited members from being analyzed twice.
    """
    seen: set[int] = set()
    for contract in unit.contracts_derived:
        members: list[FunctionLike] = list(contract.available_functions_from_inheritances())
        members += list(contract.all_modifiers())
        for function in members:
            if id(function) in seen:
                continue
            seen.add(id(function))
            yield function


def defining_ops(function: FunctionLike) -> dict[int, Operation]:
    """Plain-IR ``id(variable) -> defining op`` map for one function."""
    defs: dict[int, Operation] = {}
    for node in function.all_nodes:
        for op in node.ir_operations:
            if op.lvalue is not None:
                defs[id(op.lvalue)] = op
    return defs


# ----------------------------------------------------------- constant fold

_BOOL_WORDS = {"true": True, "false": False}


def parse_literal(value: Any) -> Optional[Any]:
    """Parse a :class:`Constant` payload into an int / bool, else ``None``.

    Literal payloads are the raw surface strings (decimal or ``0x`` hex for
    integers, ``true``/``false`` for booleans).
    """
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    lowered = text.lower()
    if lowered in _BOOL_WORDS:
        return _BOOL_WORDS[lowered]
    try:
        return int(text, 0)
    except ValueError:
        pass
    try:
        return int(text, 10)
    except ValueError:
        return None


#: Arithmetic operators folded by :func:`constant_value`.
_FOLD_BINOPS = ("+", "-", "*", "/", "%", "**", "<<", ">>")

#: Bounds that keep the folder from materialising astronomically large ints.
_MAX_EXPONENT = 512
_MAX_SHIFT = 4096


def _fold_binary(operator: str, left: Any, right: Any) -> Optional[int]:
    """Fold ``left <operator> right`` with Solidity integer semantics."""
    if not isinstance(left, int) or not isinstance(right, int):
        return None
    try:
        if operator == "+":
            return left + right
        if operator == "-":
            return left - right
        if operator == "*":
            return left * right
        if operator == "/":
            if right == 0:
                return None
            # EVM division truncates toward zero.
            sign = -1 if (left < 0) != (right < 0) else 1
            return sign * (abs(left) // abs(right))
        if operator == "%":
            if right == 0:
                return None
            sign = -1 if left < 0 else 1
            return sign * (abs(left) % abs(right))
        if operator == "**":
            if right < 0 or right > _MAX_EXPONENT:
                return None
            return left**right
        if operator == "<<":
            if right < 0 or right > _MAX_SHIFT:
                return None
            return left << right
        if operator == ">>":
            if right < 0 or right > _MAX_SHIFT:
                return None
            return left >> right
    except (OverflowError, ValueError):
        return None
    return None


def constant_value(
    variable: Any,
    defs: Optional[dict[int, Operation]] = None,
    *,
    _depth: int = 0,
    _seen: Optional[set[int]] = None,
) -> Optional[Any]:
    """Resolve ``variable`` to a constant int/bool, else ``None``.

    Chases copies (assignments, conversions) and folds integer arithmetic
    through the definition chain; anything opaque (calls, dereferences,
    non-constant reads) yields ``None``.
    """
    if _depth > 32:
        return None
    if _seen is None:
        _seen = set()
    if variable is None or id(variable) in _seen:
        return None
    _seen.add(id(variable))
    if isinstance(variable, Constant):
        return parse_literal(variable.value)
    if defs is None or not isinstance(variable, Variable):
        return None
    op = defs.get(id(variable))
    if op is None:
        return None
    if isinstance(op, (Assignment, TypeConversion)):
        return constant_value(op.rvalue, defs, _depth=_depth + 1, _seen=_seen)
    if isinstance(op, Unary):
        operand = constant_value(op.rvalue, defs, _depth=_depth + 1, _seen=_seen)
        if isinstance(operand, bool) and op.operator == "!":
            return not operand
        if isinstance(operand, int) and not isinstance(operand, bool):
            if op.operator == "-":
                return -operand
            if op.operator == "~":
                return ~operand
        return None
    if isinstance(op, Binary) and op.operator in _FOLD_BINOPS:
        left = constant_value(op.left, defs, _depth=_depth + 1, _seen=_seen)
        right = constant_value(op.right, defs, _depth=_depth + 1, _seen=_seen)
        if left is None or right is None:
            return None
        return _fold_binary(op.operator, left, right)
    return None


def is_boolean_constant(variable: Any) -> bool:
    """True for a boolean literal (``true``/``false``) constant."""
    if not isinstance(variable, Constant):
        return False
    return parse_literal(variable.value) in (True, False) and str(
        variable.value
    ).lower() in _BOOL_WORDS


# ------------------------------------------------------ expression identity


def expression_key(
    variable: Any,
    defs: Optional[dict[int, Operation]],
    *,
    _depth: int = 0,
) -> Optional[tuple]:
    """Hashable structural key of the expression rooted at ``variable``.

    Two variables with equal keys denote syntactically identical pure
    expressions.  Returns ``None`` for anything with possible side effects
    or non-determinism (calls, allocations, dereference of storage whose
    value can change between evaluations).
    """
    if variable is None or _depth > 16:
        return None
    if isinstance(variable, Constant):
        parsed = parse_literal(variable.value)
        return ("const", parsed if parsed is not None else str(variable.value))
    if not isinstance(variable, Variable):
        return None
    op = defs.get(id(variable)) if defs else None
    if op is None:
        # Plain source variable (parameter, state variable, builtin, ...).
        return ("var", id(variable))
    if getattr(op, "_yul_opaque", False):
        # Value produced by a Yul builtin (``mload(0x00)``, ...): it is
        # only *approximated* by its arguments, so it must never be
        # considered structurally identical to them (e.g. ``x > 0`` where
        # ``x := mload(0x00)`` is not the tautology ``0 > 0``).
        return None
    if isinstance(op, Assignment):
        return expression_key(op.rvalue, defs, _depth=_depth + 1)
    if isinstance(op, TypeConversion):
        # A conversion is not a value-preserving copy: narrowing casts can
        # change the value, so `int104(value) != value` (the safe-cast
        # round-trip check) is not a tautology.  Only syntactically
        # identical conversions compare equal.
        operand = expression_key(op.rvalue, defs, _depth=_depth + 1)
        if operand is None:
            return None
        return ("conv", str(op.type), operand)
    if isinstance(op, Binary):
        left = expression_key(op.left, defs, _depth=_depth + 1)
        right = expression_key(op.right, defs, _depth=_depth + 1)
        if left is None or right is None:
            return None
        return ("bin", op.operator, left, right)
    if isinstance(op, Unary):
        operand = expression_key(op.rvalue, defs, _depth=_depth + 1)
        if operand is None:
            return None
        return ("un", op.operator, operand)
    # Calls, dereferences, allocations, phi merges: not provably identical.
    return None


# ------------------------------------------------------------ type ranges


def integer_range(type_: Optional[Type]) -> Optional[tuple[int, int]]:
    """``(min, max)`` value range of an integer elementary type."""
    if not isinstance(type_, ElementaryType):
        return None
    name = type_.name.split()[0]
    if name.startswith("uint") and (name[4:].isdigit() or name == "uint"):
        bits = int(name[4:]) if name[4:].isdigit() else 256
        return (0, 2**bits - 1)
    if name.startswith("int") and (name[3:].isdigit() or name == "int"):
        bits = int(name[3:]) if name[3:].isdigit() else 256
        return (-(2 ** (bits - 1)), 2 ** (bits - 1) - 1)
    return None


# ------------------------------------------------- canonical interface types


def canonical_params(function: FunctionLike) -> list[str]:
    """Canonical parameter type strings (aliases already normalized)."""
    return [str(p.type) if p.type is not None else "" for p in function.parameters]


def canonical_returns(function: FunctionLike) -> list[str]:
    """Canonical return type strings."""
    return [str(r.type) if r.type is not None else "" for r in function.returns]


def public_getter_signatures(contract: Contract) -> set[str]:
    """Signatures of the implicit getters of ``contract``'s public variables.

    Only getters representable as plain functions are synthesized (mapping
    keys/array indices become parameters; struct-valued getters, which
    expand to member tuples, are skipped).
    """
    signatures: set[str] = set()
    for variable in contract.state_variables_ordered:
        if variable.visibility != "public":
            continue
        parts = _getter_parts(variable.type)
        if parts is None:
            continue
        params, _ret = parts
        signatures.add(f"{variable.name}({','.join(str(p) for p in params)})")
    return signatures


def _getter_parts(type_: Optional[Type]) -> Optional[tuple[list[Type], Type]]:
    """Decompose a state-variable type into getter (params, return)."""
    if type_ is None:
        return None
    params: list[Type] = []
    current = type_
    while True:
        if isinstance(current, MappingType):
            params.append(current.type_from)
            current = current.type_to
        elif isinstance(current, ArrayType):
            params.append(ElementaryType("uint256"))
            current = current.type
        else:
            break
    if isinstance(current, UserDefinedType) and isinstance(
        getattr(current, "type", None), Structure
    ):
        return None
    return params, current


#: (name, param types) -> return types, per the ERC-20 standard.
ERC20_RETURNS_TABLE: dict[tuple[str, tuple[str, ...]], list[str]] = {
    ("totalSupply", ()): ["uint256"],
    ("balanceOf", ("address",)): ["uint256"],
    ("transfer", ("address", "uint256")): ["bool"],
    ("transferFrom", ("address", "address", "uint256")): ["bool"],
    ("approve", ("address", "uint256")): ["bool"],
    ("allowance", ("address", "address")): ["uint256"],
}

#: (name, param types) -> return types, per the ERC-721 standard.
ERC721_RETURNS_TABLE: dict[tuple[str, tuple[str, ...]], list[str]] = {
    ("balanceOf", ("address",)): ["uint256"],
    ("ownerOf", ("uint256",)): ["address"],
    ("safeTransferFrom", ("address", "address", "uint256")): [],
    ("safeTransferFrom", ("address", "address", "uint256", "bytes")): [],
    ("transferFrom", ("address", "address", "uint256")): [],
    ("approve", ("address", "uint256")): [],
    ("setApprovalForAll", ("address", "bool")): [],
    ("getApproved", ("uint256",)): ["address"],
    ("isApprovedForAll", ("address", "address")): ["bool"],
}


def interface_violations(
    unit: Any,
    table: dict[tuple[str, tuple[str, ...]], list[str]],
    *,
    conforming_table: Optional[dict[tuple[str, tuple[str, ...]], list[str]]] = None,
) -> Iterator[tuple[Any, FunctionLike, list[str]]]:
    """Yield ``(contract, function, expected_returns)`` signature violations.

    ``table`` maps ``(name, (param types...))`` to the expected return
    types.  A public/external function whose name *and* parameter types
    match an entry but whose return types differ is yielded (deduplicated
    across the derived contracts it is visible from).

    ``conforming_table`` is an optional second table (the *other* token
    standard): a function that conforms to it exactly is a deliberate
    cross-standard declaration (e.g. an ERC-20 ``transferFrom`` seen from
    the ERC-721 check) and is skipped.
    """
    seen: set[int] = set()
    for contract in unit.contracts_derived:
        for function in contract.available_functions_from_inheritances():
            if id(function) in seen:
                continue
            seen.add(id(function))
            if function.visibility not in ("external", "public"):
                continue
            key = (function.name, tuple(canonical_params(function)))
            expected = table.get(key)
            if expected is None:
                continue
            returns = canonical_returns(function)
            if returns == expected:
                continue
            if conforming_table is not None and returns == conforming_table.get(key):
                continue  # deliberate declaration of the other standard
            yield contract, function, expected


# ---------------------------------------------------------------- events


def emits_event(function: FunctionLike) -> bool:
    """True when ``function`` may emit an event (incl. internal calls)."""
    if any(isinstance(op, EventCall) for op in function.all_ir_operations):
        return True
    for target in function.all_internal_calls_reachable:
        if any(isinstance(op, EventCall) for op in target.all_ir_operations):
            return True
    return False


# ---------------------------------------------------------------- balances


def _is_this(variable: Any) -> bool:
    return isinstance(variable, SolidityVariable) and variable.name == "this"


def balance_like_sources(function: FunctionLike, seeds: Any) -> bool:
    """True when the def chain of ``seeds`` reaches a balance expression.

    Balance expressions are ``<addr>.balance`` member reads (most notably
    ``address(this).balance``) and ``balanceOf(...)`` calls; plain
    assignments/conversions forward the origin so local copies of a balance
    are covered as well.
    """
    from velvet.detectors._batch_b_utils import def_chain

    _, ops = def_chain(function, [seeds] if not isinstance(seeds, list) else seeds)
    for op in ops:
        if isinstance(op, Member) and op.member_name == "balance":
            base_vars, _ = def_chain(function, [op.base])
            if any(_is_this(var) for var in base_vars):
                return True
        if isinstance(op, HighLevelCall) and op.function_name == "balanceOf":
            return True
    return False


# ---------------------------------------------------------------------- misc


def is_ir_temp(variable: Any) -> bool:
    """True for IR-synthesized variables (TMP/REF/TUPLE, incl. SSA clones)."""
    if isinstance(variable, IRVariable):
        return True
    origin = getattr(variable, "non_ssa_version", None)
    return isinstance(origin, IRVariable)


def state_variables_guarded_with_msg_sender(function: FunctionLike) -> list[StateVariable]:
    """State variables compared against ``msg.sender`` inside ``function``.

    Used to spot access-control modifiers: the guard variable (e.g.
    ``owner``) is the one compared with the caller in a ``require``/``if``.
    """
    from velvet.analyses.read_write import expand_read_variables

    guarded: list[StateVariable] = []
    for node in function.all_nodes:
        for op in node.ir_operations:
            if not (isinstance(op, Binary) and op.operator in ("==", "!=")):
                continue
            left = expand_read_variables([op.left], function)
            right = expand_read_variables([op.right], function)
            for side, other in ((left, right), (right, left)):
                if not any(
                    isinstance(v, SolidityVariable) and v.name == "msg.sender"
                    for v in side
                ):
                    continue
                for var in other:
                    if isinstance(var, StateVariable) and not any(
                        v is var for v in guarded
                    ):
                        guarded.append(var)
    return guarded
