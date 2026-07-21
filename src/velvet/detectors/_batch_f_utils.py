"""Shared IR-level helpers for detector batch F (oracle, L2/security,
complexity/best-practice and gas rules).

The oracle detectors pattern-match calls against the oracle interfaces
described in the catalog (function names/signatures as given there) and
reason about whether a returned field (confidence interval, publish time)
is ever validated.  The helpers here provide:

- :func:`unique_functions` / :func:`is_boolean_constant` — re-exported from
  the batch E helpers so the batch has a single import surface;
- :func:`destination_type_name` — the interface/contract type name a
  high-level call is made on (``IPyth``, ``IChronicle``, ...);
- :func:`is_oracle_call` — whether an op is a high-level call to one of the
  given entry points on an interface whose name contains a keyword;
- :func:`tuple_unpack` — the ``Unpack`` operation extracting a given tuple
  field of a call result;
- :func:`value_reaches_check` — forward use-chain query: does a value feed a
  comparison, a branch condition, or a ``require``/``assert`` guard?

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from velvet.core.function import FunctionLike
from velvet.detectors._batch_e_utils import is_boolean_constant, unique_functions
from velvet.ir.operations import (
    Binary,
    Condition,
    HighLevelCall,
    SolidityCall,
    Unpack,
)

__all__ = [
    "unique_functions",
    "is_boolean_constant",
    "destination_type_name",
    "is_oracle_call",
    "tuple_unpack",
    "value_reaches_check",
]

#: Comparison operators treated as "validation" of a value.
_COMPARISON_OPS = ("==", "!=", "<", "<=", ">", ">=")

#: Guard builtins whose argument is asserted to hold.
_GUARD_BUILTINS = ("require", "assert")


def destination_type_name(op: Any) -> str:
    """Interface/contract type name the call ``op`` is made on.

    The destination of a high-level call is a variable whose type is usually
    a :class:`~velvet.core.types.UserDefinedType` wrapping the target
    contract; fall back to the type's own name when it is already named.
    Returns ``""`` when no name can be determined.
    """
    destination = getattr(op, "destination", None)
    type_ = getattr(destination, "type", None)
    for candidate in (getattr(type_, "type", None), type_):
        name = getattr(candidate, "name", None)
        if name:
            return str(name)
    return ""


def is_oracle_call(
    op: Any,
    function_names: Iterable[str],
    keyword: str,
) -> bool:
    """True when ``op`` is a high-level call to a ``function_names`` entry
    point on an interface whose type name contains ``keyword`` (both matched
    case-insensitively)."""
    if not isinstance(op, HighLevelCall):
        return False
    if op.function_name not in function_names:
        return False
    return keyword.lower() in destination_type_name(op).lower()


def tuple_unpack(
    function: FunctionLike,
    tuple_variable: Any,
    index: int,
) -> Optional[Unpack]:
    """The ``Unpack`` op extracting field ``index`` of ``tuple_variable``."""
    if tuple_variable is None:
        return None
    for op in function.all_ir_operations:
        if (
            isinstance(op, Unpack)
            and op.tuple_variable is tuple_variable
            and op.index == index
        ):
            return op
    return None


def value_reaches_check(function: FunctionLike, seed: Any) -> bool:
    """True when ``seed`` feeds a comparison, branch, or guard.

    A forward use-chain chase: lvalue-producing operations (assignments,
    arithmetic, conversions, ...) forward the value, so the chase continues
    through their result.  Reaching a comparison :class:`Binary`, a
    :class:`Condition`, or a ``require``/``assert`` :class:`SolidityCall`
    means the value is actually validated.
    """
    readers: dict[int, list[Any]] = {}
    for node in function.all_nodes:
        for op in node.ir_operations:
            for read in op.read:
                readers.setdefault(id(read), []).append(op)

    seen_vars: set[int] = set()
    seen_ops: set[int] = set()
    stack = [seed]
    while stack:
        var = stack.pop()
        if var is None or id(var) in seen_vars:
            continue
        seen_vars.add(id(var))
        for op in readers.get(id(var), ()):
            if id(op) in seen_ops:
                continue
            seen_ops.add(id(op))
            if isinstance(op, Binary) and op.operator in _COMPARISON_OPS:
                return True
            if isinstance(op, Condition):
                return True
            if isinstance(op, SolidityCall) and op.function.name in _GUARD_BUILTINS:
                return True
            if op.lvalue is not None:
                stack.append(op.lvalue)
    return False
