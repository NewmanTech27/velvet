"""Protected-function heuristic (spec/architecture.md §7.2).

A function is heuristically **protected** when the caller address
(``msg.sender``) is directly involved in a guard — a condition of an
``if``/loop, a ``require``/``assert``, or a modifier check — or when the
function is a constructor.  The heuristic trades a small number of false
positives/negatives for large precision gains; detectors use it to
suppress findings in owner-only functions.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.function import FunctionLike
from velvet.core.variables import SolidityVariable
from velvet.ir.operations import Condition, SolidityCall
from velvet.analyses.read_write import expand_read_variables

_GUARD_BUILTINS = ("require", "assert")


def _involves_msg_sender(variables: list[object], function: FunctionLike) -> bool:
    for var in expand_read_variables(variables, function):
        if isinstance(var, SolidityVariable) and var.name == "msg.sender":
            return True
    return False


def is_protected(function: FunctionLike) -> bool:
    """True when the function is guarded by an explicit msg.sender check."""
    if function.is_constructor:
        return True
    for node in function.all_nodes:  # includes applied modifiers' bodies
        for op in node.ir_operations:
            if isinstance(op, Condition) and _involves_msg_sender([op.value], function):
                return True
            if (
                isinstance(op, SolidityCall)
                and op.function.name in _GUARD_BUILTINS
                and _involves_msg_sender(op.arguments, function)
            ):
                return True
    return False
