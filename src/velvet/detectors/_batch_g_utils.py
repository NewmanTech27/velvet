"""Shared helpers for detector batch G (array/assembly, constant-condition,
deprecated-syntax, enum/event, initializer and using-for rules).

Building on the core model, the expression trees and the plain SolIR these
helpers provide:

- :func:`compiled_before` — solc-version gate for compiler-bug detectors;
- :func:`assembly_block_sources` — raw text of a function's assembly blocks
  (assembly is opaque in the IR, so source text is scanned, like the
  ``incorrect-shift`` detector does);
- :func:`strip_comments_and_strings` — normalize source text before lexical
  token scans;
- :func:`internal_callers` — functions that invoke a given internal
  function (used to tell "helper called from elsewhere" apart from the
  outermost execution context);
- :func:`fold_expression_int` — a small constant folder over *expression
  trees* (complementing the IR-level :func:`constant_value` of batch E);
- :func:`iter_state_variable_initializers` — ``(contract, variable)`` pairs
  having an inline initializer expression.

Original clean-room implementation.
"""

from __future__ import annotations

import re
from typing import Any, Iterator, Optional

from packaging.version import Version

from velvet.core.cfg_node import CFGNode, NodeKind
from velvet.core.contract import Contract
from velvet.core.expressions import (
    BinaryOperation,
    Expression,
    Identifier,
    Literal,
    TupleExpression,
    UnaryOperation,
)
from velvet.core.function import FunctionLike
from velvet.core.variables import StateVariable
from velvet.detectors._versions import parse_solc_version
from velvet.ir.operations import InternalCall

# ------------------------------------------------------------------ versions


def compiled_before(unit: Any, ceiling: str) -> bool:
    """True when the unit was compiled with a solc older than ``ceiling``."""
    parsed = parse_solc_version(getattr(unit, "solc_version", "") or "")
    if parsed is None:
        return False
    return parsed < Version(ceiling)


# ----------------------------------------------------------------- assembly


def assembly_block_sources(function: FunctionLike) -> Iterator[tuple[CFGNode, str]]:
    """Yield ``(node, raw source text)`` for each assembly block of ``function``."""
    for node in function.nodes:
        if node.kind is not NodeKind.ASSEMBLY:
            continue
        mapping = node.source_mapping
        content = mapping.content if mapping is not None else ""
        if content:
            yield node, content


# ------------------------------------------------------------------ lexical

_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def strip_comments_and_strings(source: str) -> str:
    """Blank out comments and string-literal contents from ``source``.

    String literals are replaced by empty quotes so token scans never fire
    on commented-out code or on text inside string literals.
    """
    text = _BLOCK_COMMENT_RE.sub("", source)
    text = _LINE_COMMENT_RE.sub("", text)
    return _STRING_RE.sub('""', text)


# --------------------------------------------------------------------- calls


def internal_callers(unit: Any, target: FunctionLike) -> list[FunctionLike]:
    """Functions/modifiers of ``unit`` that internally call ``target``."""
    callers: list[FunctionLike] = []
    for function in unit.functions_and_modifiers:
        if function is target:
            continue
        if any(
            isinstance(op, InternalCall) and op.function is target
            for op in function.all_ir_operations
        ):
            callers.append(function)
    return callers


# -------------------------------------------------------- constant folding

_INT_LITERAL_RE = re.compile(r"^(0x[0-9a-fA-F_]+|[0-9][0-9_]*)$")

#: Bounds that keep the folder from materialising astronomically large ints.
_MAX_EXPONENT = 512
_MAX_SHIFT = 4096


def _parse_int_literal(text: str) -> Optional[int]:
    cleaned = text.strip().replace("_", "")
    if not _INT_LITERAL_RE.match(cleaned):
        return None
    try:
        return int(cleaned, 0)
    except ValueError:
        return None


def _apply_int_binop(operator: str, left: int, right: int) -> Optional[int]:
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
        if operator == "&":
            return left & right
        if operator == "|":
            return left | right
        if operator == "^":
            return left ^ right
    except (OverflowError, ValueError):
        return None
    return None


def fold_expression_int(
    expression: Optional[Expression],
    *,
    _depth: int = 0,
    _seen: Optional[set[int]] = None,
) -> Optional[int]:
    """Fold an expression tree to an ``int`` when it is a compile-time
    integer constant, else ``None``.

    Handles integer literals (decimal/hex, ``_`` separators), unary
    ``+``/``-``, arithmetic/bitwise binary operations, single-element
    parenthesized tuples, and references to ``constant`` state variables
    (folded through their own initializer, cycle-guarded).
    """
    if expression is None or _depth > 32:
        return None
    if _seen is None:
        _seen = set()
    if id(expression) in _seen:
        return None
    _seen.add(id(expression))
    if isinstance(expression, Literal):
        return _parse_int_literal(expression.value)
    if isinstance(expression, TupleExpression):
        parts = [e for e in expression.expressions if e is not None]
        if len(parts) == 1:
            return fold_expression_int(parts[0], _depth=_depth + 1, _seen=_seen)
        return None
    if isinstance(expression, UnaryOperation) and expression.is_prefix:
        operand = fold_expression_int(
            expression.expression, _depth=_depth + 1, _seen=_seen
        )
        if operand is None:
            return None
        if expression.operator == "-":
            return -operand
        if expression.operator == "+":
            return operand
        if expression.operator == "~":
            return ~operand
        return None
    if isinstance(expression, BinaryOperation):
        left = fold_expression_int(
            expression.expression_left, _depth=_depth + 1, _seen=_seen
        )
        right = fold_expression_int(
            expression.expression_right, _depth=_depth + 1, _seen=_seen
        )
        if left is None or right is None:
            return None
        return _apply_int_binop(expression.operator, left, right)
    if isinstance(expression, Identifier) and isinstance(expression.value, StateVariable):
        variable = expression.value
        if not variable.is_constant or id(variable) in _seen:
            return None
        _seen.add(id(variable))
        return fold_expression_int(
            variable.expression_initial, _depth=_depth + 1, _seen=_seen
        )
    return None


# ------------------------------------------------------------ initializers


def iter_state_variable_initializers(unit: Any) -> Iterator[tuple[Contract, StateVariable]]:
    """Yield ``(contract, variable)`` for state variables with an inline
    initializer expression."""
    for contract in unit.contracts:
        for variable in contract.state_variables:
            if variable.expression_initial is not None:
                yield contract, variable
