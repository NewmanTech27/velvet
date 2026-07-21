"""Shared helpers for detector batch H (loop value accounting, balance
deltas, assembly source checks, constructor graph and event/interface
rules).

Building on the core model these helpers provide:

- :func:`source_slice` — the exact source text covered by a model object's
  source mapping (detectors that must inspect opaque syntax — inline
  assembly blocks, the ``abstract`` keyword — use it);
- :func:`declared_abstract` — whether a contract's source declaration
  carries the ``abstract`` keyword (the parser folds
  "not fully implemented" into the ABSTRACT kind, so the source keyword
  must be checked to tell deliberate abstractness apart);
- :func:`expression_has_side_effect` — purity check over the surface
  expression tree (used to spot statements that compute nothing);
- :func:`literal_address` — normalize a literal/constant payload to an int
  (used to recognize well-known predeploy addresses).

Original clean-room implementation.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from velvet.core.expressions import (
    AssignmentOperation,
    CallExpression,
    ConditionalExpression,
    Identifier,
    IndexAccess,
    Literal,
    MemberAccess,
    NewExpression,
    TupleExpression,
    TypeConversion,
    UnaryOperation,
)

# ------------------------------------------------------------------ sources


def _sources_by_file(unit: Any) -> dict[str, str]:
    """``absolute filename -> source text`` for the compilation."""
    sources: dict[str, str] = {}
    compilation = getattr(unit, "compilation", None)
    for info in getattr(compilation, "source_units", {}).values():
        filename = getattr(info, "filename", None)
        if filename is not None and getattr(info, "source", None) is not None:
            sources.setdefault(filename.absolute, info.source)
    return sources


def source_slice(unit: Any, source_mapping: Any) -> Optional[str]:
    """Exact source text covered by ``source_mapping`` (None when unknown).

    solc source offsets are *byte* offsets into the UTF-8 file, so the
    slice is taken on the encoded source and decoded back tolerantly.
    """
    if source_mapping is None or source_mapping.filename is None:
        return None
    source = _sources_by_file(unit).get(source_mapping.filename.absolute)
    if source is None:
        return None
    start = source_mapping.start or 0
    length = source_mapping.length or 0
    if length <= 0:
        return None
    raw = source.encode("utf-8")[start : start + length]
    return raw.decode("utf-8", errors="ignore")


_ABSTRACT_RE = re.compile(r"^\s*abstract\b")


def declared_abstract(unit: Any, contract: Any) -> bool:
    """True when the contract's *source* declares it ``abstract``.

    The parser marks a contract ABSTRACT both for the source keyword and
    for ``fullyImplemented == false`` reported by solc; detectors that
    must distinguish deliberate abstractness (the documented remediation)
    from accidental missing implementations need this source-level check.
    """
    text = source_slice(unit, contract.source_mapping)
    return bool(text and _ABSTRACT_RE.match(text))


# ------------------------------------------------------------------ purity

#: Unary operators that mutate their operand.
_MUTATING_UNARY = {"++", "--", "delete"}


def expression_has_side_effect(expression: Any, *, _depth: int = 0) -> bool:
    """True when the expression tree may change state or consume gas I/O.

    Calls, assignments, ``new`` expressions and mutating unary operators
    (``++``/``--``/``delete``) are side effects; arithmetic, comparisons,
    indexing, member reads, conversions and tuples built from pure
    subexpressions are not.
    """
    if expression is None or _depth > 32:
        return False
    if isinstance(expression, (Literal, Identifier)):
        return False
    if isinstance(expression, (AssignmentOperation, CallExpression, NewExpression)):
        return True
    if isinstance(expression, UnaryOperation):
        if expression.operator in _MUTATING_UNARY:
            return True
        return expression_has_side_effect(expression.expression, _depth=_depth + 1)
    if isinstance(expression, ConditionalExpression):
        return any(
            expression_has_side_effect(part, _depth=_depth + 1)
            for part in (
                expression.condition,
                expression.then_expression,
                expression.else_expression,
            )
        )
    if isinstance(expression, TypeConversion):
        return expression_has_side_effect(expression.expression, _depth=_depth + 1)
    if isinstance(expression, IndexAccess):
        return expression_has_side_effect(
            expression.expression_left, _depth=_depth + 1
        ) or expression_has_side_effect(expression.expression_right, _depth=_depth + 1)
    if isinstance(expression, MemberAccess):
        return expression_has_side_effect(expression.expression, _depth=_depth + 1)
    if isinstance(expression, TupleExpression):
        return any(
            expression_has_side_effect(part, _depth=_depth + 1)
            for part in expression.expressions
            if part is not None
        )
    # BinaryOperation and anything else with subexpressions: check the
    # generic left/right slots when present.
    left = getattr(expression, "expression_left", None)
    right = getattr(expression, "expression_right", None)
    return expression_has_side_effect(left, _depth=_depth + 1) or (
        expression_has_side_effect(right, _depth=_depth + 1)
    )


# ----------------------------------------------------------------- literals


def literal_address(value: Any) -> Optional[int]:
    """Normalize a literal/constant payload to an int address, else None."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        pass
    try:
        return int(text, 10)
    except ValueError:
        return None
