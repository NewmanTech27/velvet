"""`incorrect-modifier` detector (spec/detectors-catalog.md §7.29 —
normative).

Flags modifiers with a control-flow path that neither executes the
placeholder ``_`` nor reverts: on that path the modified function's body
is silently skipped and the function returns default values, so callers
cannot distinguish "denied" from "returned 0".

The ``_`` placeholder carries no CFG node in the core model, so the path
analysis runs on the modifier's syntax tree (kept in the compilation
artifacts) and classifies every statement by whether control can pass it
without a placeholder/revert and whether it can ``return`` early.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Optional

from velvet.core.function import Modifier
from velvet.detectors._batch_e_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

_PASSTHROUGH = (True, False)  # control passes, no placeholder/revert/return
_STOP = (False, False)  # every path hits `_` or reverts


def _src_start(ast_node: dict[str, Any]) -> Optional[int]:
    src = ast_node.get("src")
    if not isinstance(src, str):
        return None
    try:
        return int(src.split(":")[0])
    except (ValueError, IndexError):
        return None


def _is_plain_revert(stmt: dict[str, Any]) -> bool:
    """True for an expression statement that is a bare ``revert(...)` call.

    ``revert("reason")`` reaches the AST as a function-call expression
    (only custom-error reverts become ``RevertStatement``); ``require`` and
    ``assert`` only revert conditionally and are deliberately excluded.
    """
    call = stmt.get("expression")
    if not isinstance(call, dict) or call.get("nodeType") != "FunctionCall":
        return False
    callee = call.get("expression")
    return (
        isinstance(callee, dict)
        and callee.get("nodeType") == "Identifier"
        and callee.get("name") == "revert"
    )


def _stmt_paths(stmt: Optional[dict[str, Any]]) -> tuple[bool, bool]:
    """(falls, returns) outcomes of one modifier-body statement.

    - ``falls``: some path completes the statement *without* having
      executed ``_`` or reverted (unsatisfied control continues).
    - ``returns``: some path executes ``return`` without having executed
      ``_`` or reverted first (the modified function returns early).
    """
    if not isinstance(stmt, dict):
        return _PASSTHROUGH
    kind = stmt.get("nodeType")
    if kind in ("PlaceholderStatement", "RevertStatement", "Throw"):
        return _STOP
    if kind == "ExpressionStatement" and _is_plain_revert(stmt):
        return _STOP
    if kind == "Return":
        return (False, True)
    if kind in ("Break", "Continue"):
        # Loop-local escape: from the modifier's perspective the loop (and
        # possibly the placeholder after it) is simply skipped.
        return _PASSTHROUGH
    if kind in ("Block", "UncheckedBlock"):
        return _seq_paths(stmt.get("statements") or [])
    if kind == "IfStatement":
        true_falls, true_returns = _stmt_paths(stmt.get("trueBody"))
        false_body = stmt.get("falseBody")
        if false_body is None:
            false_falls, false_returns = _PASSTHROUGH
        else:
            false_falls, false_returns = _stmt_paths(false_body)
        return (true_falls or false_falls, true_returns or false_returns)
    if kind in ("WhileStatement", "ForStatement", "DoWhileStatement"):
        _body_falls, body_returns = _stmt_paths(stmt.get("body"))
        # A loop may run zero iterations (or break), so control can always
        # pass it; a `return` inside the body is an early-exit path.
        return (True, body_returns)
    if kind == "TryStatement":
        clauses = stmt.get("clauses") or []
        outcomes = [_stmt_paths(clause.get("block")) for clause in clauses]
        falls = any(outcome[0] for outcome in outcomes) if outcomes else True
        returns = any(outcome[1] for outcome in outcomes)
        return (falls, returns)
    # ExpressionStatement, VariableDeclarationStatement, EmitStatement,
    # InlineAssembly, ... : control passes through.
    return _PASSTHROUGH


def _seq_paths(statements: list[dict[str, Any]]) -> tuple[bool, bool]:
    """Compose statement outcomes over a sequence (see _stmt_paths)."""
    falls, returns = True, False
    for stmt in statements:
        if not falls:
            break  # unsatisfied control cannot reach `stmt` anymore
        stmt_falls, stmt_returns = _stmt_paths(stmt)
        returns = returns or stmt_returns
        falls = stmt_falls
    return (falls, returns)


class IncorrectModifier(Detector):
    """Detect modifiers with a path that skips `_` without reverting."""

    RULE = "incorrect-modifier"
    TITLE = "Modifier path neither executes _ nor reverts"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#incorrect-modifier",
        title="Incorrect modifier",
        description=(
            "A modifier contains a code path that neither executes the "
            "placeholder _ nor reverts; on that path the modified "
            "function's body is silently skipped and the function returns "
            "its default values."
        ),
        exploit_scenario=(
            "modifier onlyIfOwner() { if (msg.sender == owner) { _; } } — "
            "a non-owner call to sensitive() succeeds silently and returns "
            "0 instead of reverting."
        ),
        recommendation=(
            "Make every modifier path either execute _ or revert "
            "(require(cond); _;)."
        ),
    )

    def _ast_index(self) -> dict[tuple[str, int], dict[str, Any]]:
        """``(source path, start offset) -> ModifierDefinition``."""
        index: dict[tuple[str, int], dict[str, Any]] = {}
        artifacts = self.compilation_unit.compilation
        for info in artifacts.source_units.values():
            path = info.filename.absolute
            stack: list[Any] = [info.ast]
            while stack:
                current = stack.pop()
                if isinstance(current, dict):
                    if current.get("nodeType") == "ModifierDefinition":
                        start = _src_start(current)
                        if start is not None:
                            index[(path, start)] = current
                    stack.extend(current.values())
                elif isinstance(current, list):
                    stack.extend(current)
        return index

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        ast_index: Optional[dict[tuple[str, int], dict[str, Any]]] = None
        for function in unique_functions(self.compilation_unit):
            if not isinstance(function, Modifier) or not function.is_implemented:
                continue
            if ast_index is None:
                ast_index = self._ast_index()
            mapping = function.source_mapping
            path = mapping.filename.absolute if mapping.filename else ""
            ast_node = ast_index.get((path, mapping.start))
            if ast_node is None:
                continue
            body = ast_node.get("body")
            statements = body.get("statements") if isinstance(body, dict) else []
            falls, returns = _seq_paths(statements or [])
            if not (falls or returns):
                continue
            results.append(
                self.finding(
                    [
                        function,
                        " has a path that neither executes _ nor reverts; "
                        "the modified function's body is silently skipped "
                        "and default values are returned",
                    ]
                )
            )
        return results
