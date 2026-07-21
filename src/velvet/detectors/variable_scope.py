"""`variable-scope` detector (spec/detectors-catalog.md §7.33 —
normative).

Flags a local variable read on a control-flow path where its declaration
statement has not been executed: declared later in the same block, or
declared only inside a conditional/sibling scope.  Pre-0.5.0 scoping
rules accept such code; the use then observes the zero value rather than
the value the author expected.

The check is a graph query: a use is flagged when the function's entry
can reach it without passing through the variable's declaration node
(the declaration does not dominate the use).

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterator

from velvet.core.cfg_node import CFGNode
from velvet.core.function import FunctionLike
from velvet.core.variables import LocalVariable
from velvet.detectors._batch_e_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.variables import ReferenceVariable, root_base


def _origin(variable: Any) -> Any:
    return getattr(variable, "non_ssa_version", None) or variable


def _read_locals(function: FunctionLike) -> Iterator[tuple[CFGNode, LocalVariable]]:
    """(node, local) pairs: each local variable read per node."""
    for node in function.nodes:
        reported: set[int] = set()
        for op in node.ir_operations:
            for variable in op.read:
                candidates = [variable]
                if isinstance(variable, ReferenceVariable):
                    candidates.append(root_base(variable))
                for candidate in candidates:
                    origin = _origin(candidate)
                    if not isinstance(origin, LocalVariable):
                        continue
                    if id(origin) in reported:
                        continue
                    reported.add(id(origin))
                    yield node, origin


def _reachable_without(function: FunctionLike, blocked: CFGNode) -> set[int]:
    """Node ids reachable from the entry without crossing ``blocked``."""
    entry = function.entry_point
    if entry is None:
        return set()
    seen: set[int] = set()
    stack: list[CFGNode] = [] if entry is blocked else [entry]
    while stack:
        node = stack.pop()
        if id(node) in seen or node is blocked:
            continue
        seen.add(id(node))
        stack.extend(node.successors)
    return seen


class VariableScope(Detector):
    """Detect locals used where their declaration has not executed."""

    RULE = "variable-scope"
    TITLE = "Local variable used before its declaration is executed"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#variable-scope",
        title="Local variable used before its declaration is executed",
        description=(
            "A local variable is referenced on a path where its "
            "declaration statement has not run — declared later in the "
            "same block, or only inside a conditional/sibling scope; the "
            "use observes the zero value (or an unintended binding) "
            "instead of the expected one."
        ),
        exploit_scenario=(
            "f() computes uint256 result = bonus + 1; before uint256 "
            "bonus = 5; is declared (legal under pre-0.5.0 scoping): "
            "result is 1, not 6."
        ),
        recommendation=(
            "Declare variables before first use; hoist declarations out "
            "of conditional scopes when the variable is used "
            "unconditionally."
        ),
    )

    def _analyze_function(self, function: FunctionLike) -> Iterator[Finding]:
        declarations: dict[int, tuple[LocalVariable, CFGNode]] = {}
        for node in function.nodes:
            declared = node.variable_declaration
            if isinstance(declared, LocalVariable):
                declarations.setdefault(id(_origin(declared)), (declared, node))
        if not declarations:
            return
        reachability: dict[int, set[int]] = {}
        reported_vars: set[int] = set()
        for node, local in _read_locals(function):
            entry = declarations.get(id(local))
            if entry is None:
                continue  # parameter/return/synthesized: declared at entry
            declaration, decl_node = entry
            if decl_node is node:
                continue  # the declaration statement itself
            if id(local) in reported_vars:
                continue
            if id(decl_node) not in reachability:
                reachability[id(decl_node)] = _reachable_without(
                    function, decl_node
                )
            if id(node) not in reachability[id(decl_node)]:
                continue  # every path to the use executed the declaration
            reported_vars.add(id(local))
            yield self.finding(
                [
                    node,
                    " reads ",
                    declaration,
                    " before its declaration is executed in ",
                    function,
                    "; the use observes the zero value",
                ]
            )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            if not function.is_implemented:
                continue
            results.extend(self._analyze_function(function))
        return results
