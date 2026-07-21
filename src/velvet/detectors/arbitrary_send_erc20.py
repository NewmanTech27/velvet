"""`arbitrary-send-erc20` detector (spec/detectors-catalog.md §4.1 —
normative).

Flags ERC-20 ``transferFrom(from, to, amount)`` calls whose ``from``
argument is not constrained to ``msg.sender``: the argument is
function-locally tainted (parameter or otherwise caller-controlled) or
reads caller-controlled state.  If any user approved this contract, an
attacker can pass that user's address as ``from`` and steal their tokens.

Two catalog-faithful exclusions keep the confidence high:

- **Self-implementation** — the call sits inside the contract's own
  ``transferFrom`` implementation and ``from`` is that function's own
  first parameter.  The enclosing override is itself governed by
  allowance semantics (forwarded ``super`` calls, mock upgrades), so the
  pull is authorized by definition.
- **Properly restricted** — a dominating ``require``/``assert`` in the
  same function ties a source of ``from`` to the caller (``msg.sender``,
  including the OZ ``_msgSender()`` indirection), so the spender is
  explicitly authorized before the pull happens.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Optional

from velvet.analyses.dependency import is_tainted
from velvet.analyses.read_write import expand_read_variables
from velvet.core.cfg_node import CFGNode
from velvet.core.function import FunctionLike
from velvet.core.variables import SolidityVariable, StateVariable, Variable
from velvet.detectors._batch_b_utils import is_user_settable
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import HighLevelCall, InternalCall, SolidityCall

#: Builtins whose success-path continuation implies their argument holds.
_GUARD_BUILTINS = ("require", "assert")

#: Internal helpers that evaluate to the caller address.
_CALLER_HELPERS = ("_msgSender", "msgSender")


def _constrained_to_msg_sender(sources: list[Variable]) -> bool:
    """True when every source of the `from` argument is msg.sender."""
    return bool(sources) and all(
        isinstance(var, SolidityVariable) and var.name == "msg.sender"
        for var in sources
    )


def _enclosing_is_transfer_from(
    function: FunctionLike, from_sources: list[Variable]
) -> bool:
    """True when the enclosing function is itself a ``transferFrom``
    implementation and ``from`` is its own first parameter.

    Overrides forwarding to ``super`` (or to another module's
    implementation) re-enter ``transferFrom`` with the same ``from`` the
    outer call already authorized through its allowance check.
    """
    if function.name != "transferFrom":
        return False
    parameters = list(function.parameters)
    if not parameters:
        return False
    first = parameters[0]
    return any(var is first for var in from_sources)


def _dominators(function: FunctionLike) -> dict[int, set[int]]:
    """Reflexive dominator sets over the function's (composed) CFG."""
    nodes = list(function.all_nodes)
    universe = {id(node) for node in nodes}
    dom: dict[int, set[int]] = {node_id: set(universe) for node_id in universe}

    def preds(node: CFGNode) -> list[CFGNode]:
        return [p for p in node.predecessors if id(p) in universe]

    roots = [node for node in nodes if not preds(node)]
    for node in roots:
        dom[id(node)] = {id(node)}
    changed = True
    while changed:
        changed = False
        for node in nodes:
            pred_list = preds(node)
            if not pred_list:
                continue
            current = {id(node)} | set.intersection(
                *(dom[id(p)] for p in pred_list)
            )
            if current != dom[id(node)]:
                dom[id(node)] = current
                changed = True
    return dom


def _guard_involves_caller(
    values: list[Any], function: FunctionLike
) -> tuple[list[Variable], bool]:
    """Expand guard values to sources; also report caller involvement.

    Like :func:`expand_read_variables`, but an internal call to a caller
    helper (OZ-style ``_msgSender()``) is recognized as ``msg.sender``.
    """
    defining: dict[int, Any] = {}
    for node in function.all_nodes:
        for op in node.ir_operations:
            if op.lvalue is not None:
                defining[id(op.lvalue)] = op

    sources: list[Variable] = []
    involves_caller = False
    seen: set[int] = set()
    stack = list(values)
    while stack:
        var = stack.pop()
        if var is None or id(var) in seen:
            continue
        seen.add(id(var))
        origin = getattr(var, "non_ssa_version", None) or var
        if isinstance(origin, SolidityVariable) and origin.name == "msg.sender":
            involves_caller = True
        op = defining.get(id(var)) or defining.get(id(origin))
        if op is None:
            if isinstance(origin, Variable) and not any(
                v is origin for v in sources
            ):
                sources.append(origin)
            continue
        if isinstance(op, InternalCall) and op.function_name in _CALLER_HELPERS:
            involves_caller = True
            continue
        stack.extend(op.read)
    return sources, involves_caller


def _from_provably_authorized(
    function: FunctionLike,
    call_node: CFGNode,
    call_index: int,
    from_sources: list[Variable],
    dominators: Optional[dict[int, set[int]]] = None,
) -> bool:
    """True when a dominating require/assert ties ``from`` to the caller.

    Recognizes ``require(from == msg.sender)`` (and the ``_msgSender()``
    spelling): a source of the ``from`` argument and the caller must both
    feed a guard that dominates the ``transferFrom`` call.
    """
    if dominators is None:
        dominators = _dominators(function)
    from_ids = {id(var) for var in from_sources}
    for node in function.all_nodes:
        for index, op in enumerate(node.ir_operations):
            if not (
                isinstance(op, SolidityCall)
                and op.function.name in _GUARD_BUILTINS
                and op.arguments
            ):
                continue
            # The guard must dominate the call (earlier op on the same node).
            if node is call_node and index >= call_index:
                continue
            if node is not call_node and id(node) not in dominators.get(
                id(call_node), set()
            ):
                continue
            guard_sources, involves_caller = _guard_involves_caller(
                list(op.arguments), function
            )
            if not involves_caller:
                continue
            if any(id(var) in from_ids for var in guard_sources):
                return True
    return False


class ArbitrarySendErc20(Detector):
    """Detect transferFrom with an arbitrary `from` address."""

    RULE = "arbitrary-send-erc20"
    TITLE = "transferFrom uses an arbitrary from address"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#arbitrary-send-erc20",
        title="transferFrom uses an arbitrary from address",
        description=(
            "An ERC-20 transferFrom whose from argument is not msg.sender "
            "lets an attacker spend any allowance users granted the "
            "contract, stealing their tokens."
        ),
        exploit_scenario=(
            "forward(token, holder, amount) calls "
            "token.transferFrom(holder, msg.sender, amount); the attacker "
            "passes a victim who previously approved the contract as holder "
            "and receives the victim's tokens."
        ),
        recommendation=(
            "Always use msg.sender as the from argument of transferFrom (or "
            "use permit-style signatures that authorize the spender "
            "explicitly)."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen_functions: set[int] = set()
        dominators_by_function: dict[int, dict[int, set[int]]] = {}
        for contract in self.compilation_unit.contracts_derived:
            functions = list(contract.available_functions_from_inheritances())
            functions += list(contract.all_modifiers())
            for function in functions:
                if id(function) in seen_functions:
                    continue
                seen_functions.add(id(function))
                for node in function.all_nodes:
                    for index, op in enumerate(node.ir_operations):
                        if not (
                            isinstance(op, HighLevelCall)
                            and op.function_name == "transferFrom"
                            and op.arguments
                        ):
                            continue
                        from_arg = op.arguments[0]
                        sources = expand_read_variables([from_arg], function)
                        if _constrained_to_msg_sender(sources):
                            continue
                        # The contract's own transferFrom implementation:
                        # `from` is its first parameter, governed by the
                        # enclosing allowance semantics.
                        if _enclosing_is_transfer_from(function, sources):
                            continue
                        controlled = is_tainted(from_arg, function)
                        if not controlled:
                            # Caller-controlled state (e.g. an address anyone
                            # can set) is arbitrary as well.
                            controlled = any(
                                isinstance(var, StateVariable)
                                and is_user_settable(var, contract)
                                for var in sources
                            )
                        if not controlled:
                            continue
                        # Properly restricted: a dominating require/assert
                        # ties `from` to the caller.
                        dominators = dominators_by_function.setdefault(
                            id(function), _dominators(function)
                        )
                        if _from_provably_authorized(
                            function, node, index, sources, dominators
                        ):
                            continue
                        results.append(
                            self.finding(
                                [
                                    node,
                                    " calls transferFrom with an "
                                    "arbitrary from address in ",
                                    function,
                                    "; use msg.sender instead",
                                ]
                            )
                        )
        return results
