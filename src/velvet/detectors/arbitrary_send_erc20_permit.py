"""`arbitrary-send-erc20-permit` detector (spec/detectors-catalog.md §4.2 —
normative).

Flags an ERC-20 ``permit(...)`` call followed (in the same function) by a
``transferFrom`` whose ``from`` argument is caller-controlled and not
constrained to ``msg.sender``.  ``permit`` grants an allowance to the
contract, but it does not by itself constrain whose tokens are pulled: any
holder who ever signed a permit for this contract can be drained by an
attacker supplying that holder's address as ``from``.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.analyses.dependency import is_tainted
from velvet.analyses.read_write import expand_read_variables
from velvet.core.cfg_node import CFGNode
from velvet.core.variables import SolidityVariable, StateVariable, Variable
from velvet.detectors._batch_b_utils import is_user_settable
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import HighLevelCall


def _constrained_to_msg_sender(sources: list[Variable]) -> bool:
    """True when every source of the ``from`` argument is ``msg.sender``."""
    return bool(sources) and all(
        isinstance(var, SolidityVariable) and var.name == "msg.sender"
        for var in sources
    )


def _nodes_reaching(target: CFGNode) -> set[int]:
    """Ids of nodes that can reach ``target`` (including ``target``)."""
    reached: set[int] = set()
    stack = [target]
    while stack:
        node = stack.pop()
        if id(node) in reached:
            continue
        reached.add(id(node))
        stack.extend(node.predecessors)
    return reached


class ArbitrarySendErc20Permit(Detector):
    """Detect transferFrom with arbitrary from after an ERC-20 permit call."""

    RULE = "arbitrary-send-erc20-permit"
    TITLE = "transferFrom with arbitrary from after permit"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#arbitrary-send-erc20-permit",
        title="transferFrom with arbitrary from after permit",
        description=(
            "A function calls an ERC-20 permit and then transferFrom with a "
            "from address that is not msg.sender. permit authorizes the "
            "spender but does not bind whose tokens are pulled, so an "
            "attacker can drain any holder who signed a permit for the "
            "contract."
        ),
        exploit_scenario=(
            "depositWithPermit(token, owner, ...) calls "
            "token.permit(owner, address(this), ...) and then "
            "token.transferFrom(owner, address(this), amount); the attacker "
            "passes a victim who previously signed a permit as owner and "
            "receives the victim's tokens."
        ),
        recommendation=(
            "Use msg.sender as the from argument of transferFrom after a "
            "permit, or authenticate the permit signer and the transferFrom "
            "from address."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen_functions: set[int] = set()
        for contract in self.compilation_unit.contracts_derived:
            functions = list(contract.available_functions_from_inheritances())
            functions += list(contract.all_modifiers())
            for function in functions:
                if id(function) in seen_functions:
                    continue
                seen_functions.add(id(function))
                permit_calls: list[tuple[CFGNode, int]] = []
                pull_calls: list[tuple[CFGNode, int, HighLevelCall]] = []
                for node in function.all_nodes:
                    for idx, op in enumerate(node.ir_operations):
                        if not isinstance(op, HighLevelCall):
                            continue
                        if op.function_name == "permit":
                            permit_calls.append((node, idx))
                        elif op.function_name == "transferFrom" and op.arguments:
                            pull_calls.append((node, idx, op))
                if not permit_calls or not pull_calls:
                    continue
                for node, idx, op in pull_calls:
                    from_arg = op.arguments[0]
                    sources = expand_read_variables([from_arg], function)
                    if _constrained_to_msg_sender(sources):
                        continue
                    controlled = is_tainted(from_arg, function) or any(
                        isinstance(var, StateVariable)
                        and is_user_settable(var, contract)
                        for var in sources
                    )
                    if not controlled:
                        continue
                    if not self._preceded_by_permit(permit_calls, node, idx):
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                " calls transferFrom with an arbitrary from"
                                " address after an ERC-20 permit call in ",
                                function,
                                "; bind the transfer to msg.sender instead",
                            ]
                        )
                    )
        return results

    @staticmethod
    def _preceded_by_permit(
        permit_calls: list[tuple[CFGNode, int]], node: CFGNode, idx: int
    ) -> bool:
        """True when a permit call may execute before the transferFrom."""
        upstream = _nodes_reaching(node)
        for permit_node, permit_idx in permit_calls:
            if id(permit_node) not in upstream:
                continue
            if permit_node is node and permit_idx >= idx:
                continue
            return True
        return False
