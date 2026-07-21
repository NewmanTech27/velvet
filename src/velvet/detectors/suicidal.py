"""`suicidal` detector (spec/detectors-catalog.md §2.1 — normative).

Flags public/external functions reachable by an arbitrary caller (no
``msg.sender`` check on the entry function, and none inside the
selfdestruct-hosting helper) that lead to execution of
``selfdestruct``/``suicide`` (SWC-106).

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.core.cfg_node import CFGNode
from velvet.core.function import FunctionLike
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import SolidityCall

_SELFDESTRUCT_BUILTINS = ("selfdestruct", "suicide")


def _selfdestruct_nodes(function: FunctionLike) -> list[CFGNode]:
    """Nodes of the function (incl. applied modifiers) running selfdestruct."""
    nodes: list[CFGNode] = []
    for node in function.all_nodes:
        for op in node.ir_operations:
            if (
                isinstance(op, SolidityCall)
                and op.function.name in _SELFDESTRUCT_BUILTINS
            ):
                nodes.append(node)
                break
    return nodes


class Suicidal(Detector):
    """Detect unprotected selfdestruct reachable by any caller."""

    RULE = "suicidal"
    TITLE = "Unprotected selfdestruct (any caller can destroy the contract)"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#suicidal",
        title="Unprotected selfdestruct",
        description=(
            "A function that any user can call leads to execution of "
            "selfdestruct, letting anyone destroy the contract and "
            "force-send its balance (SWC-106)."
        ),
        exploit_scenario=(
            "Game.reset executes selfdestruct(owner) without any "
            "authorization check; a griefer calls reset and force-sends the "
            "contract's balance, bricking the application."
        ),
        recommendation=(
            "Restrict destruction to a privileged account (e.g. onlyOwner) "
            "or remove selfdestruct entirely. Post-Cancun it still moves "
            "the balance even though it no longer removes code outside the "
            "creation transaction."
        ),
    )

    def _unprotected_hits(
        self, function: FunctionLike
    ) -> list[tuple[CFGNode, FunctionLike]]:
        """(selfdestruct node, hosting function) reachable without a guard."""
        hits: list[tuple[CFGNode, FunctionLike]] = [
            (node, function) for node in _selfdestruct_nodes(function)
        ]
        for target in function.all_internal_calls_reachable:
            # A guard inside the hosting helper still protects the path.
            if target.is_protected:
                continue
            hits.extend((node, target) for node in _selfdestruct_nodes(target))
        return hits

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts_derived:
            if contract.is_interface or contract.is_library:
                continue
            for function in contract.available_functions_from_inheritances():
                if function.visibility not in ("external", "public"):
                    continue
                if function.is_constructor or not function.is_implemented:
                    continue
                if function.is_protected:
                    continue
                seen: set[int] = set()
                for node, host in self._unprotected_hits(function):
                    if id(node) in seen:
                        continue
                    seen.add(id(node))
                    elements: list[Any] = [node, " executes selfdestruct"]
                    if host is not function:
                        elements += [" via ", host]
                    elements += [
                        ", reachable by any caller through unprotected ",
                        function,
                    ]
                    results.append(self.finding(elements))
        return results
