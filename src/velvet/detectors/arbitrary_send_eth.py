"""`arbitrary-send-eth` detector (spec/detectors-catalog.md §2.4 — normative).

Flags unprotected public/external functions that send Ether
(``transfer``/``send``/``call{value: ...}``) to a caller-controllable
destination (a parameter, ``msg.sender``, or state that anyone can set),
letting anyone drain the contract's balance (SWC-105).

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.analyses import is_tainted
from velvet.core.contract import Contract
from velvet.core.function import FunctionLike
from velvet.core.variables import StateVariable
from velvet.detectors._reentrancy_common import (
    expand_terminal_sources,
    sources_statically_trusted,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import (
    HighLevelCall,
    LibraryCall,
    LowLevelCall,
    Send,
    Transfer,
)


def _is_eth_send(op: Any) -> bool:
    if isinstance(op, (Transfer, Send)):
        return True
    if isinstance(op, LibraryCall):
        return False
    if isinstance(op, HighLevelCall):
        return op.call_value is not None
    if isinstance(op, LowLevelCall):
        return op.function_name == "call" and op.call_value is not None
    return False


class ArbitrarySendEth(Detector):
    """Detect Ether sends to caller-controllable destinations."""

    RULE = "arbitrary-send-eth"
    TITLE = "Ether sent to an arbitrary, caller-controllable address"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#arbitrary-send-eth",
        title="Ether sent to an arbitrary address",
        description=(
            "An unprotected function sends Ether to a destination the "
            "caller can choose or influence (SWC-105), so anyone can drain "
            "the contract's balance to themselves."
        ),
        exploit_scenario=(
            "RewardPool.sweep(to, amount) sends Ether to the "
            "caller-supplied address to without any authorization; an "
            "attacker calls it with their own address and empties the pool."
        ),
        recommendation=(
            "Require authorization for withdrawals and send funds only to "
            "addresses with a legitimate claim (pull-over-push payments "
            "with per-account accounting)."
        ),
    )

    def _destination_controllable(
        self, op: Any, function: FunctionLike, contract: Contract
    ) -> bool:
        destination = op.destination
        expanded = expand_terminal_sources([destination], function)
        if sources_statically_trusted(expanded):
            return False
        if is_tainted(destination, function):
            return True
        # A state variable destination anyone can set is controllable too.
        # Immutable/constant variables are fixed at construction and cannot
        # be set by an attacker afterwards, so they stay trusted.
        for var in expanded:
            if not isinstance(var, StateVariable):
                continue
            if var.is_immutable or var.is_constant:
                continue
            if is_tainted(var, contract):
                return True
        return False

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
                for node in function.nodes:
                    for op in node.ir_operations:
                        if not _is_eth_send(op):
                            continue
                        if self._destination_controllable(op, function, contract):
                            results.append(
                                self.finding(
                                    [
                                        node,
                                        " sends Ether to a caller-controllable"
                                        " destination in unprotected ",
                                        function,
                                    ]
                                )
                            )
        return results
