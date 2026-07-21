"""`controlled-delegatecall` detector (spec/detectors-catalog.md §3.1 —
normative).

Flags ``delegatecall``/``callcode`` whose destination address is tainted by
user input: a value that is function-locally tainted (function parameter or
builtin such as ``msg.sender``) or a state variable that unprotected
external/public functions can set (caller-controlled state).  Fixed or
trusted destinations (constants, immutables, owner-set variables,
``address(this)``) are not reported.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.analyses.dependency import is_tainted
from velvet.core.contract import Contract
from velvet.core.function import FunctionLike
from velvet.core.variables import StateVariable
from velvet.detectors._batch_b_utils import def_chain, is_user_settable
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import LowLevelCall

_DELEGATECALL_NAMES = ("delegatecall", "callcode")


class ControlledDelegatecall(Detector):
    """Detect delegatecall/callcode to a caller-controllable address (SWC-112)."""

    RULE = "controlled-delegatecall"
    TITLE = "Controlled delegatecall destination"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#controlled-delegatecall",
        title="Controlled delegatecall destination",
        description=(
            "delegatecall executes foreign code in the caller's storage and "
            "balance context; a user-chosen destination lets an attacker "
            "overwrite any storage slot, steal funds, or destroy the "
            "contract (SWC-112)."
        ),
        exploit_scenario=(
            "A router exposes exec(address module, bytes data) and runs "
            "module.delegatecall(data); an attacker points module at "
            "malicious code that takes over the contract's storage."
        ),
        recommendation=(
            "Avoid delegatecall to user-supplied addresses; whitelist "
            "implementation addresses or use established proxy patterns with "
            "immutable/trusted targets."
        ),
    )

    def _is_controlled(
        self, op: LowLevelCall, function: FunctionLike, contract: Contract
    ) -> bool:
        # Function-local taint: parameter / msg.sender-derived destination.
        if is_tainted(op.destination, function):
            return True
        # Caller-controlled state: destination reads a state variable that an
        # unprotected external/public function can set.
        variables, _ = def_chain(function, [op.destination])
        for var in variables:
            if isinstance(var, StateVariable) and is_user_settable(var, contract):
                return True
        return False

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
                for node in function.all_nodes:
                    for op in node.ir_operations:
                        if (
                            isinstance(op, LowLevelCall)
                            and op.function_name in _DELEGATECALL_NAMES
                            and self._is_controlled(op, function, contract)
                        ):
                            results.append(
                                self.finding(
                                    [
                                        node,
                                        " performs a delegatecall to a "
                                        "user-controlled destination in ",
                                        function,
                                    ]
                                )
                            )
        return results
