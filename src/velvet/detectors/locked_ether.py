"""`locked-ether` detector (spec/detectors-catalog.md §7.15 — normative).

A contract that can receive Ether (a payable function, ``receive`` or a
payable ``fallback``) but has zero Ether-withdrawing operations anywhere in
its code — including inherited functions: no ``transfer``, ``send``, call
carrying value, ``selfdestruct``, or delegated withdrawal.  Every wei sent
to such a contract is locked forever.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.core.variables import Constant
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import (
    HighLevelCall,
    LowLevelCall,
    NewContract,
    Send,
    SolidityCall,
    Transfer,
)


def _is_zero(value: Any) -> bool:
    return isinstance(value, Constant) and str(value.value) in ("0", "0x0")


def _moves_ether_out(op: Any) -> bool:
    """True when the operation can move Ether out of the contract."""
    if isinstance(op, (Transfer, Send)):
        return True
    if isinstance(op, (HighLevelCall, LowLevelCall, NewContract)):
        value = op.call_value
        return value is not None and not _is_zero(value)
    if isinstance(op, SolidityCall) and op.function.name in ("selfdestruct", "suicide"):
        return True
    return False


class LockedEther(Detector):
    """Detect contracts that can receive Ether but never release it."""

    RULE = "locked-ether"
    TITLE = "Contract locks received Ether"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#locked-ether",
        title="Contract locks received Ether",
        description=(
            "The contract can receive Ether through a payable function but "
            "contains no operation that moves Ether out (no transfer, send, "
            "value-carrying call or selfdestruct). Any Ether sent is locked "
            "in the contract forever."
        ),
        exploit_scenario=(
            "TipJar.deposit() is payable and users tip the jar, but no "
            "withdraw function exists; the balance can never be recovered."
        ),
        recommendation=(
            "Add a withdrawal path (transfer/send/call with value or "
            "selfdestruct), or reject incoming Ether."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts_derived:
            if contract.is_interface or contract.is_abstract or contract.is_library:
                continue
            functions = list(contract.available_functions_from_inheritances())
            functions += list(contract.all_modifiers())
            if not any(function.payable for function in functions):
                continue
            seen: set[int] = set()
            releases = False
            for function in functions:
                if id(function) in seen:
                    continue
                seen.add(id(function))
                if any(_moves_ether_out(op) for op in function.all_ir_operations):
                    releases = True
                    break
            if releases:
                continue
            results.append(
                self.finding(
                    [
                        contract,
                        " can receive Ether but contains no Ether-withdrawing"
                        " operation; received Ether is locked forever",
                    ]
                )
            )
        return results
