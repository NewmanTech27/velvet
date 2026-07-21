"""`var-read-using-this` detector (spec/detectors-catalog.md §9.6 —
normative).

Flags reads of the contract's own public state variables through the
external getter (``this.myVar()`` / ``this.myMap(k)``): that performs a
real ``STATICCALL`` to itself — far more expensive than reading the
state variable directly.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.variables import SolidityVariable
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import HighLevelCall, LibraryCall


def _is_this(variable: object) -> bool:
    return isinstance(variable, SolidityVariable) and variable.name == "this"


class VarReadUsingThis(Detector):
    """Detect reads of own public state via ``this.<var>()``."""

    RULE = "var-read-using-this"
    TITLE = "Public state variable read through this.<getter>()"
    IMPACT = Impact.OPTIMIZATION
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#var-read-using-this",
        title="Public state variable read through this.<getter>()",
        description=(
            "The contract reads its own public state variable through an "
            "external getter call (this.myVar() / this.myMap(k)); that "
            "performs a real STATICCALL to itself, far more expensive "
            "than reading the state variable directly."
        ),
        exploit_scenario=(
            "Ledger.myBalance() returns this.balanceOf(msg.sender): "
            "every call pays for an external self-call (address warm/cold "
            "access, call overhead) instead of one SLOAD."
        ),
        recommendation=(
            "Read the state variable directly (balanceOf[msg.sender])."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts_derived:
            getter_names = {
                variable.name
                for variable in contract.state_variables_ordered
                if variable.visibility == "public"
            }
            if not getter_names:
                continue
            seen_functions: set[int] = set()
            for function in contract.available_functions_from_inheritances():
                if id(function) in seen_functions or not function.is_implemented:
                    continue
                seen_functions.add(id(function))
                for node in function.nodes:
                    for op in node.ir_operations:
                        if not isinstance(op, HighLevelCall) or isinstance(
                            op, LibraryCall
                        ):
                            continue
                        if op.function_name not in getter_names:
                            continue
                        if not _is_this(op.destination):
                            continue
                        results.append(
                            self.finding(
                                [
                                    node,
                                    f" reads public state variable "
                                    f"{op.function_name} through an "
                                    "external call to this in ",
                                    function,
                                    "; read the state variable directly",
                                ]
                            )
                        )
        return results
