"""`unimplemented-functions` detector (spec/detectors-catalog.md §8.14 —
normative).

Flags a most-derived contract that is *not* marked ``abstract`` in its
source yet leaves inherited interface/abstract functions without an
implementation.  Modern solc rejects the pattern at compile time, but in
older codebases (pre-0.6, where contracts were implicitly abstract) it
reveals incomplete implementation intent.

The parser folds solc's ``fullyImplemented`` flag into the contract kind,
so source text is consulted to tell a deliberate ``abstract`` keyword
(the documented remediation) apart from an accidental omission.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_h_utils import declared_abstract
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class UnimplementedFunctions(Detector):
    """Detect non-abstract contracts leaving base functions unimplemented."""

    RULE = "unimplemented-functions"
    TITLE = "Contract leaves inherited functions unimplemented"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#unimplemented-functions",
        title="Contract leaves inherited functions unimplemented",
        description=(
            "A most-derived contract that is not marked abstract inherits "
            "functions (from interfaces or abstract bases) for which no "
            "implementation exists; the deployment cannot succeed and the "
            "omission reveals incomplete implementation intent."
        ),
        exploit_scenario=(
            "contract Token is IERC20Minimal implements totalSupply() "
            "but not transfer(): on pre-0.6 compilers the contract is "
            "silently abstract — it compiles but can never be deployed."
        ),
        recommendation=(
            "Implement every inherited function, or mark the contract "
            "abstract."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts_derived:
            if contract.is_interface or contract.is_library:
                continue
            missing = [
                function
                for function in contract.available_functions_from_inheritances()
                if not function.is_implemented and not function.is_constructor
            ]
            if not missing:
                continue
            if declared_abstract(self.compilation_unit, contract):
                # Deliberate: the source already says `abstract`.
                continue
            names = ", ".join(function.name for function in missing)
            results.append(
                self.finding(
                    [
                        contract,
                        " is not marked abstract but leaves inherited "
                        f"function(s) unimplemented: {names}",
                    ]
                )
            )
        return results
