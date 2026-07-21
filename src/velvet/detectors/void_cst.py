"""`void-cst` detector (spec/detectors-catalog.md §7.34 — normative).

Flags constructors that explicitly invoke a base constructor that does not
exist / has no implementation (e.g. ``constructor() A() {}`` where ``A``
defines no constructor).  The call suggests initialization happens, but
nothing runs — misleading to reviewers.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.contract import Contract
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


def _has_explicit_constructor(contract: Contract) -> bool:
    """True when ``contract`` defines a constructor of its own."""
    return any(f.is_constructor for f in contract.functions)


class VoidCst(Detector):
    """Detect explicit calls to non-existent base constructors."""

    RULE = "void-cst"
    TITLE = "Explicit call to a base constructor that does nothing"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#void-cst",
        title="Explicit call to a base constructor that does nothing",
        description=(
            "A constructor explicitly invokes a base constructor that does "
            "not exist / has no implementation (constructor() A() {} where A "
            "defines no constructor). The call suggests initialization "
            "happens, but nothing runs — misleading to reviewers."
        ),
        exploit_scenario=(
            "constructor() UpgradeableBase() {} is kept after the base is "
            "refactored to plain storage; auditors assume the base is "
            "initialized while in fact nothing runs at deployment."
        ),
        recommendation=(
            "Remove the no-op constructor call (or give the base a real "
            "constructor if initialization was intended)."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if not function.is_constructor:
                    continue
                for base in function.explicit_base_constructor_calls:
                    if _has_explicit_constructor(base):
                        continue
                    results.append(
                        self.finding(
                            [
                                function,
                                " explicitly calls the constructor of ",
                                base,
                                " but ",
                                base,
                                " defines no constructor; the call is a no-op",
                            ]
                        )
                    )
        return results
