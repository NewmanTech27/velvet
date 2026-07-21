"""`multiple-constructors` detector (spec/detectors-catalog.md §5.6 —
normative).

solc 0.4.22 accepts a contract that declares both a ``constructor(...)``
and a function whose name equals the contract's name (the pre-0.4.22
constructor style): both are compiled as constructors and which one runs
depends on the compiler version.  The parser canonicalizes the legacy
``function <ContractName>()`` form to constructor kind, so the pattern
surfaces as *two* constructor functions on one contract.  Detection is
structural; the vulnerable source only compiles on solc 0.4.22.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class MultipleConstructors(Detector):
    """Detect contracts declaring two constructor forms."""

    RULE = "multiple-constructors"
    TITLE = "Multiple constructor declarations"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#multiple-constructors",
        title="Multiple constructor declarations",
        description=(
            "solc 0.4.22 accepts a contract with both a constructor(...) "
            "declaration and a function named like the contract (the legacy "
            "constructor style). Both are compiled as constructors; which "
            "one initializes the contract depends on the compiler version."
        ),
        exploit_scenario=(
            "Token declares constructor() { supply = 1000; } and "
            "function Token() { supply = 1; }: with solc 0.4.22 one of the "
            "two initializations silently wins, and tools disagree on which."
        ),
        recommendation=(
            "Use a single constructor(...) declaration; never name a "
            "function like its contract."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts:
            constructors = [f for f in contract.functions if f.is_constructor]
            legacy_named = [
                f
                for f in contract.functions
                if not f.is_constructor and f.name == contract.name
            ]
            if len(constructors) < 2 and not (constructors and legacy_named):
                continue
            both = constructors + legacy_named
            primary = both[1] if len(both) > 1 else both[0]
            results.append(
                self.finding(
                    [
                        primary,
                        " declares a second constructor form in ",
                        contract,
                        "; both ",
                        " and ".join(f.canonical_name for f in both),
                        " are compiled as constructors (solc 0.4.22)",
                    ]
                )
            )
        return results
