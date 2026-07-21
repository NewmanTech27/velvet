"""`reused-constructor` detector (spec/detectors-catalog.md §7.24 —
normative).

Flags hierarchies where the same base constructor is invoked with
arguments from two or more distinct sites reachable from one derived
contract (e.g. ``D is B, C`` where both ``B`` and ``C`` run ``A(x)``):
only one invocation actually executes and the other is silently ignored,
so initialization can differ from what each intermediate contract
assumed.

Note: solc >= 0.5 rejects the pattern (``Base constructor arguments
given twice``), so the finding surfaces on old codebases; call sites are
read from ``explicit_base_constructor_calls`` (the constructor
initializer-list style the parser records).

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Optional

from velvet.core.contract import Contract
from velvet.core.function import FunctionLike
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


def _constructor_of(contract: Contract) -> Optional[FunctionLike]:
    for function in contract.functions:
        if function.is_constructor:
            return function
    return None


def _takes_arguments(contract: Contract) -> bool:
    """True when the contract has an explicit constructor with parameters."""
    constructor = _constructor_of(contract)
    return constructor is not None and bool(constructor.parameters)


class ReusedConstructor(Detector):
    """Detect base constructors invoked with arguments at multiple sites."""

    RULE = "reused-constructor"
    TITLE = "Base constructor called with arguments from multiple sites"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#reused-constructor",
        title="Base constructor called with arguments from multiple sites",
        description=(
            "The same base constructor is invoked with arguments from two "
            "different places in one inheritance hierarchy; only one "
            "invocation actually runs and the other is silently ignored, "
            "leaving initialization different from what each intermediate "
            "contract assumed."
        ),
        exploit_scenario=(
            "contract D is B, C where B runs A(10) and C runs A(20): A "
            "is built with fee 10 (B's call); C's A(20) never executes, "
            "contradicting C's own assumption about the fee."
        ),
        recommendation=(
            "Call the shared base constructor from exactly one place "
            "(usually the most-derived contract) and document the chosen "
            "arguments."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts_derived:
            if contract.is_interface or contract.is_library:
                continue
            lineage: list[Contract] = [contract, *contract.inheritance]
            # base id -> (base, [site contracts invoking it with args])
            sites: dict[int, tuple[Contract, list[Contract]]] = {}
            for member in lineage:
                constructor = _constructor_of(member)
                if constructor is None:
                    continue
                for base in constructor.explicit_base_constructor_calls:
                    if not isinstance(base, Contract):
                        continue
                    if not _takes_arguments(base):
                        # Invocation without arguments (or a base with no
                        # explicit constructor) is not this rule.
                        continue
                    entry = sites.setdefault(id(base), (base, []))
                    if not any(site is member for site in entry[1]):
                        entry[1].append(member)
            for base, members in sites.values():
                if len(members) < 2:
                    continue
                names = ", ".join(member.name for member in members)
                results.append(
                    self.finding(
                        [
                            contract,
                            " inherits two explicit calls with arguments "
                            "to the constructor of ",
                            base,
                            f" (from {names}); only one invocation "
                            "executes and the other is silently ignored",
                        ]
                    )
                )
        return results
