"""`domain-separator-collision` detector (spec/detectors-catalog.md §4.6 —
normative).

Flags ``DOMAIN_SEPARATOR`` declarations that collide with EIP-2612's
``DOMAIN_SEPARATOR()`` in a token meant to support ``permit``: an
overloaded variant with parameters, or a no-argument variant returning
something other than ``bytes32``.  Integrators resolving the domain
separator by signature hit the wrong function and permit flows break or
can be hijacked.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_e_utils import canonical_returns, unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class DomainSeparatorCollision(Detector):
    """Detect DOMAIN_SEPARATOR collisions in permit-supporting tokens."""

    RULE = "domain-separator-collision"
    TITLE = "DOMAIN_SEPARATOR declaration collides with EIP-2612"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#domain-separator-collision",
        title="Domain separator collision",
        description=(
            "An ERC-20 token meant to support permit declares (or "
            "inherits) a function whose name collides with EIP-2612's "
            "DOMAIN_SEPARATOR() but whose signature/return type differs; "
            "integrators resolving the domain separator hit the wrong "
            "function."
        ),
        exploit_scenario=(
            "BadToken overloads DOMAIN_SEPARATOR(bytes32 extra); a wallet "
            "resolving DOMAIN_SEPARATOR() by name binds to the wrong "
            "member and permit signatures verify against the wrong domain."
        ),
        recommendation=(
            "Remove or rename any function that collides with EIP-2612's "
            "DOMAIN_SEPARATOR(); implement DOMAIN_SEPARATOR() returns "
            "(bytes32) exactly as specified."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen_functions: set[int] = set()
        for contract in self.compilation_unit.contracts_derived:
            functions = [
                f
                for f in contract.available_functions_from_inheritances()
                if f.visibility in ("external", "public")
            ]
            if not any(f.name == "permit" for f in functions):
                continue  # not a permit-supporting token
            for function in functions:
                if function.name != "DOMAIN_SEPARATOR":
                    continue
                if id(function) in seen_functions:
                    continue
                seen_functions.add(id(function))
                has_params = bool(function.parameters)
                wrong_return = canonical_returns(function) != ["bytes32"]
                if not (has_params or wrong_return):
                    continue  # exactly DOMAIN_SEPARATOR() returns (bytes32)
                results.append(
                    self.finding(
                        [
                            function,
                            " collides with EIP-2612's DOMAIN_SEPARATOR() "
                            "in the permit-supporting token ",
                            contract,
                        ]
                    )
                )
        return results
