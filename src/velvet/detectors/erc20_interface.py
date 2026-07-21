"""`erc20-interface` detector (spec/detectors-catalog.md §4.4 — normative).

Flags functions whose name and parameters match an ERC-20 method but
whose declared return types do not — most critically
``transfer``/``transferFrom``/``approve`` returning nothing.  Contracts
compiled with Solidity > 0.4.22 that decode a ``bool`` return revert when
interacting with such tokens.

Functions that conform to the ERC-721 table exactly (e.g. an NFT's
``transferFrom`` returning nothing) are deliberate declarations of the
other standard and are skipped (checked by `erc721-interface` instead).

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_e_utils import (
    ERC20_RETURNS_TABLE,
    ERC721_RETURNS_TABLE,
    interface_violations,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class Erc20Interface(Detector):
    """Detect ERC-20-named functions with non-conforming return types."""

    RULE = "erc20-interface"
    TITLE = "Incorrect ERC-20 function interface"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#erc20-interface",
        title="Incorrect ERC-20 interface",
        description=(
            "A function's signature matches an ERC-20 method (transfer, "
            "transferFrom, approve, balanceOf, allowance, totalSupply) but "
            "the declared return types do not match the ERC-20 "
            "specification (e.g. missing bool return)."
        ),
        exploit_scenario=(
            "BrokenToken.transfer(address,uint256) returns nothing; a "
            "vault compiled with Solidity 0.8 decodes the expected bool "
            "and reverts on every withdrawal."
        ),
        recommendation=(
            "Return the correct types for all ERC-20 functions (transfer, "
            "transferFrom, approve must return bool)."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for _contract, function, expected in interface_violations(
            self.compilation_unit,
            ERC20_RETURNS_TABLE,
            conforming_table=ERC721_RETURNS_TABLE,
        ):
            results.append(
                self.finding(
                    [
                        function,
                        " matches an ERC-20 method but returns ",
                        str([str(r.type) for r in function.returns]),
                        " instead of ",
                        str(expected),
                        "; integrators decoding the standard return will "
                        "revert",
                    ]
                )
            )
        return results
