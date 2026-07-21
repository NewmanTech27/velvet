"""`erc721-interface` detector (spec/detectors-catalog.md §4.5 —
normative).

The ERC-721 analogue of `erc20-interface`: flags functions whose name and
parameters match an ERC-721 method but whose return types do not conform
to the standard, breaking interoperability with NFT tooling and other
contracts.

Functions that conform to the ERC-20 table exactly (e.g. a token's
``transferFrom`` returning ``bool``) are deliberate declarations of the
other standard and are skipped (checked by `erc20-interface` instead).

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


class Erc721Interface(Detector):
    """Detect ERC-721-named functions with non-conforming return types."""

    RULE = "erc721-interface"
    TITLE = "Incorrect ERC-721 function interface"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#erc721-interface",
        title="Incorrect ERC-721 interface",
        description=(
            "A function matches an ERC-721 method name/parameters "
            "(ownerOf, balanceOf, transferFrom, safeTransferFrom, "
            "approve, setApprovalForAll, getApproved, isApprovedForAll, "
            "...) but declares non-conforming return types."
        ),
        exploit_scenario=(
            "BrokenNFT.ownerOf(uint256) returns bool instead of address; "
            "marketplaces decoding the standard return either revert or "
            "read garbage as the owner address."
        ),
        recommendation=(
            "Match the ERC-721 interface exactly (e.g. ownerOf(uint256) "
            "returns (address))."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for _contract, function, expected in interface_violations(
            self.compilation_unit,
            ERC721_RETURNS_TABLE,
            conforming_table=ERC20_RETURNS_TABLE,
        ):
            results.append(
                self.finding(
                    [
                        function,
                        " matches an ERC-721 method but returns ",
                        str([str(r.type) for r in function.returns]),
                        " instead of ",
                        str(expected),
                        "; NFT tooling decoding the standard return will "
                        "break",
                    ]
                )
            )
        return results
