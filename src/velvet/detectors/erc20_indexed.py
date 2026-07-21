"""`erc20-indexed` detector (spec/detectors-catalog.md §4.7 — normative).

Flags ERC-20 ``Transfer``/``Approval`` events whose address parameters
lack the ``indexed`` keyword required by the standard.  Without indexing
the parameters are absent from the block's bloom filter, so external
tooling cannot filter/index logs for the token.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.types import ElementaryType
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

_ERC20_EVENT_NAMES = ("Transfer", "Approval")


def _is_address(type_: object) -> bool:
    return isinstance(type_, ElementaryType) and str(type_) == "address"


def _is_uint256(type_: object) -> bool:
    return isinstance(type_, ElementaryType) and str(type_) == "uint256"


class Erc20Indexed(Detector):
    """Detect ERC-20 Transfer/Approval events missing indexed addresses."""

    RULE = "erc20-indexed"
    TITLE = "ERC-20 event parameters are not indexed"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#erc20-indexed",
        title="Unindexed ERC-20 event parameters",
        description=(
            "Events named Transfer/Approval with the ERC-20 signature "
            "where the first two address parameters are not declared "
            "indexed; external tooling fails to filter/index logs for "
            "this token."
        ),
        exploit_scenario=(
            "Token declares event Transfer(address from, address to, "
            "uint256 value) without indexed; a block explorer cannot "
            "select the token's transfers by sender/recipient."
        ),
        recommendation=(
            "Declare event Transfer(address indexed from, address indexed "
            "to, uint256 value) (and similarly for Approval)."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen: set[int] = set()
        for contract in self.compilation_unit.contracts:
            for event in contract.events:
                if id(event) in seen:
                    continue
                seen.add(id(event))
                if event.name not in _ERC20_EVENT_NAMES:
                    continue
                params = event.elems
                if len(params) != 3:
                    continue
                first, second, third = params
                if not (
                    _is_address(first.type)
                    and _is_address(second.type)
                    and _is_uint256(third.type)
                ):
                    continue  # not the ERC-20 event signature
                if first.indexed and second.indexed:
                    continue
                missing = [
                    p.name for p in (first, second) if not p.indexed
                ]
                results.append(
                    self.finding(
                        [
                            event,
                            " does not index the address parameter(s) ",
                            ", ".join(missing),
                            " required by the ERC-20 standard in ",
                            contract,
                        ]
                    )
                )
        return results
