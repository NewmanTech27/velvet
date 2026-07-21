"""`chainlink-feed-registry` detector (spec/detectors-catalog.md §6.5 —
normative).

Flags usage of the Chainlink Feed Registry, which is deployed only on
Ethereum mainnet; code that depends on it reverts when deployed to any other
chain/L2.  Detection covers both references to the known registry address
and ``latestRoundData(base, quote)`` calls (the registry's two-address form)
on a feed-registry interface.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterator

from velvet.core.expressions import Literal
from velvet.detectors._batch_f_utils import is_oracle_call, unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

#: The Chainlink Feed Registry canonical (Ethereum-mainnet-only) address.
REGISTRY_ADDRESS = "0x47fb2585d2c56fe188d0e6ec628a38b74fceeedf"

#: Registry query entry point (two-address ``base``/``quote`` form).
_REGISTRY_QUERIES = ("latestRoundData",)

#: Interface-name keyword identifying a feed-registry contract.
_REGISTRY_KEYWORD = "registry"


def _normalize_address(text: str) -> str:
    lowered = text.strip().lower()
    return lowered[2:] if lowered.startswith("0x") else lowered


class ChainlinkFeedRegistry(Detector):
    """Detect usage of the mainnet-only Chainlink Feed Registry."""

    RULE = "chainlink-feed-registry"
    TITLE = "Chainlink Feed Registry is mainnet-only"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#chainlink-feed-registry",
        title="Chainlink Feed Registry is mainnet-only",
        description=(
            "The contract references or calls the Chainlink Feed Registry, "
            "which is deployed only on Ethereum mainnet. Code that depends on "
            "the registry reverts when deployed to any other chain or L2."
        ),
        exploit_scenario=(
            "Prices reads REGISTRY.latestRoundData(base, quote); the contract "
            "is deployed unchanged to an L2 where the registry address holds "
            "no code, so every price read reverts and the protocol halts."
        ),
        recommendation=(
            "Use chain-specific Chainlink aggregator addresses instead of "
            "the Feed Registry when deploying outside Ethereum mainnet."
        ),
    )

    def _literals(self) -> Iterator[tuple[Any, Literal]]:
        """Yield ``(owner_element, literal)`` for every numeric/address literal."""
        seen: set[int] = set()
        for function in unique_functions(self.compilation_unit):
            if id(function) in seen:
                continue
            seen.add(id(function))
            for expr in function.all_expressions:
                for node in expr.walk():
                    if isinstance(node, Literal):
                        yield function, node
        for contract in self.compilation_unit.contracts_derived:
            for variable in contract.state_variables_ordered:
                initial = variable.expression_initial
                if initial is None:
                    continue
                for node in initial.walk():
                    if isinstance(node, Literal):
                        yield variable, node

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        registry = _normalize_address(REGISTRY_ADDRESS)
        reported_address = False
        for owner, literal in self._literals():
            if reported_address:
                break
            if _normalize_address(str(literal.value)) == registry:
                results.append(
                    self.finding(
                        [
                            literal,
                            " references the Chainlink Feed Registry address, "
                            "which is deployed only on Ethereum mainnet",
                        ]
                    )
                )
                reported_address = True
        for function in unique_functions(self.compilation_unit):
            for node in function.nodes:
                for op in node.ir_operations:
                    if not (
                        is_oracle_call(op, _REGISTRY_QUERIES, _REGISTRY_KEYWORD)
                        and len(op.arguments) == 2
                    ):
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                " queries the Chainlink Feed Registry in ",
                                function,
                                "; the registry is only available on Ethereum "
                                "mainnet",
                            ]
                        )
                    )
        return results
