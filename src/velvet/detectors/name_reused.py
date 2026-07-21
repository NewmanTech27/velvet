"""`name-reused` detector (spec/detectors-catalog.md §5.9 — normative).

Two different contracts in the compilation unit share the same name (e.g. a
production ``ERC20`` and a testing ``ERC20`` in another source unit).  solc
accepts this when the files never import each other, but the wrong contract
can then be referenced, deployed or verified against: tooling, inheritance
resolution and humans all key off names.  Detection is structural over the
compilation unit's contract table.

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


class NameReused(Detector):
    """Detect distinct contracts that share a name in one compilation unit."""

    RULE = "name-reused"
    TITLE = "Contract name reused across source units"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#name-reused",
        title="Contract name reused across source units",
        description=(
            "Two different contracts share the same name in the compilation "
            "unit. The wrong implementation can be referenced, deployed or "
            "verified against, and inheritance or tooling may silently "
            "resolve to the unintended contract."
        ),
        exploit_scenario=(
            "token/ERC20.sol ships the real token while mocks/ERC20.sol "
            "contains a testing stub; a build that compiles both can deploy "
            "or verify the stub as if it were the real token."
        ),
        recommendation=(
            "Rename one of the contracts so every contract name in the "
            "compilation unit is unique."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        by_name: dict[str, list] = {}
        for contract in self.compilation_unit.contracts:
            if not contract.name:
                continue
            by_name.setdefault(contract.name, [])
            # The same Contract object may be reachable twice; keep distinct
            # definitions only.
            if all(existing is not contract for existing in by_name[contract.name]):
                by_name[contract.name].append(contract)
        for name, contracts in sorted(by_name.items()):
            if len(contracts) < 2:
                continue
            locations = ", ".join(
                c.source_mapping.filename.used
                if c.source_mapping is not None and c.source_mapping.filename
                else "<unknown>"
                for c in contracts
            )
            elements: list = [contracts[0], f" reuses the contract name {name!r}; another definition exists ("]
            elements += [locations, "): "]
            elements += contracts[1:]
            results.append(self.finding(elements))
        return results
