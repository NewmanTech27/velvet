"""`missing-inheritance` detector (spec/detectors-catalog.md §8.9 —
normative).

Flags contracts that *define* every public/external member of an interface
(or abstract contract) present in the same compilation unit but do not
declare inheritance from it — so the type relationship, and the compiler's
enforcement of signature conformance, is missing.

Catalog letter (§8.9): "A contract defines all public/external members of
some interface (or abstract contract) present in the codebase without
listing it in its inheritance specifier."

Confidence rules applied on top of the raw surface match:

- *defines*, not *provides*: members merely inherited from a base contract
  do not count — otherwise every token would be flagged for the interfaces
  its own base contracts already conform to. Only functions/getters
  implemented by the contract body itself qualify.
- the candidate must expose at least two public/external members. A
  one-member surface (overwhelmingly ``supportsInterface(bytes4)`` from
  the ERC-165 family) is idiomatically implemented standalone and does not
  imply a missing type relationship.
- inheritance is judged over the whole transitive base graph (direct
  bases walked explicitly), not just the declared specifier list, so
  contracts already inheriting the candidate through an intermediate base
  are never flagged.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.contract import Contract, ContractKind
from velvet.detectors._batch_e_utils import _getter_parts
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

#: Minimum size of a candidate's public/external surface for a finding.
#: Single-member candidates (e.g. the ERC-165 ``supportsInterface`` hook)
#: are implemented standalone all the time; flagging them is noise.
_MIN_SURFACE = 2


def _base_closure(contract: Contract) -> list[Contract]:
    """All transitive base contracts (nearest-first-ish), deduplicated.

    Walks ``direct_bases`` explicitly so the result is complete even for
    hierarchies whose C3 linearization degraded to declared order.
    """
    seen: set[int] = set()
    closure: list[Contract] = []
    stack = list(contract.direct_bases)
    while stack:
        base = stack.pop()
        if id(base) in seen:
            continue
        seen.add(id(base))
        closure.append(base)
        stack.extend(base.direct_bases)
    return closure


def _public_getter_signatures(variables) -> set[str]:
    """Signatures of the implicit getters of public state variables."""
    signatures: set[str] = set()
    for variable in variables:
        if variable.visibility != "public":
            continue
        parts = _getter_parts(variable.type)
        if parts is None:
            continue
        params, _ret = parts
        signatures.add(f"{variable.name}({','.join(str(p) for p in params)})")
    return signatures


def _required_signatures(candidate: Contract) -> set[str]:
    """The candidate's full public/external member surface (own + inherited).

    This is the API a conforming contract must expose: every public/external
    function declared anywhere in the candidate's base graph plus the
    implicit getters of its public state variables.
    """
    signatures: set[str] = set()
    for unit in [candidate, *_base_closure(candidate)]:
        signatures |= {
            f.signature
            for f in unit.functions
            if f.visibility in ("external", "public")
        }
        signatures |= _public_getter_signatures(unit.state_variables)
    return signatures


def _defined_signatures(contract: Contract) -> set[str]:
    """Public/external members the contract *defines* in its own body.

    Inherited implementations are deliberately excluded (catalog: "defines").
    """
    signatures = {
        f.signature
        for f in contract.functions
        if f.visibility in ("external", "public") and f.is_implemented
    }
    signatures |= _public_getter_signatures(contract.state_variables)
    return signatures


class MissingInheritance(Detector):
    """Detect contracts implementing an interface without inheriting it."""

    RULE = "missing-inheritance"
    TITLE = "Contract implements an interface without inheriting it"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#missing-inheritance",
        title="Missing inheritance",
        description=(
            "A contract defines all public/external members of some "
            "interface (or abstract contract) present in the codebase "
            "without listing it in its inheritance specifier, so signature "
            "conformance is not compiler-enforced."
        ),
        exploit_scenario=(
            "Vault re-implements IVault.deposit/withdraw without `is "
            "IVault`; a later refactor changes withdraw's parameter type "
            "and integrators calling through IVault break silently."
        ),
        recommendation=(
            "Declare the inheritance (contract Vault is IVault) so "
            "conformance is compiler-enforced."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        candidates = [
            c
            for c in self.compilation_unit.contracts
            if c.kind in (ContractKind.INTERFACE, ContractKind.ABSTRACT)
        ]
        if not candidates:
            return results
        required_by_candidate: dict[int, set[str]] = {}
        for candidate in candidates:
            required = _required_signatures(candidate)
            if len(required) >= _MIN_SURFACE:
                required_by_candidate[id(candidate)] = required
        for contract in self.compilation_unit.contracts:
            if contract.kind != ContractKind.CONTRACT:
                continue
            defined = _defined_signatures(contract)
            if not defined:
                continue
            inherited_ids = {id(base) for base in _base_closure(contract)}
            for candidate in candidates:
                if candidate is contract or id(candidate) in inherited_ids:
                    continue
                required = required_by_candidate.get(id(candidate))
                if not required:
                    continue
                if not required <= defined:
                    continue
                results.append(
                    self.finding(
                        [
                            contract,
                            " implements every function of ",
                            candidate,
                            " but does not inherit it; add it to the "
                            "inheritance list so conformance is "
                            "compiler-enforced",
                        ]
                    )
                )
        return results
