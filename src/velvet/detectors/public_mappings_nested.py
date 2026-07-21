"""`public-mappings-nested` detector (spec/detectors-catalog.md §5.3 —
normative).

On solc < 0.5.0 the auto-generated getter of a ``public`` mapping whose
value type contains a nested mapping (mapping-to-mapping, or
mapping-to-struct containing a mapping) returns incorrect values.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from packaging.version import Version

from velvet.core.declarations import Structure
from velvet.core.types import MappingType, UserDefinedType
from velvet.detectors._versions import parse_solc_version
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

#: First solc version whose generated getters handle nested mappings.
_FIXED_VERSION = Version("0.5.0")


def _contains_mapping(type_: Any, *, _depth: int = 0) -> bool:
    """True when ``type_`` is or (through structs) contains a mapping."""
    if type_ is None or _depth > 16:
        return False
    if isinstance(type_, MappingType):
        return True
    if isinstance(type_, UserDefinedType) and isinstance(
        getattr(type_, "type", None), Structure
    ):
        return any(
            _contains_mapping(field.type, _depth=_depth + 1)
            for field in type_.type.elems
        )
    return False


class PublicMappingsNested(Detector):
    """Detect public nested mappings on solc < 0.5.0."""

    RULE = "public-mappings-nested"
    TITLE = "Public mapping with nested structures (solc < 0.5.0)"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#public-mappings-nested",
        title="Public mapping with nested structures (solc < 0.5.0)",
        description=(
            "Compilers prior to 0.5.0 generate broken getters for public "
            "mappings whose value contains a nested mapping or a struct "
            "holding a mapping: the getter returns incorrect values."
        ),
        exploit_scenario=(
            "Ledger declares mapping(address => mapping(address => "
            "uint256)) public allowances compiled with solc 0.4.24; the "
            "auto-generated allowances(a, b) getter returns garbage."
        ),
        recommendation=(
            "Upgrade to Solidity >= 0.5.0; on old compilers drop the "
            "public keyword and write explicit getters returning the "
            "scalar fields."
        ),
    )

    def _affected_compiler(self) -> bool:
        version = parse_solc_version(self.compilation_unit.solc_version)
        return version is not None and version < _FIXED_VERSION

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        if not self._affected_compiler():
            return results
        for contract in self.compilation_unit.contracts:
            if contract.is_interface or contract.is_library:
                continue
            for variable in contract.state_variables:
                if variable.visibility != "public":
                    continue
                type_ = variable.type
                if not isinstance(type_, MappingType):
                    continue
                if not _contains_mapping(type_.type_to):
                    continue
                results.append(
                    self.finding(
                        [
                            variable,
                            " is a public mapping with a nested mapping or "
                            "struct in ",
                            contract,
                            "; its compiler-generated getter returns "
                            "incorrect values on solc "
                            f"{self.compilation_unit.solc_version} (< 0.5.0)",
                        ]
                    )
                )
        return results
