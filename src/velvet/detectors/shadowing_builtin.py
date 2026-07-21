"""`shadowing-builtin` detector (spec/detectors-catalog.md §7.31 — normative).

Flags user declarations (state variable, local variable, function,
modifier, or event) whose name collides with a Solidity built-in symbol
(``now``, ``assert``, ``require``, ``block``, ``msg``, ``suicide``, ...).
Uses of the built-in then resolve to the user declaration (or vice versa),
producing confusing or wrong behavior.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any, Iterator

from velvet.core.contract import Contract
from velvet.core.function import FunctionKind
from velvet.core.variables import LocalVariable, StateVariable
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

#: Solidity built-in symbols that user declarations must not reuse.
#: Includes legacy built-ins (``now``, ``suicide``, ``sha3``, ``throw``)
#: which remain confusing names even after their removal from the language.
BUILTIN_SYMBOLS = frozenset(
    {
        "abi",
        "addmod",
        "assert",
        "block",
        "blockhash",
        "callcode",
        "ecrecover",
        "gasleft",
        "keccak256",
        "msg",
        "mulmod",
        "now",
        "require",
        "revert",
        "ripemd160",
        "selfdestruct",
        "sha256",
        "sha3",
        "suicide",
        "throw",
        "tx",
    }
)


def _local_declarations(contract: Contract) -> Iterator[LocalVariable]:
    """Parameters, returns and body locals of the contract's functions."""
    for func in contract.functions_and_modifiers:
        for var in list(func.parameters) + list(func.returns):
            yield var
        for node in func.nodes:
            decl = node.variable_declaration
            if isinstance(decl, LocalVariable):
                yield decl


class ShadowingBuiltin(Detector):
    """Detect declarations whose name shadows a Solidity built-in."""

    RULE = "shadowing-builtin"
    TITLE = "Built-in symbol shadowing"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#shadowing-builtin",
        title="Built-in symbol shadowing",
        description=(
            "A declaration (state variable, local, function, modifier, or "
            "event) whose name collides with a Solidity built-in symbol "
            "makes uses of the built-in resolve to the user declaration "
            "(or vice versa), producing confusing or wrong behavior."
        ),
        exploit_scenario=(
            "A contract declares `uint256 public now;`; `return now;` reads "
            "the state variable instead of the current block timestamp."
        ),
        recommendation="Rename declarations that shadow built-ins.",
    )

    def _declarations(self, contract: Contract) -> Iterator[tuple[str, Any]]:
        """(kind, declaration object) pairs to check for one contract."""
        for var in contract.state_variables:
            yield "state variable", var
        for func in contract.functions:
            if func.kind == FunctionKind.NORMAL:
                yield "function", func
        for modifier in contract.modifiers:
            yield "modifier", modifier
        for event in contract.events:
            yield "event", event
        for var in _local_declarations(contract):
            yield "local variable", var

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        reported: set[tuple[str, int]] = set()
        for contract in self.compilation_unit.contracts:
            for kind, decl in self._declarations(contract):
                name = getattr(decl, "name", "")
                if not name or name not in BUILTIN_SYMBOLS:
                    continue
                key = (kind, id(decl))
                if key in reported:
                    continue
                reported.add(key)
                results.append(
                    self.finding(
                        [
                            decl,
                            f" ({kind}) shadows a Solidity built-in symbol",
                        ],
                        additional_fields={"builtin": name, "declaration_kind": kind},
                    )
                )
        return results
