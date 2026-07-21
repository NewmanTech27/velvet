"""`tx-origin` detector (spec/detectors-catalog.md §2.5 — normative).

Flags ``tx.origin`` used for authorization: a comparison/boolean expression
feeding an authorization decision (``require(tx.origin == owner)``, a
modifier testing ``tx.origin``, an ``if`` condition).

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.analyses.read_write import expand_read_variables
from velvet.core.variables import SolidityVariable
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import Binary, Condition, SolidityCall

_COMPARISON_OPERATORS = ("==", "!=", "<", ">", "<=", ">=")
_GUARD_BUILTINS = ("require", "assert")


class TxOrigin(Detector):
    """Detect usage of tx.origin for authorization."""

    RULE = "tx-origin"
    TITLE = "tx.origin used for authorization"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#tx-origin",
        title="tx.origin used for authorization",
        description=(
            "tx.origin is the externally-owned account that started the "
            "transaction chain; a malicious intermediary contract can pass a "
            "victim's tx.origin check (phishing-style attack, SWC-115)."
        ),
        exploit_scenario=(
            "A wallet authorizes emergencyDrain() with "
            "require(tx.origin == owner); the victim is tricked into calling "
            "a malicious contract which forwards the call and drains funds."
        ),
        recommendation="Use msg.sender for authorization instead of tx.origin.",
    )

    def _uses_tx_origin(self, variables: list[object], function: object) -> bool:
        for var in expand_read_variables(variables, function):  # type: ignore[arg-type]
            if isinstance(var, SolidityVariable) and var.name == "tx.origin":
                return True
        return False

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen_nodes: set[int] = set()
        for contract in self.compilation_unit.contracts_derived:
            functions = list(contract.functions) + list(contract.all_modifiers())
            for function in functions:
                for node in function.nodes:
                    flagged = False
                    for op in node.ir_operations:
                        if isinstance(op, Binary) and op.operator in _COMPARISON_OPERATORS:
                            if self._uses_tx_origin([op.left, op.right], function):
                                flagged = True
                        elif isinstance(op, Condition):
                            if self._uses_tx_origin([op.value], function):
                                flagged = True
                        elif (
                            isinstance(op, SolidityCall)
                            and op.function.name in _GUARD_BUILTINS
                        ):
                            if self._uses_tx_origin(op.arguments, function):
                                flagged = True
                        if flagged:
                            break
                    if flagged and id(node) not in seen_nodes:
                        seen_nodes.add(id(node))
                        results.append(
                            self.finding(
                                [node, " uses tx.origin for authorization in ", function]
                            )
                        )
        return results
