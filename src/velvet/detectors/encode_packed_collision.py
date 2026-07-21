"""`encode-packed-collision` detector (spec/detectors-catalog.md §7.2 —
normative).

Flags ``abi.encodePacked`` calls that receive more than one variable-length
argument (``string``, ``bytes``, dynamic arrays).  Packed encoding
concatenates values without length delimiters, so different argument tuples
can collide to the same byte string; when the result is hashed (typically
``keccak256``) for signatures or Merkle proofs, collisions let an attacker
forge a proof for different inputs.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_d_utils import is_variable_length_type
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import SolidityCall


class EncodePackedCollision(Detector):
    """Detect abi.encodePacked with several variable-length arguments."""

    RULE = "encode-packed-collision"
    TITLE = "abi.encodePacked with multiple variable-length arguments"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#encode-packed-collision",
        title="abi.encodePacked with multiple variable-length arguments",
        description=(
            "abi.encodePacked concatenates arguments without length "
            "delimiters. With two or more variable-length arguments "
            "(string, bytes, dynamic arrays) distinct inputs can produce "
            "the same packed bytes, so a hash over the result is not "
            "collision-resistant and signatures or proofs can be forged."
        ),
        exploit_scenario=(
            "leaf = keccak256(abi.encodePacked(tag, ref, user)) with two "
            'string parameters: ("ab", "c") and ("a", "bc") hash to the '
            "same leaf, letting an attacker swap signed messages."
        ),
        recommendation=(
            "Use abi.encode (length-prefixed) instead of abi.encodePacked, "
            "or keep at most one variable-length argument."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        seen_functions: set[int] = set()
        for contract in self.compilation_unit.contracts_derived:
            functions = list(contract.available_functions_from_inheritances())
            functions += list(contract.all_modifiers())
            for function in functions:
                if id(function) in seen_functions:
                    continue
                seen_functions.add(id(function))
                for node in function.all_nodes:
                    for op in node.ir_operations:
                        if not (
                            isinstance(op, SolidityCall)
                            and op.function.name == "abi.encodePacked"
                        ):
                            continue
                        dynamic = [
                            arg
                            for arg in op.arguments
                            if is_variable_length_type(getattr(arg, "type", None))
                        ]
                        if len(dynamic) < 2:
                            continue
                        results.append(
                            self.finding(
                                [
                                    node,
                                    " calls abi.encodePacked with multiple "
                                    "variable-length arguments (",
                                    ", ".join(str(getattr(a, "name", a)) for a in dynamic),
                                    ") in ",
                                    function,
                                    "; packed encoding is collision-prone",
                                ]
                            )
                        )
        return results
