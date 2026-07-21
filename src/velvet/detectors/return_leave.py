"""`return-leave` detector (spec/detectors-catalog.md §7.11 — normative).

In Yul (Solidity >= 0.7.2) ``return`` terminates the whole call frame,
while ``leave`` only exits the current assembly function/block so the
generated Solidity epilogue (ABI-encoding of named return values,
post-assembly statements) still runs.  An assembly ``return`` inside a
Solidity function that has declared returns or additional logic silently
bypasses that epilogue.

Inline assembly is opaque to the IR (a single ``ASSEMBLY`` node), so the
block's source text is checked for a ``return(...)`` builtin.

Original clean-room implementation.
"""

from __future__ import annotations

import re

from velvet.core.cfg_node import NodeKind
from velvet.detectors._batch_e_utils import unique_functions
from velvet.detectors._batch_h_utils import source_slice
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

_YUL_RETURN_RE = re.compile(r"\breturn\s*\(")

#: Node kinds that are scaffolding rather than user logic.
_SCAFFOLD_KINDS = frozenset(
    {NodeKind.ENTRYPOINT, NodeKind.RETURN, NodeKind.THROW, NodeKind.ASSEMBLY}
)


class ReturnLeave(Detector):
    """Detect assembly ``return`` where ``leave`` is required."""

    RULE = "return-leave"
    TITLE = "Assembly return bypasses the Solidity return path"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#return-leave",
        title="Assembly return bypasses the Solidity return path",
        description=(
            "Inside inline assembly, return() terminates the whole call "
            "frame; when the surrounding Solidity function declares return "
            "variables or has more logic after the assembly block, the "
            "compiler-generated epilogue (ABI encoding, subsequent "
            "statements) is skipped entirely and leave (or no terminator) "
            "is required instead."
        ),
        exploit_scenario=(
            "Codec.encode() declares returns (bytes32 a, bytes32 b) but "
            "its assembly block executes return(0, 64): the caller "
            "receives raw memory, never the ABI encoding of (a, b)."
        ),
        recommendation=(
            "Replace the assembly return with leave when the Solidity "
            "function should resume its normal return path."
        ),
    )

    def _has_additional_logic(self, function: object, assembly_node: object) -> bool:
        """True when user logic exists besides the assembly block itself."""
        for node in function.nodes:  # type: ignore[attr-defined]
            if node is assembly_node:
                continue
            if node.kind in _SCAFFOLD_KINDS:
                continue
            return True
        return False

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            if not function.contains_assembly:
                continue
            has_declared_returns = bool(function.returns)
            for node in function.nodes:
                if node.kind is not NodeKind.ASSEMBLY:
                    continue
                text = source_slice(self.compilation_unit, node.source_mapping)
                if text is None or not _YUL_RETURN_RE.search(text):
                    continue
                if not has_declared_returns and not self._has_additional_logic(
                    function, node
                ):
                    # Bare proxy-style forwarder: return() is the frame
                    # terminator by design; nothing is bypassed.
                    continue
                results.append(
                    self.finding(
                        [
                            node,
                            " uses assembly return() in ",
                            function,
                            " which declares return values or has "
                            "additional logic; the Solidity epilogue is "
                            "bypassed (use leave instead)",
                        ]
                    )
                )
        return results
