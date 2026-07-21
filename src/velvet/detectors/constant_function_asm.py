"""`constant-function-asm` detector (spec/detectors-catalog.md §5.7 —
normative).

Flags functions declared ``constant``/``view``/``pure`` that contain inline
assembly, in code compiled before Solidity 0.5.  Before 0.5 these attributes
were not enforced by the compiler, so assembly can mutate state inside a
"constant" function; once callers compiled with >= 0.5 use ``STATICCALL``,
any such state change makes every call revert.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.cfg_node import NodeKind
from velvet.detectors._batch_g_utils import compiled_before
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

#: The constant-function attributes were unenforced before solc 0.5.
FIXED_VERSION = "0.5.0"


class ConstantFunctionAsm(Detector):
    """Detect constant/view/pure functions with inline assembly (pre-0.5)."""

    RULE = "constant-function-asm"
    TITLE = "Constant/view/pure function contains inline assembly"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#constant-function-asm",
        title="Inline assembly in a constant/view/pure function (pre-0.5 compiler)",
        description=(
            "A function declared constant/view/pure contains inline "
            "assembly. Before Solidity 0.5 the compiler did not enforce "
            "these attributes, so the assembly can mutate state; callers "
            "compiled with >= 0.5 use STATICCALL and every such state "
            "change makes the call revert."
        ),
        exploit_scenario=(
            "Counter.readAndBump() is declared constant but bumps its "
            "counter via assembly sstore under solc 0.4.24; a 0.8 caller "
            "static-calls it and always reverts, trapping the dependent "
            "protocol."
        ),
        recommendation=(
            "Remove state mutations from constant functions; recompile "
            "with a modern Solidity version where the compiler enforces "
            "view/pure."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        if not compiled_before(self.compilation_unit, FIXED_VERSION):
            return results
        for contract in self.compilation_unit.contracts:
            for function in contract.functions_and_modifiers:
                if not (function.view or function.pure):
                    continue
                for node in function.nodes:
                    if node.kind is not NodeKind.ASSEMBLY:
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                " is an inline assembly block inside the "
                                "constant/view/pure function ",
                                function,
                                " (attribute not enforced by solc "
                                f"{self.compilation_unit.solc_version})",
                            ]
                        )
                    )
        return results
