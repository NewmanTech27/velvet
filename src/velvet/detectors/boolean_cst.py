"""`boolean-cst` detector (spec/detectors-catalog.md §7.21 — normative).

Flags hard-coded boolean literals participating in conditions and logical
operations: ``if (false)`` disables a branch, ``x || true`` forces one,
``while (true)`` spins forever unless broken out of.  Outside of a few
idioms such literals are leftover debug code or half-removed logic.

An always-true *loop* condition is an accepted idiom when the loop body
contains a ``break`` (or equivalent exit); those are not reported.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.cfg_node import NodeKind
from velvet.core.function import FunctionLike
from velvet.detectors._batch_e_utils import is_boolean_constant, unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import Binary, Condition


class BooleanCst(Detector):
    """Detect boolean constants in conditions and logical expressions."""

    RULE = "boolean-cst"
    TITLE = "Boolean constant used as a condition"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#boolean-cst",
        title="Boolean constant misuse",
        description=(
            "A boolean literal true/false participates in a conditional "
            "expression, logical operation, or loop condition in a way that "
            "makes one side constant — usually leftover debug code that "
            "silently disables or forces logic."
        ),
        exploit_scenario=(
            "deposit() wraps its require(!paused) check in if (false) "
            "during debugging and ships it; deposits stay enabled while the "
            "team believes the pause switch works."
        ),
        recommendation=(
            "Remove the constant and restore the intended condition; "
            "simplify boolean expressions."
        ),
    )

    @staticmethod
    def _loop_has_break(function: FunctionLike) -> bool:
        """True when ``function`` contains a ``break`` somewhere.

        The CFG does not mark break nodes as loop members, so presence in
        the function is used as the idiom signal.
        """
        return any(node.kind == NodeKind.BREAK for node in function.nodes)

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            loop_has_break: bool | None = None
            for node in function.nodes:
                flagged = False
                for op in node.ir_operations:
                    if isinstance(op, Condition) and is_boolean_constant(op.value):
                        # `while (true)` with a structured break is idiomatic.
                        if node.kind == NodeKind.IF_LOOP:
                            if loop_has_break is None:
                                loop_has_break = self._loop_has_break(function)
                            if loop_has_break and str(op.value.value).lower() == "true":
                                continue
                        flagged = True
                    elif (
                        isinstance(op, Binary)
                        and op.operator in ("&&", "||")
                        and (
                            is_boolean_constant(op.left)
                            or is_boolean_constant(op.right)
                        )
                    ):
                        flagged = True
                    if flagged:
                        break
                if flagged:
                    results.append(
                        self.finding(
                            [
                                node,
                                " uses a hard-coded boolean constant in a "
                                "condition in ",
                                function,
                                "; one side of the branch is dead",
                            ]
                        )
                    )
        return results
