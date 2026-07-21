"""`costly-loop` detector (spec/detectors-catalog.md §9.1 — normative).

Flags expensive operations repeated inside a loop that could be hoisted or
cached: repeated ``SLOAD``/``SSTORE`` on the same state variable whose value
could live in a local accumulator, and repeated ``msg.value`` reads that are
invariant across iterations.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.core.variables import SolidityVariable, StateVariable
from velvet.detectors._batch_f_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)


class CostlyLoop(Detector):
    """Detect state-variable accumulation and msg.value reads in loops."""

    RULE = "costly-loop"
    TITLE = "Expensive operation repeated inside a loop"
    IMPACT = Impact.INFORMATIONAL
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#costly-loop",
        title="Expensive operation repeated inside a loop",
        description=(
            "A loop body repeatedly reads/writes a state variable (an extra "
            "SLOAD+SSTORE per iteration) or reads msg.value, both of which "
            "could be cached in a local variable across iterations."
        ),
        exploit_scenario=(
            "accumulate() does total += xs[i] inside a for loop; over a "
            "1k-element array the per-iteration SLOAD+SSTORE on total wastes "
            "tens of thousands of gas versus a local accumulator."
        ),
        recommendation=(
            "Accumulate in a local variable inside the loop; write back to "
            "storage once after the loop (and read msg.value once into a "
            "local)."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            read: set[int] = set()
            written: dict[int, StateVariable] = {}
            msg_value_node = None
            for node in function.nodes:
                if not node.is_inside_loop:
                    continue
                for var in node.state_variables_read:
                    read.add(id(var))
                for var in node.state_variables_written:
                    written[id(var)] = var
                if msg_value_node is None:
                    for op in node.ir_operations:
                        if any(
                            isinstance(v, SolidityVariable) and v.name == "msg.value"
                            for v in op.read
                        ):
                            msg_value_node = node
                            break
            # State variables both read and written in the loop = accumulator.
            reported: set[int] = set()
            for var_id, var in written.items():
                if var_id not in read or var_id in reported:
                    continue
                reported.add(var_id)
                results.append(
                    self.finding(
                        [
                            var,
                            " is read and written on every loop iteration in ",
                            function,
                            "; accumulate in a local and write back once",
                        ]
                    )
                )
            if msg_value_node is not None:
                results.append(
                    self.finding(
                        [
                            msg_value_node,
                            " reads msg.value inside a loop in ",
                            function,
                            "; cache it in a local before the loop",
                        ]
                    )
                )
        return results
