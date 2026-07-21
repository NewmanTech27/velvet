"""`gelato-unprotected-randomness` detector (spec/detectors-catalog.md §2.8 —
normative).

Flags calls to Gelato VRF's ``_requestRandomness`` from functions any user
can invoke.  Unrestricted randomness requests let attackers drain the
contract's VRF subscription funds (each request costs fees) or spam requests
to influence application logic.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors._batch_f_utils import unique_functions
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import HighLevelCall, InternalCall

#: Gelato VRF consumer entry point that triggers a (paid) randomness request.
_REQUEST_RANDOMNESS = "_requestRandomness"

#: Call shapes that can reach ``_requestRandomness``.
_CALL_OPS = (InternalCall, HighLevelCall)


class GelatoUnprotectedRandomness(Detector):
    """Detect unprotected Gelato VRF randomness requests."""

    RULE = "gelato-unprotected-randomness"
    TITLE = "Gelato VRF randomness request is unprotected"
    IMPACT = Impact.MEDIUM
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#gelato-unprotected-randomness",
        title="Gelato VRF randomness request is unprotected",
        description=(
            "A publicly reachable function calls Gelato VRF's "
            "_requestRandomness without any access-control restriction. "
            "Anyone can trigger paid randomness requests, draining the "
            "contract's VRF subscription funds or spamming requests to "
            "influence application logic."
        ),
        exploit_scenario=(
            "spin() is external and calls _requestRandomness(abi.encode("
            "msg.sender)); an attacker floods it with requests until the "
            "Gelato VRF subscription balance is exhausted."
        ),
        recommendation=(
            "Restrict the requesting function to authorized callers (e.g. "
            "onlyOwner, an allowlist, or rate limiting)."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for function in unique_functions(self.compilation_unit):
            if function.visibility not in ("external", "public"):
                continue
            if function.is_protected:
                continue
            for node in function.nodes:
                for op in node.ir_operations:
                    if not (
                        isinstance(op, _CALL_OPS)
                        and op.function_name == _REQUEST_RANDOMNESS
                    ):
                        continue
                    results.append(
                        self.finding(
                            [
                                node,
                                " requests Gelato VRF randomness from the "
                                "unprotected ",
                                function,
                                "; anyone can trigger paid requests",
                            ]
                        )
                    )
                    break  # one finding per function
        return results
