"""Detector batch A: reentrancy + access control (SPEC.md §5).

The orchestrator wires :data:`DETECTORS` into the built-in registry;
``velvet.detectors.__init__`` is intentionally left untouched to avoid
merge conflicts between detector batches.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors.arbitrary_send_eth import ArbitrarySendEth
from velvet.detectors.base import Detector
from velvet.detectors.missing_zero_check import MissingZeroCheck
from velvet.detectors.protected_vars import ProtectedVars
from velvet.detectors.reentrancy_benign import ReentrancyBenign
from velvet.detectors.reentrancy_eth import ReentrancyEth
from velvet.detectors.reentrancy_events import ReentrancyEvents
from velvet.detectors.reentrancy_no_eth import ReentrancyNoEth
from velvet.detectors.suicidal import Suicidal
from velvet.detectors.unprotected_upgrade import UnprotectedUpgrade

#: Batch A detectors (reentrancy family + access control).
DETECTORS: list[type[Detector]] = [
    ReentrancyEth,
    ReentrancyNoEth,
    ReentrancyBenign,
    ReentrancyEvents,
    Suicidal,
    UnprotectedUpgrade,
    ArbitrarySendEth,
    MissingZeroCheck,
    ProtectedVars,
]

__all__ = [
    "DETECTORS",
    "ReentrancyEth",
    "ReentrancyNoEth",
    "ReentrancyBenign",
    "ReentrancyEvents",
    "Suicidal",
    "UnprotectedUpgrade",
    "ArbitrarySendEth",
    "MissingZeroCheck",
    "ProtectedVars",
]
