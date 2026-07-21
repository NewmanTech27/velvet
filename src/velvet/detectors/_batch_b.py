"""Detector batch B — delegatecall, token, best-practice, informational.

Exports ``DETECTORS`` for registration by the integration step (the shared
``velvet.detectors`` registry merges all batches; this module keeps batch B
self-contained so the batches can be developed independently).

Original clean-room implementation.
"""

from velvet.detectors.arbitrary_send_erc20 import ArbitrarySendErc20
from velvet.detectors.base import Detector
from velvet.detectors.controlled_delegatecall import ControlledDelegatecall
from velvet.detectors.dead_code import DeadCode
from velvet.detectors.delegatecall_loop import DelegatecallLoop
from velvet.detectors.divide_before_multiply import DivideBeforeMultiply
from velvet.detectors.timestamp import Timestamp
from velvet.detectors.unchecked_lowlevel import UncheckedLowlevel
from velvet.detectors.unchecked_send import UncheckedSend
from velvet.detectors.unchecked_transfer import UncheckedTransfer
from velvet.detectors.weak_prng import WeakPrng

#: Batch-B detectors (ids normative per spec/detectors-catalog.md).
DETECTORS: list[type[Detector]] = [
    ControlledDelegatecall,
    DelegatecallLoop,
    ArbitrarySendErc20,
    UncheckedTransfer,
    UncheckedLowlevel,
    UncheckedSend,
    WeakPrng,
    Timestamp,
    DivideBeforeMultiply,
    DeadCode,
]

__all__ = [
    "DETECTORS",
    "ControlledDelegatecall",
    "DelegatecallLoop",
    "ArbitrarySendErc20",
    "UncheckedTransfer",
    "UncheckedLowlevel",
    "UncheckedSend",
    "WeakPrng",
    "Timestamp",
    "DivideBeforeMultiply",
    "DeadCode",
]
