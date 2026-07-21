"""Batch D detectors (spec/detectors-catalog.md — normative).

Each detector lives in its own module; this module aggregates them for the
plugin registry.  Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors.arbitrary_send_erc20_permit import ArbitrarySendErc20Permit
from velvet.detectors.controlled_array_length import ControlledArrayLength
from velvet.detectors.encode_packed_collision import EncodePackedCollision
from velvet.detectors.incorrect_shift import IncorrectShift
from velvet.detectors.locked_ether import LockedEther
from velvet.detectors.multiple_constructors import MultipleConstructors
from velvet.detectors.name_reused import NameReused
from velvet.detectors.reentrancy_unlimited_gas import ReentrancyUnlimitedGas
from velvet.detectors.rtlo import Rtlo
from velvet.detectors.shadowing_abstract import ShadowingAbstract
from velvet.detectors.shadowing_local import ShadowingLocal
from velvet.detectors.uninitialized_fptr_cst import (
    UninitializedFunctionPointerConstructor,
)
from velvet.detectors.uninitialized_local import UninitializedLocal
from velvet.detectors.uninitialized_state import UninitializedState
from velvet.detectors.uninitialized_storage import UninitializedStorage

DETECTORS = [
    ArbitrarySendErc20Permit,
    ReentrancyUnlimitedGas,
    ControlledArrayLength,
    EncodePackedCollision,
    MultipleConstructors,
    NameReused,
    IncorrectShift,
    Rtlo,
    UninitializedState,
    UninitializedStorage,
    UninitializedLocal,
    UninitializedFunctionPointerConstructor,
    ShadowingAbstract,
    ShadowingLocal,
    LockedEther,
]
