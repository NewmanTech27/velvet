"""Detector batch C: best-practice, compiler-bug, informational and gas
detectors (SPEC.md §5, spec/detectors-catalog.md — normative entries).

These detectors are registered by the framework wiring that owns
``velvet.detectors``; this module only groups the batch for convenient
import (tests, plugin registration).

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors.abiencoderv2_array import AbiEncoderV2Array
from velvet.detectors.assembly import Assembly
from velvet.detectors.base import Detector
from velvet.detectors.constable_states import ConstableStates
from velvet.detectors.immutable_states import ImmutableStates
from velvet.detectors.low_level_calls import LowLevelCalls
from velvet.detectors.naming_convention import NamingConvention
from velvet.detectors.shadowing_builtin import ShadowingBuiltin
from velvet.detectors.shadowing_state import ShadowingState
from velvet.detectors.storage_array import StorageArray
from velvet.detectors.unused_state import UnusedState

#: Detectors implemented in batch C.
DETECTORS: list[type[Detector]] = [
    UnusedState,
    ShadowingState,
    ShadowingBuiltin,
    NamingConvention,
    AbiEncoderV2Array,
    StorageArray,
    Assembly,
    LowLevelCalls,
    ConstableStates,
    ImmutableStates,
]

__all__ = [
    "DETECTORS",
    "AbiEncoderV2Array",
    "Assembly",
    "ConstableStates",
    "ImmutableStates",
    "LowLevelCalls",
    "NamingConvention",
    "ShadowingBuiltin",
    "ShadowingState",
    "StorageArray",
    "UnusedState",
]
