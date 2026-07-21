"""Detector batch H: value-accounting loops, balance-delta reentrancy,
assembly return paths, constructor graphs, compiler-bug mappings,
scope/interface/event and gas rules (spec/detectors-catalog.md —
normative entries).

These detectors are registered by the framework wiring that owns
``velvet.detectors``; this module only groups the batch for convenient
import (tests, plugin registration).

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors.base import Detector
from velvet.detectors.msg_value_loop import MsgValueLoop
from velvet.detectors.optimism_deprecation import OptimismDeprecation
from velvet.detectors.public_mappings_nested import PublicMappingsNested
from velvet.detectors.redundant_statements import RedundantStatements
from velvet.detectors.reentrancy_balance import ReentrancyBalance
from velvet.detectors.return_leave import ReturnLeave
from velvet.detectors.reused_constructor import ReusedConstructor
from velvet.detectors.unimplemented_functions import UnimplementedFunctions
from velvet.detectors.unindexed_event_address import UnindexedEventAddress
from velvet.detectors.var_read_using_this import VarReadUsingThis
from velvet.detectors.variable_scope import VariableScope

#: Detectors implemented in batch H.
DETECTORS: list[type[Detector]] = [
    ReentrancyBalance,
    MsgValueLoop,
    ReturnLeave,
    PublicMappingsNested,
    ReusedConstructor,
    OptimismDeprecation,
    VariableScope,
    RedundantStatements,
    UnimplementedFunctions,
    UnindexedEventAddress,
    VarReadUsingThis,
]

__all__ = [
    "DETECTORS",
    "MsgValueLoop",
    "OptimismDeprecation",
    "PublicMappingsNested",
    "RedundantStatements",
    "ReentrancyBalance",
    "ReturnLeave",
    "ReusedConstructor",
    "UnimplementedFunctions",
    "UnindexedEventAddress",
    "VarReadUsingThis",
    "VariableScope",
]
