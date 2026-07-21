"""Detector batch E: loop/call, constant-condition, write, token-interface
and event detectors (spec/detectors-catalog.md — normative entries).

These detectors are registered by the framework wiring that owns
``velvet.detectors``; this module only groups the batch for convenient
import (tests, plugin registration).

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors.base import Detector
from velvet.detectors.boolean_cst import BooleanCst
from velvet.detectors.calls_loop import CallsLoop
from velvet.detectors.domain_separator_collision import DomainSeparatorCollision
from velvet.detectors.erc20_indexed import Erc20Indexed
from velvet.detectors.erc20_interface import Erc20Interface
from velvet.detectors.erc721_interface import Erc721Interface
from velvet.detectors.events_access import EventsAccess
from velvet.detectors.incorrect_equality import IncorrectEquality
from velvet.detectors.incorrect_modifier import IncorrectModifier
from velvet.detectors.mapping_deletion import MappingDeletion
from velvet.detectors.missing_inheritance import MissingInheritance
from velvet.detectors.tautological_compare import TautologicalCompare
from velvet.detectors.tautology import Tautology
from velvet.detectors.unused_return import UnusedReturn
from velvet.detectors.write_after_write import WriteAfterWrite

#: Detectors implemented in batch E.
DETECTORS: list[type[Detector]] = [
    CallsLoop,
    UnusedReturn,
    BooleanCst,
    Tautology,
    TautologicalCompare,
    IncorrectEquality,
    WriteAfterWrite,
    MappingDeletion,
    IncorrectModifier,
    DomainSeparatorCollision,
    Erc20Interface,
    Erc721Interface,
    Erc20Indexed,
    MissingInheritance,
    EventsAccess,
]

__all__ = [
    "DETECTORS",
    "BooleanCst",
    "CallsLoop",
    "DomainSeparatorCollision",
    "Erc20Indexed",
    "Erc20Interface",
    "Erc721Interface",
    "EventsAccess",
    "IncorrectEquality",
    "IncorrectModifier",
    "MappingDeletion",
    "MissingInheritance",
    "TautologicalCompare",
    "Tautology",
    "UnusedReturn",
    "WriteAfterWrite",
]
