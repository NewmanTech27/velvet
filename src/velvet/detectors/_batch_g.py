"""Detector batch G: array/assembly, deprecated-syntax, enum/event,
initializer, arithmetic and using-for detectors
(spec/detectors-catalog.md — normative entries).

These detectors are registered by the framework wiring that owns
``velvet.detectors``; this module only groups the batch for convenient
import (tests, plugin registration).

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors.array_by_reference import ArrayByReference
from velvet.detectors.assert_state_change import AssertStateChange
from velvet.detectors.base import Detector
from velvet.detectors.constant_function_asm import ConstantFunctionAsm
from velvet.detectors.constant_function_state import ConstantFunctionState
from velvet.detectors.deprecated_standards import DeprecatedStandards
from velvet.detectors.enum_conversion import EnumConversion
from velvet.detectors.events_maths import EventsMaths
from velvet.detectors.function_init_state import FunctionInitState
from velvet.detectors.incorrect_exp import IncorrectExp
from velvet.detectors.incorrect_return import IncorrectReturn
from velvet.detectors.incorrect_unary import IncorrectUnary
from velvet.detectors.incorrect_using_for import IncorrectUsingFor

#: Detectors implemented in batch G.
DETECTORS: list[type[Detector]] = [
    ArrayByReference,
    AssertStateChange,
    ConstantFunctionAsm,
    ConstantFunctionState,
    DeprecatedStandards,
    EnumConversion,
    EventsMaths,
    FunctionInitState,
    IncorrectExp,
    IncorrectReturn,
    IncorrectUnary,
    IncorrectUsingFor,
]

__all__ = [
    "DETECTORS",
    "ArrayByReference",
    "AssertStateChange",
    "ConstantFunctionAsm",
    "ConstantFunctionState",
    "DeprecatedStandards",
    "EnumConversion",
    "EventsMaths",
    "FunctionInitState",
    "IncorrectExp",
    "IncorrectReturn",
    "IncorrectUnary",
    "IncorrectUsingFor",
]
