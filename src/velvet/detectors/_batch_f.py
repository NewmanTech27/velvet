"""Detector batch F: oracle/randomness, L2/security, complexity/best-practice
and gas detectors (spec/detectors-catalog.md — normative entries).

These detectors are registered by the framework wiring that owns
``velvet.detectors``; this module only groups the batch for convenient
import (tests, plugin registration).

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.detectors.base import Detector
from velvet.detectors.boolean_equal import BooleanEqual
from velvet.detectors.cache_array_length import CacheArrayLength
from velvet.detectors.chainlink_feed_registry import ChainlinkFeedRegistry
from velvet.detectors.chronicle_unchecked_price import ChronicleUncheckedPrice
from velvet.detectors.costly_loop import CostlyLoop
from velvet.detectors.cyclomatic_complexity import CyclomaticComplexity
from velvet.detectors.external_function import ExternalFunction
from velvet.detectors.gelato_unprotected_randomness import (
    GelatoUnprotectedRandomness,
)
from velvet.detectors.out_of_order_retryable import OutOfOrderRetryable
from velvet.detectors.pyth_deprecated_functions import PythDeprecatedFunctions
from velvet.detectors.pyth_unchecked_confidence import PythUncheckedConfidence
from velvet.detectors.pyth_unchecked_publishtime import PythUncheckedPublishtime
from velvet.detectors.return_bomb import ReturnBomb
from velvet.detectors.too_many_digits import TooManyDigits
from velvet.detectors.void_cst import VoidCst

#: Detectors implemented in batch F.
DETECTORS: list[type[Detector]] = [
    PythUncheckedConfidence,
    PythUncheckedPublishtime,
    PythDeprecatedFunctions,
    ChronicleUncheckedPrice,
    ChainlinkFeedRegistry,
    GelatoUnprotectedRandomness,
    OutOfOrderRetryable,
    ReturnBomb,
    CyclomaticComplexity,
    VoidCst,
    TooManyDigits,
    BooleanEqual,
    CacheArrayLength,
    ExternalFunction,
    CostlyLoop,
]

__all__ = [
    "DETECTORS",
    "BooleanEqual",
    "CacheArrayLength",
    "ChainlinkFeedRegistry",
    "ChronicleUncheckedPrice",
    "CostlyLoop",
    "CyclomaticComplexity",
    "ExternalFunction",
    "GelatoUnprotectedRandomness",
    "OutOfOrderRetryable",
    "PythDeprecatedFunctions",
    "PythUncheckedConfidence",
    "PythUncheckedPublishtime",
    "ReturnBomb",
    "TooManyDigits",
    "VoidCst",
]
