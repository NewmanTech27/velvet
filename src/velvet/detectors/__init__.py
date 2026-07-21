"""velvet.detectors — detector framework + built-in detector registry.

Original clean-room implementation.
"""

from velvet.detectors import (
    _batch_a,
    _batch_b,
    _batch_c,
    _batch_d,
    _batch_e,
    _batch_f,
    _batch_g,
    _batch_h,
)
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.detectors.pragma import Pragma
from velvet.detectors.solc_version import SolcVersion
from velvet.detectors.tx_origin import TxOrigin

#: Built-in detectors, registered by default on every session.
BUILTIN_DETECTORS: list[type[Detector]] = [
    TxOrigin,
    Pragma,
    SolcVersion,
    *_batch_a.DETECTORS,
    *_batch_b.DETECTORS,
    *_batch_c.DETECTORS,
    *_batch_d.DETECTORS,
    *_batch_e.DETECTORS,
    *_batch_f.DETECTORS,
    *_batch_g.DETECTORS,
    *_batch_h.DETECTORS,
]

__all__ = [
    "Detector",
    "Finding",
    "Impact",
    "Confidence",
    "DetectorDocs",
    "BUILTIN_DETECTORS",
    "TxOrigin",
    "Pragma",
    "SolcVersion",
]
