"""velvet.printers — printer framework + built-in printer registry.

The framework contract lives in :mod:`velvet.printers.base`.  Built-in
printers are grouped into batch modules (one per delivery wave) that each
export a ``PRINTERS`` list; the imports below are flattened into
``BUILTIN_PRINTERS``.  When merging additional batches, add one import and
extend the list — keep one import per batch so merges stay conflict-free.
"""

from velvet.printers import _batch_printers
from velvet.printers.base import Printer

#: Built-in printers, registered by default on every session.
BUILTIN_PRINTERS: list[type[Printer]] = [
    *_batch_printers.PRINTERS,
]

__all__ = ["Printer", "BUILTIN_PRINTERS"]
