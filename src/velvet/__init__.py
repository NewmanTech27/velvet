"""velvet — a clean-room static analysis framework for EVM smart contracts.

Original work, Apache-2.0 licensed. See NOTICE.md for clean-room provenance.
"""

__version__ = "0.3.1"

from velvet.exceptions import (  # noqa: F401
    AdapterError,
    CompilationError,
    ParsingError,
    VelvetError,
)


def __getattr__(name: str):
    """Lazy top-level exports (session layer lands in Wave 2)."""
    if name in ("Velvet", "Analyzer"):
        from velvet.session import Analyzer, Velvet

        return Velvet if name == "Velvet" else Analyzer
    raise AttributeError(f"module 'velvet' has no attribute {name!r}")


__all__ = [
    "Velvet",
    "Analyzer",
    "VelvetError",
    "CompilationError",
    "ParsingError",
    "AdapterError",
    "__version__",
]
