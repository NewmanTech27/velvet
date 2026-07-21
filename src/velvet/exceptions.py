"""Velvet exception hierarchy."""


class VelvetError(Exception):
    """Base class for all velvet errors."""


class CompilationError(VelvetError):
    """Raised when the compilation layer fails (compiler diagnostics included)."""


class ParsingError(VelvetError):
    """Raised when the AST cannot be normalized or parsed into the core model."""


class AdapterError(VelvetError):
    """Raised when no compilation adapter can handle a target."""
