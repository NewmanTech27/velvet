"""Compilation adapter protocol. Original clean-room implementation."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from velvet.compile.artifacts import CompilationArtifacts


@runtime_checkable
class Adapter(Protocol):
    """A compilation target adapter."""

    def matches(self, target: str) -> bool:
        """Can this adapter handle the target?"""
        ...

    def compile(self, target: str, **options: Any) -> list[CompilationArtifacts]:
        """Compile the target into artifacts."""
        ...
