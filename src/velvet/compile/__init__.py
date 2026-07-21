"""velvet.compile — our own compilation abstraction layer.

Auto-discriminates the target and returns normalized CompilationArtifacts.
Original clean-room implementation (see spec/architecture.md §3).

Target discrimination order: standard-JSON document, single .sol file, 0x
contract address (block explorer), framework project (foundry.toml,
hardhat.config.*, brownie-config.yaml markers, in that order), plain
directory of .sol files. The ``force_framework`` option bypasses marker
detection and routes a directory to the named framework adapter.
"""

from __future__ import annotations

from typing import Any

from velvet.compile.adapters.brownie import BrownieAdapter
from velvet.compile.adapters.explorer import ExplorerAdapter
from velvet.compile.adapters.foundry import FoundryAdapter
from velvet.compile.adapters.hardhat import HardhatAdapter
from velvet.compile.adapters.project_dir import ProjectDirAdapter
from velvet.compile.adapters.sol_file import SolFileAdapter
from velvet.compile.adapters.standard_json import StandardJsonAdapter
from velvet.compile.artifacts import (
    CompilationArtifacts,
    Filename,
    SourceUnitInfo,
    convert_offset_to_line_column,
    is_dependency_path,
)
from velvet.exceptions import AdapterError

__all__ = [
    "CompilationArtifacts",
    "Filename",
    "SourceUnitInfo",
    "compile_target",
    "convert_offset_to_line_column",
    "is_dependency_path",
    "FRAMEWORK_ADAPTERS",
]

#: Framework name -> adapter class, for auto-detection and force_framework.
FRAMEWORK_ADAPTERS: dict[str, type] = {
    "foundry": FoundryAdapter,
    "hardhat": HardhatAdapter,
    "brownie": BrownieAdapter,
}

_ADAPTERS = [
    StandardJsonAdapter(),
    SolFileAdapter(),
    ExplorerAdapter(),
    FoundryAdapter(),
    HardhatAdapter(),
    BrownieAdapter(),
    ProjectDirAdapter(),
]


def compile_target(target: str, **options: Any) -> list[CompilationArtifacts]:
    """Compile a target (.sol file, directory, 0x address, or JSON document)."""
    force = options.get("force_framework")
    if force:
        key = str(force).strip().lower()
        adapter_class = FRAMEWORK_ADAPTERS.get(key)
        if adapter_class is None:
            raise AdapterError(
                f"Unknown framework {force!r}; "
                f"expected one of {sorted(FRAMEWORK_ADAPTERS)}"
            )
        return adapter_class().compile(target, **options)
    for adapter in _ADAPTERS:
        if adapter.matches(target):
            return adapter.compile(target, **options)
    raise AdapterError(f"No compilation adapter can handle target: {target!r}")
