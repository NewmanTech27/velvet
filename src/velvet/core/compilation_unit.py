"""CompilationUnit — everything produced by one compilation batch.

Original clean-room implementation (spec/architecture.md §4.1,
api-surface.md §3.1).
"""

from __future__ import annotations

from typing import Optional

from velvet.compile.artifacts import CompilationArtifacts
from velvet.core.contract import Contract
from velvet.core.declarations import (
    CustomError,
    Enum,
    Event,
    ImportDirective,
    PragmaDirective,
    Structure,
    UsingForDirective,
)
from velvet.core.function import Function, Modifier
from velvet.core.variables import StateVariable


class CompilationUnit:
    """Container for all model objects of one compilation."""

    def __init__(self, artifacts: CompilationArtifacts) -> None:
        self.compilation = artifacts
        self.contracts: list[Contract] = []
        self.structures: list[Structure] = []
        self.events: list[Event] = []
        self.enums: list[Enum] = []
        self.errors: list[CustomError] = []
        self.pragmas: list[PragmaDirective] = []
        self.imports: list[ImportDirective] = []
        self.top_level_functions: list[Function] = []
        self.top_level_variables: list[StateVariable] = []
        self.using_for: list[UsingForDirective] = []  # file-level directives

    # ------------------------------------------------------------ derived
    @property
    def solc_version(self) -> str:
        return self.compilation.compiler_version

    @property
    def contracts_derived(self) -> list[Contract]:
        """Most-derived contracts only (not inherited by any other contract).

        Detectors iterate this set to avoid duplicate findings.
        """
        return [c for c in self.contracts if not c.derived_contracts]

    @property
    def functions_and_modifiers(self) -> list[Function | Modifier]:
        result: list[Function | Modifier] = []
        for contract in self.contracts:
            result.extend(contract.functions)
            result.extend(contract.modifiers)
        result.extend(self.top_level_functions)
        return result

    @property
    def state_variables(self) -> list[StateVariable]:
        result: list[StateVariable] = []
        for contract in self.contracts:
            result.extend(contract.state_variables)
        result.extend(self.top_level_variables)
        return result

    # ------------------------------------------------------------ lookups
    def get_contract_from_name(self, name: str) -> Optional[Contract]:
        matches = [c for c in self.contracts if c.name == name]
        return matches[0] if matches else None

    def get_state_variable_from_name(self, name: str) -> Optional[StateVariable]:
        for var in self.state_variables:
            if var.name == name:
                return var
        return None

    def is_dependency(self, path: str) -> bool:
        from velvet.compile.artifacts import is_dependency_path

        return is_dependency_path(path)

    def filename_lookup(self, used_path: str):
        return self.compilation.filename_lookup(used_path)
