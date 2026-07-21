"""Contract model with C3 linearized inheritance.

Original clean-room implementation (spec/architecture.md §4.2,
api-surface.md §3.2).
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING, Optional

from velvet.core.declarations import (
    CustomError,
    Enum,
    Event,
    Structure,
    UsingForDirective,
)
from velvet.core.function import Function, FunctionKind, Modifier
from velvet.core.source_mapping import SourceMapping
from velvet.core.variables import StateVariable

if TYPE_CHECKING:
    pass


class ContractKind(enum.Enum):
    CONTRACT = "contract"
    ABSTRACT = "abstract"
    INTERFACE = "interface"
    LIBRARY = "library"


def c3_linearization(name: str, direct_bases: list[str], ancestors: dict[str, list[str]]) -> list[str]:
    """Compute the C3 linearization of a contract's inheritance hierarchy.

    `ancestors` maps a contract name to the C3 linearization of its parents
    (already computed). Returns the linearized ancestor list, nearest first
    (excluding `name` itself). Raises ValueError on inconsistent hierarchies.

    Solidity requires base contracts to be listed "from most base-like to
    most derived" (Solidity docs, Inheritance — Multiple Inheritance and
    Linearization), so the local precedence list used by the C3 merge is the
    declared order reversed (nearest base first). Feeding the declared order
    directly makes the merge fail on every hierarchy that lists a base before
    its own parent (the common OpenZeppelin pattern).
    """

    def merge(seqs: list[list[str]]) -> list[str]:
        result: list[str] = []
        seqs = [list(s) for s in seqs]
        while any(seqs):
            for seq in seqs:
                if not seq:
                    continue
                head = seq[0]
                if all(head not in s[1:] for s in seqs):
                    result.append(head)
                    for s in seqs:
                        if s and s[0] == head:
                            s.pop(0)
                    break
            else:
                raise ValueError(f"Inconsistent inheritance hierarchy for {name}")
        return result

    # Full linearization of a parent = parent itself followed by its ancestors.
    parent_linos = [[b] + ancestors[b] for b in direct_bases]
    return merge(parent_linos + [list(reversed(direct_bases))])


class Contract(SourceMapping):
    """A Solidity contract / interface / library / abstract contract."""

    def __init__(self, name: str = "") -> None:
        super().__init__()
        self.name = name
        self.kind = ContractKind.CONTRACT
        self.compilation_unit: Optional[object] = None
        # inheritance (object links resolved after all contracts are parsed)
        self.direct_bases: list[Contract] = []
        self.inheritance: list[Contract] = []  # C3 linearized, nearest first
        self.derived_contracts: list[Contract] = []
        # declared members
        self.state_variables: list[StateVariable] = []
        self.functions: list[Function] = []
        self.modifiers: list[Modifier] = []
        self.events: list[Event] = []
        self.structures: list[Structure] = []
        self.enums: list[Enum] = []
        self.errors: list[CustomError] = []
        self.using_for: list[UsingForDirective] = []

    # ------------------------------------------------------------ members
    @property
    def inheritance_reverse(self) -> list[Contract]:
        return list(reversed(self.inheritance))

    @property
    def state_variables_inherited(self) -> list[StateVariable]:
        result: list[StateVariable] = []
        for base in self.inheritance_reverse:
            result.extend(base.state_variables)
        return result

    @property
    def state_variables_ordered(self) -> list[StateVariable]:
        """All state variables in storage layout order (bases first)."""
        return self.state_variables_inherited + self.state_variables

    @property
    def functions_entry_points(self) -> list[Function]:
        return [
            f
            for f in self.available_functions_from_inheritances()
            if f.visibility in ("external", "public")
        ]

    @property
    def functions_and_modifiers(self) -> list[Function | Modifier]:
        return list(self.functions) + list(self.modifiers)

    # ------------------------------------------------------------ lookups
    def get_function_from_signature(self, signature: str) -> Optional[Function]:
        for func in self.available_functions_from_inheritances():
            if func.signature == signature:
                return func
        return None

    def get_modifier_from_signature(self, signature: str) -> Optional[Modifier]:
        for mod in self.all_modifiers():
            if mod.signature == signature:
                return mod
        return None

    def get_state_variable_from_name(self, name: str) -> Optional[StateVariable]:
        for var in self.state_variables_ordered:
            if var.name == name:
                return var
        return None

    def available_functions_from_inheritances(self) -> list[Function]:
        """All callable functions (incl. inherited), honoring overrides.

        A function in a derived contract shadows the same-signature function
        in its bases.
        """
        result: list[Function] = []
        seen: set[str] = set()
        for func in self.functions:
            result.append(func)
            seen.add(func.signature)
        for base in self.inheritance:
            for func in base.functions:
                if func.signature not in seen and func.visibility != "private":
                    result.append(func)
                    seen.add(func.signature)
        return result

    def all_modifiers(self) -> list[Modifier]:
        result = list(self.modifiers)
        seen = {m.signature for m in result}
        for base in self.inheritance:
            for mod in base.modifiers:
                if mod.signature not in seen:
                    result.append(mod)
                    seen.add(mod.signature)
        return result

    # ---------------------------------------------------------- shadowing
    @property
    def state_variables_shadowed(self) -> list[StateVariable]:
        """Declared state variables hiding an inherited one."""
        inherited_names = {v.name for v in self.state_variables_inherited}
        return [v for v in self.state_variables if v.name in inherited_names]

    @property
    def functions_shadowed(self) -> list[Function]:
        inherited_sigs = {
            f.signature for b in self.inheritance for f in b.functions
        }
        return [f for f in self.functions if f.signature in inherited_sigs]

    # --------------------------------------------------------- ether flow
    @property
    def has_fallback(self) -> bool:
        return any(f.kind == FunctionKind.FALLBACK for f in self.functions)

    @property
    def has_receive(self) -> bool:
        return any(f.kind == FunctionKind.RECEIVE for f in self.functions)

    def can_receive_eth(self) -> bool:
        return self.has_receive or any(f.payable for f in self.functions)

    @property
    def is_interface(self) -> bool:
        return self.kind == ContractKind.INTERFACE

    @property
    def is_library(self) -> bool:
        return self.kind == ContractKind.LIBRARY

    @property
    def is_abstract(self) -> bool:
        return self.kind == ContractKind.ABSTRACT

    @property
    def signatures(self) -> list[str]:
        return [f.signature for f in self.functions_entry_points]

    # ------------------------------------------------------------- ERC heuristics
    def is_erc20(self) -> bool:
        """Heuristic: exposes the six ERC-20 functions."""
        required = {
            "totalSupply()",
            "balanceOf(address)",
            "transfer(address,uint256)",
            "transferFrom(address,address,uint256)",
            "approve(address,uint256)",
            "allowance(address,address)",
        }
        return required.issubset(set(self.signatures))

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"Contract({self.name}, {self.kind.value})"
