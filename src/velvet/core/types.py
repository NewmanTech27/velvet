"""Solidity type system model. Original clean-room implementation."""

from __future__ import annotations

from typing import Any, Optional


class Type:
    """Base type."""

    def __str__(self) -> str:  # pragma: no cover - abstract
        raise NotImplementedError

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Type) and str(self) == str(other)

    def __hash__(self) -> int:
        return hash(str(self))


_INT_ALIASES = {"uint": "uint256", "int": "int256", "byte": "bytes1"}


class ElementaryType(Type):
    """Elementary type, e.g. uint256, address payable, bool, bytes32."""

    def __init__(self, name: str) -> None:
        parts = name.split()
        base = parts[0]
        self.payable = "payable" in parts
        base = _INT_ALIASES.get(base, base)
        self.name = base + (" payable" if self.payable else "")

    @property
    def size(self) -> Optional[int]:
        """Bit/byte size for sized elementary types, else None."""
        n = self.name.split()[0]
        for prefix, unit in (("uint", 1), ("int", 1), ("bytes", 1)):
            if n.startswith(prefix) and n[len(prefix):].isdigit():
                return int(n[len(prefix):])
        return None

    def __str__(self) -> str:
        return self.name


class ArrayType(Type):
    """Array type; length None => dynamic array."""

    def __init__(self, elem_type: Type, length: Optional[int] = None) -> None:
        self.type = elem_type
        self.length = length

    @property
    def is_dynamic(self) -> bool:
        return self.length is None

    def __str__(self) -> str:
        suffix = "[]" if self.length is None else f"[{self.length}]"
        return f"{self.type}{suffix}"


class MappingType(Type):
    """mapping(key => value)."""

    def __init__(self, key_type: Type, value_type: Type) -> None:
        self.type_from = key_type
        self.type_to = value_type

    def __str__(self) -> str:
        return f"mapping({self.type_from} => {self.type_to})"


class UserDefinedType(Type):
    """Struct, enum, contract or user-defined value type reference."""

    def __init__(self, target: Any) -> None:  # Structure | Enum | Contract
        self.type = target

    def __str__(self) -> str:
        return getattr(self.type, "name", str(self.type))


class FunctionType(Type):
    """Function type (signature only; parameters/returns as type lists)."""

    def __init__(
        self,
        params: Optional[list[Type]] = None,
        returns: Optional[list[Type]] = None,
    ) -> None:
        self.params = params or []
        self.returns = returns or []

    def __str__(self) -> str:
        params = ",".join(str(p) for p in self.params)
        return f"function({params})"


class TupleType(Type):
    """Tuple of types (multi-value returns, destructuring)."""

    def __init__(self, types: list[Type]) -> None:
        self.types = types

    def __str__(self) -> str:
        return f"tuple({','.join(str(t) for t in self.types)})"
