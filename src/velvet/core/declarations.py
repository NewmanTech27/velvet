"""Non-function declarations: events, structs, enums, errors, pragmas, imports.

Original clean-room implementation (spec/architecture.md §4.6).
"""

from __future__ import annotations

from typing import Any, Optional

from velvet.core.source_mapping import SourceMapping
from velvet.core.types import Type


class Event(SourceMapping):
    def __init__(self, name: str = "") -> None:
        super().__init__()
        self.name = name
        self.elems: list[EventParam] = []
        self.contract: Any = None
        self.anonymous: bool = False

    @property
    def signature(self) -> str:
        return f"{self.name}({','.join(str(p.type) for p in self.elems)})"

    def __str__(self) -> str:
        return self.name


class EventParam:
    def __init__(self, name: str, type_: Optional[Type], indexed: bool) -> None:
        self.name = name
        self.type = type_
        self.indexed = indexed


class Structure(SourceMapping):
    def __init__(self, name: str = "") -> None:
        super().__init__()
        self.name = name
        self.elems: list[StructField] = []
        self.contract: Any = None

    def __str__(self) -> str:
        return self.name


class StructField:
    def __init__(self, name: str, type_: Optional[Type]) -> None:
        self.name = name
        self.type = type_


class Enum(SourceMapping):
    def __init__(self, name: str = "") -> None:
        super().__init__()
        self.name = name
        self.values: list[str] = []
        self.contract: Any = None

    def __str__(self) -> str:
        return self.name


class CustomError(SourceMapping):
    def __init__(self, name: str = "") -> None:
        super().__init__()
        self.name = name
        self.parameters: list[tuple[str, Optional[Type]]] = []
        self.contract: Any = None

    @property
    def signature(self) -> str:
        return f"{self.name}({','.join(str(t) for _, t in self.parameters)})"

    def __str__(self) -> str:
        return self.name


class PragmaDirective(SourceMapping):
    def __init__(self, name: str = "", version: str = "") -> None:
        super().__init__()
        self.name = name  # e.g. "solidity"
        self.version = version  # raw version expression e.g. "^0.8.0"

    @property
    def directive(self) -> list[str]:
        return [self.name, self.version] if self.version else [self.name]

    def __str__(self) -> str:
        return f"pragma {self.name} {self.version}".strip()


class ImportDirective(SourceMapping):
    def __init__(self, path: str = "") -> None:
        super().__init__()
        self.path = path
        self.alias: Optional[str] = None
        self.symbol_aliases: dict[str, str] = {}  # imported -> local

    def __str__(self) -> str:
        return f'import "{self.path}"'


class UsingForDirective(SourceMapping):
    def __init__(self) -> None:
        super().__init__()
        self.library_name: str = ""
        self.type_name: Optional[str] = None  # None => "*"
        # Resolved cross-references (filled by the parsing resolution pass;
        # consumed by the IR layer to lower `x.f(y)` to library calls).
        self.library: Any = None  # Optional[Contract]
        self.type: Optional[Type] = None  # None => "*"

    def __str__(self) -> str:
        target = self.type_name or "*"
        return f"using {self.library_name} for {target}"
