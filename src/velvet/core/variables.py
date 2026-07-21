"""Variable model. Original clean-room implementation (spec/architecture.md §4.4)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from velvet.core.source_mapping import SourceMapping
from velvet.core.types import ElementaryType, Type

if TYPE_CHECKING:
    from velvet.core.contract import Contract
    from velvet.core.expressions import Expression
    from velvet.core.function import Function


class Variable(SourceMapping):
    """Base variable."""

    def __init__(self) -> None:
        super().__init__()
        self.name: str = ""
        self.type: Optional[Type] = None
        self.initialized: bool = False
        self.expression_initial: Optional[Expression] = None

    @property
    def is_scalar(self) -> bool:
        return isinstance(self.type, ElementaryType)

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"


class StateVariable(Variable):
    """Contract state variable."""

    def __init__(self) -> None:
        super().__init__()
        self.visibility: str = "internal"
        self.is_constant: bool = False
        self.is_immutable: bool = False
        self.slot: Optional[int] = None
        self.offset: Optional[int] = None
        self.contract: Optional[Contract] = None

    @property
    def canonical_name(self) -> str:
        cname = self.contract.name if self.contract else "?"
        return f"{cname}.{self.name}"


class LocalVariable(Variable):
    """Function-local variable (parameter, return, declared local)."""

    def __init__(self) -> None:
        super().__init__()
        self.location: Optional[str] = None  # memory | storage | calldata
        self.function: Optional[Function] = None

    @property
    def is_storage(self) -> bool:
        return self.location == "storage"


class Constant(Variable):
    """Literal constant value."""

    def __init__(self, value: Any, type_: Optional[Type] = None) -> None:
        super().__init__()
        self.value = value
        self.type = type_ or ElementaryType("uint256")
        self.name = str(value)
        self.original_str = str(value)

    def __str__(self) -> str:
        return self.original_str


class SolidityVariable(Variable):
    """Pseudo-variable for a language builtin (msg.sender, block.timestamp...)."""

    def __init__(self, name: str) -> None:
        super().__init__()
        self.name = name


_SOLIDITY_VARIABLES: dict[str, SolidityVariable] = {}


def solidity_variable(name: str) -> SolidityVariable:
    """Canonical singleton for a builtin pseudo-variable."""
    if name not in _SOLIDITY_VARIABLES:
        _SOLIDITY_VARIABLES[name] = SolidityVariable(name)
    return _SOLIDITY_VARIABLES[name]


SOLIDITY_VARIABLE_NAMES = (
    "msg.sender", "msg.value", "msg.data", "msg.sig",
    "block.timestamp", "block.number", "block.difficulty", "block.prevrandao",
    "block.coinbase", "block.gaslimit", "block.chainid", "block.basefee",
    "tx.origin", "tx.gasprice", "this", "now", "gasleft",
)


class UnresolvedSymbol:
    """Placeholder for a name that could not be resolved during parsing.

    The parsing layer resolves identifiers and type references through the
    solc AST ``referencedDeclaration`` ids; when no target is available (a
    builtin namespace such as ``msg``/``super``, or a forward reference not
    yet parsed), the placeholder keeps the surface ``name`` (and the AST
    ``ref_id`` when known) so later passes can still attempt resolution.
    """

    def __init__(self, name: str, ref_id: Optional[int] = None) -> None:
        self.name = name
        self.ref_id = ref_id

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"UnresolvedSymbol({self.name})"

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, UnresolvedSymbol)
            and self.name == other.name
            and self.ref_id == other.ref_id
        )

    def __hash__(self) -> int:
        return hash(("UnresolvedSymbol", self.name, self.ref_id))


class SolidityFunction:
    """Language builtin function (require, keccak256, selfdestruct, ...)."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"SolidityFunction({self.name})"

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, SolidityFunction) and self.name == other.name

    def __hash__(self) -> int:
        return hash(("SolidityFunction", self.name))


_SOLIDITY_FUNCTIONS: dict[str, SolidityFunction] = {}


def solidity_function(name: str) -> SolidityFunction:
    if name not in _SOLIDITY_FUNCTIONS:
        _SOLIDITY_FUNCTIONS[name] = SolidityFunction(name)
    return _SOLIDITY_FUNCTIONS[name]


SOLIDITY_FUNCTION_NAMES = (
    "require", "assert", "revert", "keccak256", "sha256", "ripemd160",
    "ecrecover", "addmod", "mulmod", "selfdestruct", "suicide",
    "blockhash", "gasleft", "type", "abi.encode", "abi.encodePacked",
    "abi.encodeWithSelector", "abi.encodeWithSignature", "abi.decode",
    "abi.encodeCall",
)
