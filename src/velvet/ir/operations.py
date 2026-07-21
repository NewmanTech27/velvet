"""SolIR operations (spec/architecture.md §6.3, api-surface.md §3.7).

Every operation exposes a uniform variable model:

- ``read`` — the list of variables the operation consumes (RVALUEs), and
- ``lvalue`` — the variable the operation writes, if any
  (:class:`OperationWithLValue` subclasses).

Each operation class declares ``_read_slots``: the attribute names that hold
read variables (a single value or a list).  ``read`` is derived from those
slots, which keeps the SSA remap trivial (rewrite the slots, ``read``
follows).  Operations also remember their originating expression/node for
source mapping.

Canonical one-line renderings follow the shapes of architecture.md §6.3.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from velvet.core.variables import Variable

if TYPE_CHECKING:
    from velvet.core.cfg_node import CFGNode
    from velvet.core.contract import Contract
    from velvet.core.declarations import CustomError, Event, Structure
    from velvet.core.expressions import Expression
    from velvet.core.function import Function, FunctionLike
    from velvet.core.types import Type
    from velvet.core.variables import SolidityFunction


def _fmt(value: Any) -> str:
    """Render an operand for the canonical one-line string."""
    if value is None:
        return ""
    if isinstance(value, Variable):
        return value.name
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    return str(value)


class Operation:
    """Base IR operation: exposes ``read`` (empty by default)."""

    _read_slots: tuple[str, ...] = ()

    def __init__(self) -> None:
        self.expression: Optional[Expression] = None  # originating expression
        self.node: Optional[CFGNode] = None  # owning CFG node

    # ------------------------------------------------------------ variables
    def _slot_values(self, slot: str) -> list[Any]:
        value = getattr(self, slot, None)
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return [v for v in value if v is not None]
        return [value]

    @property
    def read(self) -> list[Any]:
        result: list[Any] = []
        for slot in self._read_slots:
            for value in self._slot_values(slot):
                if value not in result:
                    result.append(value)
        return result

    @property
    def lvalue(self) -> Optional[Any]:
        return None

    @property
    def used(self) -> list[Any]:
        """All variables used by the operation (read + written)."""
        result = list(self.read)
        if self.lvalue is not None and self.lvalue not in result:
            result.append(self.lvalue)
        return result

    @property
    def written(self) -> list[Any]:
        return [self.lvalue] if self.lvalue is not None else []

    def __str__(self) -> str:  # pragma: no cover - overridden
        return self.__class__.__name__.upper()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self})"


class OperationWithLValue(Operation):
    """An operation that writes a variable."""

    def __init__(self, lvalue: Any) -> None:
        super().__init__()
        self._lvalue = lvalue

    @property
    def lvalue(self) -> Optional[Any]:
        return self._lvalue

    def set_lvalue(self, value: Any) -> None:
        self._lvalue = value


# ------------------------------------------------------------------ basics
class Assignment(OperationWithLValue):
    """``LVALUE := RVALUE`` (also used for tuple/function dynamic dispatch)."""

    _read_slots = ("rvalue",)

    def __init__(self, lvalue: Any, rvalue: Any) -> None:
        super().__init__(lvalue)
        self.rvalue = rvalue

    def __str__(self) -> str:
        return f"{_fmt(self.lvalue)} := {_fmt(self.rvalue)}"


class Binary(OperationWithLValue):
    """``LVALUE = RVALUE <binop> RVALUE``."""

    _read_slots = ("left", "right")

    def __init__(self, lvalue: Any, left: Any, right: Any, operator: str) -> None:
        super().__init__(lvalue)
        self.left = left
        self.right = right
        self.operator = operator

    def __str__(self) -> str:
        return f"{_fmt(self.lvalue)} = {_fmt(self.left)} {self.operator} {_fmt(self.right)}"


class Unary(OperationWithLValue):
    """``LVALUE = <unop> RVALUE`` for ``! ~ -``."""

    _read_slots = ("rvalue",)

    def __init__(self, lvalue: Any, rvalue: Any, operator: str) -> None:
        super().__init__(lvalue)
        self.rvalue = rvalue
        self.operator = operator

    def __str__(self) -> str:
        op = f"{self.operator} " if self.operator.isalpha() else self.operator
        return f"{_fmt(self.lvalue)} = {op}{_fmt(self.rvalue)}"


# ------------------------------------------------------------ dereference
class Index(OperationWithLValue):
    """``REF -> base [ index ]`` (mapping/array dereference)."""

    _read_slots = ("base", "index")

    def __init__(self, lvalue: Any, base: Any, index: Any) -> None:
        super().__init__(lvalue)
        self.base = base
        self.index = index

    def __str__(self) -> str:
        return f"{_fmt(self.lvalue)} -> {_fmt(self.base)} [ {_fmt(self.index)} ]"


class Member(OperationWithLValue):
    """``REF -> base . member`` (struct field; contract/enum member access)."""

    _read_slots = ("base",)

    def __init__(self, lvalue: Any, base: Any, member_name: str) -> None:
        super().__init__(lvalue)
        self.base = base
        self.member_name = member_name

    def __str__(self) -> str:
        return f"{_fmt(self.lvalue)} -> {_fmt(self.base)} . {self.member_name}"


# -------------------------------------------------------------- allocation
class NewArray(OperationWithLValue):
    """``LVALUE = NEW_ARRAY type depth [size]``."""

    _read_slots = ("size",)

    def __init__(self, lvalue: Any, array_type: Optional[Type], depth: int, size: Any = None) -> None:
        super().__init__(lvalue)
        self.array_type = array_type
        self.depth = depth
        self.size = size

    def __str__(self) -> str:
        out = f"{_fmt(self.lvalue)} = NEW_ARRAY {self.array_type} depth {self.depth}"
        if self.size is not None:
            out += f" size {_fmt(self.size)}"
        return out


class NewContract(OperationWithLValue):
    """``LVALUE = NEW_CONTRACT contract`` (optional value/salt)."""

    _read_slots = ("call_value", "call_salt")

    def __init__(
        self, lvalue: Any, contract: Any, call_value: Any = None, call_salt: Any = None
    ) -> None:
        super().__init__(lvalue)
        self.contract = contract
        self.contract_name = getattr(contract, "name", str(contract))
        self.call_value = call_value
        self.call_salt = call_salt

    def __str__(self) -> str:
        out = f"{_fmt(self.lvalue)} = NEW_CONTRACT {self.contract_name}"
        if self.call_value is not None:
            out += f" value:{_fmt(self.call_value)}"
        if self.call_salt is not None:
            out += f" salt:{_fmt(self.call_salt)}"
        return out


class NewStructure(OperationWithLValue):
    """``LVALUE = NEW_STRUCTURE struct [args]``."""

    _read_slots = ("arguments",)

    def __init__(self, lvalue: Any, structure: Any, arguments: list[Any]) -> None:
        super().__init__(lvalue)
        self.structure = structure
        self.structure_name = getattr(structure, "name", str(structure))
        self.arguments = arguments

    def __str__(self) -> str:
        args = ", ".join(_fmt(a) for a in self.arguments)
        return f"{_fmt(self.lvalue)} = NEW_STRUCTURE {self.structure_name} args:[{args}]"


class NewElementaryType(OperationWithLValue):
    """``LVALUE = NEW_ELEMENTARY_TYPE type [size]`` (e.g. ``new bytes(n)``)."""

    _read_slots = ("size",)

    def __init__(self, lvalue: Any, type_: Optional[Type], size: Any = None) -> None:
        super().__init__(lvalue)
        self.type = type_
        self.size = size

    def __str__(self) -> str:
        out = f"{_fmt(self.lvalue)} = NEW_ELEMENTARY_TYPE {self.type}"
        if self.size is not None:
            out += f" size {_fmt(self.size)}"
        return out


# -------------------------------------------------------------- array ops
class Push(OperationWithLValue):
    """``PUSH array value`` — dedicated op, **not** a call.

    ``value`` is ``None`` for ``array.pop()`` (rendered ``POP array``).
    Pushing mutates the array: the array is both read and written (the
    ``lvalue``).  In SSA form the two are distinct versions and the
    rendering shows the written version explicitly.
    """

    _read_slots = ("array", "value")

    def __init__(self, array: Any, value: Any = None) -> None:
        super().__init__(array)
        self.array = array
        self.value = value

    def __str__(self) -> str:
        prefix = ""
        if self.lvalue is not None and self.lvalue is not self.array:
            prefix = f"{_fmt(self.lvalue)} = "
        if self.value is None:
            return f"{prefix}POP {_fmt(self.array)}"
        return f"{prefix}PUSH {_fmt(self.array)} {_fmt(self.value)}"


class Delete(OperationWithLValue):
    """``DELETE lvalue`` — the target is read and zeroed (written)."""

    _read_slots = ("target",)

    def __init__(self, target: Any) -> None:
        super().__init__(target)
        self.target = target

    def __str__(self) -> str:
        prefix = ""
        if self.lvalue is not None and self.lvalue is not self.target:
            prefix = f"{_fmt(self.lvalue)} = "
        return f"{prefix}DELETE {_fmt(self.target)}"


# -------------------------------------------------------------- conversion
class TypeConversion(OperationWithLValue):
    """``LVALUE = CONVERT rvalue to type``."""

    _read_slots = ("rvalue",)

    def __init__(self, lvalue: Any, rvalue: Any, type_: Optional[Type]) -> None:
        super().__init__(lvalue)
        self.rvalue = rvalue
        self.type = type_

    def __str__(self) -> str:
        return f"{_fmt(self.lvalue)} = CONVERT {_fmt(self.rvalue)} to {self.type}"


# ------------------------------------------------------------------ tuples
class Unpack(OperationWithLValue):
    """``LVALUE = UNPACK tuple index``."""

    _read_slots = ("tuple_variable",)

    def __init__(self, lvalue: Any, tuple_variable: Any, index: int) -> None:
        super().__init__(lvalue)
        self.tuple_variable = tuple_variable
        self.index = index

    def __str__(self) -> str:
        return f"{_fmt(self.lvalue)} = UNPACK {_fmt(self.tuple_variable)} index: {self.index}"


class InitArray(OperationWithLValue):
    """``LVALUE = INIT [values...]`` (array literal; nested for multi-dim)."""

    _read_slots = ("values",)

    def __init__(self, lvalue: Any, values: list[Any]) -> None:
        super().__init__(lvalue)
        self.values = values

    def __str__(self) -> str:
        inner = ", ".join(_fmt(v) for v in self.values)
        return f"{_fmt(self.lvalue)} = INIT [{inner}]"


# ------------------------------------------------------------------- calls
class Call(Operation):
    """Base class for call-like operations."""

    _read_slots = ("arguments",)

    def __init__(self) -> None:
        super().__init__()
        self.arguments: list[Any] = []


class HighLevelCall(OperationWithLValue, Call):
    """``LVALUE = HIGH_LEVEL_CALL dest function [args] [value] [gas]``.

    ``function`` is the resolved target :class:`~velvet.core.function.Function`
    when known (None for e.g. cross-contract public getters); ``function_name``
    always carries the surface name.
    """

    _read_slots = ("destination", "arguments", "call_value", "call_gas")

    def __init__(
        self,
        lvalue: Any,
        destination: Any,
        function_name: str,
        arguments: list[Any],
        function: Optional[Function] = None,
        call_value: Any = None,
        call_gas: Any = None,
    ) -> None:
        super().__init__(lvalue)
        self.destination = destination
        self.function = function
        self.function_name = function_name
        self.arguments = arguments
        self.call_value = call_value
        self.call_gas = call_gas

    @property
    def is_library_call(self) -> bool:
        return False

    def _prefix(self) -> str:
        return f"{_fmt(self.lvalue)} = " if self.lvalue is not None else ""

    def __str__(self) -> str:
        args = ", ".join(_fmt(a) for a in self.arguments)
        out = (
            f"{self._prefix()}HIGH_LEVEL_CALL dest:{_fmt(self.destination)} "
            f"function:{self.function_name} args:[{args}]"
        )
        if self.call_value is not None:
            out += f" value:{_fmt(self.call_value)}"
        if self.call_gas is not None:
            out += f" gas:{_fmt(self.call_gas)}"
        return out


class LowLevelCall(OperationWithLValue, Call):
    """``LVALUE = LOW_LEVEL_CALL dest name [args]`` with name in
    {``call``, ``delegatecall``, ``staticcall``, ``callcode``} (+value/gas)."""

    _read_slots = ("destination", "arguments", "call_value", "call_gas")

    NAMES = ("call", "delegatecall", "staticcall", "callcode")

    def __init__(
        self,
        lvalue: Any,
        destination: Any,
        function_name: str,
        arguments: list[Any],
        call_value: Any = None,
        call_gas: Any = None,
    ) -> None:
        if function_name not in self.NAMES:
            raise ValueError(f"Invalid low-level call name {function_name!r}")
        super().__init__(lvalue)
        self.destination = destination
        self.function_name = function_name
        self.arguments = arguments
        self.call_value = call_value
        self.call_gas = call_gas

    def __str__(self) -> str:
        args = ", ".join(_fmt(a) for a in self.arguments)
        prefix = f"{_fmt(self.lvalue)} = " if self.lvalue is not None else ""
        out = (
            f"{prefix}LOW_LEVEL_CALL dest:{_fmt(self.destination)} "
            f"function:{self.function_name} args:[{args}]"
        )
        if self.call_value is not None:
            out += f" value:{_fmt(self.call_value)}"
        if self.call_gas is not None:
            out += f" gas:{_fmt(self.call_gas)}"
        return out


class LibraryCall(HighLevelCall):
    """``LVALUE = LIBRARY_CALL dest function [args]`` — receiver is first arg."""

    def __init__(
        self,
        lvalue: Any,
        destination: Any,  # the library Contract
        function_name: str,
        arguments: list[Any],
        function: Optional[Function] = None,
    ) -> None:
        super().__init__(lvalue, destination, function_name, arguments, function)

    @property
    def is_library_call(self) -> bool:
        return True

    def __str__(self) -> str:
        args = ", ".join(_fmt(a) for a in self.arguments)
        return (
            f"{self._prefix()}LIBRARY_CALL dest:{_fmt(self.destination)} "
            f"function:{self.function_name} args:[{args}]"
        )


class InternalCall(OperationWithLValue, Call):
    """``LVALUE = INTERNAL_CALL function [args]``.

    ``is_static`` marks statically-bound internal calls: ancestor-qualified
    ``Base.f(...)`` and ``super.f(...)`` compile to a direct jump to that
    exact implementation, so virtual dispatch (override resolution to the
    most-derived contract) must NOT be applied to them — unlike a plain
    ``f(...)`` internal call, which dispatches to the most-derived override.
    """

    def __init__(
        self,
        lvalue: Any,
        function: Optional[FunctionLike],
        arguments: list[Any],
        is_static: bool = False,
    ) -> None:
        super().__init__(lvalue)
        self.function = function
        self.function_name = getattr(function, "name", str(function))
        self.arguments = arguments
        self.is_static = is_static

    def __str__(self) -> str:
        args = ", ".join(_fmt(a) for a in self.arguments)
        prefix = f"{_fmt(self.lvalue)} = " if self.lvalue is not None else ""
        return f"{prefix}INTERNAL_CALL function:{self.function_name} args:[{args}]"


class InternalDynamicCall(OperationWithLValue, Call):
    """``LVALUE = INTERNAL_DYNAMIC_CALL fn_ptr_var [args]``."""

    _read_slots = ("function_variable", "arguments")

    def __init__(self, lvalue: Any, function_variable: Any, arguments: list[Any]) -> None:
        super().__init__(lvalue)
        self.function_variable = function_variable
        self.arguments = arguments

    def __str__(self) -> str:
        args = ", ".join(_fmt(a) for a in self.arguments)
        return (
            f"{_fmt(self.lvalue)} = INTERNAL_DYNAMIC_CALL "
            f"function:{_fmt(self.function_variable)} args:[{args}]"
        )


class SolidityCall(OperationWithLValue, Call):
    """``LVALUE = SOLIDITY_CALL builtin [args]`` (require/assert/keccak256/...)."""

    def __init__(self, lvalue: Any, function: SolidityFunction, arguments: list[Any]) -> None:
        super().__init__(lvalue)
        self.function = function
        self.arguments = arguments

    def __str__(self) -> str:
        args = ", ".join(_fmt(a) for a in self.arguments)
        prefix = f"{_fmt(self.lvalue)} = " if self.lvalue is not None else ""
        return f"{prefix}SOLIDITY_CALL {self.function.name}({args})"


class EventCall(Operation):
    """``EVENT_CALL event [args]``."""

    _read_slots = ("arguments",)

    def __init__(self, event: Optional[Event], arguments: list[Any], name: str = "") -> None:
        super().__init__()
        self.event = event
        self.name = name or getattr(event, "name", "?")
        self.arguments = arguments

    def __str__(self) -> str:
        args = ", ".join(_fmt(a) for a in self.arguments)
        return f"EVENT_CALL {self.name}({args})"


class Send(OperationWithLValue, Call):
    """``LVALUE = SEND dest amount``."""

    _read_slots = ("destination", "amount")

    def __init__(self, lvalue: Any, destination: Any, amount: Any) -> None:
        super().__init__(lvalue)
        self.destination = destination
        self.amount = amount

    def __str__(self) -> str:
        return f"{_fmt(self.lvalue)} = SEND dest:{_fmt(self.destination)} amount:{_fmt(self.amount)}"


class Transfer(Call):
    """``TRANSFER dest amount``."""

    _read_slots = ("destination", "amount")

    def __init__(self, destination: Any, amount: Any) -> None:
        super().__init__()
        self.destination = destination
        self.amount = amount

    def __str__(self) -> str:
        return f"TRANSFER dest:{_fmt(self.destination)} amount:{_fmt(self.amount)}"


# --------------------------------------------------------------- terminators
class Return(Operation):
    """``RETURN values...`` (possibly empty)."""

    _read_slots = ("values",)

    def __init__(self, values: Optional[list[Any]] = None) -> None:
        super().__init__()
        self.values = values or []

    def __str__(self) -> str:
        if not self.values:
            return "RETURN"
        inner = ", ".join(_fmt(v) for v in self.values)
        return f"RETURN {inner}"


class Condition(Operation):
    """``CONDITION rvalue`` — attached to IF / IF_LOOP nodes."""

    _read_slots = ("value",)

    def __init__(self, value: Any) -> None:
        super().__init__()
        self.value = value

    def __str__(self) -> str:
        return f"CONDITION {_fmt(self.value)}"


# ---------------------------------------------------------------------- SSA
class Phi(OperationWithLValue):
    """SSA-only ``LVALUE = phi(candidates...)``.

    Placed at control-flow merges, at function entry for state variables
    (value may come from a previous transaction) and after external calls
    (value may have changed through reentrancy), per architecture.md §6.5.
    """

    _read_slots = ("candidates",)

    # Origins for documentation/consumers: "merge" | "entry" | "external_call"
    def __init__(self, lvalue: Any, candidates: list[Any], origin: str = "merge") -> None:
        super().__init__(lvalue)
        self.candidates = candidates
        self.origin = origin

    def __str__(self) -> str:
        inner = ", ".join(_fmt(c) for c in self.candidates)
        return f"{_fmt(self.lvalue)} = phi({inner})"
