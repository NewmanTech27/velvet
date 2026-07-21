"""Typed expression trees. Original clean-room implementation
(spec/architecture.md §4.5)."""

from __future__ import annotations

from typing import Any, Iterator, Optional

from velvet.core.source_mapping import SourceMapping
from velvet.core.types import Type


class Expression(SourceMapping):
    """Base expression. `type` is attached during parsing."""

    def __init__(self) -> None:
        super().__init__()
        self.type: Optional[Type] = None

    def children(self) -> Iterator[Expression]:
        """Iterate direct sub-expressions."""
        return iter(())

    def walk(self) -> Iterator[Expression]:
        """Depth-first iteration over self and all sub-expressions."""
        yield self
        for child in self.children():
            yield from child.walk()

    @property
    def contains_conditional(self) -> bool:
        return any(isinstance(e, ConditionalExpression) for e in self.walk())


class AssignmentOperation(Expression):
    OPERATORS = (
        "=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<=", ">>=",
    )

    def __init__(self, left: Expression, right: Expression, operator: str = "=") -> None:
        super().__init__()
        if operator not in self.OPERATORS:
            raise ValueError(f"Invalid assignment operator {operator}")
        self.expression_left = left
        self.expression_right = right
        self.operator = operator

    def children(self) -> Iterator[Expression]:
        yield self.expression_left
        yield self.expression_right

    def __str__(self) -> str:
        return f"{self.expression_left} {self.operator} {self.expression_right}"


class BinaryOperation(Expression):
    OPERATORS = (
        "**", "*", "/", "%", "+", "-", "<<", ">>", "&", "^", "|",
        "<", ">", "<=", ">=", "==", "!=", "&&", "||",
    )

    def __init__(self, left: Expression, right: Expression, operator: str) -> None:
        super().__init__()
        self.expression_left = left
        self.expression_right = right
        self.operator = operator

    def children(self) -> Iterator[Expression]:
        yield self.expression_left
        yield self.expression_right

    def __str__(self) -> str:
        return f"{self.expression_left} {self.operator} {self.expression_right}"


class UnaryOperation(Expression):
    def __init__(self, operand: Expression, operator: str, is_prefix: bool = True) -> None:
        super().__init__()
        self.expression = operand
        self.operator = operator
        self.is_prefix = is_prefix

    def children(self) -> Iterator[Expression]:
        yield self.expression

    def __str__(self) -> str:
        if self.is_prefix:
            if self.operator.isalpha():  # word operators: `delete x`
                return f"{self.operator} {self.expression}"
            return f"{self.operator}{self.expression}"
        return f"{self.expression}{self.operator}"


class CallExpression(Expression):
    """A call: `called(arguments)`. `called` may be Identifier/MemberAccess/NewExpression.

    ``call_value``/``call_gas``/``call_salt`` hold the expressions attached
    through a ``{value: …, gas: …, salt: …}`` call-options suffix, when any.
    They are plain expression trees; the IR layer (Wave 2) lifts them onto
    the corresponding call operations.
    """

    def __init__(self, called: Expression, arguments: list[Expression]) -> None:
        super().__init__()
        self.called = called
        self.arguments = arguments
        self.call_value: Optional[Expression] = None
        self.call_gas: Optional[Expression] = None
        self.call_salt: Optional[Expression] = None

    def children(self) -> Iterator[Expression]:
        yield self.called
        yield from self.arguments

    def __str__(self) -> str:
        args = ", ".join(str(a) for a in self.arguments)
        return f"{self.called}({args})"


class ConditionalExpression(Expression):
    def __init__(self, condition: Expression, then: Expression, otherwise: Expression) -> None:
        super().__init__()
        self.condition = condition
        self.then_expression = then
        self.else_expression = otherwise

    def children(self) -> Iterator[Expression]:
        yield self.condition
        yield self.then_expression
        yield self.else_expression

    def __str__(self) -> str:
        return f"{self.condition} ? {self.then_expression} : {self.else_expression}"


class Identifier(Expression):
    """Reference to a variable/function/contract (resolved during parsing)."""

    def __init__(self, value: Any) -> None:
        super().__init__()
        self.value = value  # Variable | Function | Contract | SolidityFunction | Type

    def __str__(self) -> str:
        return getattr(self.value, "name", str(self.value))


class Literal(Expression):
    def __init__(self, value: str) -> None:
        super().__init__()
        self.value = value

    def __str__(self) -> str:
        return self.value


class IndexAccess(Expression):
    def __init__(self, base: Expression, index: Optional[Expression]) -> None:
        super().__init__()
        self.expression_left = base
        self.expression_right = index

    def children(self) -> Iterator[Expression]:
        yield self.expression_left
        if self.expression_right is not None:
            yield self.expression_right

    def __str__(self) -> str:
        return f"{self.expression_left}[{self.expression_right}]"


class MemberAccess(Expression):
    def __init__(self, base: Expression, member_name: str) -> None:
        super().__init__()
        self.expression = base
        self.member_name = member_name

    def children(self) -> Iterator[Expression]:
        yield self.expression

    def __str__(self) -> str:
        return f"{self.expression}.{self.member_name}"


class TupleExpression(Expression):
    def __init__(self, expressions: list[Optional[Expression]]) -> None:
        super().__init__()
        self.expressions = expressions
        # True when the tuple is an inline array literal (`[1, 2, 3]`).
        self.is_inline_array: bool = False

    def children(self) -> Iterator[Expression]:
        yield from (e for e in self.expressions if e is not None)

    def __str__(self) -> str:
        inner = ", ".join(str(e) if e else "" for e in self.expressions)
        return f"({inner})"


class NewExpression(Expression):
    """`new X(...)` — new contract or array allocation."""

    def __init__(self, type_name: str, depth: int = 0) -> None:
        super().__init__()
        self.type_name = type_name
        self.depth = depth  # array allocation nesting depth

    def __str__(self) -> str:
        return f"new {self.type_name}{'[]' * self.depth}"


class TypeConversion(Expression):
    def __init__(self, operand: Expression, target_type: Type) -> None:
        super().__init__()
        self.expression = operand
        self.type = target_type

    def children(self) -> Iterator[Expression]:
        yield self.expression

    def __str__(self) -> str:
        return f"{self.type}({self.expression})"


class ElementaryTypeNameExpression(Expression):
    """Bare type name used as an expression (e.g. `uint256` in a conversion)."""

    def __init__(self, type_: Type) -> None:
        super().__init__()
        self.type = type_

    def __str__(self) -> str:
        return str(self.type)
