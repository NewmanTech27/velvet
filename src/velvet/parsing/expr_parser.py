"""Expression parsing: compact-AST expression nodes -> velvet expression trees.

Resolution strategy: solc annotates every ``Identifier`` /
``UserDefinedTypeName`` with the AST id of the declaration it references
(``referencedDeclaration``).  The declaration parser records every model
object it creates under its AST id (``ParserContext.id_map``), so identifier
resolution here is mostly an id lookup.  Negative ids denote language
builtins: known builtin functions become ``SolidityFunction`` singletons and
magic namespaces (``msg``/``block``/``tx``/``abi``) are consumed by the
enclosing ``MemberAccess`` to build ``SolidityVariable`` /
``SolidityFunction`` singletons.  Anything left over becomes an
``UnresolvedSymbol`` marker carrying the surface name.

Calls are intentionally **not** resolved to function objects here: a
``CallExpression`` keeps its ``called`` expression as parsed.  The IR layer
(Wave 2) classifies calls (internal/high-level/low-level/library/builtin)
using the resolved identifiers and types attached by this parser.

Original clean-room implementation (spec/architecture.md §4.5).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Optional

from velvet.core.expressions import (
    AssignmentOperation,
    BinaryOperation,
    CallExpression,
    ConditionalExpression,
    ElementaryTypeNameExpression,
    Expression,
    Identifier,
    IndexAccess,
    Literal,
    MemberAccess,
    NewExpression,
    TupleExpression,
    TypeConversion,
    UnaryOperation,
)
from velvet.core.types import ElementaryType, Type
from velvet.core.variables import (
    SOLIDITY_FUNCTION_NAMES,
    UnresolvedSymbol,
    solidity_function,
    solidity_variable,
)
from velvet.parsing.ast_norm import attach_source
from velvet.parsing.type_parser import type_from_type_name, type_from_type_string

if TYPE_CHECKING:
    from velvet.core.function import FunctionLike
    from velvet.parsing.decl_parser import ParserContext

logger = logging.getLogger("velvet.parsing.expressions")

# Magic builtin namespaces handled specially at MemberAccess time.
_MAGIC_NAMESPACES = ("msg", "block", "tx", "abi")

_LITERAL_TYPES = {
    "bool": "bool",
    "number": "uint256",
    "string": "string",
    "unicodeString": "string",
    "hexString": "bytes",
    "address": "address",
}


class ExpressionParser:
    """Parses expression AST nodes within one function/contract scope."""

    def __init__(self, ctx: ParserContext, function: Optional[FunctionLike] = None) -> None:
        self._ctx = ctx
        self._function = function

    # -------------------------------------------------------------- dispatch
    def parse(self, node: Optional[dict[str, Any]]) -> Optional[Expression]:
        """Parse one expression AST node; None-tolerant, never raises."""
        if node is None:
            return None
        handler = self._HANDLERS.get(node.get("nodeType", ""))
        if handler is None:
            logger.debug(
                "Unsupported expression nodeType %r; emitting placeholder",
                node.get("nodeType"),
            )
            placeholder: Expression = Identifier(
                UnresolvedSymbol(f"<{node.get('nodeType', '?')}>")
            )
            self._attach(placeholder, node)
            return placeholder
        try:
            return handler(self, node)
        except Exception:  # noqa: BLE001 - robustness over crash (spec §12)
            logger.exception("Failed to parse expression node %s", node.get("id"))
            fallback: Expression = Identifier(
                UnresolvedSymbol(f"<{node.get('nodeType', '?')}>")
            )
            self._attach(fallback, node)
            return fallback

    def _attach(self, expr: Expression, node: dict[str, Any]) -> Expression:
        attach_source(expr, self._ctx.artifacts, node.get("src", ""))
        return expr

    def _described_type(self, node: dict[str, Any]) -> Optional[Type]:
        descriptions = node.get("typeDescriptions") or {}
        type_string = descriptions.get("typeString")
        if not type_string:
            return None
        return type_from_type_string(type_string, self._ctx)

    # ------------------------------------------------------------ primitives
    def _parse_assignment(self, node: dict[str, Any]) -> Expression:
        left = self.parse(node.get("leftHandSide"))
        right = self.parse(node.get("rightHandSide"))
        if left is None or right is None:
            return self._attach(Identifier(UnresolvedSymbol("<assign>")), node)
        expr = AssignmentOperation(left, right, node.get("operator", "="))
        expr.type = self._described_type(node)
        return self._attach(expr, node)

    def _parse_binary(self, node: dict[str, Any]) -> Expression:
        left = self.parse(node.get("leftExpression"))
        right = self.parse(node.get("rightExpression"))
        expr = BinaryOperation(left, right, node.get("operator", "?"))  # type: ignore[arg-type]
        common = node.get("commonType") or {}
        if common.get("typeString"):
            expr.type = type_from_type_string(common["typeString"], self._ctx)
        else:
            expr.type = self._described_type(node)
        return self._attach(expr, node)

    def _parse_unary(self, node: dict[str, Any]) -> Expression:
        operand = self.parse(node.get("subExpression"))
        expr = UnaryOperation(operand, node.get("operator", "?"), node.get("prefix", True))  # type: ignore[arg-type]
        expr.type = self._described_type(node)
        return self._attach(expr, node)

    def _parse_conditional(self, node: dict[str, Any]) -> Expression:
        expr = ConditionalExpression(
            self.parse(node.get("condition")),  # type: ignore[arg-type]
            self.parse(node.get("trueExpression")),  # type: ignore[arg-type]
            self.parse(node.get("falseExpression")),  # type: ignore[arg-type]
        )
        expr.type = self._described_type(node)
        return self._attach(expr, node)

    def _parse_identifier(self, node: dict[str, Any]) -> Expression:
        value = self._resolve_symbol(node)
        expr = Identifier(value)
        expr.type = self._described_type(node)
        if hasattr(value, "type") and expr.type is None:
            expr.type = getattr(value, "type", None)
        return self._attach(expr, node)

    def _parse_literal(self, node: dict[str, Any]) -> Expression:
        value = node.get("value")
        if value is None:
            value = node.get("hexValue", "")
        expr = Literal(str(value))
        kind = node.get("kind", "")
        type_name = _LITERAL_TYPES.get(kind)
        if type_name is not None:
            expr.type = ElementaryType(type_name)
        return self._attach(expr, node)

    def _parse_index_access(self, node: dict[str, Any]) -> Expression:
        base = self.parse(node.get("baseExpression"))
        index = self.parse(node.get("indexExpression"))
        expr = IndexAccess(base, index)  # type: ignore[arg-type]
        expr.type = self._described_type(node)
        return self._attach(expr, node)

    def _parse_index_range(self, node: dict[str, Any]) -> Expression:
        """`x[start:end]` slices — modeled as IndexAccess with a tuple index."""
        base = self.parse(node.get("baseExpression"))
        start = self.parse(node.get("startExpression"))
        end = self.parse(node.get("endExpression"))
        index: Optional[Expression]
        if start is not None or end is not None:
            index = TupleExpression([start, end])
        else:
            index = None
        expr = IndexAccess(base, index)  # type: ignore[arg-type]
        expr.type = self._described_type(node)
        return self._attach(expr, node)

    def _parse_member_access(self, node: dict[str, Any]) -> Expression:
        member = node.get("memberName", "")
        base = self.parse(node.get("expression"))

        # Magic namespaces: `msg.sender`, `block.timestamp`, `tx.origin`, ...
        if isinstance(base, Identifier) and isinstance(base.value, UnresolvedSymbol):
            ns = base.value.name
            if ns in _MAGIC_NAMESPACES:
                full = f"{ns}.{member}"
                if ns == "abi":
                    expr: Expression = Identifier(solidity_function(full))
                else:
                    expr = Identifier(solidity_variable(full))
                expr.type = self._described_type(node)
                return self._attach(expr, node)

        expr = MemberAccess(base, member)  # type: ignore[arg-type]
        expr.type = self._described_type(node)
        return self._attach(expr, node)

    def _parse_tuple(self, node: dict[str, Any]) -> Expression:
        components = [self.parse(c) for c in node.get("components", []) or []]
        expr = TupleExpression(components)
        expr.is_inline_array = bool(node.get("isInlineArray", False))
        expr.type = self._described_type(node)
        return self._attach(expr, node)

    def _parse_new(self, node: dict[str, Any]) -> Expression:
        type_name_node = node.get("typeName") or {}
        type_obj = type_from_type_name(type_name_node, self._ctx)
        depth = 0
        cursor = type_name_node
        while cursor.get("nodeType") == "ArrayTypeName":
            depth += 1
            cursor = cursor.get("baseType", {})
        type_label = str(type_obj) if type_obj is not None else cursor.get("name", "?")
        expr = NewExpression(type_label, depth)
        expr.type = type_obj
        return self._attach(expr, node)

    def _parse_elementary_type_name_expr(self, node: dict[str, Any]) -> Expression:
        type_name = node.get("typeName")
        type_obj: Optional[Type] = None
        if isinstance(type_name, dict):
            type_obj = type_from_type_name(type_name_node, self._ctx)
        elif isinstance(type_name, str):  # older compact dialects
            type_obj = ElementaryType(type_name)
        if type_obj is None:
            type_obj = self._described_type(node)
        if type_obj is None:
            type_obj = ElementaryType("uint256")
        expr = ElementaryTypeNameExpression(type_obj)
        return self._attach(expr, node)

    # ----------------------------------------------------------------- calls
    def _parse_function_call(self, node: dict[str, Any]) -> Expression:
        called_node = node.get("expression")
        # solc >= 0.6.2: `f{value: v, gas: g}(args)` nests a
        # FunctionCallOptions around the *callee* of the outer FunctionCall.
        options_node: Optional[dict[str, Any]] = None
        if isinstance(called_node, dict) and called_node.get("nodeType") == "FunctionCallOptions":
            options_node = called_node
            called_node = called_node.get("expression")

        called = self.parse(called_node)
        arguments = [self.parse(a) for a in node.get("arguments", []) or []]
        kind = node.get("kind", "")

        is_conversion = kind == "typeConversion" or (
            not kind and isinstance(called, ElementaryTypeNameExpression)
        )
        if is_conversion:
            target = self._described_type(node)
            if target is None and isinstance(called, ElementaryTypeNameExpression):
                target = called.type
            if target is None:
                target = ElementaryType("uint256")
            operand: Expression = (
                arguments[0] if arguments else Literal("")
            )  # type: ignore[assignment]
            expr: Expression = TypeConversion(operand, target)
        else:
            call = CallExpression(called, arguments)  # type: ignore[arg-type]
            if options_node is not None:
                self._attach_call_options(call, options_node)
            expr = call
        expr.type = self._described_type(node)
        return self._attach(expr, node)

    def _parse_function_call_options(self, node: dict[str, Any]) -> Expression:
        """Older-dialect shape: the options node wraps the whole FunctionCall."""
        expr = self.parse(node.get("expression"))
        if isinstance(expr, CallExpression):
            self._attach_call_options(expr, node)
            return expr
        if expr is not None:
            return expr
        return self._attach(Identifier(UnresolvedSymbol("<call-options>")), node)

    def _attach_call_options(
        self, call: CallExpression, options_node: dict[str, Any]
    ) -> None:
        """Attach `{value: …, gas: …, salt: …}` expressions onto a call."""
        names = options_node.get("names", []) or []
        options = options_node.get("options", []) or []
        for name, option_node in zip(names, options):
            parsed = self.parse(option_node)
            if name == "value":
                call.call_value = parsed
            elif name == "gas":
                call.call_gas = parsed
            elif name == "salt":
                call.call_salt = parsed

    # ------------------------------------------------------------ resolution
    def _resolve_symbol(self, node: dict[str, Any]) -> Any:
        """Resolve an Identifier/IdentifierPath to a model object (best effort)."""
        ref_id = node.get("referencedDeclaration")
        name = node.get("name", "")

        if isinstance(ref_id, int):
            target = self._ctx.id_map.get(ref_id)
            if target is not None:
                return target
            if ref_id < 0:
                if name in SOLIDITY_FUNCTION_NAMES:
                    return solidity_function(name)
                if name == "this":
                    return solidity_variable("this")
                if name == "now":  # pre-0.7 alias of block.timestamp
                    return solidity_variable("now")

        # Name-based fallback within the current function/contract scope.
        by_name = self._lookup_in_scope(name)
        if by_name is not None:
            return by_name
        return UnresolvedSymbol(name, ref_id if isinstance(ref_id, int) else None)

    def _lookup_in_scope(self, name: str) -> Any:
        if not name:
            return None
        function = self._function
        if function is not None:
            for var in (
                function.parameters
                + function.returns
                + function.synthesized_locals
            ):
                if var.name == name:
                    return var
            contract = function.contract_declarer or function.contract
            if contract is not None:
                state_var = contract.get_state_variable_from_name(name)
                if state_var is not None:
                    return state_var
        return None

    _HANDLERS: dict[str, Any] = {}


ExpressionParser._HANDLERS = {
    "Assignment": ExpressionParser._parse_assignment,
    "BinaryOperation": ExpressionParser._parse_binary,
    "UnaryOperation": ExpressionParser._parse_unary,
    "Conditional": ExpressionParser._parse_conditional,
    "Identifier": ExpressionParser._parse_identifier,
    "IdentifierPath": ExpressionParser._parse_identifier,
    "Literal": ExpressionParser._parse_literal,
    "IndexAccess": ExpressionParser._parse_index_access,
    "IndexRangeAccess": ExpressionParser._parse_index_range,
    "MemberAccess": ExpressionParser._parse_member_access,
    "TupleExpression": ExpressionParser._parse_tuple,
    "NewExpression": ExpressionParser._parse_new,
    "ElementaryTypeNameExpression": ExpressionParser._parse_elementary_type_name_expr,
    "FunctionCall": ExpressionParser._parse_function_call,
    "FunctionCallOptions": ExpressionParser._parse_function_call_options,
}
