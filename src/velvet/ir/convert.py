"""Expression tree -> SolIR op sequence (spec/architecture.md §6.4).

One :class:`FunctionIRConverter` per function/modifier; ``convert_node``
translates the node's single expression into a linear op sequence attached
to ``node.ir_operations``.  Normalization rules implemented:

- sub-expression results are materialized as ``TMP_n``;
- index/member dereference produce ``REF_n`` via ``Index``/``Member`` ops;
- compound assignments (``+=`` ...) become ``Binary`` + ``Assignment``;
- ``++``/``--`` become read-back + ``Binary`` + ``Assignment``;
- array ``push``/``pop`` -> :class:`Push`, ``delete x`` -> :class:`Delete`;
- ``using for`` member calls -> :class:`LibraryCall` with the receiver as
  first argument;
- ``transfer``/``send`` -> :class:`Transfer`/:class:`Send`;
- ``.call/.delegatecall/.staticcall/.callcode`` -> :class:`LowLevelCall`
  (value/gas options lifted onto the op);
- plain external calls -> :class:`HighLevelCall`; internal calls ->
  :class:`InternalCall`; function-pointer calls -> :class:`InternalDynamicCall`;
  builtins -> :class:`SolidityCall`; ``emit`` -> :class:`EventCall`;
  ``new X(...)`` -> :class:`NewContract`/:class:`NewArray`/
  :class:`NewElementaryType`; struct constructors -> :class:`NewStructure`;
- array literals -> :class:`InitArray`; tuple destructuring -> :class:`Unpack`;
- ``IF``/``IF_LOOP`` nodes get a terminal :class:`Condition` op; ``RETURN``
  nodes get a :class:`Return` op.

Ternaries are lowered by the parser; a residual ``ConditionalExpression``
(only possible inside ``if``/loop conditions) is tolerated: its three arms
are converted and combined with a ``?:``-marked ``Binary`` (documented
imprecision).

Original clean-room implementation.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from velvet.core.cfg_node import CFGNode, NodeKind
from velvet.core.contract import Contract, ContractKind
from velvet.core.declarations import CustomError, Enum, Event, Structure
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
from velvet.core.function import Function, FunctionLike
from velvet.core.types import ArrayType, ElementaryType, TupleType, UserDefinedType
from velvet.core.variables import (
    Constant,
    SolidityFunction,
    SolidityVariable,
    UnresolvedSymbol,
    Variable,
    solidity_function,
)
from velvet.ir.operations import (
    Assignment,
    Binary,
    Condition,
    Delete,
    EventCall,
    HighLevelCall,
    Index,
    InitArray,
    InternalCall,
    InternalDynamicCall,
    LibraryCall,
    LowLevelCall,
    Member,
    NewArray,
    NewContract,
    NewElementaryType,
    NewStructure,
    Operation,
    Push,
    Return,
    Send,
    SolidityCall,
    Transfer,
    TypeConversion as TypeConversionOp,
    Unary,
    Unpack,
)
from velvet.ir.variables import ReferenceVariable, TemporaryVariable, TupleVariable

logger = logging.getLogger("velvet.ir")

_NO_LVALUE_BUILTINS = ("require", "assert", "revert")


class FunctionIRConverter:
    """Converts the CFG node expressions of one function/modifier to IR."""

    def __init__(self, function: FunctionLike) -> None:
        self._func = function
        self._tmp_counter = 0
        self._ref_counter = 0
        self._tuple_counter = 0
        self._ops: list[Operation] = []

    # ------------------------------------------------------------- counters
    def _new_tmp(self, type_: Any = None) -> TemporaryVariable:
        tmp = TemporaryVariable(self._func, self._tmp_counter)
        self._tmp_counter += 1
        tmp.type = type_
        return tmp

    def _new_ref(self, points_to: Any, type_: Any = None) -> ReferenceVariable:
        ref = ReferenceVariable(self._func, self._ref_counter, points_to)
        self._ref_counter += 1
        ref.type = type_
        return ref

    def _new_tuple(self, type_: Any = None) -> TupleVariable:
        var = TupleVariable(self._func, self._tuple_counter)
        self._tuple_counter += 1
        var.type = type_
        return var

    # ------------------------------------------------------------ plumbing
    def _emit(self, op: Operation, expression: Optional[Expression]) -> Operation:
        op.expression = expression
        self._ops.append(op)
        return op

    # ---------------------------------------------------------------- nodes
    def convert_node(self, node: CFGNode) -> list[Operation]:
        """Translate ``node.expression``; attach ops to ``node.ir_operations``."""
        # ASSEMBLY nodes carry pre-modeled Yul assignment ops (attached by
        # the body parser); preserve them instead of emitting nothing.
        if node.kind == NodeKind.ASSEMBLY and node.ir_operations:
            for op in node.ir_operations:
                op.node = node
            return node.ir_operations
        self._ops = []
        expression = node.expression
        if expression is not None:
            if node.kind in (NodeKind.IF, NodeKind.IF_LOOP):
                value = self._convert(expression)
                self._emit(Condition(value), expression)
            elif node.kind == NodeKind.RETURN:
                values = self._convert_return_values(expression)
                self._emit(Return(values), expression)
            else:
                self._convert(expression)
        for op in self._ops:
            op.node = node
        node.ir_operations = self._ops
        return self._ops

    def _convert_return_values(self, expression: Expression) -> list[Any]:
        if isinstance(expression, TupleExpression) and not expression.is_inline_array:
            values = []
            for sub in expression.expressions:
                values.append(self._convert(sub) if sub is not None else None)
            return [v for v in values if v is not None]
        return [self._convert(expression)]

    # ------------------------------------------------------------ dispatch
    def _convert(self, expr: Optional[Expression]) -> Any:
        """Convert an expression; returns the value holding its result."""
        if expr is None:
            return None
        if isinstance(expr, Literal):
            return Constant(expr.value, expr.type)
        if isinstance(expr, Identifier):
            return expr.value
        if isinstance(expr, BinaryOperation):
            return self._convert_binary(expr)
        if isinstance(expr, UnaryOperation):
            return self._convert_unary(expr)
        if isinstance(expr, AssignmentOperation):
            return self._convert_assignment(expr)
        if isinstance(expr, IndexAccess):
            return self._convert_index(expr)
        if isinstance(expr, MemberAccess):
            return self._convert_member(expr)
        if isinstance(expr, CallExpression):
            return self._convert_call(expr)
        if isinstance(expr, TupleExpression):
            return self._convert_tuple(expr)
        if isinstance(expr, NewExpression):
            return self._convert_new(None, expr)
        if isinstance(expr, TypeConversion):
            operand = self._convert(expr.expression)
            tmp = self._new_tmp(expr.type)
            self._emit(TypeConversionOp(tmp, operand, expr.type), expr)
            return tmp
        if isinstance(expr, ConditionalExpression):
            return self._convert_conditional(expr)
        if isinstance(expr, ElementaryTypeNameExpression):
            return expr.type
        logger.debug("Unsupported expression %s; producing opaque temp", type(expr))
        tmp = self._new_tmp(expr.type)
        self._emit(Assignment(tmp, Constant("<?>")), expr)
        return tmp

    # ------------------------------------------------------------- basics
    def _convert_binary(self, expr: BinaryOperation) -> Any:
        left = self._convert(expr.expression_left)
        right = self._convert(expr.expression_right)
        tmp = self._new_tmp(expr.type)
        self._emit(Binary(tmp, left, right, expr.operator), expr)
        return tmp

    def _convert_unary(self, expr: UnaryOperation) -> Any:
        if expr.operator == "delete":
            target = self._convert_left(expr.expression)
            self._emit(Delete(target), expr)
            return target
        if expr.operator in ("++", "--"):
            return self._convert_inc_dec(expr)
        operand = self._convert(expr.expression)
        tmp = self._new_tmp(expr.type)
        self._emit(Unary(tmp, operand, expr.operator), expr)
        return tmp

    def _convert_inc_dec(self, expr: UnaryOperation) -> Any:
        """``x++`` / ``++x`` -> read-back, Binary(+1/-1), Assignment."""
        lvalue = self._convert_left(expr.expression)
        one = Constant("1", ElementaryType("uint256"))
        operator = "+" if expr.operator == "++" else "-"
        if expr.is_prefix:
            tmp = self._new_tmp(expr.type)
            self._emit(Binary(tmp, lvalue, one, operator), expr)
            self._emit(Assignment(lvalue, tmp), expr)
            return tmp
        old = self._new_tmp(expr.type)
        self._emit(Assignment(old, lvalue), expr)
        tmp = self._new_tmp(expr.type)
        self._emit(Binary(tmp, lvalue, one, operator), expr)
        self._emit(Assignment(lvalue, tmp), expr)
        return old

    def _convert_conditional(self, expr: ConditionalExpression) -> Any:
        """Tolerated residual ternary (parser lowers all statement positions)."""
        self._convert(expr.condition)
        then = self._convert(expr.then_expression)
        otherwise = self._convert(expr.else_expression)
        tmp = self._new_tmp(expr.type)
        self._emit(Binary(tmp, then, otherwise, "?:"), expr)
        return tmp

    # --------------------------------------------------------- assignments
    def _convert_left(self, expr: Optional[Expression]) -> Any:
        """Convert an assignment target to an LVALUE variable."""
        if expr is None:
            return None
        if isinstance(expr, Identifier):
            return expr.value
        if isinstance(expr, IndexAccess):
            return self._convert_index(expr)
        if isinstance(expr, MemberAccess):
            return self._convert_member(expr)
        if isinstance(expr, TupleExpression):
            return [self._convert_left(e) for e in expr.expressions]
        value = self._convert(expr)
        if isinstance(value, Variable):
            return value
        logger.debug("Non-lvalue assignment target %s", expr)
        return value

    def _convert_assignment(self, expr: AssignmentOperation) -> Any:
        left_expr, right_expr = expr.expression_left, expr.expression_right

        # Tuple destructuring: `(a, b) = (x, y)` element-wise;
        # `(a, b) = f()` via TUPLE + UNPACK.
        if isinstance(left_expr, TupleExpression):
            if (
                isinstance(right_expr, TupleExpression)
                and not right_expr.is_inline_array
                and len(right_expr.expressions) == len(left_expr.expressions)
            ):
                rights = [self._convert(e) if e is not None else None
                          for e in right_expr.expressions]
                lefts = self._convert_left(left_expr)
                for lval, rval in zip(lefts, rights):
                    if lval is not None and rval is not None:
                        self._emit(Assignment(lval, rval), expr)
                return lefts[0] if lefts else None
            tuple_value = self._convert(right_expr)
            lefts = self._convert_left(left_expr)
            for index, lval in enumerate(lefts):
                if lval is not None:
                    self._emit(Unpack(lval, tuple_value, index), expr)
            return lefts[0] if lefts else None

        if expr.operator != "=":
            # Compound: `x += y` -> TMP = x + y; x := TMP
            lvalue = self._convert_left(left_expr)
            right = self._convert(right_expr)
            tmp = self._new_tmp(expr.type)
            self._emit(Binary(tmp, lvalue, right, expr.operator[:-1]), expr)
            self._emit(Assignment(lvalue, tmp), expr)
            return lvalue

        right = self._convert(right_expr)
        lvalue = self._convert_left(left_expr)
        if lvalue is None or right is None:
            return lvalue  # e.g. push() used as a statement value
        self._emit(Assignment(lvalue, right), expr)
        return lvalue

    # --------------------------------------------------------- dereference
    def _convert_index(self, expr: IndexAccess) -> ReferenceVariable:
        base = self._convert(expr.expression_left)
        index = self._convert(expr.expression_right)
        ref = self._new_ref(points_to=base, type_=expr.type)
        self._emit(Index(ref, base, index), expr)
        return ref

    def _convert_member(self, expr: MemberAccess) -> ReferenceVariable:
        base_expr = expr.expression
        if isinstance(base_expr, Identifier) and isinstance(
            base_expr.value, (Contract, Enum)
        ):
            base: Any = base_expr.value  # contract/enum member access
        else:
            base = self._convert(base_expr)
        ref = self._new_ref(points_to=base, type_=expr.type)
        self._emit(Member(ref, base, expr.member_name), expr)
        return ref

    def _convert_tuple(self, expr: TupleExpression) -> Any:
        values = [self._convert(e) if e is not None else None for e in expr.expressions]
        tmp = self._new_tmp(expr.type)
        flat = [v for v in values if v is not None]
        self._emit(InitArray(tmp, flat), expr)  # packing fallback
        return tmp

    # ----------------------------------------------------------------- new
    def _convert_new(self, call: Optional[CallExpression], new_expr: NewExpression) -> Any:
        type_ = new_expr.type
        args = [self._convert(a) for a in call.arguments] if call is not None else []
        call_value = self._convert(call.call_value) if call is not None and call.call_value else None
        call_salt = self._convert(call.call_salt) if call is not None and call.call_salt else None
        expression: Expression = call if call is not None else new_expr

        contract: Optional[Contract] = None
        if isinstance(type_, UserDefinedType) and isinstance(type_.type, Contract):
            contract = type_.type
        if contract is None and not isinstance(type_, (ArrayType, ElementaryType)):
            contract = self._contract_by_name(new_expr.type_name)

        if isinstance(type_, ArrayType) or new_expr.depth > 0:
            tmp = self._new_tmp(type_)
            size = args[0] if args else None
            self._emit(NewArray(tmp, type_, max(new_expr.depth, 1), size), expression)
            return tmp
        if contract is not None:
            tmp = self._new_tmp(type_)
            self._emit(NewContract(tmp, contract, call_value, call_salt), expression)
            if args:
                constructor = next(
                    (f for f in contract.functions if f.is_constructor), None
                )
                if constructor is not None:
                    self._emit(InternalCall(None, constructor, args), expression)
            return tmp
        if isinstance(type_, ElementaryType):
            tmp = self._new_tmp(type_)
            size = args[0] if args else None
            self._emit(NewElementaryType(tmp, type_, size), expression)
            return tmp
        # Unknown new target: keep an opaque temp so the expression still has a value.
        tmp = self._new_tmp(type_)
        self._emit(NewContract(tmp, new_expr.type_name, call_value, call_salt), expression)
        return tmp

    # ---------------------------------------------------------------- calls
    def _convert_call(self, expr: CallExpression) -> Any:
        called = expr.called
        if isinstance(called, NewExpression):
            return self._convert_new(expr, called)
        if isinstance(called, Identifier):
            return self._convert_identifier_call(expr, called)
        if isinstance(called, MemberAccess):
            return self._convert_member_call(expr, called)
        if isinstance(called, (IndexAccess,)):
            fn_ptr = self._convert(called)
            args = [self._convert(a) for a in expr.arguments]
            lvalue = self._call_lvalue(expr)
            self._emit(InternalDynamicCall(lvalue, fn_ptr, args), expr)
            return lvalue
        # Fallback: convert everything; keep an opaque call temp.
        base = self._convert(called)
        args = [self._convert(a) for a in expr.arguments]
        lvalue = self._call_lvalue(expr)
        if isinstance(base, Variable):
            self._emit(InternalDynamicCall(lvalue, base, args), expr)
        else:
            self._emit(SolidityCall(lvalue, solidity_function(str(base)), args), expr)
        return lvalue

    def _call_lvalue(self, expr: CallExpression, function: Optional[FunctionLike] = None) -> Any:
        """Result holder for a call: None / TMP / TUPLE by return arity."""
        if function is not None:
            count = len(function.returns)
            if count == 0:
                return None
            if count > 1:
                return self._new_tuple(expr.type)
            return self._new_tmp(expr.type)
        type_ = expr.type
        if isinstance(type_, TupleType):
            if not type_.types:
                return None
            if len(type_.types) > 1:
                return self._new_tuple(type_)
        if type_ is None:
            return None
        return self._new_tmp(type_)

    def _convert_identifier_call(self, expr: CallExpression, called: Identifier) -> Any:
        target = called.value
        if isinstance(target, SolidityFunction):
            args = [self._convert(a) for a in expr.arguments]
            lvalue = None if target.name in _NO_LVALUE_BUILTINS else self._call_lvalue(expr)
            self._emit(SolidityCall(lvalue, target, args), expr)
            return lvalue
        if isinstance(target, Event):
            args = [self._convert(a) for a in expr.arguments]
            self._emit(EventCall(target, args), expr)
            return None
        if isinstance(target, CustomError):
            args = [self._convert(a) for a in expr.arguments]
            self._emit(SolidityCall(None, solidity_function(target.name), args), expr)
            return None
        if isinstance(target, Structure):
            args = [self._convert(a) for a in expr.arguments]
            tmp = self._new_tmp(expr.type)
            self._emit(NewStructure(tmp, target, args), expr)
            return tmp
        if isinstance(target, Enum):
            arg = self._convert(expr.arguments[0]) if expr.arguments else None
            tmp = self._new_tmp(expr.type)
            self._emit(TypeConversionOp(tmp, arg, expr.type), expr)
            return tmp
        if isinstance(target, Function):
            args = [self._convert(a) for a in expr.arguments]
            lvalue = self._call_lvalue(expr, target)
            self._emit(InternalCall(lvalue, target, args), expr)
            return lvalue
        if isinstance(target, Variable):
            # Function pointer stored in a variable.
            args = [self._convert(a) for a in expr.arguments]
            lvalue = self._call_lvalue(expr)
            self._emit(InternalDynamicCall(lvalue, target, args), expr)
            return lvalue
        # Unresolved / exotic: emit a builtin-shaped call so args are captured.
        name = getattr(target, "name", str(target))
        args = [self._convert(a) for a in expr.arguments]
        lvalue = self._call_lvalue(expr)
        self._emit(SolidityCall(lvalue, solidity_function(name), args), expr)
        return lvalue

    def _convert_member_call(self, expr: CallExpression, called: MemberAccess) -> Any:
        member = called.member_name
        base_expr = called.expression
        base_type = base_expr.type if base_expr is not None else None

        # Ether-sending primitives on address(-like) bases.
        if member in ("transfer", "send") and self._is_address_like(base_type):
            dest = self._convert(base_expr)
            amount = self._convert(expr.arguments[0]) if expr.arguments else None
            if member == "transfer":
                self._emit(Transfer(dest, amount), expr)
                return None
            tmp = self._new_tmp(ElementaryType("bool"))
            self._emit(Send(tmp, dest, amount), expr)
            return tmp

        # Low-level calls on address(-like) bases.
        if member in LowLevelCall.NAMES and self._is_address_like(base_type):
            dest = self._convert(base_expr)
            args = [self._convert(a) for a in expr.arguments]
            call_value = self._convert(expr.call_value) if expr.call_value else None
            call_gas = self._convert(expr.call_gas) if expr.call_gas else None
            tuple_var = self._new_tuple(expr.type)
            self._emit(
                LowLevelCall(tuple_var, dest, member, args, call_value, call_gas), expr
            )
            return tuple_var

        # Array/bytes push & pop (dedicated op, not a call).
        if member in ("push", "pop") and self._is_array_like(base_type):
            array = self._convert(base_expr)
            value = self._convert(expr.arguments[0]) if expr.arguments else None
            self._emit(Push(array, value if member == "push" else None), expr)
            return None

        # Direct library call: `Lib.f(...)`.
        if isinstance(base_expr, Identifier) and isinstance(base_expr.value, Contract):
            contract = base_expr.value
            function = self._find_function(contract, member, len(expr.arguments))
            args = [self._convert(a) for a in expr.arguments]
            lvalue = self._call_lvalue(expr, function)
            if contract.kind == ContractKind.LIBRARY:
                self._emit(LibraryCall(lvalue, contract, member, args, function), expr)
            elif self._is_ancestor_qualified_call(contract, function):
                # Qualified internal call: `Base.f(...)` where Base is the
                # current contract or one of its ancestors.  Statically
                # dispatched (like `super.f(...)`); no external call happens.
                self._emit(InternalCall(lvalue, function, args, is_static=True), expr)
            else:
                call_value = self._convert(expr.call_value) if expr.call_value else None
                call_gas = self._convert(expr.call_gas) if expr.call_gas else None
                self._emit(
                    HighLevelCall(lvalue, contract, member, args, function, call_value, call_gas),
                    expr,
                )
            return lvalue

        # `super.f(...)` — internal call resolved up the inheritance chain.
        if isinstance(base_expr, Identifier) and isinstance(
            base_expr.value, UnresolvedSymbol
        ) and base_expr.value.name == "super":
            function = self._find_inherited(member, len(expr.arguments))
            args = [self._convert(a) for a in expr.arguments]
            lvalue = self._call_lvalue(expr, function)
            # super.f(...) is statically bound to the inherited implementation.
            self._emit(InternalCall(lvalue, function, args, is_static=True), expr)
            return lvalue

        # `using Lib for T` member call: receiver becomes the first argument.
        using = self._find_using_for(base_type, member, len(expr.arguments))
        if using is not None:
            library, function = using
            receiver = self._convert(base_expr)
            args = [receiver] + [self._convert(a) for a in expr.arguments]
            lvalue = self._call_lvalue(expr, function)
            self._emit(LibraryCall(lvalue, library, member, args, function), expr)
            return lvalue

        # Contract-typed base: plain external call.
        if isinstance(base_type, UserDefinedType) and isinstance(base_type.type, Contract):
            contract = base_type.type
            function = self._find_function(contract, member, len(expr.arguments))
            dest = self._convert(base_expr)
            args = [self._convert(a) for a in expr.arguments]
            call_value = self._convert(expr.call_value) if expr.call_value else None
            call_gas = self._convert(expr.call_gas) if expr.call_gas else None
            lvalue = self._call_lvalue(expr, function)
            self._emit(
                HighLevelCall(lvalue, dest, member, args, function, call_value, call_gas),
                expr,
            )
            return lvalue

        # `this.f(...)` — external self-call.
        if isinstance(base_expr, Identifier) and isinstance(
            base_expr.value, SolidityVariable
        ) and base_expr.value.name == "this":
            contract = self._func.contract_declarer or self._func.contract
            function = self._find_function(contract, member, len(expr.arguments))
            args = [self._convert(a) for a in expr.arguments]
            lvalue = self._call_lvalue(expr, function)
            self._emit(
                HighLevelCall(lvalue, base_expr.value, member, args, function), expr
            )
            return lvalue

        # Function-typed variable (e.g. a local/state function pointer).
        base_value = self._convert(base_expr)
        if isinstance(base_value, Variable) and self._is_function_like(base_type):
            args = [self._convert(a) for a in expr.arguments]
            lvalue = self._call_lvalue(expr)
            self._emit(InternalDynamicCall(lvalue, base_value, args), expr)
            return lvalue

        # Unknown member call: degrade to a HighLevelCall shape (external-looking).
        args = [self._convert(a) for a in expr.arguments]
        call_value = self._convert(expr.call_value) if expr.call_value else None
        call_gas = self._convert(expr.call_gas) if expr.call_gas else None
        lvalue = self._call_lvalue(expr)
        self._emit(
            HighLevelCall(lvalue, base_value, member, args, None, call_value, call_gas),
            expr,
        )
        return lvalue

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _is_address_like(type_: Any) -> bool:
        return isinstance(type_, ElementaryType) and type_.name.split()[0] == "address"

    @staticmethod
    def _is_array_like(type_: Any) -> bool:
        if isinstance(type_, ArrayType):
            return True
        return isinstance(type_, ElementaryType) and type_.name.split()[0] in (
            "bytes",
            "string",
        )

    @staticmethod
    def _is_function_like(type_: Any) -> bool:
        return type_.__class__.__name__ == "FunctionType"

    def _contract_by_name(self, name: str) -> Optional[Contract]:
        unit = self._unit()
        return unit.get_contract_from_name(name) if unit is not None else None

    def _unit(self) -> Any:
        contract = self._func.contract_declarer or self._func.contract
        return getattr(contract, "compilation_unit", None)

    @staticmethod
    def _find_function(
        contract: Optional[Contract], name: str, nargs: int
    ) -> Optional[Function]:
        if contract is None:
            return None
        matches = [
            f
            for f in contract.available_functions_from_inheritances()
            if f.name == name
        ]
        for func in matches:
            if len(func.parameters) == nargs:
                return func
        return matches[0] if matches else None

    def _find_inherited(self, name: str, nargs: int) -> Optional[Function]:
        contract = self._func.contract_declarer or self._func.contract
        if contract is None:
            return None
        for base in contract.inheritance:
            found = self._find_function(base, name, nargs)
            if found is not None:
                return found
        return None

    def _is_ancestor_qualified_call(
        self, contract: Contract, function: Optional[Function]
    ) -> bool:
        """True for ``Base.f(...)`` when ``Base`` is the current contract or
        one of its ancestors (an internal, statically-dispatched call).

        External functions cannot be invoked through a qualified internal
        call, so those stay high-level (this mirrors solc, which rejects
        ``Base.f()`` when ``f`` is ``external``).
        """
        if function is not None and function.visibility == "external":
            return False
        declarer = self._func.contract_declarer or self._func.contract
        if declarer is None:
            return False
        if contract is declarer:
            return True
        return any(contract is base for base in declarer.inheritance)

    def _find_using_for(
        self, base_type: Any, member: str, nargs: int
    ) -> Optional[tuple[Contract, Function]]:
        """Match a `using Lib for T` directive for a `base.member(...)` call."""
        if base_type is None:
            return None
        unit = self._unit()
        contract = self._func.contract_declarer or self._func.contract
        directives: list[Any] = []
        seen: set[int] = set()
        chain = ([contract] + list(contract.inheritance)) if contract else []
        for item in chain:
            for directive in item.using_for:
                if id(directive) not in seen:
                    seen.add(id(directive))
                    directives.append(directive)
        if unit is not None:
            directives.extend(unit.using_for)
        for directive in directives:
            library = directive.library
            if library is None:
                continue
            if directive.type is not None and str(directive.type) != str(base_type):
                continue
            function = self._find_function(library, member, nargs + 1)
            if function is not None:
                return library, function
        return None


def convert_function(function: FunctionLike) -> None:
    """Convert every node of one function/modifier to IR (never raises)."""
    try:
        converter = FunctionIRConverter(function)
        for node in function.nodes:
            converter.convert_node(node)
    except Exception:  # noqa: BLE001 - degrade per spec §12
        logger.warning(
            "IR conversion failed for %s; leaving empty IR",
            function.canonical_name,
            exc_info=True,
        )
        for node in function.nodes:
            node.ir_operations = []


def convert_unit(unit: Any) -> None:
    """Convert all functions and modifiers of a compilation unit."""
    for function in unit.functions_and_modifiers:
        convert_function(function)
