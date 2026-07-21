"""CFG construction: function/modifier bodies -> control-flow graphs.

Implements the construction rules of spec/architecture.md §5:

- ``ENTRYPOINT`` first; one expression per node; sequential statements become
  ``EXPRESSION`` nodes; declarations become ``VARIABLE`` nodes.
- ``if``/``else`` -> ``IF`` (condition) + branches + ``ENDIF`` join; the join
  is pruned when neither branch falls through.
- Loops -> ``START_LOOP`` / ``IF_LOOP`` (condition) / body / ``END_LOOP``;
  ``for`` headers are distributed (init before the loop, post between body
  and back-edge); ``break``/``continue`` edges are re-pointed to the loop
  exit / loop condition (``continue`` targets the post-expression in ``for``
  loops, which is the semantically correct continuation point).
- Ternaries are *lowered*: a ``ConditionalExpression`` found in a statement
  position (expression statement, variable declaration initializer, return
  value) is split into an ``IF``/branch/``ENDIF`` subgraph assigning a
  synthesized local (``function.synthesized_locals``), innermost-first, so
  the resulting node expressions are control-flow free.  Ternaries inside
  ``if``/loop *conditions* are currently kept as ``ConditionalExpression``
  (documented limitation; the IR layer tolerates them).
- Named-return functions get a synthesized trailing ``RETURN`` of the named
  tuple; any other body that can still fall through gets a trailing empty
  ``RETURN`` so every open path ends at a terminator.
- ``InlineAssembly`` -> one ``ASSEMBLY`` node and sets
  ``function.contains_assembly``.  The Yul body stays opaque for control
  flow, but straight-line assignments (``x := div(a, b)``, ``let y := z``)
  are modeled as plain IR ops on the node so value-flow analyses can chase
  definitions through assembly (spec §5 "assembly is opaque" applies to the
  CFG shape, not to value definitions).
- ``try``/``catch`` -> ``TRY`` (external call expression) + one ``CATCH``
  node per catch clause; clause parameters are registered as initialized
  locals.
- ``emit`` -> ``EXPRESSION`` wrapping the event call; ``revert`` -> ``THROW``.
- modifier ``_`` -> an expression-free ``PLACEHOLDER`` node marking where the
  modified function's body is spliced in.
- ``unchecked``/plain blocks are recursed into.
- Unreachable nodes are marked via a reachability fixpoint from the entry
  (never deleted).

Original clean-room implementation.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from velvet.core.cfg_node import CFGNode, NodeKind
from velvet.core.expressions import (
    AssignmentOperation,
    BinaryOperation,
    CallExpression,
    ConditionalExpression,
    Expression,
    Identifier,
    IndexAccess,
    MemberAccess,
    TupleExpression,
    TypeConversion,
    UnaryOperation,
)
from velvet.core.function import FunctionLike
from velvet.core.variables import LocalVariable
from velvet.parsing.ast_norm import attach_source
from velvet.parsing.decl_parser import ParserContext
from velvet.parsing.expr_parser import ExpressionParser
from velvet.parsing.type_parser import type_from_declaration

logger = logging.getLogger("velvet.parsing.cfg")


class _LoopFrame:
    """Bookkeeping for break/continue re-pointing inside one loop."""

    def __init__(self) -> None:
        self.breaks: list[CFGNode] = []
        self.continues: list[CFGNode] = []


class CFGBuilder:
    """Builds the CFG of one function or modifier."""

    def __init__(self, ctx: ParserContext, function: FunctionLike) -> None:
        self._ctx = ctx
        self._func = function
        self._exprs = ExpressionParser(ctx, function)
        self._current: Optional[CFGNode] = None  # open fall-through end
        self._loops: list[_LoopFrame] = []
        self._pending_breaks: list[CFGNode] = []
        self._pending_joins: list[CFGNode] = []  # try/catch branch ends
        self._ternary_counter = 0
        self._locals_by_name: dict[str, LocalVariable] = {}  # Yul name lookup
        self._loop_depth = 0  # >0 while building a loop (for loop marking)

    # ------------------------------------------------------------- plumbing
    def _new_node(
        self,
        kind: NodeKind,
        src_node: Optional[dict[str, Any]] = None,
        expression: Optional[Expression] = None,
        link: bool = True,
    ) -> CFGNode:
        node = self._func.add_node(CFGNode(kind))
        if self._loop_depth > 0:
            # Parse-time loop membership: the node belongs to a loop body
            # (condition, post-expression, return/break inside the body...)
            # even when dominator-based natural-loop analysis cannot see it.
            node._inside_loop_parse = True
        if src_node is not None:
            attach_source(node, self._ctx.artifacts, src_node.get("src", ""))
        if expression is not None:
            node.expression = expression
        if link:
            self._link(node)
        return node

    def _link(self, node: CFGNode) -> None:
        """Connect `node` after the current open end(s) and make it current."""
        if self._current is not None:
            self._current.add_successor(node)
        for orphan in self._pending_joins:
            orphan.add_successor(node)
        self._pending_joins = []
        for brk in self._pending_breaks:
            brk.add_successor(node)
        self._pending_breaks = []
        self._current = node

    # ---------------------------------------------------------------- build
    def build(self, body: dict[str, Any]) -> FunctionLike:
        """Construct the CFG for the given Block AST node."""
        entry = self._new_node(NodeKind.ENTRYPOINT, body)
        entry.set_source_mapping(self._func.source_mapping)

        self._build_statement(body)

        named_returns = [r for r in self._func.returns if r.name]
        open_path = (
            self._current is not None
            or self._pending_joins
            or self._pending_breaks
            or len(self._func.nodes) == 1
        )
        if open_path:
            # Synthesized trailing RETURN: named tuple when the returns are
            # named (spec §5), empty otherwise.  Also serves as the join
            # target for dangling try-branches / loop breaks.
            trailing_expression: Optional[Expression] = None
            if named_returns:
                identifiers: list[Expression] = [
                    Identifier(var) for var in self._func.returns
                ]
                trailing_expression = (
                    identifiers[0]
                    if len(identifiers) == 1
                    else TupleExpression(identifiers)
                )
            self._new_node(NodeKind.RETURN, body, trailing_expression)

        self._mark_reachability()
        for index, node in enumerate(self._func.nodes):
            node.node_id = index
        return self._func

    # ------------------------------------------------------------ statements
    def _build_statement(self, stmt: Optional[dict[str, Any]]) -> None:
        if stmt is None:
            return
        node_type = stmt.get("nodeType")
        handler = getattr(self, f"_stmt_{node_type}", None)
        if handler is None:
            logger.debug("Skipping unsupported statement %r", node_type)
            return
        handler(stmt)

    def _build_statements(self, stmts: list[dict[str, Any]]) -> None:
        for stmt in stmts or []:
            self._build_statement(stmt)

    def _stmt_Block(self, stmt: dict[str, Any]) -> None:
        self._build_statements(stmt.get("statements", []) or [])

    def _stmt_UncheckedBlock(self, stmt: dict[str, Any]) -> None:
        self._build_statements(stmt.get("statements", []) or [])

    def _stmt_PlaceholderStatement(self, stmt: dict[str, Any]) -> None:
        # Modifier `_`: the point where the modified function's body (and
        # any inner modifiers) runs.  A dedicated, expression-free node so
        # analyses can split the modifier body into the parts running
        # before/after `_` (spec/architecture.md §5).
        self._new_node(NodeKind.PLACEHOLDER, stmt)

    def _stmt_ExpressionStatement(self, stmt: dict[str, Any]) -> None:
        expression = self._exprs.parse(stmt.get("expression"))
        if expression is not None and expression.contains_conditional:
            expression = self._lower_conditionals(expression, stmt)
        self._new_node(NodeKind.EXPRESSION, stmt, expression)

    def _stmt_VariableDeclarationStatement(self, stmt: dict[str, Any]) -> None:
        declarations = stmt.get("declarations", []) or []
        variables: list[Optional[LocalVariable]] = []
        for decl in declarations:
            if decl is None:
                variables.append(None)
            else:
                variables.append(self._declare_local(decl))

        initial = self._exprs.parse(stmt.get("initialValue"))
        if initial is not None and initial.contains_conditional:
            initial = self._lower_conditionals(initial, stmt)

        node = self._new_node(NodeKind.VARIABLE, stmt)
        declared = next((v for v in variables if v is not None), None)
        node.variable_declaration = declared
        if initial is not None:
            targets: list[Optional[Expression]] = [
                Identifier(v) if v is not None else None for v in variables
            ]
            if len(targets) == 1:
                left: Expression = targets[0]  # type: ignore[assignment]
            else:
                left = TupleExpression(targets)
            node.expression = AssignmentOperation(left, initial, "=")
            for var in variables:
                if var is not None:
                    var.initialized = True
                    var.expression_initial = initial

    def _stmt_IfStatement(self, stmt: dict[str, Any]) -> None:
        condition = self._exprs.parse(stmt.get("condition"))
        if_node = self._new_node(NodeKind.IF, stmt, condition)

        self._current = if_node
        self._build_statement(stmt.get("trueBody"))
        true_end = self._current

        false_body = stmt.get("falseBody")
        if false_body is not None:
            self._current = if_node
            self._build_statement(false_body)
            false_end: Optional[CFGNode] = self._current
        else:
            false_end = if_node

        if true_end is None and false_end is None:
            # Both branches terminate: the ENDIF is pruned (spec §5) and
            # whatever follows starts an unreachable segment.
            self._current = None
            return
        endif = self._new_node(NodeKind.ENDIF, stmt, link=False)
        if true_end is not None:
            true_end.add_successor(endif)
        if false_end is not None:
            false_end.add_successor(endif)
        self._current = endif

    def _stmt_WhileStatement(self, stmt: dict[str, Any]) -> None:
        self._new_node(NodeKind.START_LOOP, stmt)
        self._loop_depth += 1
        condition = self._exprs.parse(stmt.get("condition"))
        if_loop = self._new_node(NodeKind.IF_LOOP, stmt, condition)

        frame = _LoopFrame()
        self._loops.append(frame)
        self._current = if_loop
        self._build_statement(stmt.get("body"))
        body_end = self._current
        self._loops.pop()

        self._loop_depth -= 1
        end_loop = self._new_node(NodeKind.END_LOOP, stmt, link=False)
        if_loop.add_successor(end_loop)  # condition false -> exit
        if body_end is not None:
            body_end.add_successor(if_loop)  # back edge
        for cont in frame.continues:
            cont.add_successor(if_loop)
        self._pending_breaks.extend(frame.breaks)
        self._current = end_loop

    def _stmt_DoWhileStatement(self, stmt: dict[str, Any]) -> None:
        self._new_node(NodeKind.START_LOOP, stmt)
        self._loop_depth += 1

        frame = _LoopFrame()
        self._loops.append(frame)
        body_top_index = len(self._func.nodes)
        self._build_statement(stmt.get("body"))
        body_end = self._current
        self._loops.pop()

        condition = self._exprs.parse(stmt.get("condition"))
        if_loop = self._new_node(NodeKind.IF_LOOP, stmt, condition, link=False)
        if body_end is not None:
            body_end.add_successor(if_loop)
        body_top = (
            self._func.nodes[body_top_index]
            if len(self._func.nodes) > body_top_index
            else if_loop
        )
        if_loop.add_successor(body_top)  # condition true -> repeat

        self._loop_depth -= 1
        end_loop = self._new_node(NodeKind.END_LOOP, stmt, link=False)
        if_loop.add_successor(end_loop)
        for cont in frame.continues:
            cont.add_successor(if_loop)
        self._pending_breaks.extend(frame.breaks)
        self._current = end_loop

    def _stmt_ForStatement(self, stmt: dict[str, Any]) -> None:
        init = stmt.get("initializationExpression")
        if init is not None:
            self._build_statement(init)
            # A for-header declaration without initializer
            # (``for (uint256 i; ...; ++i)``) is the loop variable's defining
            # point: the counter deliberately starts at zero, so treat it as
            # initialized (like try/catch clause parameters, spec §5) —
            # otherwise every read of the counter is a false
            # uninitialized-local.
            if (
                init.get("nodeType") == "VariableDeclarationStatement"
                and init.get("initialValue") is None
            ):
                for decl in init.get("declarations", []) or []:
                    if decl is None:
                        continue
                    var = self._ctx.id_map.get(decl.get("id"))
                    if isinstance(var, LocalVariable):
                        var.initialized = True

        self._new_node(NodeKind.START_LOOP, stmt)
        self._loop_depth += 1
        condition = self._exprs.parse(stmt.get("condition"))
        if_loop = self._new_node(NodeKind.IF_LOOP, stmt, condition)

        frame = _LoopFrame()
        self._loops.append(frame)
        self._current = if_loop
        self._build_statement(stmt.get("body"))
        body_end = self._current
        self._loops.pop()

        post = stmt.get("loopExpression")
        if post is not None:
            post_expr = self._exprs.parse(post.get("expression"))
            post_node = self._new_node(NodeKind.EXPRESSION, post, post_expr, link=False)
            if body_end is not None:
                body_end.add_successor(post_node)
            for cont in frame.continues:
                cont.add_successor(post_node)
            post_node.add_successor(if_loop)
        else:
            if body_end is not None:
                body_end.add_successor(if_loop)
            for cont in frame.continues:
                cont.add_successor(if_loop)

        self._loop_depth -= 1
        end_loop = self._new_node(NodeKind.END_LOOP, stmt, link=False)
        if_loop.add_successor(end_loop)
        self._pending_breaks.extend(frame.breaks)
        self._current = end_loop

    def _stmt_Return(self, stmt: dict[str, Any]) -> None:
        expression = self._exprs.parse(stmt.get("expression"))
        if expression is not None and expression.contains_conditional:
            expression = self._lower_conditionals(expression, stmt)
        self._new_node(NodeKind.RETURN, stmt, expression)
        self._current = None

    def _stmt_Break(self, stmt: dict[str, Any]) -> None:
        node = self._new_node(NodeKind.BREAK, stmt)
        if self._loops:
            self._loops[-1].breaks.append(node)
        self._current = None

    def _stmt_Continue(self, stmt: dict[str, Any]) -> None:
        node = self._new_node(NodeKind.CONTINUE, stmt)
        if self._loops:
            self._loops[-1].continues.append(node)
        self._current = None

    def _stmt_EmitStatement(self, stmt: dict[str, Any]) -> None:
        call = self._exprs.parse(stmt.get("eventCall"))
        self._new_node(NodeKind.EXPRESSION, stmt, call)

    def _stmt_RevertStatement(self, stmt: dict[str, Any]) -> None:
        # Modern `revert CustomError(...)` (solc >= 0.8.4): aborts control
        # flow like the legacy `throw`, but it is NOT the deprecated
        # `throw` statement — the node's source text/expression records
        # the error call so downstream analyses can tell them apart.
        call = self._exprs.parse(stmt.get("errorCall"))
        self._new_node(NodeKind.THROW, stmt, call)
        self._current = None

    def _stmt_Throw(self, stmt: dict[str, Any]) -> None:
        # Legacy `throw;` statement (solc < 0.5 AST): aborts the whole
        # transaction without an error payload, so the node carries no
        # expression. Deprecated-standards flags exactly these nodes.
        self._new_node(NodeKind.THROW, stmt)
        self._current = None

    def _stmt_InlineAssembly(self, stmt: dict[str, Any]) -> None:
        # Opaque single node for control flow; straight-line Yul value
        # definitions are modeled as IR ops on the node (see module docstring).
        self._func.contains_assembly = True
        node = self._new_node(NodeKind.ASSEMBLY, stmt)
        ops = self._model_yul_block(stmt.get("AST") or {})
        if ops:
            node.ir_operations = ops

    # ---------------------------------------------------- Yul value modeling
    _YUL_BINOPS = {
        "add": "+",
        "sub": "-",
        "mul": "*",
        "div": "/",
        "sdiv": "/",
        "mod": "%",
        "smod": "%",
        "exp": "**",
        "shl": "<<",
        "shr": ">>",
        "sar": ">>",
        "and": "&",
        "or": "|",
        "xor": "^",
        "eq": "==",
        "lt": "<",
        "gt": ">",
        "slt": "<",
        "sgt": ">",
    }

    def _yul_lookup(self, name: str, scope: dict[str, Any]) -> Any:
        """Resolve a Yul identifier to a function-local value by name.

        Resolution order: Yul block scope, function parameters/returns,
        function locals, then — like plain Solidity expressions — the
        enclosing contract's state variables and constants (walking
        inheritance).  Only when none of those match is a fresh local
        minted (a genuinely assembly-local variable such as one declared
        by ``let`` and used across statements, or an assignment target).
        """
        if name in scope:
            return scope[name]
        if "." in name:
            # Yul pseudo-member of a Solidity variable (``arr.slot``,
            # ``arr.offset``, ``arr.length``, ``sig.offset``, ``$.slot``):
            # the value is derived from the base variable, so model reads
            # and writes as flowing through the base itself.  This avoids
            # minting a fresh (never-initialized) local for e.g. ``arr.slot``.
            base = self._yul_lookup(name.split(".", 1)[0], scope)
            scope[name] = base
            return base
        for param in list(self._func.parameters) + list(self._func.returns):
            if param.name == name:
                scope[name] = param
                return param
        variable = self._locals_by_name.get(name)
        if variable is not None:
            scope[name] = variable
            return variable
        contract = self._func.contract_declarer or self._func.contract
        if contract is not None:
            state_var = contract.get_state_variable_from_name(name)
            if state_var is not None:
                # A compile-time constant used in assembly (the ERC-7201
                # ``$.slot := SomeStorageLocation`` idiom) is a literal,
                # not a storage read.
                if state_var.is_constant:
                    from velvet.core.expressions import Literal
                    from velvet.core.variables import Constant

                    initial = state_var.expression_initial
                    if isinstance(initial, Literal):
                        constant = Constant(initial.value)
                        attach_source(
                            constant,
                            self._ctx.artifacts,
                            getattr(initial, "src", "") or "",
                        )
                        scope[name] = constant
                        return constant
                scope[name] = state_var
                return state_var
        # Unknown (e.g. only assigned inside assembly): fresh local.
        variable = LocalVariable()
        variable.name = name
        variable.function = self._func  # type: ignore[assignment]
        scope[name] = variable
        return variable

    def _model_yul_value(self, expr: Any, scope: dict[str, Any], ops: list[Any]) -> Any:
        """Build the IR value for a Yul expression (ops appended in order)."""
        from velvet.core.variables import Constant
        from velvet.ir.operations import Assignment, Binary
        from velvet.ir.variables import TemporaryVariable

        if not isinstance(expr, dict):
            return None
        node_type = expr.get("nodeType")
        if node_type == "YulLiteral":
            constant = Constant(expr.get("value", ""))
            attach_source(constant, self._ctx.artifacts, expr.get("src", ""))
            return constant
        if node_type == "YulIdentifier":
            return self._yul_lookup(expr.get("name", ""), scope)
        if node_type == "YulFunctionCall":
            fname = (expr.get("functionName") or {}).get("name", "")
            args = [
                self._model_yul_value(arg, scope, ops)
                for arg in expr.get("arguments", []) or []
            ]
            operator = self._YUL_BINOPS.get(fname)
            if operator is not None and len(args) == 2 and all(
                arg is not None for arg in args
            ):
                tmp = TemporaryVariable(self._func, -1 - len(ops))
                ops.append(Binary(tmp, args[0], args[1], operator))
                return tmp
            if fname in ("not", "iszero") and len(args) == 1 and args[0] is not None:
                from velvet.ir.operations import Unary

                tmp = TemporaryVariable(self._func, -1 - len(ops))
                ops.append(Unary(tmp, args[0], "!"))
                return tmp
            # Opaque builtin (mload, keccak256, mulmod, byte, ...): fresh
            # value conservatively depending on all of its arguments.  The
            # result is tagged ``_yul_opaque`` so structural tautology checks
            # do not resolve it to a literal argument (``mload(0x00)`` reads
            # memory; it is NOT the constant ``0``).
            tmp = TemporaryVariable(self._func, -1 - len(ops))
            present = [arg for arg in args if arg is not None]
            if len(present) == 1:
                op = Assignment(tmp, present[0])
                op._yul_opaque = True  # type: ignore[attr-defined]
                ops.append(op)
            elif present:
                acc = present[0]
                for extra in present[1:]:
                    acc_tmp = TemporaryVariable(self._func, -1 - len(ops))
                    op = Binary(acc_tmp, acc, extra, "|")
                    op._yul_opaque = True  # type: ignore[attr-defined]
                    ops.append(op)
                    acc = acc_tmp
                op = Assignment(tmp, acc)
                op._yul_opaque = True  # type: ignore[attr-defined]
                ops.append(op)
            return tmp
        return None

    def _model_yul_statements(
        self, statements: list[Any], scope: dict[str, Any], ops: list[Any]
    ) -> None:
        from velvet.ir.operations import Assignment

        for stmt in statements or []:
            if not isinstance(stmt, dict):
                continue
            node_type = stmt.get("nodeType")
            if node_type == "YulAssignment":
                names = stmt.get("variableNames", []) or []
                if len(names) != 1:
                    continue  # tuple destructuring: not modeled
                value = self._model_yul_value(stmt.get("value"), scope, ops)
                if value is None:
                    continue
                target = self._yul_lookup(names[0].get("name", ""), scope)
                ops.append(Assignment(target, value))
            elif node_type == "YulVariableDeclaration":
                variables = stmt.get("variables", []) or []
                value = self._model_yul_value(stmt.get("value"), scope, ops)
                for decl in variables:
                    if not isinstance(decl, dict) or not decl.get("name"):
                        continue
                    variable = LocalVariable()
                    variable.name = decl["name"]
                    variable.function = self._func  # type: ignore[assignment]
                    scope[variable.name] = variable
                    if value is not None:
                        ops.append(Assignment(variable, value))
            elif node_type in ("YulIf",):
                self._model_yul_statements(
                    (stmt.get("body") or {}).get("statements"), scope, ops
                )
            elif node_type == "YulForLoop":
                for part in ("pre", "post", "body"):
                    self._model_yul_statements(
                        (stmt.get(part) or {}).get("statements"), scope, ops
                    )
            elif node_type == "YulBlock":
                self._model_yul_statements(stmt.get("statements"), scope, ops)
            # YulFunctionDefinition / YulExpressionStatement / YulSwitch /
            # YulLeave / YulBreak / YulContinue: no value definitions modeled.

    def _model_yul_block(self, ast: dict[str, Any]) -> list[Any]:
        """Model straight-line Yul assignments of one InlineAssembly stmt."""
        if ast.get("nodeType") != "YulBlock":
            return []
        ops: list[Any] = []
        scope: dict[str, Any] = {}
        self._model_yul_statements(ast.get("statements"), scope, ops)
        return ops

    def _stmt_TryStatement(self, stmt: dict[str, Any]) -> None:
        call = self._exprs.parse(stmt.get("externalCall"))
        try_node = self._new_node(NodeKind.TRY, stmt, call)

        branch_ends: list[CFGNode] = []
        for index, clause in enumerate(stmt.get("clauses", []) or []):
            parameters = (clause.get("parameters") or {}).get("parameters", []) or []
            declared = [self._declare_local(p) for p in parameters]
            for var in declared:
                var.initialized = True  # clause params are initialized (spec §5)

            if index == 0:
                # Success path: return values flow from the TRY node.
                self._current = try_node
            else:
                catch = self._new_node(NodeKind.CATCH, clause, link=False)
                try_node.add_successor(catch)
                self._current = catch
            self._build_statement(clause.get("block"))
            if self._current is not None:
                branch_ends.append(self._current)

        # All surviving branch ends join at the next statement.
        self._pending_joins.extend(branch_ends)
        self._current = None

    # -------------------------------------------------------------- locals
    def _declare_local(self, decl: dict[str, Any]) -> LocalVariable:
        variable = LocalVariable()
        variable.name = decl.get("name", "")
        variable.type = type_from_declaration(decl, self._ctx)
        location = decl.get("storageLocation", "default")
        variable.location = None if location == "default" else location
        variable.function = self._func  # type: ignore[assignment]
        attach_source(variable, self._ctx.artifacts, decl.get("src", ""))
        if "id" in decl:
            self._ctx.id_map[decl["id"]] = variable
        if variable.name:
            self._locals_by_name[variable.name] = variable
        return variable

    # ------------------------------------------------- ternary lowering
    def _lower_conditionals(
        self, expression: Expression, src_node: dict[str, Any]
    ) -> Expression:
        """Split ConditionalExpressions into IF/ENDIF subgraphs.

        Returns a control-flow-free expression where each ternary was
        replaced by an Identifier of a fresh synthesized local.  Records are
        emitted innermost-first so nested ternaries evaluate correctly.
        """
        records: list[tuple[Expression, Expression, Expression, LocalVariable]] = []
        rewritten = self._extract_conditionals(expression, records)
        for condition, then, otherwise, temp in records:
            if_node = self._new_node(NodeKind.IF, src_node, condition)

            self._current = if_node
            then_assign = AssignmentOperation(Identifier(temp), then, "=")
            then_node = self._new_node(NodeKind.EXPRESSION, src_node, then_assign)

            self._current = if_node
            else_assign = AssignmentOperation(Identifier(temp), otherwise, "=")
            else_node = self._new_node(NodeKind.EXPRESSION, src_node, else_assign)

            endif = self._new_node(NodeKind.ENDIF, src_node, link=False)
            then_node.add_successor(endif)
            else_node.add_successor(endif)
            self._current = endif
        return rewritten

    def _extract_conditionals(
        self,
        expression: Expression,
        records: list[tuple[Expression, Expression, Expression, LocalVariable]],
    ) -> Expression:
        if isinstance(expression, ConditionalExpression):
            condition = self._extract_conditionals(expression.condition, records)
            then = self._extract_conditionals(expression.then_expression, records)
            otherwise = self._extract_conditionals(expression.else_expression, records)
            temp = self._new_ternary_local(expression)
            records.append((condition, then, otherwise, temp))
            replacement = Identifier(temp)
            replacement.type = expression.type
            replacement.set_source_mapping(expression.source_mapping)
            return replacement

        # Mutate child slots in place (children first => innermost-first).
        if isinstance(expression, (AssignmentOperation, BinaryOperation)):
            expression.expression_left = self._extract_conditionals(
                expression.expression_left, records
            )
            expression.expression_right = self._extract_conditionals(
                expression.expression_right, records
            )
        elif isinstance(expression, UnaryOperation):
            expression.expression = self._extract_conditionals(
                expression.expression, records
            )
        elif isinstance(expression, CallExpression):
            expression.called = self._extract_conditionals(expression.called, records)
            expression.arguments = [
                self._extract_conditionals(arg, records)
                for arg in expression.arguments
            ]
            for option in ("call_value", "call_gas", "call_salt"):
                opt = getattr(expression, option)
                if opt is not None:
                    setattr(expression, option, self._extract_conditionals(opt, records))
        elif isinstance(expression, IndexAccess):
            expression.expression_left = self._extract_conditionals(
                expression.expression_left, records
            )
            if expression.expression_right is not None:
                expression.expression_right = self._extract_conditionals(
                    expression.expression_right, records
                )
        elif isinstance(expression, MemberAccess):
            expression.expression = self._extract_conditionals(
                expression.expression, records
            )
        elif isinstance(expression, TupleExpression):
            expression.expressions = [
                self._extract_conditionals(e, records) if e is not None else None
                for e in expression.expressions
            ]
        elif isinstance(expression, TypeConversion):
            expression.expression = self._extract_conditionals(
                expression.expression, records
            )
        # Identifier / Literal / NewExpression / ElementaryTypeNameExpression
        # carry no sub-expressions.
        return expression

    def _new_ternary_local(self, source: Expression) -> LocalVariable:
        temp = LocalVariable()
        temp.name = f"__ternary_{self._ternary_counter}"
        self._ternary_counter += 1
        temp.type = source.type
        temp.location = "memory"
        temp.function = self._func  # type: ignore[assignment]
        temp.initialized = True
        temp.set_source_mapping(source.source_mapping)
        self._func.synthesized_locals.append(temp)
        return temp

    # ----------------------------------------------------------- analysis
    def _mark_reachability(self) -> None:
        """Fixpoint from the entry; unreachable nodes are marked, not deleted."""
        entry = self._func.entry_point
        if entry is None:
            return
        seen: set[int] = set()
        stack = [entry]
        while stack:
            node = stack.pop()
            if id(node) in seen:
                continue
            seen.add(id(node))
            stack.extend(node.successors)
        for node in self._func.nodes:
            node.set_reachable(id(node) in seen)


def build_bodies(ctx: ParserContext, *, skip_assembly: bool = True) -> None:
    """Second pass: build CFGs for every parsed function/modifier body.

    ``skip_assembly`` is accepted for forward compatibility with the session
    option of the same name; v1 always emits opaque ASSEMBLY nodes.
    """
    del skip_assembly  # v1: inline assembly is always opaque
    for function, body in ctx.pending_bodies:
        if body is None:
            continue
        try:
            CFGBuilder(ctx, function).build(body)
        except Exception:  # noqa: BLE001 - degrade, don't crash (spec §12)
            logger.exception("CFG construction failed for %s", function.canonical_name)
