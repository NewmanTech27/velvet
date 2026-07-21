"""Declaration parsing: normalized SourceUnit ASTs -> populated CompilationUnit.

Two-phase design (spec/architecture.md §2 stage 2):

1. :func:`parse_declarations` walks every source unit and builds contracts,
   state variables, functions, modifiers, events, structs, enums, errors,
   pragmas, imports and using-for directives.  Every created object is
   recorded in ``ParserContext.id_map`` under its solc AST id; bodies and
   cross-references are left pending.
2. :func:`resolve_references` resolves everything that needs a complete
   symbol table: inheritance edges + C3 linearization, modifier invocations
   and explicit base-constructor calls, using-for targets, the override
   graph, state-variable initializers, and unresolved type placeholders.

Function/modifier bodies are *not* parsed here; ``body_parser`` consumes
``ctx.pending_bodies`` in a later pass.

Original clean-room implementation.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from velvet.compile.artifacts import CompilationArtifacts
from velvet.core.compilation_unit import CompilationUnit
from velvet.core.contract import Contract, ContractKind, c3_linearization
from velvet.core.declarations import (
    CustomError,
    Enum,
    Event,
    EventParam,
    ImportDirective,
    PragmaDirective,
    StructField,
    Structure,
    UsingForDirective,
)
from velvet.core.function import Function, FunctionKind, FunctionLike, Modifier
from velvet.core.variables import LocalVariable, StateVariable
from velvet.parsing.ast_norm import attach_source, normalize_ast
from velvet.parsing.expr_parser import ExpressionParser
from velvet.parsing.type_parser import (
    resolve_unresolved_type,
    type_from_declaration,
    type_from_type_name,
)

logger = logging.getLogger("velvet.parsing.declarations")

_KIND_MAP = {
    "function": FunctionKind.NORMAL,
    "constructor": FunctionKind.CONSTRUCTOR,
    "fallback": FunctionKind.FALLBACK,
    "receive": FunctionKind.RECEIVE,
}


class ParserContext:
    """Shared state threaded through all parsing passes."""

    def __init__(self, artifacts: CompilationArtifacts) -> None:
        self.artifacts = artifacts
        self.unit = CompilationUnit(artifacts)
        # solc AST id -> model object (contracts, variables, functions, ...)
        self.id_map: dict[int, Any] = {}
        # pending cross-reference work, consumed by resolve_references()
        self.pending_bases: list[tuple[Contract, list[tuple[Optional[int], str]]]] = []
        self.pending_modifiers: list[tuple[FunctionLike, list[dict[str, Any]]]] = []
        self.pending_using: list[
            tuple[UsingForDirective, Optional[int], Optional[dict[str, Any]]]
        ] = []
        self.pending_overrides: list[FunctionLike] = []
        self.pending_initializers: list[tuple[StateVariable, dict[str, Any]]] = []
        # (function, body Block AST) consumed by body_parser.build_bodies()
        self.pending_bodies: list[tuple[FunctionLike, Optional[dict[str, Any]]]] = []

    # ------------------------------------------------------------ lookups
    def resolve_type_name(self, name: str) -> Any:
        """Resolve a user-defined type by (possibly qualified) name.

        Handles `Name` (any contract/struct/enum in the unit) and
        `ContractName.MemberName` (struct/enum nested in a contract).
        """
        if not name:
            return None
        parts = name.split(".")
        if len(parts) >= 2:
            contract = self.unit.get_contract_from_name(parts[-2])
            if contract is not None:
                member = parts[-1]
                for group in (contract.structures, contract.enums):
                    for decl in group:
                        if decl.name == member:
                            return decl
            return None
        for contract in self.unit.contracts:
            if contract.name == name:
                return contract
        for group in (
            self.unit.structures,
            self.unit.enums,
        ):
            for decl in group:
                if decl.name == name:
                    return decl
        # bare name of a contract-nested struct/enum
        for contract in self.unit.contracts:
            for group in (contract.structures, contract.enums):
                for decl in group:
                    if decl.name == name:
                        return decl
        return None

    def all_typed_objects(self) -> list[Any]:
        """Objects whose `.type` may still hold UnresolvedSymbol placeholders."""
        result: list[Any] = []
        for contract in self.unit.contracts:
            result.extend(contract.state_variables)
            for struct in contract.structures:
                result.extend(struct.elems)
            for event in contract.events:
                result.extend(event.elems)
            for function in contract.functions_and_modifiers:
                result.extend(function.parameters)
                result.extend(function.returns)
                result.extend(function.synthesized_locals)
                for node in function.nodes:
                    if node.variable_declaration is not None:
                        result.append(node.variable_declaration)
        result.extend(self.unit.top_level_variables)
        for function in self.unit.top_level_functions:
            result.extend(function.parameters)
            result.extend(function.returns)
        for struct in self.unit.structures:
            result.extend(struct.elems)
        for event in self.unit.events:
            result.extend(event.elems)
        result.extend(self.unit.using_for)
        for contract in self.unit.contracts:
            result.extend(contract.using_for)
        for error in self.unit.errors + [e for c in self.unit.contracts for e in c.errors]:
            # CustomError stores (name, type) tuples; handled separately below.
            result.extend(_ErrorParamProxy(error, i) for i in range(len(error.parameters)))
        return result


class _ErrorParamProxy:
    """Adapter letting the type sweep treat CustomError tuples as objects."""

    def __init__(self, error: CustomError, index: int) -> None:
        self._error = error
        self._index = index

    @property
    def type(self) -> Any:
        return self._error.parameters[self._index][1]

    @type.setter
    def type(self, value: Any) -> None:
        name, _ = self._error.parameters[self._index]
        self._error.parameters[self._index] = (name, value)


# ------------------------------------------------------------------ pass 1
def parse_declarations(ctx: ParserContext) -> None:
    """Walk every source unit AST and populate the CompilationUnit."""
    for source_id in sorted(ctx.artifacts.source_units):
        info = ctx.artifacts.source_units[source_id]
        ast = normalize_ast(info.ast)
        for node in ast.get("nodes", []) or []:
            _parse_top_level(ctx, node)


def _parse_top_level(ctx: ParserContext, node: dict[str, Any]) -> None:
    node_type = node.get("nodeType")
    if node_type == "PragmaDirective":
        _parse_pragma(ctx, node)
    elif node_type == "ImportDirective":
        _parse_import(ctx, node)
    elif node_type == "ContractDefinition":
        _parse_contract(ctx, node)
    elif node_type == "FunctionDefinition":
        function = _parse_function(ctx, node, contract=None)
        ctx.unit.top_level_functions.append(function)
    elif node_type == "VariableDeclaration":
        variable = _parse_state_variable(ctx, node, contract=None)
        ctx.unit.top_level_variables.append(variable)
    elif node_type == "StructDefinition":
        struct = _parse_struct(ctx, node, contract=None)
        ctx.unit.structures.append(struct)
    elif node_type == "EnumDefinition":
        enum = _parse_enum(ctx, node, contract=None)
        ctx.unit.enums.append(enum)
    elif node_type == "ErrorDefinition":
        error = _parse_error(ctx, node, contract=None)
        ctx.unit.errors.append(error)
    elif node_type == "UsingForDirective":
        directive = _parse_using_for(ctx, node)
        ctx.unit.using_for.append(directive)
    elif node_type in ("UserDefinedValueTypeDefinition",):
        logger.debug("User-defined value types are not modeled yet: %s", node.get("name"))
    else:
        logger.debug("Skipping unsupported top-level node %r", node_type)


def _parse_pragma(ctx: ParserContext, node: dict[str, Any]) -> None:
    literals = node.get("literals", []) or []
    name = literals[0] if literals else ""
    version = "".join(literals[1:]) if len(literals) > 1 else ""
    pragma = PragmaDirective(name, version)
    attach_source(pragma, ctx.artifacts, node.get("src", ""))
    ctx.unit.pragmas.append(pragma)


def _parse_import(ctx: ParserContext, node: dict[str, Any]) -> None:
    path = node.get("file") or node.get("absolutePath", "")
    directive = ImportDirective(path)
    directive.alias = node.get("unitAlias") or None
    for alias in node.get("symbolAliases", []) or []:
        foreign = (alias.get("foreign") or {}).get("name", "")
        if foreign:
            directive.symbol_aliases[foreign] = alias.get("local") or foreign
    attach_source(directive, ctx.artifacts, node.get("src", ""))
    ctx.unit.imports.append(directive)


# ---------------------------------------------------------------- contracts
def _parse_contract(ctx: ParserContext, node: dict[str, Any]) -> Contract:
    contract = Contract(node.get("name", ""))
    contract.compilation_unit = ctx.unit

    kind = node.get("contractKind", "contract")
    abstract = node.get("abstract", False) or not node.get("fullyImplemented", True)
    if kind == "interface":
        contract.kind = ContractKind.INTERFACE
    elif kind == "library":
        contract.kind = ContractKind.LIBRARY
    elif abstract:
        contract.kind = ContractKind.ABSTRACT
    else:
        contract.kind = ContractKind.CONTRACT

    attach_source(contract, ctx.artifacts, node.get("src", ""))
    ctx.unit.contracts.append(contract)
    ctx.id_map[node["id"]] = contract

    bases: list[tuple[Optional[int], str]] = []
    for base in node.get("baseContracts", []) or []:
        base_name = base.get("baseName") or {}
        ref_id = base_name.get("referencedDeclaration")
        name = base_name.get("name") or base_name.get("namePath", "")
        bases.append((ref_id if isinstance(ref_id, int) else None, name))
    ctx.pending_bases.append((contract, bases))

    for child in node.get("nodes", []) or []:
        _parse_contract_member(ctx, contract, child)
    return contract


def _parse_contract_member(
    ctx: ParserContext, contract: Contract, node: dict[str, Any]
) -> None:
    node_type = node.get("nodeType")
    if node_type == "VariableDeclaration" and node.get("stateVariable"):
        variable = _parse_state_variable(ctx, node, contract)
        contract.state_variables.append(variable)
    elif node_type == "FunctionDefinition":
        function = _parse_function(ctx, node, contract)
        contract.functions.append(function)
    elif node_type == "ModifierDefinition":
        modifier = _parse_modifier(ctx, node, contract)
        contract.modifiers.append(modifier)
    elif node_type == "EventDefinition":
        event = _parse_event(ctx, node, contract)
        contract.events.append(event)
    elif node_type == "StructDefinition":
        struct = _parse_struct(ctx, node, contract)
        contract.structures.append(struct)
    elif node_type == "EnumDefinition":
        enum = _parse_enum(ctx, node, contract)
        contract.enums.append(enum)
    elif node_type == "ErrorDefinition":
        error = _parse_error(ctx, node, contract)
        contract.errors.append(error)
    elif node_type == "UsingForDirective":
        directive = _parse_using_for(ctx, node)
        contract.using_for.append(directive)
    elif node_type in ("UserDefinedValueTypeDefinition",):
        logger.debug("User-defined value types are not modeled yet: %s", node.get("name"))
    else:
        logger.debug("Skipping unsupported contract member %r", node_type)


def _parse_state_variable(
    ctx: ParserContext, node: dict[str, Any], contract: Optional[Contract]
) -> StateVariable:
    variable = StateVariable()
    variable.name = node.get("name", "")
    variable.visibility = node.get("visibility", "internal")
    variable.is_constant = node.get("constant", False)
    variable.is_immutable = node.get("mutability") == "immutable"
    variable.type = type_from_declaration(node, ctx)
    variable.contract = contract
    value = node.get("value")
    variable.initialized = value is not None
    attach_source(variable, ctx.artifacts, node.get("src", ""))
    if value is not None:
        ctx.pending_initializers.append((variable, value))
    ctx.id_map[node["id"]] = variable
    return variable


def _parse_local_variable(
    ctx: ParserContext,
    node: dict[str, Any],
    function: Optional[FunctionLike],
) -> LocalVariable:
    variable = LocalVariable()
    variable.name = node.get("name", "")
    variable.type = type_from_declaration(node, ctx)
    location = node.get("storageLocation", "default")
    variable.location = None if location == "default" else location
    variable.function = function  # type: ignore[assignment]
    attach_source(variable, ctx.artifacts, node.get("src", ""))
    if "id" in node:
        ctx.id_map[node["id"]] = variable
    return variable


def _function_kind(node: dict[str, Any], contract: Optional[Contract]) -> tuple[FunctionKind, str]:
    """Determine (kind, canonical name) across solc dialects."""
    name = node.get("name", "") or ""
    kind = node.get("kind")
    if kind in _KIND_MAP:
        mapped = _KIND_MAP[kind]
    elif node.get("isConstructor") or (
        name and contract is not None and name == contract.name
    ) or name == "constructor":
        mapped = FunctionKind.CONSTRUCTOR  # old-style `function ContractName()`
    elif name == "fallback":
        mapped = FunctionKind.FALLBACK
    elif name == "receive":
        mapped = FunctionKind.RECEIVE
    else:
        mapped = FunctionKind.NORMAL

    if mapped == FunctionKind.CONSTRUCTOR:
        canonical = "constructor"
    elif mapped == FunctionKind.FALLBACK:
        canonical = "fallback"
    elif mapped == FunctionKind.RECEIVE:
        canonical = "receive"
    else:
        canonical = name
    return mapped, canonical


def _parse_function_like(
    ctx: ParserContext,
    node: dict[str, Any],
    contract: Optional[Contract],
    function: FunctionLike,
) -> FunctionLike:
    mutability = node.get("stateMutability", "")
    function.payable = mutability == "payable"
    function.view = mutability == "view"
    function.pure = mutability == "pure"
    function.virtual = node.get("virtual", False)
    function.is_implemented = node.get("implemented", node.get("body") is not None)
    function.contract = contract
    function.contract_declarer = contract

    parameters = (node.get("parameters") or {}).get("parameters", []) or []
    function.parameters = [_parse_local_variable(ctx, p, function) for p in parameters]
    returns = (node.get("returnParameters") or {}).get("parameters", []) or []
    function.returns = [_parse_local_variable(ctx, p, function) for p in returns]

    attach_source(function, ctx.artifacts, node.get("src", ""))
    if "id" in node:
        ctx.id_map[node["id"]] = function
    ctx.pending_bodies.append((function, node.get("body")))
    ctx.pending_modifiers.append((function, node.get("modifiers", []) or []))
    if node.get("overrides") is not None or node.get("override"):
        ctx.pending_overrides.append(function)
    return function


def _parse_function(
    ctx: ParserContext, node: dict[str, Any], contract: Optional[Contract]
) -> Function:
    function = Function()
    kind, name = _function_kind(node, contract)
    function.set_kind(kind)
    function.name = name
    function.visibility = node.get("visibility", "public")
    _parse_function_like(ctx, node, contract, function)
    return function


def _parse_modifier(
    ctx: ParserContext, node: dict[str, Any], contract: Optional[Contract]
) -> Modifier:
    modifier = Modifier()
    modifier.name = node.get("name", "")
    modifier.visibility = node.get("visibility", "internal")
    _parse_function_like(ctx, node, contract, modifier)
    return modifier


def _parse_event(
    ctx: ParserContext, node: dict[str, Any], contract: Optional[Contract]
) -> Event:
    event = Event(node.get("name", ""))
    event.anonymous = node.get("anonymous", False)
    event.contract = contract
    for param in (node.get("parameters") or {}).get("parameters", []) or []:
        event.elems.append(
            EventParam(
                param.get("name", ""),
                type_from_declaration(param, ctx),
                param.get("indexed", False),
            )
        )
    attach_source(event, ctx.artifacts, node.get("src", ""))
    ctx.id_map[node["id"]] = event
    return event


def _parse_struct(
    ctx: ParserContext, node: dict[str, Any], contract: Optional[Contract]
) -> Structure:
    struct = Structure(node.get("name", ""))
    struct.contract = contract
    for member in node.get("members", []) or []:
        struct.elems.append(
            StructField(member.get("name", ""), type_from_declaration(member, ctx))
        )
    attach_source(struct, ctx.artifacts, node.get("src", ""))
    ctx.id_map[node["id"]] = struct
    return struct


def _parse_enum(
    ctx: ParserContext, node: dict[str, Any], contract: Optional[Contract]
) -> Enum:
    enum = Enum(node.get("name", ""))
    enum.contract = contract
    enum.values = [m.get("name", "") for m in node.get("members", []) or []]
    attach_source(enum, ctx.artifacts, node.get("src", ""))
    ctx.id_map[node["id"]] = enum
    return enum


def _parse_error(
    ctx: ParserContext, node: dict[str, Any], contract: Optional[Contract]
) -> CustomError:
    error = CustomError(node.get("name", ""))
    error.contract = contract
    for param in (node.get("parameters") or {}).get("parameters", []) or []:
        error.parameters.append(
            (param.get("name", ""), type_from_declaration(param, ctx))
        )
    attach_source(error, ctx.artifacts, node.get("src", ""))
    ctx.id_map[node["id"]] = error
    return error


def _parse_using_for(ctx: ParserContext, node: dict[str, Any]) -> UsingForDirective:
    directive = UsingForDirective()
    library_node = node.get("libraryName") or {}
    directive.library_name = library_node.get("name", "")
    ref_id = library_node.get("referencedDeclaration")
    type_node = node.get("typeName")
    if type_node is not None:
        descriptions = type_node.get("typeDescriptions") or {}
        directive.type_name = descriptions.get("typeString") or type_node.get("name")
    attach_source(directive, ctx.artifacts, node.get("src", ""))
    ctx.pending_using.append(
        (directive, ref_id if isinstance(ref_id, int) else None, type_node)
    )
    return directive


# ------------------------------------------------------------------ pass 2
def resolve_references(ctx: ParserContext) -> None:
    """Resolve all cross-references now that every declaration exists."""
    _resolve_inheritance(ctx)
    _resolve_modifier_invocations(ctx)
    _resolve_using_for(ctx)
    _resolve_override_graph(ctx)
    _parse_initializers(ctx)


def _resolve_inheritance(ctx: ParserContext) -> None:
    unit = ctx.unit
    for contract, bases in ctx.pending_bases:
        for ref_id, name in bases:
            target = ctx.id_map.get(ref_id) if ref_id is not None else None
            if target is None and name:
                target = unit.get_contract_from_name(name.split(".")[-1])
            if isinstance(target, Contract) and target not in contract.direct_bases:
                contract.direct_bases.append(target)

    # C3 linearization over unique per-object keys (names may collide across
    # source units); computed parents-first with a cycle guard so malformed
    # hierarchies degrade to declared order instead of raising.
    def key(c: Contract) -> str:
        return f"{c.name}#{id(c)}"

    ancestors: dict[str, list[str]] = {}

    def linearize(contract: Contract) -> list[str]:
        k = key(contract)
        if k in ancestors:
            return ancestors[k]
        ancestors[k] = []  # cycle guard
        for base in contract.direct_bases:
            linearize(base)
        # c3_linearization() takes the bases in DECLARED order and applies
        # the Solidity preference rule internally (do NOT pre-reverse here —
        # doing so double-reverses and restores the wrong order).
        preference = [key(b) for b in contract.direct_bases]
        try:
            ancestors[k] = c3_linearization(k, preference, ancestors)
        except ValueError:
            logger.warning(
                "Inconsistent inheritance hierarchy for %s; using declared order",
                contract.name,
            )
            # Degrade to the preference order plus every ancestor of each
            # base (deduped) so the ancestor set stays complete even when no
            # consistent linearization exists.
            degraded: list[str] = []
            for base_key in preference:
                for ancestor_key in [base_key] + ancestors.get(base_key, []):
                    if ancestor_key not in degraded:
                        degraded.append(ancestor_key)
            ancestors[k] = degraded
        return ancestors[k]

    for contract in unit.contracts:
        linearize(contract)

    by_key = {key(c): c for c in unit.contracts}
    for contract in unit.contracts:
        contract.inheritance = [
            by_key[k] for k in ancestors[key(contract)] if k in by_key
        ]
        for base in contract.direct_bases:
            if contract not in base.derived_contracts:
                base.derived_contracts.append(contract)


def _resolve_modifier_invocations(ctx: ParserContext) -> None:
    for function, invocations in ctx.pending_modifiers:
        for invocation in invocations:
            name_node = invocation.get("modifierName") or {}
            ref_id = name_node.get("referencedDeclaration")
            name = name_node.get("name", "")
            target = ctx.id_map.get(ref_id) if isinstance(ref_id, int) else None
            kind = invocation.get("kind", "modifierInvocation")
            if kind == "baseConstructorSpecifier":
                contract = _as_contract(ctx, target, name)
                if contract is not None:
                    function.explicit_base_constructor_calls.append(contract)
                continue
            modifier = _as_modifier(ctx, function, target, name)
            if modifier is not None:
                function.modifiers.append(modifier)
            else:
                logger.debug(
                    "Could not resolve modifier %s on %s", name, function.name
                )


def _as_contract(ctx: ParserContext, target: Any, name: str) -> Optional[Contract]:
    if isinstance(target, Contract):
        return target
    if name:
        found = ctx.unit.get_contract_from_name(name.split(".")[-1])
        if isinstance(found, Contract):
            return found
    return None


def _as_modifier(
    ctx: ParserContext, function: FunctionLike, target: Any, name: str
) -> Optional[Modifier]:
    if isinstance(target, Modifier):
        return target
    if name and function.contract_declarer is not None:
        simple = name.split(".")[-1]
        for modifier in function.contract_declarer.all_modifiers():
            if modifier.name == simple:
                return modifier
    if name:
        simple = name.split(".")[-1]
        for contract in ctx.unit.contracts:
            for modifier in contract.modifiers:
                if modifier.name == simple:
                    return modifier
    return None


def _resolve_using_for(ctx: ParserContext) -> None:
    for directive, ref_id, type_node in ctx.pending_using:
        target = ctx.id_map.get(ref_id) if ref_id is not None else None
        if not isinstance(target, Contract) and directive.library_name:
            target = ctx.unit.get_contract_from_name(directive.library_name.split(".")[-1])
        if isinstance(target, Contract):
            directive.library = target
        if type_node is not None:
            directive.type = type_from_type_name(type_node, ctx)


def _resolve_override_graph(ctx: ParserContext) -> None:
    for function in ctx.pending_overrides:
        contract = function.contract_declarer
        if contract is None:
            continue
        for base in contract.inheritance:
            match: Optional[FunctionLike] = None
            if isinstance(function, Modifier):
                candidates: list[Any] = base.modifiers
            else:
                candidates = base.functions
            for candidate in candidates:
                if candidate.signature == function.signature:
                    match = candidate
                    break
            if match is not None:
                function.overrides.append(match)
                if function not in match.overridden_by:
                    match.overridden_by.append(function)
                break


def _parse_initializers(ctx: ParserContext) -> None:
    for variable, value_node in ctx.pending_initializers:
        parser = ExpressionParser(ctx, function=None)
        variable.expression_initial = parser.parse(value_node)


def resolve_types(ctx: ParserContext) -> None:
    """Patch UnresolvedSymbol placeholders inside every parsed type tree."""
    for obj in ctx.all_typed_objects():
        resolve_unresolved_type(getattr(obj, "type", None), ctx)
