"""Detector batch H tests: value-accounting loops, balance-delta
reentrancy, assembly return paths, constructor graphs, compiler-bug
mappings, scope/interface/event and gas rules over per-rule fixtures
(spec/detectors-catalog.md — normative entries).

Each rule gets a vulnerable fixture (must fire) and a safe fixture (must
not fire) exercised through a full Velvet session.

Three catalog patterns cannot be produced by any solc velvet can parse
(velvet's parser requires the compact AST of solc >= 0.5, and solc >= 0.5
rejects the pattern or predates the affected compiler):

- ``public-mappings-nested`` needs solc < 0.5.0;
- ``reused-constructor`` is rejected by solc >= 0.5 ("Base constructor
  arguments given twice");
- ``variable-scope`` needs pre-0.5.0 scoping rules.

Their positive tests build the equivalent core model programmatically
(as batch D does for ``multiple-constructors``); their vulnerable .sol
fixtures document the pattern for the required compiler.

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path

from velvet.compile.artifacts import CompilationArtifacts
from velvet.core.cfg_node import CFGNode, NodeKind
from velvet.core.compilation_unit import CompilationUnit
from velvet.core.contract import Contract
from velvet.core.declarations import Structure, StructField
from velvet.core.function import Function, FunctionKind
from velvet.core.types import ElementaryType, MappingType, UserDefinedType
from velvet.core.variables import Constant, LocalVariable, StateVariable
from velvet.detectors._batch_h import DETECTORS
from velvet.detectors.base import Confidence, DetectorDocs, Impact
from velvet.detectors.public_mappings_nested import PublicMappingsNested
from velvet.detectors.reused_constructor import ReusedConstructor
from velvet.detectors.variable_scope import VariableScope
from velvet.ir.operations import Assignment
from velvet.session import Velvet

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "detectors"

_BY_RULE = {detector.RULE: detector for detector in DETECTORS}

#: Lazily-built sessions: (rule, "Vulnerable"|"Safe") -> Velvet.
_SESSIONS: dict[tuple[str, str], Velvet] = {}


def _session(rule: str, kind: str) -> Velvet:
    key = (rule, kind)
    if key not in _SESSIONS:
        session = Velvet(str(FIXTURES / rule / f"{kind}.sol"))
        session.register_detector(_BY_RULE[rule])
        _SESSIONS[key] = session
    return _SESSIONS[key]


def _findings(rule: str, kind: str):
    session = _session(rule, kind)
    return [f for f in session.run_detectors() if f.check == rule]


# ------------------------------------------------------------- metadata
class TestBatchHMetadata:
    def test_all_rules_present(self):
        assert set(_BY_RULE) == {
            "msg-value-loop",
            "optimism-deprecation",
            "public-mappings-nested",
            "redundant-statements",
            "reentrancy-balance",
            "return-leave",
            "reused-constructor",
            "unimplemented-functions",
            "unindexed-event-address",
            "var-read-using-this",
            "variable-scope",
        }

    def test_rules_unique_and_kebab_case(self):
        rules = [cls.RULE for cls in DETECTORS]
        assert len(rules) == len(set(rules))
        for rule in rules:
            assert rule == rule.lower() and " " not in rule and "_" not in rule

    def test_metadata_contract(self):
        for cls in DETECTORS:
            assert cls.RULE and isinstance(cls.RULE, str)
            assert cls.TITLE
            assert isinstance(cls.IMPACT, Impact)
            assert isinstance(cls.CONFIDENCE, Confidence)
            assert isinstance(cls.DOCS, DetectorDocs)
            assert cls.DOCS.url.startswith("http")
            assert cls.DOCS.description
            assert cls.DOCS.exploit_scenario
            assert cls.DOCS.recommendation

    def test_catalog_classification(self):
        expected = {
            "msg-value-loop": (Impact.HIGH, Confidence.MEDIUM),
            "optimism-deprecation": (Impact.LOW, Confidence.HIGH),
            "public-mappings-nested": (Impact.HIGH, Confidence.HIGH),
            "redundant-statements": (Impact.INFORMATIONAL, Confidence.HIGH),
            "reentrancy-balance": (Impact.HIGH, Confidence.MEDIUM),
            "return-leave": (Impact.HIGH, Confidence.MEDIUM),
            "reused-constructor": (Impact.MEDIUM, Confidence.MEDIUM),
            "unimplemented-functions": (Impact.INFORMATIONAL, Confidence.HIGH),
            "unindexed-event-address": (Impact.INFORMATIONAL, Confidence.HIGH),
            "var-read-using-this": (Impact.OPTIMIZATION, Confidence.HIGH),
            "variable-scope": (Impact.LOW, Confidence.HIGH),
        }
        for cls in DETECTORS:
            assert (cls.IMPACT, cls.CONFIDENCE) == expected[cls.RULE], cls.RULE


# ----------------------------------------------------------- msg-value-loop
class TestMsgValueLoop:
    RULE = "msg-value-loop"

    def test_positive_msg_value_in_loops_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "fund" in text  # credited once per receiver
        assert "payout" in text  # transferred once per iteration

    def test_negative_bounded_share_and_amounts_array_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------ optimism-deprecation
class TestOptimismDeprecation:
    RULE = "optimism-deprecation"

    def test_positive_deprecated_scalar_calls_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "feeScalar" in text  # constant predeploy binding
        assert "inlineScalar" in text  # on-the-fly cast to the predeploy
        assert "0x420000000000000000000000000000000000000f" in text

    def test_negative_supported_functions_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------- reentrancy-balance
class TestReentrancyBalance:
    RULE = "reentrancy-balance"

    def test_positive_balance_delta_around_call_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 1
        assert "mint" in findings[0].description
        assert "balance" in findings[0].description
        assert findings[0].impact == Impact.HIGH
        assert findings[0].confidence == Confidence.MEDIUM

    def test_negative_pull_payment_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------------- return-leave
class TestReturnLeave:
    RULE = "return-leave"

    def test_positive_assembly_return_bypassing_epilogue_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "encode" in text  # named returns bypassed
        assert "tag" in text  # statement after the block skipped

    def test_negative_leave_and_bare_forwarder_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ----------------------------------------------------- redundant-statements
class TestRedundantStatements:
    RULE = "redundant-statements"

    def test_positive_no_effect_statements_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 4
        text = " ".join(f.description for f in findings)
        assert "uint256" in text  # bare type name
        assert "Draft" in text  # bare contract identifier
        assert "42" in text  # bare literal
        assert "x + 1" in text  # pure expression, no consumer

    def test_negative_effectful_statements_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# --------------------------------------------------- unindexed-event-address
class TestUnindexedEventAddress:
    RULE = "unindexed-event-address"

    def test_positive_unindexed_address_event_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 1
        assert "UserRegistered" in findings[0].description

    def test_negative_indexed_address_event_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ------------------------------------------------------- var-read-using-this
class TestVarReadUsingThis:
    RULE = "var-read-using-this"

    def test_positive_this_getter_reads_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "balanceOf" in text  # mapping getter through this
        assert "totalSupply" in text  # plain getter through this

    def test_negative_direct_reads_and_function_calls_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# --------------------------------------------------- unimplemented-functions
class TestUnimplementedFunctions:
    RULE = "unimplemented-functions"

    def test_positive_implicitly_abstract_contract_flagged(self):
        findings = _findings(self.RULE, "Vulnerable")
        assert len(findings) == 1
        assert "Token" in findings[0].description
        assert "transfer" in findings[0].description

    def test_negative_abstract_or_complete_contracts_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


# ----------------------------------------------------- programmatic models
def _unit(version: str) -> CompilationUnit:
    return CompilationUnit(CompilationArtifacts(compiler_version=version))


def _nested_mapping_unit(
    version: str, *, nested: bool, visibility: str = "public"
) -> CompilationUnit:
    """Ledger with a public (nested) allowances mapping."""
    unit = _unit(version)
    ledger = Contract("Ledger")
    variable = StateVariable()
    variable.name = "allowances"
    variable.visibility = visibility
    variable.contract = ledger
    value_type = (
        MappingType(ElementaryType("address"), ElementaryType("uint256"))
        if nested
        else ElementaryType("uint256")
    )
    variable.type = MappingType(ElementaryType("address"), value_type)
    ledger.state_variables = [variable]
    unit.contracts = [ledger]
    return unit


def _mapping_struct_unit(version: str) -> CompilationUnit:
    """Ledger with a public mapping to a struct holding a mapping."""
    unit = _unit(version)
    ledger = Contract("Ledger")
    struct = Structure("Account")
    struct.elems = [
        StructField("nonce", ElementaryType("uint256")),
        StructField(
            "bags",
            MappingType(ElementaryType("address"), ElementaryType("uint256")),
        ),
    ]
    variable = StateVariable()
    variable.name = "accounts"
    variable.visibility = "public"
    variable.contract = ledger
    variable.type = MappingType(
        ElementaryType("address"), UserDefinedType(struct)
    )
    ledger.state_variables = [variable]
    unit.contracts = [ledger]
    return unit


# ---------------------------------------------------- public-mappings-nested
class TestPublicMappingsNested:
    RULE = "public-mappings-nested"

    def test_positive_nested_mapping_on_old_compiler_flagged(self):
        unit = _nested_mapping_unit("0.4.24", nested=True)
        findings = PublicMappingsNested(unit, None).analyze()
        assert len(findings) == 1
        assert "allowances" in findings[0].description
        assert findings[0].impact == Impact.HIGH
        assert findings[0].confidence == Confidence.HIGH

    def test_positive_mapping_to_struct_with_mapping_flagged(self):
        unit = _mapping_struct_unit("0.4.26")
        findings = PublicMappingsNested(unit, None).analyze()
        assert len(findings) == 1
        assert "accounts" in findings[0].description

    def test_negative_fixed_compiler_not_flagged(self):
        unit = _nested_mapping_unit("0.5.0", nested=True)
        assert PublicMappingsNested(unit, None).analyze() == []

    def test_negative_flat_mapping_not_flagged(self):
        unit = _nested_mapping_unit("0.4.24", nested=False)
        assert PublicMappingsNested(unit, None).analyze() == []

    def test_negative_private_nested_mapping_not_flagged(self):
        unit = _nested_mapping_unit("0.4.24", nested=True, visibility="private")
        assert PublicMappingsNested(unit, None).analyze() == []

    def test_negative_modern_fixture_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


def _constructor(owner: Contract, calls: list[Contract], with_params: bool) -> Function:
    function = Function()
    function.name = "constructor"
    function.set_kind(FunctionKind.CONSTRUCTOR)
    function.contract_declarer = owner
    function.is_implemented = True
    if with_params:
        parameter = LocalVariable()
        parameter.name = "f"
        parameter.type = ElementaryType("uint256")
        function.parameters = [parameter]
    function.explicit_base_constructor_calls = list(calls)
    return function


def _reused_constructor_unit() -> CompilationUnit:
    """A built via B's A(10) and C's A(20) — only one runs under D."""
    unit = _unit("0.4.24")
    a = Contract("A")
    a.functions = [_constructor(a, [], with_params=True)]
    b = Contract("B")
    b.functions = [_constructor(b, [a], with_params=False)]
    c = Contract("C")
    c.functions = [_constructor(c, [a], with_params=False)]
    d = Contract("D")
    d.functions = [_constructor(d, [], with_params=False)]
    d.inheritance = [b, c, a]
    b.inheritance = [a]
    c.inheritance = [a]
    a.derived_contracts = [b, c]
    b.derived_contracts = [d]
    c.derived_contracts = [d]
    unit.contracts = [a, b, c, d]
    return unit


def _single_site_constructor_unit() -> CompilationUnit:
    """Only B calls A(uint256) with arguments, reachable from D."""
    unit = _unit("0.8.0")
    a = Contract("A")
    a.functions = [_constructor(a, [], with_params=True)]
    b = Contract("B")
    b.functions = [_constructor(b, [a], with_params=False)]
    d = Contract("D")
    d.functions = [_constructor(d, [], with_params=False)]
    d.inheritance = [b, a]
    b.inheritance = [a]
    a.derived_contracts = [b]
    b.derived_contracts = [d]
    unit.contracts = [a, b, d]
    return unit


# --------------------------------------------------------- reused-constructor
class TestReusedConstructor:
    RULE = "reused-constructor"

    def test_positive_two_argument_sites_flagged(self):
        unit = _reused_constructor_unit()
        findings = ReusedConstructor(unit, None).analyze()
        assert len(findings) == 1
        description = findings[0].description
        assert "D" in description
        assert "A" in description
        assert "B" in description and "C" in description
        assert findings[0].impact == Impact.MEDIUM
        assert findings[0].confidence == Confidence.MEDIUM

    def test_negative_single_site_not_flagged(self):
        unit = _single_site_constructor_unit()
        assert ReusedConstructor(unit, None).analyze() == []

    def test_negative_parameterless_base_not_flagged(self):
        unit = _unit("0.8.0")
        a = Contract("A")
        a.functions = [_constructor(a, [], with_params=False)]
        b = Contract("B")
        b.functions = [_constructor(b, [a], with_params=False)]
        c = Contract("C")
        c.functions = [_constructor(c, [a], with_params=False)]
        d = Contract("D")
        d.inheritance = [b, c, a]
        a.derived_contracts = [b, c]
        b.derived_contracts = [d]
        c.derived_contracts = [d]
        unit.contracts = [a, b, c, d]
        assert ReusedConstructor(unit, None).analyze() == []

    def test_negative_safe_fixture_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []


def _scope_unit(bad: bool) -> CompilationUnit:
    """Scope.f: reads of `bonus`/`limit` before their declarations run."""
    unit = _unit("0.4.24")
    scope = Contract("Scope")
    function = Function()
    function.name = "f"
    function.is_implemented = True
    function.contract_declarer = scope
    function.contract = scope
    scope.functions = [function]
    unit.contracts = [scope]

    result = LocalVariable()
    result.name = "result"
    result.type = ElementaryType("uint256")
    result.function = function
    bonus = LocalVariable()
    bonus.name = "bonus"
    bonus.type = ElementaryType("uint256")
    bonus.function = function
    limit = LocalVariable()
    limit.name = "limit"
    limit.type = ElementaryType("uint256")
    limit.function = function

    entry = function.add_node(CFGNode(NodeKind.ENTRYPOINT))
    if bad:
        # uint256 result = bonus + 1;  (reads bonus before its declaration)
        use_before = function.add_node(CFGNode(NodeKind.EXPRESSION))
        use_before.ir_operations = [Assignment(result, bonus)]
        entry.add_successor(use_before)
        previous = use_before
    else:
        previous = entry

    declaration = function.add_node(CFGNode(NodeKind.VARIABLE))
    declaration.variable_declaration = bonus
    declaration.ir_operations = [Assignment(bonus, Constant(5))]
    previous.add_successor(declaration)

    branch = function.add_node(CFGNode(NodeKind.IF))
    declaration.add_successor(branch)

    inner_declaration = function.add_node(CFGNode(NodeKind.VARIABLE))
    inner_declaration.variable_declaration = limit
    inner_declaration.ir_operations = [Assignment(limit, Constant(10))]
    branch.add_successor(inner_declaration)

    merge = function.add_node(CFGNode(NodeKind.EXPRESSION))
    if bad:
        # return result + limit; reachable without the if-body declaration
        merge.ir_operations = [Assignment(result, limit)]
    else:
        # dominated read: every path to the merge executed the declaration
        merge.ir_operations = [Assignment(result, bonus)]
    inner_declaration.add_successor(merge)
    branch.add_successor(merge)  # false path skips the inner declaration

    exit_node = function.add_node(CFGNode(NodeKind.RETURN))
    merge.add_successor(exit_node)
    return unit


# ------------------------------------------------------------ variable-scope
class TestVariableScope:
    RULE = "variable-scope"

    def test_positive_uses_before_declaration_flagged(self):
        unit = _scope_unit(bad=True)
        findings = VariableScope(unit, None).analyze()
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "bonus" in text  # declared later in the same block
        assert "limit" in text  # declared only inside the if-scope
        assert all(f.impact == Impact.LOW for f in findings)
        assert all(f.confidence == Confidence.HIGH for f in findings)

    def test_negative_declarations_dominate_uses_not_flagged(self):
        unit = _scope_unit(bad=False)
        assert VariableScope(unit, None).analyze() == []

    def test_negative_safe_fixture_not_flagged(self):
        assert _findings(self.RULE, "Safe") == []
