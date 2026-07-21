"""Detector batch G tests (spec/detectors-catalog.md — normative entries).

Each detector has at least one positive (vulnerable pattern flagged) and
one negative (safe pattern / unaffected compiler not flagged) test.

Three catalog patterns need compilers velvet cannot drive
(``constant-function-asm`` and ``constant-function-state`` need solc < 0.5
— modern solc rejects state-changing constant functions — and
``enum-conversion`` needs solc < 0.4.5, while velvet's parser requires the
compact AST of solc >= 0.5).  Their positive tests build the equivalent
core model programmatically; their vulnerable .sol fixtures document the
pattern for the required compiler and are not compiled by the suite.

``deprecated-standards`` covers constructs removed before solc 0.5
(``sha3``, ``msg.gas``, ``block.blockhash``, ``var``, ``years``,
``suicide``, ``callcode``, ``throw``, the ``constant`` function modifier):
the source scanner and the AST-level rules are exercised directly, while
the session tests cover ``now`` (removed in 0.7.0) through solc 0.6.12.

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path

from velvet.compile.artifacts import CompilationArtifacts
from velvet.core.cfg_node import CFGNode, NodeKind
from velvet.core.compilation_unit import CompilationUnit
from velvet.core.contract import Contract
from velvet.core.declarations import Enum, Event
from velvet.core.function import Function
from velvet.core.source_mapping import SourceRange
from velvet.core.types import ElementaryType, UserDefinedType
from velvet.core.variables import (
    Constant,
    LocalVariable,
    StateVariable,
    solidity_function,
    solidity_variable,
)
from velvet.detectors._batch_g import DETECTORS
from velvet.detectors.base import Confidence, DetectorDocs, Impact
from velvet.detectors.constant_function_asm import ConstantFunctionAsm
from velvet.detectors.constant_function_state import ConstantFunctionState
from velvet.detectors.deprecated_standards import (
    DeprecatedStandards,
    find_deprecated_lexemes,
)
from velvet.detectors.enum_conversion import EnumConversion
from velvet.detectors.incorrect_unary import has_suspicious_unary_sequence
from velvet.ir.operations import (
    Assignment,
    EventCall,
    LowLevelCall,
    SolidityCall,
    TypeConversion,
)
from velvet.ir.variables import TemporaryVariable
from velvet.session import Velvet

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "detectors"

_BY_RULE = {detector.RULE: detector for detector in DETECTORS}

#: Lazily-built sessions: (rule, "vulnerable"|"safe") -> Velvet.
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


# ----------------------------------------------------- programmatic models
def _unit(version: str) -> CompilationUnit:
    return CompilationUnit(CompilationArtifacts(compiler_version=version))


def _attach(contract: Contract, function: Function, name: str, **attrs) -> Function:
    function.name = name
    function.is_implemented = True
    function.contract_declarer = contract
    function.contract = contract
    for key, value in attrs.items():
        setattr(function, key, value)
    contract.functions.append(function)
    return function


# ------------------------------------------------------------- metadata
class TestBatchGMetadata:
    def test_all_rules_present(self):
        assert set(_BY_RULE) == {
            "array-by-reference",
            "assert-state-change",
            "constant-function-asm",
            "constant-function-state",
            "deprecated-standards",
            "enum-conversion",
            "events-maths",
            "function-init-state",
            "incorrect-exp",
            "incorrect-return",
            "incorrect-unary",
            "incorrect-using-for",
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
            "array-by-reference": (Impact.HIGH, Confidence.HIGH),
            "assert-state-change": (Impact.INFORMATIONAL, Confidence.HIGH),
            "constant-function-asm": (Impact.MEDIUM, Confidence.MEDIUM),
            "constant-function-state": (Impact.MEDIUM, Confidence.MEDIUM),
            "deprecated-standards": (Impact.INFORMATIONAL, Confidence.HIGH),
            "enum-conversion": (Impact.MEDIUM, Confidence.HIGH),
            "events-maths": (Impact.LOW, Confidence.MEDIUM),
            "function-init-state": (Impact.INFORMATIONAL, Confidence.HIGH),
            "incorrect-exp": (Impact.HIGH, Confidence.MEDIUM),
            "incorrect-return": (Impact.HIGH, Confidence.MEDIUM),
            "incorrect-unary": (Impact.LOW, Confidence.MEDIUM),
            "incorrect-using-for": (Impact.INFORMATIONAL, Confidence.HIGH),
        }
        for cls in DETECTORS:
            assert (cls.IMPACT, cls.CONFIDENCE) == expected[cls.RULE], cls.RULE


# ------------------------------------------------------- array-by-reference
class TestArrayByReference:
    RULE = "array-by-reference"

    def test_positive_by_value_mutations_flagged(self):
        findings = _findings(self.RULE, "vulnerable")
        assert len(findings) == 3
        text = " ".join(f.description for f in findings)
        assert "bump" in text  # fixed array, arr[0] += 1 on the copy
        assert "wipe" in text  # fixed array, arr[1] = 0 on the copy
        assert "touch" in text  # dynamic array copied too
        assert all(f.impact == Impact.HIGH for f in findings)
        assert all(f.confidence == Confidence.HIGH for f in findings)

    def test_negative_storage_ref_or_read_only_not_flagged(self):
        assert _findings(self.RULE, "safe") == []


# ------------------------------------------------------- assert-state-change
class TestAssertStateChange:
    RULE = "assert-state-change"

    def test_positive_side_effects_in_assert_flagged(self):
        findings = _findings(self.RULE, "vulnerable")
        assert len(findings) == 3
        text = " ".join(f.description for f in findings)
        assert "bump" in text  # (n += 1) inside assert
        assert "bumpBounded" in text  # n++ inside assert
        assert "callChecked" in text  # mutating call inside assert

    def test_negative_pure_invariants_not_flagged(self):
        assert _findings(self.RULE, "safe") == []


# ----------------------------------------------------- constant-function-asm
def _constant_asm_unit(version: str) -> CompilationUnit:
    """Counter.readAndBump: a view function with an inline assembly block."""
    unit = _unit(version)
    counter = Contract("Counter")
    fn = _attach(counter, Function(), "readAndBump", view=True)
    fn.add_node(CFGNode(NodeKind.ASSEMBLY))
    writer = _attach(counter, Function(), "writer")  # not constant: out of scope
    writer.add_node(CFGNode(NodeKind.ASSEMBLY))
    unit.contracts = [counter]
    return unit


class TestConstantFunctionAsm:
    RULE = "constant-function-asm"

    def test_positive_pre05_constant_with_assembly_flagged(self):
        findings = ConstantFunctionAsm(_constant_asm_unit("0.4.24"), None).analyze()
        assert len(findings) == 1
        assert "readAndBump" in findings[0].description
        assert findings[0].impact == Impact.MEDIUM
        assert findings[0].confidence == Confidence.MEDIUM

    def test_negative_modern_compiler_not_flagged(self):
        assert ConstantFunctionAsm(_constant_asm_unit("0.8.0"), None).analyze() == []

    def test_negative_session_modern_view_assembly_not_flagged(self):
        # The vulnerable pattern itself is present, but compiled with a
        # modern solc the pre-0.5 bug window does not apply.
        assert _findings(self.RULE, "safe") == []


# --------------------------------------------------- constant-function-state
def _constant_state_unit(version: str) -> CompilationUnit:
    """Stats.total writes a state variable; Stats.notify emits an event;
    Stats.readOnly is a plain view function. All declared constant/view."""
    unit = _unit(version)
    stats = Contract("Stats")
    queries = StateVariable()
    queries.name = "queries"
    queries.type = ElementaryType("uint256")
    queries.contract = stats
    stats.state_variables = [queries]

    total = _attach(stats, Function(), "total", view=True)
    write = total.add_node(CFGNode(NodeKind.EXPRESSION))
    write.ir_operations = [Assignment(queries, Constant(1))]

    ping = Event("Ping")
    ping.contract = stats
    stats.events = [ping]
    notify = _attach(stats, Function(), "notify", view=True)
    emit = notify.add_node(CFGNode(NodeKind.EXPRESSION))
    emit.ir_operations = [EventCall(ping, [])]

    read_only = _attach(stats, Function(), "readOnly", view=True)
    read_only.add_node(CFGNode(NodeKind.EXPRESSION))

    unit.contracts = [stats]
    return unit


class TestConstantFunctionState:
    RULE = "constant-function-state"

    def test_positive_pre05_constant_state_changes_flagged(self):
        findings = ConstantFunctionState(_constant_state_unit("0.4.24"), None).analyze()
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "queries" in text  # state variable write
        assert "Ping" in text  # event emission
        assert "readOnly" not in text
        assert all(f.impact == Impact.MEDIUM for f in findings)
        assert all(f.confidence == Confidence.MEDIUM for f in findings)

    def test_negative_modern_compiler_not_flagged(self):
        assert ConstantFunctionState(_constant_state_unit("0.8.0"), None).analyze() == []

    def test_negative_session_modern_view_not_flagged(self):
        assert _findings(self.RULE, "safe") == []


# ------------------------------------------------------- deprecated-standards
class TestDeprecatedStandards:
    RULE = "deprecated-standards"

    def test_positive_now_flagged(self):
        findings = _findings(self.RULE, "vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "touch" in text  # lastSeen = now
        assert "stale" in text  # now > deadline
        assert "block.timestamp" in text
        assert all(f.impact == Impact.INFORMATIONAL for f in findings)
        assert all(f.confidence == Confidence.HIGH for f in findings)

    def test_negative_modern_equivalents_not_flagged(self):
        assert _findings(self.RULE, "safe") == []

    def test_scanner_flags_removed_constructs(self):
        source = (
            "contract Old {\n"
            "    function h(uint a) public returns (bytes32) {\n"
            "        var x = sha3(a);\n"
            "        if (msg.gas == 0) { throw; }\n"
            "        return block.blockhash(a % 2 years);\n"
            "    }\n"
            "}\n"
        )
        found = dict(find_deprecated_lexemes(source))
        assert set(found) == {"sha3", "msg.gas", "block.blockhash", "var", "years"}

    def test_scanner_ignores_comments_and_strings(self):
        source = (
            'contract C { string s = "sha3(msg.gas)"; /* var x = 1; */'
            " // block.blockhash(2 years);\n"
            " function g() public pure returns (bytes32 h) { return keccak256(\"x\"); } }"
        )
        assert find_deprecated_lexemes(source) == []

    def test_ast_level_constructs_flagged(self):
        """Programmatic model: constant modifier, suicide, callcode, throw, now."""
        unit = _unit("0.4.24")
        legacy = Contract("Legacy")
        h = _attach(legacy, Function(), "h", view=True)
        h.set_source_mapping(
            SourceRange(content="function h() public constant returns (uint256)")
        )
        go = _attach(legacy, Function(), "go")
        go.add_node(CFGNode(NodeKind.THROW))
        kill = go.add_node(CFGNode(NodeKind.EXPRESSION))
        kill.ir_operations = [SolidityCall(None, solidity_function("suicide"), [])]
        forward = go.add_node(CFGNode(NodeKind.EXPRESSION))
        forward.ir_operations = [LowLevelCall(None, Constant(0), "callcode", [])]
        stamp = go.add_node(CFGNode(NodeKind.EXPRESSION))
        tmp = TemporaryVariable(go, 0)
        stamp.ir_operations = [Assignment(tmp, solidity_variable("now"))]
        unit.contracts = [legacy]

        findings = DeprecatedStandards(unit, None).analyze()
        text = " ".join(f.description for f in findings)
        assert "constant" in text
        assert "suicide" in text
        assert "callcode" in text
        assert "throw" in text
        assert "now" in text
        assert len(findings) == 5


# ------------------------------------------------------------ enum-conversion
def _enum_conversion_unit(version: str, *, constant_arg: bool = False) -> CompilationUnit:
    """Machine.set: converts an integer to the State enum."""
    unit = _unit(version)
    machine = Contract("Machine")
    state_enum = Enum("State")
    state_enum.values = ["Off", "On"]
    state_enum.contract = machine
    machine.enums = [state_enum]

    fn = _attach(machine, Function(), "set", visibility="external")
    param = LocalVariable()
    param.name = "s"
    param.type = ElementaryType("uint256")
    param.function = fn
    fn.parameters = [param]

    node = fn.add_node(CFGNode(NodeKind.RETURN))
    tmp = TemporaryVariable(fn, 0)
    source = Constant(1) if constant_arg else param
    node.ir_operations = [TypeConversion(tmp, source, UserDefinedType(state_enum))]
    unit.contracts = [machine]
    return unit


class TestEnumConversion:
    RULE = "enum-conversion"

    def test_positive_user_controlled_conversion_flagged(self):
        findings = EnumConversion(_enum_conversion_unit("0.4.2"), None).analyze()
        assert len(findings) == 1
        assert "State" in findings[0].description
        assert "set" in findings[0].description
        assert findings[0].impact == Impact.MEDIUM
        assert findings[0].confidence == Confidence.HIGH

    def test_negative_modern_compiler_not_flagged(self):
        assert EnumConversion(_enum_conversion_unit("0.8.0"), None).analyze() == []

    def test_negative_constant_argument_not_flagged(self):
        unit = _enum_conversion_unit("0.4.2", constant_arg=True)
        assert EnumConversion(unit, None).analyze() == []

    def test_negative_session_modern_conversion_not_flagged(self):
        assert _findings(self.RULE, "safe") == []


# --------------------------------------------------------------- events-maths
class TestEventsMaths:
    RULE = "events-maths"

    def test_positive_silent_parameter_changes_flagged(self):
        findings = _findings(self.RULE, "vulnerable")
        assert len(findings) == 2
        text = " ".join(f.description for f in findings)
        assert "setPrice" in text  # priceWei change, no event
        assert "setFee" in text  # feeBps change via internal helper
        assert "priceWei" in text
        assert "feeBps" in text
        assert all(f.impact == Impact.LOW for f in findings)
        assert all(f.confidence == Confidence.MEDIUM for f in findings)

    def test_negative_announced_or_out_of_scope_not_flagged(self):
        assert _findings(self.RULE, "safe") == []


# -------------------------------------------------------- function-init-state
class TestFunctionInitState:
    RULE = "function-init-state"

    def test_positive_order_dependent_initializers_flagged(self):
        findings = _findings(self.RULE, "vulnerable")
        assert len(findings) == 3
        text = " ".join(f.description for f in findings)
        assert "base" in text  # = compute() before factor is set
        assert "scaled" in text  # = compute() after factor
        assert "copied" in text  # = factor (non-constant read)
        assert all(f.impact == Impact.INFORMATIONAL for f in findings)
        assert all(f.confidence == Confidence.HIGH for f in findings)

    def test_negative_pure_or_constant_initializers_not_flagged(self):
        assert _findings(self.RULE, "safe") == []


# ------------------------------------------------------------- incorrect-exp
class TestIncorrectExp:
    RULE = "incorrect-exp"

    def test_positive_constant_xor_flagged(self):
        findings = _findings(self.RULE, "vulnerable")
        assert len(findings) == 4
        text = " ".join(f.description for f in findings)
        assert "HARD_CAP" in text  # 1000 * 10 ^ 18 in a constant definition
        assert "flag" in text  # 2 ^ 256 in a function body
        assert "inverse" in text  # (3 * d) ^ 2: decimal-literal operand
        assert "pow2" in text  # x ^ 2: exponent-shaped literal
        assert all(f.impact == Impact.HIGH for f in findings)
        assert all(f.confidence == Confidence.MEDIUM for f in findings)

    def test_negative_exponentiation_or_variable_xor_not_flagged(self):
        assert _findings(self.RULE, "safe") == []


# ---------------------------------------------------------- incorrect-return
class TestIncorrectReturn:
    RULE = "incorrect-return"

    def test_positive_assembly_return_in_internal_flagged(self):
        findings = _findings(self.RULE, "vulnerable")
        assert len(findings) == 1
        assert "_size" in findings[0].description
        assert "check" in findings[0].description  # internal caller named
        assert findings[0].impact == Impact.HIGH
        assert findings[0].confidence == Confidence.MEDIUM

    def test_negative_normal_or_outermost_return_not_flagged(self):
        assert _findings(self.RULE, "safe") == []


# ----------------------------------------------------------- incorrect-unary
class TestIncorrectUnary:
    RULE = "incorrect-unary"

    def test_positive_equals_minus_sequence_flagged(self):
        findings = _findings(self.RULE, "vulnerable")
        assert len(findings) == 1
        assert "=-" in findings[0].description
        assert "addOne" in findings[0].description
        assert findings[0].impact == Impact.LOW
        assert findings[0].confidence == Confidence.MEDIUM

    def test_negative_compound_or_spaced_assignments_not_flagged(self):
        assert _findings(self.RULE, "safe") == []

    def test_token_sequence_helper(self):
        assert has_suspicious_unary_sequence("count =- 1") == "=-"
        assert has_suspicious_unary_sequence("count =+ 1") == "=+"
        assert has_suspicious_unary_sequence("count = -1") is None
        assert has_suspicious_unary_sequence("count -= 1") is None
        assert has_suspicious_unary_sequence("count == 1") is None
        assert has_suspicious_unary_sequence("a = b <= 1 ? -1 : 2") is None


# -------------------------------------------------------- incorrect-using-for
class TestIncorrectUsingFor:
    RULE = "incorrect-using-for"

    def test_positive_unmatched_library_type_flagged(self):
        findings = _findings(self.RULE, "vulnerable")
        assert len(findings) == 1
        assert "Strings" in findings[0].description
        assert "bytes32" in findings[0].description
        assert findings[0].impact == Impact.INFORMATIONAL
        assert findings[0].confidence == Confidence.HIGH

    def test_negative_matching_first_parameters_not_flagged(self):
        assert _findings(self.RULE, "safe") == []
