"""Batch D detector tests (spec/detectors-catalog.md — normative entries).

Each detector has at least one positive (vulnerable pattern flagged) and
one negative (safe pattern / unaffected compiler not flagged) test.

Two catalog patterns cannot be produced by any solc velvet can parse
(``multiple-constructors`` needs solc 0.4.22; ``uninitialized-storage``
needs a pre-0.5 compiler — velvet's parser requires the compact AST from
solc >= 0.5, and solc >= 0.5 rejects the pattern).  Their positive tests
build the equivalent core model programmatically; their vulnerable .sol
fixtures document the pattern for the required compiler.

Original clean-room implementation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from velvet.compile.artifacts import CompilationArtifacts
from velvet.core.cfg_node import CFGNode, NodeKind
from velvet.core.compilation_unit import CompilationUnit
from velvet.core.contract import Contract
from velvet.core.declarations import Structure
from velvet.core.function import Function, FunctionKind
from velvet.core.types import UserDefinedType
from velvet.core.variables import Constant, LocalVariable
from velvet.detectors._batch_d import DETECTORS
from velvet.detectors.base import Confidence, DetectorDocs, Impact
from velvet.detectors.multiple_constructors import MultipleConstructors
from velvet.detectors.uninitialized_storage import UninitializedStorage
from velvet.ir.operations import Assignment, Member
from velvet.ir.variables import ReferenceVariable
from velvet.session import Velvet

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "detectors"


def _session(path: Path) -> Velvet:
    session = Velvet(str(path))
    for cls in DETECTORS:
        session.register_detector(cls)
    return session


def _findings(session: Velvet, rule: str):
    return [f for f in session.run_detectors() if f.check == rule]


# ----------------------------------------------------- programmatic models
def _unit(version: str) -> CompilationUnit:
    return CompilationUnit(CompilationArtifacts(compiler_version=version))


def _two_constructor_unit(legacy_canonicalized: bool) -> CompilationUnit:
    """Contract Token with both a constructor() and a function Token()."""
    unit = _unit("0.4.22")
    token = Contract("Token")
    ctor = Function()
    ctor.name = "constructor"
    ctor.set_kind(FunctionKind.CONSTRUCTOR)
    ctor.contract_declarer = token
    legacy = Function()
    legacy.name = "Token"
    if legacy_canonicalized:
        # The parser maps functions named like their contract to constructor
        # kind, so a both-styles contract yields two constructor functions.
        legacy.set_kind(FunctionKind.CONSTRUCTOR)
    legacy.contract_declarer = token
    token.functions = [ctor, legacy]
    unit.contracts = [token]
    return unit


def _storage_pointer_unit(assign_at_declaration: bool) -> CompilationUnit:
    """Wallet.corrupt with a struct-typed storage local, used via Member."""
    unit = _unit("0.4.24")
    wallet = Contract("Wallet")
    fn = Function()
    fn.name = "corrupt"
    fn.is_implemented = True
    fn.contract_declarer = wallet
    fn.contract = wallet
    wallet.functions = [fn]
    unit.contracts = [wallet]

    local = LocalVariable()
    local.name = "e"
    local.type = UserDefinedType(Structure("Entry"))
    local.location = "storage"
    local.function = fn

    entry = fn.add_node(CFGNode(NodeKind.ENTRYPOINT))
    declaration = fn.add_node(CFGNode(NodeKind.VARIABLE))
    declaration.variable_declaration = local
    if assign_at_declaration:
        declaration.ir_operations = [Assignment(local, Constant(1))]
    use = fn.add_node(CFGNode(NodeKind.EXPRESSION))
    ref = ReferenceVariable(fn, 0, points_to=local)
    use.ir_operations = [Member(ref, local, "amount"), Assignment(ref, Constant(0))]
    entry.add_successor(declaration)
    declaration.add_successor(use)
    return unit


# ---------------------------------------------------------------- metadata
class TestBatchDMetadata:
    def test_rules_unique_and_kebab_case(self):
        rules = [cls.RULE for cls in DETECTORS]
        assert len(rules) == len(set(rules))
        for rule in rules:
            assert rule == rule.lower() and " " not in rule and "_" not in rule

    def test_metadata_complete(self):
        expected = {
            "arbitrary-send-erc20-permit",
            "reentrancy-unlimited-gas",
            "controlled-array-length",
            "encode-packed-collision",
            "multiple-constructors",
            "name-reused",
            "incorrect-shift",
            "rtlo",
            "uninitialized-state",
            "uninitialized-storage",
            "uninitialized-local",
            "uninitialized-fptr-cst",
            "shadowing-abstract",
            "shadowing-local",
            "locked-ether",
        }
        assert {cls.RULE for cls in DETECTORS} == expected
        for cls in DETECTORS:
            assert cls.TITLE
            assert isinstance(cls.IMPACT, Impact)
            assert isinstance(cls.CONFIDENCE, Confidence)
            assert isinstance(cls.DOCS, DetectorDocs)
            assert cls.DOCS.url.startswith("http")
            assert cls.DOCS.description
            assert cls.DOCS.exploit_scenario
            assert cls.DOCS.recommendation


# --------------------------------------------- arbitrary-send-erc20-permit
@pytest.fixture(scope="module")
def permit_vulnerable():
    return _session(FIXTURES / "arbitrary-send-erc20-permit" / "vulnerable.sol")


@pytest.fixture(scope="module")
def permit_safe():
    return _session(FIXTURES / "arbitrary-send-erc20-permit" / "safe.sol")


class TestArbitrarySendErc20Permit:
    RULE = "arbitrary-send-erc20-permit"

    def test_positive_arbitrary_from_after_permit_flagged(self, permit_vulnerable):
        findings = _findings(permit_vulnerable, self.RULE)
        assert len(findings) == 1
        assert "transferFrom" in findings[0].description
        assert "permit" in findings[0].description
        assert "depositWithPermit" in findings[0].description
        assert findings[0].impact == Impact.HIGH
        assert findings[0].confidence == Confidence.MEDIUM

    def test_negative_msg_sender_bound_not_flagged(self, permit_safe):
        assert _findings(permit_safe, self.RULE) == []


# ---------------------------------------------------- reentrancy-unlimited
@pytest.fixture(scope="module")
def reentrancy_gas_vulnerable():
    return _session(FIXTURES / "reentrancy-unlimited-gas" / "vulnerable.sol")


@pytest.fixture(scope="module")
def reentrancy_gas_safe():
    return _session(FIXTURES / "reentrancy-unlimited-gas" / "safe.sol")


class TestReentrancyUnlimitedGas:
    RULE = "reentrancy-unlimited-gas"

    def test_positive_transfer_before_update_flagged(self, reentrancy_gas_vulnerable):
        findings = _findings(reentrancy_gas_vulnerable, self.RULE)
        assert len(findings) == 1
        assert "send/transfer" in findings[0].description
        assert "balances" in findings[0].description
        assert findings[0].impact == Impact.INFORMATIONAL
        assert findings[0].confidence == Confidence.MEDIUM

    def test_negative_cei_order_not_flagged(self, reentrancy_gas_safe):
        assert _findings(reentrancy_gas_safe, self.RULE) == []


# -------------------------------------------------- controlled-array-length
@pytest.fixture(scope="module")
def length_vulnerable():
    return _session(FIXTURES / "controlled-array-length" / "vulnerable.sol")


@pytest.fixture(scope="module")
def length_safe():
    return _session(FIXTURES / "controlled-array-length" / "safe.sol")


@pytest.fixture(scope="module")
def length_safe_modern():
    return _session(FIXTURES / "controlled-array-length" / "safe-modern.sol")


class TestControlledArrayLength:
    RULE = "controlled-array-length"

    def test_positive_user_controlled_length_flagged(self, length_vulnerable):
        findings = _findings(length_vulnerable, self.RULE)
        assert len(findings) == 1
        assert "entries" in findings[0].description
        assert "resize" in findings[0].description
        assert findings[0].impact == Impact.HIGH
        assert findings[0].confidence == Confidence.MEDIUM

    def test_negative_constant_and_protected_not_flagged(self, length_safe):
        assert _findings(length_safe, self.RULE) == []

    def test_negative_fixed_compiler_not_flagged(self, length_safe_modern):
        assert _findings(length_safe_modern, self.RULE) == []


# ------------------------------------------------- encode-packed-collision
@pytest.fixture(scope="module")
def encode_vulnerable():
    return _session(FIXTURES / "encode-packed-collision" / "vulnerable.sol")


@pytest.fixture(scope="module")
def encode_safe():
    return _session(FIXTURES / "encode-packed-collision" / "safe.sol")


class TestEncodePackedCollision:
    RULE = "encode-packed-collision"

    def test_positive_two_dynamic_args_flagged(self, encode_vulnerable):
        findings = _findings(encode_vulnerable, self.RULE)
        assert len(findings) == 1
        assert "abi.encodePacked" in findings[0].description
        assert "tag" in findings[0].description
        assert findings[0].impact == Impact.HIGH
        assert findings[0].confidence == Confidence.HIGH

    def test_negative_single_dynamic_or_encode_not_flagged(self, encode_safe):
        assert _findings(encode_safe, self.RULE) == []


# --------------------------------------------------- multiple-constructors
@pytest.fixture(scope="module")
def constructors_safe():
    return _session(FIXTURES / "multiple-constructors" / "safe.sol")


class TestMultipleConstructors:
    RULE = "multiple-constructors"

    def test_positive_two_constructor_kinds_flagged(self):
        # Parser-canonicalized form: both declarations map to constructors.
        unit = _two_constructor_unit(legacy_canonicalized=True)
        findings = MultipleConstructors(unit, None).analyze()
        assert len(findings) == 1
        assert "Token" in findings[0].description
        assert findings[0].impact == Impact.HIGH
        assert findings[0].confidence == Confidence.HIGH

    def test_positive_legacy_named_function_flagged(self):
        # Raw form: a modern constructor plus a function named Token.
        unit = _two_constructor_unit(legacy_canonicalized=False)
        findings = MultipleConstructors(unit, None).analyze()
        assert len(findings) == 1

    def test_negative_single_constructor_not_flagged(self, constructors_safe):
        assert _findings(constructors_safe, self.RULE) == []


# ------------------------------------------------------------- name-reused
@pytest.fixture(scope="module")
def names_vulnerable():
    return _session(FIXTURES / "name-reused" / "vulnerable")


@pytest.fixture(scope="module")
def names_safe():
    return _session(FIXTURES / "name-reused" / "safe")


class TestNameReused:
    RULE = "name-reused"

    def test_positive_duplicate_contract_name_flagged(self, names_vulnerable):
        findings = _findings(names_vulnerable, self.RULE)
        assert len(findings) == 1
        assert "ERC20" in findings[0].description
        assert findings[0].impact == Impact.HIGH
        assert findings[0].confidence == Confidence.HIGH

    def test_negative_unique_names_not_flagged(self, names_safe):
        assert _findings(names_safe, self.RULE) == []


# ---------------------------------------------------------- incorrect-shift
@pytest.fixture(scope="module")
def shift_vulnerable():
    return _session(FIXTURES / "incorrect-shift" / "vulnerable.sol")


@pytest.fixture(scope="module")
def shift_safe():
    return _session(FIXTURES / "incorrect-shift" / "safe.sol")


class TestIncorrectShift:
    RULE = "incorrect-shift"

    def test_positive_swapped_operands_flagged(self, shift_vulnerable):
        findings = _findings(shift_vulnerable, self.RULE)
        assert len(findings) == 3
        joined = " ".join(f.description for f in findings)
        assert "shr(word, 248)" in joined
        assert "sar(x, 255)" in joined
        assert "shl(v, 4)" in joined
        assert all(f.impact == Impact.HIGH for f in findings)
        assert all(f.confidence == Confidence.HIGH for f in findings)

    def test_negative_amount_first_not_flagged(self, shift_safe):
        assert _findings(shift_safe, self.RULE) == []


# ---------------------------------------------------------------------- rtlo
@pytest.fixture(scope="module")
def rtlo_vulnerable():
    return _session(FIXTURES / "rtlo" / "vulnerable.sol")


@pytest.fixture(scope="module")
def rtlo_safe():
    return _session(FIXTURES / "rtlo" / "safe.sol")


class TestRtlo:
    RULE = "rtlo"

    def test_positive_override_character_flagged(self, rtlo_vulnerable):
        findings = _findings(rtlo_vulnerable, self.RULE)
        assert len(findings) == 1
        assert "U+202E" in findings[0].description
        assert "Pay" in findings[0].description
        assert findings[0].impact == Impact.HIGH
        assert findings[0].confidence == Confidence.HIGH

    def test_negative_clean_source_not_flagged(self, rtlo_safe):
        assert _findings(rtlo_safe, self.RULE) == []


# ------------------------------------------------------- uninitialized-state
@pytest.fixture(scope="module")
def uninit_state_vulnerable():
    return _session(FIXTURES / "uninitialized-state" / "vulnerable.sol")


@pytest.fixture(scope="module")
def uninit_state_safe():
    return _session(FIXTURES / "uninitialized-state" / "safe.sol")


class TestUninitializedState:
    RULE = "uninitialized-state"

    def test_positive_never_assigned_but_read_flagged(self, uninit_state_vulnerable):
        findings = _findings(uninit_state_vulnerable, self.RULE)
        assert len(findings) == 1
        assert "beneficiary" in findings[0].description
        assert findings[0].impact == Impact.HIGH
        assert findings[0].confidence == Confidence.HIGH

    def test_negative_assigned_or_unread_not_flagged(self, uninit_state_safe):
        findings = _findings(uninit_state_safe, self.RULE)
        assert findings == []


# ---------------------------------------------------- uninitialized-storage
@pytest.fixture(scope="module")
def uninit_storage_safe():
    return _session(FIXTURES / "uninitialized-storage" / "safe.sol")


class TestUninitializedStorage:
    RULE = "uninitialized-storage"

    def test_positive_pointer_used_before_assignment_flagged(self):
        # Pattern needs a pre-0.5 compiler; model constructed programmatically.
        unit = _storage_pointer_unit(assign_at_declaration=False)
        findings = UninitializedStorage(unit, None).analyze()
        assert len(findings) == 1
        assert "uninitialized storage pointer" in findings[0].description
        assert findings[0].impact == Impact.HIGH
        assert findings[0].confidence == Confidence.HIGH

    def test_positive_assigned_pointer_not_flagged(self):
        unit = _storage_pointer_unit(assign_at_declaration=True)
        assert UninitializedStorage(unit, None).analyze() == []

    def test_negative_bound_pointer_not_flagged(self, uninit_storage_safe):
        assert _findings(uninit_storage_safe, self.RULE) == []


# ------------------------------------------------------- uninitialized-local
@pytest.fixture(scope="module")
def uninit_local_vulnerable():
    return _session(FIXTURES / "uninitialized-local" / "vulnerable.sol")


@pytest.fixture(scope="module")
def uninit_local_safe():
    return _session(FIXTURES / "uninitialized-local" / "safe.sol")


class TestUninitializedLocal:
    RULE = "uninitialized-local"

    def test_positive_read_on_unassigned_path_flagged(self, uninit_local_vulnerable):
        findings = _findings(uninit_local_vulnerable, self.RULE)
        assert len(findings) == 1
        assert "dst" in findings[0].description
        assert "pay" in findings[0].description
        assert findings[0].impact == Impact.MEDIUM
        assert findings[0].confidence == Confidence.MEDIUM

    def test_negative_assigned_on_all_paths_not_flagged(self, uninit_local_safe):
        assert _findings(uninit_local_safe, self.RULE) == []

    def test_negative_assembly_assigned_not_flagged(self, uninit_local_safe):
        # `ptr := ...` inside inline assembly is an assignment.
        findings = _findings(uninit_local_safe, self.RULE)
        assert not any("ptr" in f.description for f in findings)

    def test_negative_for_header_declaration_not_flagged(self, uninit_local_safe):
        # `for (uint256 i; ...; ++i)`: the header defines the counter.
        findings = _findings(uninit_local_safe, self.RULE)
        assert not any(" i " in f.description or f.description.endswith(" i")
                       for f in findings)

    def test_negative_erc7201_constant_in_assembly_not_flagged(self):
        # `$.slot := SLOT` with SLOT a contract constant: the Yul model must
        # resolve SLOT to the constant, not a synthetic uninitialized local.
        session = _session(FIXTURES / "uninitialized-local" / "erc7201_accessor.sol")
        assert _findings(session, self.RULE) == []


# -------------------------------------------------- uninitialized-fptr-cst
@pytest.fixture(scope="module")
def fptr_vulnerable():
    return _session(FIXTURES / "uninitialized-fptr-cst" / "vulnerable.sol")


@pytest.fixture(scope="module")
def fptr_safe():
    return _session(FIXTURES / "uninitialized-fptr-cst" / "safe.sol")


@pytest.fixture(scope="module")
def fptr_safe_modern():
    return _session(FIXTURES / "uninitialized-fptr-cst" / "safe-modern.sol")


class TestUninitializedFptrCst:
    RULE = "uninitialized-fptr-cst"

    def test_positive_unassigned_pointer_call_flagged(self, fptr_vulnerable):
        findings = _findings(fptr_vulnerable, self.RULE)
        assert len(findings) == 1
        assert "function pointer" in findings[0].description
        assert "cb" in findings[0].description
        assert findings[0].impact == Impact.LOW
        assert findings[0].confidence == Confidence.HIGH

    def test_negative_assigned_pointer_not_flagged(self, fptr_safe):
        assert _findings(fptr_safe, self.RULE) == []

    def test_negative_fixed_compiler_not_flagged(self, fptr_safe_modern):
        assert _findings(fptr_safe_modern, self.RULE) == []


# ------------------------------------------------------- shadowing-abstract
@pytest.fixture(scope="module")
def shadow_abstract_vulnerable():
    return _session(FIXTURES / "shadowing-abstract" / "vulnerable.sol")


@pytest.fixture(scope="module")
def shadow_abstract_safe():
    return _session(FIXTURES / "shadowing-abstract" / "safe.sol")


class TestShadowingAbstract:
    RULE = "shadowing-abstract"

    def test_positive_abstract_base_shadowed_flagged(self, shadow_abstract_vulnerable):
        findings = _findings(shadow_abstract_vulnerable, self.RULE)
        assert len(findings) == 1
        assert "rate" in findings[0].description
        assert "Base" in findings[0].description
        assert findings[0].impact == Impact.MEDIUM
        assert findings[0].confidence == Confidence.HIGH

    def test_negative_distinct_names_not_flagged(self, shadow_abstract_safe):
        assert _findings(shadow_abstract_safe, self.RULE) == []


# ---------------------------------------------------------- shadowing-local
@pytest.fixture(scope="module")
def shadow_local_vulnerable():
    return _session(FIXTURES / "shadowing-local" / "vulnerable.sol")


@pytest.fixture(scope="module")
def shadow_local_safe():
    return _session(FIXTURES / "shadowing-local" / "safe.sol")


class TestShadowingLocal:
    RULE = "shadowing-local"

    def test_positive_param_and_local_shadowing_flagged(self, shadow_local_vulnerable):
        findings = _findings(shadow_local_vulnerable, self.RULE)
        assert len(findings) == 2
        joined = " ".join(f.description for f in findings)
        assert "state variable" in joined  # parameter total
        assert "function" in joined  # local deposit
        assert all(f.impact == Impact.LOW for f in findings)
        assert all(f.confidence == Confidence.HIGH for f in findings)

    def test_negative_distinct_names_not_flagged(self, shadow_local_safe):
        assert _findings(shadow_local_safe, self.RULE) == []

    def test_negative_erc7201_constant_in_assembly_not_shadowing(self):
        # The ERC-7201 accessor reads the contract constant SLOT inside
        # assembly; no synthetic local may "shadow" that state variable.
        session = _session(FIXTURES / "shadowing-local" / "erc7201_accessor.sol")
        assert _findings(session, self.RULE) == []


# ------------------------------------------------------------- locked-ether
@pytest.fixture(scope="module")
def locked_vulnerable():
    return _session(FIXTURES / "locked-ether" / "vulnerable.sol")


@pytest.fixture(scope="module")
def locked_safe():
    return _session(FIXTURES / "locked-ether" / "safe.sol")


class TestLockedEther:
    RULE = "locked-ether"

    def test_positive_payable_without_withdrawal_flagged(self, locked_vulnerable):
        findings = _findings(locked_vulnerable, self.RULE)
        assert len(findings) == 1
        assert "TipJar" in findings[0].description
        assert findings[0].impact == Impact.MEDIUM
        assert findings[0].confidence == Confidence.HIGH

    def test_negative_withdrawal_path_not_flagged(self, locked_safe):
        assert _findings(locked_safe, self.RULE) == []
