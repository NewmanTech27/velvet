"""``velvet-check-upgradeability`` — upgradeability reviewer
(spec/printers-and-tools.md §B.2).

Reviews contracts that use the ``delegatecall``-based proxy upgradeability
pattern and statically detects the classic failure classes, as the 17-check
catalog of §B.2.2:

- initializer presence/protection on the implementation (checks 4-6, 9,
  14-17): an ``initialize`` function exists, is guarded by the
  ``Initializable.initializer`` once-only modifier, calls every base
  initializer exactly once, and no state variable relies on
  declaration-time initialization;
- storage-layout compatibility between the implementation V1 and its
  planned upgrade V2 (checks 1, 7, 10, 12-13): variables are matched by
  position, the common prefix must be identical in order and type,
  variables never change ``constant`` status, and variables are never
  deleted, only appended;
- proxy/implementation surface and layout review (checks 2-3, 8, 11):
  selector collisions, name/signature shadowing, and storage agreement
  for variables existing in both.

On top of the documented catalog, the tool emits clearly separated
*enhancement* observations (§B.2.3 explicitly allows a dedicated
gap-consistency check): storage-gap reservations and consumption, plus
``selfdestruct``/``delegatecall`` presence in implementation contracts
(upgradeable-incompatible patterns; a V2 introducing one becomes
incompatible).

Invocation::

    velvet-check-upgradeability TARGET CONTRACT [NEW_CONTRACT]
        [--new-contract-filename TARGET2]
        [--proxy-name PROXY [--proxy-filename TARGET3]]
        [--json FILE]

Exit code: 0 = no FAIL finding, 1 = at least one FAIL finding,
2 = usage/compilation error.

Original clean-room implementation.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from velvet.core.contract import Contract
from velvet.core.function import Function, FunctionKind, Modifier
from velvet.core.types import ArrayType
from velvet.core.variables import StateVariable
from velvet.exceptions import VelvetError
from velvet.ir.operations import InternalCall, LowLevelCall, SolidityCall
from velvet.outputs.console import render_source_ref
from velvet.outputs.json_out import element_to_dict
from velvet.session import Velvet
from velvet.tools.common import (
    build_session,
    canonical_params,
    canonical_type,
    find_contract,
    function_selector,
    public_getters,
    signature_of,
)

# ---------------------------------------------------------------------------
# check catalog (spec/printers-and-tools.md §B.2.2 — the 17 documented checks)
# ---------------------------------------------------------------------------

#: JSON sub-reports (§C.4.2).
GROUP_INIT = "check-initialization"
GROUP_INIT_V2 = "check-initialization-v2"
GROUP_FUNCTION_IDS = "compare-function-ids"
GROUP_PROXY_VARS = "compare-variables-order-proxy"
GROUP_IMPL_VARS = "compare-variables-order-implementation"

SUB_REPORTS = (
    GROUP_INIT,
    GROUP_INIT_V2,
    GROUP_FUNCTION_IDS,
    GROUP_PROXY_VARS,
    GROUP_IMPL_VARS,
)

#: Checklist statuses. FAIL/WARN/INFO map from the documented impact
#: (High -> FAIL, Medium -> WARN, Informational -> INFO); a check with no
#: finding is PASS; a check whose mode was not requested is SKIP.
PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
INFO = "INFO"
SKIP = "SKIP"


@dataclass(frozen=True)
class CheckSpec:
    """One checklist entry (documented check or velvet enhancement)."""

    key: str
    impact: str  # High | Medium | Informational
    title: str
    pass_text: str
    group: str
    needs_proxy: bool = False
    needs_v2: bool = False
    enhancement: bool = False


CHECKS: tuple[CheckSpec, ...] = (
    CheckSpec(
        "became-constant", "High",
        "A variable that was non-constant in V1 became constant in V2 — "
        "removes a storage slot and shifts the layout of every later variable",
        "no V1 variable became constant in V2",
        GROUP_IMPL_VARS, needs_v2=True,
    ),
    CheckSpec(
        "function-id-collision", "High",
        "A proxy function's 4-byte selector collides with an implementation "
        "function's selector (different names, same selector)",
        "no proxy/implementation selector collision",
        GROUP_FUNCTION_IDS, needs_proxy=True,
    ),
    CheckSpec(
        "function-shadowing", "High",
        "A proxy function has the same name/signature as an implementation "
        "function — calls never reach the logic contract",
        "no proxy function shadows an implementation function",
        GROUP_FUNCTION_IDS, needs_proxy=True,
    ),
    CheckSpec(
        "missing-calls", "High",
        "A derived contract's initialize does not call a base contract's "
        "initialize (missing init call in the inheritance chain)",
        "every base initializer is called from the derived initialize",
        GROUP_INIT,
    ),
    CheckSpec(
        "missing-init-modifier", "High",
        "The initialize function lacks the Initializable.initializer "
        "modifier, so it can be invoked multiple times (re-initialization)",
        "every initialize function is guarded by the `initializer` modifier",
        GROUP_INIT,
    ),
    CheckSpec(
        "multiple-calls", "High",
        "The same initialize function is called more than once along one "
        "initialization path",
        "no base initializer is called more than once",
        GROUP_INIT,
    ),
    CheckSpec(
        "order-vars-contracts", "High",
        "V1 and V2 state variables differ in order/type — the two versions "
        "do not share a storage layout",
        "V2 preserves the V1 storage layout (order and types)",
        GROUP_IMPL_VARS, needs_v2=True,
    ),
    CheckSpec(
        "order-vars-proxy", "High",
        "Proxy and implementation state variables differ — layouts must "
        "match for any variable that exists in both",
        "shared proxy/implementation variables agree in order and type",
        GROUP_PROXY_VARS, needs_proxy=True,
    ),
    CheckSpec(
        "variables-initialized", "High",
        "A state variable is initialized at declaration — the assignment "
        "runs only in the implementation's context and is invisible "
        "through the proxy",
        "no state variable is initialized at declaration time",
        GROUP_INIT,
    ),
    CheckSpec(
        "were-constant", "High",
        "A constant variable in V1 became non-constant in V2 — inserts a "
        "storage slot and shifts the layout",
        "no V1 constant became a state variable in V2",
        GROUP_IMPL_VARS, needs_v2=True,
    ),
    CheckSpec(
        "extra-vars-proxy", "Medium",
        "Variables present in the proxy but not in the implementation — a "
        "later implementation upgrade may corrupt the proxy's storage",
        "the proxy declares no variable unknown to the implementation",
        GROUP_PROXY_VARS, needs_proxy=True,
    ),
    CheckSpec(
        "missing-variables", "Medium",
        "Variables present in V1 but removed in V2 — a still-later V3 "
        "adding a variable at that position would read stale values",
        "no V1 variable was removed in V2",
        GROUP_IMPL_VARS, needs_v2=True,
    ),
    CheckSpec(
        "extra-vars-v2", "Informational",
        "Variables newly added in V2 — must only ever be appended after "
        "all V1 variables",
        "V2 adds no new state variables",
        GROUP_IMPL_VARS, needs_v2=True,
    ),
    CheckSpec(
        "init-inherited", "Informational",
        "The contract does not inherit an Initializable helper",
        "the contract inherits an Initializable helper",
        GROUP_INIT,
    ),
    CheckSpec(
        "init-missing", "Informational",
        "No Initializable contract is present in the codebase",
        "an Initializable contract is present in the codebase",
        GROUP_INIT,
    ),
    CheckSpec(
        "initialize-target", "Informational",
        "Reports the initialize function(s) that must be called at "
        "deployment (checklist aid)",
        "",
        GROUP_INIT,
    ),
    CheckSpec(
        "initializer-missing", "Informational",
        "The Initializable.initializer modifier is not used anywhere",
        "the `initializer` modifier is used",
        GROUP_INIT,
    ),
)

CHECKS_BY_KEY = {check.key: check for check in CHECKS}

#: Velvet enhancements (§B.2.3 explicitly allows a dedicated gap-consistency
#: check; selfdestruct/delegatecall presence completes the
#: upgradeable-incompatibility review the initializer checks describe).
ENHANCEMENTS: tuple[CheckSpec, ...] = (
    CheckSpec(
        "gap-reserved", "Informational",
        "Storage gap reserving slots for future variables (convention: "
        "50 - number of declared variables)",
        "no storage gap declared",
        GROUP_INIT, enhancement=True,
    ),
    CheckSpec(
        "gap-consistency", "Medium",
        "Variables added by V2 without shrinking the storage gap by the "
        "same number of slots",
        "storage gap consumption is consistent with the appended variables",
        GROUP_IMPL_VARS, needs_v2=True, enhancement=True,
    ),
    CheckSpec(
        "no-selfdestruct", "Medium",
        "selfdestruct/suicide present in an implementation contract — "
        "destroying it bricks every attached proxy",
        "no selfdestruct path in the implementation contract",
        GROUP_INIT, enhancement=True,
    ),
    CheckSpec(
        "no-delegatecall", "Medium",
        "delegatecall/callcode present in an implementation contract — a "
        "tainted destination hijacks the proxy's storage context",
        "no delegatecall in the implementation contract",
        GROUP_INIT, enhancement=True,
    ),
)

ENHANCEMENTS_BY_KEY = {check.key: check for check in ENHANCEMENTS}


# ---------------------------------------------------------------------------
# findings and report
# ---------------------------------------------------------------------------


@dataclass
class CheckFinding:
    """One emitted observation, attached to a check (FAIL/WARN/INFO)."""

    spec: CheckSpec
    status: str
    message: str
    elements: list[Any] = field(default_factory=list)
    group: str = GROUP_INIT
    additional_fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "check": self.spec.key,
            "impact": self.spec.impact,
            "confidence": "High",
            "description": self.message,
            "elements": [element_to_dict(e) for e in self.elements],
        }
        if self.additional_fields:
            result["additional_fields"] = self.additional_fields
        return result


@dataclass
class ReviewContext:
    """Everything one tool run reviews."""

    session: Velvet
    contract: Contract
    v2_contract: Optional[Contract] = None
    v2_session: Optional[Velvet] = None
    proxy_contract: Optional[Contract] = None
    proxy_session: Optional[Velvet] = None


class UpgradeabilityReport:
    """Checklist report: per-check status lines plus finding accounting."""

    def __init__(self, context: ReviewContext) -> None:
        self.context = context
        # check key -> findings, per reviewed-scope bucket
        self.v1_findings: dict[str, list[CheckFinding]] = {}
        self.v2_findings: dict[str, list[CheckFinding]] = {}
        self.layout_findings: dict[str, list[CheckFinding]] = {}
        self.proxy_findings: dict[str, list[CheckFinding]] = {}

    # ------------------------------------------------------------ recording
    @staticmethod
    def _bucket_for(group: str) -> str:
        if group == GROUP_INIT:
            return "v1"
        if group == GROUP_INIT_V2:
            return "v2"
        if group in (GROUP_FUNCTION_IDS, GROUP_PROXY_VARS):
            return "proxy"
        return "layout"

    def add(self, finding: CheckFinding) -> None:
        bucket = self._bucket_for(finding.group)
        getattr(self, f"{bucket}_findings").setdefault(
            finding.spec.key, []
        ).append(finding)

    def findings_for(self, bucket: str, key: str) -> list[CheckFinding]:
        return getattr(self, f"{bucket}_findings").get(key, [])

    def all_findings(self) -> list[CheckFinding]:
        result: list[CheckFinding] = []
        ordered = [c.key for c in CHECKS] + [e.key for e in ENHANCEMENTS]
        for bucket in (
            self.v1_findings,
            self.v2_findings,
            self.layout_findings,
            self.proxy_findings,
        ):
            for key in ordered:
                result.extend(bucket.get(key, []))
        return result

    # ------------------------------------------------------------ accounting
    def _count(self, status: str) -> int:
        return sum(1 for f in self.all_findings() if f.status == status)

    @property
    def failures(self) -> int:
        return self._count(FAIL)

    @property
    def warnings(self) -> int:
        return self._count(WARN)

    @property
    def notes(self) -> int:
        return self._count(INFO)

    @property
    def ok(self) -> bool:
        return self.failures == 0


# ---------------------------------------------------------------------------
# model helpers
# ---------------------------------------------------------------------------


def _is_initializer_name(name: str) -> bool:
    """Initialize-family function names (§B.2.3)."""
    return name == "init" or name.startswith("initialize")


def _initialize_functions(contract: Contract) -> list[Function]:
    """All initialize-family functions visible on ``contract``."""
    return [
        f
        for f in contract.available_functions_from_inheritances()
        if not f.is_constructor and f.is_implemented and _is_initializer_name(f.name)
    ]


def _entry_initializers(contract: Contract) -> list[Function]:
    """Externally callable initialize functions (the deployment targets)."""
    return [
        f
        for f in _initialize_functions(contract)
        if f.visibility in ("external", "public")
    ]


def _has_initializer_modifier(function: Function) -> bool:
    """True when ``function`` is guarded by an ``initializer`` modifier."""
    return any(m.name == "initializer" for m in function.modifiers)


def _find_initializable(session: Velvet) -> Optional[Contract]:
    """The codebase's ``Initializable`` helper contract, when present."""
    for unit in session.compilation_units:
        for contract in unit.contracts:
            if contract.name == "Initializable":
                return contract
    return None


def _inherits_initializable(contract: Contract) -> bool:
    if contract.name == "Initializable":
        return True
    return any(base.name == "Initializable" for base in contract.inheritance)


def _modifier_used_anywhere(contract: Contract, name: str) -> bool:
    for function in contract.available_functions_from_inheritances():
        if any(m.name == name for m in function.modifiers):
            return True
    return False


def _init_call_counts(entries: list[Function]) -> dict[str, int]:
    """Call-site count per target (canonical name) reachable from ``entries``.

    Walks internal calls transitively (modifier bodies included) so calls
    hidden behind internal helpers are counted too.
    """
    counts: dict[str, int] = {}
    visited: set[int] = set()
    stack: list[Any] = list(entries)
    while stack:
        current = stack.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        for op in current.all_ir_operations:
            if isinstance(op, InternalCall) and isinstance(
                op.function, (Function, Modifier)
            ):
                target = op.function
                counts[target.canonical_name] = counts.get(target.canonical_name, 0) + 1
                stack.append(target)
    return counts


def _is_gap_variable(var: StateVariable) -> bool:
    """Storage-gap convention: a fixed-size array named ``__gap``."""
    return (
        var.name == "__gap"
        and isinstance(var.type, ArrayType)
        and var.type.length is not None
    )


def _storage_variables(contract: Contract) -> list[StateVariable]:
    """Storage-occupying state variables in layout order (bases first).

    ``constant``/``immutable`` variables occupy no storage slot and are
    excluded (constant-status transitions are reviewed separately by the
    became-constant/were-constant checks). Storage-gap arrays are included;
    the layout comparison treats them by name+type like any variable.
    """
    return [
        var
        for var in contract.state_variables_ordered
        if not var.is_constant and not var.is_immutable
    ]


def _gap_slots(contract: Contract) -> tuple[int, list[StateVariable]]:
    """(total reserved slots, gap variables) of one contract."""
    gaps = [
        var for var in contract.state_variables_ordered if _is_gap_variable(var)
    ]
    total = 0
    for var in gaps:
        assert isinstance(var.type, ArrayType)
        total += int(var.type.length or 0)
    return total, gaps


def _type_str(var: StateVariable) -> str:
    return canonical_type(var.type)


def _destructive_nodes(contract: Contract, kinds: str) -> list[Any]:
    """Nodes running selfdestruct/suicide or delegatecall/callcode."""
    nodes: list[Any] = []
    for function in contract.available_functions_from_inheritances():
        if not function.is_implemented:
            continue
        for node in function.all_nodes:
            for op in node.ir_operations:
                if kinds == "selfdestruct" and (
                    isinstance(op, SolidityCall)
                    and op.function.name in ("selfdestruct", "suicide")
                ):
                    nodes.append(node)
                elif kinds == "delegatecall" and (
                    isinstance(op, LowLevelCall)
                    and op.function_name in ("delegatecall", "callcode")
                ):
                    nodes.append(node)
    return nodes


@dataclass
class _SurfaceItem:
    signature: str
    selector: bytes
    element: Any  # Function, or StateVariable behind an implicit getter


def _function_surface(contract: Contract) -> list[_SurfaceItem]:
    """Externally callable surface: functions + public-variable getters."""
    items: list[_SurfaceItem] = []
    seen: set[str] = set()
    for function in contract.functions_entry_points:
        if function.is_constructor or function.kind in (
            FunctionKind.FALLBACK,
            FunctionKind.RECEIVE,
        ):
            continue
        signature = signature_of(function.name, canonical_params(function))
        if signature in seen:
            continue
        seen.add(signature)
        items.append(
            _SurfaceItem(signature, function_selector(signature), function)
        )
    for getter in public_getters(contract):
        if getter.signature in seen:
            continue
        seen.add(getter.signature)
        items.append(
            _SurfaceItem(
                getter.signature, function_selector(getter.signature), getter.variable
            )
        )
    return items


# ---------------------------------------------------------------------------
# initialization checks (4-6, 9, 14-17 + enhancement observations)
# ---------------------------------------------------------------------------


def run_initialization_checks(
    report: UpgradeabilityReport,
    contract: Contract,
    session: Velvet,
    group: str,
) -> None:
    """Run the initializer-presence/protection checks on one contract."""
    spec = CHECKS_BY_KEY
    enh = ENHANCEMENTS_BY_KEY

    # -- 16 initialize-target (first: it identifies the entry points) -------
    entries = _entry_initializers(contract)
    if entries:
        for function in entries:
            report.add(
                CheckFinding(
                    spec["initialize-target"], INFO,
                    f"call {function.canonical_name} at deployment",
                    [function], group,
                )
            )
    else:
        report.add(
            CheckFinding(
                spec["initialize-target"], INFO,
                f"no initialize function found on {contract.name}",
                [contract], group,
            )
        )

    # -- 5 missing-init-modifier -------------------------------------------
    for function in entries:
        if not _has_initializer_modifier(function):
            report.add(
                CheckFinding(
                    spec["missing-init-modifier"], FAIL,
                    f"{function.canonical_name} lacks the `initializer` "
                    "modifier and can be invoked multiple times "
                    "(re-initialization)",
                    [function], group,
                )
            )

    # -- 4 missing-calls / 6 multiple-calls --------------------------------
    if entries:
        counts = _init_call_counts(entries)
        entry_names = {f.canonical_name for f in entries}
        for function in _initialize_functions(contract):
            if function.canonical_name in entry_names:
                continue
            count = counts.get(function.canonical_name, 0)
            if count == 0:
                report.add(
                    CheckFinding(
                        spec["missing-calls"], FAIL,
                        f"{function.canonical_name} is never called from "
                        + ", ".join(sorted(entry_names)),
                        [function], group,
                    )
                )
            elif count > 1:
                report.add(
                    CheckFinding(
                        spec["multiple-calls"], FAIL,
                        f"{function.canonical_name} is called {count} times "
                        "along the initialization path of "
                        + ", ".join(sorted(entry_names)),
                        [function], group,
                        {"call_count": count},
                    )
                )

    # -- 9 variables-initialized -------------------------------------------
    for var in _storage_variables(contract):
        if var.initialized:
            declarer = var.contract.name if var.contract else contract.name
            report.add(
                CheckFinding(
                    spec["variables-initialized"], FAIL,
                    f"{declarer}.{var.name} is initialized at declaration "
                    "time; the value only exists in the implementation's "
                    "context and is invisible through the proxy — assign it "
                    "in an initialize function instead",
                    [var], group,
                )
            )

    # -- 15 init-missing ----------------------------------------------------
    if _find_initializable(session) is None:
        report.add(
            CheckFinding(
                spec["init-missing"], INFO,
                "no Initializable contract is present in the codebase",
                [contract], group,
            )
        )

    # -- 14 init-inherited ---------------------------------------------------
    if not _inherits_initializable(contract):
        report.add(
            CheckFinding(
                spec["init-inherited"], INFO,
                f"{contract.name} does not inherit an Initializable helper",
                [contract], group,
            )
        )

    # -- 17 initializer-missing ---------------------------------------------
    if not _modifier_used_anywhere(contract, "initializer"):
        report.add(
            CheckFinding(
                spec["initializer-missing"], INFO,
                "the `initializer` modifier is not used anywhere in "
                f"{contract.name}",
                [contract], group,
            )
        )

    # -- enhancement: storage-gap reservations --------------------------------
    _, gaps = _gap_slots(contract)
    for var in gaps:
        assert isinstance(var.type, ArrayType)
        declarer = var.contract.name if var.contract else contract.name
        report.add(
            CheckFinding(
                enh["gap-reserved"], INFO,
                f"{declarer}.__gap reserves {var.type.length} storage "
                "slots for future variables",
                [var], group,
            )
        )

    # -- enhancement: selfdestruct / delegatecall -----------------------------
    for node in _destructive_nodes(contract, "selfdestruct"):
        function = node.function
        report.add(
            CheckFinding(
                enh["no-selfdestruct"], WARN,
                "selfdestruct is reachable in "
                f"{getattr(function, 'canonical_name', '?')}; destroying "
                "the implementation contract bricks every proxy pointing "
                "to it",
                [node], group,
            )
        )
    for node in _destructive_nodes(contract, "delegatecall"):
        function = node.function
        report.add(
            CheckFinding(
                enh["no-delegatecall"], WARN,
                "delegatecall is used in "
                f"{getattr(function, 'canonical_name', '?')}; a tainted "
                "destination executes foreign code against the proxy's "
                "storage",
                [node], group,
            )
        )


# ---------------------------------------------------------------------------
# storage-layout checks (1, 7, 10, 12, 13 + gap-consistency enhancement)
# ---------------------------------------------------------------------------


def _layout_sequence(contract: Contract) -> list[StateVariable]:
    """Storage variables compared positionally between V1 and V2.

    Storage-gap arrays are excluded here: resizing a gap while appending
    variables keeps the layout stable, and gap hygiene is reviewed by the
    dedicated gap-consistency enhancement (§B.2.3).
    """
    return [v for v in _storage_variables(contract) if not _is_gap_variable(v)]


def _by_name(variables: list[StateVariable]) -> dict[str, StateVariable]:
    """Name -> variable map (later declarers win on shadowed duplicates)."""
    result: dict[str, StateVariable] = {}
    for var in variables:
        result[var.name] = var
    return result


def run_layout_checks(
    report: UpgradeabilityReport, v1: Contract, v2: Contract
) -> None:
    """Compare the storage layouts of implementation V1 and upgrade V2."""
    spec = CHECKS_BY_KEY
    group = GROUP_IMPL_VARS

    v1_vars = _layout_sequence(v1)
    v2_vars = _layout_sequence(v2)
    # All non-gap variables (incl. constants) by name, for constant-status
    # transitions and name-presence comparisons.
    v1_all = _by_name(
        [v for v in v1.state_variables_ordered if not _is_gap_variable(v)]
    )
    v2_all = _by_name(
        [v for v in v2.state_variables_ordered if not _is_gap_variable(v)]
    )

    # -- 7 order-vars-contracts (positional, first divergence) --------------
    for position, (old, new) in enumerate(zip(v1_vars, v2_vars)):
        if old.name != new.name or _type_str(old) != _type_str(new):
            report.add(
                CheckFinding(
                    spec["order-vars-contracts"], FAIL,
                    f"{v2.name} storage layout diverges from {v1.name} at "
                    f"position {position}: V1 `{old.name}: {_type_str(old)}` "
                    f"vs V2 `{new.name}: {_type_str(new)}` — variables are "
                    "matched by position, not by name",
                    [new, old], group,
                    {
                        "position": position,
                        "v1_variable": f"{old.name}: {_type_str(old)}",
                        "v2_variable": f"{new.name}: {_type_str(new)}",
                    },
                )
            )
            break

    # -- 1 became-constant / 10 were-constant ---------------------------------
    for name, old in v1_all.items():
        new = v2_all.get(name)
        if new is None:
            continue
        if not old.is_constant and new.is_constant:
            report.add(
                CheckFinding(
                    spec["became-constant"], FAIL,
                    f"{name} was a state variable in {v1.name} and became "
                    f"constant in {v2.name} — removes a storage slot and "
                    "shifts the layout of every later variable",
                    [new, old], group,
                )
            )
        elif old.is_constant and not new.is_constant:
            report.add(
                CheckFinding(
                    spec["were-constant"], FAIL,
                    f"{name} was constant in {v1.name} and became a state "
                    f"variable in {v2.name} — inserts a storage slot and "
                    "shifts the layout of every later variable",
                    [new, old], group,
                )
            )

    # -- 12 missing-variables -------------------------------------------------
    for var in v1_vars:
        if var.name not in v2_all:
            report.add(
                CheckFinding(
                    spec["missing-variables"], WARN,
                    f"V1 variable `{var.name}: {_type_str(var)}` is missing "
                    f"in {v2.name} — a still-later V3 adding a variable at "
                    "that position would read stale values",
                    [var], group,
                )
            )

    # -- 13 extra-vars-v2 -------------------------------------------------------
    for var in v2_vars:
        if var.name not in v1_all:
            report.add(
                CheckFinding(
                    spec["extra-vars-v2"], INFO,
                    f"{v2.name} adds new variable `{var.name}: "
                    f"{_type_str(var)}` — must only ever be appended after "
                    "all V1 variables",
                    [var], group,
                )
            )

    # -- enhancement: gap-consistency -------------------------------------------
    v1_gap, _ = _gap_slots(v1)
    v2_gap, _ = _gap_slots(v2)
    appended = len(v2_vars) - len(v1_vars)
    enh = ENHANCEMENTS_BY_KEY["gap-consistency"]
    if v1_gap or v2_gap:
        if appended > 0 and v2_gap != v1_gap - appended:
            report.add(
                CheckFinding(
                    enh, WARN,
                    f"{v2.name} appends {appended} variable(s) but its "
                    f"storage gap reserves {v2_gap} slots (V1 reserved "
                    f"{v1_gap}); shrink the gap by the number of added "
                    "variables so the layout stays stable",
                    [v2], group,
                    {
                        "v1_gap_slots": v1_gap,
                        "v2_gap_slots": v2_gap,
                        "appended_variables": appended,
                    },
                )
            )
        else:
            report.add(
                CheckFinding(
                    enh, INFO,
                    f"storage gap reserves {v1_gap} slots in {v1.name} and "
                    f"{v2_gap} in {v2.name}, consistent with {appended} "
                    "appended variable(s)",
                    [v2], group,
                    {
                        "v1_gap_slots": v1_gap,
                        "v2_gap_slots": v2_gap,
                        "appended_variables": appended,
                    },
                )
            )


# ---------------------------------------------------------------------------
# proxy checks (2, 3, 8, 11)
# ---------------------------------------------------------------------------


def run_proxy_checks(
    report: UpgradeabilityReport, proxy: Contract, implementation: Contract
) -> None:
    """Review the proxy against the implementation it forwards to."""
    spec = CHECKS_BY_KEY

    proxy_surface = _function_surface(proxy)
    impl_surface = _function_surface(implementation)
    impl_by_signature = {item.signature: item for item in impl_surface}
    impl_by_selector: dict[bytes, list[_SurfaceItem]] = {}
    for item in impl_surface:
        impl_by_selector.setdefault(item.selector, []).append(item)

    # -- 3 function-shadowing ---------------------------------------------------
    for item in proxy_surface:
        twin = impl_by_signature.get(item.signature)
        if twin is not None:
            report.add(
                CheckFinding(
                    spec["function-shadowing"], FAIL,
                    f"{proxy.name}.{item.signature} has the same "
                    "name/signature as "
                    f"{implementation.name}.{twin.signature} — calls never "
                    "reach the logic contract and cannot be upgraded",
                    [item.element, twin.element], GROUP_FUNCTION_IDS,
                )
            )

    # -- 2 function-id-collision --------------------------------------------------
    for item in proxy_surface:
        for twin in impl_by_selector.get(item.selector, []):
            if twin.signature != item.signature:
                report.add(
                    CheckFinding(
                        spec["function-id-collision"], FAIL,
                        f"{proxy.name}.{item.signature} selector "
                        f"0x{item.selector.hex()} collides with "
                        f"{implementation.name}.{twin.signature} — the "
                        "proxy function shadows the implementation function",
                        [item.element, twin.element], GROUP_FUNCTION_IDS,
                        {"selector": f"0x{item.selector.hex()}"},
                    )
                )

    # -- 8 order-vars-proxy ---------------------------------------------------------
    proxy_vars = _storage_variables(proxy)
    impl_vars = _storage_variables(implementation)
    impl_by_name = _by_name(impl_vars)
    shared = [v for v in proxy_vars if v.name in impl_by_name]
    for var in shared:
        twin = impl_by_name[var.name]
        if _type_str(var) != _type_str(twin):
            report.add(
                CheckFinding(
                    spec["order-vars-proxy"], FAIL,
                    f"shared variable `{var.name}` has type "
                    f"`{_type_str(var)}` in {proxy.name} but "
                    f"`{_type_str(twin)}` in {implementation.name}",
                    [var, twin], GROUP_PROXY_VARS,
                )
            )
    proxy_order = [v.name for v in shared]
    shared_names = {v.name for v in shared}
    impl_order = [v.name for v in impl_vars if v.name in shared_names]
    if proxy_order != impl_order:
        report.add(
            CheckFinding(
                spec["order-vars-proxy"], FAIL,
                "shared variables appear in a different relative order in "
                f"{proxy.name} ({', '.join(proxy_order)}) and "
                f"{implementation.name} ({', '.join(impl_order)}) — proxy "
                "and implementation layouts must agree",
                [proxy, implementation], GROUP_PROXY_VARS,
                {"proxy_order": proxy_order, "implementation_order": impl_order},
            )
        )

    # -- 11 extra-vars-proxy -----------------------------------------------------------
    impl_name_set = {v.name for v in impl_vars}
    for var in proxy_vars:
        if var.name not in impl_name_set:
            report.add(
                CheckFinding(
                    spec["extra-vars-proxy"], WARN,
                    f"{proxy.name}.{var.name} exists in the proxy but not "
                    f"in {implementation.name} — a later implementation "
                    "upgrade may corrupt the proxy's storage",
                    [var], GROUP_PROXY_VARS,
                )
            )


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------


def _annotate_v2_destructive(
    report: UpgradeabilityReport, context: ReviewContext
) -> None:
    """Tag destructive patterns newly introduced (or removed) by V2."""
    assert context.v2_contract is not None
    v1, v2 = context.contract, context.v2_contract
    for kind, key in (
        ("selfdestruct", "no-selfdestruct"),
        ("delegatecall", "no-delegatecall"),
    ):
        v1_nodes = _destructive_nodes(v1, kind)
        v2_nodes = _destructive_nodes(v2, kind)
        if not v1_nodes and v2_nodes:
            for finding in report.findings_for("v2", key):
                finding.message += (
                    " — newly introduced in V2: the upgrade becomes "
                    "upgradeable-incompatible"
                )
        elif v1_nodes and not v2_nodes:
            report.add(
                CheckFinding(
                    ENHANCEMENTS_BY_KEY[key], INFO,
                    f"{v2.name} no longer contains {kind}; the upgrade "
                    "restores upgradeability",
                    [v2], GROUP_INIT_V2,
                )
            )


def review(context: ReviewContext) -> UpgradeabilityReport:
    """Run every applicable check and build the checklist report."""
    report = UpgradeabilityReport(context)
    run_initialization_checks(report, context.contract, context.session, GROUP_INIT)
    if context.v2_contract is not None:
        run_initialization_checks(
            report,
            context.v2_contract,
            context.v2_session or context.session,
            GROUP_INIT_V2,
        )
        run_layout_checks(report, context.contract, context.v2_contract)
        _annotate_v2_destructive(report, context)
    if context.proxy_contract is not None:
        run_proxy_checks(report, context.proxy_contract, context.contract)
    return report


# ---------------------------------------------------------------------------
# console rendering
# ---------------------------------------------------------------------------

_STATUS_RANK = {INFO: 1, WARN: 2, FAIL: 3}


def _worst_status(findings: list[CheckFinding]) -> str:
    return max((f.status for f in findings), key=lambda s: _STATUS_RANK[s])


def _refs(finding: CheckFinding) -> str:
    refs = [render_source_ref(e) for e in finding.elements]
    refs = [r for r in refs if r]
    return f" ({'; '.join(refs[:2])})" if refs else ""


def _render_spec(
    lines: list[str], report: UpgradeabilityReport, bucket: str, spec: CheckSpec
) -> None:
    findings = report.findings_for(bucket, spec.key)
    if not findings:
        lines.append(f"[PASS] {spec.key} — {spec.pass_text or spec.title}")
        return
    status = _worst_status(findings)
    lines.append(f"[{status}] {spec.key} ({spec.impact}) — {spec.title}")
    for finding in findings:
        lines.append(f"    - {finding.message}{_refs(finding)}")


def _render_skip(lines: list[str], specs: list[CheckSpec], requirement: str) -> None:
    for spec in specs:
        lines.append(f"[SKIP] {spec.key} — requires {requirement}")


def render(report: UpgradeabilityReport) -> str:
    """Render the checklist-style console report."""
    context = report.context
    contract = context.contract
    v2 = context.v2_contract
    proxy = context.proxy_contract

    init_checks = [c for c in CHECKS if c.group == GROUP_INIT]
    layout_checks = [c for c in CHECKS if c.group == GROUP_IMPL_VARS]
    id_checks = [c for c in CHECKS if c.group == GROUP_FUNCTION_IDS]
    proxy_checks = [c for c in CHECKS if c.group == GROUP_PROXY_VARS]
    observations = [e for e in ENHANCEMENTS if e.group == GROUP_INIT]

    header = f"# Check upgradeability: {contract.name}"
    if v2 is not None:
        header += f" -> {v2.name}"
    lines = [header, ""]

    lines.append(f"## Initialization checks — {contract.name}")
    for spec in init_checks:
        _render_spec(lines, report, "v1", spec)
    lines.append(
        f"## Convention observations — {contract.name} (velvet enhancements)"
    )
    for spec in observations:
        _render_spec(lines, report, "v1", spec)
    lines.append("")

    if v2 is not None:
        lines.append(f"## Initialization checks — {v2.name} (V2)")
        for spec in init_checks:
            _render_spec(lines, report, "v2", spec)
        lines.append(
            f"## Convention observations — {v2.name} (velvet enhancements)"
        )
        for spec in observations:
            _render_spec(lines, report, "v2", spec)
        lines.append("")
        lines.append(f"## Storage layout — {contract.name} -> {v2.name}")
        for spec in layout_checks:
            _render_spec(lines, report, "layout", spec)
        _render_spec(lines, report, "layout", ENHANCEMENTS_BY_KEY["gap-consistency"])
    else:
        lines.append("## Storage layout — V1 vs V2")
        _render_skip(lines, layout_checks, "NEW_CONTRACT (V2 comparison)")
    lines.append("")

    if proxy is not None:
        lines.append(f"## Proxy review — {proxy.name} vs {contract.name}")
        for spec in id_checks + proxy_checks:
            _render_spec(lines, report, "proxy", spec)
    else:
        lines.append("## Proxy review")
        _render_skip(lines, id_checks + proxy_checks, "--proxy-name")
    lines.append("")

    lines.append(
        f"## Summary: {report.failures} failure(s), {report.warnings} "
        f"warning(s), {report.notes} informational note(s)"
    )
    lines.append(f"RESULT: {'PASS' if report.ok else 'FAIL'}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON output (spec/printers-and-tools.md §C.4.2)
# ---------------------------------------------------------------------------


def build_json_document(report: UpgradeabilityReport) -> dict[str, Any]:
    """Assemble the ``upgradeability-check`` JSON envelope."""
    context = report.context
    requested = {GROUP_INIT}
    if context.v2_contract is not None:
        requested.update((GROUP_INIT_V2, GROUP_IMPL_VARS))
    if context.proxy_contract is not None:
        requested.update((GROUP_FUNCTION_IDS, GROUP_PROXY_VARS))
    sub_reports: dict[str, Any] = {}
    for key in SUB_REPORTS:
        if key not in requested:
            # documented: empty objects when the comparison was not requested
            sub_reports[key] = {}
        else:
            sub_reports[key] = [
                finding.to_dict()
                for finding in report.all_findings()
                if finding.group == key
            ]
    return {
        "success": True,
        "error": None,
        "results": {"upgradeability-check": sub_reports},
    }


def _emit_json(document: dict[str, Any], target: str) -> None:
    text = json.dumps(document, indent=2) + "\n"
    if target == "-":
        print(text, end="")
    else:
        Path(target).write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="velvet-check-upgradeability",
        description=(
            "Review a delegatecall-proxy upgradeable contract: initializer "
            "protection, storage-layout compatibility with a planned "
            "upgrade, and proxy surface collisions."
        ),
    )
    parser.add_argument("target", help=".sol file, project directory or standard-JSON")
    parser.add_argument("contract", help="implementation contract to review (V1)")
    parser.add_argument(
        "new_contract",
        nargs="?",
        default=None,
        help="planned upgrade (V2) to compare the storage layout against",
    )
    parser.add_argument(
        "--new-contract-filename",
        default=None,
        metavar="TARGET2",
        help="target containing NEW_CONTRACT when it lives in another codebase",
    )
    parser.add_argument(
        "--proxy-name",
        default=None,
        metavar="PROXY",
        help="also review the proxy contract against the implementation",
    )
    parser.add_argument(
        "--proxy-filename",
        default=None,
        metavar="TARGET3",
        help="target containing the proxy when it lives in another codebase",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        default=None,
        help="write the upgradeability-check JSON document (use - for stdout)",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.new_contract_filename and not args.new_contract:
            raise VelvetError("--new-contract-filename requires NEW_CONTRACT")
        if args.proxy_filename and not args.proxy_name:
            raise VelvetError("--proxy-filename requires --proxy-name")
        session = build_session(args.target)
        contract = find_contract(session, args.contract)
        v2_session: Optional[Velvet] = None
        v2_contract: Optional[Contract] = None
        if args.new_contract:
            v2_session = (
                build_session(args.new_contract_filename)
                if args.new_contract_filename
                else session
            )
            v2_contract = find_contract(v2_session, args.new_contract)
        proxy_session: Optional[Velvet] = None
        proxy_contract: Optional[Contract] = None
        if args.proxy_name:
            proxy_session = (
                build_session(args.proxy_filename)
                if args.proxy_filename
                else session
            )
            proxy_contract = find_contract(proxy_session, args.proxy_name)
        context = ReviewContext(
            session=session,
            contract=contract,
            v2_contract=v2_contract,
            v2_session=v2_session,
            proxy_contract=proxy_contract,
            proxy_session=proxy_session,
        )
    except VelvetError as exc:
        if args.json:
            _emit_json(
                {
                    "success": False,
                    "error": str(exc),
                    "results": {
                        "upgradeability-check": {key: {} for key in SUB_REPORTS}
                    },
                },
                args.json,
            )
        else:
            print(f"velvet-check-upgradeability: {exc}", file=sys.stderr)
        return 2

    report = review(context)
    if args.json:
        _emit_json(build_json_document(report), args.json)
    if args.json != "-":
        print(render(report))
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
