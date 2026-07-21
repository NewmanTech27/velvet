"""`missing-zero-check` detector (spec/detectors-catalog.md §2.7 — normative).

Flags functions that store an address-typed parameter into a state variable
(directly or after minimal transformation such as ``payable(p)``) without
validating anywhere in the function that the parameter is not
``address(0)`` — setting ownership/roles/treasury state to zero can brick
the contract or lock funds.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.analyses.read_write import expand_read_variables
from velvet.core.function import FunctionLike
from velvet.core.types import ElementaryType
from velvet.core.variables import Constant, LocalVariable, StateVariable
from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)
from velvet.ir.operations import Binary, Index, Member
from velvet.ir.variables import root_base

_EQUALITY_OPERATORS = ("==", "!=")


def _is_address_typed(variable: LocalVariable) -> bool:
    var_type = variable.type
    return isinstance(var_type, ElementaryType) and str(var_type).startswith("address")


def _is_zero(value: Any) -> bool:
    if not isinstance(value, Constant):
        return False
    try:
        return int(str(value.value), 0) == 0
    except (TypeError, ValueError):
        return False


def _zero_checked(function: FunctionLike, params: list[LocalVariable]) -> set[int]:
    """Ids of parameters compared against address(0) anywhere in the function."""
    checked: set[int] = set()
    for node in function.all_nodes:  # includes applied modifiers
        for op in node.ir_operations:
            if not (isinstance(op, Binary) and op.operator in _EQUALITY_OPERATORS):
                continue
            left = expand_read_variables([op.left], function)
            right = expand_read_variables([op.right], function)
            for param in params:
                if id(param) in checked:
                    continue
                left_is_param = any(v is param for v in left)
                right_is_param = any(v is param for v in right)
                if (left_is_param and any(_is_zero(v) for v in right)) or (
                    right_is_param and any(_is_zero(v) for v in left)
                ):
                    checked.add(id(param))
    return checked


class MissingZeroCheck(Detector):
    """Detect address parameters stored without a zero-address check."""

    RULE = "missing-zero-check"
    TITLE = "Address parameter stored without zero-address validation"
    IMPACT = Impact.LOW
    CONFIDENCE = Confidence.MEDIUM
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#missing-zero-check",
        title="Missing zero-address check",
        description=(
            "An address taken from a function parameter is stored into "
            "state without validating that it is not address(0); setting a "
            "critical variable to zero can brick the contract or lock funds."
        ),
        exploit_scenario=(
            "Ownable.setOwner(newOwner) stores newOwner without checking it; "
            "the owner fat-fingers the call, sets owner to address(0) and "
            "every onlyOwner function becomes permanently unusable."
        ),
        recommendation=(
            "Validate newOwner != address(0) before storing (and consider a "
            "two-step ownership transfer with an accept step)."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        for contract in self.compilation_unit.contracts_derived:
            if contract.is_interface:
                continue
            for function in contract.available_functions_from_inheritances():
                if not function.is_implemented:
                    continue
                if function.is_constructor:
                    # Constructors are entry points like any setter (spec
                    # §2.7): an address parameter stored without a zero
                    # check bricks the contract from deployment.  Analyze
                    # each constructor once — in its declaring contract —
                    # and only when that contract is deployable: an
                    # abstract contract's constructor only ever runs
                    # through a concrete derived one (whose own parameters
                    # are what need validating).
                    if (
                        function.contract_declarer is not contract
                        or contract.is_abstract
                    ):
                        continue
                params = [p for p in function.parameters if _is_address_typed(p)]
                if not params:
                    continue
                checked = _zero_checked(function, params)
                reported: set[tuple[int, int]] = set()
                for node in function.nodes:
                    for op in node.ir_operations:
                        lvalue = op.lvalue
                        if lvalue is None:
                            continue
                        # Index/Member define a reference (their reads are
                        # the base and the index), they do not store a value.
                        if isinstance(op, (Index, Member)):
                            continue
                        root = root_base(lvalue)
                        if not isinstance(root, StateVariable):
                            continue
                        sources = expand_read_variables(op.read, function)
                        for param in params:
                            if id(param) in checked:
                                continue
                            if not any(v is param for v in sources):
                                continue
                            key = (id(param), id(root))
                            if key in reported:
                                continue
                            reported.add(key)
                            results.append(
                                self.finding(
                                    [
                                        node,
                                        " stores ",
                                        param,
                                        " in ",
                                        root,
                                        " without a zero-address check in ",
                                        function,
                                    ]
                                )
                            )
        return results
