"""``velvet-check-erc`` — ERC conformance checker (spec/printers-and-tools.md §B.1).

Verifies that a contract conforms to ERC-20, ERC-721 or ERC-1155. The
requirements of each EIP are transcribed below as data (requirement tables);
the checker evaluates a :class:`~velvet.core.contract.Contract` against them:

- required function presence (exact name + canonical parameter types),
- return types and mutability conformance,
- required event presence and parameter indexing,
- mandated event emission sites (e.g. ``transfer`` emits ``Transfer``),
- inherited members count toward conformance (broken overrides are flagged).

Behavioral MUST-revert conditions of the EIPs (zero-address checks,
balance sufficiency, receiver-hook return values, ...) are not decidable
statically in general and are out of scope, per §B.1.4.

Invocation: ``velvet-check-erc TARGET CONTRACT [--erc 20|721|1155]``.
Exit code: 0 = conformant (warnings allowed), 1 = conformance failure,
2 = usage/compilation error.

Original clean-room implementation.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from typing import Optional

from velvet.core.contract import Contract
from velvet.core.function import Function
from velvet.exceptions import VelvetError
from velvet.tools.common import (
    available_events,
    build_session,
    canonical_returns,
    emitted_event_names,
    find_contract,
    mutability_of,
    resolve_function,
    signature_of,
)

# ---------------------------------------------------------------------------
# requirement tables (transcribed from the EIP-derived tables of §B.1.4)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FunctionRequirement:
    """One required (or optional) function of an ERC."""

    name: str
    params: tuple[str, ...] = ()
    returns: tuple[str, ...] = ()
    #: ``view`` | ``payable`` | ``nonpayable`` — see mutability_ok().
    mutability: str = "nonpayable"
    #: events a successful call MUST emit (checked at emission sites).
    emits: tuple[str, ...] = ()
    optional: bool = False
    note: str = ""

    @property
    def signature(self) -> str:
        return signature_of(self.name, list(self.params))


@dataclass(frozen=True)
class EventRequirement:
    """One required (or optional) event of an ERC."""

    name: str
    params: tuple[str, ...]
    indexed: tuple[bool, ...]
    optional: bool = False

    @property
    def signature(self) -> str:
        return signature_of(self.name, list(self.params))


@dataclass(frozen=True)
class ERCStandard:
    key: str
    title: str
    functions: tuple[FunctionRequirement, ...]
    events: tuple[EventRequirement, ...]


# ----- ERC-20 (EIP-20) ------------------------------------------------------

_ERC20 = ERCStandard(
    key="erc20",
    title="ERC20",
    functions=(
        FunctionRequirement("totalSupply", (), ("uint256",), "view"),
        FunctionRequirement("balanceOf", ("address",), ("uint256",), "view"),
        FunctionRequirement(
            "transfer", ("address", "uint256"), ("bool",), "nonpayable", ("Transfer",)
        ),
        FunctionRequirement(
            "transferFrom",
            ("address", "address", "uint256"),
            ("bool",),
            "nonpayable",
            ("Transfer",),
        ),
        FunctionRequirement(
            "approve", ("address", "uint256"), ("bool",), "nonpayable", ("Approval",)
        ),
        FunctionRequirement(
            "allowance", ("address", "address"), ("uint256",), "view"
        ),
        # EIP-20 OPTIONAL methods
        FunctionRequirement("name", (), ("string",), "view", optional=True),
        FunctionRequirement("symbol", (), ("string",), "view", optional=True),
        FunctionRequirement("decimals", (), ("uint8",), "view", optional=True),
    ),
    events=(
        EventRequirement(
            "Transfer", ("address", "address", "uint256"), (True, True, False)
        ),
        EventRequirement(
            "Approval", ("address", "address", "uint256"), (True, True, False)
        ),
    ),
)

# ----- ERC-721 (EIP-721) ----------------------------------------------------
# Payable-marked functions MAY be implemented non-payable (EIP-721 mutability
# rule); `external` in the EIP MAY be `public` in the implementation.

_ERC721 = ERCStandard(
    key="erc721",
    title="ERC721",
    functions=(
        FunctionRequirement(
            "supportsInterface", ("bytes4",), ("bool",), "view", note="ERC-165"
        ),
        FunctionRequirement("balanceOf", ("address",), ("uint256",), "view"),
        FunctionRequirement("ownerOf", ("uint256",), ("address",), "view"),
        FunctionRequirement(
            "safeTransferFrom",
            ("address", "address", "uint256", "bytes"),
            (),
            "payable",
            ("Transfer",),
        ),
        FunctionRequirement(
            "safeTransferFrom",
            ("address", "address", "uint256"),
            (),
            "payable",
            ("Transfer",),
        ),
        FunctionRequirement(
            "transferFrom",
            ("address", "address", "uint256"),
            (),
            "payable",
            ("Transfer",),
        ),
        FunctionRequirement(
            "approve", ("address", "uint256"), (), "payable", ("Approval",)
        ),
        FunctionRequirement(
            "setApprovalForAll",
            ("address", "bool"),
            (),
            "nonpayable",
            ("ApprovalForAll",),
        ),
        FunctionRequirement("getApproved", ("uint256",), ("address",), "view"),
        FunctionRequirement(
            "isApprovedForAll", ("address", "address"), ("bool",), "view"
        ),
        # ERC721Metadata extension (optional)
        FunctionRequirement("name", (), ("string",), "view", optional=True),
        FunctionRequirement("symbol", (), ("string",), "view", optional=True),
        FunctionRequirement(
            "tokenURI", ("uint256",), ("string",), "view", optional=True
        ),
        # ERC721Enumerable extension (optional)
        FunctionRequirement(
            "totalSupply", (), ("uint256",), "view", optional=True
        ),
        FunctionRequirement(
            "tokenByIndex", ("uint256",), ("uint256",), "view", optional=True
        ),
        FunctionRequirement(
            "tokenOfOwnerByIndex",
            ("address", "uint256"),
            ("uint256",),
            "view",
            optional=True,
        ),
    ),
    events=(
        EventRequirement(
            "Transfer", ("address", "address", "uint256"), (True, True, True)
        ),
        EventRequirement(
            "Approval", ("address", "address", "uint256"), (True, True, True)
        ),
        EventRequirement(
            "ApprovalForAll", ("address", "address", "bool"), (True, True, False)
        ),
    ),
)

# ----- ERC-1155 (EIP-1155) --------------------------------------------------

_ERC1155 = ERCStandard(
    key="erc1155",
    title="ERC1155",
    functions=(
        FunctionRequirement(
            "supportsInterface", ("bytes4",), ("bool",), "view", note="ERC-165"
        ),
        FunctionRequirement(
            "safeTransferFrom",
            ("address", "address", "uint256", "uint256", "bytes"),
            (),
            "nonpayable",
            ("TransferSingle",),
        ),
        FunctionRequirement(
            "safeBatchTransferFrom",
            ("address", "address", "uint256[]", "uint256[]", "bytes"),
            (),
            "nonpayable",
            ("TransferBatch",),
        ),
        FunctionRequirement(
            "balanceOf", ("address", "uint256"), ("uint256",), "view"
        ),
        FunctionRequirement(
            "balanceOfBatch",
            ("address[]", "uint256[]"),
            ("uint256[]",),
            "view",
        ),
        FunctionRequirement(
            "setApprovalForAll",
            ("address", "bool"),
            (),
            "nonpayable",
            ("ApprovalForAll",),
        ),
        FunctionRequirement(
            "isApprovedForAll", ("address", "address"), ("bool",), "view"
        ),
        # ERC1155Metadata_URI extension (optional)
        FunctionRequirement(
            "uri", ("uint256",), ("string",), "view", optional=True
        ),
    ),
    events=(
        EventRequirement(
            "TransferSingle",
            ("address", "address", "address", "uint256", "uint256"),
            (True, True, True, False, False),
        ),
        EventRequirement(
            "TransferBatch",
            ("address", "address", "address", "uint256[]", "uint256[]"),
            (True, True, True, False, False),
        ),
        EventRequirement(
            "ApprovalForAll", ("address", "address", "bool"), (True, True, False)
        ),
        # MUST emit when the URI changes *if* the metadata extension exists.
        EventRequirement("URI", ("string", "uint256"), (False, True), optional=True),
    ),
)

STANDARDS: dict[str, ERCStandard] = {s.key: s for s in (_ERC20, _ERC721, _ERC1155)}


def normalize_standard_key(raw: str) -> str:
    """Normalize ``--erc`` spellings (``20``/``erc20``/``ERC-721`` ...) to a key."""
    digits = "".join(ch for ch in raw if ch.isdigit())
    key = f"erc{digits}" if digits else raw.lower().replace("-", "")
    if key not in STANDARDS:
        supported = ", ".join(s.key for s in STANDARDS.values())
        raise VelvetError(f"unsupported ERC standard {raw!r} (supported: {supported})")
    return key


# ---------------------------------------------------------------------------
# conformance evaluation
# ---------------------------------------------------------------------------

_MUTABILITY_WORDS = {"view": "view", "payable": "payable", "nonpayable": "non-payable"}


def mutability_ok(required: str, actual: str) -> bool:
    """Mutability conformance per §B.1.2(4) and the EIP-721 payable rule.

    A *stronger* mutability than required only violates the standard where it
    breaks the guarantee: ``pure`` satisfies a ``view`` requirement, and
    EIP-721 ``payable`` functions MAY be implemented non-payable. A ``view``
    or ``pure`` implementation of a state-changing function never conforms.
    """
    if required == "view":
        return actual in ("view", "pure")
    if required == "payable":
        return actual in ("payable", "nonpayable")
    return actual in ("nonpayable", "payable")


@dataclass
class ERCReport:
    """Checklist result: display lines plus failure/warning accounting."""

    standard: ERCStandard
    contract_name: str
    lines: list[str] = field(default_factory=list)
    failures: int = 0
    warnings: int = 0

    def _add(self, ok: bool, text: str, *, optional: bool = False, indent: bool = False) -> None:
        mark = "[✓]" if ok else "[ ]"
        pad = "\t" if indent else ""
        self.lines.append(f"{pad}{mark} {text}")
        if not ok:
            if optional:
                self.warnings += 1
            else:
                self.failures += 1

    def passed(self, text: str, *, indent: bool = False) -> None:
        self._add(True, text, indent=indent)

    def failed(self, text: str, *, optional: bool = False, indent: bool = False) -> None:
        self._add(False, text, optional=optional, indent=indent)

    @property
    def ok(self) -> bool:
        return self.failures == 0

    def render(self) -> str:
        summary = (
            f"## Summary: {self.failures} failure(s), {self.warnings} warning(s)\n"
            f"RESULT: {'PASS' if self.ok else 'FAIL'}"
        )
        return "\n".join([*self.lines, "", summary])


def _check_function(
    report: ERCReport, contract: Contract, req: FunctionRequirement
) -> None:
    optional_suffix = " (optional)" if req.optional else ""
    note_suffix = f" [{req.note}]" if req.note else ""
    function = resolve_function(contract, req.name, req.params)
    if function is None:
        report.failed(
            f"{req.signature}{note_suffix} is missing{optional_suffix}",
            optional=req.optional,
        )
        return
    report.passed(f"{req.signature}{note_suffix} is present")

    # return types
    required_returns = list(req.returns)
    actual_returns = canonical_returns(function)
    if actual_returns == required_returns:
        if required_returns:
            report.passed(
                f"{req.signature} returns {','.join(required_returns)}", indent=True
            )
    else:
        report.failed(
            f"{req.signature} -> ({','.join(actual_returns)})"
            f" should return {','.join(required_returns) or 'nothing'}",
            optional=req.optional,
            indent=True,
        )

    # mutability
    actual_mutability = mutability_of(function)
    if not mutability_ok(req.mutability, actual_mutability):
        report.failed(
            f"{req.signature} should be {_MUTABILITY_WORDS[req.mutability]}"
            f" (is {actual_mutability})",
            optional=req.optional,
            indent=True,
        )

    # mandated event emissions (only verifiable on implemented functions;
    # getters are view-only and never match a requirement with emissions)
    if req.emits and function.is_implemented and isinstance(function, Function):
        emitted = emitted_event_names(function)
        events_by_name = {e.name: e for e in available_events(contract)}
        for event_name in req.emits:
            event = events_by_name.get(event_name)
            label = event.signature if event is not None else event_name
            if event_name in emitted:
                report.passed(f"{label} is emitted", indent=True)
            else:
                report.failed(
                    f"{label} is not emitted by {req.signature}",
                    optional=req.optional,
                    indent=True,
                )


def _check_event(report: ERCReport, contract: Contract, req: EventRequirement) -> None:
    optional_suffix = " (optional)" if req.optional else ""
    events = available_events(contract)
    event = next((e for e in events if e.signature == req.signature), None)
    if event is None:
        same_name = next((e for e in events if e.name == req.name), None)
        hint = (
            f" (found {same_name.signature} with different parameters)"
            if same_name is not None
            else ""
        )
        report.failed(
            f"{req.signature} is missing{hint}{optional_suffix}", optional=req.optional
        )
        return
    report.passed(f"{req.signature} is present")
    for index, (param, must_be_indexed) in enumerate(zip(req.params, req.indexed)):
        is_indexed = bool(event.elems[index].indexed) if index < len(event.elems) else False
        if must_be_indexed and is_indexed:
            report.passed(f"parameter {index} is indexed", indent=True)
        elif must_be_indexed and not is_indexed:
            report.failed(
                f"parameter {index} should be indexed",
                optional=req.optional,
                indent=True,
            )
        elif not must_be_indexed and is_indexed:
            report.failed(
                f"parameter {index} should not be indexed",
                optional=req.optional,
                indent=True,
            )
        else:
            report.passed(f"parameter {index} is not indexed", indent=True)


def check_contract(contract: Contract, standard: ERCStandard) -> ERCReport:
    """Evaluate ``contract`` against ``standard`` and return the checklist."""
    report = ERCReport(standard=standard, contract_name=contract.name)
    report.lines.append(f"# Check {standard.title}")
    report.lines.append("")
    report.lines.append("## Check functions")
    for req in standard.functions:
        _check_function(report, contract, req)
    report.lines.append("")
    report.lines.append("## Check events")
    for req in standard.events:
        _check_event(report, contract, req)
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="velvet-check-erc",
        description="Verify that a contract conforms to an ERC token standard.",
    )
    parser.add_argument("target", help=".sol file, project directory or standard-JSON")
    parser.add_argument("contract", help="contract to check (case sensitive)")
    parser.add_argument(
        "--erc",
        default="20",
        metavar="STANDARD",
        help="standard to check against: 20, 721 or 1155 (default: 20)",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        key = normalize_standard_key(args.erc)
        session = build_session(args.target)
        contract = find_contract(session, args.contract)
    except VelvetError as exc:
        print(f"velvet-check-erc: {exc}", file=sys.stderr)
        return 2

    report = check_contract(contract, STANDARDS[key])
    print(report.render())
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
