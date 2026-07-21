"""``human-summary`` printer — executive overview of the analysis.

Spec: spec/printers-and-tools.md §A.2.  Prints a global detector tally
(findings per severity), codebase counts, and one block per contract with
complexity stats and ERC20 token-trait heuristics.

Original clean-room implementation.
"""

from __future__ import annotations

from typing import Any

from velvet.detectors.base import Impact
from velvet.printers.base import Printer

# Heuristic thresholds for the "Complex code?" assessment: a contract is
# flagged when it is large (many functions), deeply branched (a function with
# high cyclomatic complexity), or heavy overall (total complexity).
_COMPLEX_MAX_FUNCTIONS = 10
_COMPLEX_MAX_FUNCTION_CC = 7
_COMPLEX_MAX_TOTAL_CC = 20


def _is_complex(contract: Any) -> bool:
    functions = [f for f in contract.functions_and_modifiers if f.is_implemented]
    if len(functions) > _COMPLEX_MAX_FUNCTIONS:
        return True
    complexities = [f.cyclomatic_complexity for f in functions]
    if any(cc > _COMPLEX_MAX_FUNCTION_CC for cc in complexities):
        return True
    return sum(complexities) > _COMPLEX_MAX_TOTAL_CC


def _can_be_paused(contract: Any) -> bool:
    """Token-trait heuristic: the contract surface mentions pausing."""
    names = [f.name.lower() for f in contract.functions]
    names += [m.name.lower() for m in contract.all_modifiers()]
    names += [v.name.lower() for v in contract.state_variables_ordered]
    names += [b.name.lower() for b in contract.inheritance]
    return any("paus" in name for name in names)


def _minting_restriction(contract: Any) -> str:
    """Token-trait heuristic: mint functions and their protection posture."""
    mints = [f for f in contract.functions if "mint" in f.name.lower()]
    if not mints:
        return "No minting"
    if all(f.is_protected for f in mints):
        return "Restricted (protected)"
    return "Unrestricted minting"


def _erc20_race_mitigated(contract: Any) -> bool:
    """Token-trait heuristic: approve() front-running mitigation present.

    Either the contract exposes increase/decrease-allowance helpers, or its
    ``approve`` requires the previous allowance to be zero before setting a
    new (non-zero) one.
    """
    names = {f.name for f in contract.functions}
    if {"increaseAllowance", "decreaseAllowance"} <= names:
        return True
    approve = contract.get_function_from_signature("approve(address,uint256)")
    if approve is None:
        return False
    for expression in approve.all_expressions:
        text = str(expression)
        if "allowance" in text and "0" in text and "require" in text:
            return True
    return False


class HumanSummaryPrinter(Printer):
    RULE = "human-summary"
    TITLE = "Human-readable project summary: issue counts + per-contract traits"

    # ------------------------------------------------------------ sections
    def _detector_tally(self) -> None:
        try:
            findings = self.session.run_detectors()
        except Exception:  # noqa: BLE001 - printers must stay read-only/robust
            self.info("Detectors' results: unavailable")
            return
        counts = {impact: 0 for impact in Impact}
        for finding in findings:
            counts[finding.impact] = counts.get(finding.impact, 0) + 1
        self.info("Detectors' results (number of findings):")
        for impact in (
            Impact.HIGH,
            Impact.MEDIUM,
            Impact.LOW,
            Impact.INFORMATIONAL,
            Impact.OPTIMIZATION,
        ):
            self.info(f"  {impact.value}: {counts.get(impact, 0)}")

    def _contract_block(self, contract: Any) -> None:
        functions = [f for f in contract.functions_and_modifiers if f.is_implemented]
        total_cc = sum(f.cyclomatic_complexity for f in functions)
        self.info(f"+ Contract {contract.name}")
        self.info(f"  Number of functions: {len(contract.functions)}")
        self.info(f"  Cyclomatic complexity (total): {total_cc}")
        self.info(f"  Complex code? {'Yes' if _is_complex(contract) else 'No'}")
        is_erc20 = contract.is_erc20()
        self.info(f"  Is ERC20 token: {is_erc20}")
        if is_erc20:
            self.info(f"  Can be paused: {_can_be_paused(contract)}")
            self.info(f"  Minting restriction: {_minting_restriction(contract)}")
            self.info(f"  ERC20 race condition mitigation: {_erc20_race_mitigated(contract)}")

    # --------------------------------------------------------------- output
    def output(self) -> None:
        unit = self.compilation_unit
        # The detector tally is session-global: print it only once even when
        # the session carries several compilation units.
        first_unit = self.session.compilation_units[0] if self.session.compilation_units else None
        if unit is first_unit:
            self._detector_tally()
        functions = list(unit.functions_and_modifiers)
        self.info(f"Number of contracts: {len(unit.contracts)}")
        self.info(f"Number of functions: {len(functions)}")
        self.info(f"Number of state variables: {len(unit.state_variables)}")
        for contract in unit.contracts:
            self._contract_block(contract)
