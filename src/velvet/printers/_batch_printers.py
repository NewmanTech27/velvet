"""v1 printer batch registry (SPEC.md §6).

Exports ``PRINTERS``: the ten v1 printers.  ``velvet.printers.__init__``
flattens this list into ``BUILTIN_PRINTERS``; later printer batches add their
own batch modules alongside this one.

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.printers.call_graph import CallGraphPrinter
from velvet.printers.cfg import CfgPrinter
from velvet.printers.contract_summary import ContractSummaryPrinter
from velvet.printers.entry_points import EntryPointsPrinter
from velvet.printers.function_summary import FunctionSummaryPrinter
from velvet.printers.human_summary import HumanSummaryPrinter
from velvet.printers.inheritance_graph import InheritanceGraphPrinter
from velvet.printers.loc import LocPrinter
from velvet.printers.solir import SolirPrinter
from velvet.printers.solir_ssa import SolirSsaPrinter

PRINTERS = [
    HumanSummaryPrinter,
    ContractSummaryPrinter,
    FunctionSummaryPrinter,
    EntryPointsPrinter,
    LocPrinter,
    InheritanceGraphPrinter,
    CallGraphPrinter,
    CfgPrinter,
    SolirPrinter,
    SolirSsaPrinter,
]

__all__ = [
    "PRINTERS",
    "CallGraphPrinter",
    "CfgPrinter",
    "ContractSummaryPrinter",
    "EntryPointsPrinter",
    "FunctionSummaryPrinter",
    "HumanSummaryPrinter",
    "InheritanceGraphPrinter",
    "LocPrinter",
    "SolirPrinter",
    "SolirSsaPrinter",
]
