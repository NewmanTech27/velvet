"""velvet.analyses — framework-level analyses shared by all detectors.

Original clean-room implementation (spec/architecture.md §7).
"""

from velvet.analyses.dependency import TAINTED_BUILTINS, is_dependent, is_tainted
from velvet.analyses.protected import is_protected
from velvet.analyses.reachability import (
    entry_points_reaching,
    internal_calls_reachable,
    is_reachable_from,
)
from velvet.analyses.read_write import (
    ReadWriteSets,
    deep_state_variables,
    expand_read_variables,
    function_read_write,
    node_read_write,
)

__all__ = [
    "ReadWriteSets",
    "node_read_write",
    "function_read_write",
    "deep_state_variables",
    "expand_read_variables",
    "is_protected",
    "is_dependent",
    "is_tainted",
    "TAINTED_BUILTINS",
    "is_reachable_from",
    "entry_points_reaching",
    "internal_calls_reachable",
]
