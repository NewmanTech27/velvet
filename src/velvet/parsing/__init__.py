"""velvet.parsing — AST normalization, declaration/expression parsing, CFG.

Public entry point: :func:`parse_artifacts`.
"""

from velvet.parsing.ast_norm import attach_source, normalize_ast, parse_src
from velvet.parsing.parser import parse_artifacts

__all__ = ["parse_artifacts", "normalize_ast", "parse_src", "attach_source"]
