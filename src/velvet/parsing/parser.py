"""Parsing orchestrator: compilation artifacts -> populated CompilationUnit.

Pipeline (spec/architecture.md §2 stage 2):

1. normalize ASTs (compact dialect enforced by ``ast_norm``),
2. first pass — declarations for all source units
   (:func:`~velvet.parsing.decl_parser.parse_declarations`),
3. cross-reference resolution — inheritance + C3, modifier invocations,
   using-for targets, override graph, state-variable initializers
   (:func:`~velvet.parsing.decl_parser.resolve_references`),
4. second pass — bodies and CFGs
   (:func:`~velvet.parsing.body_parser.build_bodies`),
5. final type-placeholder sweep
   (:func:`~velvet.parsing.decl_parser.resolve_types`).

Original clean-room implementation.
"""

from __future__ import annotations

from velvet.compile.artifacts import CompilationArtifacts
from velvet.core.compilation_unit import CompilationUnit
from velvet.parsing.body_parser import build_bodies
from velvet.parsing.decl_parser import (
    ParserContext,
    parse_declarations,
    resolve_references,
    resolve_types,
)


def parse_artifacts(
    artifacts: CompilationArtifacts, *, skip_assembly: bool = True
) -> CompilationUnit:
    """Build the full core model (declarations + CFGs) for one compilation.

    ``skip_assembly``: accepted for API compatibility with the session
    layer; v1 always models inline assembly as a single opaque ASSEMBLY
    node (see body_parser).
    """
    ctx = ParserContext(artifacts)
    parse_declarations(ctx)
    resolve_references(ctx)
    build_bodies(ctx, skip_assembly=skip_assembly)
    resolve_types(ctx)
    return ctx.unit
