"""NatSpec doc-comment extraction from raw source text.

The solc AST spans velvet consumes do not include doc comments, so tags such
as ``@custom:security non-reentrant`` (spec/architecture.md §11.3) are
recovered from the source text directly above a declaration's source span.

Association rules (deliberately strict, since a tag can suppress findings):

- the doc comment must end on the line *directly above* the declaration
  (blank lines or code in between break the association);
- line doc comments are consecutive ``///`` lines (``////`` is a plain
  comment, not NatSpec);
- block doc comments open with ``/**`` and close with ``*/``;
- same-line doc comments (``/** tag */ uint256 x;``) are not associated.

Original clean-room implementation.
"""

from __future__ import annotations

import re
from typing import Optional


def docstring_above(source: str, offset: int) -> str:
    """Return the doc comment directly above the declaration at ``offset``.

    ``offset`` is the byte/character offset of the declaration's start in
    ``source`` (as found in ``SourceRange.start``).  Returns the raw comment
    text, or ``""`` when no doc comment is associated with the declaration.
    """
    if not source or offset <= 0 or offset > len(source):
        return ""
    prefix = source[:offset]
    # Drop the declaration's own line fragment (indentation is allowed);
    # the comment must live entirely on lines above it.
    newline = prefix.rfind("\n")
    head = prefix[:newline] if newline >= 0 else ""
    if not head.strip():
        return ""
    lines = head.split("\n")
    last = lines[-1].strip()
    if last.endswith("*/"):
        # Block doc comment: walk upward to its `/**` opener.
        for index in range(len(lines) - 1, -1, -1):
            if "/**" in lines[index]:
                return "\n".join(lines[index:])
            if "*/" in lines[index] and index != len(lines) - 1:
                return ""  # an unrelated comment closes before any opener
        return ""
    if last.startswith("///") and not last.startswith("////"):
        block: list[str] = []
        for line in reversed(lines):
            stripped = line.strip()
            if stripped.startswith("///") and not stripped.startswith("////"):
                block.append(line)
            else:
                break
        block.reverse()
        return "\n".join(block)
    return ""


def _clean_doc_lines(docstring: str) -> list[str]:
    """Strip comment syntax, yielding one logical line per source line."""
    result: list[str] = []
    for raw in docstring.split("\n"):
        line = raw.strip()
        if line.startswith("/**"):
            line = line[3:]
        elif line.startswith("///"):
            line = line[3:]
        elif line.startswith("*"):
            line = line[1:]
        line = line.strip()
        if line.endswith("*/"):
            line = line[:-2].strip()
        result.append(line)
    return result


def find_tag(docstring: str, tag: str) -> Optional[str]:
    """Value of the first ``@tag`` line in the doc comment, if present.

    ``tag`` is given without the leading ``@`` (e.g. ``"custom:security"``).
    The returned value is the stripped remainder of the tag's line (``""``
    for a bare tag).  Returns ``None`` when the tag is absent.
    """
    if not docstring:
        return None
    pattern = re.compile(r"^@" + re.escape(tag) + r"(?:\s+(.*))?$")
    for line in _clean_doc_lines(docstring):
        match = pattern.match(line)
        if match is not None:
            return (match.group(1) or "").strip()
    return None


def has_tag(docstring: str, tag: str, value: Optional[str] = None) -> bool:
    """True when the doc comment carries ``@tag`` (optionally ``@tag value``).

    With ``value`` given, the first whitespace-separated token of the tag's
    value must equal it, so ``@custom:security non-reentrant (rationale)``
    still matches ``value="non-reentrant"``.
    """
    found = find_tag(docstring, tag)
    if found is None:
        return False
    if value is None:
        return True
    tokens = found.split()
    return bool(tokens) and tokens[0] == value
