"""Solidity pragma parsing and solc version selection.

Original clean-room implementation.
"""

from __future__ import annotations

import re
from functools import lru_cache

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from velvet.exceptions import CompilationError

_PRAGMA_RE = re.compile(
    r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE
)
_TOKEN_RE = re.compile(r"(>=|<=|\^|~|=|>|<)?\s*(\d+(?:\.\d+){0,2})")


def parse_pragma(source: str) -> SpecifierSet:
    """Extract the solidity pragma from source text as a packaging SpecifierSet.

    Handles `^0.8.0`, `>=0.6.0 <0.9.0`, `=0.8.24`, bare versions.
    Empty source/pragma -> unconstrained.
    """
    match = _PRAGMA_RE.search(source)
    if not match:
        return SpecifierSet("")
    expr = match.group(1).strip()
    parts: list[str] = []
    for token in re.split(r"\s*\|\|\s*", expr):
        # OR ranges: take the first range (good enough for version picking)
        sub: list[str] = []
        for op, ver in _TOKEN_RE.findall(token):
            if ver.count(".") == 0:
                ver = f"{ver}.0.0"
            elif ver.count(".") == 1:
                ver = f"{ver}.0"
            if op == "^":
                major, minor, _patch = (int(x) for x in ver.split("."))
                upper = f"{major + 1}.0.0" if major > 0 else f"0.{minor + 1}.0"
                sub.append(f">={ver},<{upper}")
            elif op == "~":
                major, minor, _patch = (int(x) for x in ver.split("."))
                sub.append(f">={ver},<{major}.{minor + 1}.0")
            elif op in (">", ">=", "<", "<="):
                sub.append(f"{op}{ver}")
            elif op == "=":
                sub.append(f"=={ver}")
            else:
                sub.append(f"=={ver}")
        if sub:
            parts.append(",".join(sub))
            break
    return SpecifierSet(",".join(parts))


def combined_specifier(sources: list[str]) -> SpecifierSet:
    """Intersect the pragmas of several sources."""
    combined = SpecifierSet("")
    for src in sources:
        combined &= parse_pragma(src)
    return combined


@lru_cache(maxsize=1)
def available_versions() -> tuple[str, ...]:
    """Installed + remotely installable solc versions (via py-solc-x)."""
    import solcx

    installed = {str(v) for v in solcx.get_installed_solc_versions()}
    try:
        installable = {str(v) for v in solcx.get_installable_solc_versions()}
    except Exception:
        installable = set()
    return tuple(sorted(installed | installable, key=Version))


def select_version(sources: list[str], preferred: str | None = None) -> str:
    """Pick the newest solc version compatible with the combined pragma.

    Installs it on demand via solcx. Raises CompilationError if nothing fits.
    """
    import solcx

    if preferred:
        version = preferred
    else:
        spec = combined_specifier(sources)
        candidates = [v for v in available_versions() if Version(v) in spec]
        if not candidates:
            raise CompilationError(
                f"No available solc version satisfies pragma {spec!s}"
            )
        version = candidates[-1]

    installed = {str(v) for v in solcx.get_installed_solc_versions()}
    if version not in installed:
        solcx.install_solc(version)
    return version
