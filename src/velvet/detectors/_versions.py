"""Shared solc-version range helpers for compiler-bug detectors.

Original clean-room implementation.
"""

from __future__ import annotations

from packaging.version import InvalidVersion, Version


def parse_solc_version(version: str) -> Version | None:
    """Parse a compiler version string (``"0.5.8"``); None when unknown."""
    text = (version or "").strip()
    # Tolerate full build strings such as "0.8.24+commit.e11b9ed9".
    text = text.split("+")[0].split("-")[0]
    try:
        return Version(text)
    except InvalidVersion:
        return None


def in_version_range(version: str, floor: str, ceiling: str) -> bool:
    """True when ``version`` falls inside ``[floor, ceiling]`` inclusive."""
    parsed = parse_solc_version(version)
    if parsed is None:
        return False
    return Version(floor) <= parsed <= Version(ceiling)
