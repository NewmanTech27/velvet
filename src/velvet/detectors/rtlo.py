"""`rtlo` detector (spec/detectors-catalog.md §7.4 — normative).

Flags source units whose raw text contains a Unicode bidirectional
directional-override control character — U+202E (RIGHT-TO-LEFT OVERRIDE)
or an equivalent from the U+202A..U+202E / U+2066..U+2069 ranges.  Such
characters reorder displayed text, so a contract can read as harmless while
the compiler sees the opposite order (Trojan-source attacks).

The raw sources are taken from the compilation artifacts; every contract
declared in an affected source unit is reported.  Original clean-room
implementation.
"""

from __future__ import annotations

from velvet.detectors.base import (
    Confidence,
    Detector,
    DetectorDocs,
    Finding,
    Impact,
)

#: Directional-override / isolate controls that reorder displayed source.
BIDI_OVERRIDE_CHARS = {
    "\u202a": "U+202A LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "U+202B RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "U+202C POP DIRECTIONAL FORMATTING",
    "\u202d": "U+202D LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "U+202E RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "U+2066 LEFT-TO-RIGHT ISOLATE",
    "\u2067": "U+2067 RIGHT-TO-LEFT ISOLATE",
    "\u2068": "U+2068 FIRST STRONG ISOLATE",
    "\u2069": "U+2069 POP DIRECTIONAL ISOLATE",
}


class Rtlo(Detector):
    """Detect right-to-left-override control characters in source text."""

    RULE = "rtlo"
    TITLE = "Right-to-left-override control character in source"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki/Detector-Documentation#rtlo",
        title="Right-to-left-override control character in source",
        description=(
            "The source contains a Unicode bidirectional override character "
            "(U+202E or equivalent). Displayed text is reordered, so a "
            "reviewer can read the contract as harmless while the compiler "
            "parses a different, malicious order (trojan-source attack)."
        ),
        exploit_scenario=(
            "A comment hides U+202E so that `/* attacker controlled */` "
            "renders over real code, disguising a backdoor transfer as an "
            "innocent token-name line."
        ),
        recommendation=(
            "Remove bidirectional override characters from the source; "
            "reject files containing U+202A-U+202E or U+2066-U+2069."
        ),
    )

    def analyze(self) -> list[Finding]:
        results: list[Finding] = []
        artifacts = self.compilation_unit.compilation
        for info in artifacts.source_units.values():
            found = sorted(
                {name for char, name in BIDI_OVERRIDE_CHARS.items() if char in info.source}
            )
            if not found:
                continue
            contracts = [
                c
                for c in self.compilation_unit.contracts
                if c.source_mapping is not None
                and c.source_mapping.filename is not None
                and c.source_mapping.filename.absolute == info.filename.absolute
            ]
            if not contracts:
                results.append(
                    self.finding(
                        [
                            f"Source unit {info.filename.used} contains a "
                            f"bidirectional override character ({'; '.join(found)})",
                        ]
                    )
                )
                continue
            for contract in contracts:
                results.append(
                    self.finding(
                        [
                            contract,
                            " is declared in a source unit containing a "
                            "bidirectional override character (",
                            "; ".join(found),
                            ")",
                        ]
                    )
                )
        return results
