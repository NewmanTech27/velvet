#!/usr/bin/env python3
"""Benchmark comparison harness — velvet vs a reference JSON report.

Usage:
    python3 scripts/compare_benchmark.py TARGET --reference slither-report.json \
        [--velvet-json out.json] [--reference-name slither]

Runs velvet on TARGET (or reuses --velvet-json), loads the reference tool's
JSON report, and prints a per-rule comparison table. Informational (exit 0).
"""

from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def load_counts(path):
    doc = json.loads(Path(path).read_text())
    findings = doc.get("results", {}).get("detectors", [])
    counts = collections.Counter(f["check"] for f in findings)
    return counts, len(findings)


def run_velvet(target):
    out = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, prefix="velvet-bench-")
    out.close()
    cmd = [sys.executable, "-m", "velvet.cli", target, "--json", out.name, "--fail-on", "none"]
    subprocess.run(cmd, check=False, capture_output=True, timeout=1800)
    return out.name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--reference", required=True)
    parser.add_argument("--velvet-json")
    parser.add_argument("--reference-name", default="reference")
    args = parser.parse_args()

    velvet_json = args.velvet_json or run_velvet(args.target)
    ref_counts, ref_total = load_counts(args.reference)
    vel_counts, vel_total = load_counts(velvet_json)

    rules = sorted(set(ref_counts) | set(vel_counts))
    width = max([len(r) for r in rules] + [10])
    header = f"{'rule':{width}s} {args.reference_name:>12s} {'velvet':>8s} {'delta':>6s}"
    print(header)
    print("-" * len(header))
    matched = close = 0
    for rule in rules:
        r, v = ref_counts.get(rule, 0), vel_counts.get(rule, 0)
        delta = v - r
        mark = "==" if r == v else ("~" if abs(delta) <= max(2, r // 4) else "!=")
        if r == v:
            matched += 1
        elif mark == "~":
            close += 1
        print(f"{rule:{width}s} {r:>12d} {v:>8d} {delta:>+6d} {mark}")
    print("-" * len(header))
    print(f"{'TOTAL':{width}s} {ref_total:>12d} {vel_total:>8d} {vel_total - ref_total:>+6d}")
    print(f"\nrules exact-match: {matched} | close: {close} | divergent: {len(rules) - matched - close} of {len(rules)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
