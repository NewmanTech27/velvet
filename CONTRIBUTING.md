# Contributing to Velvet

Thanks for helping make Velvet better!

## Ground rules

1. **Clean-room integrity is non-negotiable.** Velvet is an original work
   re-implemented from public documentation. Do **not** read, copy, adapt, or
   paraphrase the source code of AGPL-licensed analysis tools (including
   Slither or crytic-compile) when contributing. Base contributions on:
   - the specifications in `spec/`,
   - public documentation and standards (EIPs, SWC registry, Solidity docs),
   - your own expertise.
   Every PR must affirm this in its description.
2. All contributions are licensed under Apache-2.0.

## Development setup

```bash
git clone <repo> && cd velvet
pip install -e ".[dev]"
python3 -m pytest -q
```

## Adding a detector

1. Read `spec/architecture.md` §8 and `spec/api-surface.md` §5.
2. Create `src/velvet/detectors/<rule_id>.py` with `RULE`, `TITLE`, `IMPACT`,
   `CONFIDENCE`, and a complete `DOCS` block, plus `analyze()`.
3. Register it in `src/velvet/detectors/__init__.py`.
4. Add original fixtures under `fixtures/detectors/<rule-id>/`
   (a vulnerable contract and a safe contract).
5. Add tests in `tests/detectors/` — at minimum one positive and one negative
   case. Keep the whole suite green.

## Adding a printer

Same pattern in `src/velvet/printers/`; see `spec/architecture.md` §9.

## Code standards

- Python ≥ 3.10, type hints on public APIs, docstrings on public modules.
- Deterministic output: no dict-order or time dependence in serialized results.
- Prefer using the framework's IR/analyses over re-walking the AST.
