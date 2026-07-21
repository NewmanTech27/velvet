# Plan — Clean-Room Open-Source Solidity Static Analyzer (Slither-equivalent)

## Goal
Create an original, permissively-licensed (MIT/Apache-2.0) open-source static analysis
library for EVM smart contracts that covers Slither's feature surface:
- Detector engine + full detector catalog (100 detectors)
- Printers (code comprehension reports)
- Auxiliary tools (ERC conformance checks, upgradeability checks, flatten, interface gen)
- Python API + custom detector framework + IR
- CLI, SARIF/CI integration

## Clean-Room Strategy (CRITICAL)
Slither is AGPLv3 — we must NOT copy its code. Process:
1. **Spec team** (research subagents): derive functional specs ONLY from public docs,
   README tables, detector documentation pages, and observable behavior descriptions.
   Output = neutral specification documents (what each detector flags, severity,
   confidence, remediation) — no AGPL code in specs.
2. **Implementation team** (coder subagents): implement ONLY from the specs,
   never looking at Slither source. Provenance log records that impl came from spec.
3. Permissive license (MIT or Apache-2.0) + NOTICE documenting clean-room provenance.

## Stages

### Stage 0 — Clean-Room Specification (research subagents, parallel)
- 0a: Full detector catalog spec (name, impact, confidence, what it detects, false-positive notes)
- 0b: Architecture/API spec (compilation pipeline, IR concept, detector/printer framework contract)
- 0c: Printers + auxiliary tools spec (slither-check-erc, upgradeability, flat, interface, storage)
Output: `spec/` folder of markdown specs.

### Stage 1 — Core Framework (coder subagents)
- Compilation abstraction (invoke solc directly, consume standard JSON AST — no crytic-compile)
- Core model: Contract, Function, CFG, StateVariable, modifiers, inheritance (C3 linearization)
- IR layer (SSA-like, our own design)
- Detector registry framework (impact/confidence, SARIF + JSON output, filtering/triage)
- Printer framework

### Stage 2 — Detector Implementation (parallel coder subagents, batched by category)
- Batches: reentrancy / access-control / delegatecall / token-ERC / compiler-bugs /
  bad-practices / oracle / gas-optimization
- Each detector: implementation + unit tests against vulnerable fixture contracts

### Stage 3 — Printers + Aux Tools
- human-summary, call-graph, inheritance-graph, cfg (graphviz dot), function-summary, loc
- check-erc (ERC20/721/1155 conformance), check-upgradeability, flatten, interface-gen

### Stage 4 — Packaging & OSS Readiness
- CLI, pyproject, CI (GitHub Actions), SARIF output, docs site content, README,
  CONTRIBUTING, LICENSE (permissive), clean-room NOTICE, test suite, release

## Skills to load
- Stage 1–4: `vibecoding-general-swarm` (coding orchestration)
- Spec stage: orchestrator-designed clean-room research guidance

## Open decisions (asking user)
- Implementation language: Python (recommended) vs TypeScript vs Rust
- License: MIT vs Apache-2.0
- v1 scope: full 100-detector catalog vs top ~30 high-value detectors first


## v0.2 wave (launched 2026-07-19)
- compile-adapters: hardhat/foundry/brownie adapters + explorer-address targets (etherscan)
- triage: interactive triage mode + velvet.db.json + --checklist/--markdown-root
- upgradeability: velvet-check-upgradeability (17 checks per spec)
- detectors batch D: 15 high/medium security detectors
- detectors batch E: 15 medium/low/info detectors
- reentrancy-hardening: NatSpec non-reentrant tag, modifier-body coverage
