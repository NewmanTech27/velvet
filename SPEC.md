# VELVET — Master Specification (Single Source of Truth)

**Project:** `velvet` — an original, permissively-licensed (Apache-2.0) static analysis
framework for EVM smart contracts (Solidity ≥ 0.4.21 primary focus on ≥ 0.8).
**Clean-room:** functional equivalent of Trail of Bits' Slither, implemented ONLY from
the neutral specs in `/mnt/agents/output/spec/`. NO Slither source code may be read,
copied, or paraphrased by any implementer. Slither is AGPLv3; velvet is original work.
See `NOTICE.md` (to be created at packaging stage) for provenance.

**Authoritative specs (read these before implementing):**
- `/mnt/agents/output/spec/architecture.md` — pipeline, object model, CFG, IR, SSA,
  detector/printer framework contracts, outputs, filtering. **Naming note:** the spec
  used placeholder codename `solscope`/`solbuild`; in velvet these become package
  `velvet` (framework) and subpackage `velvet.compile` (compilation layer).
  Suppression comments are `// velvet-disable-next-line`, config file
  `velvet.config.json`, triage db `velvet.db.json`.
- `/mnt/agents/output/spec/api-surface.md` — public API surface, CLI spec.
  Entry point class is `velvet.Velvet` (alias `Analyzer` exported for ergonomics).
- `/mnt/agents/output/spec/detectors-catalog.md` — all 100 detectors (id, impact,
  confidence, detection condition, example, remediation).
- `/mnt/agents/output/spec/printers-and-tools.md` — printers, tools, CLI.

Where this SPEC.md conflicts with those specs, SPEC.md wins (it is more recent and
reconciles naming/scope).

---

## 1. Packaging & tech

- Python ≥ 3.10, fully typed, dataclasses/enums. License **Apache-2.0**.
- Package: `src/velvet/` (src layout), PyPI name `velvet-analyzer`, import name `velvet`.
- Console scripts: `velvet` (main CLI), `velvet-check-erc`, `velvet-check-upgradeability`,
  `velvet-flat`, `velvet-interface`.
- Dependencies (runtime, keep minimal): `py-solc-x` (MIT — solc binary management ONLY;
  we write our own standard-JSON invocation), `packaging` (version parsing).
  Dev deps: `pytest`. NO crytic-compile, NO slither code.
- Repo: `/mnt/agents/output/velvet` (git, main branch). Subagents work in worktrees
  (`$HOME/work-<branch>`), commit on their branch; the main agent merges.

## 2. Module tree (normative)

```
src/velvet/
  __init__.py            # Velvet, Analyzer alias, __version__
  exceptions.py          # VelvetError, CompilationError, ParsingError
  compile/
    __init__.py          # compile_target(target, **opts) -> list[CompilationArtifacts]
    artifacts.py         # CompilationArtifacts, SourceUnitInfo, Filename, path utils,
                         #   byte-offset -> (line,col) conversion, is_dependency()
    solc_runner.py       # standard-JSON invocation, diagnostics propagation
    versions.py          # pragma parsing -> compatible solc version selection
    adapters/
      base.py            # Adapter protocol: matches(target), compile(target, **opts)
      sol_file.py        # single .sol file adapter (v1)
      standard_json.py   # standard-JSON input/output adapter (v1)
      project_dir.py     # plain directory of .sol files (v1; hardhat/foundry v2)
  core/
    source_mapping.py    # SourceRange mixin (file forms, bytes, lines, cols, snippet)
    compilation_unit.py
    contract.py          # Contract, ContractKind, C3 linearization, shadowing queries
    function.py          # FunctionLike base, Function, Modifier, FunctionKind
    variables.py         # Variable, StateVariable, LocalVariable, SolidityVariable,
                         #   SolidityFunction, Constant
    types.py             # Type hierarchy (elementary/array/mapping/UDT/function/tuple)
    expressions.py       # expression tree classes (typed, context-aware)
    cfg_node.py          # CFGNode, NodeKind
  parsing/
    ast_norm.py          # compact/legacy AST normalization to one internal dialect
    decl_parser.py       # AST -> contracts/variables/functions (bodies deferred)
    body_parser.py       # statements -> CFG (construction rules per architecture §5)
    expr_parser.py       # AST expressions -> expression trees
  ir/
    variables.py         # TemporaryVariable, ReferenceVariable, TupleVariable
    operations.py        # op classes per architecture §6.3, canonical __str__
    convert.py           # expression tree -> IR op sequence (normalization §6.4)
    ssa.py               # SolIR-SSA transform (phi placement incl. state-var rules)
  analyses/
    read_write.py        # read/write sets all granularities + deep variants
    dependency.py        # is_dependent(var, source, context), is_tainted(var, context)
    protected.py         # is_protected heuristic
  detectors/
    base.py              # Detector, Finding, Impact, Confidence, DetectorDocs
    __init__.py          # BUILTIN_DETECTORS registry list
    <one module per detector, snake_case of rule id>
  printers/
    base.py              # Printer
    __init__.py          # BUILTIN_PRINTERS registry
    <one module per printer>
  outputs/
    console.py           # colorized findings rendering
    json_out.py          # JSON schema per architecture §10.2
    sarif.py             # SARIF v2.1.0 export (§10.3)
  filtering.py           # path filters, inline suppressions, triage db, fail-on policy
  session.py             # Velvet session class (pipeline orchestration, plugin registries)
  cli.py                 # argparse CLI per api-surface §7
  tools/
    check_erc.py         # ERC20/721/1155 conformance
    check_upgradeability.py
    flat.py
    interface.py
tests/                   # pytest; unit + golden-file detector tests
fixtures/                # vulnerable .sol fixtures per detector (original code)
```

## 3. Pipeline contract

`Velvet(target, **options)` runs: compile (velvet.compile) -> parse (AST norm -> model)
-> CFG -> IR -> SSA -> built-in analyses. All cached at construction. Then:
`register_detector/run_detectors/run_printers`. See api-surface §2-4 for the full
traversal API — **those names are normative** (substitute `velvet` for `solscope`,
`Velvet` for the session class).

## 4. v1 scope (normative)

**In scope v0.1 (this build):**
1. Compilation: single .sol files, directories of .sol files (import resolution via
   solc base-path/include-path), standard-JSON input. solc version auto-selection from
   pragma via py-solc-x. (Hardhat/Foundry/explorer adapters: v0.2.)
2. Full core model + CFG + IR (all op categories) + SSA (incl. state-var phi rules)
   + analyses (read/write deep sets, is_dependent, is_tainted, is_protected).
3. Detector framework + **32 detectors** (§5 list).
4. Printer framework + **10 printers** (§6 list).
5. CLI: detect/exclude/list, --print, --json (+json-types), --sarif, --disable-color,
   --filter-paths, --exclude-dependencies, inline suppressions, --fail-on,
   velvet.config.json. (triage-mode, checklist, zip, wiki: v0.2.)
6. Tools: velvet-check-erc (ERC20 full; 721/1155 if time), velvet-flat, velvet-interface.
   (check-upgradeability, read-storage, prop: v0.2.)
7. Tests: unit tests per module; golden-file JSON tests per detector over fixtures;
   CLI end-to-end smoke tests. `pytest` green is the merge gate.
8. OSS files: README.md, LICENSE (Apache-2.0), NOTICE.md (clean-room provenance),
   CONTRIBUTING.md, pyproject.toml, .github/workflows/ci.yml.

**Explicitly out of v1:** Vyper, explorer-address targets, framework adapters
(hardhat/foundry/brownie), interactive triage mode, patches, echidna/solscope-prop,
code-similarity utilities, remaining ~68 detectors, remaining printers.

## 5. v1 detector set (32)

From detectors-catalog.md (ids normative, impact/confidence per catalog):

Reentrancy (4): reentrancy-eth, reentrancy-no-eth, reentrancy-benign, reentrancy-events
Access control (5): suicidal, unprotected-upgrade, arbitrary-send-eth,
  missing-zero-check, protected-vars
Delegatecall (2): controlled-delegatecall, delegatecall-loop
Tokens (2): arbitrary-send-erc20, unchecked-transfer
Best-practice (13): tx-origin, unchecked-lowlevel, unchecked-send, weak-prng,
  timestamp, divide-before-multiply, dead-code, unused-state, shadowing-state,
  shadowing-builtin, naming-convention, pragma, solc-version
Compiler-bug (2): abiencoderv2-array, storage-array
Informational (2): assembly, low-level-calls
Gas (2): constable-states, immutable-states

(If a catalog detector's analysis infra is missing, substitute the nearest same-category
detector and record the substitution in the PR notes.)

## 6. v1 printer set (10)

human-summary, contract-summary, function-summary, entry-points, loc,
inheritance-graph, call-graph, cfg, solir, solir-ssa

## 7. Quality gates (merge criteria, enforced by main agent)

- `pytest` green (unit + golden + CLI smoke).
- Deterministic JSON output (byte-stable across two runs on same fixture).
- Self-check: `velvet fixtures/` completes without crash; zero unhandled tracebacks.
- Every detector has: fixture contract(s), ≥1 positive and ≥1 negative test.
- Type hints on all public API; no TODO stubs in merged code.
- Clean-room: no Slither source in any file; NOTICE.md present.

## 8. Stage plan (orchestrator execution)

- Wave 1 (1 coder, foreground): compilation layer + core model + parsing + CFG
  (modules: velvet.compile, velvet.core, velvet.parsing) + unit tests. Branch `core-model`.
- Wave 2 (1 coder, foreground): IR + SSA + analyses + detector/printer framework +
  outputs + CLI skeleton. Branch `framework`. (Depends on Wave 1 interfaces.)
- Wave 3 (parallel coders): detector batches by category on branches
  `detectors-<batch>`; printers on `printers`; tools on `tools`.
- Wave 4 (main agent): merge all, integration tests, packaging, OSS files, release.
