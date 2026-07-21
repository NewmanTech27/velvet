# Public API Surface Specification — `solscope`

**Status:** normative specification for implementers
**Companion document:** `architecture.md` (pipeline, object model, IR, frameworks)
**Clean-room rule:** derived only from public documentation (wiki *Python API*,
*Adding a new detector*, *Usage*, *JSON output*, README, WETSEB'19 paper). It specifies
**what** a compatible library must expose, using **our own names** and **original
example code**. Implementers must not consult the reference tool's source.

Codename used below: package **`solscope`** (framework), **`solbuild`** (compilation).
All identifiers are proposals and may be renamed at packaging time.

---

## 1. Design principles for the API

1. **One entry object.** Users construct a single analysis session object from a
   *target*; everything else is reachable by traversal (documented publicly as:
   "the main object contains a list of contracts, each contract contains a list of
   functions, each function contains a list of nodes, and so on").
2. **Everything is source-mapped.** Every model object exposes a `source_mapping`
   (`SourceRange`: file forms, byte start/length, 1-based lines/columns, snippet).
3. **Computed information is cached** and exposed as read-only properties.
4. **Two plugin kinds**: `Detector` (emits findings) and `Printer` (emits reports).
5. **Language**: Python ≥ 3.10, typed, `dataclasses`/enums for metadata.

---

## 2. Session entry point

### 2.1 Construction

```python
from solscope import Analyzer

session = Analyzer(target, **options)
```

- `target`: one of
  - path to a `.sol` file,
  - path to a project directory (framework auto-detected; `--force-framework` equivalent
    option `force_framework: str`),
  - contract address string `0x…` (with `explorer_network`/`explorer_api_key` options),
  - path to an AST-JSON dump or standard-JSON document,
  - an already-built `solbuild.Compilation` object (for embedding).
- Common options (all keyword, all optional): `solc` (binary/version),
  `solc_args`, `solc_remaps`, `filter_paths: list[str]`, `include_paths: list[str]`,
  `exclude_dependencies: bool`, `triage_mode: bool`, `triage_database: str`,
  `skip_assembly: bool`, `generate_patches: bool`, `show_ignored_findings: bool`,
  `no_fail: bool`, `change_line_prefix: str` (default `"#"` for `file.sol#L1-L2`
  rendering), `markdown_root: str`.

Construction performs the full pipeline (compile → parse → CFG → IR → SSA → built-in
analyses). On completion the model is read-only for analyses.

### 2.2 Traversal surface (conceptual properties/methods)

| Member | Returns | Notes |
|--------|---------|-------|
| `compilation_units` | `list[CompilationUnit]` | usually 1 |
| `contracts` | `list[Contract]` | across all units |
| `contracts_derived` | `list[Contract]` | only most-derived (not inherited by another contract); **use this in detectors to avoid duplicate findings** |
| `get_contract_from_name(name)` | `Contract \| None` / list if ambiguous | |
| `filename_lookup(path)` | normalized path object | absolute/relative/short/used |
| `source_code(path)` | `str` | original text |
| `register_detector(cls)` / `unregister_detector(cls)` | — | plugin management |
| `register_printer(cls)` / `unregister_printer(cls)` | — | |
| `run_detectors() -> list[Finding]` | runs all registered detectors, applies filtering/triage | detectors grouped by impact via `detectors_high/medium/low/informational/optimization` |
| `run_printers() -> list[PrinterOutput]` | runs registered printers | |
| `valid_result(finding)` / suppression & triage internals | framework-level, not for plugin authors | |

---

## 3. Core object API (what plugins traverse)

### 3.1 `CompilationUnit`

`contracts`, `contracts_derived`, `functions_and_modifiers` (all, incl. inherited
views), `state_variables`, `structures`, `events`, `enums`, `pragmas`, `imports`,
`top_level_functions`, plus name/id lookups (`get_contract_from_name`,
`get_function_from_id`, `get_state_variable_from_name`, …), `solc_version`,
`is_dependency(path)`, and the underlying `solbuild` compilation handle
(`crytic`-free: `unit.compilation`).

### 3.2 `Contract`

| Member | Type / semantics |
|--------|------------------|
| `name`, `kind` | str; `ContractKind.{CONTRACT, ABSTRACT, INTERFACE, LIBRARY}` |
| `direct_bases` | ordered immediate parents |
| `inheritance` | C3-linearized ancestors (nearest first) |
| `inheritance_reverse` | linearization in reverse (most-base first) |
| `derived_contracts` | contracts inheriting this one |
| `state_variables` / `state_variables_ordered` | declared (and inherited) state vars; storage-layout order |
| `functions` / `modifiers` | declared members |
| `functions_entry_points` | public/external functions |
| `all_functions_called` | transitive internal functions/modifiers reachable from this contract |
| `events`, `structures`, `enums`, `errors`, `using_for` | declared type-level members |
| `get_function_from_signature(sig)` / `get_modifier_from_signature(sig)` / `get_state_variable_from_name(name)` | lookup helpers; signature format `"transfer(address,uint256)"` |
| `available_functions_from_inheritances()` | all callable functions incl. inherited, honoring overrides |
| `is_erc20()`/…, `is_token`-style heuristics | optional convenience heuristics (used by human-summary printer) |
| `can_send_eth()`, `can_receive_eth()`, fallback/receive availability | ether-flow facts |
| `signatures` / selectors, `functions_shadowed`, shadowing queries | naming/override analysis |

### 3.3 `Function` / `Modifier` (shared base `FunctionLike`)

| Member | Semantics |
|--------|-----------|
| `name`, `signature`, `full_name`, `solidity_signature`, selector (`function_id`) | identity; canonical types in signatures |
| `kind` | `FunctionKind.{NORMAL, CONSTRUCTOR, FALLBACK, RECEIVE}` |
| `visibility` | `external/public/internal/private` |
| `payable`, `view`, `pure` | mutability flags |
| `is_implemented`, `is_empty`, `is_constructor`, `contains_assembly` | structural flags |
| `virtual`, `overrides`, `overridden_by` | override graph |
| `contract`, `contract_declarer` | declaring vs. viewing contract |
| `parameters`, `returns` | ordered `LocalVariable`s |
| `modifiers`, `explicit_base_constructor_calls` | applied modifiers / constructor invocations, in order |
| `entry_point`, `nodes` | CFG access (entry `CFGNode`; ordered node list) |
| `all_expressions`, `all_nodes` incl. modifiers | traversal incl. modifier bodies |
| **Read/write sets** | `variables_read`, `variables_written`, `state_variables_read`, `state_variables_written`, `local_variables_read/written`; **deep variants** folding in internal calls: `state_variables_read_deep`, `state_variables_written_deep` (a.k.a. transitive) |
| **Call decomposition** | `internal_calls`, `high_level_calls`, `low_level_calls`, `library_calls`, `solidity_calls` (builtins), `event_calls`, `calls_as_expressions`, `external_calls_as_expressions`, `all_internal_calls_reachable` (transitive), `all_slithir_operations` / `all_ir_operations`, SSA variants |
| `is_protected` | protected-function heuristic (msg.sender guard/constructor) |
| `is_reachable_from(entry_fn)` / `entry_points_reaching_this` | reachability over call graph |
| `can_send_eth()`, `can_reenter()` (calls-before-writes) | derived facts |
| `cyclomatic_complexity` | CFG metric |
| `is_shadowed`, shadowing of builtin names | naming analysis |

### 3.4 `CFGNode`

| Member | Semantics |
|--------|-----------|
| `node_id`, `kind` (`NodeKind`) | identity; kind ∈ {`ENTRYPOINT`, `EXPRESSION`, `VARIABLE`, `IF`, `ENDIF`, `START_LOOP`, `END_LOOP`, `IF_LOOP`, `CONTINUE`, `BREAK`, `RETURN`, `THROW`, `ASSEMBLY`, `END_ASSEMBLY`, `TRY`, `CATCH`} |
| `successors` / `predecessors` | CFG edges (both directions) |
| `expression` | the node's single expression (if any) |
| `ir_operations` | plain SolIR ops for the expression |
| `ir_operations_ssa` | SSA-view ops |
| `variables_read`/`written`, `state_variables_read`/`written`, `local_variables_read`/`written` | per-node read/write sets |
| `function`, `contract` | owners |
| `is_reachable`, `is_inside_loop`, `dominators`/`dominance_frontier` | CFG analysis helpers |
| `calls` / destination info | convenience for call nodes |
| `variables_declaration` | for `VARIABLE` nodes |

### 3.5 Variables and types

- `Variable` (base): `name`, `type`, `source_mapping`, `initialized`,
  `expression_initial` (initializer), `is_scalar`/`is_constant`-style predicates.
- `StateVariable`: `visibility`, `is_constant`, `is_immutable`, `slot`, `offset`,
  `contract`.
- `LocalVariable`: `location` (`memory/storage/calldata`), `function`.
- IR-synthesized: `TemporaryVariable`, `ReferenceVariable` (with `points_to` base),
  `TupleVariable` (with `index` for unpack origins). SSA wrappers expose
  `non_ssa_version` back-links and `index` version numbers.
- `SolidityVariable`: builtins (`msg.sender`, `msg.value`, `block.timestamp`,
  `block.number`, `tx.origin`, `blockhash`, `gasleft`, …); `SolidityFunction` builtins
  (`require`, `assert`, `revert`, `keccak256`, `sha256`, `ecrecover`, `selfdestruct`,
  `suicide`, `addmod`, …) addressable by canonical name.
- `Type` hierarchy: `ElementaryType(name, size)`, `ArrayType(elem, length?)`,
  `MappingType(key, value)`, `UserDefinedType(struct|enum|contract)`, `FunctionType`,
  `TupleType`; types render canonical Solidity strings (used in signatures).

### 3.6 Expressions

Expression nodes (typed, context-aware): `AssignmentOperation(op, left, right)`,
`BinaryOperation`, `UnaryOperation`, `CallExpression`, `ConditionalExpression`,
`Identifier` (→ resolved variable), `Literal`, `IndexAccess`, `MemberAccess`,
`TupleExpression`, `NewExpression`, `TypeConversion`, `ElementaryTypeNameExpression`.
Helpers: iterate sub-expressions, collect referenced variables/calls
("export values" behavior), detect whether an expression contains a conditional.

### 3.7 IR operations

Every op: `read: list[Variable]`; writing ops: `lvalue` (plus `used`/`written`
convenience). Op classes (by category, see `architecture.md` §6.3): `Assignment`,
`Binary`, `Unary`, `Index`, `Member`, `NewArray`, `NewContract`, `NewStructure`,
`NewElementaryType`, `Push`, `Delete`, `TypeConversion`, `Unpack`, `InitArray`,
`HighLevelCall` (`.destination`, `.function`, `.arguments`, `.call_value`, `.call_gas`),
`LowLevelCall` (`.function_name` ∈ call/delegatecall/staticcall/…), `LibraryCall`,
`InternalCall`, `InternalDynamicCall`, `SolidityCall`, `EventCall`, `Send`, `Transfer`,
`Return`, `Condition`. Each op renders a canonical one-line string (printer output).

---

## 4. Shared analysis helpers (framework-provided)

```python
from solscope.analyses import is_dependent, is_tainted

is_dependent(var, source, context)   # context: Function | Contract
is_tainted(var, context)             # depends on a user-controlled input
```

- Contract context ⇒ multi-transaction fixpoint semantics (documented publicly with
  the setA/setB example).
- Taint sources: function parameters + user-controlled builtins; the protected-function
  heuristic modulates privilege-level answers.
- Additional helpers: storage-alias targets of a local, φ-function inspection on SSA
  nodes, loop membership, dominator queries.

---

## 5. Writing a custom detector

### 5.1 Contract (normative)

A detector is a class deriving from `solscope.detectors.Detector` with:

- **Class attributes (metadata)** — required:
  - `RULE: str` — unique kebab-case id; usable via `--detect <id>`; appears as `check`
    in JSON, in suppression comments, in the triage DB.
  - `TITLE: str` — one-line help shown by `--list-detectors`.
  - `IMPACT: Impact` — `OPTIMIZATION | INFORMATIONAL | LOW | MEDIUM | HIGH`.
  - `CONFIDENCE: Confidence` — `LOW | MEDIUM | HIGH`.
  - `DOCS: DetectorDocs` — `url`, `title`, `description`, `exploit_scenario`,
    `recommendation` (drives generated documentation/wiki).
- **Instance state**: `self.compilation_unit` (the unit under analysis) and
  `self.session` (the `Analyzer`); a `logger` for diagnostics. One instance is created
  **per compilation unit**.
- **Method**: `analyze(self) -> list[Finding]` — the only required override.
- **Result builder**: `self.finding(elements: list[str | ModelObject], *,
  additional_fields: dict | None = None) -> Finding` — interleave human text with model
  objects; **the first object element must be the primary location** (external tooling
  focuses on it, per the public JSON docs). The framework wraps findings with metadata,
  renders `description`/`markdown`, computes the identity hash, applies filtering and
  triage, and orders output by (impact, confidence, rule).

### 5.2 Skeleton (original example, our API)

```python
from solscope.detectors import Detector, Impact, Confidence, DetectorDocs

class HiddenBackdoor(Detector):
    """Flag functions whose name suggests a hidden backdoor."""

    RULE = "hidden-backdoor"
    TITLE = "Function name contains 'backdoor'"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH

    DOCS = DetectorDocs(
        url="https://example.invalid/detectors/hidden-backdoor",
        title="Hidden backdoor",
        description="A function name suggests a deliberate backdoor.",
        exploit_scenario="Bob calls `backdoor()` and drains the contract.",
        recommendation="Remove or protect the function.",
    )

    def analyze(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if "backdoor" in function.name:
                    text = ["Potential backdoor function ", function, " in ", contract]
                    results.append(self.finding(text))
        return results
```

Traversal patterns detectors typically use (all documented public capabilities):
contracts → functions/modifiers → CFG nodes → `node.ir_operations` /
`ir_operations_ssa` → op kinds and `read`/`lvalue`; read/write sets and their deep
variants; `is_dependent`/`is_tainted`; call decomposition lists.

### 5.3 Registration and execution

1. **Built-in**: ship in the framework's detector package; registered by default.
2. **Programmatic**:
   ```python
   session.register_detector(HiddenBackdoor)
   findings = session.run_detectors()
   ```
3. **Plugin package**: detectors advertised via Python entry points
   (`solscope.detectors` group) are auto-registered; same for printers.
4. **CLI**: `solscope target --detect hidden-backdoor` (with `--exclude`,
   `--exclude-low`, … governing the default set).

Duplicate `RULE` registration is an error; `unregister_detector(cls)` removes an
instance. Detector authors never print; they only return findings.

### 5.4 Testing expectation

Each detector ships fixture contracts + golden-file expected outputs (JSON), run in CI;
docs fields are validated non-empty; identity hashes stable across runs.

---

## 6. Writing a custom printer

```python
from solscope.printers import Printer

class FunctionSignatures(Printer):
    RULE = "function-signatures"          # used with --print function-signatures
    TITLE = "Print the 4-byte selector of every function"

    def output(self):
        for contract in self.session.contracts_derived:
            for function in contract.functions_entry_points:
                self.info(contract, function, function.selector)   # console sink
```

Contract: printers are read-only; they may write text via the provided sink and/or
emit files (dot graphs); they return nothing. Registered like detectors
(`register_printer`, entry points, `--print <id>`). Printers run only on request.

---

## 7. Command-line interface (functional spec)

Command: **`solscope`** (plus companion tools, §8). Invocation forms:

```
solscope .                          # analyze a framework project (preferred with deps)
solscope contract.sol               # single file without imports
solscope 0xABC…                     # fetch verified source from an explorer
solscope file.ast.json              # consume a solc AST dump directly
```

### 7.1 Analysis selection

| Flag | Behavior |
|------|----------|
| `--detect a,b` | run only the listed detectors |
| `--exclude a,b` | run all except the listed detectors |
| `--exclude-informational` / `--exclude-optimization` / `--exclude-low` / `--exclude-medium` / `--exclude-high` | drop impact classes |
| `--exclude-dependencies` | drop findings located only in dependency paths (node_modules/lib/…) |
| `--list-detectors` | table: id, title, impact, confidence (+ JSON variant) |
| `--print a,b` | run listed printers (none by default) |
| `--list-printers` | table of printers |

### 7.2 Output

| Flag | Behavior |
|------|----------|
| `--json FILE` (`-` = stdout) | machine output (schema in §10 of architecture.md) |
| `--json-types detectors,printers,compilations,console,list-detectors,list-printers` | select JSON sections |
| `--sarif FILE` | SARIF v2.1.0 export for GitHub code scanning / SARIF viewers |
| `--sarif-input FILE`, `--sarif-triage FILE` | SARIF triage workflow (import/export for SARIF explorer) |
| `--checklist` | markdown checklist report; `--markdown-root URL` prefixes GitHub `…/blob/<ref>/` links; `--checklist-limit` truncates per-rule items |
| `--wiki` | render detector documentation from metadata |
| `--zip FILE`, `--zip-type lzma` | bundle results export |
| `--disable-color`, `--change-line-prefix` | console cosmetics |
| `--fail-on pedantic|low|medium|high|none` | CI exit policy |
| `--show-ignored-findings` | reveal triage-hidden findings |

### 7.3 Filtering & triage

| Flag | Behavior |
|------|----------|
| `--filter-paths "mocks|tests"` | drop findings wholly under matching paths (substr + regex) |
| `--include-paths P` | keep only findings under P |
| `--triage-mode` | interactive per-finding keep/hide; persists to `--triage-database` (default `solscope.db.json`) |
| inline comments | `// solscope-disable-next-line rule`, `// solscope-disable-start [rule]` … `// solscope-disable-end [rule]`; NatSpec `@custom:security non-reentrant` on state vars |

### 7.4 Compilation pass-through (to `solbuild`)

`--force-framework NAME`, `--solc BIN`, `--solc-args`, `--solc-remaps`,
`--solc-disable-warnings`, `--solc-working-dir`, `--ignore-compile`,
`--skip-clean`, `--etherscan-apikey`, `--compile-libraries "(Name,0x…)"`,
`--export-dir` (artifact export), `--skip-assembly`, `--legacy-ast`, `--no-fail`.

### 7.5 Configuration file

`solscope.config.json` auto-loaded from cwd (override: `--config-file`); CLI wins.
Keys mirror the flags: `detectors_to_run`, `detectors_to_exclude`,
`detectors_to_include`, `printers_to_run`, `exclude_dependencies`,
`exclude_informational|optimization|low|medium|high`, `fail_on`, `json`, `sarif`,
`json-types`, `disable_color`, `filter_paths`, `include_paths`, `generate_patches`,
`skip_assembly`, `legacy_ast`, `zip`, `zip_type`, `show_ignored_findings`,
`sarif_input`, `sarif_triage`, `triage_database`, plus `solbuild` compilation keys.

---

## 8. Companion tools (functional parity list)

Separate console scripts sharing the session API:
`solscope-check-upgradeability` (proxy/implementation storage + initializer checks),
`solscope-check-erc` (ERC20/721/1155 conformance tables), `solscope-flat` (source
flattening), `solscope-interface` (interface generation), `solscope-read-storage`
(on-chain storage slot reading), `solscope-prop` (property/test scaffolding),
plus code-similarity and path-finding utilities. v1 scope: check-erc,
check-upgradeability, flat, interface (see project plan).

---

## 9. JSON result schema (consumer contract)

Exactly as specified in `architecture.md` §10.2: top-level
`{success, error, results}`; detector findings carry `check`, `impact`, `confidence`,
`description`, `markdown`, `first_markdown_element`, `id`, `elements[]` with typed
`source_mapping` and `type_specific_fields.parent` chains; optional
`additional_fields` per detector; optional `patches` when patch generation is enabled.
SARIF mapping: rule per detector (`id`=rule, `helpUri`=docs url), result per finding
(`level` ← impact: HIGH→error, MEDIUM→warning, LOW/INFO/OPT→note), primary location ←
first element's source mapping, related locations ← remaining elements,
`partialFingerprints` ← finding identity hash.

---

## 10. Stability, errors, versioning

- Public API = the names in this document; everything else is private (single
  underscore prefix). SemVer: breaking changes only on major versions.
- Errors: `SolscopeError` base; compilation failures raise `CompilationError` with
  the underlying compiler diagnostics; per-unit failures are skippable via `no_fail`.
- Logging: standard `logging` (`"solscope"` logger), `--log-level`-style verbosity.
- Determinism: JSON byte-stable for identical inputs (golden tests rely on it).

---

## Appendix A — Public sources used

Same provenance list as `architecture.md` Appendix A: project README; wiki pages
*Usage*, *Python API*, *Adding a new detector*, *Printer documentation*, *SlithIR*,
*SlithIR SSA*, *Data dependency*, *JSON output*; WETSEB'19 paper
(arXiv:1908.09878); compilation-layer README; auto-generated API documentation index
(surface concepts only). No source code was read, copied, or paraphrased.
