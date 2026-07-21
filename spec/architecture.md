# Architecture Specification — Solidity Static Analysis Framework

**Status:** normative specification for implementers
**Audience:** implementation team members who have **never read Slither's source code**
**Clean-room rule:** this document was derived exclusively from *public documentation*
(project README, public wiki pages, the peer-reviewed WETSEB'19 paper *"Slither: A Static
Analysis Framework For Smart Contracts"*, public user guides/blog posts, and general
static-analysis literature). It contains **no code or pseudo-code copied from Slither**.
Where the reference tool's observable behavior is described, we describe *what* it does,
never *how* its code does it. All names in this document are our own clean-room names.

---

## 0. Naming (proposed codename)

The implementation will use its own package name. Throughout this spec we use the
placeholder codename **`solscope`** for the analysis framework and **`solbuild`** for the
compilation-abstraction layer. These are proposals; the final name is a packaging decision.

| Concept (neutral description)            | Our clean-room name (proposal) |
|------------------------------------------|--------------------------------|
| Root analysis object / entry point       | `Analyzer` (module `solscope`) |
| Compilation-abstraction package          | `solbuild`                     |
| One compiled batch of sources            | `CompilationUnit`              |
| Intermediate representation              | **SolIR**                      |
| SSA form of the IR                       | **SolIR-SSA**                  |
| Vulnerability-analysis plugin base class | `Detector`                     |
| Impact/confidence classifications        | `Impact`, `Confidence` enums   |
| Code-comprehension plugin base class     | `Printer`                      |
| CFG vertex                               | `CFGNode` (kind: `NodeKind`)   |
| Finding object                           | `Finding`                      |
| Source-location mixin                    | `SourceMapping` / `SourceRange`|

Terminology used with its standard industry meaning (not package names): *detector*,
*printer*, *finding*, *compilation unit*, *taint*, *SSA*, *CFG*, *SARIF*.

---

## 1. Purpose and design goals

`solscope` is a **static analysis framework for EVM smart-contract source code**
(Solidity ≥ 0.4; Vyper support is an explicit stretch goal, not required for v1).
It runs a suite of vulnerability/optimization **detectors**, offers **printers** that
summarize and visualize contract structure, and exposes a **Python API** for custom
analyses. Per the reference tool's public paper and README, the framework must satisfy:

1. **Correct level of abstraction.** The model must be rich enough to express
   smart-contract semantics (calls, ether flows, storage, reentrancy, inheritance),
   yet generic enough that new analyses are easy to add.
2. **Robustness.** Parse and analyze real-world code without crashing; target
   ≥ 99% of public Solidity code. Degraded behavior (partial results + warning) is
   preferable to a crash.
3. **Performance.** Average analysis time on the order of **≤ 1 second per contract**,
   including compilation, so it fits IDEs and CI.
4. **Accuracy.** Detectors must achieve a low false-positive rate; the framework
   provides taint/dependency information and source locations to make this practical.
5. **Batteries included.** Ship a catalog of ~100 detectors and ~15 printers covering
   vulnerabilities, optimizations, informational and code-comprehension use cases.

**Four supported use cases** (from the public paper): (a) automated vulnerability
detection, (b) automated detection of code-optimization opportunities, (c) code
understanding via printers, (d) assisted code review via the Python API and custom
detectors/tools built by third parties.

---

## 2. End-to-end pipeline

The framework operates as a **multi-stage pipeline**. Every stage produces immutable-ish
model objects consumed by later stages. The conceptual flow (redrawn from the public
architecture figure in the WETSEB'19 paper, in our own terms):

```
                        ┌────────────────────────── solscope core ──────────────────────────┐
 source code            │                                                                   │
 (.sol / project dir /  │  ┌────────────────┐   ┌─────────────────┐   ┌──────────────────┐  │
  address / AST json)   │  │  INFORMATION    │   │  IR CONVERSION  │   │  CODE ANALYSIS   │  │
        │               │  │  RECOVERY       │   │                 │   │                  │  │
        ▼               │  │                 │   │                 │   │                  │  │
 ┌──────────────┐       │  │ • inheritance   │   │ • per-node IR   │   │ • read/write sets│  │
 │  COMPILATION │──────▶│  │   graph + C3    │──▶│   generation    │──▶│ • protected-     │──┼──▶ DETECTORS
 │  (solbuild)  │ ASTs  │  │ • CFG per func  │   │ • SSA transform │   │   functions      │  │──▶ PRINTERS
 │  solc std-   │ src   │  │ • expression    │   │                 │   │ • data dependency│  │──▶ THIRD-PARTY TOOLS
 │  JSON / build│ maps  │  │   trees, types  │   │                 │   │   / taint        │  │
 │  artifacts   │       │  └────────────────┘   └─────────────────┘   └──────────────────┘  │
 └──────────────┘       │                                                                   │
                        └─────────────────────────────────────────────────────────────────────┘
```

**Stage 1 — Compilation (solbuild).** Resolve the *target* (single file, framework
project, explorer address, AST dump, standard-JSON), drive the Solidity compiler,
and return **compilation artifacts**: per compilation unit, the ASTs of all source
units, the original source text, source-unit id → path mapping, ABI/bytecode when
available, compiler version, and path metadata (relative/absolute/short forms,
dependency flag).

**Stage 2 — Information recovery (parsing).** Walk each AST and build the **core object
model**: contracts (with inheritance edges and C3 linearization), state variables,
functions, modifiers, events, structs, enums, errors, pragmas, and top-level items.
Build a **control-flow graph** for every function/modifier body; attach at most one
typed **expression tree** per CFG node. Attach a `SourceRange` (file, byte offsets,
lines, columns) to every model object. Resolve all symbol references (calls to
functions, identifiers to variables, type names to types).

**Stage 3 — IR conversion.** Translate each node's expression tree into a linear
sequence of **SolIR operations**. Then build the **SolIR-SSA** view: rename variables so
each is assigned once, insert φ-functions where control flow merges and (crucially for
contracts) at function entries and after external calls for state variables.

**Stage 4 — Built-in code analysis.** Compute framework-level analyses once, so all
detectors share them: read/write sets at every granularity, the protected-function
heuristic, data-dependency sets and taint flags (function-local, then cross-function
fixpoint), entry-point reachability, storage-reference alias analysis.

**Stage 5 — Consumption.** Run registered **detectors** (each returns findings with
source locations), run requested **printers**, serialize output (console, JSON, SARIF,
markdown), apply filtering/triage, and compute the process exit code.

Design decision: stages 1–4 are **lazy-safe** — detectors must not trigger re-parsing;
all analysis products are computed during initialization and cached.

---

## 3. Compilation layer (`solbuild`) — our own abstraction

The reference tool delegates compilation to a separate library (`crytic-compile`).
**We design our own**; this section specifies its required behavior only.

### 3.1 Target kinds

The facade must accept, and auto-discriminate between:

| Target form                | Detection strategy (conceptual)                                  |
|----------------------------|------------------------------------------------------------------|
| Single `.sol` file         | direct `solc` invocation; user-selected or pragma-derived version|
| Project directory (`.`)    | framework auto-detection by marker files (e.g. `foundry.toml`, `hardhat.config.*`, `truffle-config.js`, `brownie-config.yaml`, `embark.json`, `dapp` tools, `waffle`/`buidler` configs) |
| Contract address (0x…)     | fetch verified source via block-explorer API (multiple networks) |
| AST JSON file              | solc `--ast-compact-json`/`--ast-json` output consumed directly  |
| solc standard-JSON in/out  | user-supplied standard-JSON input or output document             |
| Exported archive (zip)     | a previously exported compilation archive, for offline replay    |

A flag (`--force-framework <name>`) overrides auto-detection. Framework projects are
compiled **using the framework's own build pipeline when possible** (so remappings,
plugins and dependency layouts are honored), falling back to direct `solc` with parsed
configuration. The analyzer requires the AST, so projects must compile cleanly
(`npx hardhat compile`/`forge build` must succeed first when the framework only emits
artifacts on demand).

### 3.2 Adapter interface

Each platform is an **adapter** implementing a small interface (conceptual):

- `matches(target) -> bool` — can this adapter handle the target?
- `compile(target, **options) -> CompilationArtifacts` — run/obtain compilation.
- options include: explicit solc binary or version, extra solc arguments, import
  remappings, working directory, "ignore compile" (reuse existing build artifacts),
  library linking (`name=address` pairs applied to deployed bytecode), disable
  compiler warnings, remove metadata, export directory.

### 3.3 Compilation artifacts (the contract between solbuild and solscope)

For each **compilation unit** produced (a target may yield several, e.g. multiple solc
versions or multi-config builds):

- `source_units`: ordered mapping `source_id -> {path forms, AST, source text}`.
- `asts`: the solc AST per file (compact-JSON format by default; legacy format tolerated).
- `abis`, `bytecode` (init + deployed) per contract name — optional for analysis,
  required by some auxiliary tools.
- `compiler_version`, `remappings`, `libraries`.
- Path utilities: `filename_lookup(used_path)` → normalized `{absolute, relative, short,
  used}`; `is_dependency(path)` (anything under dependency directories such as
  `node_modules`, `lib/`, or framework package dirs); **byte-offset → (line, column)**
  conversion per file, built from the source text. The analyzer's entire source-mapping
  system depends on these two helpers.
- `export()` — write `solbuild-export/artifacts.json` (AST/ABI/bytecode bundle) so runs
  are reproducible and CI-cacheable.

### 3.4 solc interaction

- Invoke `solc` with **standard-JSON** input requesting the AST output
  (`ast` per source file; ABI/bytecode when needed). Parse the pragma in each source
  file to select a compatible solc version when no framework dictates one; support
  version-switching tools conceptually (e.g. a `solc-select`-style shim) but do not
  require them.
- Support `--solc-ast-format compact|legacy` handling internally; downstream parsing
  must be insulated from AST-format differences by a thin normalization layer.
- Propagate compiler diagnostics; a flag suppresses solc warnings in our output.

Design decisions: keep the AST as the *only* required compiler output (bytecode/ABI
optional). Never reimplement a Solidity parser — robustness comes from consuming the
reference compiler's AST.

---

## 4. Core object model (information recovery)

All model objects share two mixins conceptually: **`SourceMapping`** (every object can
answer where it was defined: file, byte start/length, line list, columns, and the raw
source snippet) and **`Context`** (objects belong to scopes; name resolution is
scope-aware).

### 4.1 CompilationUnit

- Groups everything produced by one compilation: its contracts, functions, top-level
  constructs, pragmas, imports, source units, and the underlying compilation artifacts.
- Exposes lookup helpers (by name, by id) for contracts, functions, structures, events,
  enums, variables; exposes the set of **top-level** (free) functions and constants
  introduced by newer Solidity versions by placing them in a synthesized container.

### 4.2 Contract

- `name`, `kind` ∈ {`contract`, `abstract`, `interface`, `library`}.
- **Inheritance**: `direct_bases` (immediate parents, declared order) and the
  **C3-linearized** ancestor list (Solidity resolves multiple inheritance by C3
  linearization; the model exposes the linearization so analyses can walk the true
  override/dispatch order). Also expose `derived_contracts` (children) so analyses can
  iterate only over most-derived contracts to avoid duplicate findings.
- Members: `state_variables` (declared + inherited views available separately),
  `functions`, `modifiers`, `events`, `structs`, `enums`, `errors`, `using_for`
  directives.
- Derived queries: all functions **reachable** from this contract (including inherited
  and internal library calls), entry points (public/external functions), function by
  **signature** (`name(type1,type2)`), signature **hashes** (4-byte selectors),
  availability/payability of the fallback and receive functions, whether the contract
  can send/receive ether, summary counts used by human-summary printer (LOC,
  cyclomatic complexity, etc.).
- Name-resolution must surface **shadowing** information: state variables or functions
  that hide an inherited or builtin symbol (a whole detector family depends on it).

### 4.3 Function and Modifier

`Modifier` is a function-like object; both share one base type (`FunctionOrModifier`
conceptually). A function exposes:

- Identity: `name`, `signature` (name + canonical parameter types), `full_name`,
  4-byte selector where applicable.
- Classification: `kind` ∈ {`normal`, `constructor`, `fallback`, `receive`};
  `visibility` ∈ {`external`, `public`, `internal`, `private`}; mutability flags
  `payable`, `view`, `pure`; `virtual`/`override` markers and links to the functions
  it **overrides** / is **overridden by**; `is_implemented` (has a body), `is_empty`,
  `is_constructor`.
- Parameters and returns: ordered `parameters`, `returns` (as `LocalVariable`s).
- `modifiers`: the modifiers applied, in application order; also explicit base-
  constructor calls for constructors.
- **CFG**: `entry_point`, ordered `nodes` (list of `CFGNode`), and per-node access.
- **Read/write analysis** (framework-computed, cached): `variables_read`,
  `variables_written`, filtered views `state_variables_read`, `state_variables_written`,
  `local_variables_read/written`, plus **deep/transitive variants** that fold in
  everything reachable through internal calls (e.g. "state variables written by this
  function or anything it internally calls").
- **Call decomposition**: lists of internal calls, external/high-level calls, low-level
  calls, library calls, solidity-builtin calls, event calls — both as IR operations and
  as expression-level call sites; `all_internal_calls_reachable` (transitive closure).
- Heuristics: `is_protected` (see §7.2), `is_reachable_from` / entry-point sets,
  `contains_assembly`, cyclomatic complexity, whether it reads/writes a given variable,
  whether it can send ether, can re-enter (calls before writes), etc. These are
  **queries over CFG + IR**, computed once and cached.

### 4.4 Variables

- `StateVariable`: name, type, visibility, `constant`/`immutable` flags, initialized-at-
  declaration flag and initializer expression, storage **slot/offset** information
  (layout order for the variable-order printer and upgradeability checks).
- `LocalVariable`: name, type, data location (`memory`/`storage`/`calldata`), the
  function that declares it, initialized flag. Storage-typed locals participate in
  **alias analysis** (§6.3).
- IR-only variables (§5): `TemporaryVariable` (`TMP_n`), `ReferenceVariable` (`REF_n`),
  `TupleVariable` (`TUPLE_n`).
- `SolidityVariable`: pseudo-variables for language builtins (`msg.sender`, `msg.value`,
  `block.timestamp`, `tx.origin`, `block.number`, …) so they flow through dependency
  analysis uniformly. Also `SolidityFunction` for builtins (`require`, `assert`,
  `keccak256`, `selfdestruct`, …).
- `Constant`: literal values with type and value.
- Every variable carries a **Type**; the type system models elementary types
  (incl. sizes), arrays (fixed/dynamic), mappings, structs, enums, contracts,
  function types, and tuples.

### 4.5 Expressions

Expression trees are the parsed form of exactly-one statement/condition per CFG node.
Node kinds include: assignment (incl. compound ops), binary/unary operations, call
expressions, conditional (ternary), identifier, literal, index access, member access,
tuple, `new` expression, type conversion, elementary-type-name expression. Expressions
are **typed** and expose their **context** (which function/contract they belong to) so
that identifiers resolve to the right variable even under inheritance and scoping.

### 4.6 Other declarations

`Event` (name, params, indexed flags), `Struct`, `Enum`, `CustomError`,
`PragmaDirective` (name + version tokens), `ImportDirective`, and `UsingForDirective`
(library attached to type) are first-class objects with source mappings, because
detectors inspect all of them (pragma/version checks, event indexing checks, etc.).

---

## 5. Control-flow graph (CFG)

- Each implemented function/modifier owns a **directed CFG** of `CFGNode`s with a unique
  `entry_point`. Edges are navigable in both directions (`successors`/`predecessors`,
  also known as sons/fathers in the reference docs).
- **At most one expression per node** (public paper): a statement, condition, or return
  expression. This invariant is what makes the per-node IR conversion well-defined.
- `NodeKind` distinguishes structural vertices, at minimum: `ENTRYPOINT`, `EXPRESSION`,
  `VARIABLE` (declaration), `IF`, `ENDIF`, `START_LOOP`, `END_LOOP`, `IF_LOOP`
  (loop condition), `CONTINUE`, `BREAK`, `RETURN`, `THROW`, `ASSEMBLY`, `END_ASSEMBLY`,
  `TRY`, `CATCH`. Structural nodes carry no expression; expression-carrying nodes
  expose `expression`, `ir_operations`, `ir_operations_ssa`.
- **Construction rules** (behavioral requirements, not implementation):
  - `if/else` → condition node, branch bodies, join (`ENDIF`) node; degenerate
    both-branches-return `ENDIF`s are pruned.
  - Loops → `START_LOOP`/`END_LOOP` sentinels plus an `IF_LOOP` condition node;
    `for` headers (init/condition/post) are distributed to the correct nodes.
  - `break`/`continue` edges are re-pointed to the matching loop exit/condition.
  - **Ternary expressions are lowered** to `IF`/branch/`ENDIF` subgraphs so the IR never
    contains control flow inside an expression.
  - Functions with **named return variables** get a synthesized trailing `RETURN` node
    returning the named tuple, so every path ends at a return vertex.
  - `try/catch` produces `TRY`/`CATCH` nodes; catch-clause parameters are treated as
    initialized variables.
  - Inline assembly either becomes a single `ASSEMBLY` node (opaque) or, when a Yul AST
    is available and assembly parsing is enabled, a sub-graph of assembly nodes; a
    configuration flag (`skip_assembly`) forces the opaque behavior.
  - Unreachable nodes are marked (`is_reachable` fixpoint from the entry), not deleted.
- Dominator/loop utilities must be available to analyses: loop membership
  ("is this node inside a loop" — needed by loop-related detectors), dominator tree,
  and path reachability between nodes.

---

## 6. Intermediate representation (SolIR) and SSA

### 6.1 Why an IR at all (requirements distilled from public docs)

Solidity has syntactic quirks whose surface form hides semantics (e.g. an array `push`
looks like a method call; `using for` rewrites operator sites; implicit conversions).
The framework therefore **normalizes every expression into a small operation set**
before analysis. Public design goals for the IR:

- **Reduced instruction set** (< ~40 operation kinds), **no internal control flow**
  (control flow lives only in the CFG).
- A **uniform variable model** so analyses can ask any operation "what do you read?"
  and "what do you write?" — this is the foundation of taint and dependency tracking.
- Preserve semantics lost at bytecode level (types, calls, events), while discarding
  sugar (the reference tool keeps *two* views of each node: plain IR and SSA IR).
- Operator **hierarchy**: every operation inherits a `read` list; operations that write
  expose an `lvalue`. In a few lines, an analysis can then find "all operations that
  write variable X" — the public docs call this out as the key usability property.

### 6.2 IR variables

`StateVariable`, `LocalVariable`, `Constant`, `SolidityVariable` (builtins),
plus IR-synthesized: `TemporaryVariable` (results of sub-expressions),
`ReferenceVariable` (results of dereferencing: mapping/array indexing, struct member
access), `TupleVariable` (multi-return values).

Type discipline (from public IR docs): an **LVALUE** may be a state/local/temporary/
reference/tuple variable; an **RVALUE** may additionally be a constant or builtin
solidity variable. Every operation documents which side each operand is on.

### 6.3 Operation taxonomy (functional catalog)

Each operation is specified by its *shape* (operands) and *semantics*. The catalog below
is a functional requirement list (derived from the public IR documentation):

| Category      | Operations (conceptual shapes) |
|---------------|--------------------------------|
| Assignment    | `LVALUE := RVALUE` (also from tuple/function for dynamic dispatch) |
| Arithmetic/ logic | `LVALUE = RVALUE <binop> RVALUE` for `** * / % + - << >> & ^ | < > <= >= == != && \|\|`; `LVALUE = <unop> RVALUE` for `! ~ -` |
| Dereference   | `REF -> base [ index ]` (Index), `REF -> base . member` (Member; also contract/enum member access) |
| Allocation    | `NEW_ARRAY type depth`, `NEW_CONTRACT contract_name`, `NEW_STRUCTURE`, `NEW_ELEMENTARY_TYPE` |
| Array ops     | `PUSH array value` (dedicated op — **not** a call), `DELETE lvalue` |
| Conversion    | `CONVERT lvalue rvalue target_type` |
| Tuples        | `LVALUE = UNPACK tuple index`; array-literal init `LVALUE = INIT [values…]` (nested for multi-dimensional) |
| Calls         | `HIGH_LEVEL_CALL dest function [args]` (opt. `value`, `gas`), `LOW_LEVEL_CALL dest name [args]` where name ∈ {`call`,`delegatecall`,`staticcall`,`callcode`} (opt. `value`, `gas`), `LIBRARY_CALL dest function [args]`, `INTERNAL_CALL function [args]`, `INTERNAL_DYNAMIC_CALL fn_ptr_var [args]` (function pointers), `SOLIDITY_CALL builtin [args]` (require/assert/keccak256/…), `EVENT_CALL event [args]`, `SEND dest amount`, `TRANSFER dest amount` |
| Terminators   | `RETURN values…` (incl. empty return) |
| Conditions    | `CONDITION rvalue` attached to `IF`/`IF_LOOP` nodes |

Behavioral requirements: calls that transfer ether expose `call_value`; calls can be
queried for destination/function/arguments; every operation exposes
`read`/`lvalue`-based write sets used by dependency analysis; IR operations remember
their originating expression for source mapping. The printer `slithir`/`slithir-ssa`
equivalents render one operation per line using the shapes above.

### 6.4 Normalization rules worth specifying

- Array `push`/`pop`, `delete x`, `abi.encode*` etc. map to dedicated operations, not
  generic calls — so detectors can pattern-match precisely.
- `using Library for T` sites (e.g. `x.add(y)`) become `LIBRARY_CALL` with the receiver
  as first argument.
- Ether-sending `transfer`/`send` are distinct from `call` (they have fixed gas
  semantics and different reentrancy implications).
- Implicit compiler-generated operations (getter functions for public state variables,
  implicit constructors) are materialized so analyses see them uniformly.

### 6.5 SSA form (SolIR-SSA)

Publicly documented properties to reproduce:

- Each variable is assigned **exactly once** and defined before use; the SSA builder
  versions variables (`x`, `x_1`, `x_2`, …). SSA exposes **def-use chains**, which makes
  data-dependency computation straightforward and enables bounded-model-checking-style
  analyses later.
- **φ-functions at control-flow merges**, and — the smart-contract-specific rule —
  **φ-functions for state variables at function entry and after every external call**:
  a state variable's value may be the initial value, the value left by any previous
  transaction, or changed by reentrancy. The public paper is explicit about this
  placement rule.
- **Storage-reference alias analysis**: a local variable of `storage` location may
  alias several state variables (e.g. `S storage ref = cond ? a : b`). The framework
  computes possible alias targets and feeds them to SSA construction so that a write
  through an alias inserts φ-functions for **all** candidate state variables.
- Both the **plain IR** and the **SSA IR** are retained per node
  (`ir_operations` vs `ir_operations_ssa` conceptually); dependency analysis consumes
  SSA, simple pattern detectors consume plain IR.
- SSA variables keep a link to their **non-SSA origin** so findings still map to source.

---

## 7. Built-in analyses (computed once, shared by all detectors)

### 7.1 Read/write sets

For every node, function, modifier, and contract: variables read/written, with filtered
views (state vs local) and **transitive/deep** variants across internal calls. These
sets are derived from the IR (`read`/`lvalue`) and are the single most-used detector
input (uninitialized-variable, reentrancy, unused-variable detectors all consume them).

### 7.2 Protected-function heuristic

A function is heuristically **protected** if the caller address (`msg.sender`) is
directly involved in a guard (comparison/`require`/modifier) or the function is a
constructor. The public paper documents this heuristic explicitly and warns it trades
small numbers of false positives/negatives for large precision gains; detectors use it
to suppress findings in owner-only functions.

### 7.3 Data dependency and taint

- `is_dependent(variable, source, context) -> bool` where `context` is a function or a
  contract (public wiki behavior):
  - **Function-local** dependencies: computed from SSA def-use chains within one
    function.
  - **Contract-level (multi-transaction)**: a fixpoint over all functions, so `b`
    depends on `input_a` if `setA(x){ a=x }` and `setB(){ b=a }` can run in separate
    transactions.
- **Taint**: a variable is *tainted* if it depends on a user-controlled input
  (function parameter or builtin like `msg.sender`/`msg.value`). Taint propagates
  through the same fixpoint, and the protected-function heuristic modulates it
  (privilege-aware taint: "tainted only for the owner" vs "tainted for anyone").
- Dependency info is exposed per function and per contract and is also printable
  (data-dependency printer).

### 7.4 Other framework-level analyses

- **Entry-point/reachability** sets: which external functions can reach a given
  function; used for dead-code and authorization printers.
- **Cyclomatic complexity** per function (CFG-based) for the human-summary printer and
  complexity detector.
- **Storage layout**: state-variable slot order across the C3 hierarchy (variable-order
  printer, upgradeability tooling).

---

## 8. Detector framework contract

A **detector** is a plugin that inspects the core model and emits **findings**.
The public detector-authoring documentation fixes the following contract
(functional description; our class/attribute names differ — see `api-surface.md`):

### 8.1 Required metadata (class-level)

| Metadata            | Semantics |
|---------------------|-----------|
| **rule id**         | stable kebab-case identifier used on the CLI (`--detect <id>`), in JSON (`check`), in suppression comments, and in the triage database |
| **help/title**      | one-line human description shown in `--list-detectors` |
| **impact**          | one of `OPTIMIZATION`, `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`; drives console color (green/yellow/red) and severity filtering |
| **confidence**      | one of `LOW`, `MEDIUM`, `HIGH`; expresses analysis certainty |
| **documentation block** | structured strings for docs generation: title, description, exploit scenario, recommendation, and a URL — used to auto-generate the detector documentation/wiki |

### 8.2 Lifecycle and execution contract

1. The framework **registers** detector classes (built-ins plus user plugins);
   a detector instance is created **per compilation unit** and receives access to the
   compilation unit and the core session (so it can reach every contract, and shared
   analyses like `is_dependent`).
2. The framework invokes the detector's analysis method, which returns a
   **list of findings**. Detectors never print directly; they only produce findings.
3. The framework wraps each finding with the detector's metadata (impact, confidence,
   rule id, docs URL), applies **filtering and triage** (§11), deduplicates, sorts by
   (impact, confidence, id), and renders/serializes.
4. A finding is an ordered list of **elements**: human-readable strings interleaved
   with **model objects** (contract, function, variable, node, event, struct, enum,
   pragma…). The framework renders each object with its name and source location.
   **The first element is the primary location** (public JSON docs state tooling keys
   off it — detectors must choose it carefully).
5. Findings carry a **stable identity** (hash over rule id + normalized element
   signature) so triage decisions survive re-runs; they may carry
   `additional_fields` for detector-specific structured data (e.g. the naming-convention
   detector's violated convention, or a reentrancy detector's element classification).

### 8.3 Conventions detectors rely on

- **Iterate over derived contracts** to avoid duplicate findings on inherited code.
- Use **SSA-based dependency helpers** and read/write sets rather than re-walking the
  AST; use IR operation kinds to pattern-match (e.g. "any `LOW_LEVEL_CALL` named
  `delegatecall` whose destination is tainted").
- Report **node-level elements** for precision (findings point at the offending
  statement, not just the function).
- Respect inline suppressions automatically (the framework strips suppressed findings
  before detectors' results are returned — see §11).

---

## 9. Printer framework contract

A **printer** is a read-only plugin that reports/visualizes model information and emits
no findings. Contract (from the public printer documentation):

- Metadata: **printer id** (CLI name for `--print <id>`) and **help** text.
- Execution: receives the core session; writes human-readable text to the console
  and/or files (several printers emit Graphviz **dot** files: call-graph, cfg,
  inheritance-graph — dot/xdot are optional system dependencies).
- Printers run **only when requested** (default: none); detectors run by default.
- Required printer catalog (functional): `human-summary` (overview, issue counts,
  ERC20 heuristics, complexity), `contract-summary`, `function-summary`,
  `inheritance` / `inheritance-graph`, `call-graph`, `cfg`, `vars-and-auth`
  (state variables written + authorization per function), `modifiers`, `require`
  (require/assert per function), `constructor-calls`, `data-dependency`, `function-id`
  (selectors), `variable-order` (storage layout), `entry-points`, `loc` (lines of code
  split src/deps/tests), `not-pausable`, `evm` (evm mapping), `echidna` (fuzzing
  guidance export), `solir`/`solir-ssa` (IR dumps).

---

## 10. Output formats

### 10.1 Console

Default: human-readable, **colorized by impact** (red = high, yellow = medium,
green = low/informational/optimization), one finding per block with nested source
locations rendered `file.sol#Lstart-Lend` (line prefix configurable). A
`--disable-color` flag exists for CI logs.

### 10.2 JSON (functional schema, from the public JSON documentation)

Top level: `{ "success": bool, "error": string|null, "results": {...} }`.
`results.detectors` is an array of findings:

- `check` (rule id), `impact`, `confidence`, `description` (rendered markdown-ish text),
  optional `markdown`, `first_markdown_element`, `id` (finding identity hash),
  optional `patches`, optional detector-specific `additional_fields`.
- `elements[]`: `{type, name, source_mapping, type_specific_fields?, additional_fields?}`
  where `type` ∈ {`contract`, `function`, `variable`, `node`, `pragma`, `enum`,
  `struct`, `event`, `other`}; `type_specific_fields.parent` chains element → parent
  (function → contract, node → function, variable → contract-or-function);
  function/event elements add `signature`; pragma elements add the parsed `directive`.
- `source_mapping`: `{start, length, filename_relative, filename_absolute,
  filename_short, filename_used, lines[], starting_column, ending_column}` — byte
  offsets plus 1-based line/column spans.
- JSON may be written to a file or stdout (`--json -`), and a flag selects which
  sections to include (detectors, printers, detector/printer listings, compilation
  info, console text).

### 10.3 SARIF

`--sarif <file>` exports **SARIF v2.1.0** for ingestion by **GitHub code scanning** and
generic SARIF viewers (VS Code extension etc.): one SARIF `rule` per detector
(rule id, help, docs URL), one `result` per finding with `level` mapped from impact
(error/warning/note), and `locations[].physicalLocation` filled from the finding's
primary source mapping (artifact URI + line/col region). Related locations may carry
secondary elements. A companion flag set supports SARIF-based triage workflows
(importing an existing SARIF, exporting a triage file for a SARIF explorer).

### 10.4 Markdown / checklist

`--checklist` renders a markdown report: summary table (rule, count, impact) followed
by per-rule checkbox items (`- [ ] ID-n`) with linked source locations; a
`--markdown-root <url>` option prefixes locations with a repository URL (auto-normalized
to `.../blob/<ref>/`) so links resolve on GitHub. `--wiki` renders the detector
documentation pages from the detectors' documentation blocks. Optional machine-export
of detector/printer listings to JSON, and a **zip** export bundling results.

### 10.5 Patches

An opt-in mode attaches machine-applicable **patches** to certain findings (JSON
output only), for tooling that auto-fixes simple issues.

---

## 11. Filtering, suppression, and triage

All mechanisms below are framework responsibilities (detectors never see suppressed
findings):

1. **Detector selection**: run all (default), run a subset (`--detect a,b`), exclude a
   subset (`--exclude a,b`), exclude whole impact classes (`--exclude-informational`,
   `--exclude-optimization`, `--exclude-low|medium|high`), exclude findings located
   **only in dependencies** (`--exclude-dependencies`).
2. **Path filtering**: `--filter-paths <regex|substr>` drops findings whose locations
   are entirely under matching paths (e.g. tests/mocks); `--include-paths` inverts it.
3. **Inline suppression comments** (parsed from source):
   `// solscope-disable-next-line <rule-id>` suppresses the next line's findings for
   that rule; `solscope-disable-start [rule]` / `solscope-disable-end [rule]` bracket
   larger regions; a NatSpec tag (e.g. `@custom:security non-reentrant` on a state
   variable) annotates externally-called variables considered safe, consumed by
   reentrancy detectors.
4. **Interactive triage mode** (`--triage-mode`): each finding is shown with an index;
   the user selects which to hide; decisions persist in a local database file
   (default `solscope.db.json`) keyed by the finding's stable identity; subsequent runs
   hide them (`--show-ignored-findings` reveals them again; deleting the db resets).
5. **Exit policy for CI**: `--fail-on pedantic|low|medium|high|none` — the process exits
   non-zero when any surviving finding meets the threshold (pedantic = any finding;
   none = never fail). This is the documented mechanism used by CI templates.

---

## 12. Non-functional requirements

- **Performance**: ≤ ~1s per contract end-to-end on typical hardware; per-contract
  timeout policy so one pathological contract cannot hang CI (reference tool used a
  per-contract timeout in its evaluation; recommend same).
- **Robustness**: handle solc 0.4.x → 0.8.x AST dialects via the normalization layer;
  degrade gracefully (skip + warn) on unparseable constructs rather than crash;
  `--no-fail`-style switch to continue after per-unit failures.
- **Determinism**: stable ordering of contracts/nodes/findings; JSON output byte-stable
  given identical inputs (needed for golden-file tests and CI diffing).
- **Extensibility**: detectors/printers discoverable via Python entry points
  (third-party packages) in addition to programmatic registration.
- **Testability**: golden-file snapshot tests per detector over a fixtures corpus;
  printer output snapshots; end-to-end CLI tests incl. JSON/SARIF schema validation.
- **Licensing**: all code original, permissively licensed (MIT/Apache-2.0); this spec
  and the implementation NOTICE document the clean-room provenance.

---

## 13. Design decisions made for our implementation

1. **Own compilation facade** (`solbuild`) instead of depending on the reference
   compilation library: smaller surface (solc standard-JSON + framework adapters),
   exports a normalized `CompilationArtifacts` object (§3.3).
2. **Compilation-unit-centric detectors**: one detector instance per compilation unit
   (matches documented reference behavior and keeps findings naturally grouped).
3. **Keep both IR views** (plain + SSA) — required by documented printers and by the
   dependency analysis; SSA is additive, never replacing plain IR.
4. **Finding identity = hash(rule id + normalized element signature)** so triage and
   SARIF `fingerprints` are stable across line-number churn.
5. **Suppressions parsed by the framework**, not detectors — uniform behavior.
6. **Vyper**: out of v1 scope; the pipeline is language-adapter-ready (parse stage is
   pluggable), matching the reference tool's documented multi-language direction.

Open questions for the lead/user: final package name; minimum Solidity version for
full support; whether Vyper lands in v2; printer catalog subset for v1.

---

## Appendix A — Public sources used (clean-room provenance)

- Project README (feature list, detector table with impact/confidence, printer list,
  tools list, CLI quick usage): `https://github.com/crytic/slither`
- Wiki — *Usage* (CLI flags, detector/printer selection, path filtering, triage mode,
  configuration file keys): `https://github.com/crytic/slither/wiki/Usage`
- Wiki — *Adding a new detector* (detector metadata + result contract):
  `https://github.com/crytic/slither/wiki/Adding-a-new-detector`
- Wiki — *Printer documentation* (printer catalog/behavior):
  `https://github.com/crytic/slither/wiki/Printer-Documentation`
- Wiki — *Python API* (object traversal concepts):
  `https://github.com/crytic/slither/wiki/Python-API`
- Wiki — *SlithIR* (IR rationale, variable taxonomy, operator catalog):
  `https://github.com/crytic/slither/wiki/SlithIR`
- Wiki — *SlithIR SSA* (SSA purpose): `https://github.com/crytic/slither/wiki/SlithIR-SSA`
- Wiki — *Data dependency* (is_dependent semantics, contexts):
  `https://github.com/crytic/slither/wiki/Data-dependency`
- Wiki — *JSON output* (output schema):
  `https://github.com/crytic/slither/wiki/JSON-output`
- J. Feist, G. Grieco, A. Groce, *Slither: A Static Analysis Framework For Smart
  Contracts*, WETSEB'19 (pipeline stages, SSA φ-placement for state variables,
  storage-alias analysis, protected-function heuristic, design goals):
  `https://arxiv.org/abs/1908.09878`
- Compilation-abstraction README (supported platforms, artifact export, library
  linking): `https://github.com/crytic/crytic-compile`
- Auto-generated API documentation index (public API surface concepts only):
  `https://crytic.github.io/slither/`

No source files were read, copied, or paraphrased for this document.
