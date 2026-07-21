# Functional Specification — Printers, Auxiliary Tools, and CLI Surface

**Project:** Clean-room reimplementation of a Solidity static analyzer (functionally equivalent to Trail of Bits' Slither).
**Audience:** Implementers who have never seen Slither's source code.
**Provenance:** This document was produced exclusively from **public documentation**: the project README, the public GitHub wiki ("Printer documentation", "Usage", "JSON output", "Detector documentation"), the "Building Secure Contracts" docs site (secure-contracts.com tool guides), the public API reference landing pages (module/CLI names only), the `slither-action` README, and the normative texts of EIP-20, EIP-721, and EIP-1155. **No Slither source code was consulted or copied.**
**Conventions:**
- Statements marked *(documented)* come from the sources above. Statements marked *(inference)* are reasonable design extrapolations an implementer may adjust.
- "The analyzer" refers to our reimplementation; upstream command names (`slither`, `slither-check-erc`, ...) are kept as CLI-compatible names to match.
- Severity taxonomy used across outputs: `High`, `Medium`, `Low`, `Informational`, `Optimization`. Confidence taxonomy: `High`, `Medium`, `Low`. *(documented)*

---

## A. PRINTERS (code-comprehension outputs)

### A.0 Printer execution model (applies to all printers)

- Printers are **read-only, code-comprehension reports** computed from the analyzer's intermediate model of the codebase (contracts, functions, CFG, inheritance, data dependencies). They do not report vulnerabilities; detectors do. *(documented)*
- Printers are **off by default**; they run only when requested: `slither TARGET --print printer1,printer2`. `--list-printers` lists all available printers. *(documented)*
- Output channels:
  1. **Colorized human-readable text** on stdout/log (prefixed `INFO:Printers:` upstream; colorization can be disabled). Tables are rendered as ASCII "pretty tables" (`+---+` grid style). *(documented)*
  2. **Graphviz `.dot` files** written to disk for graph printers (`inheritance-graph`, `call-graph`, `cfg`). The output file path is logged. Visualization is external: `xdot file.dot` or `dot file.dot -Tsvg -o file.svg`. *(documented)*
- Multiple printers may be selected in one run (comma-separated). *(documented)*

### A.1 Printer summary table

| # | Name | Category | Output channel | One-line function |
|---|------|----------|----------------|-------------------|
| 1 | `human-summary` | Quick review | text | Human-readable project summary: issue counts + per-contract traits |
| 2 | `inheritance-graph` | Quick review | `.dot` file | Inheritance graph of the codebase |
| 3 | `call-graph` | In-depth | `.dot` file(s) | Call graph of the contracts |
| 4 | `cfg` | In-depth | `.dot` file(s) | Control-flow graph of every function |
| 5 | `contract-summary` | Quick review | text | Quick per-contract overview (functions + visibility) |
| 6 | `function-summary` | In-depth | text tables | Per-function summary: visibility, modifiers, reads, writes, calls |
| 7 | `vars-and-auth` | In-depth | text table | State variables written and `msg.sender` authorization conditions per function |
| 8 | `variable-order` | In-depth | text table | State variables in storage declaration order |
| 9 | `loc` | Quick review | text | Line counts (LOC/SLOC/CLOC) split by source/dependency/test |
| 10 | `not-pausable` | In-depth | text | Functions not guarded by a `whenNotPaused` modifier |
| 11 | `entry-points` | Quick review | text | State-changing externally callable functions and their variables |
| 12 | `solc-version` | Informational | text | Solidity compiler version constraints in use and risky versions |
| 13 | `authorization` | In-depth | text table | Alias/companion of `vars-and-auth` (authorization conditions on `msg.sender`) |

Provenance notes for #12 and #13 are given in their sections below.

---

### A.2 `human-summary`

**What it does:** Prints a human-readable executive summary of the whole analysis. *(documented)*

**Output content:**
- **Global detector tally:** number of findings per severity (informational, low, medium, high; optimization counts may also appear). *(documented)*
- **Per contract block**, e.g.:
  - Contract name.
  - `Complex code?` Yes/No — heuristic assessment of overall contract complexity.
  - `Number of functions:` count.
  - Token-trait heuristics when the contract looks like a token: `Is ERC20 token: True/False`, `Can be paused:`, `Minting restriction:`, `ERC20 race condition mitigation:` (whether the `approve` front-running race is mitigated). *(documented; the upstream example prints exactly these fields for an ERC20-like contract)*

**Format:** Plain text lines with color highlighting, printed to the log. *(documented)*

**Implementation notes:** *(inference)* Complexity can be derived from metrics such as cyclomatic complexity / number of functions / inheritance depth; token traits are detected by matching the ERC-20 function surface and scanning for pausing/minting/allowance-set-to-zero-before-increase patterns.

---

### A.3 `inheritance-graph`

**What it does:** Exports the inheritance relationships between all contracts of the codebase to a single Graphviz `.dot` file. *(documented)*

**Output content:**
- One **record node per contract**, containing the contract name, its public functions, and its state variables.
- **Directed edges from a derived contract to each immediate base contract.** When a contract has multiple bases, edges are **labelled with the 1-based inheritance declaration order** (e.g. `C is A, B` yields edges `C -> A [label=1]`, `C -> B [label=2]`).
- **Visual indicators** *(documented)*:
  - Functions that **override a parent's function** are highlighted (orange upstream).
  - Functions that **collide through multiple inheritance** (no direct override but same signature via two parents, where linearization chooses one) are emphasized in a note at the bottom of the affected contract's node (grey upstream).
  - Variables that **overshadow (shadow) a parent's variable** are highlighted (red upstream).
  - Variables of **contract type** display the referenced contract name in parentheses (blue upstream).

**Format:** `.dot` text file (e.g. `<target>.dot`); the log line reports the written path (`Inheritance Graph: <path>`). Rendering via `xdot`/`dot`. *(documented)*

---

### A.4 `call-graph`

**What it does:** Exports the function call graph of the contracts to Graphviz `.dot` file(s). *(documented)*

**Output content:**
- **Ellipse node per function**, grouped visually into one **cluster (box) per contract** (constructors appear as `constructor` nodes).
- **Directed edge caller -> callee** for every call: internal calls within the contract, cross-contract calls, and library calls.
- Calls to **Solidity built-ins** (e.g. `keccak256()`) are grouped in a synthetic `[Solidity]` cluster so external and built-in calls are visible. *(documented, from the published example graph)*

**Format:** One `.dot` file per contract (upstream naming example: `<file>.sol.<Contract>.call-graph.dot`); path logged. Rendering via `xdot`/`dot -Tpng`. *(documented)*

**Notes:** *(inference)* "Call" should include high-level calls, library `using for` calls, and low-level calls where the destination can be resolved; dynamic calls to unresolvable targets may be omitted or represented as unknown.

---

### A.5 `cfg`

**What it does:** Exports the **control-flow graph of every function** to Graphviz `.dot` files. *(documented)*

**Output content:**
- One graph per function (all functions of all contracts, including modifiers and the constructor).
- **One node per basic block**, labelled with the block's statements/expressions (upstream labels include the node kind such as `ENTRY_POINT`, `NEW VARIABLE`, `RETURN`, `IF`, ... and the source expression).
- **Directed edges for control flow**, including branch edges out of condition nodes and loop back-edges; function calls may link to the callee's graph or be shown inline depending on implementation. *(partially inference)*

**Format:** `.dot` files, one per function (e.g. `<function>.dot`); rendering via `xdot`/`dot`. *(documented)*

---

### A.6 `contract-summary`

**What it does:** Prints a **quick per-contract overview**. *(documented)*

**Output content:** For each contract:
- Header line `+ Contract <Name>`.
- One line per function: `- <name> (<visibility>)`, with visibility shown for each function (`public`, `private`, `external`, `internal`), color-coded. *(documented from the published example output)*

**Format:** Plain text with color highlighting. *(documented)*

**Notes:** *(inference)* Useful as a first-look map of a contract's surface; may also include state variables and inheritance info in extended versions — keep the documented core (functions + visibility) as the required output.

---

### A.7 `function-summary`

**What it does:** Prints a **summary of every function of every contract**, showing for each function: visibility, modifiers, state variables read, state variables written, internal calls, and external calls. *(documented)*

**Output content:** For each contract:
- `Contract vars:` list of state variables; `Inheritances:` list of base contracts.
- A table with columns:
  `Function | Visibility | Modifiers | Read | Write | Internal Calls | External Calls`
  where Read/Write list variables read/written (including special variables such as `msg.sender` when read), and the call columns list called signatures. *(documented, from the published example)*
- A second table for **modifiers** with columns:
  `Modifiers | Visibility | Read | Write | Internal Calls | External Calls`. *(documented)*

**Format:** ASCII pretty table per contract, printed to the log. *(documented)*

---

### A.8 `vars-and-auth`

**What it does:** Prints, for every function of every contract, the **state variables it writes** and the **authorization conditions it enforces on `msg.sender`**. Purpose: answer "who is allowed to do what" at a glance. *(documented)*

**Output content:** Per contract, a table with columns:
`Function | State variables written | Conditions on msg.sender`
- *State variables written*: the set of state variables assigned anywhere in the function, including through internal calls it makes (transitively).
- *Conditions on `msg.sender`*: the string forms of conditional expressions — from `if(...)` conditions and `require(...)`/`assert(...)` calls — that read `msg.sender`, collected from the function itself, its modifiers, and the internal functions it calls. Example row:
  `mint | ['balances'] | ['require(bool)(msg.sender == owner)']`. *(documented)*

**Format:** ASCII pretty table per contract. *(documented)*

---

### A.9 `variable-order`

**What it does:** Prints the **storage (declaration) order of the state variables** of each contract — i.e., the sequence in which variables occupy storage slots, accounting for inherited variables (base-contract variables come first in C3-linearization order). *(documented for the printer; the linearization remark is inference)*

**Output content:** Per contract, a table with columns `Name | Type`, one row per state variable in storage order. *(documented)*

**Format:** ASCII pretty table per contract. *(documented)*

**Use:** This is the layout view used when reviewing upgradeable contracts for storage collisions (see B.2). *(inference)*

---

### A.10 `loc`

**What it does:** Counts lines of code in the analyzed codebase, split by file role. *(documented)*

**Output content:** Totals for:
- **LOC** — total lines,
- **SLOC** — source (non-empty, non-comment) lines,
- **CLOC** — comment lines,
each broken down by:
- **SRC** — project source files,
- **DEP** — dependency files (e.g. `node_modules`, `lib`),
- **TEST** — test files. *(documented)*

**Format:** Human-readable text/table summary printed to the log. *(documented)*

**Notes:** *(inference)* File-role classification follows the compilation framework's layout and/or conventional path heuristics (`test/`, `tests/`, `.t.sol`, `node_modules/`, `lib/`).

---

### A.11 `not-pausable`

**What it does:** Prints the functions that **do not use the `whenNotPaused` modifier** — i.e., in codebases that implement an OpenZeppelin-style pausable pattern, the functions that remain active while the contract is paused. *(documented)*

**Output content:** Per contract, the list of functions lacking the `whenNotPaused` guard. *(documented)*

**Format:** Human-readable text list. *(documented)*

**Notes:** *(inference)* The meaningful scope is external/public **state-changing** functions of pausable contracts (view functions and the pause/unpause admin functions themselves are noise); checking the modifiers of the function and of any function it delegates to is a reasonable refinement.

---

### A.12 `entry-points`

**What it does:** Prints **all state-changing entry-point functions of the contracts and their variables** — the externally reachable functions (`external`/`public`) through which an arbitrary caller can mutate contract state. *(documented)*

**Output content:** Per contract, the list of externally callable, non-`view`/`pure` functions, each with the state variables it reads and/or writes. *(documented for the function list; the read/write detail is inference from "and their variables")*

**Format:** Human-readable text list. *(documented)*

**Use:** Attack-surface review: the natural starting point for audits and for building fuzzing harnesses. *(inference)*

---

### A.13 `solc-version`

**Provenance:** Upstream, `solc-version` is documented as an *informational detector* ("Incorrect Solidity version"); no distinct printer of this name appears in the current public printer catalog. It is specified here as a **code-comprehension output** because it reports codebase-wide facts rather than a single defect location. *(documented + inference)*

**What it does:** Reports the **Solidity compiler version requirements in use across the codebase** and flags version constraints that are risky:
- Collect every `pragma solidity <constraint>;` directive (and report if different files use different constraints — see also the `pragma` detector's concept).
- Flag constraints that:
  - allow **outdated compiler versions** (old versions miss newer security checks; deploying with anything below 0.8.x is discouraged),
  - allow versions with **known severe bugs** (cross-checked against the public Solidity bugs list),
  - are **overly complex** (e.g. compound constraints such as `>=0.4.0 <0.9.0`). *(documented, from the Detector documentation for `solc-version`)*

**Recommendation text (to embed in output):** Deploy with a recent Solidity version (at least `0.8.0`) with no known severe issues; use a simple pragma that allows any of those versions; consider the latest Solidity for testing. *(documented)*

**Output content:** For each flagged constraint: the constraint string, the reason (outdated / known severe issues / complex), and the list of source locations using it. *(documented from the published finding format: "Version constraint X contains known severe issues ... It is used by: - X (file.sol#line)")*

**Format:** Human-readable text. *(documented)*

---

### A.14 `authorization`

**Provenance:** The upstream printer module that implements `vars-and-auth` is internally named "authorization" (the wiki section is titled "Variables written and authorization"); the CLI-facing printer name is `vars-and-auth`. This entry documents the same capability under the conceptual name, so implementations may expose both names as aliases. *(documented)*

**What it does:** Reports the **authorization posture of every function**: which functions are gated by checks on `msg.sender` and what those checks are — together with the state variables each function can modify. A function with **no** `msg.sender` condition that writes state is an unprotected state-changing function — the key review question this output answers. *(documented + inference)*

**Output content / format:** Identical to A.8 (`vars-and-auth`): per-contract ASCII table
`Function | State variables written | Conditions on msg.sender`, where conditions are the `if`/`require`/`assert` expressions reading `msg.sender`, gathered through the function, its modifiers, and its internal call chain. *(documented)*

---

### A.15 Other printers existing upstream (context, not required)

The public printer catalog also documents: `constructor-calls` (C3-linearized constructor call sequence), `data-dependency` (per-variable data-dependency tables), `echidna` (Echidna guidance export, WIP), `evm` (EVM instructions per CFG node), `function-id` (keccak256 4-byte selectors), `inheritance` (textual inheritance relations), `modifiers` (modifiers used per function), `require` (require/assert expressions per function), `slithir` / `slithir-ssa` (IR dumps), `declaration`, `dominator`, code-metric printers (`ck`, `halstead`, `martin`), and `cheatcodes` (Foundry cheatcode usage). These are optional extensions for feature parity beyond this spec's scope. *(documented)*

---

## B. AUXILIARY TOOLS

All auxiliary tools are separate CLI entry points that reuse the analyzer's compilation and analysis pipeline. They accept the same *target* forms as the main command (Solidity file, framework project directory, or — where documented — an on-chain contract address with verified source). *(documented)*

---

### B.1 ERC conformance checker — `slither-check-erc`

#### B.1.1 Purpose and invocation

**Function:** Verify that a contract conforms to a given ERC token standard. *(documented)*

**Invocation:** `slither-check-erc <target> <ContractName> [--erc <standard>]`
- `<target>`: a `.sol` file, a project directory, or a deployed contract address (works on addresses, e.g. `slither-check-erc 0xdac17f... TetherToken --erc erc20`). *(documented)*
- `<ContractName>`: contract to check (case sensitive).
- `--erc`: the standard to check against; when omitted, a default (ERC-20) is used. *(documented)*

**Supported standards (upstream):** ERC-20, ERC-223, ERC-777, ERC-721, ERC-165, ERC-1155, ERC-1820, ERC-4524, ERC-1363, ERC-2612, ERC-4626. This spec details ERC-20/721/1155 below. *(documented)*

#### B.1.2 What is checked (tool-level requirements)

For the selected standard, the checker verifies: *(documented)*
1. **All required functions are present** (exact names and parameter types).
2. **All required events are present** (exact names and parameter types).
3. **Functions return the correct types** (e.g. `transfer` must return `bool`, `balanceOf` must return `uint256`).
4. **Functions that must be `view` are `view`** (mutability conformance; a stricter mutability than the standard's is a violation only where it breaks the guarantee — see EIP-721 mutability rules in B.1.4).
5. **Event parameters are correctly `indexed`** per the standard.
6. **Functions actually emit the mandated events** (e.g. `transfer` emits `Transfer`).
7. **Derived contracts do not break conformance** (inherited members count toward conformance; broken overrides are flagged).

Optional standard members (e.g. ERC-20 `name`/`symbol`/`decimals`) are reported as **missing (optional)** rather than hard failures. *(documented)*

#### B.1.3 Output format

Human-readable **checklist** printed to stdout, one section per standard, using `[ ]` for unmet and `[✓]` for met requirements, with indented sub-checks per function/event. Canonical example (from the docs, shortened):

```
# Check ERC20
## Check functions
[ ] totalSupply() is missing
[ ] balanceOf(address) is missing
[✓] transfer(address,uint256) is present
	[ ] transfer(address,uint256) -> () should return bool
	[✓] Transfer(address,address,uint256) is emitted
[ ] name() is missing (optional)
## Check events
[✓] Transfer(address,address,uint256) is present
	[✓] parameter 0 is indexed
	[ ] parameter 1 should be indexed
[ ] Approval(address,address,uint256) is missing
```
*(documented)*

#### B.1.4 Standard-derived requirement tables

The following requirements are derived directly from the EIP texts (normative MUST/SHOULD). The checker tests the statically verifiable ones (presence, signatures, return types, mutability, indexing, event emission sites); the MUST-revert conditions below are listed for completeness as the standard's behavioral rules (a static checker can only heuristically detect some, e.g. missing zero-address checks). *(documented from EIPs; split into static vs behavioral is inference)*

##### ERC-20 (EIP-20)

Required functions:
| Function | Signature / return | Mutability | Notes |
|---|---|---|---|
| `totalSupply` | `totalSupply() -> uint256` | view | total token supply |
| `balanceOf` | `balanceOf(address) -> uint256` | view | |
| `transfer` | `transfer(address, uint256) -> bool` | non-view | MUST fire `Transfer`; SHOULD throw if sender balance insufficient; 0-value transfers MUST be treated as normal transfers and fire `Transfer` |
| `transferFrom` | `transferFrom(address, address, uint256) -> bool` | non-view | MUST fire `Transfer`; SHOULD throw unless `_from` authorized the caller; 0-value transfers likewise allowed |
| `approve` | `approve(address, uint256) -> bool` | non-view | MUST fire `Approval` on any successful call; re-approving overwrites allowance |
| `allowance` | `allowance(address, address) -> uint256` | view | |

Optional functions (reported as optional when missing): `name() -> string` (view), `symbol() -> string` (view), `decimals() -> uint8` (view).

Required events:
| Event | Signature | Indexing / emission rules |
|---|---|---|
| `Transfer` | `Transfer(address indexed _from, address indexed _to, uint256 _value)` | both address params indexed; MUST trigger on any transfer incl. zero-value; minting SHOULD emit `Transfer` with `_from = 0x0` |
| `Approval` | `Approval(address indexed _owner, address indexed _spender, uint256 _value)` | both address params indexed; MUST trigger on any successful `approve` |

##### ERC-721 (EIP-721)

A compliant contract MUST implement the ERC-721 interface **and ERC-165** (`supportsInterface(bytes4) -> bool`, interface id `0x80ac58cd`).

Required functions (payable functions MAY be implemented with a stronger, non-payable mutability; `external` in the spec MAY be `public` in the implementation):
| Function | Signature / return | Mutability per spec | MUST-throw conditions (from EIP-721) |
|---|---|---|---|
| `balanceOf` | `balanceOf(address) -> uint256` | view | throw for queries about the zero address |
| `ownerOf` | `ownerOf(uint256) -> address` | view | throw if the token id is not a valid NFT |
| `safeTransferFrom` (4 args) | `safeTransferFrom(address, address, uint256, bytes)` | payable | throw unless `msg.sender` is owner/operator/approved; throw if `_from` is not current owner; throw if `_to` is zero address; throw if token id invalid; if `_to` is a contract, call `onERC721Received` and throw unless it returns `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))` |
| `safeTransferFrom` (3 args) | `safeTransferFrom(address, address, uint256)` | payable | identical, with `data = ""` |
| `transferFrom` | `transferFrom(address, address, uint256)` | payable | same throw conditions minus the receiver check (unsafe variant) |
| `approve` | `approve(address, uint256)` | payable | throw unless `msg.sender` is the token owner or an authorized operator of the owner |
| `setApprovalForAll` | `setApprovalForAll(address, bool)` | non-view | MUST allow multiple operators per owner; emits `ApprovalForAll` |
| `getApproved` | `getApproved(uint256) -> address` | view | throw if token id invalid |
| `isApprovedForAll` | `isApprovedForAll(address, address) -> bool` | view | |

Required events:
| Event | Signature | Rules |
|---|---|---|
| `Transfer` | `Transfer(address indexed _from, address indexed _to, uint256 indexed _tokenId)` | all three params indexed; emits on any ownership change; `_from == 0` on mint, `_to == 0` on burn; a transfer resets the approved address |
| `Approval` | `Approval(address indexed _owner, address indexed _approved, uint256 indexed _tokenId)` | emits when the approved address changes/reaffirms |
| `ApprovalForAll` | `ApprovalForAll(address indexed _owner, address indexed _operator, bool _approved)` | emits when an operator is enabled/disabled |

Optional extensions (checked when selected): `ERC721Metadata` (`name`, `symbol`, `tokenURI`) and `ERC721Enumerable` (`totalSupply`, `tokenByIndex`, `tokenOfOwnerByIndex`).

##### ERC-1155 (EIP-1155)

A compliant contract MUST implement all `ERC1155` functions plus ERC-165 (`supportsInterface` MUST return `true` for `0xd9b67a26`).

Required functions:
| Function | Signature / return | Mutability | MUST-revert / behavioral conditions (from EIP-1155) |
|---|---|---|---|
| `safeTransferFrom` | `safeTransferFrom(address _from, address _to, uint256 _id, uint256 _value, bytes _data)` | non-view | revert if `_to` is zero address; revert if holder balance of `_id` < `_value`; revert on any other error; MUST emit `TransferSingle`; if `_to` is a contract, MUST call `onERC1155Received` and revert unless it returns `0xf23a6e61`; `_data` MUST be passed unaltered |
| `safeBatchTransferFrom` | `safeBatchTransferFrom(address _from, address _to, uint256[] _ids, uint256[] _values, bytes _data)` | non-view | revert if `_to` is zero; revert if `_ids.length != _values.length`; revert on any insufficient balance; revert on any other error; MUST emit `TransferSingle`/`TransferBatch` covering all balance changes, in array order; if `_to` is a contract, MUST call `onERC1155BatchReceived` and revert unless it returns `0xbc197c81` |
| `balanceOf` | `balanceOf(address _owner, uint256 _id) -> uint256` | view | |
| `balanceOfBatch` | `balanceOfBatch(address[] _owners, uint256[] _ids) -> uint256[]` | view | one balance per (owner, id) pair |
| `setApprovalForAll` | `setApprovalForAll(address _operator, bool _approved)` | non-view | MUST emit `ApprovalForAll` on success |
| `isApprovedForAll` | `isApprovedForAll(address _owner, address _operator) -> bool` | view | |

Required events:
| Event | Signature | Rules |
|---|---|---|
| `TransferSingle` | `TransferSingle(address indexed _operator, address indexed _from, address indexed _to, uint256 _id, uint256 _value)` | MUST emit on any single-token transfer incl. zero-value, mint (`_from = 0x0`) and burn (`_to = 0x0`) |
| `TransferBatch` | `TransferBatch(address indexed _operator, address indexed _from, address indexed _to, uint256[] _ids, uint256[] _values)` | same for batch; `_ids`/`_values` same length and order |
| `ApprovalForAll` | `ApprovalForAll(address indexed _owner, address indexed _operator, bool _approved)` | MUST emit when operator approval is enabled/disabled |
| `URI` | `URI(string _value, uint256 indexed _id)` | MUST emit when the URI for a token id changes (if the metadata extension is implemented) |

Optional extension: `ERC1155Metadata_URI` (`uri(uint256) -> string`), ERC-165 id `0x0e89341c`. Balances MUST be updated and transfer events emitted **before** receiver hooks are called; events alone MUST be sufficient to reconstruct balances. *(all documented from EIP-1155)*

---

### B.2 Upgradeability checker — `slither-check-upgradeability`

#### B.2.1 Purpose and invocation

**Function:** Review contracts that use the **`delegatecall`-based proxy upgradeability pattern** (a proxy contract forwards calls via `delegatecall` to a logic/implementation contract, so all state lives in the proxy's storage while code lives in the implementation). It statically detects the classic failure classes of this pattern. *(documented)*

**Invocation:**
```
slither-check-upgradeability <project> <ContractName> \
    [--new-contract-name V2Name [--new-contract-filename project2]] \
    [--proxy-name ProxyName [--proxy-filename proxy_project]]
```
- `<project>`: Solidity file or framework directory. *(documented)*
- `--new-contract-name/--new-contract-filename`: compare the logic contract against its planned upgrade (V2). The filename is only needed if V2 is in a different codebase. *(documented)*
- `--proxy-name/--proxy-filename`: also review the proxy contract (e.g. an OpenZeppelin/zos proxy living in another repo). *(documented)*
- `--json`: machine-readable output (see C.4.2). *(documented)*

#### B.2.2 Check catalog (17 checks)

Applicability columns: **Proxy** = requires `--proxy-name`; **V2** = requires `--new-contract-name`. *(all documented)*

| # | Check | Impact | Proxy | V2 | What it detects |
|---|-------|--------|-------|----|-----------------|
| 1 | `became-constant` | High | | X | A variable that was non-constant in V1 became `constant` in V2 — removes a storage slot and shifts the layout of every later variable (storage corruption). |
| 2 | `function-id-collision` | High | X | | A proxy function's 4-byte selector collides with an implementation function's selector (different names, same selector) — the proxy function shadows the implementation function. |
| 3 | `function-shadowing` | High | X | | A proxy function has the same name/signature as an implementation function — calls never reach the logic contract and cannot be upgraded. |
| 4 | `missing-calls` | High | | | A derived contract's `initialize` does not call a base contract's `initialize` (missing init call in the inheritance chain). |
| 5 | `missing-init-modifier` | High | | | The `initialize` function lacks the `Initializable.initializer` modifier, so it can be invoked multiple times (re-initialization). |
| 6 | `multiple-calls` | High | | | The same `initialize` function is called more than once along one initialization path. |
| 7 | `order-vars-contracts` | High | | X | V1 and V2 state variables differ in order/type — the two versions do not share a storage layout. |
| 8 | `order-vars-proxy` | High | X | | Proxy and implementation state variables differ — layouts must match for any variable that exists in both. |
| 9 | `variables-initialized` | High | | | A state variable is initialized at declaration (`uint x = 10;`) — the assignment runs only in the implementation's context and is invisible through the proxy; use an initialize function instead. |
| 10 | `were-constant` | High | | X | A `constant` variable in V1 became non-constant in V2 — inserts a storage slot and shifts the layout. |
| 11 | `extra-vars-proxy` | Medium | X | | Variables present in the proxy but not in the implementation — a later implementation upgrade may corrupt the proxy's storage. |
| 12 | `missing-variables` | Medium | | X | Variables present in V1 but removed in V2 — a still-later V3 adding a variable at that position would read stale values. |
| 13 | `extra-vars-v2` | Informational | | X | Variables newly added in V2 — review aid; must only ever be appended after all V1 variables. |
| 14 | `init-inherited` | Informational | | | The contract does not inherit an `Initializable` helper. |
| 15 | `init-missing` | Informational | | | No `Initializable` contract is present in the codebase. |
| 16 | `initialize-target` | Informational | | | Reports the initialize function(s) that must be called at deployment (checklist aid). |
| 17 | `initializer-missing` | Informational | | | The `Initializable.initializer` modifier is not used anywhere. |

#### B.2.3 Functional concepts an implementation must model

- **Initializer presence and protection (checks 4–6, 9, 14–17):** Because a proxy cannot run the implementation's constructor in its own context, upgradeable contracts replace constructors with an `initialize()` function protected by a once-only guard (the `initializer` modifier from an `Initializable` base, typically implemented with a storage "initialized" flag). The checker verifies: an initialize function exists and is identified (`initialize-target`), it is guarded (`missing-init-modifier`, `initializer-missing`), every base contract's initializer is reachable exactly once from the most-derived one (`missing-calls`, `multiple-calls`), no state variable relies on declaration-time initialization (`variables-initialized`), and the standard `Initializable` pattern is used (`init-missing`, `init-inherited`). *(documented check semantics; the Initializable-flag mechanism is widely documented background)*
- **Storage-layout compatibility (checks 1, 7, 8, 10–13):** `delegatecall` executes implementation code against the proxy's storage, so variables are matched **by position, not by name**. The checker extracts the ordered (name, type) state-variable sequence of V1/proxy and V2 and requires that: the common prefix is identical in order and type; a variable never changes `constant` status either way; variables are never deleted (only appended); and the proxy introduces no extra variables the implementation does not know about. *(documented)*
- **Missing gap variables:** Upgradeable base contracts conventionally reserve storage for future variables by declaring a "storage gap" array (e.g. `uint256[50] private __gap;`) sized so that `50 - (number of inherited variables)` slots remain; subclasses then reduce the gap when adding variables. Gaps exist precisely to satisfy the layout rules above when a *base* contract (not the most-derived one) gains variables. Note: the documented upstream checks do not include an explicit "missing gap" rule — gap compliance is a consumer of the same layout comparison (if a base adds variables without shrinking its gap, `order-vars-contracts` fires on every derived contract). Implementations may additionally offer a dedicated gap-consistency check (base added variables ⟺ gap shrunk by the same number of slots) as an enhancement. *(inference, based on EIP-7201/OpenZeppelin conventions and the documented check semantics)*
- **Function-surface collision (checks 2–3):** Any `external`/`public` function on the proxy intercepts calls meant for the implementation; collisions are detected both by identical name+parameters and by identical 4-byte selector (first 4 bytes of the keccak256 of the signature). *(documented)*

#### B.2.4 Output

Human-readable findings (same finding format as detectors: description, source references, impact) plus, with `--json`, a machine-readable `upgradeability-check` object (schema in C.4.2). *(documented)*

---

### B.3 Code flattener — `slither-flat`

#### B.3.1 What flattening means

**Function:** Merge a multi-file Solidity codebase into **standalone, compilable Solidity source file(s)** by textually inlining the import graph: every `import` is replaced by the imported file's contents, each original source unit is emitted exactly once (imports are **deduplicated** — a file imported N times appears once), `pragma` directives and SPDX license identifiers are **merged/deduplicated** into a single file preamble, and circular dependencies between files are tolerated. The result contains no `import` statements (strategy-dependent) and can be pasted into tools that only accept one file (block explorers' verifier, Remix, Echidna). *(documented features: code flattening, multiple strategies, circular dependency support, all compilation platforms)*

**Invocation:** `slither-flat <target>` where target is any supported project/file. `--contract <Name>` restricts output to one contract (standalone file). *(documented)*

#### B.3.2 Strategies (`--strategy`)

| Strategy | Behavior |
|---|---|
| `MostDerived` (default) | Export **each most-derived contract** (contracts not inherited by any other) into **its own standalone file** (file contains the contract plus everything it needs). |
| `OneFile` | Export **the entire codebase into one standalone file**. |
| `LocalImport` | Export **every contract into a separate file** and express their dependencies as local `import "./...";` statements in each file's prelude. |

*(documented)*

#### B.3.3 Source-to-source patching options

- `--convert-external`: rewrite `external` functions to `public` — facilitates Echidna harnesses (Echidna historically cannot call `external` functions in some setups). *(documented)*
- `--remove-assert`: remove `assert()` calls. *(documented)*
- `--contract <name>`: flatten only the target contract. *(documented)*

#### B.3.4 Export options

- `--dir <DirName>`: output directory for generated files. *(documented)*
- `--json file.json` / `--json -`: export results as JSON (stdout with `-`). *(documented)*
- `--zip file.zip` with `--zip-type` (`lzma` default): export as a ZIP archive. *(documented)*

**Implementation notes:** *(inference)* Deduplication is keyed on source unit (file path), not on symbol; name collisions between files are assumed already disambiguated by the compiler's namespacing (`import {X as Y}` aliasing must be preserved). SPDX license merging keeps a single license comment to satisfy the compiler's license requirements.

---

### B.4 Interface generator — `slither-interface`

#### B.4.1 Purpose and invocation

**Function:** Generate **Solidity interface source code** for a given contract: an `interface` declaration exposing the contract's **public and external functions** as function prototypes, so other contracts/tests can interact with it without importing its implementation. *(documented)*

**Invocation:** `slither-interface <ContractName> <source>` where `<source>` is a project directory/filename for local contracts **or a deployed address** (the verified source is fetched from an Etherscan-like platform; a chain prefix selects the network). *(documented)*

#### B.4.2 Generated content

- One `interface` (named after the contract, e.g. `I<ContractName>` upstream-style) containing, for every `public`/`external` function of the contract: the function prototype with `external` visibility, original parameter types/names, mutability (`view`/`pure`/`payable`), and return types. *(documented for the core behavior; interface naming/visibility details are inference)*
- **Supporting type declarations**, included by default and individually excludable: *(documented flags)*
  - `--exclude-events`: omit event signatures.
  - `--exclude-errors`: omit custom error signatures.
  - `--exclude-enums`: omit enum definitions.
  - `--exclude-structs`: omit struct definitions.
- `--unroll-structs`: where a function uses a user-defined struct, emit the struct's **underlying component types** instead of the struct type (tuple expansion), so the interface needs no struct definitions. *(documented)*

**Output:** Solidity source printed to stdout (redirect to a file to save). *(documented behavior; channel is inference)*

**Notes:** *(inference)* Public state variables' auto-generated getters are part of the external surface and may be included as function prototypes; constructors, `internal`/`private` functions, and the fallback/receive pair require special-case decisions (fallback/receive can only appear in an interface as `receive`/`fallback` declarations).

---

### B.5 Storage layout reader — `slither-read-storage`

#### B.5.1 Functional concept

**Function:** Compute the **storage layout** of a contract — the exact EVM storage slot and byte offset every state variable occupies, following Solidity's storage layout rules over the contract's full inheritance hierarchy — and optionally **read the live values** of those slots from a node. In short: "given source code and (optionally) an address, show me what is in every storage slot." *(documented)*

**Inputs:**
- A target: `file.sol`, a project directory + address for unverified contracts, or a **deployed address** whose source is verified on an Etherscan-like platform (source is required — the tool is source-driven, not bytecode-driven). *(documented)*
- `--rpc-url <url>`: node endpoint used to fetch values (via `eth_getStorageAt`-style queries); required only when values are requested. *(documented)*

**Core capabilities (documented flags):**
- Print the whole layout: every state variable with its **slot, offset, type, and size**.
- Drill down:
  - `--variable-name <name>`: restrict to one variable.
  - `--key <k>`: read `mapping[k]` or `array[k]` (mapping slots are derived as `keccak256(h(k) . slot)` per Solidity rules — mechanism documented by Solidity; the flag itself is documented).
  - `--deep-key <k>`: key for nested mappings / multidimensional arrays.
  - `--struct-var <member>`: select a struct member.
  - `--max-depth <n>`: bound recursion into deep data structures.
- **Proxy support:** `--storage-address <addr>` reads slots at the proxy address while interpreting them with the logic contract's layout; `--contract-name <name>` disambiguates which contract's layout to use (important because Etherscan returns every source file). *(documented)*
- **Historical reads:** `--block <n>` reads storage at a past block (requires an archive node). *(documented)*
- `--unstructured`: include **unstructured storage slots** (deliberately hash-positioned slots such as EIP-1967's implementation/admin slots, which live outside the sequential layout). *(documented)*

**Outputs:**
- Default human-readable layout listing; `--table` prints a table view of the storage layout. *(documented)*
- `--json <file>`: machine-readable layout (per-variable name/type/slot/offset(/size) entries, plus values when requested). *(documented)*
- `--value`: include the actual on-chain **values** (decoded per type) in the output. *(documented)*
- `--silent`: suppress log output. *(documented)*

**Documented limitations:** requires source code; Solidity only; mappings cannot be enumerated (keys must be supplied); not all data types supported; cannot find variables with unstructured storage unless requested. *(documented)*

---

### B.6 Property / unit-test generator — `slither-prop`

#### B.6.1 Functional concept and relation to Echidna

**Function:** Automatically generate **testable security properties (invariants)** for a contract, as both (a) **Truffle unit tests** and (b) an **Echidna fuzzing harness** — entirely automatically from the contract's code. Echidna is a property-based fuzzer: it generates random sequences of transactions against a deployed copy of the harness contract and checks, after each transaction, that every property function still holds; any sequence violating a property is minimized and reported as a counterexample. `slither-prop` bridges static analysis and fuzzing by emitting ready-made properties plus the harness boilerplate. *(documented tool purpose; Echidna behavior is documented background of the target tool)*

**Invocation:** `slither-prop <project> --contract <ContractName> [--scenario <NAME>]`. (Documented limitation: upstream initially supports Truffle projects only.) *(documented)*

#### B.6.2 Generated artifacts

For a target contract, the generator writes: *(documented)*
- `contracts/crytic/interfaces.sol` — interfaces needed by the harness.
- `contracts/crytic/Properties<Contract>.sol` — the property predicates (Solidity boolean functions / assertions expressing the invariants).
- `contracts/crytic/Test<Contract>.sol` — the Echidna harness contract, deploying the target and exposing three fixed actors: `crytic_owner`, `crytic_user`, `crytic_attacker`. *(documented workflow + file names; actor set from the documented constructor example)*
- `echidna_config.yaml` — Echidna configuration.
- `migrations/1_Test<Contract>.js` — Truffle migration.
- `test/crytic/InitializationTest<Contract>.js` — unit tests checking the constructor/initial state (e.g. "total supply correctly initialized", "owner/user/attacker balances initialized", "all users have positive balance").
- `test/crytic/Test<Contract>.js` — unit tests executing the property scenarios.

#### B.6.3 Workflow (documented 4-step process)

1. **Generate the tests** (`slither-prop . --contract X`); the tool prints the file list and follow-up commands.
2. **Customize the constructor** of `Test<Contract>.sol` to establish a meaningful initial state (e.g. seed balances for the three actors) and to snapshot initial values (`initialTotalSupply`, `initialBalance_*`).
3. **Run the unit tests** (`truffle test test/crytic/InitializationTest<Contract>.js` then `.../Test<Contract>.js`).
4. **Run Echidna** (`echidna-test . --contract Test<Contract> --config echidna_config.yaml`) for property-based fuzzing of the same properties.

#### B.6.4 Scenarios and generated properties

`--scenario NAME` selects a property bundle (documented scenario list is ERC-20-oriented): `Transferable` (default), `Pausable`, `NotMintable`, `NotMintableNotBurnable`, `NotBurnable`, `Burnable` (requires a `burn(address)` function). Documented property catalog:

| # | Property | Scenario |
|---|----------|----------|
| 0 | The address 0x0 should not receive tokens. | Transferable |
| 1 | Allowance can be changed. | Transferable |
| 2 | Balance of one user must be less or equal to the total supply. | Transferable |
| 3 | Balance of the crytic users must be less or equal to the total supply. | Transferable |
| 4 | No one should be able to send tokens to the address 0x0 (transfer). | Transferable |
| 5 | No one should be able to send tokens to the address 0x0 (transferFrom). | Transferable |
| 6 | Self transferFrom works. | Transferable |
| 7 | transferFrom works. | Transferable |
| 8 | Self transfer works. | Transferable |
| 9 | transfer works. | Transferable |
| 10 | Cannot transfer more than the balance. | Transferable |
| 11 | Cannot transfer (while paused). | Pausable |
| 12 | Cannot execute transferFrom (while paused). | Pausable |
| 13 | Cannot change the balance (while paused). | Pausable |
| 14 | Cannot change the allowance (while paused). | Pausable |
| 15 | The total supply does not increase. | NotMintable |
| 16 | The total supply does not change. | NotMintableNotBurnable |
| 17 | The total supply does not decrease. | NotBurnable |
| 18 | The total supply does not decrease (except via burn). | Burnable |

*(documented)*

**Implementation notes:** *(inference)* Property selection is driven by the contract surface detected by the analyzer (which functions exist: `transfer`, `transferFrom`, `approve`, `burn`, `pause`...); each property is expressed relative to the three fixed actors and checked both as a Truffle test case and as an Echidna invariant; continuous fuzzing of generated properties in CI (e.g. with crytic.io) is the intended end state.

---

### B.7 Other upstream tools (context, not required by this spec)

The upstream "Tool documentation" index references additional utilities beyond the six above, e.g. `slither-format` (automatic patch generation for findings), `slither-simil` (ML-based similar-function detection), `slither-find-paths` (path existence queries), `slither-mutate` (mutation testing), and `slither-doc` (documentation generation). They are mentioned here only for parity planning. *(documented that they exist; descriptions per README/one-liners)*

---

## C. CLI SURFACE

### C.1 Commands and target forms

**Main command:** `slither <target> [flags]`. The auxiliary tools are sibling commands: `slither-check-erc`, `slither-check-upgradeability`, `slither-flat`, `slither-interface`, `slither-read-storage`, `slither-prop`. *(documented)*

**Target forms** *(documented)*:
| Target | Meaning |
|---|---|
| `slither .` | Project directory of a supported framework (Hardhat, Foundry, Truffle, Brownie, Dapp, Embark, Etherlime). Preferred mode — the framework compiles the code and the analyzer consumes its artifacts/ASTs. |
| `slither file.sol` | Standalone Solidity file (only if it has no external dependencies). |
| `slither 0xABC...` | Contract address: verified source is fetched from an Etherscan-like explorer (chain prefixes select non-Ethereum networks, e.g. `avax:0x...`). |
| `slither file.ast.json` | Pre-generated solc AST JSON. |

**Compilation layer:** all compilation is delegated to the analyzer's compilation component, whose flags are also available on every command (compiler selection/pinning such as `--solc`, solc version switching, `--solc-remaps`, `--solc-args`, framework forcing such as `--compile-force-framework`, `--etherscan-apikey`, etc.). The config key namespace for these lives alongside the analyzer's own keys. *(documented that "all the crytic-compile options are available through Slither"; individual flag names are compilation-layer details)*

### C.2 Analysis selection flags

| Flag | Behavior |
|---|---|
| `--detect d1,d2` | Run only the listed detectors (comma-separated). |
| `--exclude d1,d2` | Run all detectors except the listed ones. Default: all detectors run. |
| `--exclude-informational` / `--exclude-optimization` / `--exclude-low` / `--exclude-medium` / `--exclude-high` | Drop findings of the given severity class. |
| `--exclude-dependencies` | Drop findings located in dependency files (config key `exclude_dependencies`). |
| `--list-detectors` | Print the available detectors and exit. |
| `--print p1,p2` | Run the listed printers (none run by default). |
| `--list-printers` | Print the available printers and exit. |

*(all documented)*

### C.3 Output flags

| Flag | Behavior |
|---|---|
| `--json <file>` / `--json -` | Write results as JSON to `<file>` (or stdout with `-`). |
| `--sarif <file>` | Write results as a SARIF file (for code-scanning ingestion / SARIF viewers). |
| `--checklist` | Print a Markdown checklist report to stdout (one checkbox item per finding). |
| `--markdown-root <url>` | Prefix used to build clickable source links in the Markdown report (e.g. `https://github.com/ORG/REPO/blob/COMMIT/`). |
| `--zip <file>` / `--zip-type <type>` | Export results as a ZIP archive (compression `lzma` by default). |
| `--disable-color` | Disable ANSI colorization of human output. |
| `--solc-disable-warnings` | Suppress solc warnings in the output. |
| `--generate-patches` | Emit machine-applicable patches for findings that support them (feeds the `slither-format` patch tool). |
| `--config-file <file>` | Use an alternate JSON configuration file (default: `slither.config.json` if present). |

*(all documented)*

### C.4 Output formats

#### C.4.1 Human-readable text (default)

Structure of a finding in the default terminal output: *(documented from published examples)*
- A log prefix block (`INFO:Detectors:`) followed by the finding description, one line per source element, with compact source references of the form `<name> (<file>#L<start>[-L<end>])`, e.g. `f (test.sol#5-7)`.
- Severity is conveyed by color (red/orange/yellow/blue-green convention by impact) unless `--disable-color`.
- Every finding ends with a `Reference:` line linking to the public detector documentation anchor for that check.
- The run ends with a summary line of the form `<target> analyzed (<N> contracts with <M> detectors), <K> result(s) found`.

#### C.4.2 JSON schema (concept)

Top level — every command shares this envelope: *(documented)*
```json
{
  "success": true,
  "error": null,
  "results": { }
}
```
- `success` (bool): whether results were produced; `error` (string|null): populated when `success` is `false`; `results`: command-specific payload.

`results.detectors` — array of findings, each: *(documented)*
```json
{
  "check": "detector-id",
  "impact": "High|Medium|Low|Informational|Optimization",
  "confidence": "High|Medium|Low",
  "description": "human-readable finding text",
  "elements": [ ... ],
  "additional_fields": { "optional": "detector-specific data" }
}
```
Conventions: the **first element** of `elements` should represent the most significant source region of the finding (the spot external tooling should point at).

Each element: *(documented)*
```json
{
  "type": "contract|function|variable|node|pragma|enum|struct|event",
  "name": "definition name (for nodes: string of the expression; for pragma: the version portion)",
  "source_mapping": {
    "start": 45, "length": 58,
    "filename_relative": "contracts/tests/constant.sol",
    "filename_absolute": "/tmp/contracts/tests/constant.sol",
    "filename_short": "tests/constant.sol",
    "filename_used": "contracts/tests/constant.sol",
    "lines": [5, 6, 7],
    "starting_column": 1, "ending_column": 24
  },
  "type_specific_fields": {
    "parent": "<element object: owning contract or function>",
    "signature": "<functions/events only: full signature>",
    "directive": ["pragma only: serialized directive parts"]
  },
  "additional_fields": { "optional": "detector-specific element data" }
}
```
Source mapping semantics: `start`/`length` are byte offsets; `lines` is 1-based; columns are 1-based; `filename_short` hides platform directories such as `node_modules`. Documented examples of detector-specific `additional_fields`: reentrancy results tag elements with `underlying_type` (`external_calls`, `external_calls_sending_eth`, `variables_written`); naming-convention results tag `convention` and `target`. *(documented)*

`results.upgradeability-check` — produced by `slither-check-upgradeability --json`, grouped into five sub-reports: *(documented)*
```json
{
  "check-initialization": { },
  "check-initialization-v2": { },
  "compare-function-ids": { },
  "compare-variables-order-proxy": { },
  "compare-variables-order-implementation": { }
}
```
(Empty objects when the corresponding comparison was not requested, e.g. no `--proxy-name`/`--new-contract-name`.)

Printer outputs are primarily the text/dot artifacts of Section A; when printers and JSON export are combined, printer results are carried as result entries tagged with the printer name. *(partially inference — the JSON documentation covers detectors and the upgradeability tool explicitly)*

#### C.4.3 SARIF

- `--sarif export.sarif` emits a **SARIF 2.1.0 JSON** document suitable for GitHub Code Scanning and generic SARIF viewers (IDE plugins such as the VS Code Sarif Viewer are explicitly referenced in the docs). *(documented that SARIF export exists and targets code scanning/viewers; "2.1.0" is the SARIF standard version)*
- Conceptual mapping (implement to SARIF spec): one `run` per analysis; each detector becomes a `rule` in `tool.driver.rules` (id = check name, `helpUri` = detector documentation URL); each finding becomes a `result` with `ruleId`, `message`, `level` mapped from impact (conceptually `High -> error`, `Medium/Low -> warning`, `Informational/Optimization -> note`), and `locations` built from the finding's source mappings (`artifactLocation.uri` + `region.startLine`). *(mapping is inference from the SARIF spec and the documented integration; GitHub's code-scanning UI displays severities from this mapping)*
- **SARIF triage interop:** the config keys `sarif_input` (default `export.sarif`) and `sarif_triage` (default `export.sarif.sarifexplorer`) support a triage workflow in which an external SARIF triage tool's state file (a `.sarifexplorer` database: bug/false-positive classifications and comments) is carried alongside the SARIF report. *(documented config keys; workflow described in the vendor's public triage-tool announcement)*

#### C.4.4 Markdown checklist

`--checklist` prints a Markdown report to stdout: findings grouped by detector, each as a `- [ ]` checkbox item with a short description and a source link; combined with `--markdown-root`, links point at the exact file/line on the code host. Used to paste triage-able reports into issues/PRs. *(documented; item layout is inference)*

### C.5 Exit codes and fail thresholds

- Findings-based failure is controlled by a **fail-on severity threshold**: `--fail-pedantic` (fail on any finding, the default), `--fail-low`, `--fail-medium`, `--fail-high`, `--fail-none` (never fail on findings). These flags were introduced in upstream 0.8.4; earlier versions always failed on any finding. The corresponding config key is `fail_on` (default `PEDANTIC`). *(documented via the slither-action README table and the Usage wiki config reference)*
- Behavior: **exit status 0** when no finding at or above the threshold exists (or `--fail-none`); **non-zero exit status** when such findings exist, and on fatal errors (compilation failure, invalid target). *(documented at the "fail/do not fail" level; exact non-zero value is an implementation choice — recommendation: 1 for findings, distinct non-zero for hard errors)*
- CI guidance from the docs: use `--fail-* none`-equivalent settings when producing SARIF for code scanning, so the SARIF upload step runs even when findings exist. *(documented)*

### C.6 Triage and result-filtering behavior

Four documented mechanisms, composable:

1. **Detector-level selection/exclusion** — see C.2.
2. **Path filtering:** `--filter-paths "<path-or-regex>"` excludes every finding whose elements relate *only* to the given paths; both plain substring and regular-expression matching are applied (e.g. `--filter-paths "openzeppelin"`, `--filter-paths "Migrations.sol|ConvertLib.sol"`). A complementary include-paths option exists in config (`include_paths`). *(documented)*
3. **Inline source suppressions** *(documented)*:
   - `//slither-disable-next-line DETECTOR_NAME` — suppress the finding reported on the next line (multiple detectors comma-separated).
   - `// slither-disable-start [detector]` ... `// slither-disable-end [detector]` — suppress a detector over a code region.
   - `@custom:security non-reentrant` — NatSpec tag on a state variable declaration telling the analyzer that external calls through that variable are non-reentrant (informational hint to detectors, e.g. for known non-reentrant ERC-777-like tokens).
4. **Interactive triage mode:** `--triage-mode` prints each finding and prompts `Results to hide during next runs: "0,1,..." or "All" (enter to not hide results)`; selections persist in a local database file `slither.db.json` (path configurable via `triage_database`), and subsequent runs hide the recorded findings. Deleting `slither.db.json` restores them; `--show-ignored-findings` re-displays hidden findings without deleting the database. Finding identity is effectively (detector id + involved source locations), stable across runs. *(documented; identity definition is inference)*

### C.7 Configuration file

- A JSON config file supplies defaults for every option; `slither.config.json` in the working directory is loaded automatically if present, or use `--config-file <file>`. **CLI flags take priority over the config file.** *(documented)*
- Documented keys (Usage wiki): `detectors_to_run`, `printers_to_run`, `detectors_to_exclude`, `detectors_to_include`, `exclude_dependencies`, `exclude_informational`, `exclude_optimization`, `exclude_low`, `exclude_medium`, `exclude_high`, `fail_on`, `json`, `sarif`, `disable_color`, `filter_paths`, `include_paths`, `generate_patches`, `skip_assembly`, `legacy_ast`, `zip`, `zip_type`, `show_ignored_findings`, `sarif_input`, `sarif_triage`, `triage_database` (plus optional AI-assisted triage keys and the compilation-layer keys). *(documented)*

### C.8 Environment/auxiliary behavior worth mirroring

- **Logging:** informational logs are namespaced (`INFO:Detectors:`, `INFO:Printers:`, `INFO:Slither:`); printer and detector text go to stdout/log, artifacts (`.dot`, `.json`, `.sarif`, `.zip`) to files. *(documented)*
- **Graph printers require Graphviz** only for rendering; the analyzer emits `.dot` text without it. *(documented)*
- **Determinism/re-runs:** printers and detectors are pure functions of the compiled AST model; triage state is the only persisted cross-run state (`slither.db.json`). *(inference)*

---

## Appendix — Source documents used

1. crytic/slither README (printer/tool one-liners, `--checklist`, `--markdown-root`, integration notes).
2. crytic/slither GitHub wiki: "Printer documentation" (per-printer outputs and examples), "Usage" (flags, filtering, triage mode, config keys), "JSON output" (schema above), "Detector documentation" (severity/confidence taxonomy, `solc-version`, ERC interface detector semantics).
3. Building Secure Contracts docs (secure-contracts.com mirror of the Slither docs): Upgradeability Checks, ERC Conformance, Contract Flattening, Property Generation, Read Storage, Interface.
4. crytic/slither-action README (`--fail-*` flag semantics across versions, SARIF/code-scanning workflow).
5. EIP-20, EIP-721, EIP-1155 normative texts (all function/event tables and MUST-revert conditions in B.1.4).
6. crytic.github.io public API reference (module/CLI naming only, e.g. confirming the printer name `vars-and-auth`).

*Clean-room statement: no Slither source files were fetched, read, or copied for this specification. Where documentation was ambiguous, items are explicitly marked (inference) rather than reverse-engineered.*
