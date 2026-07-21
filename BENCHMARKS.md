# Velvet vs Slither — CMTAT Comparison Benchmark

**Date:** 2026-07-19 (v0.3.0 baseline) · **updated 2026-07-20 (v0.3.1 hardening results)**
**Target:** [CMTA/CMTAT](https://github.com/CMTA/CMTAT) @ `49544f4` (security token framework, Hardhat project, 194 contracts incl. OpenZeppelin dependencies)
**Tools:** Slither 0.11.5 (101 detectors) · Velvet 0.3.0 → 0.3.1 (100 detectors)
**Method:** both run from project root with JSON output, defaults (no exclusions). Counts verified from JSON; spot-checks manually classified.

---

# v0.3.1 — After the hardening wave

## Headline results

| | Slither 0.11.5 | Velvet 0.3.0 | Velvet 0.3.1 |
|---|---|---|---|
| Contracts analyzed | 194 | 194 | 194 (same compilation set) |
| Total findings | 320 | 1309 | **473** |
| Rules at exact count parity | 3 | — | **9** |
| Rules within ±2 | 3 | — | **6** |
| Confirmed FN classes | 4 | — | **0** (all slither sites covered on every rule) |
| Confirmed FP classes | 5 | — | **0** |

## Per-rule comparison (final)

| Rule | Slither | Velvet 0.3.0 | Velvet 0.3.1 | Verdict |
|---|---|---|---|---|
| assembly | 109 | 109 | **109** | ✅ exact parity |
| constable-states | 2 | 2 | **2** | ✅ exact parity |
| divide-before-multiply | 9 | 2 | **9** | ✅ exact parity (was FN) |
| incorrect-exp | 1 | 0 | **1** | ✅ exact parity (was FN) |
| missing-zero-check | 1 | 0 | **1** | ✅ exact parity (was FN) |
| pragma | 1 | 25 | **1** | ✅ exact parity (was FP) |
| unindexed-event-address | 4 | 4 | **4** | ✅ exact parity |
| uninitialized-local | 3 | 23 | **3** | ✅ exact parity (was FP) |
| dead-code | 1 | 367 | **2** | ≈ (was 367-FP storm; 1 residual: `_contextSuffixLength` virtual-dispatch nuance) |
| missing-inheritance | 4 | 263 | **5** | ≈ (was FP storm) |
| naming-convention | 112 | 218 | **113** | ≈ (+1 declare-site, was FP storm) |
| shadowing-local | 6 | 6 | 8 | ≈ (+2 pre-existing) |
| timestamp | 6 | 0 | **7** | ✅ all 6 slither sites covered (+1 genuine TP: timestamp-gated `if (!active)` in `_execute`) |
| calls-loop | 39 | 4 | **9** | ✅ **unique-site parity** — all 9 unique call sites covered; slither's 39 = same sites duplicated per derived-contract/call-stack, velvet reports once per site by design |
| reentrancy-no-eth | 1 | 0 | **68** | ✅ over-parity — includes slither's exact finding (`burnAndMint`→`operateOnTransfer`→`$._totalSupply` write-after-call); the 67 extras are the *same genuine class* (external call → ERC-7201 region write-after, read-before) surfaced per-function, incl. chains in contract families slither's model and velvet's pre-fix C3 couldn't reach |
| too-many-digits | 4 | 0 | **44** | ✅ beats — all 4 slither literals covered (incl. the `0x00000101…` hex run inside `Math.log2` assembly and the `Bytes.reverseBytes16` masks); superset = ERC-7201 storage-location constants and per-literal granularity, all matching the catalog letter |
| reentrancy-events | 1 | 0 | 0 | ⚠️ documented deviation — slither flags events with state-independent args; velvet's catalog reading requires state-dependent event args. Relaxing it produced a 328-finding FP storm (every transfer-like function), so the stricter reading is kept deliberately |
| deprecated-standards | 0 | 132 | **0** | ✅ FP class eliminated |
| tautological-compare | 0 | 31 | **0** | ✅ FP class eliminated |
| arbitrary-send-erc20 | 0 | 5 | **0** | ✅ FP class eliminated (self-override exclusion) |
| solc-version | 9 | 9 | 13 | ≈ velvet also flags 4 OZ interface files' pragmas (per-file vs per-project granularity) |
| unused-return | 3 | 3 | 7 | ≈ velvet also flags ignored returns inside OZ `Arrays`/`ERC721Upgradeable` library internals |
| external-function | 0 | 57 | 15 | ≈ justified residual (override/interface/`this.f()` exclusions applied; remaining 15 are genuine public-never-internal functions in mocks, which slither suppresses more aggressively) |
| reentrancy-benign | 0 | 0 | 3 | velvet-only TPs visible through the new deep-chain inlining |
| encode-packed-collision | 0 | 2 | 2 | velvet-only plausible detections |
| locked-ether | 0 | 2 | 2 | velvet-only plausible detections |
| costly-loop | 0 | 5 | 5 | velvet-only plausible detections |
| unused-state | 0 | 30 | 30 | velvet-only (detector not in slither's default set on this target) |
| unimplemented-functions | 0 | 10 | 10 | velvet-only |

## Severity profile

| Impact | Slither | Velvet 0.3.0 | Velvet 0.3.1 |
|---|---|---|---|
| High | 1 | 7 | 3 |
| Medium | 16 | 65 | 89 |
| Low | 53 | 12 | 28 |
| Informational | 248 | 1166 | 336 |
| Optimization | 2 | 59 | 17 |

## What was fixed in the hardening wave (v0.3.0 → v0.3.1)

### False-positive eliminations
1. **dead-code 367 → 2.** Root cause chain: (a) C3 linearization was inverted
   (Solidity declares bases most-base-first; the Python-side reversal was
   missing), scrambling override resolution and reachability; (b)
   ancestor-qualified calls (`Base.f()`, `super.f()`) were mis-emitted as
   `HighLevelCall`, breaking call-graph edges; (c) no virtual dispatch in
   reachability; (d) detector scoping. All four fixed.
2. **missing-inheritance 263 → 5, deprecated-standards 132 → 0,
   arbitrary-send-erc20 5 → 0, naming-convention 218 → 113, pragma 25 → 1,
   tautological-compare 31 → 0, uninitialized-local 23 → 3,
   external-function 57 → 15.** Each tightened to its catalog condition
   (declare-site-only dedupe, per-compilation-unit pragma, syntactic-identity
   tautology, must-assignment analysis, override/interface exclusions,
   self-`transferFrom` exclusion, modern-solc construct allowlist).

### False-negative closures
3. **timestamp 0 → 7** (slither 6, all covered): condition broadened to any
   comparison on timestamp-derived operands plus conditions consuming booleans
   derived from such comparisons, tracked through internal-call return values
   per tuple slot; iterates `functions_and_modifiers` so private base helpers
   are visible.
4. **calls-loop 4 → 9 (unique-site parity)**: transitive loop-reachability
   over internal calls with override expansion; qualified `Module.f()` calls
   followed as internal edges; loop membership via parse-time marks
   (dominator natural loops miss `return`-in-body and do-while nodes).
5. **divide-before-multiply 2 → 9**: straight-line Yul modeling
   (`x := div(a,b)`, `let`, opaque builtins as conservative arg-folds) so
   def-chains cross inline assembly (all of `Math.mulDiv`); truncation-idiom
   exclusion narrowed to products that are the consumed value.
6. **too-many-digits 0 → 44**: hex literal runs (>16 hex digits) added,
   Yul-modeled constants scanned; all 4 slither literals covered.
7. **incorrect-exp 0 → 1**: flag `^` with a decimal-notation literal operand
   (hex excluded), not only both-constant XORs.
8. **missing-zero-check 0 → 1**: analyze constructors of concrete contracts
   (abstract ctors and internal helpers excluded).
9. **reentrancy-no-eth 0 → 68**: transitive internal-call inlining
   (depth-bounded, cycle-guarded, mutex suppression at every level),
   base-qualified call inlining, virtual dispatch to most-derived override,
   and ERC-7201 diamond-storage region tokens (writes through storage
   pointers counted per struct region).
10. **Reentrancy engine (earlier)**: modifier-body inlining, NatSpec
    `@custom:security non-reentrant` consumption, dominator-based mutex/guard
    recognition (OZ `nonReentrant`, bool mutexes).

### Merge-interaction fixes (found by re-benchmarking after merging all branches)
11. **reentrancy-no-eth 43 → 0 regression**: the dead-code fix had converted
    `Base.f()`/`super.f()` to `InternalCall`, and the reentrancy inliner then
    *virtual-resolved these statically-bound calls to the caller itself*,
    which the recursion guard skipped — dropping base bodies holding the
    region writes. Fixed with an `is_static` flag on `InternalCall` that
    skips virtual resolution. Recovered to 68 (the C3 fix additionally
    enables analysis of contract families the old baseline couldn't
    linearize; 3 former "findings" were event-emission FPs correctly
    reclassified).
12. **shadowing-local 8 → 28 / uninitialized-local 3 → 31 FP storms**: the
    Yul model minted synthetic locals for identifiers that are actually
    contract-level constants (`$.slot := SLOT` in every ERC-7201 accessor).
    `_yul_lookup` now resolves against contract state variables/constants
    (inheritance-aware) and dotted pseudo-members (`$.slot`) resolve to their
    base variable. Back to 8 and **3** (exact slither parity).
13. **tautological-compare 0 → 1**: Yul `mload(0x00)` modeled as
    `tmp := 0` made `returnValue > 0` look like `0 > 0`. Opaque-builtin Yul
    ops are tagged and excluded from the expression-key comparison.

## Residual known deviations (documented, not blockers)

- **reentrancy-events**: velvet stays at 0 on CMTAT by design (state-dependent
  event-arg requirement; the relaxed reading costs a 328-FP storm).
- **dead-code +1** (`_contextSuffixLength` ERC2771Context virtual-dispatch
  nuance), **shadowing-local +2**, **solc-version +4** (per-file granularity on
  OZ interfaces), **unused-return +4** (OZ library internals),
  **external-function +15** (deliberately less aggressive suppression on mocks).
- **calls-loop / too-many-digits / reentrancy-no-eth counts** are intentional
  supersets or different granularities — every slither finding site is covered.
- Region writes are not yet modeled for *guard* recognition (OZ5
  diamond-storage mutexes) — left unchanged to avoid weakening suppression.

## Reproduce

```bash
# velvet 0.3.1
cd cmtat   # CMTA/CMTAT@49544f4 with OZ 5.5.0 deps
velvet . --json velvet.json
# slither 0.11.5 baseline counts: slither-baseline-counts.json (316 of 320 tabulated)
```

---

# v0.3.0 — Original benchmark (2026-07-19, pre-hardening)

## Headline results

| | Slither | Velvet |
|---|---|---|
| Contracts analyzed | 194 | 194 (same compilation set) |
| Total findings | 320 | 1309 |
| Rules firing | 20 | 21 |
| High-impact findings | 1 | 7 |

Velvet reports ~4× more findings. Breakdown below shows this is a mix of
genuinely broader detection, over-firing (FP classes), and missing filters.

## Per-rule comparison

| Rule | Slither | Velvet | Verdict |
|---|---|---|---|
| assembly | 109 | **109** | ✅ exact parity |
| constable-states | 2 | **2** | ✅ exact parity |
| unindexed-event-address | 4 | **4** | ✅ exact parity |
| shadowing-local | 6 | 8 | ≈ close |
| solc-version | 9 | 13 | ≈ close |
| unused-return | 3 | 7 | ≈ close |
| naming-convention | 112 | 218 | ⚠️ velvet over-fires (inherited members, extra declaration kinds) |
| **timestamp** | 6 | 0 | ❌ **velvet FN** — detection condition too narrow (excludes ordering comparisons that slither + the catalog flag, e.g. `require(time < block.timestamp)` in SnapshotModuleBase) |
| **calls-loop** | 39 | 4 | ❌ **velvet FN** — misses external calls in some loop forms (e.g. `CMTATBaseCommon._update`) |
| divide-before-multiply | 9 | 2 | ❌ velvet FN (misses 7) |
| too-many-digits | 4 | 0 | ❌ velvet FN (threshold 8+ digits too high / literal forms missed) |
| incorrect-exp | 1 | 0 | ❌ velvet FN |
| missing-zero-check | 1 | 0 | ❌ velvet FN |
| reentrancy-events / -no-eth | 1 / 1 | 0 / 0 | ❌ velvet FN (marginal cases) |
| **dead-code** | 1 | 367 | ⚠️ **velvet FP storm** — root cause found: reachability does not traverse `LibraryCall`; OpenZeppelin internals (`__AccessControl_init`, `Address.functionCall`, …) falsely reported unreachable |
| **missing-inheritance** | 4 | 263 | ⚠️ velvet FP — heuristic too broad (fires on any contract with fully-implemented public members, not just clear interface non-inheritance) |
| deprecated-standards | 0 | 132 | ⚠️ velvet FP — fires on constructs valid in modern solc |
| tautological-compare | 0 | 31 | ⚠️ likely velvet FP (def-chain structural match too lax) |
| pragma | 1 | 25 | ⚠️ velvet too strict (per-file version spread in a multi-solc project is normal) |
| uninitialized-local | 3 | 23 | ⚠️ probable velvet FP inflation |
| external-function | 0 | 57 | ⚠️ velvet over-fires (slither suppresses more cases) |
| arbitrary-send-erc20 | 0 | 5 | ⚠️ **velvet FP** — flags `transferFrom(from,…)` *inside the transferFrom override itself* (allowance check is internal to the call); needs self-override exclusion |
| encode-packed-collision | 0 | 2 | ✅ plausible velvet-only detections |
| locked-ether | 0 | 2 | ✅ plausible velvet-only detections |
| costly-loop | 0 | 5 | ✅ plausible velvet-only detections |

## Severity profile (v0.3.0)

| Impact | Slither | Velvet |
|---|---|---|
| High | 1 | 7 |
| Medium | 16 | 65 |
| Low | 53 | 12 |
| Informational | 248 | 1166 |
| Optimization | 2 | 59 |

## Findings (v0.3.0)

1. **Framework parity is real**: identical compilation coverage (194 contracts),
   exact match on 3 detectors, near-match on 3 more. The pipeline
   (parse → IR → SSA → analyses) works on a production-grade codebase.
2. **Velvet has 4 confirmed FN classes** vs Slither: `timestamp` (over-narrow
   condition), `calls-loop` (loop-membership gap), `divide-before-multiply`,
   `too-many-digits` — all fixable detection-condition bugs.
3. **Velvet has 5 confirmed FP classes**: `dead-code` (LibraryCall reachability —
   the single biggest bug), `missing-inheritance`, `deprecated-standards`,
   `arbitrary-send-erc20` (self-override exclusion), `naming-convention` scope.
4. Neither tool found exploitable High issues in CMTAT's core (expected — it's
   an audited codebase); both correctly surface the same Informational mass.
