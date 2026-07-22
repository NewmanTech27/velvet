# Velvet

**Velvet** is a clean-room, permissively-licensed (Apache-2.0) static analysis
framework for EVM smart contracts. It finds vulnerabilities, visualizes contract
structure, and gives you a Python API to build your own analyses — without
executing the code.

> Velvet is an original implementation built from public documentation via a
> two-team clean-room process. See [NOTICE.md](NOTICE.md).

## Features

- **100 vulnerability & quality detectors** out of the box (reentrancy incl.
  modifier/internal-call inlining, access control, delegatecall, unchecked
  calls, token issues, shadowing, uninitialized variables, compiler bugs,
  gas optimizations, …) on a documented detector framework — write your own
  in a few lines of Python.
- **10 printers** for code comprehension: human summary, entry points, LOC,
  call graph, inheritance graph, CFG (Graphviz), IR dumps.
- **Solidity IR with SSA** — a small, well-defined operation set with
  def-use chains, φ-functions at merges and after external calls, and
  storage-alias awareness, powering precise taint/dependency analysis.
- **Built-in analyses** shared by all detectors: read/write sets (incl.
  transitive), protected-function heuristic, data dependency & taint.
- **Companion tools**: `velvet-check-erc` (ERC-20/721/1155 conformance),
  `velvet-check-upgradeability` (proxy/initializer/storage-layout checks),
  `velvet-flat` (source flattening), `velvet-interface` (interface generation),
  `velvet-read-storage` (storage layout + live slot values via JSON-RPC),
  `velvet-prop` (Echidna/Truffle property scaffolding for ERC-20 scenarios).
- **Project support**: single files, directories, Foundry/Hardhat/Brownie
  projects (auto-detected), standard-JSON, and verified contracts by address
  (`velvet 0x…`, Etherscan-family explorers).
- **Triage workflow**: interactive triage mode with a persistent database,
  markdown checklist reports with repository links.
- **CI-ready**: JSON + SARIF output for GitHub code scanning, `--fail-on`
  exit policies, inline suppressions, config file, deterministic output.

## Installation

```bash
pip install velvet-analyzer
```

Requires Python ≥ 3.10. Solidity compilers are managed automatically
(via py-solc-x binaries).

## Quick start

```bash
velvet .                              # analyze a project
velvet contract.sol                   # analyze a single file
velvet . --list-detectors             # show all detectors
velvet . --detect reentrancy-eth,tx-origin
velvet . --print human-summary,entry-points
velvet . --json results.json --sarif results.sarif
velvet . --fail-on medium             # CI gate
velvet . --triage-mode                # interactively hide accepted findings
velvet . --checklist --markdown-root https://github.com/you/repo
velvet 0x1234… --explorer-network mainnet   # verified on-chain contract
```

### Python API

```python
from velvet import Velvet

session = Velvet("contract.sol")
findings = session.run_detectors()

for contract in session.contracts_derived:
    for function in contract.functions:
        for node in function.nodes:
            for op in node.ir_operations:
                print(function, node, op)
```

### Writing a custom detector

```python
from velvet.detectors.base import Confidence, Detector, DetectorDocs, Impact

class HiddenBackdoor(Detector):
    RULE = "hidden-backdoor"
    TITLE = "Function name contains 'backdoor'"
    IMPACT = Impact.HIGH
    CONFIDENCE = Confidence.HIGH
    DOCS = DetectorDocs(
        url="https://github.com/velvet-analyzer/velvet/wiki",
        title="Hidden backdoor",
        description="A function name suggests a deliberate backdoor.",
        exploit_scenario="Bob calls backdoor() and drains the contract.",
        recommendation="Remove or protect the function.",
    )

    def analyze(self):
        results = []
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if "backdoor" in function.name:
                    results.append(
                        self.finding(["Potential backdoor ", function, " in ", contract])
                    )
        return results

session.register_detector(HiddenBackdoor)
```

## Suppressions & filtering

```solidity
// velvet-disable-next-line reentrancy-eth
(bool ok, ) = msg.sender.call{value: amount}("");
```

Also: `--filter-paths`, `--exclude-dependencies`, `velvet-disable-start/end`
regions, and `velvet.config.json`.

## Documentation

- `spec/` — the full functional specifications this implementation follows
  (architecture, API surface, detector catalog, printers & tools)
- [NOTICE.md](NOTICE.md) — clean-room provenance
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to add detectors/printers

## License

Apache-2.0. See [LICENSE](LICENSE).
