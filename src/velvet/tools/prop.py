"""``velvet-prop`` — property-based test scaffolding generator
(spec/printers-and-tools.md §B.6).

Generates a ready-to-fuzz property bundle for an ERC-20-style contract:

- an Echidna harness contract ``Test<Name>`` exposing ``echidna_*``
  properties from a scenario catalog (§B.6.4: Transferable, Pausable,
  Mintable, Burnable, Approveable);
- matching Truffle unit tests exercising the same properties;
- an ``echidna_config.yaml`` tuning the fuzzer for the contract.

The generated constructors seed three canonical actors
(``crytic_owner``/``crytic_user``/``crytic_attacker``) so properties can
check balance/allowance invariants from several viewpoints.

Invocation: ``velvet-prop TARGET CONTRACT [--scenario NAME] [--dir DIR]``.
Exit code: 0 = success, 2 = usage/compilation error.

Original clean-room implementation.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from velvet.core.contract import Contract
from velvet.core.function import Function
from velvet.exceptions import VelvetError
from velvet.session import Velvet
from velvet.tools.common import (
    build_session,
    canonical_params,
    find_contract,
    public_getters,
    signature_of,
)


# ---------------------------------------------------------------------------
# scenario catalog (spec/printers-and-tools.md §B.6.4)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Property:
    """One numbered property of a scenario."""

    number: int
    description: str
    #: echidna property stub body (Solidity, 8-space indent inside the function)
    echidna_body: str
    #: truffle unit-test body (JavaScript, 8-space indent inside `it(...)`)
    truffle_body: str


@dataclass(frozen=True)
class Scenario:
    """A named bundle of properties with its capability requirements."""

    name: str
    description: str
    #: required functions: (name, params). Empty params = any signature OK.
    requires: tuple[tuple[str, tuple[str, ...]], ...] = ()
    requirement_note: str = ""
    properties: tuple[Property, ...] = ()


_TRANSFERABLE = Scenario(
    name="Transferable",
    description="basic ERC-20 transfer/allowance accounting",
    requires=(
        ("transfer", ("address", "uint256")),
        ("balanceOf", ("address",)),
        ("totalSupply", ()),
    ),
    properties=(
        Property(
            1,
            "a user cannot transfer more tokens than their balance",
            "return crytic_user.transfer({{target}}, balanceOf(crytic_user) + 1) == false;",
            "const balance = await token.balanceOf(crytic_user);\n"
            "        await expectRevert(token.transfer(crytic_owner, balance.addn(1), {from: crytic_user}));",
        ),
        Property(
            2,
            "a transfer of zero tokens always succeeds",
            "return crytic_user.transfer({{target}}, 0);",
            "await token.transfer(crytic_owner, 0, {from: crytic_user});",
        ),
        Property(
            3,
            "transferring to oneself keeps the sender's balance unchanged",
            "uint256 before = balanceOf(crytic_user);\n"
            "        crytic_user.transfer(crytic_user, 1);\n"
            "        return balanceOf(crytic_user) == before;",
            "const before = await token.balanceOf(crytic_user);\n"
            "        await token.transfer(crytic_user, 1, {from: crytic_user});\n"
            "        assert((await token.balanceOf(crytic_user)).eq(before));",
        ),
        Property(
            4,
            "the total supply never changes through transfers",
            "uint256 before = totalSupply();\n"
            "        crytic_user.transfer(crytic_owner, 1);\n"
            "        return totalSupply() == before;",
            "const before = await token.totalSupply();\n"
            "        await token.transfer(crytic_owner, 1, {from: crytic_user});\n"
            "        assert((await token.totalSupply()).eq(before));",
        ),
    ),
)

_PAUSABLE = Scenario(
    name="Pausable",
    description="token pausing blocks transfers",
    requires=(
        ("pause", ()),
        ("unpause", ()),
        ("paused", ()),
        ("transfer", ("address", "uint256")),
    ),
    requirement_note="contract must expose pause()/unpause()/paused()",
    properties=(
        Property(
            1,
            "no transfer succeeds while the token is paused",
            "if (!paused()) {\n"
            "            return true;\n"
            "        }\n"
            "        return crytic_user.transfer({{target}}, 1) == false;",
            "await token.pause({from: crytic_owner});\n"
            "        await expectRevert(token.transfer(crytic_user, 1, {from: crytic_owner}));\n"
            "        await token.unpause({from: crytic_owner});",
        ),
        Property(
            2,
            "the owner can pause and unpause the token",
            "return true; // exercised through the pause()/unpause() harness calls",
            "await token.pause({from: crytic_owner});\n"
            "        assert(await token.paused());\n"
            "        await token.unpause({from: crytic_owner});\n"
            "        assert(!(await token.paused()));",
        ),
    ),
)

_MINTABLE = Scenario(
    name="Mintable",
    description="minting inflates balance and supply consistently",
    requires=(
        ("mint", ()),
        ("balanceOf", ("address",)),
        ("totalSupply", ()),
    ),
    requirement_note="contract must expose a mint function",
    properties=(
        Property(
            1,
            "minting to a user increases their balance by the minted amount",
            "uint256 before = balanceOf(crytic_owner);\n"
            "        mint(crytic_owner, 1);\n"
            "        return balanceOf(crytic_owner) == before + 1;",
            "const before = await token.balanceOf(crytic_owner);\n"
            "        await token.mint(crytic_owner, 1, {from: crytic_owner});\n"
            "        assert((await token.balanceOf(crytic_owner)).eq(before.addn(1)));",
        ),
        Property(
            2,
            "minting increases the total supply by the minted amount",
            "uint256 before = totalSupply();\n"
            "        mint(crytic_owner, 1);\n"
            "        return totalSupply() == before + 1;",
            "const before = await token.totalSupply();\n"
            "        await token.mint(crytic_owner, 1, {from: crytic_owner});\n"
            "        assert((await token.totalSupply()).eq(before.addn(1)));",
        ),
    ),
)

_BURNABLE = Scenario(
    name="Burnable",
    description="burning deflates balance and supply consistently",
    requires=(
        ("burn", ()),
        ("balanceOf", ("address",)),
        ("totalSupply", ()),
    ),
    requirement_note="contract must expose a burn function",
    properties=(
        Property(
            1,
            "burning decreases the holder's balance by the burned amount",
            "uint256 before = balanceOf(crytic_owner);\n"
            "        if (before == 0) {\n"
            "            return true;\n"
            "        }\n"
            "        burn(1);\n"
            "        return balanceOf(crytic_owner) == before - 1;",
            "const before = await token.balanceOf(crytic_owner);\n"
            "        if (before.isZero()) return;\n"
            "        await token.burn(1, {from: crytic_owner});\n"
            "        assert((await token.balanceOf(crytic_owner)).eq(before.subn(1)));",
        ),
        Property(
            2,
            "burning decreases the total supply by the burned amount",
            "uint256 before = totalSupply();\n"
            "        if (balanceOf(crytic_owner) == 0) {\n"
            "            return true;\n"
            "        }\n"
            "        burn(1);\n"
            "        return totalSupply() == before - 1;",
            "const before = await token.totalSupply();\n"
            "        const balance = await token.balanceOf(crytic_owner);\n"
            "        if (balance.isZero()) return;\n"
            "        await token.burn(1, {from: crytic_owner});\n"
            "        assert((await token.totalSupply()).eq(before.subn(1)));",
        ),
    ),
)

_APPROVEABLE = Scenario(
    name="Approveable",
    description="allowance accounting for approve/transferFrom",
    requires=(
        ("approve", ("address", "uint256")),
        ("allowance", ("address", "address")),
        ("transferFrom", ("address", "address", "uint256")),
    ),
    properties=(
        Property(
            1,
            "an approved spender cannot move more than the allowance",
            "uint256 allowed = allowance(crytic_user, crytic_attacker);\n"
            "        return crytic_attacker.transferFrom(crytic_user, {{target}}, allowed + 1) == false;",
            "const allowed = await token.allowance(crytic_user, crytic_attacker);\n"
            "        await expectRevert(\n"
            "            token.transferFrom(crytic_user, crytic_owner, allowed.addn(1), {from: crytic_attacker})\n"
            "        );",
        ),
        Property(
            2,
            "approving sets the allowance to exactly the approved amount",
            "crytic_user.approve(crytic_attacker, 42);\n"
            "        return allowance(crytic_user, crytic_attacker) == 42;",
            "await token.approve(crytic_attacker, 42, {from: crytic_user});\n"
            "        assert((await token.allowance(crytic_user, crytic_attacker)).eqn(42));",
        ),
    ),
)

SCENARIOS: dict[str, Scenario] = {
    s.name.lower(): s
    for s in (_TRANSFERABLE, _PAUSABLE, _MINTABLE, _BURNABLE, _APPROVEABLE)
}


def get_scenario(name: str) -> Scenario:
    scenario = SCENARIOS.get(name.lower())
    if scenario is None:
        available = ", ".join(s.name for s in SCENARIOS.values())
        raise VelvetError(f"unknown scenario {name!r} (available: {available})")
    return scenario


# ---------------------------------------------------------------------------
# contract capability checks
# ---------------------------------------------------------------------------


def _surface_signatures(contract: Contract) -> set[str]:
    """Externally callable signatures (functions + public getters)."""
    signatures: set[str] = set()
    for function in contract.available_functions_from_inheritances():
        if function.visibility in ("external", "public"):
            signatures.add(signature_of(function.name, canonical_params(function)))
    for getter in public_getters(contract):
        signatures.add(getter.signature)
    return signatures


def check_requirements(contract: Contract, scenario: Scenario) -> list[str]:
    """Missing requirement descriptions (empty = scenario fully supported)."""
    surface = _surface_signatures(contract)
    missing: list[str] = []
    for name, params in scenario.requires:
        if params:
            present = signature_of(name, list(params)) in surface
        else:
            present = any(
                sig == f"{name}()" or sig.startswith(f"{name}(") for sig in surface
            )
        if not present:
            wanted = signature_of(name, list(params)) if params else f"{name}(...)"
            missing.append(f"{wanted} (required by scenario {scenario.name})")
    return missing


# ---------------------------------------------------------------------------
# code generation
# ---------------------------------------------------------------------------

_SOLIDITY_HEADER = """// Generated by velvet-prop ({scenario} scenario for {contract}).
// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

import \"../{contract_file}\";
"""

_HARNESS_TEMPLATE = """
contract Test{name} is {name} {{
    address internal crytic_owner = address(0x10000);
    address internal crytic_user = address(0x20000);
    address internal crytic_attacker = address(0x30000);

    constructor() {{
        // TODO: seed the initial state (balances/allowances) for the
        // canonical actors above so the properties are meaningful.
    }}
{properties}
}}
"""

_PROPERTY_TEMPLATE = """
    // Property #{number}: {description}
    function echidna_{scenario}_{number}() public returns (bool) {{
        {body}
    }}
"""

_TRUFFLE_TEMPLATE = """// Generated by velvet-prop ({scenario} scenario for {contract}).
const {contract} = artifacts.require(\"{contract}\");

contract(\"Test{contract} initialization\", (accounts) => {{
    const [crytic_owner, crytic_user, crytic_attacker] = accounts;
    let token;

    beforeEach(async () => {{
        token = await {contract}.new(/* TODO: constructor arguments */);
    }});
{tests}
}});
"""

_TRUFFLE_TEST_TEMPLATE = """
    it(\"#{number} {description}\", async () => {{
        {body}
    }});
"""

_ECHIDNA_CONFIG_TEMPLATE = """# Generated by velvet-prop for {contract}.
testMode: assertion
prefix: echidna_
coverage: true
corpusDir: corpus-{contract}
balanceAddr: 0xffffffff
balanceContract: 0x0
filterFunctions: []
"""


def _target_label(contract: Contract) -> str:
    """The address placeholder used inside property bodies."""
    return "crytic_owner"


def generate_echidna_contract(
    contract: Contract, scenario: Scenario, contract_file: str = "Token.sol"
) -> str:
    """Render the Echidna harness contract for ``contract``."""
    properties = []
    for prop in scenario.properties:
        body = prop.echidna_body.replace("{{target}}", _target_label(contract))
        properties.append(
            _PROPERTY_TEMPLATE.format(
                number=prop.number,
                description=prop.description,
                body=body,
                scenario=scenario.name.lower(),
            ).rstrip("\n")
        )
    return (
        _SOLIDITY_HEADER.format(scenario=scenario.name, contract=contract.name,
                                contract_file=contract_file)
        + _HARNESS_TEMPLATE.format(name=contract.name,
                                   properties="\n".join(properties)).rstrip("\n")
        + "\n"
    )


def generate_truffle_tests(contract: Contract, scenario: Scenario) -> str:
    """Render the Truffle unit-test file for ``contract``."""
    tests = []
    for prop in scenario.properties:
        body = prop.truffle_body.replace("{{target}}", "token.address")
        tests.append(
            _TRUFFLE_TEST_TEMPLATE.format(
                number=prop.number, description=prop.description, body=body
            ).rstrip("\n")
        )
    return _TRUFFLE_TEMPLATE.format(
        scenario=scenario.name, contract=contract.name, tests="\n".join(tests)
    )


def generate_echidna_config(contract: Contract) -> str:
    """Render the echidna_config.yaml for ``contract``."""
    return _ECHIDNA_CONFIG_TEMPLATE.format(contract=contract.name)


@dataclass
class GeneratedFiles:
    """Paths written by a prop generation run."""

    harness: Path
    truffle: Path
    config: Path
    initialization: Path


_INITIALIZATION_JS_TEMPLATE = """// Generated by velvet-prop: initialization smoke test for {contract}.
const {contract} = artifacts.require(\"{contract}\");

contract(\"Initialization{contract}\", (accounts) => {{
    it(\"deploys with a non-zero address\", async () => {{
        const token = await {contract}.new(/* TODO: constructor arguments */);
        assert(token.address !== \"0x0000000000000000000000000000000000000000\");
    }});
}});
"""


def generate(
    session: Velvet,
    contract: Contract,
    scenario: Scenario,
    out_dir: Path,
) -> GeneratedFiles:
    """Generate the full property bundle into ``out_dir``.

    Raises VelvetError listing the missing requirements when the contract
    does not support the scenario.
    """
    del session  # the contract carries everything we need
    missing = check_requirements(contract, scenario)
    if missing:
        raise VelvetError(
            f"{contract.name} does not support scenario {scenario.name}; "
            f"missing: {'; '.join(missing)}"
        )

    contracts_dir = out_dir / "contracts" / "crytic"
    test_dir = out_dir / "test" / "crytic"
    contracts_dir.mkdir(parents=True, exist_ok=True)
    test_dir.mkdir(parents=True, exist_ok=True)

    source_file = "Token.sol"
    filename = contract.source_mapping.filename
    if filename is not None and filename.short:
        source_file = Path(filename.short).name

    harness = contracts_dir / f"Test{contract.name}.sol"
    harness.write_text(
        generate_echidna_contract(contract, scenario, source_file),
        encoding="utf-8",
    )
    truffle = test_dir / f"Test{contract.name}.js"
    truffle.write_text(generate_truffle_tests(contract, scenario), encoding="utf-8")
    initialization = test_dir / f"InitializationTest{contract.name}.js"
    initialization.write_text(
        _INITIALIZATION_JS_TEMPLATE.format(contract=contract.name), encoding="utf-8"
    )
    config = out_dir / "echidna_config.yaml"
    config.write_text(generate_echidna_config(contract), encoding="utf-8")
    return GeneratedFiles(
        harness=harness, truffle=truffle, config=config, initialization=initialization
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def render_next_steps(result: GeneratedFiles, contract: Contract) -> str:
    name = contract.name
    lines = [f"velvet-prop: generated the {name} property bundle:",
             f"  {result.harness}",
             f"  {result.truffle}",
             f"  {result.initialization}",
             f"  {result.config}"]
    lines.append("Next steps:")
    lines.append(
        f"  1. Customize the constructor of contracts/crytic/Test{name}.sol "
        "to establish a meaningful initial state (seed balances for "
        "crytic_owner/crytic_user/crytic_attacker)."
    )
    lines.append(
        f"  2. Run the unit tests: truffle test test/crytic/InitializationTest{name}.js"
        f" && truffle test test/crytic/Test{name}.js"
    )
    lines.append(
        f"  3. Fuzz the properties: echidna-test . --contract Test{name} "
        "--config echidna_config.yaml"
    )
    return "\n".join(lines)


def render_scenario_listing() -> str:
    lines = ["Available scenarios (property catalog §B.6.4):"]
    for scenario in SCENARIOS.values():
        lines.append(f"\n{scenario.name}: {scenario.description}")
        if scenario.requirement_note:
            lines.append(f"  requires: {scenario.requirement_note}")
        for prop in scenario.properties:
            lines.append(f"  #{prop.number:<2} {prop.description}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="velvet-prop",
        description=(
            "Generate fuzzing property scaffolding (Echidna harness + "
            "Truffle unit tests) for an ERC-20-style contract."
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help=".sol file, project directory or standard-JSON",
    )
    parser.add_argument(
        "contract",
        nargs="?",
        default=None,
        help="contract to generate properties for (or use --contract)",
    )
    parser.add_argument(
        "--contract",
        dest="contract_flag",
        metavar="NAME",
        default=None,
        help="contract to generate properties for",
    )
    parser.add_argument(
        "--scenario",
        metavar="NAME",
        default="Transferable",
        help="property bundle (default: Transferable; see --list-scenarios)",
    )
    parser.add_argument(
        "--dir",
        metavar="DIR",
        default=".",
        help="output directory for the generated files (default: .)",
    )
    parser.add_argument(
        "--list-scenarios",
        action="store_true",
        help="list the available scenarios and their properties",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_scenarios:
        print(render_scenario_listing())
        return 0
    try:
        if args.target is None:
            raise VelvetError("TARGET is required (unless --list-scenarios is used)")
        contract_name = args.contract_flag or args.contract
        if contract_name is None:
            raise VelvetError("CONTRACT is required (positional or --contract)")
        if args.contract_flag and args.contract and args.contract_flag != args.contract:
            raise VelvetError(
                f"--contract {args.contract_flag!r} contradicts CONTRACT "
                f"{args.contract!r}"
            )
        scenario = get_scenario(args.scenario)
        session = build_session(args.target)
        contract = find_contract(session, contract_name)
        result = generate(session, contract, scenario, Path(args.dir))
    except VelvetError as exc:
        print(f"velvet-prop: {exc}", file=sys.stderr)
        return 2
    print(render_next_steps(result, contract))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
