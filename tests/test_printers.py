"""Printer tests: v1 printer set over smoke/cfg/parsing fixtures
(spec/printers-and-tools.md §A; architecture.md §9).

Original clean-room implementation.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from velvet.cli import main
from velvet.printers import BUILTIN_PRINTERS, Printer
from velvet.session import Velvet

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SIMPLE = FIXTURES / "smoke" / "Simple.sol"
TOKEN = FIXTURES / "smoke" / "Token.sol"
BRANCHING = FIXTURES / "cfg" / "Branching.sol"
MODIFIERS = FIXTURES / "cfg" / "Modifiers.sol"
DIAMOND = FIXTURES / "parsing" / "Diamond.sol"
OPS = FIXTURES / "ir" / "Ops.sol"

RULES = {
    "human-summary",
    "contract-summary",
    "function-summary",
    "entry-points",
    "loc",
    "inheritance-graph",
    "call-graph",
    "cfg",
    "solir",
    "solir-ssa",
}


def run_only(session: Velvet, rule: str) -> str:
    """Run a single registered printer on a shared session; restore registry."""
    removed = []
    for cls in list(session.registered_printers):
        if cls.RULE != rule:
            session.unregister_printer(cls)
            removed.append(cls)
    try:
        return "\n".join(session.run_printers())
    finally:
        for cls in removed:
            session.register_printer(cls)


# ------------------------------------------------------------- sessions
@pytest.fixture(scope="module")
def simple_session(tmp_path_factory):
    export = tmp_path_factory.mktemp("simple")
    return Velvet(str(SIMPLE), export_dir=str(export))


@pytest.fixture(scope="module")
def token_session(tmp_path_factory):
    export = tmp_path_factory.mktemp("token")
    return Velvet(str(TOKEN), export_dir=str(export))


@pytest.fixture(scope="module")
def branching_session(tmp_path_factory):
    export = tmp_path_factory.mktemp("branching")
    return Velvet(str(BRANCHING), export_dir=str(export))


@pytest.fixture(scope="module")
def diamond_session(tmp_path_factory):
    export = tmp_path_factory.mktemp("diamond")
    return Velvet(str(DIAMOND), export_dir=str(export))


@pytest.fixture(scope="module")
def ops_session(tmp_path_factory):
    export = tmp_path_factory.mktemp("ops")
    return Velvet(str(OPS), export_dir=str(export))


def dot_files(session: Velvet) -> dict[str, str]:
    """filename -> content for every .dot emitted into the session export dir."""
    out = {}
    for path in Path(session.export_dir).glob("*.dot"):
        out[path.name] = path.read_text()
    return out


# ------------------------------------------------------------- registry
class TestRegistry:
    def test_v1_printer_set_registered(self):
        assert {cls.RULE for cls in BUILTIN_PRINTERS} == RULES

    def test_metadata(self):
        for cls in BUILTIN_PRINTERS:
            assert issubclass(cls, Printer)
            assert cls.RULE and cls.RULE == cls.RULE.lower()
            assert cls.TITLE

    def test_session_registers_builtins(self, simple_session):
        assert {cls.RULE for cls in simple_session.registered_printers} == RULES


# ------------------------------------------------------------- human-summary
class TestHumanSummary:
    def test_overview(self, simple_session):
        out = run_only(simple_session, "human-summary")
        assert "Detectors' results (number of findings):" in out
        assert "High: 0" in out
        assert "Number of contracts: 1" in out
        assert "Number of functions: 2" in out
        assert "+ Contract Simple" in out
        assert "Number of functions: 2" in out
        assert "Complex code? No" in out
        assert "Is ERC20 token: False" in out

    def test_erc20_traits(self, tmp_path):
        source = tmp_path / "MyToken.sol"
        source.write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.0;\n"
            "contract MyToken {\n"
            "    mapping(address => uint256) private _balances;\n"
            "    mapping(address => mapping(address => uint256)) private _allowances;\n"
            "    uint256 private _totalSupply;\n"
            "    address private _owner;\n"
            "    bool private _paused;\n"
            "    constructor() { _owner = msg.sender; }\n"
            "    modifier whenNotPaused() { require(!_paused, 'paused'); _; }\n"
            "    function totalSupply() public view returns (uint256) { return _totalSupply; }\n"
            "    function balanceOf(address a) public view returns (uint256) { return _balances[a]; }\n"
            "    function transfer(address to, uint256 amount) public returns (bool) {\n"
            "        _balances[msg.sender] -= amount; _balances[to] += amount; return true;\n"
            "    }\n"
            "    function transferFrom(address from, address to, uint256 amount) public returns (bool) {\n"
            "        _allowances[from][msg.sender] -= amount;\n"
            "        _balances[from] -= amount; _balances[to] += amount; return true;\n"
            "    }\n"
            "    function approve(address spender, uint256 amount) public returns (bool) {\n"
            "        _allowances[msg.sender][spender] = amount; return true;\n"
            "    }\n"
            "    function allowance(address o, address s) public view returns (uint256) { return _allowances[o][s]; }\n"
            "    function mint(uint256 amount) external {\n"
            "        require(msg.sender == _owner, 'not owner');\n"
            "        _totalSupply += amount; _balances[msg.sender] += amount;\n"
            "    }\n"
            "    function pause() external { _paused = true; }\n"
            "}\n"
        )
        session = Velvet(str(source), export_dir=str(tmp_path))
        out = run_only(session, "human-summary")
        assert "Is ERC20 token: True" in out
        assert "Can be paused: True" in out
        assert "Minting restriction: Restricted (protected)" in out
        assert "ERC20 race condition mitigation: False" in out


# ------------------------------------------------------------- contract-summary
class TestContractSummary:
    def test_functions_with_visibility(self, simple_session):
        out = run_only(simple_session, "contract-summary")
        assert "+ Contract Simple" in out
        assert "- constructor (public)" in out
        assert "- setValue(uint256) (external)" in out

    def test_interface_kind_marked(self, diamond_session):
        out = run_only(diamond_session, "contract-summary")
        assert "+ Contract ICounter [interface]" in out


# ------------------------------------------------------------- function-summary
class TestFunctionSummary:
    def test_table(self, token_session):
        out = run_only(token_session, "function-summary")
        assert "Contract Token" in out
        assert "Contract vars: balanceOf, name" in out
        assert "Inheritances:" in out
        for column in (
            "Function",
            "Visibility",
            "Modifiers",
            "Read",
            "Write",
            "Internal Calls",
            "External Calls",
        ):
            assert column in out
        assert "transfer(address,uint256)" in out
        assert "balanceOf" in out
        assert "msg.sender" in out  # special variables appear in Read
        assert "+---" in out  # pretty-table grid

    def test_modifiers_table(self, branching_session):
        session = Velvet(str(MODIFIERS), export_dir=branching_session.export_dir)
        out = run_only(session, "function-summary")
        assert "| Modifiers" in out
        assert "onlyOwner()" in out
        assert "whenUnlocked()" in out
        # the function row carries its modifier names
        assert "sensitive(uint256)" in out
        assert "onlyOwner" in out


# ------------------------------------------------------------- entry-points
class TestEntryPoints:
    def test_transfer_listed(self, token_session):
        out = run_only(token_session, "entry-points")
        assert "+ Contract Token" in out
        assert "- transfer(address,uint256)" in out
        assert "read: balanceOf" in out
        assert "written: balanceOf" in out
        # constructors are not post-deployment entry points
        section = out.split("+ Contract Token", 1)[1]
        assert "constructor" not in section

    def test_view_and_pure_excluded(self, branching_session):
        out = run_only(branching_session, "entry-points")
        # classify/sign are pure, touch(uint256) is the only state-changing one
        assert "- touch(uint256)" in out
        assert "classify" not in out
        assert "sign(int256)" not in out


# ------------------------------------------------------------------- loc
class TestLoc:
    def test_counts(self, simple_session):
        out = run_only(simple_session, "loc")
        assert "| LOC " in out
        assert "| SLOC " in out
        assert "| CLOC " in out
        assert "SRC" in out and "DEP" in out and "TEST" in out
        assert "Total LOC:" in out
        row = next(line for line in out.splitlines() if line.startswith("| LOC "))
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        src_loc = int(cells[1])
        assert src_loc == len(SIMPLE.read_text().splitlines())
        cloc_row = next(line for line in out.splitlines() if line.startswith("| CLOC "))
        cloc = int([c.strip() for c in cloc_row.strip("|").split("|")][1])
        assert cloc == 1  # the SPDX header comment line


# ------------------------------------------------------------- inheritance-graph
class TestInheritanceGraph:
    def test_dot_file(self, simple_session):
        out = run_only(simple_session, "inheritance-graph")
        assert "Inheritance Graph:" in out
        files = dot_files(simple_session)
        assert "Simple.inheritance-graph.dot" in files
        content = files["Simple.inheritance-graph.dot"]
        assert content.startswith('digraph "inheritance-graph"')
        assert '"Simple"' in content
        assert "setValue(uint256)" in content

    def test_edges_and_overrides(self, diamond_session):
        run_only(diamond_session, "inheritance-graph")
        content = dot_files(diamond_session)["Diamond.inheritance-graph.dot"]
        assert '"Diamond" -> "Left" [label="1"];' in content
        assert '"Diamond" -> "Right" [label="2"];' in content
        assert '"Left" -> "Base" [label="1"];' in content
        # overriding functions are highlighted (orange)
        assert content.count("#e68a00") >= 3
        # interface annotated
        assert "interface" in content


# ------------------------------------------------------------- call-graph
class TestCallGraph:
    def test_solidity_cluster(self, token_session):
        out = run_only(token_session, "call-graph")
        assert "Call Graph:" in out
        files = dot_files(token_session)
        assert "Token.sol.Token.call-graph.dot" in files
        content = files["Token.sol.Token.call-graph.dot"]
        assert content.startswith('digraph "Token.call-graph"')
        assert '"Token.transfer(address,uint256)"' in content
        assert '"[Solidity]:require"' in content
        assert '"Token.transfer(address,uint256)" -> "[Solidity]:require";' in content

    def test_internal_and_library_edges(self, ops_session):
        run_only(ops_session, "call-graph")
        content = dot_files(ops_session)["Ops.sol.Ops.call-graph.dot"]
        assert '"Ops.arithmetic(uint256,uint256)" -> "Ops._double(uint256)";' in content
        assert '"Ops.libraryUse(uint256)" -> "Counter.add(uint256,uint256)";' in content
        assert 'label="Counter";' in content  # library gets its own cluster


# ------------------------------------------------------------------- cfg
class TestCfg:
    def test_dot_per_function(self, branching_session):
        out = run_only(branching_session, "cfg")
        assert "CFG:" in out
        files = dot_files(branching_session)
        name = "Branching.classify_int256_.cfg.dot"
        assert name in files
        content = files[name]
        assert content.startswith('digraph "Branching.classify(int256)"')
        assert "IF" in content
        assert "ENDIF" in content
        assert "RETURN" in content
        assert '"2" -> "3";' in content

    def test_modifiers_get_graphs(self, branching_session):
        session = Velvet(str(MODIFIERS), export_dir=branching_session.export_dir)
        run_only(session, "cfg")
        names = dot_files(session)
        assert any("onlyOwner" in name for name in names)


# ------------------------------------------------------------------- solir
class TestSolir:
    def test_op_strings(self, token_session):
        out = run_only(token_session, "solir")
        assert "Contract: Token" in out
        assert "Function: Token.transfer(address,uint256)" in out
        assert "\tNode 1: EXPRESSION" in out
        assert "REF_0 -> balanceOf [ msg.sender ]" in out
        assert "SOLIDITY_CALL require(TMP_0, insufficient)" in out
        assert "RETURN true" in out

    def test_ssa_form(self, token_session):
        out = run_only(token_session, "solir-ssa")
        assert "phi(" in out
        assert "REF_0_1 -> balanceOf_1 [ msg.sender ]" in out
        assert "balanceOf_1 = phi(balanceOf)" in out


# ------------------------------------------------------------- robustness
class TestNoCrash:
    """Every printer runs over the smoke + cfg fixtures without crashing."""

    @pytest.mark.parametrize(
        "fixture",
        sorted(FIXTURES.glob("smoke/*.sol")) + sorted(FIXTURES.glob("cfg/*.sol")),
        ids=lambda p: p.name,
    )
    def test_all_printers_run(self, fixture, tmp_path, caplog):
        session = Velvet(str(fixture), export_dir=str(tmp_path))
        with caplog.at_level(logging.ERROR, logger="velvet.session"):
            lines = session.run_printers()
        assert not caplog.records, "\n".join(r.getMessage() for r in caplog.records)
        assert lines  # all printers produced some output


# ------------------------------------------------------------------- CLI
class TestCli:
    def test_print_flag(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        code = main([str(SIMPLE), "--print", "human-summary,entry-points,solir"])
        out = capsys.readouterr().out
        assert code == 0
        assert "+ Contract Simple" in out
        assert "- setValue(uint256)" in out
        assert "Function: Simple.setValue(uint256)" in out
        assert "value := v" in out

    def test_print_graph_printers_write_to_cwd(self, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        code = main([str(TOKEN), "--print", "cfg,call-graph,inheritance-graph"])
        assert code == 0
        dots = {p.name: p.read_text() for p in tmp_path.glob("*.dot")}
        assert "Token.sol.Token.call-graph.dot" in dots
        assert "Token.inheritance-graph.dot" in dots
        assert any(name.endswith(".cfg.dot") for name in dots)
        for content in dots.values():
            assert content.lstrip().startswith("digraph")

    def test_list_printers(self, capsys):
        assert main(["--list-printers"]) == 0
        out = capsys.readouterr().out
        for rule in RULES:
            assert rule in out
