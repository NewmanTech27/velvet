"""Tests for velvet.compile (compilation layer)."""

from __future__ import annotations

from pathlib import Path

import pytest

from velvet.compile import (
    compile_target,
    convert_offset_to_line_column,
    is_dependency_path,
)
from velvet.compile.artifacts import Filename
from velvet.compile.versions import combined_specifier, parse_pragma, select_version

FIXTURES = Path(__file__).parent.parent / "fixtures" / "smoke"


# ---------------------------------------------------------------- versions
def test_parse_pragma_caret():
    spec = parse_pragma("pragma solidity ^0.8.0;")
    assert "0.8.24" in spec
    assert "0.9.0" not in spec
    assert "0.7.6" not in spec


def test_parse_pragma_range():
    spec = parse_pragma("pragma solidity >=0.6.0 <0.9.0;")
    assert "0.6.12" in spec
    assert "0.8.24" in spec
    assert "0.9.1" not in spec


def test_parse_pragma_exact():
    spec = parse_pragma("pragma solidity =0.8.24;")
    assert "0.8.24" in spec
    assert "0.8.25" not in spec


def test_parse_pragma_bare():
    spec = parse_pragma("pragma solidity 0.8.24;")
    assert "0.8.24" in spec


def test_combined_specifier_intersection():
    spec = combined_specifier(["pragma solidity >=0.8.0;", "pragma solidity <0.9.0;"])
    assert "0.8.24" in spec
    assert "0.9.0" not in spec


def test_select_version_installed():
    # 0.8.24 is installed in this environment
    v = select_version(["pragma solidity =0.8.24;"])
    assert v == "0.8.24"


# ---------------------------------------------------------------- artifacts
def test_offset_to_line_column_single_line():
    src = "contract A {}\n"
    lines, scol, ecol = convert_offset_to_line_column(src, 0, 8)
    assert lines == [1]
    assert scol == 1
    assert ecol == 9


def test_offset_to_line_column_multiline():
    src = "line one\nline two\nline three\n"
    start = src.index("two")
    lines, scol, ecol = convert_offset_to_line_column(src, start, 3)
    assert lines == [2]
    assert scol == 6


def test_offset_to_line_column_spanning_lines():
    src = "aaa\nbbb\nccc\n"
    lines, _, _ = convert_offset_to_line_column(src, 2, 6)  # from line1 into line2
    assert lines == [1, 2]


def test_is_dependency_path():
    assert is_dependency_path("/proj/node_modules/lib/x.sol")
    assert is_dependency_path("/proj/lib/forge-std/x.sol")
    assert not is_dependency_path("/proj/src/Token.sol")


def test_filename_defaults():
    f = Filename(absolute="/a/b/C.sol", used="src/C.sol")
    assert f.short == "C.sol"
    assert f.relative == "/a/b/C.sol"


# ------------------------------------------------------------- integration
@pytest.mark.integration
def test_compile_single_file():
    artifacts = compile_target(str(FIXTURES / "Simple.sol"))
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.compiler_version.startswith("0.8.")
    assert len(art.source_units) == 1
    unit = next(iter(art.source_units.values()))
    assert unit.ast["nodeType"] == "SourceUnit"
    assert "contract Simple" in unit.source


@pytest.mark.integration
def test_compile_project_dir():
    artifacts = compile_target(str(FIXTURES))
    art = artifacts[0]
    names = {u.filename.short for u in art.source_units.values()}
    assert {"Simple.sol", "Token.sol"} <= names
    # distinct source ids
    ids = list(art.source_units.keys())
    assert len(ids) == len(set(ids))
