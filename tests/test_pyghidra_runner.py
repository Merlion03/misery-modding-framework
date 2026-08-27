#!/usr/bin/env python3
"""Tests for pyghidra_scripts/_pyghidra_runner.py (S-03/S-04/S-05 shared driver).

What is and is not tested here, and why
---------------------------------------
This module's whole point is opening a live Ghidra ``Program`` through
PyGhidra, and that is not something a test suite can do cheaply: it needs an
863 MB Ghidra install, a pinned JDK, and (for anything beyond "the JVM
starts") the 2 GiB T05 project this wave reuses. No test here starts a JVM
or opens a project -- that is what ``research/evidence/S-03/README.md``,
``S-04/README.md`` and ``S-05/README.md`` record instead, against the real
project, with real numbers.

What IS tested is everything this module does BEFORE or AROUND that call:
argument-group wiring, address/function resolution against small hand-built
stand-ins for Ghidra's ``Program``/``Address``/``Function`` objects (the
narrow interfaces each helper's own docstring names), reference-type
classification against a hand-built ``RefType``-shaped object, the
target-copy hash gate, and the output-path guard -- the same split
``tests/test_ghidra_import.py`` documents and uses for the same reason.

One thing IS tested for real: :func:`_pyghidra_runner.require_pyghidra`
succeeds under THIS interpreter, because the canonical interpreter
(``D:\\Tools\\venv-research\\Scripts\\python.exe``) is exactly the one gate
requires tests to run under, so pyghidra/jpype genuinely are importable here.
Its failure path is exercised by temporarily hiding both modules from
``sys.modules`` rather than by running under a different interpreter.
"""

from __future__ import annotations

import hashlib
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "pyghidra_scripts"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "static"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _pyghidra_runner as runner  # noqa: E402
import pathguard  # noqa: E402
from test_discovery import make_install_tree  # noqa: E402


# --------------------------------------------------------------------------- #
# fakes standing in for the Ghidra/jpype objects the helpers actually touch
# --------------------------------------------------------------------------- #

class FakeAddress:
    """Stands in for ``ghidra.program.model.address.Address``: only needs to
    be ``str()``-able and comparable, both of which real Ghidra addresses
    also support."""

    def __init__(self, text: str):
        self.text = text

    def __str__(self) -> str:
        return self.text

    def __eq__(self, other):
        return isinstance(other, FakeAddress) and self.text == other.text

    def __hash__(self):
        return hash(self.text)


class FakeAddressFactory:
    def __init__(self, valid_hex_prefix_len: int = 9):
        self._len = valid_hex_prefix_len

    def getAddress(self, text: str):
        # Real AddressFactory.getAddress returns None for something it
        # cannot place in any address space; mirrored here for the "bad
        # address" test.
        if not text or any(c not in "0123456789abcdefABCDEF" for c in text):
            return None
        return FakeAddress(text)


class FakeFunction:
    def __init__(self, entry: str, name: str, *, is_thunk=False, is_external=False):
        self.entry = FakeAddress(entry)
        self.name = name
        self._is_thunk = is_thunk
        self._is_external = is_external

    def getEntryPoint(self):
        return self.entry

    def getName(self):
        return self.name

    def isThunk(self):
        return self._is_thunk

    def isExternal(self):
        return self._is_external


class FakeFunctionManager:
    def __init__(self, functions: list[FakeFunction]):
        self._by_entry = {f.getEntryPoint().text: f for f in functions}
        self._all = functions

    def getFunctionAt(self, addr):
        return self._by_entry.get(addr.text if isinstance(addr, FakeAddress) else addr)

    def getFunctionContaining(self, addr):
        # Simplified: only exact-entry containment, sufficient for the tests
        # that use it (resolve_function's fallback path).
        return self.getFunctionAt(addr)

    def getFunctions(self, forward: bool):
        return list(self._all)


class FakeProgram:
    def __init__(self, functions: list[FakeFunction]):
        self._af = FakeAddressFactory()
        self._fm = FakeFunctionManager(functions)

    def getAddressFactory(self):
        return self._af

    def getFunctionManager(self):
        return self._fm


class FakeRefType:
    """Stands in for ``ghidra.program.model.symbol.RefType``/``FlowType``:
    real Ghidra's is*() predicates are independent booleans, not a
    partition, and this fake preserves that (see classify_ref_type's own
    docstring)."""

    def __init__(self, name, *, call=False, jump=False, data=False, read=False,
                write=False, flow=False, computed=False, conditional=False):
        self._name = name
        self._call, self._jump, self._data = call, jump, data
        self._read, self._write, self._flow = read, write, flow
        self._computed, self._conditional = computed, conditional

    def getName(self):
        return self._name

    def isCall(self):
        return self._call

    def isJump(self):
        return self._jump

    def isData(self):
        return self._data

    def isRead(self):
        return self._read

    def isWrite(self):
        return self._write

    def isFlow(self):
        return self._flow

    def isComputed(self):
        return self._computed

    def isConditional(self):
        return self._conditional


# --------------------------------------------------------------------------- #
# parse_address
# --------------------------------------------------------------------------- #

def test_parse_address_accepts_bare_hex():
    program = FakeProgram([])
    addr = runner.parse_address(program, "140f4d8e0")
    assert str(addr) == "140f4d8e0"


def test_parse_address_strips_0x_prefix():
    # Ghidra's own AddressFactory.getAddress does not recognise "0x" -- the
    # prefix must be stripped before it ever reaches Ghidra's parser.
    program = FakeProgram([])
    addr = runner.parse_address(program, "0x140f4d8e0")
    assert str(addr) == "140f4d8e0"


def test_parse_address_rejects_empty_string():
    with pytest.raises(ValueError, match="empty"):
        runner.parse_address(FakeProgram([]), "")


def test_parse_address_rejects_non_hex():
    with pytest.raises(ValueError, match="hex"):
        runner.parse_address(FakeProgram([]), "not-an-address")


def test_parse_address_surfaces_a_none_from_the_address_factory():
    # A FakeAddressFactory that refuses every address exercises the "Ghidra
    # itself could not resolve it" branch, distinct from "not hex-shaped".
    class RefusingFactory(FakeAddressFactory):
        def getAddress(self, text):
            return None

    program = FakeProgram([])
    program._af = RefusingFactory()
    with pytest.raises(ValueError, match="could not resolve"):
        runner.parse_address(program, "deadbeef")


# --------------------------------------------------------------------------- #
# resolve_function
# --------------------------------------------------------------------------- #

def test_resolve_function_by_hex_entry_point():
    target = FakeFunction("140f4d8e0", "FUN_140f4d8e0")
    program = FakeProgram([target])
    assert runner.resolve_function(program, "140f4d8e0") is target


def test_resolve_function_by_exact_name():
    target = FakeFunction("1414e6930", "std_exception_what")
    program = FakeProgram([target])
    assert runner.resolve_function(program, "std_exception_what") is target


def test_resolve_function_ambiguous_name_lists_every_address():
    # Real Ghidra genuinely produces this: switch-case fragment names like
    # "caseD_1" repeat across unrelated functions (found against the real
    # T05 project -- research/evidence/S-04/README.md).
    a = FakeFunction("140f309c0", "caseD_1")
    b = FakeFunction("1459e9890", "caseD_1")
    program = FakeProgram([a, b])
    with pytest.raises(ValueError) as caught:
        runner.resolve_function(program, "caseD_1")
    assert "140f309c0" in str(caught.value)
    assert "1459e9890" in str(caught.value)
    assert "2 functions" in str(caught.value)


def test_resolve_function_unknown_name_names_what_was_tried():
    program = FakeProgram([FakeFunction("140f4d8e0", "FUN_140f4d8e0")])
    with pytest.raises(ValueError, match="does-not-exist"):
        runner.resolve_function(program, "does-not-exist")


def test_resolve_function_hex_with_no_function_there_falls_back_to_name_search():
    # "beef" parses as hex but nothing is defined there; resolve_function
    # must not raise from the address branch alone, it must also try the
    # name branch (and only then fail, naming the input once).
    program = FakeProgram([FakeFunction("140f4d8e0", "FUN_140f4d8e0")])
    with pytest.raises(ValueError, match="beef"):
        runner.resolve_function(program, "beef")


# --------------------------------------------------------------------------- #
# describe_function_brief
# --------------------------------------------------------------------------- #

def test_describe_function_brief_shape():
    f = FakeFunction("140f4d8e0", "FUN_140f4d8e0", is_thunk=True, is_external=False)
    assert runner.describe_function_brief(f) == {
        "name": "FUN_140f4d8e0", "entry": "140f4d8e0",
        "is_thunk": True, "is_external": False,
    }


def test_describe_function_brief_of_none_is_none():
    # The "no containing function" case S-03/S-05 both need to represent.
    assert runner.describe_function_brief(None) is None


# --------------------------------------------------------------------------- #
# classify_ref_type
# --------------------------------------------------------------------------- #

def test_classify_ref_type_call_bucket():
    rt = FakeRefType("UNCONDITIONAL_CALL", call=True, flow=True)
    result = runner.classify_ref_type(rt)
    assert result["name"] == "UNCONDITIONAL_CALL"
    assert result["bucket"] == "CALL"
    assert result["is_call"] is True


def test_classify_ref_type_data_bucket():
    rt = FakeRefType("DATA", data=True)
    result = runner.classify_ref_type(rt)
    assert result["bucket"] == "DATA"
    assert result["is_call"] is False


def test_classify_ref_type_priority_call_over_write():
    # A reference could in principle satisfy more than one predicate;
    # CALL must win the coarse bucket even if isWrite() also happens to be
    # true, because "this is a call" is the more informative fact.
    rt = FakeRefType("CALL_AND_WRITE", call=True, write=True)
    assert runner.classify_ref_type(rt)["bucket"] == "CALL"


def test_classify_ref_type_falls_back_to_other():
    rt = FakeRefType("FALL_THROUGH")
    assert runner.classify_ref_type(rt)["bucket"] == "OTHER"


# --------------------------------------------------------------------------- #
# verify_target_copy
# --------------------------------------------------------------------------- #

def test_verify_target_copy_matches(tmp_path):
    target = tmp_path / "x.exe"
    target.write_bytes(b"hello world")
    expected = hashlib.sha256(b"hello world").hexdigest()
    record = runner.verify_target_copy(str(target), expected)
    assert record["sha256_matches"] is True
    assert record["sha256"] == expected
    assert record["bytes"] == 11


def test_verify_target_copy_mismatch_raises(tmp_path):
    target = tmp_path / "x.exe"
    target.write_bytes(b"hello world")
    with pytest.raises(runner.PrerequisiteError, match="mismatch"):
        runner.verify_target_copy(str(target), "0" * 64)


def test_verify_target_copy_missing_file_raises(tmp_path):
    with pytest.raises(runner.PrerequisiteError, match="not found"):
        runner.verify_target_copy(str(tmp_path / "does-not-exist.exe"), None)


def test_verify_target_copy_none_expected_always_matches(tmp_path):
    target = tmp_path / "x.exe"
    target.write_bytes(b"anything")
    record = runner.verify_target_copy(str(target), None)
    assert record["sha256_matches"] is True


# --------------------------------------------------------------------------- #
# output-path guarding (layer 1, D-01) -- same discipline as every other tool
# --------------------------------------------------------------------------- #

def test_write_json_guarded_refuses_a_path_inside_an_installation(tmp_path):
    install_root = make_install_tree(str(tmp_path / "install"))
    bad_out = os.path.join(install_root, "MISERY", "sneaky.json")
    with pytest.raises(pathguard.OutputPathRefused):
        runner.write_json_guarded({"a": 1}, bad_out, install_root, "--out")


def test_write_jsonl_guarded_refuses_a_path_inside_an_installation(tmp_path):
    install_root = make_install_tree(str(tmp_path / "install"))
    bad_out = os.path.join(install_root, "MISERY", "sneaky.jsonl")
    with pytest.raises(pathguard.OutputPathRefused):
        runner.write_jsonl_guarded([{"a": 1}], bad_out, install_root, "--jsonl-out")


def test_write_json_guarded_writes_sorted_indented_json(tmp_path):
    # install_root must be somewhere OTHER than out's own directory -- an
    # install_root that happens to contain the output path is exactly the
    # "protected" case OutputPathRefused tests above already cover.
    out = tmp_path / "out" / "doc.json"
    elsewhere = str(tmp_path / "unrelated-install-root")
    written = runner.write_json_guarded({"b": 2, "a": 1}, str(out), elsewhere, "--out")
    text = open(written, encoding="utf-8").read()
    assert text.index('"a"') < text.index('"b"')  # sort_keys
    assert text.endswith("\n")
    assert "\r\n" not in text  # LF, not CRLF


def test_write_jsonl_guarded_one_object_per_line(tmp_path):
    out = tmp_path / "out.jsonl"
    elsewhere = str(tmp_path / "unrelated-install-root")
    written = runner.write_jsonl_guarded([{"a": 1}, {"a": 2}], str(out), elsewhere,
                                        "--jsonl-out")
    lines = open(written, encoding="utf-8").read().splitlines()
    assert lines == ['{"a": 1}', '{"a": 2}']


def test_dump_jsonl_empty_list_is_empty_string():
    assert runner.dump_jsonl([]) == ""


# --------------------------------------------------------------------------- #
# common CLI argument group
# --------------------------------------------------------------------------- #

def test_add_common_arguments_defaults_point_at_the_reused_t05_project():
    import argparse
    parser = argparse.ArgumentParser()
    runner.add_common_arguments(parser)
    args = parser.parse_args([])
    assert args.project_name == runner.DEFAULT_PROJECT_NAME
    assert args.program == runner.DEFAULT_PROGRAM_PATH
    assert args.expect_sha256 == runner.DEFAULT_EXPECT_SHA256
    assert args.skip_copy_verification is False
    assert args.recorded_at is None


def test_recorded_at_uses_the_override_when_given():
    import argparse
    parser = argparse.ArgumentParser()
    runner.add_common_arguments(parser)
    args = parser.parse_args(["--recorded-at", "2020-01-01T00:00:00Z"])
    assert runner.recorded_at(args) == "2020-01-01T00:00:00Z"


def test_recorded_at_defaults_to_now_when_unset():
    import argparse
    parser = argparse.ArgumentParser()
    runner.add_common_arguments(parser)
    args = parser.parse_args([])
    stamp = runner.recorded_at(args)
    assert stamp.endswith("Z")
    assert len(stamp) == len("2026-08-26T00:00:00Z")


# --------------------------------------------------------------------------- #
# require_pyghidra
# --------------------------------------------------------------------------- #

def test_require_pyghidra_succeeds_under_the_canonical_interpreter():
    # This test file is only meaningful run under
    # D:\Tools\venv-research\Scripts\python.exe (the gate's interpreter),
    # under which pyghidra/jpype genuinely are installed.
    runner.require_pyghidra()  # must not raise


def test_require_pyghidra_names_the_fix_when_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "pyghidra", None)
    monkeypatch.setitem(sys.modules, "jpype", None)
    with pytest.raises(runner.PyGhidraUnavailable) as caught:
        runner.require_pyghidra()
    assert "venv-research" in str(caught.value)
    assert "python.exe" in str(caught.value)


# --------------------------------------------------------------------------- #
# generator identity / defaults sanity
# --------------------------------------------------------------------------- #

def test_default_build_key_matches_the_expected_sha256():
    assert runner.DEFAULT_BUILD_KEY == "sha256:" + runner.DEFAULT_EXPECT_SHA256


def test_reused_constants_come_from_ghidra_import_not_a_second_copy():
    # DRY check: these must be the SAME values ghidra_import.py itself uses,
    # imported rather than retyped (a retyped copy is exactly the drift
    # pathguard's own docstring warns about).
    import ghidra_import as gi
    assert runner.DEFAULT_GHIDRA_ROOT == gi.DEFAULT_GHIDRA_ROOT
    assert runner.DEFAULT_JDK_HOME == gi.DEFAULT_JDK_HOME
    assert runner.REQUIRED_JDK_MAJOR == gi.REQUIRED_JDK_MAJOR
    assert runner.dump_json is gi.dump_json
    assert runner.now_iso_utc is gi.now_iso_utc
    assert runner.sha256_file is gi.sha256_file
