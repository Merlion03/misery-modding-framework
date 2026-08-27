#!/usr/bin/env python3
"""Tests for pyghidra_scripts/dump_function.py (S-04).

Same split as tests/test_pyghidra_runner.py and
tests/test_dump_xrefs_for_string.py: no JVM here.
``describe_signature``/``decompile``/``sanity_check_c_code``/``disassemble``/
``one_level_calls``/``excerpt`` are exercised against small hand-built
stand-ins for ``Function``/``DecompInterface``/``DecompileResults``/
``Listing``/``Instruction``. The real decompiled output -- proof that a
function found from a real RTTI vtable slot decompiles to genuinely
plausible, independently-checkable C, not garbage -- is
``research/evidence/S-04/README.md``.
"""

from __future__ import annotations

import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "pyghidra_scripts"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "static"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dump_function as tool  # noqa: E402
import pathguard  # noqa: E402
from test_discovery import make_install_tree  # noqa: E402
from test_pyghidra_runner import FakeAddress, FakeFunction  # noqa: E402


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #

class FakeParameter:
    def __init__(self, ordinal, name, data_type):
        self._ordinal, self._name, self._data_type = ordinal, name, data_type

    def getOrdinal(self):
        return self._ordinal

    def getName(self):
        return self._name

    def getDataType(self):
        return self._data_type


class FakeAddressSet:
    def __init__(self, count):
        self._count = count

    def getNumAddresses(self):
        return self._count


class FakeSigFunction(FakeFunction):
    def __init__(self, entry, name, *, calling_convention="__cdecl",
                signature="void FUN(void)", return_type="void",
                parameters=None, body_size=10, is_thunk=False, is_external=False):
        super().__init__(entry, name, is_thunk=is_thunk, is_external=is_external)
        self._cc = calling_convention
        self._sig = signature
        self._ret = return_type
        self._params = parameters or []
        self._body = FakeAddressSet(body_size)

    def getCallingConventionName(self):
        return self._cc

    def getSignature(self, formal):
        return self._sig

    def getReturnType(self):
        return self._ret

    def getParameters(self):
        return list(self._params)

    def getParameterCount(self):
        return len(self._params)

    def getBody(self):
        return self._body

    def getCalledFunctions(self, monitor):
        return getattr(self, "_called", [])

    def getCallingFunctions(self, monitor):
        return getattr(self, "_calling", [])


class FakeDecompiledFunction:
    def __init__(self, c_code):
        self._c = c_code

    def getC(self):
        return self._c


class FakeDecompileResults:
    def __init__(self, *, completed=True, error=None, c_code="void f(void)\n{\n  return;\n}\n"):
        self._completed = completed
        self._error = error
        self._c_code = c_code

    def decompileCompleted(self):
        return self._completed

    def getErrorMessage(self):
        return self._error

    def getDecompiledFunction(self):
        return FakeDecompiledFunction(self._c_code) if self._completed else None


class FakeDecompiler:
    def __init__(self, results: FakeDecompileResults):
        self._results = results
        self.calls = []

    def decompileFunction(self, func, timeout, monitor):
        self.calls.append((func, timeout, monitor))
        return self._results


class FakeInstruction:
    def __init__(self, address, mnemonic, operands, length=1):
        self._addr = FakeAddress(address)
        self._mnemonic = mnemonic
        self._operands = operands
        self._length = length

    def getMinAddress(self):
        return self._addr

    def getMnemonicString(self):
        return self._mnemonic

    def getNumOperands(self):
        return len(self._operands)

    def getDefaultOperandRepresentation(self, i):
        return self._operands[i]

    def getLength(self):
        return self._length


class FakeListing:
    def __init__(self, instructions):
        self._instrs = instructions

    def getInstructions(self, body, forward):
        return list(self._instrs)


# --------------------------------------------------------------------------- #
# describe_signature
# --------------------------------------------------------------------------- #

def test_describe_signature_shape():
    func = FakeSigFunction(
        "1000", "FUN_1000", calling_convention="__thiscall",
        signature="void FUN_1000(undefined8 *this)", return_type="void",
        parameters=[FakeParameter(0, "this", "undefined8 *")])
    result = tool.describe_signature(func)
    assert result["calling_convention"] == "__thiscall"
    assert result["signature"] == "void FUN_1000(undefined8 *this)"
    assert result["return_type"] == "void"
    assert result["parameter_count"] == 1
    assert result["parameters"] == [{"ordinal": 0, "name": "this", "data_type": "undefined8 *"}]


def test_describe_signature_tolerates_a_raising_calling_convention():
    class Raising(FakeSigFunction):
        def getCallingConventionName(self):
            raise RuntimeError("unknown to Ghidra")

    func = Raising("1000", "FUN_1000")
    result = tool.describe_signature(func)
    assert result["calling_convention"] is None


# --------------------------------------------------------------------------- #
# decompile
# --------------------------------------------------------------------------- #

def test_decompile_success_reports_the_c_code():
    decompiler = FakeDecompiler(FakeDecompileResults(c_code="void f(void)\n{\n  return;\n}\n"))
    func = FakeSigFunction("1000", "FUN_1000")
    result = tool.decompile(decompiler, func, 60, monitor=None)
    assert result["succeeded"] is True
    assert result["error_message"] is None
    assert "return;" in result["c_code"]
    assert decompiler.calls[0][1] == 60


def test_decompile_failure_reports_exactly_what_ghidra_said():
    decompiler = FakeDecompiler(FakeDecompileResults(completed=False,
                                                     error="Unable to decompile function"))
    func = FakeSigFunction("1000", "FUN_1000")
    result = tool.decompile(decompiler, func, 60, monitor=None)
    assert result["succeeded"] is False
    assert result["error_message"] == "Unable to decompile function"
    assert result["c_code"] is None


# --------------------------------------------------------------------------- #
# sanity_check_c_code -- mechanical, not a correctness judgement
# --------------------------------------------------------------------------- #

def test_sanity_check_plausible_c():
    c = "void f(void)\n\n{\n  x = 1;\n  return;\n}\n"
    result = tool.sanity_check_c_code(c)
    assert result["plausible"] is True
    assert result["braces_balanced"] is True
    assert result["parens_balanced"] is True
    assert result["semicolon_count"] == 2


def test_sanity_check_empty_string_is_not_plausible():
    result = tool.sanity_check_c_code("")
    assert result["non_empty"] is False
    assert result["plausible"] is False


def test_sanity_check_unbalanced_braces_is_not_plausible():
    result = tool.sanity_check_c_code("void f(void) {\n  return;\n")
    assert result["braces_balanced"] is False
    assert result["plausible"] is False


def test_sanity_check_error_marker_is_not_plausible():
    result = tool.sanity_check_c_code("WARNING: Unable to decompile function")
    assert result["contains_error_marker"] is True
    assert result["plausible"] is False


# --------------------------------------------------------------------------- #
# disassemble
# --------------------------------------------------------------------------- #

def test_disassemble_one_row_per_instruction():
    listing = FakeListing([
        FakeInstruction("1000", "PUSH", ["RBX"], length=2),
        FakeInstruction("1002", "RET", [], length=1),
    ])
    rows, truncated = tool.disassemble(listing, body=None, max_instructions=100)
    assert truncated is False
    assert rows == [
        {"address": "1000", "mnemonic": "PUSH", "operands": ["RBX"], "length": 2},
        {"address": "1002", "mnemonic": "RET", "operands": [], "length": 1},
    ]


def test_disassemble_truncates_and_flags_it():
    listing = FakeListing([FakeInstruction(str(i), "NOP", []) for i in range(5)])
    rows, truncated = tool.disassemble(listing, body=None, max_instructions=3)
    assert len(rows) == 3
    assert truncated is True


def test_disassemble_multi_operand_instruction():
    listing = FakeListing([FakeInstruction("1000", "MOV", ["RAX", "0x8"])])
    rows, _ = tool.disassemble(listing, body=None, max_instructions=100)
    assert rows[0]["operands"] == ["RAX", "0x8"]


# --------------------------------------------------------------------------- #
# one_level_calls
# --------------------------------------------------------------------------- #

def test_one_level_calls_sorted_by_entry_address():
    func = FakeSigFunction("1000", "FUN_1000")
    func._called = [FakeFunction("3000", "FUN_3000"), FakeFunction("2000", "FUN_2000")]
    func._calling = [FakeFunction("0500", "FUN_0500")]
    outgoing, incoming = tool.one_level_calls(func, monitor=None)
    assert [f["entry"] for f in outgoing] == ["2000", "3000"]
    assert [f["entry"] for f in incoming] == ["0500"]


def test_one_level_calls_empty_when_none():
    func = FakeSigFunction("1000", "FUN_1000")
    outgoing, incoming = tool.one_level_calls(func, monitor=None)
    assert outgoing == []
    assert incoming == []


# --------------------------------------------------------------------------- #
# bound_call_list -- a popular address (5612 real callers found in
# research/evidence/S-04/README.md) must not blow up the JSON document
# --------------------------------------------------------------------------- #

def test_bound_call_list_under_the_cap_is_unchanged():
    calls = [{"entry": str(i)} for i in range(5)]
    bounded, truncated = tool.bound_call_list(calls, 10)
    assert bounded == calls
    assert truncated is False


def test_bound_call_list_over_the_cap_is_truncated_and_flagged():
    calls = [{"entry": str(i)} for i in range(5000)]
    bounded, truncated = tool.bound_call_list(calls, 100)
    assert len(bounded) == 100
    assert bounded == calls[:100]
    assert truncated is True


# --------------------------------------------------------------------------- #
# excerpt
# --------------------------------------------------------------------------- #

def test_excerpt_under_the_limit_is_unchanged():
    text = "a\nb\nc"
    result, truncated = tool.excerpt(text, 20)
    assert result == text
    assert truncated is False


def test_excerpt_over_the_limit_is_cut_and_flagged():
    text = "\n".join(str(i) for i in range(30))
    result, truncated = tool.excerpt(text, 5)
    assert result == "\n".join(str(i) for i in range(5))
    assert truncated is True


# --------------------------------------------------------------------------- #
# CLI argument parsing
# --------------------------------------------------------------------------- #

def test_function_is_required():
    with pytest.raises(SystemExit):
        tool.build_arg_parser().parse_args(["--out", "a.json"])


def test_defaults():
    args = tool.build_arg_parser().parse_args(["--function", "1000", "--out", "a.json"])
    assert args.decompile_timeout == tool.runner.DEFAULT_DECOMPILE_TIMEOUT_SECONDS
    assert args.max_instructions == tool.DEFAULT_MAX_INSTRUCTIONS
    assert args.excerpt_lines == tool.DEFAULT_EXCERPT_LINES
    assert args.c_out is None
    assert args.disasm_out is None


# --------------------------------------------------------------------------- #
# output-path guarding on main(), no JVM needed
# --------------------------------------------------------------------------- #

def test_main_refuses_an_out_path_inside_an_installation(tmp_path, capsys):
    install_root = make_install_tree(str(tmp_path / "install"))
    bad_out = os.path.join(install_root, "MISERY", "sneaky.json")
    rc = tool.main(["--function", "1000", "--out", bad_out,
                   "--install-dir", install_root])
    assert rc == 2
    assert "installation" in capsys.readouterr().err


def test_main_refuses_a_c_out_path_inside_an_installation(tmp_path, capsys):
    install_root = make_install_tree(str(tmp_path / "install"))
    bad_c_out = os.path.join(install_root, "MISERY", "sneaky.c")
    good_out = str(tmp_path / "ok.json")
    rc = tool.main(["--function", "1000", "--out", good_out, "--c-out", bad_c_out,
                   "--install-dir", install_root])
    assert rc == 2
    assert "installation" in capsys.readouterr().err
