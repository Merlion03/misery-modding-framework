#!/usr/bin/env python3
"""Tests for pyghidra_scripts/dump_xrefs_for_string.py (S-03).

See tests/test_pyghidra_runner.py's module docstring for what this family of
tests can and cannot cover -- the same split applies here: no test starts a
JVM. ``find_string_occurrences``/``find_xrefs_to_address``/
``build_records_and_summary`` are exercised against small hand-built
stand-ins for Ghidra's ``Listing``/``Data``/``ReferenceManager``/
``FunctionManager``, each shaped to exactly the narrow interface the
function's own docstring names. The CLI's output-path guard is exercised
for real (``main()`` really refuses a path inside a synthetic installation)
because that refusal happens BEFORE anything Ghidra-related is touched, so
it needs no JVM either. The real run against the T05 project is
``research/evidence/S-03/README.md``.
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

import dump_xrefs_for_string as tool  # noqa: E402
import pathguard  # noqa: E402
from test_discovery import make_install_tree  # noqa: E402
from test_pyghidra_runner import FakeAddress, FakeFunction, FakeRefType  # noqa: E402


# --------------------------------------------------------------------------- #
# fakes for Listing / Data / ReferenceManager / FunctionManager / Reference
# --------------------------------------------------------------------------- #

class FakeData:
    def __init__(self, address: str, value, length: int, has_string=True):
        self._addr = FakeAddress(address)
        self._value = value
        self._length = length
        self._has_string = has_string

    def hasStringValue(self):
        return self._has_string

    def getValue(self):
        return self._value

    def getAddress(self):
        return self._addr

    def getLength(self):
        return self._length


class FakeListing:
    def __init__(self, data_items: list[FakeData]):
        self._items = data_items

    def getDefinedData(self, forward: bool):
        return list(self._items)


class FakeReference:
    def __init__(self, from_addr: str, ref_type: FakeRefType, primary=True):
        self._from = FakeAddress(from_addr)
        self._type = ref_type
        self._primary = primary

    def getFromAddress(self):
        return self._from

    def getReferenceType(self):
        return self._type

    def isPrimary(self):
        return self._primary


class FakeReferenceManager:
    def __init__(self, refs_by_address: dict[str, list[FakeReference]]):
        self._refs = refs_by_address

    def getReferencesTo(self, address):
        key = address.text if isinstance(address, FakeAddress) else address
        return list(self._refs.get(key, []))


class FakeFunctionManagerForXrefs:
    """A narrower fake than test_pyghidra_runner's: getFunctionContaining
    keyed directly by from-address text, matching real Ghidra's ability to
    map ANY address inside a function's body, not just its entry point."""

    def __init__(self, containing: dict[str, FakeFunction]):
        self._containing = containing

    def getFunctionContaining(self, addr):
        key = addr.text if isinstance(addr, FakeAddress) else addr
        return self._containing.get(key)


class FakeProgramForXrefs:
    def __init__(self, listing, ref_mgr, func_mgr, address_factory):
        self._listing = listing
        self._ref_mgr = ref_mgr
        self._func_mgr = func_mgr
        self._af = address_factory

    def getListing(self):
        return self._listing

    def getReferenceManager(self):
        return self._ref_mgr

    def getFunctionManager(self):
        return self._func_mgr

    def getAddressFactory(self):
        return self._af


class FakeAddressFactory:
    def getAddress(self, text):
        return FakeAddress(text)


# --------------------------------------------------------------------------- #
# string_matches
# --------------------------------------------------------------------------- #

def test_string_matches_substring_default():
    assert tool.string_matches("/Script/CoreUObject", "CoreUObject",
                              whole_string=False, ignore_case=False)


def test_string_matches_whole_string_rejects_a_substring():
    assert not tool.string_matches("/Script/CoreUObject", "CoreUObject",
                                  whole_string=True, ignore_case=False)


def test_string_matches_whole_string_accepts_exact_equality():
    assert tool.string_matches("CoreUObject", "CoreUObject",
                              whole_string=True, ignore_case=False)


def test_string_matches_is_case_sensitive_by_default():
    assert not tool.string_matches("coreuobject", "CoreUObject",
                                  whole_string=False, ignore_case=False)


def test_string_matches_ignore_case():
    assert tool.string_matches("COREUOBJECT", "CoreUObject",
                              whole_string=False, ignore_case=True)


# --------------------------------------------------------------------------- #
# find_string_occurrences
# --------------------------------------------------------------------------- #

def test_find_string_occurrences_finds_substring_hits():
    listing = FakeListing([
        FakeData("1000", "/Script/CoreUObject", 20),
        FakeData("2000", "SomethingElse", 13),
    ])
    hits = tool.find_string_occurrences(listing, ["CoreUObject"])
    assert len(hits) == 1
    assert hits[0]["address"] == "1000"
    assert hits[0]["value"] == "/Script/CoreUObject"
    assert hits[0]["needle"] == "CoreUObject"


def test_find_string_occurrences_skips_non_string_data():
    listing = FakeListing([FakeData("1000", "CoreUObject", 11, has_string=False)])
    assert tool.find_string_occurrences(listing, ["CoreUObject"]) == []


def test_find_string_occurrences_skips_none_value():
    listing = FakeListing([FakeData("1000", None, 0, has_string=True)])
    assert tool.find_string_occurrences(listing, ["CoreUObject"]) == []


def test_find_string_occurrences_one_record_per_matching_needle():
    # A data item matching two needles yields two occurrence records --
    # so the per-needle counts in the summary add up correctly.
    listing = FakeListing([FakeData("1000", "/Script/CoreUObject", 20)])
    hits = tool.find_string_occurrences(listing, ["CoreUObject", "Script"])
    assert {h["needle"] for h in hits} == {"CoreUObject", "Script"}
    assert len(hits) == 2


def test_find_string_occurrences_truncates_and_flags_it():
    listing = FakeListing([FakeData("1000", "x" * 100, 100)])
    hits = tool.find_string_occurrences(listing, ["x"], max_string_length=10)
    assert len(hits[0]["value"]) == 10
    assert hits[0]["value_truncated"] is True


# --------------------------------------------------------------------------- #
# find_xrefs_to_address
# --------------------------------------------------------------------------- #

def test_find_xrefs_to_address_reports_referencing_address_and_type():
    data_ref_type = FakeRefType("DATA", data=True)
    ref_mgr = FakeReferenceManager({"1000": [FakeReference("2000", data_ref_type)]})
    func = FakeFunction("1f00", "FUN_1f00")
    func_mgr = FakeFunctionManagerForXrefs({"2000": func})
    xrefs = tool.find_xrefs_to_address(ref_mgr, func_mgr, FakeAddress("1000"))
    assert len(xrefs) == 1
    assert xrefs[0]["referencing_address"] == "2000"
    assert xrefs[0]["containing_function"]["name"] == "FUN_1f00"
    assert xrefs[0]["reference_type"]["bucket"] == "DATA"
    assert xrefs[0]["is_primary"] is True


def test_find_xrefs_to_address_containing_function_none_when_unowned():
    data_ref_type = FakeRefType("DATA", data=True)
    ref_mgr = FakeReferenceManager({"1000": [FakeReference("2000", data_ref_type)]})
    func_mgr = FakeFunctionManagerForXrefs({})  # nothing owns 2000
    xrefs = tool.find_xrefs_to_address(ref_mgr, func_mgr, FakeAddress("1000"))
    assert xrefs[0]["containing_function"] is None


def test_find_xrefs_to_address_empty_when_no_refs():
    ref_mgr = FakeReferenceManager({})
    func_mgr = FakeFunctionManagerForXrefs({})
    assert tool.find_xrefs_to_address(ref_mgr, func_mgr, FakeAddress("1000")) == []


# --------------------------------------------------------------------------- #
# build_records_and_summary -- the end-to-end wiring, still fully faked
# --------------------------------------------------------------------------- #

def test_build_records_and_summary_counts_are_consistent():
    data_ref_type = FakeRefType("DATA", data=True)
    listing = FakeListing([FakeData("1000", "/Script/CoreUObject", 20)])
    ref_mgr = FakeReferenceManager({
        "1000": [FakeReference("2000", data_ref_type),
                FakeReference("3000", data_ref_type)],
    })
    caller_a = FakeFunction("1f00", "FUN_1f00")
    func_mgr = FakeFunctionManagerForXrefs({"2000": caller_a, "3000": caller_a})
    program = FakeProgramForXrefs(listing, ref_mgr, func_mgr, FakeAddressFactory())

    records, counts = tool.build_records_and_summary(
        program, ["CoreUObject"], whole_string=False, ignore_case=False,
        max_string_length=2000)

    assert counts["occurrence_count"] == 1
    assert counts["xref_count"] == 2
    assert len(records) == 2
    # Both xrefs point at the same caller function, so exactly one distinct
    # containing function despite two xrefs.
    assert counts["distinct_containing_functions"] == 1
    assert counts["xrefs_per_needle"] == {"CoreUObject": 2}
    assert counts["reference_type_histogram"] == {"DATA": 2}
    assert counts["occurrences_with_no_xrefs"] == 0


def test_build_records_and_summary_counts_occurrences_with_no_xrefs():
    listing = FakeListing([FakeData("1000", "CoreUObject", 11)])
    ref_mgr = FakeReferenceManager({})  # no xrefs to anything
    func_mgr = FakeFunctionManagerForXrefs({})
    program = FakeProgramForXrefs(listing, ref_mgr, func_mgr, FakeAddressFactory())

    records, counts = tool.build_records_and_summary(
        program, ["CoreUObject"], whole_string=False, ignore_case=False,
        max_string_length=2000)
    assert records == []
    assert counts["occurrence_count"] == 1
    assert counts["occurrences_with_no_xrefs"] == 1


# --------------------------------------------------------------------------- #
# CLI argument parsing
# --------------------------------------------------------------------------- #

def test_needle_is_repeatable():
    args = tool.build_arg_parser().parse_args(
        ["--needle", "CoreUObject", "--needle", "/Script/CoreUObject",
         "--out", "a.json", "--jsonl-out", "a.jsonl"])
    assert args.needle == ["CoreUObject", "/Script/CoreUObject"]


def test_needle_is_required(capsys):
    with pytest.raises(SystemExit):
        tool.build_arg_parser().parse_args(["--out", "a.json", "--jsonl-out", "a.jsonl"])


def test_defaults_match_the_t05_project():
    args = tool.build_arg_parser().parse_args(
        ["--needle", "x", "--out", "a.json", "--jsonl-out", "a.jsonl"])
    assert args.whole_string is False
    assert args.ignore_case is False
    assert args.max_string_length == tool.DEFAULT_MAX_STRING_LENGTH
    assert args.project_name == "T05-primary-default-analysis"


# --------------------------------------------------------------------------- #
# output-path guarding on main(), no JVM needed (refused before Ghidra opens)
# --------------------------------------------------------------------------- #

def test_main_refuses_an_out_path_inside_an_installation(tmp_path, capsys):
    install_root = make_install_tree(str(tmp_path / "install"))
    bad_out = os.path.join(install_root, "MISERY", "sneaky.json")
    good_jsonl = str(tmp_path / "ok.jsonl")
    rc = tool.main(["--needle", "x", "--out", bad_out, "--jsonl-out", good_jsonl,
                   "--install-dir", install_root])
    assert rc == 2
    assert "installation" in capsys.readouterr().err


def test_main_refuses_a_jsonl_out_path_inside_an_installation(tmp_path, capsys):
    install_root = make_install_tree(str(tmp_path / "install"))
    bad_jsonl = os.path.join(install_root, "MISERY", "sneaky.jsonl")
    good_out = str(tmp_path / "ok.json")
    rc = tool.main(["--needle", "x", "--out", good_out, "--jsonl-out", bad_jsonl,
                   "--install-dir", install_root])
    assert rc == 2
    assert "installation" in capsys.readouterr().err
