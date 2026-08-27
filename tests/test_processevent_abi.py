#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for tools/reflection/processevent_abi.py (Phase 2 -- ProcessEvent
parameter-marshaling-safety classification, per the user's own explicit
directive after PE-02's live confirmation, research/RESEARCH_LOG.md
LOG-0056/LOG-0057).

Standard library only. This tool is offline analysis over already-committed
JSONL -- no live process, no ctypes, no game installation -- so these tests
never touch anything outside this repo's own files, and the one end-to-end
test that DOES read a real committed file
(research/reflection/misery-24953925-ue5.4.4-bace50f7185d/functions.jsonl,
I-05's own real 247-row output) is read-only and pins its own real numbers
as a regression, not a live-process test.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "reflection"))

import processevent_abi as tool  # noqa: E402

REAL_FUNCTIONS_JSONL = os.path.join(
    REPO_ROOT, "research", "reflection",
    "misery-24953925-ue5.4.4-bace50f7185d", "functions.jsonl")


# --------------------------------------------------------------------------- #
# classify_parameter_marshaling -- the CPF_IsPlainOldData/CPF_ZeroConstructor/
# CPF_NoDestructor rule itself.
# --------------------------------------------------------------------------- #

def _param(property_class="FIntProperty", flags=0):
    return {"property_class": property_class, "flags_raw": "0x%x" % flags}


def test_trivial_when_all_three_flags_set():
    flags = tool.CPF_IS_PLAIN_OLD_DATA | tool.CPF_ZERO_CONSTRUCTOR | tool.CPF_NO_DESTRUCTOR
    assert tool.classify_parameter_marshaling(_param(flags=flags)) == tool.TIER_TRIVIAL


def test_unsupported_when_no_flags_set():
    assert tool.classify_parameter_marshaling(_param(flags=0)) == tool.TIER_UNSUPPORTED


def test_unsupported_missing_no_destructor_even_if_pod_and_zeroctor():
    # FStrProperty/FArrayProperty-shaped: real cleanup required.
    flags = tool.CPF_IS_PLAIN_OLD_DATA | tool.CPF_ZERO_CONSTRUCTOR
    assert tool.classify_parameter_marshaling(
        _param(property_class="FStrProperty", flags=flags)) == tool.TIER_UNSUPPORTED


def test_object_reference_tier_for_object_property_without_pod():
    # Real observed pattern (I-06 live data): FObjectProperty has
    # ZeroConstructor+NoDestructor but NOT IsPlainOldData.
    flags = tool.CPF_ZERO_CONSTRUCTOR | tool.CPF_NO_DESTRUCTOR
    assert tool.classify_parameter_marshaling(
        _param(property_class="FObjectProperty", flags=flags)) == tool.TIER_OBJECT_REFERENCE
    assert tool.classify_parameter_marshaling(
        _param(property_class="FClassProperty", flags=flags)) == tool.TIER_OBJECT_REFERENCE
    assert tool.classify_parameter_marshaling(
        _param(property_class="FWeakObjectProperty", flags=flags)) == tool.TIER_OBJECT_REFERENCE


def test_object_reference_flags_alone_do_not_promote_a_non_reference_class():
    # Same two flags, but NOT one of the three recognised reference classes
    # -- e.g. a struct that happens to share the flag pattern must NOT be
    # silently treated as a pointer.
    flags = tool.CPF_ZERO_CONSTRUCTOR | tool.CPF_NO_DESTRUCTOR
    assert tool.classify_parameter_marshaling(
        _param(property_class="FStructProperty", flags=flags)) == tool.TIER_UNSUPPORTED


def test_bitfield_bool_is_unsupported_native_bool_is_trivial():
    # Real observed pattern (I-06 live data, MiseryEditableText::bStartEditing
    # etc.): a native full-byte bool has all three flags; a packed bitfield
    # bool does not (writing it would clobber sibling bits without a
    # read-modify-write this tool never attempts).
    native_bool_flags = tool.CPF_IS_PLAIN_OLD_DATA | tool.CPF_ZERO_CONSTRUCTOR | tool.CPF_NO_DESTRUCTOR
    bitfield_bool_flags = tool.CPF_NO_DESTRUCTOR  # POD/ZeroConstructor NOT set.
    assert tool.classify_parameter_marshaling(
        _param(property_class="FBoolProperty", flags=native_bool_flags)) == tool.TIER_TRIVIAL
    assert tool.classify_parameter_marshaling(
        _param(property_class="FBoolProperty", flags=bitfield_bool_flags)) == tool.TIER_UNSUPPORTED


def test_missing_flags_raw_is_unsupported_never_guessed():
    param = {"property_class": "FIntProperty"}  # no 'flags_raw' key at all.
    assert tool.classify_parameter_marshaling(param) == tool.TIER_UNSUPPORTED


def test_property_flags_raw_key_also_accepted():
    # I-06's own property_record uses 'property_flags_raw', not 'flags_raw'
    # (I-05's own parameters[] uses 'flags_raw') -- both must work.
    flags = tool.CPF_IS_PLAIN_OLD_DATA | tool.CPF_ZERO_CONSTRUCTOR | tool.CPF_NO_DESTRUCTOR
    param = {"property_class": "FIntProperty", "property_flags_raw": "0x%x" % flags}
    assert tool.classify_parameter_marshaling(param) == tool.TIER_TRIVIAL


# --------------------------------------------------------------------------- #
# classify_function_eligibility
# --------------------------------------------------------------------------- #

def _trivial_param(name="ReturnValue", is_return=False, is_out=False):
    flags = tool.CPF_IS_PLAIN_OLD_DATA | tool.CPF_ZERO_CONSTRUCTOR | tool.CPF_NO_DESTRUCTOR
    return {
        "name": name, "property_class": "FIntProperty", "flags_raw": "0x%x" % flags,
        "is_return": is_return, "is_out": is_out, "is_reference": False,
    }


def _unsupported_param(name="Text"):
    return {
        "name": name, "property_class": "FStrProperty", "flags_raw": "0x0",
        "is_return": False, "is_out": False, "is_reference": False,
    }


def _function(raw_name="DoStuff", owner="SomeClass", parameters=None, **overrides):
    base = {
        "raw_name": raw_name, "owner": owner, "parameters": parameters or [],
        "is_native": True, "is_static": True, "is_event": False, "is_net": False,
        "parms_size": 0, "local_variable_count": 0,
    }
    base.update(overrides)
    return base


def test_zero_parameter_function_is_strict_eligible():
    entry = tool.classify_function_eligibility(_function(parameters=[]))
    assert entry["strict_eligible"] is True
    assert entry["eligible_with_object_refs"] is True
    assert entry["parameter_tiers"] == []


def test_all_trivial_parameters_is_strict_eligible():
    entry = tool.classify_function_eligibility(
        _function(parameters=[_trivial_param("A"), _trivial_param("B")]))
    assert entry["strict_eligible"] is True
    assert entry["parameter_tiers"] == [tool.TIER_TRIVIAL, tool.TIER_TRIVIAL]


def test_object_reference_parameter_excludes_strict_but_allows_with_refs():
    flags = tool.CPF_ZERO_CONSTRUCTOR | tool.CPF_NO_DESTRUCTOR
    obj_param = {
        "name": "Target", "property_class": "FObjectProperty",
        "flags_raw": "0x%x" % flags, "is_return": False, "is_out": False,
        "is_reference": False,
    }
    entry = tool.classify_function_eligibility(
        _function(parameters=[_trivial_param("A"), obj_param]))
    assert entry["strict_eligible"] is False
    assert entry["eligible_with_object_refs"] is True


def test_unsupported_parameter_excludes_both_tiers():
    entry = tool.classify_function_eligibility(
        _function(parameters=[_trivial_param("A"), _unsupported_param("B")]))
    assert entry["strict_eligible"] is False
    assert entry["eligible_with_object_refs"] is False


def test_mutation_and_getter_name_heuristics():
    spawn_entry = tool.classify_function_eligibility(_function(raw_name="SpawnActor"))
    assert spawn_entry["looks_like_mutation"] is True
    getter_entry = tool.classify_function_eligibility(_function(raw_name="IsSteamDeck"))
    assert getter_entry["looks_like_mutation"] is False
    assert getter_entry["looks_like_getter"] is True


# --------------------------------------------------------------------------- #
# rank_candidates -- ordering rules.
# --------------------------------------------------------------------------- #

def test_rank_prefers_strict_over_object_ref_tier():
    flags_ref = tool.CPF_ZERO_CONSTRUCTOR | tool.CPF_NO_DESTRUCTOR
    obj_param = {
        "name": "Target", "property_class": "FObjectProperty",
        "flags_raw": "0x%x" % flags_ref, "is_return": False, "is_out": False,
        "is_reference": False,
    }
    with_ref_fn = _function(raw_name="GetSomething", owner="A", parameters=[obj_param])
    strict_fn = _function(raw_name="GetOther", owner="B", parameters=[_trivial_param()])
    result = tool.rank_candidates([with_ref_fn, strict_fn])
    assert result["strict_eligible_count"] == 1
    assert result["eligible_with_object_refs_count"] == 1
    assert result["strict_eligible_ranked"][0]["raw_name"] == "GetOther"
    assert result["eligible_with_object_refs_ranked"][0]["raw_name"] == "GetSomething"


def test_rank_prefers_non_mutation_and_fewer_params_and_static_native():
    mutating = _function(raw_name="SetVolume", owner="A", parameters=[_trivial_param()])
    query_two_params = _function(
        raw_name="GetTwoThings", owner="B",
        parameters=[_trivial_param("A"), _trivial_param("B")])
    query_zero_params = _function(raw_name="IsReady", owner="C", parameters=[])
    instance_query = _function(
        raw_name="IsEditing", owner="D", parameters=[_trivial_param()], is_static=False)
    result = tool.rank_candidates(
        [mutating, query_two_params, query_zero_params, instance_query])
    ranked_names = [e["raw_name"] for e in result["strict_eligible_ranked"]]
    # IsReady (0 params, non-mutating, static) must rank above everything else;
    # SetVolume (mutation-sounding name) must rank last.
    assert ranked_names[0] == "IsReady"
    assert ranked_names[-1] == "SetVolume"


def test_unsupported_function_excluded_from_both_ranked_lists():
    unsupported_fn = _function(raw_name="SendMessage", parameters=[_unsupported_param()])
    result = tool.rank_candidates([unsupported_fn])
    assert result["unsupported_count"] == 1
    assert result["strict_eligible_ranked"] == []
    assert result["eligible_with_object_refs_ranked"] == []


# --------------------------------------------------------------------------- #
# End-to-end against the REAL committed functions.jsonl (I-05's own 247-row
# live output) -- pins real numbers as a regression, never re-derives them
# from a live process.
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not os.path.exists(REAL_FUNCTIONS_JSONL),
                     reason="committed functions.jsonl not present in this checkout")
def test_real_functions_jsonl_produces_expected_candidate_counts():
    with open(REAL_FUNCTIONS_JSONL, encoding="utf-8") as handle:
        function_records = [json.loads(line) for line in handle if line.strip()]
    assert len(function_records) == 247

    result = tool.rank_candidates(function_records)
    assert result["total_functions"] == 247
    assert result["strict_eligible_count"] == 139
    assert result["eligible_with_object_refs_count"] == 58
    assert result["unsupported_count"] == 247 - 139 - 58

    top_names = {
        "%s::%s" % (e["owner"], e["raw_name"])
        for e in result["strict_eligible_ranked"][:5]}
    # IsSteamDeck/IsUsingSlateFocus: static, native, 1 trivial (return-only)
    # parameter, non-mutating names -- expected to rank at or near the top.
    assert "MiseryBlueprintFunctionLibrary::IsSteamDeck" in (
        {"%s::%s" % (e["owner"], e["raw_name"])
         for e in result["strict_eligible_ranked"][:20]})


def test_cli_end_to_end_writes_ranked_json(tmp_path, capsys):
    functions = [
        _function(raw_name="IsSteamDeck", owner="MiseryBlueprintFunctionLibrary",
                  parameters=[_trivial_param("ReturnValue", is_return=True, is_out=True)]),
        _function(raw_name="SpawnActor", owner="World",
                  parameters=[_unsupported_param()]),
    ]
    jsonl_path = tmp_path / "functions.jsonl"
    jsonl_path.write_text(
        "\n".join(json.dumps(f) for f in functions) + "\n", encoding="utf-8")
    out_path = tmp_path / "out.json"

    rc = tool.main([str(jsonl_path), "--out", str(out_path), "--top", "5"])
    assert rc == 0
    doc = json.loads(out_path.read_text(encoding="utf-8"))
    assert doc["total_functions"] == 2
    assert doc["strict_eligible_count"] == 1
    assert doc["unsupported_count"] == 1

    captured = capsys.readouterr()
    assert "PE-ABI: total=2" in captured.err


def test_cli_subprocess_smoke(tmp_path):
    # A genuine subprocess invocation (not just calling main() in-process) --
    # confirms the script is runnable as `python tools/reflection/
    # processevent_abi.py ...` exactly as documented, not only importable.
    functions = [_function(raw_name="IsReady", owner="X", parameters=[])]
    jsonl_path = tmp_path / "functions.jsonl"
    jsonl_path.write_text(json.dumps(functions[0]) + "\n", encoding="utf-8")
    script = os.path.join(REPO_ROOT, "tools", "reflection", "processevent_abi.py")
    completed = subprocess.run(
        [sys.executable, script, str(jsonl_path), "--top", "1"],
        capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0
    doc = json.loads(completed.stdout)
    assert doc["strict_eligible_count"] == 1
