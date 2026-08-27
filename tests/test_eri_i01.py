#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for research/instruments/eri/eri.py, capability I-01 (plan.md 8.2).

No MISERY process runs in this environment (nor in CI), so every test below
exercises the plain-Python logic functions (find_process_by_name,
find_module_in_process, open_process_read_only, run_i01) against a
FakeWin32Api that returns scripted process/module lists without touching the
real Windows API -- the same "duck-typed interface, faked in tests" idiom
tests/test_dump_xrefs_for_string.py uses for the Ghidra API it cannot start a
JVM to exercise. main()'s CLI/argument-parsing, output-path guarding and
document/manifest shape are also covered without any live handle.

The one thing this file cannot test is the real Win32Api class's ctypes
struct layout against an actual running process -- that is exactly the
live-process integration test the task brief reserves for a human to run
separately.

Run:  python -m pytest -q tests/test_eri_i01.py
(plain stdlib ctypes + jsonschema/referencing, both available under the
system interpreter -- this suite does NOT need
D:\\Tools\\venv-research\\Scripts\\python.exe, unlike the pyghidra_scripts
family.)
"""

from __future__ import annotations

import json
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))

import eri as tool  # noqa: E402
import pathguard  # noqa: E402

SCHEMA_DIR = os.path.join(REPO_ROOT, "research", "schema")
MANIFEST_SCHEMA_PATH = os.path.join(SCHEMA_DIR, "instrument-run-manifest.schema.json")

VALID_BUILD_KEY = "sha256:" + "a" * 64
TARGET_NAME = "MISERY-Win64-Shipping.exe"


# --------------------------------------------------------------------------- #
# FakeWin32Api -- scripted process/module lists, plus handle-leak bookkeeping
# --------------------------------------------------------------------------- #

class FakeWin32Api:
    """Stands in for eri.Win32Api. Every method matches its real sibling's
    signature and semantics (returns None on Toolhelp32 exhaustion / a
    failed OpenProcess, an invalid-handle sentinel on a failed snapshot).

    Handle-leak bookkeeping: every successfully "opened" handle (a snapshot
    that did not fail, or an OpenProcess that did not fail) is recorded in
    ``opened_handles``; every close_handle call is recorded in
    ``closed_handles``. A test asserts the two multisets are equal, which is
    how a handle leak (an open with no matching close on some code path)
    would be caught without ever running against a real process.
    """

    def __init__(self, *, processes=None, modules_by_pid=None,
                 fail_process_snapshot=False, fail_module_snapshot_pids=(),
                 fail_open_process_pids=()):
        self._processes = list(processes or [])
        self._modules_by_pid = dict(modules_by_pid or {})
        self._fail_process_snapshot = fail_process_snapshot
        self._fail_module_snapshot_pids = set(fail_module_snapshot_pids)
        self._fail_open_process_pids = set(fail_open_process_pids)

        self._next_handle = 1000
        self._iters: dict[int, iter] = {}
        self.opened_handles: list[int] = []
        self.closed_handles: list[int] = []
        self.calls = {
            "create_toolhelp32_snapshot": 0, "open_process": 0, "close_handle": 0,
        }

    def _fresh_handle(self) -> int:
        self._next_handle += 1
        return self._next_handle

    # -- process snapshot ---------------------------------------------------

    def create_toolhelp32_snapshot(self, flags: int, pid: int) -> int:
        self.calls["create_toolhelp32_snapshot"] += 1
        if flags == tool.TH32CS_SNAPPROCESS:
            if self._fail_process_snapshot:
                return -1
            handle = self._fresh_handle()
            self._iters[handle] = iter(list(self._processes))
            self.opened_handles.append(handle)
            return handle
        if flags == tool.TH32CS_SNAPMODULE:
            if pid in self._fail_module_snapshot_pids:
                return -1
            handle = self._fresh_handle()
            self._iters[handle] = iter(list(self._modules_by_pid.get(pid, [])))
            self.opened_handles.append(handle)
            return handle
        raise AssertionError("unexpected snapshot flags: 0x%x" % flags)

    def process32_first(self, snapshot: int):
        return next(self._iters[snapshot], None)

    def process32_next(self, snapshot: int):
        return next(self._iters[snapshot], None)

    def module32_first(self, snapshot: int):
        return next(self._iters[snapshot], None)

    def module32_next(self, snapshot: int):
        return next(self._iters[snapshot], None)

    def open_process(self, pid: int) -> int:
        self.calls["open_process"] += 1
        if pid in self._fail_open_process_pids:
            return 0
        handle = self._fresh_handle()
        self.opened_handles.append(handle)
        return handle

    def close_handle(self, handle: int) -> bool:
        self.calls["close_handle"] += 1
        self.closed_handles.append(handle)
        return True

    def get_last_error(self) -> int:
        return 5  # ERROR_ACCESS_DENIED, a plausible stand-in


def proc(pid: int, exe_file: str) -> tool.ProcessEntry:
    return tool.ProcessEntry(pid=pid, exe_file=exe_file)


def mod(module_name: str, exe_path: str, base_address: int, size: int) -> tool.ModuleEntry:
    return tool.ModuleEntry(module_name=module_name, exe_path=exe_path,
                            base_address=base_address, size=size)


# --------------------------------------------------------------------------- #
# happy path
# --------------------------------------------------------------------------- #

def test_run_i01_happy_path_finds_process_and_module():
    api = FakeWin32Api(
        processes=[proc(11, "explorer.exe"), proc(4242, TARGET_NAME)],
        modules_by_pid={
            4242: [
                mod("ntdll.dll", r"C:\Windows\SYSTEM32\ntdll.dll", 0x7FF800000000, 0x1F0000),
                mod(TARGET_NAME, r"D:\Games\MISERY\MISERY\Binaries\Win64\%s" % TARGET_NAME,
                    0x7FF700000000, 0x0A123000),
            ]
        },
    )
    result = tool.run_i01(api, TARGET_NAME)
    assert result == {
        "pid": 4242,
        "process_name": TARGET_NAME,
        "base_address": 0x7FF700000000,
        "image_size_bytes": 0x0A123000,
    }


def test_run_i01_happy_path_closes_every_handle_it_opens():
    api = FakeWin32Api(
        processes=[proc(4242, TARGET_NAME)],
        modules_by_pid={4242: [mod(TARGET_NAME, "x", 0x1000, 0x2000)]},
    )
    tool.run_i01(api, TARGET_NAME)
    # process snapshot + OpenProcess + module snapshot == 3 handles, all closed.
    assert sorted(api.opened_handles) == sorted(api.closed_handles)
    assert len(api.opened_handles) == 3


# --------------------------------------------------------------------------- #
# fail loudly: process not found
# --------------------------------------------------------------------------- #

def test_process_not_found_raises_and_closes_its_snapshot():
    api = FakeWin32Api(processes=[proc(1, "explorer.exe"), proc(2, "steam.exe")])
    with pytest.raises(tool.ProcessNotFoundError):
        tool.run_i01(api, TARGET_NAME)
    assert sorted(api.opened_handles) == sorted(api.closed_handles)
    assert api.calls["open_process"] == 0  # never got that far


def test_process_snapshot_creation_failure_raises_snapshot_error():
    api = FakeWin32Api(fail_process_snapshot=True)
    with pytest.raises(tool.SnapshotFailedError):
        tool.run_i01(api, TARGET_NAME)
    assert api.opened_handles == [] and api.closed_handles == []


# --------------------------------------------------------------------------- #
# fail loudly: module not found within a found process
# --------------------------------------------------------------------------- #

def test_module_not_found_raises_and_closes_every_handle():
    api = FakeWin32Api(
        processes=[proc(4242, TARGET_NAME)],
        modules_by_pid={4242: [mod("ntdll.dll", "x", 0x1000, 0x2000)]},  # no target module
    )
    with pytest.raises(tool.TargetModuleNotFoundError):
        tool.run_i01(api, TARGET_NAME)
    assert sorted(api.opened_handles) == sorted(api.closed_handles)
    assert len(api.opened_handles) == 3  # process snapshot + OpenProcess + module snapshot


# --------------------------------------------------------------------------- #
# fail loudly: OpenProcess refused
# --------------------------------------------------------------------------- #

def test_open_process_failure_raises_and_never_calls_module_snapshot():
    api = FakeWin32Api(
        processes=[proc(4242, TARGET_NAME)],
        modules_by_pid={4242: [mod(TARGET_NAME, "x", 0x1000, 0x2000)]},
        fail_open_process_pids={4242},
    )
    with pytest.raises(tool.OpenProcessFailedError, match="PROCESS_QUERY_INFORMATION"):
        tool.run_i01(api, TARGET_NAME)
    # process snapshot opened+closed; OpenProcess attempted but yielded no handle;
    # module snapshot never attempted at all.
    assert sorted(api.opened_handles) == sorted(api.closed_handles)
    assert len(api.opened_handles) == 1
    assert api.calls["create_toolhelp32_snapshot"] == 1  # process only, not module


def test_module_snapshot_failure_after_open_process_still_closes_process_handle():
    api = FakeWin32Api(
        processes=[proc(4242, TARGET_NAME)],
        fail_module_snapshot_pids={4242},
    )
    with pytest.raises(tool.SnapshotFailedError):
        tool.run_i01(api, TARGET_NAME)
    assert sorted(api.opened_handles) == sorted(api.closed_handles)
    assert len(api.opened_handles) == 2  # process snapshot + OpenProcess


# --------------------------------------------------------------------------- #
# exact match, never substring (the safety-critical rule)
# --------------------------------------------------------------------------- #

def test_process_match_is_exact_not_substring_prefix_variant():
    # "NotMISERY-Win64-Shipping.exe" contains the target name as a substring
    # but must NOT match.
    api = FakeWin32Api(processes=[proc(1, "NotMISERY-Win64-Shipping.exe")])
    with pytest.raises(tool.ProcessNotFoundError):
        tool.find_process_by_name(api, TARGET_NAME)


def test_process_match_is_exact_not_substring_suffix_variant():
    api = FakeWin32Api(processes=[proc(1, "MISERY-Win64-Shipping.exe.bak")])
    with pytest.raises(tool.ProcessNotFoundError):
        tool.find_process_by_name(api, TARGET_NAME)


def test_process_match_is_case_insensitive():
    api = FakeWin32Api(processes=[proc(7, TARGET_NAME.upper())])
    entry = tool.find_process_by_name(api, TARGET_NAME)
    assert entry.pid == 7


def test_module_match_is_exact_not_substring():
    api = FakeWin32Api(modules_by_pid={
        99: [mod("NotMISERY-Win64-Shipping.exe", "x", 0x1000, 0x2000)]})
    with pytest.raises(tool.TargetModuleNotFoundError):
        tool.find_module_in_process(api, 99, TARGET_NAME)


def test_module_match_falls_back_to_exe_path_basename():
    api = FakeWin32Api(modules_by_pid={
        99: [mod("weird-alias.dll", r"D:\Games\MISERY\Binaries\Win64\%s" % TARGET_NAME,
                 0x5000, 0x6000)]})
    entry = tool.find_module_in_process(api, 99, TARGET_NAME)
    assert entry.base_address == 0x5000 and entry.size == 0x6000


def test_module_exe_path_basename_match_is_also_exact_not_substring():
    api = FakeWin32Api(modules_by_pid={
        99: [mod("weird-alias.dll",
                 r"D:\Games\MISERY\Binaries\Win64\NotMISERY-Win64-Shipping.exe",
                 0x5000, 0x6000)]})
    with pytest.raises(tool.TargetModuleNotFoundError):
        tool.find_module_in_process(api, 99, TARGET_NAME)


# --------------------------------------------------------------------------- #
# exactly one OpenProcess call site, with the minimal access mask
# --------------------------------------------------------------------------- #

def test_source_has_exactly_one_openprocess_call_site():
    source = open(tool.__file__, encoding="utf-8").read()
    # Two mentions of the bare API name are expected and fine: the prototype
    # registration ("dll.OpenProcess.argtypes = ...") and the actual call
    # ("_kernel32_dll().OpenProcess(..."). What must be exactly one is the
    # CALL -- an open paren right after ".OpenProcess", which a prototype
    # assignment does not have.
    assert source.count(".OpenProcess(") == 1, (
        "eri.py must call OpenProcess from exactly one place -- Win32Api.open_process "
        "-- so a reviewer can audit the access-rights argument by reading one line")


def test_process_access_rights_is_query_and_vm_read_only():
    assert tool.PROCESS_ACCESS_RIGHTS == (
        tool.PROCESS_QUERY_INFORMATION | tool.PROCESS_VM_READ)
    assert tool.PROCESS_ACCESS_RIGHTS == 0x0410
    # No write/execute/inject-capable bit is present in the mask at all.
    forbidden_bits = 0xFFFFFFFF & ~(tool.PROCESS_QUERY_INFORMATION | tool.PROCESS_VM_READ)
    assert tool.PROCESS_ACCESS_RIGHTS & forbidden_bits == 0


def test_no_write_or_injection_capable_win32_call_anywhere_in_the_source():
    """The module docstring names several forbidden APIs BY NAME, in prose,
    precisely to state that this tool never calls them -- so this check
    looks for an actual CALL SITE shape (``.Name(`` or ``kernel32.Name``),
    not a bare substring, which the docstring's own explanatory sentence
    would otherwise trip.
    """
    source = open(tool.__file__, encoding="utf-8").read()
    forbidden = (
        "WriteProcessMemory", "VirtualAllocEx", "VirtualProtectEx",
        "CreateRemoteThread", "NtCreateThreadEx", "SetWindowsHookEx",
        "SuspendThread", "SetThreadContext", "NtWriteVirtualMemory",
        "PROCESS_ALL_ACCESS",
    )
    for name in forbidden:
        assert ("." + name) not in source, "a call site for %s must never appear in eri.py" % name


# --------------------------------------------------------------------------- #
# document shape (task item 6)
# --------------------------------------------------------------------------- #

def test_build_i01_document_shape_and_values():
    result = {"pid": 4242, "process_name": TARGET_NAME,
             "base_address": 0x7FF700000000, "image_size_bytes": 0x0A123000}
    doc = tool.build_i01_document(
        result=result, build_key=VALID_BUILD_KEY, recorded_at="2026-08-27T12:00:00Z")
    assert doc["capability"] == "I-01"
    assert doc["process_name"] == TARGET_NAME
    assert doc["pid"] == 4242
    assert doc["base_address_hex"] == "0x7ff700000000"
    assert doc["base_address_decimal"] == 0x7FF700000000
    assert doc["image_size_bytes"] == 0x0A123000
    assert doc["build_key"] == VALID_BUILD_KEY
    assert doc["recorded_at"] == "2026-08-27T12:00:00Z"
    assert doc["generator"] == tool.GENERATOR_NAME
    assert doc["generator_version"] == tool.GENERATOR_VERSION
    # Deliberately does NOT carry evidence_level/oracle -- see
    # build_i01_document's own docstring: those marker keys make
    # tools/kb/validate.py's is_record() treat this raw single-run
    # document as a full knowledge-base record and then demand
    # confidence/sources[]/claim_type on it too, which it has no
    # business carrying (the manifest is the graded record).
    assert "evidence_level" not in doc
    assert "oracle" not in doc
    # round-trips through dump_json cleanly
    json.loads(tool.dump_json(doc))


def test_build_i01_document_recorded_at_can_be_null():
    result = {"pid": 1, "process_name": TARGET_NAME, "base_address": 1, "image_size_bytes": 1}
    doc = tool.build_i01_document(result=result, build_key=VALID_BUILD_KEY, recorded_at=None)
    assert doc["recorded_at"] is None
    json.loads(tool.dump_json(doc))  # null serializes fine


# --------------------------------------------------------------------------- #
# build_key validation
# --------------------------------------------------------------------------- #

def test_validate_build_key_accepts_canonical_shape():
    tool.validate_build_key(VALID_BUILD_KEY)  # must not raise


@pytest.mark.parametrize("bad", [
    "sha256:short", "not-a-build-key", "sha256:" + "A" * 64,  # uppercase hex refused
    "sha256:" + "g" * 64, "",
])
def test_validate_build_key_rejects_malformed(bad):
    with pytest.raises(ValueError):
        tool.validate_build_key(bad)


# --------------------------------------------------------------------------- #
# manifest shape + schema validation
# --------------------------------------------------------------------------- #

def _load_schema(name: str) -> dict:
    with open(os.path.join(SCHEMA_DIR, name), encoding="utf-8") as handle:
        return json.load(handle)


def _build_registry():
    """Offline registry so instrument-run-manifest.schema.json's cross-file
    $refs to kb-record.schema.json resolve without any network access --
    same approach tools/kb/validate.py's _jsonschema_registry uses.
    """
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    resources = []
    for name in os.listdir(SCHEMA_DIR):
        if not name.endswith(".json"):
            continue
        document = _load_schema(name)
        resource = Resource.from_contents(document, default_specification=DRAFT202012)
        for uri in {document.get("$id"), name}:
            if uri:
                resources.append((uri, resource))
    return Registry().with_resources(resources)


def _manifest_validator():
    pytest.importorskip("jsonschema")
    pytest.importorskip("referencing")
    from jsonschema import Draft202012Validator

    schema = _load_schema("instrument-run-manifest.schema.json")
    return Draft202012Validator(schema, registry=_build_registry())


def test_build_manifest_shape():
    manifest = tool.build_manifest(
        run_id="2026-08-27T120000Z", arguments=["--build-key", VALID_BUILD_KEY],
        tool_version="0.1.0", build_key=VALID_BUILD_KEY,
        executed_at="2026-08-27T12:00:00Z", recorded_at="2026-08-27T12:00:00Z",
        artifacts=["research/instrument-runs/2026-08-27T120000Z/i01-process-info.json"])
    assert manifest["run_id"] == "2026-08-27T120000Z"
    assert manifest["instrument_level"] == "eri"
    assert manifest["capabilities_enabled"] == ["I-01"]
    assert manifest["verify_install_before"] is None
    assert manifest["verify_install_after"] is None
    assert manifest["build_key"] == VALID_BUILD_KEY
    # claim_type 'other' needs a justification field or tools/kb/validate.py's
    # EV-04/JUSTIFICATION_KEYS policy rejects the record (see build_manifest's
    # own docstring) -- pinned here so a future edit cannot drop it silently.
    assert manifest["claim_type"] == "other"
    assert manifest["claim_type_note"]
    json.loads(tool.dump_json(manifest))


def test_manifest_validates_against_the_published_schema():
    validator = _manifest_validator()
    manifest = tool.build_manifest(
        run_id="2026-08-27T120000Z", arguments=["--build-key", VALID_BUILD_KEY],
        tool_version="0.1.0", build_key=VALID_BUILD_KEY,
        executed_at="2026-08-27T12:00:00Z", recorded_at="2026-08-27T12:00:00Z",
        artifacts=["research/instrument-runs/2026-08-27T120000Z/i01-process-info.json"])
    errors = sorted(validator.iter_errors(manifest), key=lambda e: list(e.absolute_path))
    assert errors == [], "\n".join(
        "%s: %s" % (list(e.absolute_path), e.message) for e in errors)


def test_manifest_null_verify_install_is_legal_for_eri():
    """Pins the task's own open question: the schema's instrument_level=='eri'
    branch does NOT force verify_install_before/after to non-null (only the
    'ipp' branch does), so this tool's null-by-design choice validates.
    """
    validator = _manifest_validator()
    manifest = tool.build_manifest(
        run_id="r", arguments=[], tool_version="0.1.0", build_key=VALID_BUILD_KEY,
        executed_at="2026-08-27T12:00:00Z", recorded_at="2026-08-27T12:00:00Z",
        artifacts=None)
    assert manifest["verify_install_before"] is None
    assert manifest["verify_install_after"] is None
    assert list(validator.iter_errors(manifest)) == []


def test_manifest_rejects_a_p_star_capability_on_an_eri_record():
    """Negative control: proves the validator is actually checking something,
    not merely reporting success on everything handed to it.
    """
    validator = _manifest_validator()
    manifest = tool.build_manifest(
        run_id="r", arguments=[], tool_version="0.1.0", build_key=VALID_BUILD_KEY,
        executed_at="2026-08-27T12:00:00Z", recorded_at="2026-08-27T12:00:00Z",
        artifacts=None)
    manifest["capabilities_enabled"] = ["P-01"]  # an IPP id, illegal on an eri record
    assert list(validator.iter_errors(manifest)) != []


# --------------------------------------------------------------------------- #
# _repo_relative: must degrade, never raise, when the output path cannot be
# expressed relative to the repository root (Windows: different drive letter)
# --------------------------------------------------------------------------- #

def test_repo_relative_under_the_repo_root(tmp_path):
    inside = os.path.join(REPO_ROOT, "research", "instrument-runs", "x", "y.json")
    relative = tool._repo_relative(inside)
    assert relative == "research/instrument-runs/x/y.json"
    assert "\\" not in relative


def test_repo_relative_falls_back_to_absolute_when_relpath_is_impossible(monkeypatch):
    """os.path.relpath() raises ValueError on Windows for two paths on
    different drive letters; this must never propagate out of
    _repo_relative (see main()'s ordering -- the I-01 document may already
    be on disk by the time this runs, so raising here would silently lose
    the manifest write entirely, contradicting 'fail loudly' in the worst
    possible way: not a clean error, an orphaned half-written run).
    """
    def _raise(*_a, **_kw):
        raise ValueError("path is on mount 'C:', start on mount 'D:'")

    monkeypatch.setattr(os.path, "relpath", _raise)
    result = tool._repo_relative(r"C:\elsewhere\out.json")
    assert result == "C:/elsewhere/out.json"


# --------------------------------------------------------------------------- #
# CLI argument parsing
# --------------------------------------------------------------------------- #

def test_cli_requires_build_key():
    with pytest.raises(SystemExit):
        tool.build_arg_parser().parse_args(["--out", "a.json", "--manifest-out", "b.json"])


def test_cli_process_name_default():
    args = tool.build_arg_parser().parse_args(["--build-key", VALID_BUILD_KEY])
    assert args.process_name == tool.DEFAULT_PROCESS_NAME == TARGET_NAME


def test_resolve_output_paths_requires_out_and_manifest_out_without_run_dir():
    args = tool.build_arg_parser().parse_args(["--build-key", VALID_BUILD_KEY])
    with pytest.raises(ValueError):
        tool._resolve_output_paths(args)


def test_resolve_output_paths_run_dir_convenience(tmp_path):
    run_dir = str(tmp_path / "run1")
    args = tool.build_arg_parser().parse_args(
        ["--build-key", VALID_BUILD_KEY, "--run-dir", run_dir])
    out_path, manifest_path = tool._resolve_output_paths(args)
    assert out_path == os.path.join(run_dir, "i01-process-info.json")
    assert manifest_path == os.path.join(run_dir, "manifest.json")


def test_resolve_output_paths_explicit_out_overrides_run_dir_default(tmp_path):
    run_dir = str(tmp_path / "run1")
    explicit_out = str(tmp_path / "custom.json")
    args = tool.build_arg_parser().parse_args(
        ["--build-key", VALID_BUILD_KEY, "--run-dir", run_dir, "--out", explicit_out])
    out_path, manifest_path = tool._resolve_output_paths(args)
    assert out_path == explicit_out
    assert manifest_path == os.path.join(run_dir, "manifest.json")


# --------------------------------------------------------------------------- #
# main() end-to-end, against tmp_path, real Win32Api never touched because
# main() only fails for CLI-level reasons in these tests (bad build_key,
# path guard) -- no live process needed.
# --------------------------------------------------------------------------- #

def test_main_rejects_malformed_build_key_before_writing_anything(tmp_path, capsys):
    run_dir = str(tmp_path / "run1")
    rc = tool.main(["--build-key", "not-a-real-key", "--run-dir", run_dir])
    assert rc == 2
    assert "build-key" in capsys.readouterr().err
    assert not os.path.exists(run_dir)


def test_main_refuses_an_out_path_inside_an_installation(tmp_path, capsys):
    install_root = tmp_path / "install"
    marker_dir = install_root / "MISERY" / "Binaries" / "Win64"
    marker_dir.mkdir(parents=True)
    (marker_dir / "MISERY-Win64-Shipping.exe").write_bytes(b"stub")
    paks_dir = install_root / "MISERY" / "Content" / "Paks"
    paks_dir.mkdir(parents=True)
    (paks_dir / "global.utoc").write_bytes(b"stub")

    bad_out = str(install_root / "MISERY" / "sneaky.json")
    good_manifest = str(tmp_path / "manifest.json")
    rc = tool.main(["--build-key", VALID_BUILD_KEY, "--out", bad_out,
                    "--manifest-out", good_manifest])
    assert rc == 2
    assert "installation" in capsys.readouterr().err


def test_main_requires_out_and_manifest_out_or_run_dir(capsys):
    rc = tool.main(["--build-key", VALID_BUILD_KEY])
    assert rc == 2
    assert "--run-dir" in capsys.readouterr().err
