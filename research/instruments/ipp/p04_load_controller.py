#!/usr/bin/env python3
"""RESEARCH ONLY -- NOT PRODUCTION. See README.md and plan.md 8.1/8.3/8.4/8.5.

IPP capability P-04 (plan.md 8.3): trigger ONE synchronous load of a single,
already-known content package inside the running game, to answer the one
question CT-05 left open -- can Shipping MISERY actually resolve and load our
own cooked package from an automatically-mounted external container, not just
mount its container and register its packages.

Escalation record: research/decisions.md, ESC-02. Do not run this without that
record. This is NOT a generic loader: --allow-load accepts only the single
literal package path this build was reviewed and checkpointed against.

The load is ASYNCHRONOUS in this build (Zen loader): LoadPackage enqueues on a
thread-safe queue, the off-game-thread flush no-ops, and the call returns null
while the real load lands a few frames later on the loader thread. So this
controller does the one call, then hands OBSERVATION back to read-only tools
(I-14 + find_live_object polling) -- the return value is recorded but is not the
success criterion. See probe_load/probe_loadpackage.cpp's header and ESC-02.

Reuses ipp_controller.py's already-reviewed injection helpers (the same
LoadLibrary-via-CreateRemoteThread + Toolhelp32 base resolution + VEH-guarded
call that P-02 used and that was adversarially reviewed), and eri.py's
read-only build-identity check. The only P-04-specific pieces here are: the
LoadPackage RVA, allocating the package-name wide string in the target, and the
LoadProbeIo wire format.
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import sys
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
IPP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, IPP_DIR)
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))

import eri  # noqa: E402
import ipp_controller as ipp  # noqa: E402  (reuse its reviewed injection helpers)

TOOL_VERSION = "p04-load-controller-0.1.0"

# The single package this build is permitted to load (ESC-02). Extending this
# is a NEW escalation, not a flag change.
ALLOWED_PACKAGE_PATHS = frozenset({"/Game/ModKit/MK_Canary"})

# HARD GATE. LOG-0071 established that LOAD_PACKAGE_RVA below has NO reproducible
# derivation: the target's log/trace strings are stripped, LoadPackage is not
# exported, no PDB ships, and .pdata only proves 0x12CF3B0 is *a* function of
# size 0x2af -- not that it is LoadPackage. Firing an executable call at an
# unidentified address in the live game is exactly the irreversible action this
# whole framework refuses on assertion. So this controller REFUSES to inject
# until a real derivation exists and this flag is flipped deliberately, in the
# same commit that lands the derivation evidence. Do not flip it to "just try".
ADDRESS_IDENTITY_VERIFIED = False

EXPECTED_BUILD_SHA256 = "bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331"

# CANDIDATE (UNVERIFIED) address for LoadPackage(UPackage*, const TCHAR*,
# uint32, FArchive*, const FLinkerInstancingContext*). This number was inherited
# from a prior session's summary with NO derivation trail (LOG-0071). The
# sha256==build_key check only proves the image is unchanged since that number
# was written; it does NOT prove the number is LoadPackage. Kept only so the
# derivation, once done, can confirm or replace it.
LOAD_PACKAGE_RVA = 0x12CF3B0

# The ACTUAL first 16 bytes at 0x12CF3B0 in the installed image, read read-only
# (LOG-0071): MOV [RSP+8],RBX; MOV [RSP+18],RSI; MOV [RSP+20],RDI; PUSH RBP...
# a standard save-registers prologue. NOTE: matching this proves only that *a*
# function begins here, NOT that it is LoadPackage -- it is a boundary check,
# never an identity check. Identity is what LOG-0071 says is missing.
LOAD_PACKAGE_PROLOGUE = bytes.fromhex("48895c2408488974241848897c242055")

# LoadProbeIo wire format -- MUST match probe_loadpackage.cpp byte for byte:
#   Q magic, I protocol_version, Q load_package_ptr, Q package_name_ptr,
#   I status, Q exception_code, Q returned_package_ptr, 4x B reserved
IO_STRUCT_FORMAT = "<QIQQIQQ4B"
IO_STRUCT_SIZE = struct.calcsize(IO_STRUCT_FORMAT)
assert IO_STRUCT_SIZE == 52, "LoadProbeIo wire format drifted from probe's 52-byte layout"
IO_MAGIC = 0x4950502D4C4F4144  # "IPP-LOAD"
IO_PROTOCOL_VERSION = 1

STATUS_NAMES = {0: "not_run", 1: "success_call_returned", 2: "exception", 3: "sanity_check_failed"}


def build_load_probe_dll() -> str:
    """Compile probe_load/probe_loadpackage.cpp fresh, same toolchain and same
    clean-compile-is-a-per-run-check discipline as ipp.build_probe_dll()."""
    gxx = r"D:\tools\mingw64\bin\g++.exe"
    if not os.path.isfile(gxx):
        raise ipp.Blocked("MinGW g++ not found at %r" % gxx)
    src = os.path.join(IPP_DIR, "probe_load", "probe_loadpackage.cpp")
    build_dir = os.path.join(IPP_DIR, "build")
    os.makedirs(build_dir, exist_ok=True)
    out_dll = os.path.join(build_dir, "ipp_load_probe.dll")
    import subprocess
    cmd = [gxx, "-shared", "-o", out_dll, src, "-static", "-O2",
           "-Wall", "-Wextra", "-Wshadow", "-Wconversion"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 or result.stdout.strip() or result.stderr.strip():
        raise ipp.Blocked("probe_loadpackage.cpp did not compile cleanly (exit=%d):\n%s\n%s"
                          % (result.returncode, result.stdout, result.stderr))
    return out_dll


def resolve_target(api, run_note: list) -> dict:
    """Read-only: confirm build identity, then resolve and byte-verify the
    LoadPackage address. Raises ipp.Blocked on any mismatch; never guesses."""
    result = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid = result["pid"]
    base = result["base_address"]
    observed = ipp.sha256_of_file(result["exe_path"])
    if observed != EXPECTED_BUILD_SHA256:
        raise ipp.Blocked(
            "build identity mismatch: process is sha256:%s, this tool targets sha256:%s"
            % (observed, EXPECTED_BUILD_SHA256))
    run_note.append("build identity confirmed sha256:%s (self-computed from live exe)" % observed)

    load_package_va = base + LOAD_PACKAGE_RVA
    handle = eri.open_process_read_only(api, pid)
    try:
        prologue = api.read_process_memory(handle, load_package_va, len(LOAD_PACKAGE_PROLOGUE))
    finally:
        api.close_handle(handle)
    if prologue != LOAD_PACKAGE_PROLOGUE:
        raise ipp.Blocked(
            "LoadPackage prologue mismatch at 0x%x: read %s, expected %s -- refusing to call "
            "an address that is not byte-for-byte the analyzed function"
            % (load_package_va, prologue.hex(), LOAD_PACKAGE_PROLOGUE.hex()))
    run_note.append("LoadPackage prologue byte-verified at 0x%x (%s)"
                    % (load_package_va, prologue.hex()))
    return {"pid": pid, "base_address": base, "exe_path": result["exe_path"],
            "build_sha256": observed, "load_package_va": load_package_va}


def invoke_load(target: dict, dll_path: str, package_path: str, cleanup_report: dict) -> dict:
    """The one write/execute phase: allocate the package-name wide string in the
    target, inject the probe DLL, run RunProbe once with a LoadProbeIo pointing
    at LoadPackage and the string, read back, unload. Mirrors ipp.invoke_probe
    step for step (which was adversarially reviewed) with a P-04 payload."""
    cleanup_report.update({"unload_attempted": False, "unload_freelibrary_result": None,
                           "unload_wait_timed_out": None, "unload_skipped_reason": None})
    k32 = ipp._k32()
    hproc = k32.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, target["pid"])
    if not hproc:
        raise ipp.Blocked("OpenProcess failed: %d" % ctypes.get_last_error())

    remote_path_buf = remote_io_buf = remote_name_buf = remote_base = None
    runprobe_thread_may_be_running = False
    try:
        # 1. write the DLL path and the package-name wide string.
        path_bytes = (dll_path + "\x00").encode("utf-16-le")
        remote_path_buf = k32.VirtualAllocEx(hproc, None, len(path_bytes),
                                             ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
        if not remote_path_buf:
            raise ipp.Blocked("VirtualAllocEx(dll path) failed: %d" % ctypes.get_last_error())
        written = ctypes.c_size_t(0)
        if not k32.WriteProcessMemory(hproc, remote_path_buf, path_bytes, len(path_bytes),
                                      ctypes.byref(written)):
            raise ipp.Blocked("WriteProcessMemory(dll path) failed: %d" % ctypes.get_last_error())

        name_bytes = (package_path + "\x00").encode("utf-16-le")
        remote_name_buf = k32.VirtualAllocEx(hproc, None, len(name_bytes),
                                             ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
        if not remote_name_buf:
            raise ipp.Blocked("VirtualAllocEx(package name) failed: %d" % ctypes.get_last_error())
        if not k32.WriteProcessMemory(hproc, remote_name_buf, name_bytes, len(name_bytes),
                                      ctypes.byref(written)):
            raise ipp.Blocked("WriteProcessMemory(package name) failed: %d" % ctypes.get_last_error())

        # 2. LoadLibraryW(dll) via a remote thread; base via Toolhelp32.
        h_k32 = k32.GetModuleHandleW("kernel32.dll")
        p_loadlibraryw = k32.GetProcAddress(h_k32, b"LoadLibraryW")
        h1 = k32.CreateRemoteThread(hproc, None, 0, p_loadlibraryw, remote_path_buf, 0, None)
        if not h1:
            raise ipp.Blocked("CreateRemoteThread(LoadLibraryW) failed: %d" % ctypes.get_last_error())
        if k32.WaitForSingleObject(h1, ipp.WAIT_TIMEOUT_MS) != 0:
            k32.CloseHandle(h1)
            cleanup_report["unload_skipped_reason"] = "LoadLibraryW thread hung"
            raise ipp.Blocked("LoadLibraryW remote thread did not finish in time")
        k32.CloseHandle(h1)
        dll_name = os.path.basename(dll_path)
        remote_base = ipp.find_remote_module_base(k32, target["pid"], dll_name)
        if remote_base is None:
            raise ipp.Blocked("probe DLL not in module list after LoadLibraryW")

        rva = ipp.find_export_rva(dll_path, "RunProbe")
        remote_run_probe = remote_base + rva

        # 3. write the LoadProbeIo and run RunProbe once.
        io_bytes = struct.pack(IO_STRUCT_FORMAT, IO_MAGIC, IO_PROTOCOL_VERSION,
                               target["load_package_va"], remote_name_buf,
                               0, 0, 0, 0, 0, 0, 0)
        remote_io_buf = k32.VirtualAllocEx(hproc, None, IO_STRUCT_SIZE,
                                           ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
        if not remote_io_buf:
            raise ipp.Blocked("VirtualAllocEx(io) failed: %d" % ctypes.get_last_error())
        if not k32.WriteProcessMemory(hproc, remote_io_buf, io_bytes, len(io_bytes),
                                      ctypes.byref(written)):
            raise ipp.Blocked("WriteProcessMemory(io) failed: %d" % ctypes.get_last_error())

        runprobe_thread_may_be_running = True
        h2 = k32.CreateRemoteThread(hproc, None, 0, remote_run_probe, remote_io_buf, 0, None)
        if not h2:
            runprobe_thread_may_be_running = False
            raise ipp.Blocked("CreateRemoteThread(RunProbe) failed: %d" % ctypes.get_last_error())
        wait2 = k32.WaitForSingleObject(h2, ipp.WAIT_TIMEOUT_MS)
        if wait2 != 0:
            cleanup_report["unload_skipped_reason"] = "RunProbe thread hung -- FreeLibrary withheld"
            raise ipp.Blocked("RunProbe remote thread did not finish in time")
        runprobe_thread_may_be_running = False
        exit_code = wt.DWORD(0)
        k32.GetExitCodeThread(h2, ctypes.byref(exit_code))
        k32.CloseHandle(h2)

        result_buf = ctypes.create_string_buffer(IO_STRUCT_SIZE)
        read = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(hproc, remote_io_buf, result_buf, IO_STRUCT_SIZE,
                                     ctypes.byref(read)):
            raise ipp.Blocked("ReadProcessMemory(io) failed: %d" % ctypes.get_last_error())
        fields = struct.unpack(IO_STRUCT_FORMAT, result_buf.raw)
        status, exc_code, returned = fields[4], fields[5], fields[6]
        return {"thread_exit_code": exit_code.value, "status": status,
                "status_name": STATUS_NAMES.get(status, "unknown"),
                "exception_code": exc_code, "returned_package_ptr_hex": "0x%x" % returned,
                "returned_null": returned == 0,
                "remote_dll_base": remote_base, "remote_run_probe": remote_run_probe}
    finally:
        if remote_base is not None and not runprobe_thread_may_be_running:
            cleanup_report["unload_attempted"] = True
            p_free = k32.GetProcAddress(k32.GetModuleHandleW("kernel32.dll"), b"FreeLibrary")
            h3 = k32.CreateRemoteThread(hproc, None, 0, p_free, remote_base, 0, None)
            if h3:
                w3 = k32.WaitForSingleObject(h3, ipp.WAIT_TIMEOUT_MS)
                cleanup_report["unload_wait_timed_out"] = (w3 != 0)
                if w3 == 0:
                    fx = wt.DWORD(0)
                    k32.GetExitCodeThread(h3, ctypes.byref(fx))
                    cleanup_report["unload_freelibrary_result"] = bool(fx.value)
                k32.CloseHandle(h3)
            else:
                cleanup_report["unload_skipped_reason"] = "CreateRemoteThread(FreeLibrary) failed"
        elif remote_base is not None:
            cleanup_report.setdefault("unload_skipped_reason",
                                      "RunProbe thread outcome unknown -- FreeLibrary withheld")
        for buf in (remote_path_buf, remote_name_buf, remote_io_buf):
            if buf is not None:
                k32.VirtualFreeEx(hproc, buf, 0, ipp.MEM_RELEASE)
        k32.CloseHandle(hproc)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-load", metavar="PACKAGE_PATH", default=None,
                        help="Enable P-04 for exactly one package path; only %r is accepted."
                             % sorted(ALLOWED_PACKAGE_PATHS))
    parser.add_argument("--run-dir", default=None)
    args = parser.parse_args(argv)

    arguments = list(argv) if argv is not None else list(sys.argv[1:])
    run_note = []
    capabilities_enabled = []
    cleanup_report = {}
    verify_before = verify_after = None
    artifacts = []
    dll_name = None
    target_pid = None

    run_id = args.run_dir and os.path.basename(args.run_dir) \
        or time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
    run_dir = args.run_dir or os.path.join(REPO_ROOT, "research", "instrument-runs", run_id)
    os.makedirs(run_dir, exist_ok=True)

    try:
        api = eri.Win32Api()
        if args.allow_load is not None:
            ipp.confirm_live_build_identity_ok = True  # marker; identity re-checked in resolve_target
            verify_before = ipp.run_verify_install(run_dir, "before")
            if verify_before.get("report_artifact"):
                artifacts.append(verify_before["report_artifact"])
            if verify_before["result"] == "mismatch":
                raise ipp.Blocked("verify_install MISMATCH before session (%d serious)"
                                  % verify_before["serious_count"])

        target = resolve_target(api, run_note)
        target_pid = target["pid"]
        report = {"run_note": run_note,
                  "target": {"pid": target["pid"], "build_sha256": target["build_sha256"],
                             "load_package_va": "0x%x" % target["load_package_va"]}}

        if args.allow_load is None:
            report["invocation"] = None
            report["outcome"] = ("dry run: no --allow-load, P-04 not enabled, nothing written "
                                 "to or executed in the target")
        else:
            if args.allow_load not in ALLOWED_PACKAGE_PATHS:
                raise ipp.Blocked("--allow-load %r refused: only %r permitted (extending is a new "
                                  "escalation)" % (args.allow_load, sorted(ALLOWED_PACKAGE_PATHS)))
            if not ADDRESS_IDENTITY_VERIFIED:
                raise ipp.Blocked(
                    "P-04 injection refused: LoadPackage @ RVA 0x%x is UNVERIFIED (LOG-0071). "
                    "The address has no reproducible derivation and ESC-02's supporting claims are "
                    "partly false (LoadPackage is not exported; the cited RESEARCH_LOG derivation "
                    "entry does not exist). Refusing to inject an executable call at an unidentified "
                    "address in the live game. Derive the address first, land the evidence, then set "
                    "ADDRESS_IDENTITY_VERIFIED = True in the same commit." % LOAD_PACKAGE_RVA)
            capabilities_enabled.append("P-04")
            dll_path = build_load_probe_dll()
            dll_name = os.path.basename(dll_path)
            run_note.append("probe_loadpackage.cpp compiled cleanly")
            invocation = invoke_load(target, dll_path, args.allow_load, cleanup_report)
            report["invocation"] = invocation
            report["cleanup"] = cleanup_report
            unloaded = ipp.confirm_dll_unloaded(target["pid"], dll_name)
            report["dll_unloaded_confirmed"] = unloaded
            verify_after = ipp.run_verify_install(run_dir, "after")
            if verify_after.get("report_artifact"):
                artifacts.append(verify_after["report_artifact"])
            report["outcome"] = (
                "call status=%s thread_exit=%d returned=%s exception_code=0x%x dll_unloaded=%s -- "
                "NOTE the load is asynchronous; a null return is expected and success must be "
                "confirmed by polling GUObjectArray with find_live_object.py after this run"
                % (invocation["status_name"], invocation["thread_exit_code"],
                   invocation["returned_package_ptr_hex"], invocation["exception_code"], unloaded))

        report_path = os.path.join(run_dir, "report.json")
        with open(report_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")
        artifacts.append(os.path.relpath(report_path, REPO_ROOT).replace(os.sep, "/"))
        print(json.dumps(report, indent=2, sort_keys=True))
        exit_code = 0
    except (ipp.Blocked, eri.EriError) as exc:
        report = {"blocked": True, "reason": str(exc), "run_note": run_note,
                  "cleanup": cleanup_report or None}
        if "P-04" in capabilities_enabled and dll_name and target_pid:
            try:
                report["dll_unloaded_confirmed"] = ipp.confirm_dll_unloaded(target_pid, dll_name)
            except Exception:  # noqa: BLE001
                report["dll_unloaded_confirmed"] = None
        report_path = os.path.join(run_dir, "report.json")
        with open(report_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")
        artifacts.append(os.path.relpath(report_path, REPO_ROOT).replace(os.sep, "/"))
        print("BLOCKED:", exc, file=sys.stderr)
        exit_code = 2
    finally:
        if args.allow_load is not None and verify_before is not None and verify_after is None:
            try:
                verify_after = ipp.run_verify_install(run_dir, "after-blocked")
                if verify_after.get("report_artifact"):
                    artifacts.append(verify_after["report_artifact"])
            except Exception:  # noqa: BLE001
                verify_after = None
        manifest_level = "ipp" if capabilities_enabled else "eri"
        manifest_caps = capabilities_enabled or ["I-01"]
        manifest = ipp.write_manifest(
            run_dir, arguments=arguments, capabilities_enabled=manifest_caps,
            build_sha256=EXPECTED_BUILD_SHA256, verify_before=verify_before,
            verify_after=verify_after, artifacts=artifacts, instrument_level=manifest_level)
        print("manifest:", manifest, file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
