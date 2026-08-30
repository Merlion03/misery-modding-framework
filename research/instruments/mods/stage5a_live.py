#!/usr/bin/env python3
"""Stage 5A in-game: CoreCLR-hosted C# mods inside live MISERY.

WHAT IS DIFFERENT FROM THE OFF-GAME HARNESS
-------------------------------------------
One function pointer. The harness installs a recording items backend; this
installs ``Stage5RegisterItem``, which drives the same four CR-01C5 jobs --
intern the row, load the icon, load the mesh, populate -- that passed the
world/drop/pickup acceptance. Everything else is the same code on both sides,
which is the point: if the two disagree, the difference is the game.

HOW IT BOOTSTRAPS, AND WHY IT LOOKS LIKE THIS
---------------------------------------------
The proven Stage 2 session already knows how to resolve every address the
registration path needs, inject a DLL and create the aggregate table. Rather
than reimplement any of that, this points that session at the COMBINED runtime
DLL -- which contains the CR-01C5 code, the bridge tables and the managed-host
starter in one module -- and then asks the runtime to start CoreCLR on the game
thread.

The managed host is NOT handed a mod list by this file. It is handed the Stage 4
load plan's order, and the fixture assemblies the Stage 5A staging produced.
"""
import argparse
import ctypes
import json
import os
import struct
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "items"),
           os.path.join(REPO, "tools", "modplatform"),
           os.path.join(REPO, "tools", "modframework"),
           os.path.join(REPO, "tools", "modkit")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                        # noqa: E402
import ipp_controller as ipp                      # noqa: E402
import cr01c5_controller as c5                    # noqa: E402
import items_session                              # noqa: E402
import nativebuild as nb                          # noqa: E402
import p04_controller as p04                       # noqa: E402
from aggregate_acceptance import world_state      # noqa: E402

STAGE5_MAGIC = 0x35454741545300
STAGE5_PROTO = 1
RUNTIME_DLL = "MiseryRuntimeStage5.dll"
STAGE = os.path.join(nb.BUILD_DIR, "stage")

# The Stage5Io layout, mirroring Stage5RuntimeDll.cpp. Sizes are asserted
# against the DLL's own Stage5IoSize export rather than trusted.
IO_FMT = "<QII512s512s8192sIIiI1024s32768s"
IO_SIZE = struct.calcsize(IO_FMT)


class LiveError(Exception):
    pass


def build_runtime():
    internal = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
    return nb.build_dll(
        [os.path.join(internal, "Stage5RuntimeDll.cpp"),
         os.path.join(internal, "BridgeTables.cpp"),
         os.path.join(internal, "CR01C5ProbeDll.cpp"),
         os.path.join(internal, "UE54TickerCarrier.cpp")],
        RUNTIME_DLL,
        extra='/I"%s"' % nb.DOTNET_PACK,
        libs='"%s"' % os.path.join(nb.DOTNET_PACK, "libnethost.lib"))


def pack_io(nethost, host_assembly, plan):
    return struct.pack(
        IO_FMT, STAGE5_MAGIC, STAGE5_PROTO, IO_SIZE,
        nethost.encode("utf-8")[:511].ljust(512, b"\x00"),
        host_assembly.encode("utf-8")[:511].ljust(512, b"\x00"),
        plan.encode("utf-8")[:8191].ljust(8192, b"\x00"),
        0, 0, -1, 0, b"\x00" * 1024, b"\x00" * 32768)


def unpack_io(raw):
    values = struct.unpack(IO_FMT, raw)
    return {"magic": values[0], "started": values[6], "done": values[7],
            "rc": values[8], "game_thread_id": values[9],
            "error": values[10].split(b"\x00", 1)[0].decode("utf-8", "replace"),
            "report": values[11].split(b"\x00", 1)[0].decode("utf-8", "replace")}


def plan_argument():
    """mod_id=assembly, in the Stage 4 plan's order where one resolves."""
    mods_dir = os.path.join(STAGE, "mods")
    if not os.path.isdir(mods_dir):
        raise LiveError("the Stage 5A staging has not been produced; run "
                        "stage5a_harness.py first")
    available = {}
    for mod_id in sorted(os.listdir(mods_dir)):
        folder = os.path.join(mods_dir, mod_id)
        for name in sorted(os.listdir(folder)):
            if name.lower().endswith(".dll") and "ModAPI" not in name:
                available[mod_id] = os.path.join(folder, name)
                break
    healthy = [m for m in ("alphamod", "betamod") if m in available]
    order = []
    try:
        import resolve                                            # noqa: PLC0415
        import container_report                                   # noqa: PLC0415
        plan, _ = resolve.plan_from_root(
            "D:/UEScratch/ModsRoot",
            container_reader=container_report.read_container)
        order = [m for m in plan.load_order if m in available]
    except Exception:                                              # noqa: BLE001
        order = []
    ordered = order + [m for m in healthy if m not in order]
    rest = [m for m in sorted(available) if m not in ordered]
    return ";".join("%s=%s" % (m, available[m]) for m in ordered + rest), \
        ordered, order


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=float, default=180.0)
    a = ap.parse_args(argv)

    report = {"stage": "5A", "in_game": True,
              "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    checks = []

    def check(label, ok, detail=""):
        checks.append({"check": label, "pass": bool(ok), "detail": str(detail)})
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", label,
                               "" if ok else "  -- %s" % detail))
        return bool(ok)

    runtime = build_runtime()
    report["runtime_dll"] = runtime
    plan_arg, ordered, stage4_order = plan_argument()
    report["plan_arg"] = plan_arg
    report["stage4_order"] = stage4_order
    check("the mod list came from the Stage 4 load plan", bool(stage4_order),
          str(stage4_order))
    check("at least two managed mods are staged", len(ordered) >= 2, str(ordered))

    # The proven session, pointed at the combined runtime instead of the probe.
    original_build, original_name = c5.build_dll, c5.DLL_NAME
    c5.build_dll = lambda: runtime
    c5.DLL_NAME = RUNTIME_DLL
    session = items_session.AggregateSession()
    try:
        info = session.init()
        report["session_init"] = info
        check("the runtime injected and the aggregate table was created",
              info.get("attached"), info)

        before = world_state(session.api)
        report["world_before"] = before

        # Verify the DLL and this script agree about the block before writing it.
        size = p04.call_export(session.k, session.hp, session.rbase, runtime,
                               "Stage5IoSize", None, ipp.WAIT_TIMEOUT_MS)
        check("the runtime and the controller agree on the Stage5Io size",
              size == IO_SIZE, "dll=%s controller=%s" % (size, IO_SIZE))
        if size != IO_SIZE:
            raise LiveError("Stage5Io layout mismatch")

        nethost = os.path.join(nb.BUILD_DIR, "nethost.dll")
        host_assembly = os.path.join(STAGE, "Misery.ModHost.dll")
        check("the managed host assembly is staged",
              os.path.isfile(host_assembly), host_assembly)

        packed = pack_io(nethost, host_assembly, plan_arg)
        remote = session.k.VirtualAllocEx(session.hp, None, IO_SIZE,
                                          ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                          ipp.PAGE_READWRITE)
        written = ctypes.c_size_t(0)
        session.k.WriteProcessMemory(session.hp, remote, packed, len(packed),
                                     ctypes.byref(written))

        rc = p04.call_export(session.k, session.hp, session.rbase, runtime,
                             "StartManagedHost", remote, ipp.WAIT_TIMEOUT_MS)
        check("StartManagedHost was accepted", rc == 0, "rc=%s" % rc)

        # Polled, not waited on: the thread that must do the work is the game
        # thread, and blocking it is the one thing that cannot work.
        buffer = ctypes.create_string_buffer(IO_SIZE)
        deadline = time.time() + a.timeout
        state = None
        while time.time() < deadline:
            read = ctypes.c_size_t(0)
            session.k.ReadProcessMemory(session.hp, remote, buffer, IO_SIZE,
                                        ctypes.byref(read))
            state = unpack_io(buffer.raw)
            if state["done"]:
                break
            time.sleep(0.5)

        report["stage5_io"] = state
        if not check("the managed host finished within %ds" % a.timeout,
                     state and state["done"], str(state)[:400]):
            raise LiveError("the managed host did not complete")

        check("CoreCLR started and the host bootstrapped inside MISERY",
              state["rc"] == 0, "rc=%s error=%s" % (state["rc"], state["error"]))
        check("the bootstrap ran on the game thread",
              state["game_thread_id"] != 0, state["game_thread_id"])

        acceptance = None
        if state["report"]:
            try:
                acceptance = json.loads(state["report"])
            except ValueError as error:
                report["report_parse_error"] = str(error)
        report["acceptance"] = acceptance
        if acceptance:
            print("\n  --- managed acceptance, inside MISERY ---")
            for entry in acceptance.get("checks", []):
                print("    [%s] %s%s"
                      % ("PASS" if entry["pass"] else "FAIL", entry["check"],
                         "" if entry["pass"]
                         else "  -- " + entry.get("detail", "")))
            check("every managed check passed inside the game",
                  acceptance.get("ok"),
                  "%s passed, %s failed" % (acceptance.get("passed"),
                                            acceptance.get("failed")))

        # The game's OWN item lookup, asked about rows a C# mod registered.
        stats = p04.call_export(session.k, session.hp, session.rbase, runtime,
                                "Stage5ResolveStats", None, ipp.WAIT_TIMEOUT_MS)
        attempts = stats & 0xFFFF
        found = (stats >> 16) & 0xFFFF
        report["sgk_resolve"] = {"attempts": attempts, "found": found}
        check("the game's own SGK ItemDetails was asked about C#-registered rows",
              attempts > 0, "attempts=%d" % attempts)
        check("the game FOUND the item a C# mod registered",
              found > 0, "found %d of %d attempts" % (found, attempts))
        check("every C# registration was findable by the game",
              attempts > 0 and found == attempts,
              "found %d of %d" % (found, attempts))

        after = world_state(session.api)
        report["world_after"] = after
        mod_rows = [n for n in after["MasterItemList"] if "__" in n]
        report["mod_rows_after"] = mod_rows
        check("no managed mod row is left registered in the live game",
              not mod_rows, str(mod_rows))
        check("MasterItemList is back to its vanilla count",
              after["master_rows"] == before["master_rows"],
              "%s -> %s" % (before["master_rows"], after["master_rows"]))
    finally:
        c5.build_dll, c5.DLL_NAME = original_build, original_name
        if session.initialised:
            try:
                report["session_shutdown"] = session.shutdown()
            except Exception as error:                             # noqa: BLE001
                report["session_shutdown_error"] = "%s: %s" % (
                    type(error).__name__, error)

    report["checks"] = checks
    report["passed"] = sum(1 for c in checks if c["pass"])
    report["failed"] = sum(1 for c in checks if not c["pass"])
    report["verdict"] = "PASS" if report["failed"] == 0 else "FAIL"
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, default=str)
        handle.write("\n")
    print("\n%s -- %d passed, %d failed -> %s"
          % (report["verdict"], report["passed"], report["failed"], a.out))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
