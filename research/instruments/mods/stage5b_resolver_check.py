#!/usr/bin/env python3
"""Cross-check the C++ resolver against the Python research oracle.

WHY BOTH, AND WHY ON ONE PROCESS
--------------------------------
The Python oracle has been right for four stages. The C++ resolver is a rewrite
of it, and a rewrite of something that works is exactly where a silent
regression hides -- it will resolve SOMETHING, and every pointer it returns will
look plausible. So both run against the same live process, given the same two
root addresses, and every anchor is compared as a number. Agreement on 25
pointers is not a coincidence; disagreement on one is a defect.

THIS IS DEVELOPMENT SCAFFOLDING, AND IT SAYS SO
-----------------------------------------------
The Stage 5B execution path calls the C++ resolver directly and has no Python in
it. This file exists to justify that, once, and to be re-runnable after a change
to either side. Deleting it would not change what ships.

TRANSITION STATES ARE NOT FAILURES
----------------------------------
The live player inventory does not exist before gameplay. At the main menu the
correct answer is "absent", and both resolvers must say so -- an oracle that
called the menu a resolution failure would be wrong about the lifecycle, not
about the process.
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
           os.path.join(REPO, "tools", "modplatform")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                        # noqa: E402
import ipp_controller as ipp                      # noqa: E402
import cr01c3_recon as recon                      # noqa: E402
import cr01c5_controller as c5                    # noqa: E402
import nativebuild as nb                          # noqa: E402
import p04_controller as p04                      # noqa: E402

RESOLVE_MAGIC = 0x4D42504C52535600
# Proto 3: resolution runs on the game thread AND is chunked across ticks, so
# the carrier bindings are inputs and the per-slice numbers come back as output.
RESOLVE_PROTO = 4
RUNTIME_DLL = "MiseryRuntimeStage5.dll"
# Spelled out rather than written as one long run of letters: this struct has
# been miscounted twice by hand, and each time the mismatch was only caught by
# comparing sizeof() against calcsize(). The groups match the C++ declaration
# order in ResolverDump.cpp, and the 21 is the integer block from require_phase
# through completed_phase.
IO_FMT = ("<"
          "Q"          # magic
          "II"         # proto, struct_size
          "QQ"         # guobjectarray, namepool
          "QQQ"        # add_ticker, get_core_ticker, fmemory_malloc
          "16s16s16s"  # sig_add, sig_get, sig_malloc
          "IIIi" + "I" * 17 +   # 21 ints: phase..completed_phase (rc is signed)
          "128s"       # world_item_class
          "1024s"      # error
          "8192s")     # json
IO_SIZE = struct.calcsize(IO_FMT)

# How long to let the game thread drain one resolution. Generous: during a level
# load a frame can be long, and a timeout here would be reported as a resolver
# failure when it is really a busy engine.
RESOLVE_TIMEOUT_MS = 180000


def carrier_from_bindings(profile, module_base):
    """The game-thread carrier, read out of the binding profile.

    Live addresses are module_base + rva, and the signature bytes are the ones
    the profile recorded from the shipped executable -- the carrier re-checks
    them against mapped memory before it binds anything, so a wrong profile
    fails closed inside the game rather than here.
    """
    def entry(name):
        record = profile["addresses"][name]
        return (module_base + int(record["rva"]),
                bytes.fromhex(record["bytes"]))

    add, sig_add = entry("add_ticker")
    get, sig_get = entry("get_core_ticker")
    malloc, sig_malloc = entry("fmemory_malloc")
    return {"add_ticker": add, "get_core_ticker": get,
            "fmemory_malloc": malloc, "sig_add": sig_add,
            "sig_get": sig_get, "sig_malloc": sig_malloc}

# Every anchor both sides must agree on. Named individually so a mismatch says
# WHICH one, rather than "the dicts differ".
COMPARED = [
    "item_list", "master_item_list", "row_struct", "transient_package",
    "datatable_class", "composite_class", "texture2d_class", "staticmesh_class",
    "actor_class", "world_class", "cdo_gameplaystatics", "cdo_stringlib",
    "cdo_textlib", "cdo_syslib", "cdo_sgkfunctions", "fn_spawn_object",
    "fn_conv_str_to_name", "fn_str_to_text", "fn_text_to_str",
    "fn_load_asset_blocking", "fn_soft_to_string", "fn_sgk_itemdetails",
    "fn_additem", "fn_removeitem", "plain_vtable", "composite_vtable",
    "row_struct_size",
]


def python_oracle(api, handle, base, size, image, note):
    """The existing resolver, unchanged, as the reference answer."""
    r = c5.resolve(api, handle, base, size, image, note)
    # The oracle's own key names, mapped once, here. Renaming them in the
    # oracle would be editing a module four closed stages depend on.
    return {
        "item_list": r["itemlist"], "master_item_list": r["master"],
        "row_struct": r["row_struct"], "transient_package": r["transient"],
        "datatable_class": r["dt_class"], "composite_class": r["cdt_class"],
        "texture2d_class": r["tex_class"], "staticmesh_class": r["sm_class"],
        "actor_class": r["actor_class"], "world_class": r["world_class"],
        "cdo_gameplaystatics": r["gs_cdo"], "cdo_stringlib": r["sl_cdo"],
        "cdo_textlib": r["tl_cdo"], "cdo_syslib": r["sy_cdo"],
        "cdo_sgkfunctions": r["sgk_cdo"], "fn_spawn_object": r["spawn"],
        "fn_conv_str_to_name": r["conv"], "fn_str_to_text": r["str2txt"],
        "fn_text_to_str": r["txt2str"],
        "fn_load_asset_blocking": r["load_blocking"],
        "fn_soft_to_string": r["soft2str"],
        "fn_sgk_itemdetails": r["sgk_details"], "fn_additem": r["add_item"],
        "fn_removeitem": r["remove_item"],
        "player_inventory": r["player_inv"],
        "plain_vtable": r["plain_vtable"],
        "composite_vtable": r["composite_vtable"],
        "row_struct_size": r["struct_size"],
        "_raw": r,
    }


# The phases the resolver knows about. 3 is survey: resolve everything, fail
# nothing, report what is present -- which is how the phase assignment itself
# was measured rather than assumed.
PHASE_STARTUP, PHASE_CONTENT, PHASE_GAMEPLAY, PHASE_SURVEY = 0, 1, 2, 3


def pack_io(guobjectarray, namepool, require_phase, world_class, carrier,
            timeout_ms=RESOLVE_TIMEOUT_MS):
    return struct.pack(
        IO_FMT, RESOLVE_MAGIC, RESOLVE_PROTO, IO_SIZE, guobjectarray, namepool,
        carrier["add_ticker"], carrier["get_core_ticker"],
        carrier["fmemory_malloc"],
        carrier["sig_add"], carrier["sig_get"], carrier["sig_malloc"],
        int(require_phase), int(timeout_ms),
        0, -1, 0,
        0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
        world_class.encode("utf-8")[:127].ljust(128, b"\x00"),
        b"\x00" * 1024, b"\x00" * 8192)


def unpack_io(raw):
    v = struct.unpack(IO_FMT, raw)
    return {"done": v[13], "rc": v[14], "object_count": v[15],
            "queued_us": v[16], "build_us": v[17], "resolve_us": v[18],
            "reads": v[19], "vqueries": v[20], "cache_hits": v[21],
            "game_thread_id": v[22],
            # The chunking evidence. max_slice_us is the acceptance number: the
            # property is not that the work finished but that no single
            # game-thread slice was long enough to be seen.
            "slices": v[23], "max_slice_us": v[24],
            "max_slice_index": v[25],
            "objects_processed": v[26], "restarts": v[27],
            "revalidation_failures": v[28], "validate_us": v[29],
            "requested_phase": v[30], "completed_phase": v[31],
            "error": v[33].split(b"\x00", 1)[0].decode("utf-8", "replace"),
            "json": v[34].split(b"\x00", 1)[0].decode("utf-8", "replace")}


def run_cpp(session, runtime, guobjectarray, namepool, require_phase,
            carrier, world_class="BP_StaticMasterItem_C"):
    packed = pack_io(guobjectarray, namepool, require_phase, world_class,
                     carrier)
    remote = session.k.VirtualAllocEx(session.hp, None, IO_SIZE,
                                      ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                      ipp.PAGE_READWRITE)
    written = ctypes.c_size_t(0)
    session.k.WriteProcessMemory(session.hp, remote, packed, len(packed),
                                 ctypes.byref(written))
    p04.call_export(session.k, session.hp, session.rbase, runtime,
                    "Stage5ResolveDump", remote, ipp.WAIT_TIMEOUT_MS)
    buffer = ctypes.create_string_buffer(IO_SIZE)
    read = ctypes.c_size_t(0)
    session.k.ReadProcessMemory(session.hp, remote, buffer, IO_SIZE,
                                ctypes.byref(read))
    return unpack_io(buffer.raw)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--phase", default="gameplay",
                    help="a label for which lifecycle phase this run captured")
    ap.add_argument("--expect-player", default="auto",
                    choices=("auto", "yes", "no"))
    a = ap.parse_args(argv)

    checks = []

    def check(label, ok, detail=""):
        checks.append({"check": label, "pass": bool(ok), "detail": str(detail)})
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", label,
                               "" if ok else "  -- %s" % detail))
        return bool(ok)

    report = {"stage": "5B", "phase": a.phase,
              "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    internal = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
    runtime = nb.build_dll(
        [os.path.join(internal, n) for n in
         ("Stage5RuntimeDll.cpp", "BridgeTables.cpp", "CR01C5ProbeDll.cpp",
          "UE54TickerCarrier.cpp", "Resolver.cpp", "ResolverDump.cpp")],
        RUNTIME_DLL, extra='/I"%s"' % nb.DOTNET_PACK,
        libs='"%s"' % os.path.join(nb.DOTNET_PACK, "libnethost.lib"))

    import items_session                                           # noqa: PLC0415
    original_build, original_name = c5.build_dll, c5.DLL_NAME
    c5.build_dll = lambda: runtime
    c5.DLL_NAME = RUNTIME_DLL
    session = items_session.AggregateSession()
    api = eri.Win32Api()
    try:
        i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
        base, size = i01["base_address"], i01["image_size_bytes"]
        guobjectarray = base + eri.DEFAULT_GUOBJECTARRAY_RVA
        namepool = base + eri.DEFAULT_NAMEPOOL_RVA
        report["roots"] = {"guobjectarray": guobjectarray, "namepool": namepool}

        # THE ORACLE RUNS FIRST, on an untouched process.
        #
        # c5.resolve asserts ParentTables is the vanilla baseline -- one parent,
        # the spare slot null -- and refuses otherwise. That assertion is
        # correct and worth keeping: it is how the oracle knows nothing has
        # already attached to the composite. But AggregateSession.init() ATTACHES
        # the aggregate, so running it first made the oracle refuse a process
        # this script had itself modified. Oracle first, then inject.
        handle = eri.open_process_read_only(api, i01["pid"])
        note = []
        try:
            image = c5.DiskImage(i01["exe_path"])
            oracle = python_oracle(api, handle, base, size, image, note)
        finally:
            api.close_handle(handle)
        report["oracle"] = {k: v for k, v in oracle.items() if k != "_raw"}

        # Now inject, so the C++ resolver can be called at all. None of the
        # anchors being compared is affected by attaching the aggregate: they
        # are classes, CDOs, functions and the two tables themselves.
        session.init()
        check("the runtime is loaded in the live process", session.rbase is not None)

        # --- the C++ resolver ------------------------------------------
        want = PHASE_GAMEPLAY if a.expect_player != "no" else PHASE_CONTENT
        cpp = run_cpp(session, runtime, guobjectarray, namepool, want,
                      carrier)
        report["cpp"] = cpp
        if not check("the C++ resolver completed", cpp["done"] == 1, str(cpp)[:300]):
            raise SystemExit(_finish(report, checks, a.out))
        if not check("the C++ resolver succeeded", cpp["rc"] == 0, cpp["error"]):
            raise SystemExit(_finish(report, checks, a.out))

        answers = json.loads(cpp["json"])
        report["cpp_answers"] = answers
        check("the C++ resolver saw a full object universe",
              answers["object_count"] > 100000, answers["object_count"])

        # --- the comparison --------------------------------------------
        mismatched = []
        for key in COMPARED:
            if int(oracle[key]) != int(answers[key]):
                mismatched.append("%s: python=0x%x cpp=0x%x"
                                  % (key, int(oracle[key]), int(answers[key])))
        check("all %d anchors agree between the two resolvers" % len(COMPARED),
              not mismatched, "; ".join(mismatched))

        present = bool(answers["player_inventory_present"])
        report["player_inventory_present"] = present
        if a.expect_player == "no":
            check("the player inventory is correctly reported ABSENT "
                  "(a transition state, not a failure)", not present,
                  "0x%x" % answers["player_inventory"])
        else:
            check("the live player inventory resolved", present)
            if present:
                check("both resolvers found the SAME player inventory",
                      int(oracle["player_inventory"]) ==
                      int(answers["player_inventory"]),
                      "python=0x%x cpp=0x%x" % (int(oracle["player_inventory"]),
                                                int(answers["player_inventory"])))

        # Ambiguity safety, exercised rather than asserted: a name that exists
        # many times must be REFUSED, not resolved to whichever came first.
        ambiguous = run_cpp(session, runtime, guobjectarray, namepool,
                            PHASE_CONTENT, carrier, world_class="Object")
        report["ambiguity_probe"] = ambiguous
        check("an ambiguous class name is refused, not first-matched",
              ambiguous["rc"] != 0 and
              ("ambiguous" in ambiguous["error"] or
               "no object named" in ambiguous["error"] or
               "does not derive" in ambiguous["error"]),
              ambiguous["error"][:200])

        # A wrong root must fail loudly rather than resolve garbage.
        bad = run_cpp(session, runtime, guobjectarray + 0x1000, namepool, False)
        report["bad_root_probe"] = bad
        check("a wrong GUObjectArray address fails closed",
              bad["rc"] != 0, bad["error"][:200])
    finally:
        c5.build_dll, c5.DLL_NAME = original_build, original_name
        if session.initialised:
            try:
                session.shutdown()
            except Exception as error:                             # noqa: BLE001
                report["shutdown_error"] = str(error)

    return _finish(report, checks, a.out)


def _finish(report, checks, out_path):
    report["checks"] = checks
    report["passed"] = sum(1 for c in checks if c["pass"])
    report["failed"] = sum(1 for c in checks if not c["pass"])
    report["verdict"] = "PASS" if report["failed"] == 0 else "FAIL"
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, default=str)
        handle.write("\n")
    print("\n%s -- %d passed, %d failed -> %s"
          % (report["verdict"], report["passed"], report["failed"], out_path))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
