#!/usr/bin/env python3
"""The CR-01C5-era hot-reload lifecycle, run N times against ONE game process.

WHY THIS EXISTS
---------------
Register -> Unregister -> Register in a single process is proven only for the
CR-01C4A-era probe, which wrote texts and scalars and nothing else. The C5 path
adds an icon, a static mesh, a world class and a transform, and every C5 process
so far ran exactly one arm. So the lifecycle this subsystem is about to be built
on has never actually been cycled.

The game process is NOT restarted between cycles. That is the whole point: a
defect that only shows up as accumulated state -- a root that is never released,
a delegate subscribed twice, a dispatcher left ticking, a row that survives its
own removal, an FText refcount that climbs -- is invisible to a test that starts
from a fresh process every time.

WHAT IT MEASURES, EVERY CYCLE
-----------------------------
    runtime table row count        our own table, before and after
    MasterItemList resolution      the composite's row count and our row's
                                   presence in it
    ItemList integrity             the vanilla parent must stay byte-identical
    ParentTables                   Num back to 1, spare slot zeroed
    delegates / subscriptions      ItemList's OnDataTableChanged invocation list
    roots / asset store            owned_count and the rooted flags
    dispatcher / ticker            state, wait_stopped_ok, module unloaded
    FText                          the InitializeStruct defaults and OUR text
                                   data pointers, plus their refcounts when a
                                   verified read recipe is available
    duplicate registration         a second arm while one is already held
    unregister idempotence         a second cleanup with nothing held

Everything is read from the game read-only except the arm/cleanup runs
themselves, which use the already-proven controller unchanged.
"""
import argparse
import json
import os
import struct
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "runner")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                       # noqa: E402
import cr01c3_recon as recon                     # noqa: E402
import readiness                                 # noqa: E402
import read_datatable_rows as rdr                # noqa: E402
import ftext_refcount as ftr                     # noqa: E402
from cr01c3b_controller import OFF_PARENT_TABLES  # noqa: E402

PYTHON = sys.executable
CONTROLLER = os.path.join(REPO, "research", "instruments", "ipp", "cr01c5_controller.py")
STATE_PATH = os.path.join(REPO, "workspace", "c5-demo-state.json")
ROW_NAME = "mbpl__radio"
OFF_DELEGATE = 0x98          # ItemList's OnDataTableChanged, derived in CR-01C3


def run_controller(*args, timeout=900):
    """Run the proven controller unchanged, and capture what it did."""
    t0 = time.time()
    proc = subprocess.run([PYTHON, CONTROLLER] + list(args), capture_output=True,
                          text=True, timeout=timeout, cwd=REPO)
    return {"args": list(args), "exit": proc.returncode,
            "seconds": round(time.time() - t0, 1),
            "stderr_tail": (proc.stderr or "").strip().splitlines()[-3:],
            "stdout_tail": (proc.stdout or "").strip().splitlines()[-3:]}


def latest_run_report():
    runs = sorted(d for d in os.listdir(os.path.join(REPO, "research", "instrument-runs"))
                  if d.startswith("2026-"))
    if not runs:
        return None
    p = os.path.join(REPO, "research", "instrument-runs", runs[-1], "report.json")
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def observe(api, textdata_pointers=None, expect_strings=None):
    """One read-only observation of everything that could accumulate.

    *textdata_pointers* are the three persistent ITextData defaults of
    S_ItemDetails, learned from the first arm. They are sampled on EVERY
    observation, because the question is whether their refcount climbs with each
    materialization -- which is what "overwriting the field without destructing
    it drops a reference" predicts.
    """
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    h = eri.open_process_read_only(api, i01["pid"])
    out = {"pid": i01["pid"], "at": time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())}
    try:
        np, objs = recon.universe(api, h, i01["base_address"], i01["image_size_bytes"])
        out["objects_total"] = len(objs)

        def nm(a):
            return (objs.get(a) or {}).get("name_text") if a else None

        def cls_of(a):
            return nm(eri._read_u64(api, h, a + eri.DEFAULT_CLASS_PRIVATE_OFFSET)) if a else None

        def path_of(a):
            if not a:
                return None
            try:
                return eri.canonicalize_object_path(
                    eri.resolve_object_path(a, objs).get("object_path"))
            except Exception:                                  # noqa: BLE001
                return None

        def one(name, clsname):
            c = [a for a, r in objs.items() if r.get("name_ok") and r.get("name_text") == name
                 and cls_of(a) == clsname]
            return c[0] if len(c) == 1 else None

        def fname(eid):
            try:
                return eri.decode_fname_entry_id(api, h, np, eid).get("text")
            except Exception:                                  # noqa: BLE001
                return None

        itemlist = one("ItemList", "DataTable")
        master = one("MasterItemList", "CompositeDataTable")

        def keys(table):
            if not table:
                return None
            try:
                rows, _diag = rdr.read_rowmap(api, h, table)
            except Exception as exc:                           # noqa: BLE001
                return {"error": repr(exc)}
            return [fname(c) for c, _n, _v in rows]

        il, ml = keys(itemlist), keys(master)
        out["ItemList"] = {"rows": None if il is None else len(il),
                           "contains_our_row": bool(il) and ROW_NAME in il}
        out["MasterItemList"] = {"rows": None if ml is None else len(ml),
                                 "contains_our_row": bool(ml) and ROW_NAME in ml}

        # ParentTables: Num must be back to 1 and the spare slot zeroed
        if master:
            data = eri._read_u64(api, h, master + OFF_PARENT_TABLES)
            num = struct.unpack("<i", api.read_process_memory(
                h, master + OFF_PARENT_TABLES + 8, 4))[0]
            mx = struct.unpack("<i", api.read_process_memory(
                h, master + OFF_PARENT_TABLES + 12, 4))[0]
            slots = []
            if data and 0 < mx <= 64:
                raw = api.read_process_memory(h, data, mx * 8)
                slots = [struct.unpack_from("<Q", raw, i * 8)[0] for i in range(mx)]
            out["ParentTables"] = {"num": num, "max": mx,
                                   "slots": ["0x%x" % x for x in slots],
                                   "names": [nm(x) for x in slots]}

        # the delegate ItemList broadcasts on change -- a second subscription
        # here would mean the composite got wired up twice
        if itemlist:
            d = eri._read_u64(api, h, itemlist + OFF_DELEGATE)
            n = struct.unpack("<i", api.read_process_memory(
                h, itemlist + OFF_DELEGATE + 8, 4))[0]
            out["itemlist_change_delegate"] = {"data": "0x%x" % d, "num": n}

        # runtime tables that should NOT outlive a cleanup
        out["transient_datatables"] = [
            {"object": "0x%x" % a, "path": path_of(a)}
            for a in objs
            if cls_of(a) == "DataTable" and (path_of(a) or "").startswith("/Engine/Transient")]

        # our content: still resident? still rooted?
        content = {}
        for name, want in (("T_MBPL_Radio_Icon", "Texture2D"),
                           ("SM_MBPL_Radio", "StaticMesh")):
            hits = [a for a, r in objs.items()
                    if r.get("name_ok") and r.get("name_text") == name and cls_of(a) == want]
            content[name] = [{"object": "0x%x" % a, "rooted": _is_rooted(api, h, objs, a)}
                             for a in hits]
        out["content"] = content

        # the probe module must be gone after a cleanup
        out["probe_module_loaded"] = _module_base(i01["pid"])

        if textdata_pointers:
            out["textdata"] = ftr.probe_many(
                api, h, [ftr.as_int(p) for p in textdata_pointers],
                expect_strings=expect_strings)
    finally:
        api.close_handle(h)
    return out


def _is_rooted(api, h, objs, address):
    """Read the object's own RF_MirroredGarbage-adjacent flags is not enough for
    rootedness; the RootSet bit lives in FUObjectItem. Reported as unknown when
    it cannot be established rather than guessed."""
    return None


def _module_base(pid):
    try:
        import ipp_controller as ipp
        import gt01_controller as gt
        k, _ = gt._k32full()
        base = ipp.find_remote_module_base(k, pid, "CR01C5Probe.dll")
        return ("0x%x" % base) if base else None
    except Exception:                                          # noqa: BLE001
        return "unknown"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cycles", type=int, default=3)
    ap.add_argument("--out", required=True)
    ap.add_argument("--test-duplicate", action="store_true",
                    help="after arming, try to arm AGAIN and record what happens")
    ap.add_argument("--test-idempotent-unregister", action="store_true",
                    help="after cleanup, run cleanup AGAIN and record what happens")
    a = ap.parse_args(argv)

    api = eri.Win32Api()
    report = {"cycles_requested": a.cycles, "started_at": time.strftime("%Y-%m-%dT%H%M%SZ",
                                                                       time.gmtime()),
              "cycles": []}

    # Learned from the first arm; None until then, so the very first baseline
    # has no refcount column. That is honest -- the pointers are not knowable
    # before a materialization reveals them.
    defaults = None
    expect = None

    print("baseline observation")
    report["baseline"] = observe(api)
    b = report["baseline"]
    print("  ItemList=%s Master=%s ParentTables.num=%s transient_dts=%d module=%s"
          % (b["ItemList"]["rows"], b["MasterItemList"]["rows"],
             b.get("ParentTables", {}).get("num"), len(b["transient_datatables"]),
             b["probe_module_loaded"]))

    for i in range(a.cycles):
        cyc = {"index": i}
        print("\n--- cycle %d: ARM ---" % i)
        cyc["arm"] = run_controller("--arm")
        print("   exit=%s in %ss" % (cyc["arm"]["exit"], cyc["arm"]["seconds"]))
        rep = latest_run_report()
        if rep:
            cyc["arm_report"] = {
                "verdict": rep.get("verdict"),
                "empty_textdata": rep.get("empty_textdata"),
                "our_textdata": rep.get("our_textdata"),
                "row_textdata": rep.get("row_textdata"),
                "owned_count": (rep.get("mesh_load") or {}).get("owned_count"),
                "master_rows": (rep.get("after_publish") or {}).get("master_rows"),
                "itemlist_exact_unchanged": (rep.get("after_publish") or {}).get(
                    "itemlist_exact_unchanged"),
            }
            print("   verdict=%s master_rows=%s owned=%s"
                  % (cyc["arm_report"]["verdict"], cyc["arm_report"]["master_rows"],
                     cyc["arm_report"]["owned_count"]))
        td = (rep or {}).get("textdata") or {}
        if defaults is None and td.get("initializestruct_defaults"):
            defaults = td["initializestruct_defaults"]
            report["textdata_defaults"] = defaults
            report["textdata_defaults_note"] = td.get("what_the_defaults_are")
            print("   learned the three ITextData defaults: %s" % defaults)
        if td.get("ours"):
            cyc["our_textdata_this_cycle"] = td["ours"]
        cyc["after_arm"] = observe(api, defaults, expect)

        if a.test_duplicate:
            print("   duplicate arm while one is held...")
            cyc["duplicate_arm"] = run_controller("--arm")
            print("     exit=%s" % cyc["duplicate_arm"]["exit"])
            cyc["after_duplicate"] = observe(api, defaults, expect)

        print("--- cycle %d: CLEANUP ---" % i)
        cyc["cleanup"] = run_controller("--cleanup")
        print("   exit=%s in %ss" % (cyc["cleanup"]["exit"], cyc["cleanup"]["seconds"]))
        crep = latest_run_report()
        if crep:
            cyc["cleanup_report"] = {
                "verdict": crep.get("verdict"),
                "release_table": crep.get("release_table"),
                "final_tables": crep.get("final_tables"),
                "teardown": crep.get("teardown"),
                "dll_unloaded": crep.get("dll_unloaded")}
            print("   verdict=%s dll_unloaded=%s"
                  % (cyc["cleanup_report"]["verdict"], cyc["cleanup_report"]["dll_unloaded"]))
        rc_a = ((cyc.get("after_arm") or {}).get("textdata") or {}).get("refcounts")
        if rc_a:
            print("   FText default refcounts after arm: %s" % rc_a)
        cyc["after_cleanup"] = observe(api, defaults, expect)

        if a.test_idempotent_unregister:
            print("   second cleanup with nothing held...")
            cyc["idempotent_cleanup"] = run_controller("--cleanup")
            print("     exit=%s  stderr=%s" % (cyc["idempotent_cleanup"]["exit"],
                                               cyc["idempotent_cleanup"]["stderr_tail"]))

        rc_c = ((cyc.get("after_cleanup") or {}).get("textdata") or {}).get("refcounts")
        if rc_c:
            print("   FText default refcounts after cleanup: %s" % rc_c)
        report["cycles"].append(cyc)
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(report, f, indent=2, sort_keys=False, default=str)
            f.write("\n")

    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    print("\nwrote %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
