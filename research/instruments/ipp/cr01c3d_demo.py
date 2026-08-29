#!/usr/bin/env python3
"""RESEARCH ONLY. CR-01C3D DEMO -- hold the published item live for a visual check.

Exactly the CR-01C3D path, proven in ae7396e, split into two halves:

  --demo     resolve -> create -> root -> materialize -> AddRow -> attach ->
             publish -> resolve check -> AddItem -> VERIFY -> STOP AND HOLD.
             The Runtime table stays rooted, the ParentTables publication stays
             live, and the probe module and its IO block stay loaded, so the item
             remains in the inventory for as long as the game runs.

  --cleanup  the already-proven rollback, against the module the demo left
             loaded: RemoveItem -> verify absent -> detach -> restore
             MasterItemList -> zero the spare slot -> release the root ->
             Shutdown handshake -> FreeLibrary.

Nothing here is new mechanism. The only difference from the gate is that the
teardown is deferred to a separate invocation instead of running in a finally.

Because the demo deliberately leaves the module loaded, it also deliberately
leaves the remote IO block allocated -- the module holds g_io, and freeing it
would leave a live dispatcher writing into unmapped memory.
"""
import argparse
import ctypes
import json
import os
import struct
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
IPP = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, IPP)
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO, "tools", "reflection"))
import eri, ipp_controller as ipp, gt01_controller as gt, fts_controller as fts, p04_controller as p04  # noqa: E402
import probe_teardown  # noqa: E402
import cr01c3d_controller as c3d  # noqa: E402
from cr01c3b_controller import DiskImage, verify_carrier_addresses, verify_fields  # noqa: E402

STATE_PATH = os.path.join(REPO, "workspace", "c3d-demo-state.json")
DEMO_ROW_NAME = "mbpl__demo_item"
DEMO_TRIGGER_NAME = "mbpl__demo_neutral_trigger"


def _patch_names():
    """The demo publishes its own row name so it can never be confused with the
    gate's probe. Everything else is the proven configuration, unchanged."""
    c3d.ROW_NAME = DEMO_ROW_NAME
    c3d.TRIGGER_NAME = DEMO_TRIGGER_NAME


def save_state(state):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8", newline="\n") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")


def load_state():
    if not os.path.isfile(STATE_PATH):
        raise ipp.Blocked("no demo state at %s -- nothing to clean up" % STATE_PATH)
    with open(STATE_PATH, encoding="utf-8") as f:
        return json.load(f)


def preflight(api, run_note):
    """Fresh identification of THIS session's player inventory, plus the
    authority and fingerprint gates. Fails closed if there is no valid live
    player inventory to add to."""
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    pid, base, size, exe = i01["pid"], i01["base_address"], i01["image_size_bytes"], i01["exe_path"]
    if ipp.sha256_of_file(exe) != fts.EXPECTED_BUILD_SHA256:
        raise ipp.Blocked("build fingerprint mismatch")
    run_note.append("pid=%d build fingerprint confirmed" % pid)
    img = DiskImage(exe)
    addrs = verify_carrier_addresses(api, pid, base, img, run_note)
    h = eri.open_process_read_only(api, pid)
    try:
        r = c3d.resolve(api, h, base, size, img, run_note)
        offs, field_report = verify_fields(api, h, r["np"], r["row_struct"])
        for kk in field_report:
            field_report[kk]["value"] = c3d.VALUES[kk]
        inv = c3d.read_inventory(api, h, r["player_inv"])
    finally:
        api.close_handle(h)
    if not inv["slots"] or inv["num"] <= 0:
        raise ipp.Blocked("the live player inventory has no allocated slot array -- is the "
                          "character dead or the save not fully loaded? Respawn or load a save.")
    free_slots = sum(1 for s in inv["slots"] if not s["occupied"])
    if free_slots == 0:
        raise ipp.Blocked("the player inventory has no free slot (%d/%d occupied); free a slot "
                          "before the demo" % (inv["num"] - free_slots, inv["num"]))
    run_note.append("player inventory 0x%x: %d slots, %d occupied, %d free, weight=%r count=%d"
                    % (r["player_inv"], inv["num"], inv["num"] - free_slots, free_slots,
                       inv["current_weight"], inv["item_count"]))
    return {"pid": pid, "base": base, "size": size, "exe": exe, "img": img,
            "addrs": addrs, "r": r, "offs": offs, "field_report": field_report, "inv": inv}


def run_demo(api, run_note):
    _patch_names()
    k, _ = gt._k32full()
    pf = preflight(api, run_note)
    pid, r, offs, img = pf["pid"], pf["r"], pf["offs"], pf["img"]
    inv0 = pf["inv"]

    dll = c3d.build_dll()
    sigs = {"add": img.bytes_at(fts.RVA_ADD_TICKER, 16),
            "get": img.bytes_at(fts.RVA_GET_CORE_TICKER, 16),
            "malloc": img.bytes_at(fts.RVA_FMEMORY_MALLOC, 16)}
    carrier = {"add_ticker": pf["addrs"]["add_ticker"],
               "get_core_ticker": pf["addrs"]["get_core_ticker"],
               "fmemory_malloc": pf["addrs"]["fmemory_malloc"]}

    hp = k.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, pid)
    if not hp:
        raise ipp.Blocked("OpenProcess failed")
    pth = (dll + "\x00").encode("utf-16-le")
    rpath = k.VirtualAllocEx(hp, None, len(pth), ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
    wr = ctypes.c_size_t(0)
    k.WriteProcessMemory(hp, rpath, pth, len(pth), ctypes.byref(wr))
    pll = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
    t = k.CreateRemoteThread(hp, None, 0, pll, rpath, 0, None)
    k.WaitForSingleObject(t, ipp.WAIT_TIMEOUT_MS); k.CloseHandle(t)
    rbase = ipp.find_remote_module_base(k, pid, c3d.DLL_NAME)
    if rbase is None:
        raise ipp.Blocked("probe DLL not loaded")
    io = c3d.pack_io(carrier, sigs, r, offs)
    rio = k.VirtualAllocEx(hp, None, c3d.IO_SIZE, ipp.MEM_COMMIT | ipp.MEM_RESERVE, ipp.PAGE_READWRITE)
    k.WriteProcessMemory(hp, rio, io, len(io), ctypes.byref(wr))
    buf = ctypes.create_string_buffer(c3d.IO_SIZE); rd = ctypes.c_size_t(0)

    def read_io():
        k.ReadProcessMemory(hp, rio, buf, c3d.IO_SIZE, ctypes.byref(rd))
        return c3d.unpack_io(buf.raw)

    def call(export, field, timeout=25.0):
        p04.call_export(k, hp, rbase, dll, export, rio, ipp.WAIT_TIMEOUT_MS)
        st = read_io(); dl = time.time() + timeout
        while time.time() < dl and st[field] == 0:
            time.sleep(0.05); st = read_io()
        return st

    report = {"mode": "demo", "pid": pid, "row_name": DEMO_ROW_NAME,
              "definition": {kk: v["value"] for kk, v in pf["field_report"].items()},
              "invitem_initial_state": dict(c3d.INVITEM),
              "baseline_inventory": {"slots": inv0["num"],
                                     "occupied": sum(1 for s in inv0["slots"] if s["occupied"]),
                                     "current_weight": inv0["current_weight"],
                                     "item_count": inv0["item_count"]}}

    if p04.call_export(k, hp, rbase, dll, "Init", rio, ipp.WAIT_TIMEOUT_MS) != 0:
        raise ipp.Blocked("Init failed")
    st = call("RunCreate", "create_ran")
    if st["create_ran"] != 1:
        raise ipp.Blocked("create failed err=%d step=%d" % (st["err"], st["err_step"]))
    table_ptr, row_fname = st["table_ptr"], st["row_fname"]

    st = call("RunPopulate", "populate_ran")
    if st["populate_ran"] != 1:
        raise ipp.Blocked("populate failed err=%d" % st["err"])
    if st["use_item_decay"]:
        raise ipp.Blocked("materialized definition has UseItemDecay=1; refusing")
    run_note.append("definition materialized (UseDurability=%d UseItemDecay=%d)"
                    % (st["use_durability"], st["use_item_decay"]))

    st = call("RunAttach", "attach_ran")
    if st["attach_ran"] != 1:
        raise ipp.Blocked("attach refused err=%d step=%d" % (st["err"], st["err_step"]))
    run_note.append("published: ParentTables Num %d->%d"
                    % (st["parent_num_before"], st["parent_num_after_attach"]))

    st = call("RunResolve", "resolve_ran")
    if st["resolve_ran"] != 1 or st["resolve_found"] != 1:
        raise ipp.Blocked("SGK ItemDetails did not resolve the definition (found=%d)"
                          % st["resolve_found"])
    report["resolver"] = {"found": st["resolve_found"], "weight": st["resolve_weight"],
                          "width": st["resolve_width"], "height": st["resolve_height"],
                          "maxstack": st["resolve_maxstack"]}
    run_note.append("resolver found the definition: weight=%r %dx%d"
                    % (st["resolve_weight"], st["resolve_width"], st["resolve_height"]))

    st = call("RunAddItem", "additem_ran")
    if st["additem_ran"] != 1:
        raise ipp.Blocked("AddItem job did not run err=%d" % st["err"])
    report["additem_out"] = {"RemainingItem": st["out_remaining_item"],
                             "NewItemSlot": st["out_newitemslot"]}

    h = eri.open_process_read_only(api, pid)
    try:
        inv1 = c3d.read_inventory(api, h, r["player_inv"])
    finally:
        api.close_handle(h)
    ours = c3d.occupied_with(inv1, row_fname & 0xFFFFFFFF)
    report["inventory"] = {"entries_with_item": len(ours),
                           "slot": ours[0] if ours else None,
                           "item_count": inv1["item_count"],
                           "current_weight": inv1["current_weight"],
                           "changed_slots": c3d.slot_diff(inv0, inv1)}
    if len(ours) != 1:
        raise ipp.Blocked("expected exactly one inventory entry, found %d -- the demo is NOT "
                          "holding a valid state; run --cleanup" % len(ours))

    save_state({"pid": pid, "rbase": rbase, "rio": rio, "rpath": rpath, "dll": dll,
                "row_fname": row_fname, "table_ptr": table_ptr,
                "player_inv": r["player_inv"], "master": r["master"], "itemlist": r["itemlist"],
                "row_struct": r["row_struct"], "objects_ptr": r["objects_ptr"],
                "struct_size": r["struct_size"], "offs": offs, "row_name": DEMO_ROW_NAME,
                "baseline_inventory_sha256": inv0["slots_sha256"],
                "baseline_weight": inv0["current_weight"],
                "baseline_item_count": inv0["item_count"],
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    report["state_file"] = STATE_PATH
    report["status"] = "READY_FOR_VISUAL_CHECK"
    report["held"] = {"runtime_table_rooted": True, "parenttables_publication_live": True,
                      "probe_module_loaded": True, "remote_io_allocated": True}
    k.CloseHandle(hp)
    return report


def run_cleanup(api, run_note):
    _patch_names()
    k, _ = gt._k32full()
    state = load_state()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    if i01["pid"] != state["pid"]:
        raise ipp.Blocked("the game has been restarted (pid %d, demo held pid %d). The demo state "
                          "died with the old process; nothing to roll back. Delete %s."
                          % (i01["pid"], state["pid"], STATE_PATH))
    pid, dll, rbase, rio = state["pid"], state["dll"], state["rbase"], state["rio"]
    if ipp.find_remote_module_base(k, pid, c3d.DLL_NAME) != rbase:
        raise ipp.Blocked("the probe module is no longer loaded at the recorded base")

    hp = k.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, pid)
    if not hp:
        raise ipp.Blocked("OpenProcess failed")
    buf = ctypes.create_string_buffer(c3d.IO_SIZE); rd = ctypes.c_size_t(0)
    wr = ctypes.c_size_t(0)

    def read_io():
        k.ReadProcessMemory(hp, rio, buf, c3d.IO_SIZE, ctypes.byref(rd))
        return c3d.unpack_io(buf.raw)

    def read_io_safe():
        k.ReadProcessMemory(hp, rio, buf, c3d.IO_SIZE, ctypes.byref(rd))
        return {"wait_stopped_ok": struct.unpack_from("<I", buf.raw,
                                                      c3d.WAIT_STOPPED_OK_OFFSET)[0],
                "state": struct.unpack_from("<I", buf.raw, c3d.STATE_OFFSET)[0]}

    def call(export, field, timeout=25.0):
        before = read_io()[field]
        p04.call_export(k, hp, rbase, dll, export, rio, ipp.WAIT_TIMEOUT_MS)
        st = read_io(); dl = time.time() + timeout
        while time.time() < dl and st[field] == before:
            time.sleep(0.05); st = read_io()
        return st

    report = {"mode": "cleanup", "pid": pid, "row_name": state["row_name"]}
    fake_r = {"itemlist": state["itemlist"], "master": state["master"],
              "player_inv": state["player_inv"], "objects_ptr": state["objects_ptr"],
              "struct_size": state["struct_size"], "row_struct": state["row_struct"]}
    fid = state["row_fname"] & 0xFFFFFFFF

    h = eri.open_process_read_only(api, pid)
    try:
        inv = c3d.read_inventory(api, h, state["player_inv"])
    finally:
        api.close_handle(h)
    mine = c3d.occupied_with(inv, fid)
    report["found_before_cleanup"] = len(mine)
    if mine:
        k.WriteProcessMemory(hp, rio + c3d.SLOT_IN_OFFSET, bytes.fromhex(mine[0]["raw"]), 80,
                             ctypes.byref(wr))
        st = call("RunRemoveItem", "removeitem_ran")
        report["removeitem_ran"] = st["removeitem_ran"]
        run_note.append("RemoveItem ran=%d" % st["removeitem_ran"])
    else:
        run_note.append("no inventory entry carried the demo id; skipping RemoveItem")

    h = eri.open_process_read_only(api, pid)
    try:
        inv2 = c3d.read_inventory(api, h, state["player_inv"])
    finally:
        api.close_handle(h)
    report["inventory_after_remove"] = {
        "entries_with_item": len(c3d.occupied_with(inv2, fid)),
        "item_count": inv2["item_count"], "current_weight": inv2["current_weight"],
        "slots_sha256_restored": inv2["slots_sha256"] == state["baseline_inventory_sha256"],
        "weight_restored": abs(inv2["current_weight"] - state["baseline_weight"]) < 1e-9,
        "count_restored": inv2["item_count"] == state["baseline_item_count"]}

    st = call("RunDetach", "detach_ran"); report["detach_ran"] = st["detach_ran"]
    st = call("RunZeroSlot", "zero_ran"); report["zero_ran"] = st["zero_ran"]
    st = call("RunRelease", "release_ran")
    report["release"] = {"release_ran": st["release_ran"],
                         "rooted_after_release": st["rooted_after_release"],
                         "owned_count": st["owned_count"]}

    h = eri.open_process_read_only(api, pid)
    try:
        from cr01c3c_controller import parent_raw, old_parent_state
        report["final"] = {
            "master_rows": len(c3d.rows_by_key(api, h, state["master"])),
            "itemlist_rows": len(c3d.rows_by_key(api, h, state["itemlist"])),
            "parent_raw": parent_raw(api, h, state["master"]),
            "old_parent": old_parent_state(api, h, state["master"])}
    finally:
        api.close_handle(h)

    td = probe_teardown.shutdown_then_unload(k, hp, rbase, dll, rio, read_io_safe, run_note)
    report["teardown"] = td
    if td["safe_to_free_remote_memory"]:
        for b2 in (state.get("rpath"), rio):
            if b2:
                k.VirtualFreeEx(hp, b2, 0, ipp.MEM_RELEASE)
        report["remote_memory_freed"] = True
    else:
        report["remote_memory_left_allocated"] = True
    try:
        report["dll_unloaded"] = ipp.confirm_dll_unloaded(pid, c3d.DLL_NAME)
    except Exception:  # noqa: BLE001
        report["dll_unloaded"] = None
    k.CloseHandle(hp)

    if td["attempted"] and not td["unloaded"]:
        report["status"] = "BLOCKED-TEARDOWN"
        report["teardown_blocked"] = td["left_loaded_reason"]
    else:
        report["status"] = "CLEAN"
        if os.path.isfile(STATE_PATH):
            os.remove(STATE_PATH)
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--demo", action="store_true", help="add the item and HOLD the state")
    g.add_argument("--cleanup", action="store_true", help="run the proven rollback")
    ap.add_argument("--run-dir", default=None)
    a = ap.parse_args(argv)
    arguments = list(argv) if argv is not None else list(sys.argv[1:])
    rid = (a.run_dir and os.path.basename(a.run_dir)) or time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())
    rdir = a.run_dir or os.path.join(REPO, "research", "instrument-runs", rid)
    os.makedirs(rdir, exist_ok=True)
    note, arts = [], []
    vb = va = None
    code = 0
    try:
        api = eri.Win32Api()
        vb = ipp.run_verify_install(rdir, "before")
        if vb.get("report_artifact"):
            arts.append(vb["report_artifact"])
        if vb["result"] == "mismatch":
            raise ipp.Blocked("verify_install MISMATCH before")
        rep = run_demo(api, note) if a.demo else run_cleanup(api, note)
        rep["run_note"] = note
        va = ipp.run_verify_install(rdir, "after")
        if va.get("report_artifact"):
            arts.append(va["report_artifact"])
        rp = os.path.join(rdir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, indent=2, sort_keys=True, default=str); f.write("\n")
        arts.append(os.path.relpath(rp, REPO).replace(os.sep, "/"))
        print(json.dumps(rep, indent=2, sort_keys=True, default=str))
        if rep.get("status") == "BLOCKED-TEARDOWN":
            code = 2
    except (ipp.Blocked, eri.EriError) as e:
        rep = {"blocked": True, "reason": str(e), "run_note": note}
        rp = os.path.join(rdir, "report.json")
        with open(rp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, indent=2, sort_keys=True, default=str); f.write("\n")
        arts.append(os.path.relpath(rp, REPO).replace(os.sep, "/"))
        print("BLOCKED:", e, file=sys.stderr)
        code = 2
    finally:
        ipp.write_manifest(rdir, arguments=arguments, capabilities_enabled=["CR-01C3D"],
                           build_sha256=fts.EXPECTED_BUILD_SHA256, verify_before=vb,
                           verify_after=va, artifacts=arts, instrument_level="ipp")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
