#!/usr/bin/env python3
"""STRICTLY READ-ONLY. CR-01C4B post-run integrity verification.

The demo process was terminated by a full game restart, so there is no in-memory
state left to roll back and no stale pointer may be dereferenced. What is still
checkable, and what actually matters for closing the gate, is that the runtime
work left NOTHING behind anywhere durable:

  * the fresh process carries no probe module,
  * the vanilla registry in the fresh process is at its untouched baseline,
  * the row name exists nowhere in the fresh session,
  * the Steam installation is byte-identical to its baseline,
  * no save file on disk carries the runtime row's name -- a save that did
    would reference a definition that does not exist without our runtime, which
    is the one way a purely in-memory experiment could still bite later.

Nothing is written to the game, the install, or the saves.
"""
import glob
import json
import os
import struct
import sys

REPO = "D:/Dev/MiseryFramework"
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "ipp"))
sys.path.insert(0, os.path.join(REPO, "tools", "reflection"))
import eri  # noqa: E402
import ipp_controller as ipp  # noqa: E402
import gt01_controller as gt  # noqa: E402
import fts_controller as fts  # noqa: E402
import cr01c3_recon as recon  # noqa: E402
import read_datatable_rows as rdr  # noqa: E402

ROW = "mbpl__radio"
PROBES = ("CR01C4BProbe.dll", "CR01C4BPatchProbe.dll", "CR01C4AProbe.dll",
          "CR01C3DProbe.dll", "CR01C3CProbe.dll", "CR01C3BProbe.dll")
SAVE_DIRS = [os.path.expandvars(r"%LOCALAPPDATA%\MISERY\Saved\SaveGames"),
             os.path.expandvars(r"%LOCALAPPDATA%\MISERY\Saved")]
PAK_DIR = os.path.expandvars(r"%LOCALAPPDATA%\MISERY\Saved\Paks")


def main():
    state_path = os.path.join(REPO, "workspace", "c4b-demo-state.json")
    st = json.load(open(state_path, encoding="utf-8")) if os.path.isfile(state_path) else {}
    rep = {"held_state_pid": st.get("pid"), "held_state_file": state_path}

    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    rep["current_pid"] = i01["pid"]
    rep["demo_process_terminated"] = i01["pid"] != st.get("pid")
    rep["build_fingerprint_matches"] = (
        ipp.sha256_of_file(i01["exe_path"]) == fts.EXPECTED_BUILD_SHA256)

    k, _ = gt._k32full()
    rep["probe_modules_in_fresh_process"] = {
        n: ipp.find_remote_module_base(k, i01["pid"], n) for n in PROBES}
    rep["no_probe_module_loaded"] = all(
        v is None for v in rep["probe_modules_in_fresh_process"].values())

    h = eri.open_process_read_only(api, i01["pid"])
    try:
        np, objs = recon.universe(api, h, i01["base_address"], i01["image_size_bytes"])

        def one(nm, cls):
            c = [a for a, r in objs.items() if r.get("name_ok") and r.get("name_text") == nm
                 and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == cls]
            return c[0] if len(c) == 1 else None

        il = one("ItemList", "DataTable")
        mi = one("MasterItemList", "CompositeDataTable")
        rep["itemlist"] = "0x%x" % il if il else None
        rep["master_item_list"] = "0x%x" % mi if mi else None

        def rows_named(t):
            raw, _ = rdr.read_rowmap(api, h, t)
            names = set()
            for eid, num, ptr in raw:
                try:
                    x = eri.decode_fname_entry_id(api, h, np, eid).get("text")
                except Exception:  # noqa: BLE001
                    x = None
                if x:
                    names.add(x)
            return len(raw), names

        if il and mi:
            il_n, il_names = rows_named(il)
            mi_n, mi_names = rows_named(mi)
            pt = mi + 176
            data = eri._read_u64(api, h, pt)
            num = struct.unpack("<i", api.read_process_memory(h, pt + 8, 4))[0]
            mx = struct.unpack("<i", api.read_process_memory(h, pt + 12, 4))[0]
            slots = [eri._read_u64(api, h, data + i * 8) for i in range(num)] if data else []
            rep["registry_baseline"] = {
                "itemlist_rows": il_n, "master_rows": mi_n,
                "master_equals_itemlist": mi_n == il_n,
                "row_absent_from_itemlist": ROW not in il_names,
                "row_absent_from_master": ROW not in mi_names,
                "ParentTables": {"num": num, "max": mx,
                                 "slots": ["0x%x" % s for s in slots],
                                 "single_vanilla_parent": num == 1 and slots == [il]},
                "holds": (mi_n == il_n and ROW not in il_names and ROW not in mi_names
                          and num == 1 and slots == [il])}

        # nothing in the fresh session carries the name at all
        hits = [a for a, r in objs.items() if r.get("name_ok") and r.get("name_text") == ROW]
        rep["objects_named_row_in_fresh_process"] = len(hits)
        tex = [a for a, r in objs.items() if r.get("name_ok")
               and r.get("name_text") == "T_MBPL_Radio_Icon"]
        rep["mod_texture_loaded_in_fresh_process"] = len(tex)
    finally:
        api.close_handle(h)

    # the Steam install must be untouched
    rdir = os.path.join(REPO, "research", "instrument-runs",
                        "_c4b-close-verify")
    os.makedirs(rdir, exist_ok=True)
    vi = ipp.run_verify_install(rdir, "close")
    rep["verify_install"] = {kk: vi.get(kk) for kk in
                             ("result", "mode", "strict", "serious_count", "benign_count",
                              "baseline_build_key", "report_artifact")}

    # no save file may reference the runtime row
    needles = [ROW.encode("ascii"), ROW.encode("utf-16-le")]
    scanned, carriers = [], []
    seen = set()
    for d in SAVE_DIRS:
        if not os.path.isdir(d):
            continue
        for p in glob.glob(os.path.join(d, "**", "*"), recursive=True):
            if not os.path.isfile(p) or p in seen:
                continue
            if os.path.commonpath([os.path.abspath(p), os.path.abspath(PAK_DIR)]) == \
                    os.path.abspath(PAK_DIR):
                continue          # our own mod container, not a save
            seen.add(p)
            try:
                blob = open(p, "rb").read()
            except Exception:  # noqa: BLE001
                continue
            scanned.append({"file": p, "bytes": len(blob),
                            "mtime": int(os.path.getmtime(p))})
            if any(n in blob for n in needles):
                carriers.append(p)
    rep["save_scan"] = {"files_scanned": len(scanned),
                        "files_carrying_row_name": carriers,
                        "holds": not carriers,
                        "note": "ASCII and UTF-16LE forms of the row name were both searched; "
                                "the mod container directory is excluded because it is our own "
                                "content, not a save"}
    rep["save_files"] = sorted(scanned, key=lambda x: -x["mtime"])[:12]

    rep["all_checks_hold"] = bool(
        rep["demo_process_terminated"] and rep["build_fingerprint_matches"]
        and rep["no_probe_module_loaded"]
        and rep.get("registry_baseline", {}).get("holds")
        and rep["objects_named_row_in_fresh_process"] == 0
        and rep["verify_install"]["result"] == "match"
        and rep["save_scan"]["holds"])

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "postrun.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=True, default=str)
        f.write("\n")
    print(json.dumps(rep, indent=2, sort_keys=True, default=str))
    return 0 if rep["all_checks_hold"] else 1


if __name__ == "__main__":
    sys.exit(main())
