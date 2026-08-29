#!/usr/bin/env python3
"""STRICTLY READ-ONLY. CR-01C4B follow-up: why does the vanilla icon move on
selection and ours does not?

Nothing is written to the target. The process is opened
PROCESS_QUERY_INFORMATION | PROCESS_VM_READ through ERI's single call site.

Method, in the order the answer has to be built:
  1. Enumerate every reflected member of S_UIDetails and record each member's
     FProperty address -- the address, not the name, is what identifies it in
     bytecode.
  2. For every live UFunction, read UStruct::Script (0x60) and scan it for those
     FProperty pointers. A property a widget reads is embedded as a literal
     FProperty* by EX_StructMemberContext / EX_*Property opcodes, so this finds
     the actual consumers rather than the plausibly-named ones.
  3. Enumerate BP_InventoryItemIcon_C's own functions and, for each, resolve
     ScriptAndPropertyObjectReferences and the FName call targets in its
     bytecode, so SetBrush / SetRenderTranslation / SetDesiredSize style calls
     are visible by name.
  4. Read the vanilla row and our materialized row side by side over the whole
     64-byte UIDetails block plus the scalars a widget could plausibly use.
"""
import argparse
import json
import os
import struct
import sys

REPO = "D:/Dev/MiseryFramework"
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "ipp"))
sys.path.insert(0, os.path.join(REPO, "tools", "reflection"))
import eri  # noqa: E402
import cr01c3_recon as recon  # noqa: E402
import read_datatable_rows as rdr  # noqa: E402

SCRIPT = 0x60
SPOR = 0x90
CHILD_PROPERTIES = eri.USTRUCT_CHILD_PROPERTIES_OFFSET
NAME_CALL = {0x1B: "EX_VirtualFunction", 0x45: "EX_LocalVirtualFunction"}
PTR_CALL = {0x1C: "EX_FinalFunction", 0x46: "EX_LocalFinalFunction"}


def tarray(api, h, addr, elem=1, cap=1 << 22):
    data = eri._read_u64(api, h, addr)
    num = struct.unpack("<i", api.read_process_memory(h, addr + 8, 4))[0]
    if not data or num <= 0 or num > cap:
        return b""
    return api.read_process_memory(h, data, num * elem) or b""


def members(api, h, np, struct_addr, objs):
    cp = eri._read_u64(api, h, struct_addr + CHILD_PROPERTIES)
    out = []
    for pr in eri.walk_property_chain(api, h, cp, namepool_live_va=np,
                                      owner_address=struct_addr,
                                      objects_by_address=objs).get("accepted", []):
        rec = {"name": (pr.get("raw_name") or "").split("_")[0],
               "raw_name": pr.get("raw_name"),
               "fproperty": int(pr["address_hex"], 16),
               "offset": pr.get("offset"), "size": pr.get("size"),
               "class": pr.get("property_class")}
        if pr.get("property_class") in ("FObjectProperty", "FClassProperty",
                                        "FSoftObjectProperty"):
            pc = eri._read_u64(api, h, rec["fproperty"] + 0x70)
            rec["property_class_of"] = (objs.get(pc) or {}).get("name_text")
        if pr.get("property_class") == "FStructProperty":
            sp = eri._read_u64(api, h, rec["fproperty"] + 0x70)
            rec["struct"] = (objs.get(sp) or {}).get("name_text")
            rec["struct_addr"] = sp
        out.append(rec)
    return out


def scan_functions_for(api, h, objs, fmeta, wanted):
    """wanted: {pointer -> label}. Returns {label -> [function descriptions]}."""
    hits = {v: [] for v in wanted.values()}
    scanned = 0
    for a, r in objs.items():
        if r.get("class_ptr") != fmeta or not r.get("name_ok"):
            continue
        scanned += 1
        try:
            code = tarray(api, h, a + SCRIPT)
        except Exception:  # noqa: BLE001
            continue
        if not code:
            continue
        n = len(code)
        for off in range(0, n - 7):
            p = struct.unpack_from("<Q", code, off)[0]
            lab = wanted.get(p)
            if lab is None:
                continue
            owner = eri._read_u64(api, h, a + eri.DEFAULT_OUTER_PRIVATE_OFFSET)
            hits[lab].append({"function": r.get("name_text"),
                              "owner": (objs.get(owner) or {}).get("name_text"),
                              "address": "0x%x" % a, "at_bytecode_offset": off,
                              "script_len": n})
    return hits, scanned


def call_targets(api, h, np, faddr, objs):
    """FName-dispatched and pointer-dispatched call targets inside one function."""
    code = tarray(api, h, faddr + SCRIPT)
    names, ptrs = [], []
    n = len(code)
    for off in range(0, n - 8):
        op = code[off]
        if op in NAME_CALL:
            fid = struct.unpack_from("<I", code, off + 1)[0]
            num = struct.unpack_from("<I", code, off + 5)[0]
            try:
                nm = eri.decode_fname_entry_id(api, h, np, fid).get("text")
            except Exception:  # noqa: BLE001
                nm = None
            if nm and nm.isprintable() and len(nm) > 2:
                names.append({"op": NAME_CALL[op], "name": nm, "number": num, "offset": off})
        elif op in PTR_CALL:
            tgt = struct.unpack_from("<Q", code, off + 1)[0]
            rec = objs.get(tgt)
            if rec and rec.get("name_ok"):
                owner = eri._read_u64(api, h, tgt + eri.DEFAULT_OUTER_PRIVATE_OFFSET)
                ptrs.append({"op": PTR_CALL[op], "name": rec.get("name_text"),
                             "owner": (objs.get(owner) or {}).get("name_text"),
                             "offset": off})
    return {"script_len": n, "name_calls": names, "ptr_calls": ptrs}


def spor(api, h, faddr, objs):
    raw = tarray(api, h, faddr + SPOR, elem=8, cap=4096)
    out = []
    for i in range(0, len(raw), 8):
        p = struct.unpack_from("<Q", raw, i)[0]
        rec = objs.get(p)
        if rec and rec.get("name_ok"):
            out.append({"name": rec.get("name_text"),
                        "class": (objs.get(rec.get("class_ptr") or 0) or {}).get("name_text")})
        elif p:
            out.append({"raw": "0x%x" % p})
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=None)
    ap.add_argument("--widget", default="BP_InventoryItemIcon_C")
    ap.add_argument("--row", default="mbpl__radio")
    a = ap.parse_args(argv)

    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    h = eri.open_process_read_only(api, i01["pid"])
    rep = {"pid": i01["pid"], "widget_class": a.widget}
    try:
        np, objs = recon.universe(api, h, i01["base_address"], i01["image_size_bytes"])
        fmeta = recon.find_function_meta(objs)

        def one(nm, clsname):
            c = [x for x, r in objs.items() if r.get("name_ok") and r.get("name_text") == nm
                 and (objs.get(r.get("class_ptr") or 0) or {}).get("name_text") == clsname]
            return c[0] if len(c) == 1 else None

        ui = one("S_UIDetails", "UserDefinedStruct")
        it = one("S_ItemDetails", "UserDefinedStruct")
        so = one("S_SizeOverride", "UserDefinedStruct")
        rep["structs"] = {"S_UIDetails": "0x%x" % ui, "S_ItemDetails": "0x%x" % it,
                          "S_SizeOverride": "0x%x" % so}

        ui_m = members(api, h, np, ui, objs)
        it_m = members(api, h, np, it, objs)
        so_m = members(api, h, np, so, objs)
        rep["S_UIDetails_members"] = [{k: v for k, v in m.items() if k != "struct_addr"}
                                      for m in ui_m]
        rep["S_SizeOverride_members"] = [{k: v for k, v in m.items() if k != "struct_addr"}
                                         for m in so_m]

        # --- who actually reads each S_UIDetails member? ---------------------
        wanted = {m["fproperty"]: "S_UIDetails." + m["name"] for m in ui_m}
        for m in so_m:
            wanted[m["fproperty"]] = "S_SizeOverride." + m["name"]
        for m in it_m:
            if m["name"] in ("ItemOffsets", "IconBackroundColor", "Width", "Height", "UIDetails"):
                wanted[m["fproperty"]] = "S_ItemDetails." + m["name"]
        hits, scanned = scan_functions_for(api, h, objs, fmeta, wanted)
        rep["functions_scanned"] = scanned
        rep["consumers"] = {k: v for k, v in sorted(hits.items())}

        # --- the widget class itself ----------------------------------------
        wcls = one(a.widget, "BlueprintGeneratedClass")
        rep["widget_found"] = wcls is not None
        if wcls:
            fns = recon.class_functions(api, h, np, wcls, fmeta)
            rep["widget_functions"] = []
            for f in fns:
                d = {"name": f.get("raw_name"), "address": "0x%x" % f["address"]}
                d.update(call_targets(api, h, np, f["address"], objs))
                d["object_refs"] = spor(api, h, f["address"], objs)
                rep["widget_functions"].append(d)
            wp = members(api, h, np, wcls, objs)
            rep["widget_properties"] = [{k: v for k, v in m.items() if k != "struct_addr"}
                                        for m in wp]

        # --- vanilla row vs our row -----------------------------------------
        il = one("ItemList", "DataTable")
        rows, _ = rdr.read_rowmap(api, h, il)
        by_name = {}
        for r0 in rows:
            by_name[r0[0]] = r0[2]
        ours = None
        mi = one("MasterItemList", "CompositeDataTable")
        mrows, _ = rdr.read_rowmap(api, h, mi)
        for r0 in mrows:
            if r0[0] == a.row:
                ours = r0[2]
        rep["our_row_found"] = ours is not None
        ui_off = [m for m in it_m if m["name"] == "UIDetails"][0]["offset"]

        def read_ui(rowptr):
            blob = api.read_process_memory(h, rowptr + ui_off, 64)
            out = {}
            for m in ui_m:
                if m["class"] == "FObjectProperty":
                    p = struct.unpack_from("<Q", blob, m["offset"])[0]
                    rec = objs.get(p)
                    out[m["name"]] = None if not p else {
                        "ptr": "0x%x" % p, "name": (rec or {}).get("name_text"),
                        "path": eri.canonicalize_object_path(
                            eri.resolve_object_path(p, objs).get("object_path")) if rec else None}
                elif m["name"] == "MoveIconSizeOverride":
                    out[m["name"]] = {
                        "OverrideImageSize": blob[m["offset"] + 0],
                        "SizeY": struct.unpack_from("<i", blob, m["offset"] + 4)[0],
                        "SizeX": struct.unpack_from("<i", blob, m["offset"] + 8)[0]}
            out["_raw"] = blob.hex()
            return out

        def read_scalars(rowptr):
            out = {}
            for m in it_m:
                if m["name"] in ("Width", "Height"):
                    out[m["name"]] = struct.unpack_from(
                        "<i", api.read_process_memory(h, rowptr + m["offset"], 4), 0)[0]
                if m["name"] == "IconBackroundColor":
                    out[m["name"]] = list(struct.unpack(
                        "<4f", api.read_process_memory(h, rowptr + m["offset"], 16)))
                if m["name"] == "ItemOffsets":
                    out[m["name"]] = api.read_process_memory(h, rowptr + m["offset"], 96).hex()
            return out

        rep["rows"] = {}
        if ours:
            rep["rows"][a.row] = {"ui": read_ui(ours), "scalars": read_scalars(ours)}
        # a handful of normal 1x1 vanilla items for comparison
        picked = 0
        rep["vanilla_1x1_sample"] = {}
        wo = [m for m in it_m if m["name"] == "Width"][0]["offset"]
        ho = [m for m in it_m if m["name"] == "Height"][0]["offset"]
        stats = {"total": 0, "with_moveicon": 0, "moveicon_eq_inventoryicon": 0,
                 "override_on": 0, "moveicon_null": 0}
        mi_off = [m for m in ui_m if m["name"] == "MoveIcon"][0]["offset"]
        ii_off = [m for m in ui_m if m["name"] == "InventoryIcon"][0]["offset"]
        ov_off = [m for m in ui_m if m["name"] == "MoveIconSizeOverride"][0]["offset"]
        for nm, ptr in sorted(by_name.items()):
            blob = api.read_process_memory(h, ptr + ui_off, 64)
            iic = struct.unpack_from("<Q", blob, ii_off)[0]
            mic = struct.unpack_from("<Q", blob, mi_off)[0]
            stats["total"] += 1
            if mic:
                stats["with_moveicon"] += 1
                if mic == iic:
                    stats["moveicon_eq_inventoryicon"] += 1
            else:
                stats["moveicon_null"] += 1
            if blob[ov_off]:
                stats["override_on"] += 1
            w = struct.unpack_from("<i", api.read_process_memory(h, ptr + wo, 4), 0)[0]
            hgt = struct.unpack_from("<i", api.read_process_memory(h, ptr + ho, 4), 0)[0]
            if w == 1 and hgt == 1 and iic and picked < 6:
                rep["vanilla_1x1_sample"][nm] = {"ui": read_ui(ptr),
                                                 "scalars": read_scalars(ptr)}
                picked += 1
        rep["vanilla_moveicon_stats"] = stats
    finally:
        api.close_handle(h)

    txt = json.dumps(rep, indent=2, sort_keys=True, default=str)
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(txt + "\n")
        print("wrote", a.out, len(txt), "bytes")
    else:
        print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
