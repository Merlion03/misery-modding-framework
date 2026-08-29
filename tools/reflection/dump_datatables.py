#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Enumerate every live UDataTable AND UCompositeDataTable,
with RowStruct, row count, and -- for composites -- the ParentTables array.

CR-01B's registry census filtered on class name == "DataTable" exactly and so
could not see a UCompositeDataTable at all. That blind spot matters: the
inventory definition resolver reaches a composite, and UCompositeDataTable
overrides AddRow/RemoveRow to do NOTHING (CompositeDataTable.cpp:191-199), so
"which class is this table really" decides whether the proven registration
primitive applies to it at all.

Opens the process PROCESS_QUERY_INFORMATION | PROCESS_VM_READ only.
"""
import argparse
import json
import os
import struct
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO, "tools", "reflection"))
import eri  # noqa: E402
import read_datatable_rows as rdr  # noqa: E402

TABLE_CLASSES = ("DataTable", "CompositeDataTable")


def find_property_offset(api, h, np, cls_addr, want_name, objs):
    """Reflected offset of a named property on a UClass (never assumed)."""
    cp = eri._read_u64(api, h, cls_addr + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
    props = eri.walk_property_chain(api, h, cp, namepool_live_va=np, owner_address=cls_addr,
                                    objects_by_address=objs)
    for pr in props.get("accepted", []):
        if pr.get("raw_name") == want_name:
            return pr.get("offset"), pr.get("property_class"), pr.get("size")
    return None, None, None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)

    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    base, size = i01["base_address"], i01["image_size_bytes"]
    h = eri.open_process_read_only(api, i01["pid"])
    try:
        i02 = eri.run_i02(api, h, base, size, guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                          sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                          max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
        i03 = eri.run_i03(api, h, base, size, namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
                          name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
                          name_entry_id=0)
        np = i03["namepool_live_va"]
        w = eri.walk_object_universe(api, h, i02["objects_ptr_live_va"], i02["num_elements"],
                                     base, size, np,
                                     class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,
                                     name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
                                     outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,
                                     max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
        objs = w["objects_by_address"]

        # locate the UCompositeDataTable UClass so ParentTables can be reflected
        comp_cls = None
        for addr, r in objs.items():
            if r.get("name_ok") and r.get("name_text") == "CompositeDataTable":
                cn = (objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
                if cn == "Class":
                    comp_cls = addr
                    break
        parent_off = parent_cls = None
        if comp_cls:
            parent_off, parent_cls, _ = find_property_offset(
                api, h, np, comp_cls, "ParentTables", objs)

        tables = []
        for addr, r in objs.items():
            if not r.get("name_ok"):
                continue
            cn = (objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
            if cn not in TABLE_CLASSES:
                continue
            nm = r.get("name_text") or ""
            if nm.startswith("Default__"):
                continue
            rs = eri._read_u64(api, h, addr + rdr.OFF_ROWSTRUCT)
            rs_name = (objs.get(rs) or {}).get("name_text")
            try:
                rows, diag = rdr.read_rowmap(api, h, addr)
                nrows = len(rows)
            except Exception as exc:  # noqa: BLE001
                rows, nrows, diag = [], None, {"error": str(exc)}
            entry = {
                "name": nm, "class": cn, "address": "0x%x" % addr,
                "object_path": eri.resolve_object_path(addr, objs).get("object_path"),
                "row_struct": rs_name, "row_struct_address": "0x%x" % rs,
                "row_count": nrows,
                "vtable": "0x%x" % eri._read_u64(api, h, addr),
            }
            if cn == "CompositeDataTable" and parent_off is not None:
                pdata = eri._read_u64(api, h, addr + parent_off)
                pnum = struct.unpack("<i", api.read_process_memory(
                    h, addr + parent_off + 8, 4))[0]
                parents = []
                if pdata and 0 < pnum < 4096:
                    raw = api.read_process_memory(h, pdata, pnum * 8)
                    for i in range(pnum):
                        p = struct.unpack_from("<Q", raw, i * 8)[0]
                        prec = objs.get(p) or {}
                        parents.append({
                            "index": i, "address": "0x%x" % p,
                            "name": prec.get("name_text"),
                            "class": (objs.get(prec.get("class_ptr") or 0) or {}).get("name_text"),
                            "object_path": eri.resolve_object_path(p, objs).get("object_path")
                            if p in objs else None,
                        })
                entry["parent_tables_offset"] = parent_off
                entry["parent_tables_property_class"] = parent_cls
                entry["parent_table_count"] = pnum
                entry["parent_tables"] = parents
            tables.append(entry)

        tables.sort(key=lambda t: (t["class"], t["name"]))
        result = {"pid": i01["pid"],
                  "composite_class_address": "0x%x" % comp_cls if comp_cls else None,
                  "parent_tables_reflected_offset": parent_off,
                  "table_count": len(tables), "tables": tables}
        out = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)
        if a.out:
            os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
            with open(a.out, "w", encoding="utf-8", newline="\n") as f:
                f.write(out + "\n")
        for t in tables:
            print("%-20s %-20s rows=%-6s struct=%-16s %s" % (
                t["class"], t["name"], t["row_count"], t["row_struct"],
                ("parents=%d" % t.get("parent_table_count", 0)) if t["class"] == "CompositeDataTable" else ""))
        return 0
    finally:
        api.close_handle(h)


if __name__ == "__main__":
    raise SystemExit(main())
