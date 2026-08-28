#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Walk a live UDataTable's RowMap and read named fields of a
named row -- the P-04 content-depth gate.

No code executes in the target: this only reads memory through ERI's single
read-only open call site. Layout used (all proven, none guessed):

  UDataTable::RowStruct  @ +40   -- OBSERVED via reflection (FProperty offset)
  UDataTable::RowMap     @ +48   -- DERIVED: RowMap is declared immediately after
                                    RowStruct (DataTable.h:85,89) and is NOT a
                                    UPROPERTY; sizeof(TObjectPtr)==8 (measured)
  TMap == TSet == TSparseArray at +0 (each has the next as its first member)
  TSparseArray: Data(TArray)@0, AllocationFlags(TBitArray)@16,
                FirstFreeIndex@48, NumFreeIndices@52      (sizes sum to 56)
  TArray:       Data@0, ArrayNum@8, ArrayMax@12           (sizes sum to 16)
  TBitArray:    inline words@0 (16B), secondary ptr@16, NumBits@24, MaxBits@28
  element:      stride 24, key FName@0, value uint8*@8

Every size above was measured from genuine UE 5.4.4 headers with MSVC 14.38, and
the traversal algorithm was validated host-side against a real UE TMap across
empty / single / many / sparse-hole / free-slot-reuse / secondary-storage cases.
"""
import argparse
import json
import os
import struct
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))
import eri  # noqa: E402

OFF_ROWSTRUCT = 40
OFF_ROWMAP = 48
SPARSE_DATA, ARR_PTR, ARR_NUM = 0, 0, 8
SPARSE_ALLOCFLAGS = 16
BITS_INLINE, BITS_SECONDARY, BITS_NUMBITS = 0, 16, 24
ELEM_STRIDE, ELEM_KEY, ELEM_VALUE = 24, 0, 8


def read_rowmap(api, handle, table_addr):
    """Return (rows, diag). rows = [(fname_id, fname_num, value_ptr)]."""
    m = table_addr + OFF_ROWMAP
    data_ptr = eri._read_u64(api, handle, m + SPARSE_DATA + ARR_PTR)
    array_num = struct.unpack("<i", api.read_process_memory(
        handle, m + SPARSE_DATA + ARR_NUM, 4))[0]
    bits = m + SPARSE_ALLOCFLAGS
    num_bits = struct.unpack("<i", api.read_process_memory(handle, bits + BITS_NUMBITS, 4))[0]
    diag = {"data_ptr_hex": "0x%x" % data_ptr, "array_num": array_num, "num_bits": num_bits}
    rows = []
    if not data_ptr or array_num <= 0:
        return rows, diag
    if num_bits > 4 * 32:
        words_base = eri._read_u64(api, handle, bits + BITS_SECONDARY)
        diag["bit_storage"] = "secondary"
    else:
        words_base = bits + BITS_INLINE
        diag["bit_storage"] = "inline"
    nwords = (max(num_bits, 0) + 31) // 32
    words = []
    if nwords:
        raw = api.read_process_memory(handle, words_base, nwords * 4)
        words = list(struct.unpack("<%dI" % nwords, raw))
    blob = api.read_process_memory(handle, data_ptr, array_num * ELEM_STRIDE)
    for i in range(array_num):
        if i >= num_bits:
            continue
        if not ((words[i >> 5] >> (i & 31)) & 1):
            continue  # unallocated sparse slot
        e = i * ELEM_STRIDE
        cmp_index, number = struct.unpack_from("<II", blob, e + ELEM_KEY)
        value_ptr = struct.unpack_from("<Q", blob, e + ELEM_VALUE)[0]
        rows.append((cmp_index, number, value_ptr))
    diag["allocated_rows"] = len(rows)
    return rows, diag


def struct_fields(api, handle, np, struct_addr):
    """Exact field offsets of a UScriptStruct, from live reflection."""
    cp = eri._read_u64(api, handle, struct_addr + eri.USTRUCT_CHILD_PROPERTIES_OFFSET)
    props = eri.walk_property_chain(api, handle, cp, namepool_live_va=np,
                                    owner_address=struct_addr)
    out = {}
    for p in props.get("accepted", []):
        out[p.get("raw_name")] = {"offset": p.get("offset"), "size": p.get("size"),
                                  "property_class": p.get("property_class")}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--object-path", default="/Game/ModKit/MK_Canary.MK_Canary")
    ap.add_argument("--address", default=None,
                    help="hex address of the UDataTable; skips the full GUObjectArray walk "
                         "(the object is unreferenced and GC-collectable, so the fast path "
                         "avoids racing a collection)")
    ap.add_argument("--row", default="CT05Row")
    ap.add_argument("--missing-row", default="CT05_NO_SUCH_ROW")
    ap.add_argument("--out", default=None)
    ap.add_argument("--process-name", default=eri.DEFAULT_PROCESS_NAME)
    args = ap.parse_args(argv)

    api = eri.Win32Api()
    i01 = eri.run_i01(api, args.process_name)
    handle = eri.open_process_read_only(api, i01["pid"])
    try:
        base, size = i01["base_address"], i01["image_size_bytes"]
        i02 = eri.run_i02(api, handle, base, size, guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,
                          sample_size=eri.DEFAULT_I02_SAMPLE_SIZE, poll_interval_seconds=0,
                          max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
        i03 = eri.run_i03(api, handle, base, size, namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
                          name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
                          name_entry_id=0)
        np = i03["namepool_live_va"]

        def obj_name(addr):
            """Decode one UObject's NamePrivate without walking the universe."""
            ci, nu = struct.unpack("<II", api.read_process_memory(
                handle, addr + eri.DEFAULT_NAME_PRIVATE_OFFSET, 8))
            t = eri.decode_fname_entry_id(api, handle, np, ci).get("text")
            return "%s_%d" % (t, nu - 1) if nu else t

        if args.address:
            table = int(args.address, 16)
            cls_ptr = eri._read_u64(api, handle, table + eri.DEFAULT_CLASS_PRIVATE_OFFSET)
            rs_ptr = eri._read_u64(api, handle, table + OFF_ROWSTRUCT)
            result = {"object_path": None, "address_hex": "0x%x" % table,
                      "object_name": obj_name(table),
                      "class_name": obj_name(cls_ptr) if cls_ptr else None,
                      "rowstruct_name": obj_name(rs_ptr) if rs_ptr else None,
                      "rowstruct_ptr_hex": "0x%x" % rs_ptr,
                      "fast_path": True}
            rows, diag = read_rowmap(api, handle, table)
            result["rowmap"] = diag
            fields = struct_fields(api, handle, np, rs_ptr) if rs_ptr else {}
            result["rowstruct_fields"] = fields
            decoded = []
            for cmp_index, number, vptr in rows:
                t = eri.decode_fname_entry_id(api, handle, np, cmp_index).get("text")
                nm = "%s_%d" % (t, number - 1) if number else t
                entry = {"row_name": nm, "value_ptr_hex": "0x%x" % vptr, "fields": {}}
                for fn, meta in fields.items():
                    off, sz, pc = meta["offset"], meta["size"], meta["property_class"]
                    if off is None or not vptr:
                        continue
                    raw = api.read_process_memory(handle, vptr + off, sz)
                    if pc == "FNameProperty" and sz >= 8:
                        ci2, nu2 = struct.unpack("<II", raw[:8])
                        t2 = eri.decode_fname_entry_id(api, handle, np, ci2).get("text")
                        entry["fields"][fn] = "%s_%d" % (t2, nu2 - 1) if nu2 else t2
                    elif pc in ("FByteProperty", "FEnumProperty") and sz >= 1:
                        entry["fields"][fn] = raw[0]
                    else:
                        entry["fields"][fn] = raw.hex()
                decoded.append(entry)
            result["rows"] = decoded
            result["row_names"] = [r["row_name"] for r in decoded]
            result["target_row_found"] = args.row in result["row_names"]
            result["missing_row_found"] = args.missing_row in result["row_names"]
            print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
            if args.out:
                os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
                with open(args.out, "w", encoding="utf-8", newline="\n") as f:
                    json.dump(result, f, indent=2, sort_keys=True, ensure_ascii=False)
                    f.write("\n")
            return 0 if result["target_row_found"] and not result["missing_row_found"] else 3

        walk = eri.walk_object_universe(api, handle, i02["objects_ptr_live_va"],
                                        i02["num_elements"], base, size, np,
                                        class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,
                                        name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
                                        outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,
                                        max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
        objs = walk["objects_by_address"]
        want = eri.canonicalize_object_path(args.object_path)
        table = None
        for a, r in objs.items():
            if r.get("name_ok") and r.get("name_text") == want.rsplit(".", 1)[-1]:
                if eri.canonicalize_object_path(
                        eri.resolve_object_path(a, objs).get("object_path")) == want:
                    cls = objs.get(r.get("class_ptr") or 0) or {}
                    if cls.get("name_text") == "DataTable":
                        table = a
                        break
        if table is None:
            print("BLOCKED: %s not found as a live DataTable" % args.object_path, file=sys.stderr)
            return 2

        rec = objs[table]
        cls_rec = objs.get(rec.get("class_ptr") or 0) or {}
        rs_ptr = eri._read_u64(api, handle, table + OFF_ROWSTRUCT)
        rs_rec = objs.get(rs_ptr) or {}
        result = {
            "object_path": eri.resolve_object_path(table, objs).get("object_path"),
            "address_hex": "0x%x" % table,
            "class_name": cls_rec.get("name_text"),
            "rowstruct_name": rs_rec.get("name_text"),
            "rowstruct_ptr_hex": "0x%x" % rs_ptr,
        }
        rows, diag = read_rowmap(api, handle, table)
        result["rowmap"] = diag
        fields = struct_fields(api, handle, np, rs_ptr) if rs_ptr else {}
        result["rowstruct_fields"] = fields

        decoded = []
        for cmp_index, number, vptr in rows:
            d = eri.decode_fname_entry_id(api, handle, np, cmp_index)
            name = d.get("text")
            if number:
                name = "%s_%d" % (name, number - 1)
            entry = {"row_name": name, "value_ptr_hex": "0x%x" % vptr, "fields": {}}
            for fname, meta in fields.items():
                off, sz, pc = meta["offset"], meta["size"], meta["property_class"]
                if off is None or not vptr:
                    continue
                raw = api.read_process_memory(handle, vptr + off, sz)
                if pc == "FNameProperty" and sz >= 8:
                    ci, nu = struct.unpack("<II", raw[:8])
                    dd = eri.decode_fname_entry_id(api, handle, np, ci)
                    txt = dd.get("text")
                    if nu:
                        txt = "%s_%d" % (txt, nu - 1)
                    entry["fields"][fname] = txt
                elif pc in ("FByteProperty", "FEnumProperty") and sz >= 1:
                    entry["fields"][fname] = raw[0]
                else:
                    entry["fields"][fname] = raw.hex()
            decoded.append(entry)
        result["rows"] = decoded
        result["row_names"] = [r["row_name"] for r in decoded]
        result["target_row_found"] = args.row in result["row_names"]
        result["missing_row_found"] = args.missing_row in result["row_names"]

        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            with open(args.out, "w", encoding="utf-8", newline="\n") as f:
                json.dump(result, f, indent=2, sort_keys=True, ensure_ascii=False)
                f.write("\n")
        return 0 if result["target_row_found"] and not result["missing_row_found"] else 3
    finally:
        api.close_handle(handle)


if __name__ == "__main__":
    raise SystemExit(main())
