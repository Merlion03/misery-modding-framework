#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Search the live FName pool for exact name strings and
report each match's FNameEntryId (the value an FName's ComparisonIndex holds).

Enumerates FNamePool blocks with ERI's own live-verified addressing
(NAMEPOOL_OFFSET_BLOCKS, FNAME_BLOCK_OFFSET_BITS, FNAME_ENTRY_STRIDE,
FNAME_ENTRY_HEADER_SIZE_BYTES and the FNameEntryHeader bit layout), decoding each
entry exactly the way decode_fname_entry_id() does. Opens the process read-only
(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ) through ERI's single open call site
and writes nothing.

A hit proves the name is ALREADY INTERNED in the running process -- which is what
makes a POD FName value constructible without calling any engine function.
"""
import argparse
import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))
import eri  # noqa: E402

# FNameEntryAllocator layout (see eri.NAMEPOOL_OFFSET_BLOCKS' own derivation):
#   +0x00 FRWLock Lock (8B)
#   +0x08 uint32 CurrentBlock
#   +0x0C uint32 CurrentByteCursor
#   +0x10 Blocks[]
OFF_CURRENT_BLOCK = 0x08
OFF_CURRENT_BYTE_CURSOR = 0x0C
# Offset within a block is a 16-bit field scaled by Stride(2) => 128 KiB max.
BLOCK_LIMIT_BYTES = (1 << eri.FNAME_BLOCK_OFFSET_BITS) * eri.FNAME_ENTRY_STRIDE


def enumerate_block(api, handle, block_base, limit_bytes, block_index, wanted, hits):
    pos = 0
    entries = 0
    while pos + eri.FNAME_ENTRY_HEADER_SIZE_BYTES <= limit_bytes:
        try:
            header = eri._read_u16(api, handle, block_base + pos)
        except Exception:  # noqa: BLE001
            break
        is_wide = bool(header & eri.FNAME_HEADER_IS_WIDE_MASK)
        length = (header >> eri.FNAME_HEADER_LEN_SHIFT) & eri.FNAME_HEADER_LEN_MASK
        if length == 0:
            # A zero-length header is how an unused tail reads; stop this block.
            break
        byte_len = length * (2 if is_wide else 1)
        if pos + eri.FNAME_ENTRY_HEADER_SIZE_BYTES + byte_len > limit_bytes:
            break
        try:
            raw = api.read_process_memory(
                handle, block_base + pos + eri.FNAME_ENTRY_HEADER_SIZE_BYTES, byte_len)
            text = raw.decode("utf-16-le") if is_wide else raw.decode("ascii")
        except Exception:  # noqa: BLE001
            text = None
        entries += 1
        if text is not None and text in wanted:
            entry_id = (block_index << eri.FNAME_BLOCK_OFFSET_BITS) + (pos // eri.FNAME_ENTRY_STRIDE)
            hits.setdefault(text, []).append({
                "text": text,
                "entry_id": entry_id,
                "entry_id_hex": "0x%x" % entry_id,
                "block": block_index,
                "offset_units": pos // eri.FNAME_ENTRY_STRIDE,
                "is_wide": is_wide,
                "length": length,
                "entry_ptr_hex": "0x%x" % (block_base + pos),
            })
        size = eri.FNAME_ENTRY_HEADER_SIZE_BYTES + byte_len
        # entries are stride-aligned
        size = (size + eri.FNAME_ENTRY_STRIDE - 1) & ~(eri.FNAME_ENTRY_STRIDE - 1)
        pos += size
    return entries


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("name", nargs="+", help="exact name string(s) to find")
    p.add_argument("--out", default=None)
    p.add_argument("--process-name", default=eri.DEFAULT_PROCESS_NAME)
    args = p.parse_args(argv)
    wanted = set(args.name)

    api = eri.Win32Api()
    i01 = eri.run_i01(api, args.process_name)
    handle = eri.open_process_read_only(api, i01["pid"])
    try:
        i03 = eri.run_i03(
            api, handle, i01["base_address"], i01["image_size_bytes"],
            namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,
            name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
            name_entry_id=0)
        pool = i03["namepool_live_va"]
        current_block = eri._read_u32(api, handle, pool + OFF_CURRENT_BLOCK)
        current_cursor = eri._read_u32(api, handle, pool + OFF_CURRENT_BYTE_CURSOR)

        hits = {}
        total_entries = 0
        blocks_scanned = 0
        for b in range(current_block + 1):
            try:
                block_base = eri._read_u64(
                    api, handle, pool + eri.NAMEPOOL_OFFSET_BLOCKS + b * 8)
            except Exception:  # noqa: BLE001
                continue
            if not block_base:
                continue
            limit = current_cursor if b == current_block else BLOCK_LIMIT_BYTES
            total_entries += enumerate_block(api, handle, block_base, limit, b, wanted, hits)
            blocks_scanned += 1

        result = {
            "pid": i01["pid"],
            "namepool_live_va": "0x%x" % pool,
            "current_block": current_block,
            "current_byte_cursor": current_cursor,
            "blocks_scanned": blocks_scanned,
            "entries_enumerated": total_entries,
            "queried": sorted(wanted),
            "found": {n: hits.get(n, []) for n in sorted(wanted)},
            "all_found": all(hits.get(n) for n in wanted),
        }
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            with open(args.out, "w", encoding="utf-8", newline="\n") as f:
                json.dump(result, f, indent=2, sort_keys=True, ensure_ascii=False)
                f.write("\n")
        return 0 if result["all_found"] else 3
    finally:
        api.close_handle(handle)


if __name__ == "__main__":
    raise SystemExit(main())
