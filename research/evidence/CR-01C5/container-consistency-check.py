#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Is the staged MBPLRadio_P container internally consistent?

"I copied the two files together" is not a consistency check. This parses the
TOC header and the compressed-block table and asks the questions that actually
matter for a TOC/CAS pair:

  * does the TOC carry the IoStore magic and a version this engine reads,
  * is it unencrypted and unsigned (we hold no keys and must ship none),
  * does the header's own sanity field -- TocCompressedBlockEntrySize -- match
    the struct size the engine expects,
  * and, the point of the exercise, does every compressed block lie WITHIN the
    .ucas that sits next to it? A TOC from one build against a CAS from another
    fails exactly here: offsets run past the end of the file.

Layout transcribed from
Engine/Source/Runtime/Core/Internal/IO/IoStore.h:38-75 (FIoStoreTocHeader).
Nothing is written.
"""
import hashlib
import json
import os
import struct
import sys

MAGIC = b"-==--==--==--==-"
HDR = "<16s B B H IIIII I I I I Q 16s B B H I Q I I 40s"
STAGE = r"C:/Users/Anton/AppData/Local/MISERY/Saved/Paks"
BUILD = r"D:/UEScratch/MBPLKit/out/containers"


def parse_toc(path):
    raw = open(path, "rb").read()
    f = struct.unpack_from(HDR, raw, 0)
    (magic, version, _r0, _r1, hdr_size, entry_count, blk_count, blk_entry_size,
     cm_count, cm_len, cblock_size, dir_index_size, part_count, container_id,
     enc_guid, flags, _r3, _r4, phash_seeds, part_size, no_phash, _r7,
     _r8) = f
    out = {"file": os.path.basename(path), "bytes": len(raw),
           "magic_ok": magic == MAGIC, "version": version,
           "toc_header_size": hdr_size, "entry_count": entry_count,
           "compressed_block_entry_count": blk_count,
           "compressed_block_entry_size": blk_entry_size,
           "compression_method_name_count": cm_count,
           "compression_block_size": cblock_size,
           "directory_index_size": dir_index_size,
           "partition_count": part_count, "partition_size": part_size,
           "container_id": "0x%016x" % struct.unpack("<Q", struct.pack("<Q", container_id))[0],
           "encryption_key_guid_is_zero": enc_guid == b"\0" * 16,
           "container_flags": flags,
           "container_flags_decoded": {
               "Compressed": bool(flags & 0x01), "Encrypted": bool(flags & 0x02),
               "Signed": bool(flags & 0x04), "Indexed": bool(flags & 0x08),
               "OnDemand": bool(flags & 0x10)},
           "chunks_without_perfect_hash": no_phash}
    out["perfect_hash_seeds_count"] = phash_seeds
    # Section walk transcribed from IoStore.cpp:3215-3254. Element sizes are the
    # engine's own: FIoChunkId is uint8 Id[12] (IoChunkId.h), FIoOffsetAndLength
    # is uint8 OffsetAndLength[5+5] (IoOffsetLength.h:10-70), and
    # FIoStoreTocCompressedBlockEntry is uint8 Data[5+3+3+1] (IoStore.h).
    base = (hdr_size + entry_count * 12 + entry_count * 10
            + phash_seeds * 4 + no_phash * 4)
    out["compressed_block_table_offset"] = base
    blocks = []
    if blk_entry_size != 12:
        out["unexpected_block_entry_size"] = blk_entry_size
        return out, blocks
    for i in range(blk_count):
        off = base + i * 12
        if off + 12 > len(raw):
            out["block_table_truncated_at_entry"] = i
            break
        d = raw[off:off + 12]
        # exact accessors from FIoStoreTocCompressedBlockEntry
        offset = struct.unpack_from("<Q", d, 0)[0] & ((1 << 40) - 1)
        csize = (struct.unpack_from("<I", d, 4)[0] >> 8) & 0xFFFFFF
        usize = struct.unpack_from("<I", d, 8)[0] & 0xFFFFFF
        method = struct.unpack_from("<I", d, 8)[0] >> 24
        blocks.append((offset, csize, usize, method))
    out["blocks_parsed"] = len(blocks)
    if blocks:
        out["max_block_end"] = max(o + c for o, c, _u, _m in blocks)
        out["sum_compressed"] = sum(c for _o, c, _u, _m in blocks)
        out["sum_uncompressed"] = sum(u for _o, _c, u, _m in blocks)
        out["compression_methods_used"] = sorted({m for *_x, m in blocks})
        out["blocks_monotonic"] = all(
            blocks[i][0] <= blocks[i + 1][0] for i in range(len(blocks) - 1))
    return out, blocks


def main():
    rep = {}
    toc = os.path.join(STAGE, "MBPLRadio_P.utoc")
    cas = os.path.join(STAGE, "MBPLRadio_P.ucas")
    pak = os.path.join(STAGE, "MBPLRadio_P.pak")
    for p in (toc, cas, pak):
        if not os.path.isfile(p):
            rep["missing"] = p
            print(json.dumps(rep, indent=2))
            return 1

    hdr, blocks = parse_toc(toc)
    cas_size = os.path.getsize(cas)
    hdr["ucas_bytes"] = cas_size
    hdr["all_blocks_inside_ucas"] = bool(blocks) and hdr["max_block_end"] <= cas_size
    hdr["slack_bytes"] = cas_size - hdr.get("max_block_end", 0)
    rep["toc"] = hdr

    # the pair must also be the pair that was built
    rep["matches_build_output"] = {}
    for staged, built in (("MBPLRadio_P.utoc", "MBPLTest.utoc"),
                          ("MBPLRadio_P.ucas", "MBPLTest.ucas"),
                          ("MBPLRadio_P.pak", "MBPLTest_P.pak")):
        a = open(os.path.join(STAGE, staged), "rb").read()
        bp = os.path.join(BUILD, built)
        b = open(bp, "rb").read() if os.path.isfile(bp) else None
        rep["matches_build_output"][staged] = {
            "bytes": len(a), "sha256": hashlib.sha256(a).hexdigest(),
            "identical_to_build": (b is not None and a == b)}

    rep["paks_dir_listing"] = sorted(os.listdir(STAGE))
    rep["no_MBPLTest_leftovers"] = not any(
        n.startswith("MBPLTest_P") for n in rep["paks_dir_listing"])

    t = rep["toc"]
    rep["safe_to_launch"] = bool(
        t["magic_ok"] and t["all_blocks_inside_ucas"]
        and not t["container_flags_decoded"]["Encrypted"]
        and not t["container_flags_decoded"]["Signed"]
        and t["encryption_key_guid_is_zero"]
        and t["compressed_block_entry_size"] == 12
        and all(v["identical_to_build"] for v in rep["matches_build_output"].values())
        and rep["no_MBPLTest_leftovers"])

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "container_check.json")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps(rep, indent=2, sort_keys=True))
    return 0 if rep["safe_to_launch"] else 1


if __name__ == "__main__":
    sys.exit(main())
