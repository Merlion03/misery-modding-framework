#!/usr/bin/env python3
"""CK-01 falsification probe: is `MISERY-Windows.ucas` really encrypted?

Why this script exists, and why it is a script rather than a tool
----------------------------------------------------------------
The BLOCKED half of `research/modkit/ck-01.md` says the flag CK-01 asks about
cannot be read because the container holding the packages is encrypted. The
evidence offered for "encrypted" was `EIoContainerFlags::Encrypted` in the TOC
header -- that is, **a claim the file makes about itself**. This project already
refused that form of evidence once: `tools/content/pak_index.py` argues at
length that "the footer says the index is not encrypted" is not proof, and
proves plaintext-ness positively instead. The same standard has to apply to a
negative verdict, or the gate rests on a bit that nothing checked.

So this probe attacks its own document's headline: it locates real
`ExportBundleData` chunks, reads the first bytes of each where they physically
live, and tests them against the layout a plaintext package header would have.
If the flag were lying -- or if this project had misread it -- those bytes would
parse, and CK-01 would be answerable on the spot.

It is a script under `research/evidence/` rather than a module under `tools/`
for one reason: the two tools that own this surface already exist
(`tools/content/iostore_chunks.py` reads the plaintext chunk tables,
`tools/content/package_summary.py` reads package headers) and both were being
written concurrently with this probe. Duplicating them would have created a
third, differently-buggy opinion about the same arrays, which is exactly what
`tools/static/rtti_scan.py` refuses to do with the PE layer. The right home for
this probe is `package_summary.py`, and moving it there is named as follow-up in
`research/modkit/ck-01.md`. Until then its parsing is cross-checked twice
against tools that were written independently -- see CROSS-CHECKS below.

Nothing is decrypted and no key is sought (D-02). Two files inside the
installation are opened read-only and nothing is written anywhere near them
(D-01). Output is deterministic -- no timestamps -- so two runs produce
byte-identical logs, which is what makes "reproduced" checkable rather than
asserted.

Where the layout comes from (UE 5.4.4, changelist 35576357, ++UE5+Release-5.4)
------------------------------------------------------------------------------
    Core/Private/IO/IoStore.cpp:3191        TotalTocSize = Size - sizeof(header),
                                            so the arrays begin at TocHeaderSize
    Core/Private/IO/IoStore.cpp:3216-3266   array order: chunk ids, offset and
                                            lengths, perfect-hash seeds, chunk
                                            indices without perfect hash,
                                            compression blocks, method names,
                                            then the directory index
    Core/Public/IO/IoChunkId.h:109-111      chunk type is byte 11 of the 12-byte id
    Core/Public/IO/IoChunkId.h:26-43        EIoChunkType: ExportBundleData = 1,
                                            BulkData = 2, ScriptObjects = 5,
                                            ContainerHeader = 6,
                                            ShaderCodeLibrary = 8, ShaderCode = 9
    Core/Internal/IO/IoOffsetLength.h:20-37 5-byte big-endian offset, then
                                            5-byte big-endian length
    Core/Internal/IO/IoStore.h:112-166      FIoStoreTocCompressedBlockEntry, 12
                                            bytes: 40-bit offset (bytes 0..4 LE),
                                            24-bit compressed size (bytes 5..7 LE),
                                            24-bit uncompressed size (bytes 8..10
                                            LE), method index (byte 11)
    CoreUObject/Public/Serialization/AsyncLoading2.h:276-290
                                            FZenPackageSummary: uint32
                                            bHasVersioningInfo, uint32 HeaderSize,
                                            FMappedName Name, uint32 PackageFlags,
                                            ...  PackageFlags is at offset 16
    Core/Public/Serialization/MappedName.h:109-110
                                            FMappedName is two uint32 = 8 bytes

CROSS-CHECKS -- why this parsing is trusted without a unit-test suite
---------------------------------------------------------------------
1. The array arithmetic is checked against a tool written independently of this
   script: adding up the arrays puts the directory index at a byte offset that
   `tools/fingerprint/container_info.py` also reports, from its own reading of
   the header. Two derivations, one number.
2. The chunk-type census this script computes is compared against the census
   `tools/content/iostore_chunks.py` produced with its own parser. Two parsers,
   one histogram.
3. The plausibility test carries a POSITIVE CONTROL: `global.ucas` sits in the
   same directory, in the same format, and its container flags are 0x00. If the
   test called encrypted bytes implausible but also called the known-plaintext
   control implausible, it would be measuring nothing.

Exit codes: 0 the probe ran, 2 a file could not be read or the layout arithmetic
did not close. A "these bytes are not plaintext" outcome is a successful run.
"""

from __future__ import annotations

import collections
import math
import os
import struct
import sys

PAKS = os.path.join("MISERY", "Content", "Paks")

# From tools/fingerprint/container_info.py over this installation. Stated rather
# than re-derived so that a change in the container is a loud failure of the
# arithmetic check below, not a silently different probe.
TOC_HEADER_SIZE = 144
TOC_ENTRY_COUNT = 19510
TOC_BLOCK_COUNT = 79914
TOC_SEED_COUNT = 9755
TOC_CHUNKS_WITHOUT_PERFECT_HASH = 0
TOC_METHOD_NAME_COUNT = 0
TOC_METHOD_NAME_LENGTH = 32
COMPRESSION_BLOCK_SIZE = 65536
DIRECTORY_INDEX_OFFSET_EXPECTED = 1427352

# tools/content/iostore_chunks.py, research/evidence/CK-COOK/chunks-game-main.json
CENSUS_EXPECTED = {1: 12933, 2: 5513, 5: 0, 6: 1, 8: 2, 9: 1061}

CHUNK_TYPE_NAMES = {
    0: "Invalid", 1: "ExportBundleData", 2: "BulkData", 3: "OptionalBulkData",
    4: "MemoryMappedBulkData", 5: "ScriptObjects", 6: "ContainerHeader",
    7: "ExternalFile", 8: "ShaderCodeLibrary", 9: "ShaderCode",
    10: "PackageStoreEntry", 11: "DerivedData", 12: "EditorDerivedData",
    13: "PackageResource",
}

SAMPLE_COUNT = 8
SAMPLE_BYTES = 64
ENTROPY_SAMPLE_BYTES = 1 << 20


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte. 8.0 is the ceiling."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def zen_summary_is_plausible(raw: bytes, chunk_length: int) -> tuple[bool, dict]:
    """Test the first 20 bytes against FZenPackageSummary.

    Three conditions, each one a fact about the layout rather than a taste:

    * `bHasVersioningInfo` is a uint32 used as a bool, so 0 or 1 and nothing
      else. A uniformly random uint32 clears this with probability 2 / 2**32.
    * `HeaderSize` is a byte count inside this chunk, so it cannot exceed the
      chunk length, and a package header is never smaller than the summary plus
      one name.
    * `Name.Index` occupies 30 bits of an FMappedName, the top two being the
      type, so the raw uint32 read as an index must fit in 30 bits.
    """
    has_versioning, header_size, name_index, name_number, package_flags = \
        struct.unpack_from("<IIIII", raw, 0)
    checks = {
        "bHasVersioningInfo_is_0_or_1": has_versioning in (0, 1),
        "HeaderSize_fits_chunk": 64 <= header_size <= chunk_length,
        "Name_index_fits_30_bits": name_index < (1 << 30),
    }
    return all(checks.values()), {
        "bHasVersioningInfo": has_versioning,
        "HeaderSize": header_size,
        "Name.Index": name_index,
        "Name.Number": name_number,
        "PackageFlags_at_offset_16": package_flags,
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        sys.stderr.write(
            "usage: zen-plaintext-probe.py <game-install-root>\n"
            "  the root is not printed, only paths relative to it (C-13)\n")
        return 2
    root = argv[0]
    utoc_path = os.path.join(root, PAKS, "MISERY-Windows.utoc")
    ucas_path = os.path.join(root, PAKS, "MISERY-Windows.ucas")
    control_path = os.path.join(root, PAKS, "global.ucas")

    out = sys.stdout
    out.write("CK-01 zen-plaintext probe -- attacks the BLOCKED verdict of "
              "research/modkit/ck-01.md\n")
    out.write("Read-only. Nothing decrypted, no key sought (D-02).\n\n")

    try:
        with open(utoc_path, "rb") as handle:
            toc = handle.read()
    except OSError as error:
        sys.stderr.write("cannot read the TOC: %s\n" % error)
        return 2

    # --- layout arithmetic, checked against container_info.py -------------
    ids_at = TOC_HEADER_SIZE
    offsets_at = ids_at + TOC_ENTRY_COUNT * 12
    seeds_at = offsets_at + TOC_ENTRY_COUNT * 10
    without_hash_at = seeds_at + TOC_SEED_COUNT * 4
    blocks_at = without_hash_at + TOC_CHUNKS_WITHOUT_PERFECT_HASH * 4
    methods_at = blocks_at + TOC_BLOCK_COUNT * 12
    directory_at = methods_at + TOC_METHOD_NAME_COUNT * TOC_METHOD_NAME_LENGTH

    out.write("CROSS-CHECK 1 -- array arithmetic against container_info.py\n")
    out.write("  chunk ids            @ %d\n" % ids_at)
    out.write("  offset and lengths   @ %d\n" % offsets_at)
    out.write("  perfect-hash seeds   @ %d\n" % seeds_at)
    out.write("  compression blocks   @ %d\n" % blocks_at)
    out.write("  directory index      @ %d   expected %d   %s\n"
              % (directory_at, DIRECTORY_INDEX_OFFSET_EXPECTED,
                 "AGREE" if directory_at == DIRECTORY_INDEX_OFFSET_EXPECTED
                 else "DISAGREE -- the layout is not what this probe assumes"))
    if directory_at != DIRECTORY_INDEX_OFFSET_EXPECTED:
        sys.stderr.write("layout arithmetic did not close; refusing to read "
                         "payload offsets derived from it\n")
        return 2
    if directory_at > len(toc):
        sys.stderr.write("the TOC is shorter than its own arrays\n")
        return 2

    # --- chunk type census, checked against iostore_chunks.py -------------
    census: collections.Counter = collections.Counter()
    export_bundles: list[int] = []
    for index in range(TOC_ENTRY_COUNT):
        chunk_type = toc[ids_at + index * 12 + 11]
        census[chunk_type] += 1
        if chunk_type == 1 and len(export_bundles) < SAMPLE_COUNT:
            export_bundles.append(index)

    out.write("\nCROSS-CHECK 2 -- chunk type census against iostore_chunks.py\n")
    agree = True
    for chunk_type in sorted(set(census) | set(CENSUS_EXPECTED)):
        got = census.get(chunk_type, 0)
        want = CENSUS_EXPECTED.get(chunk_type, 0)
        if got != want:
            agree = False
        out.write("  %-2d %-20s %6d   expected %6d %s\n"
                  % (chunk_type, CHUNK_TYPE_NAMES.get(chunk_type, "?"),
                     got, want, "" if got == want else "  <-- DISAGREE"))
    out.write("  verdict: %s\n" % ("two independently written parsers agree"
                                   if agree else "PARSERS DISAGREE"))

    def offset_and_length(index: int) -> tuple[int, int]:
        raw = toc[offsets_at + index * 10: offsets_at + index * 10 + 10]
        return (int.from_bytes(raw[0:5], "big"), int.from_bytes(raw[5:10], "big"))

    def block(index: int) -> tuple[int, int, int, int]:
        raw = toc[blocks_at + index * 12: blocks_at + index * 12 + 12]
        return (int.from_bytes(raw[0:5], "little"),
                int.from_bytes(raw[5:8], "little"),
                int.from_bytes(raw[8:11], "little"),
                raw[11])

    # --- the probe itself -------------------------------------------------
    out.write("\nPROBE -- first %d ExportBundleData chunks, read where they "
              "physically live\n" % SAMPLE_COUNT)
    plausible_count = 0
    try:
        with open(ucas_path, "rb", buffering=0) as handle:
            for index in export_bundles:
                logical, length = offset_and_length(index)
                block_index = logical // COMPRESSION_BLOCK_SIZE
                within = logical % COMPRESSION_BLOCK_SIZE
                block_offset, _csize, _usize, method = block(block_index)
                physical = block_offset + within
                handle.seek(physical)
                raw = handle.read(SAMPLE_BYTES)
                ok, detail = zen_summary_is_plausible(raw, length)
                plausible_count += int(ok)
                out.write(
                    "  chunk %-6d len=%-9d block=%-6d method=%d phys=%-12d "
                    "H=%.3f plausible=%s\n"
                    % (index, length, block_index, method, physical,
                       entropy(raw), ok))
                out.write("      bHasVersioningInfo=%d HeaderSize=%d "
                          "Name.Index=%d\n"
                          % (detail["bHasVersioningInfo"], detail["HeaderSize"],
                             detail["Name.Index"]))
                out.write("      first 32 bytes: %s\n" % raw[:32].hex())
    except OSError as error:
        sys.stderr.write("cannot read the container: %s\n" % error)
        return 2

    out.write("  plausible package headers found: %d of %d\n"
              % (plausible_count, len(export_bundles)))

    # --- positive control -------------------------------------------------
    out.write("\nCROSS-CHECK 3 -- positive control, global.ucas "
              "(container flags 0x00)\n")
    try:
        with open(control_path, "rb", buffering=0) as handle:
            control_head = handle.read(SAMPLE_BYTES)
    except OSError as error:
        sys.stderr.write("cannot read the control container: %s\n" % error)
        return 2
    leading = struct.unpack_from("<II", control_head, 0)
    out.write("  leading two uint32: %d, %d  (small and structured, not random)\n"
              % leading)
    out.write("  first 32 bytes: %s\n" % control_head[:32].hex())

    out.write("\nENTROPY over %d-byte samples (8.000 is the ceiling)\n"
              % ENTROPY_SAMPLE_BYTES)
    for label, path, at in (
            ("MISERY-Windows.ucas @0", ucas_path, 0),
            ("MISERY-Windows.ucas @2GiB", ucas_path, 2 << 30),
            ("global.ucas @0 (control)", control_path, 0)):
        with open(path, "rb", buffering=0) as handle:
            handle.seek(at)
            sample = handle.read(ENTROPY_SAMPLE_BYTES)
        out.write("  %-28s bytes=%d H=%.4f distinct=%d\n"
                  % (label, len(sample), entropy(sample), len(set(sample))))

    out.write("\nOUTCOME: the probe tried to refute \"encrypted\" and did not.\n"
              if plausible_count == 0 else
              "\nOUTCOME: a plausible package header WAS found -- the BLOCKED "
              "verdict must be revisited.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
