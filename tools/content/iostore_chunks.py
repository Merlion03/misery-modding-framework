#!/usr/bin/env python3
"""Read-only census of the PLAINTEXT chunk tables of an IoStore ``.utoc``.

Why this tool exists
--------------------
``tools/fingerprint/container_info.py`` reads the 144-byte ``FIoStoreTocHeader``
and counts what follows it. It never opens the arrays themselves. But in a UE 5.4
IoStore TOC only ONE section is ever encrypted -- the directory index -- and the
chunk id array, the offset/length array, the compression block array, the
compression method table and the chunk metas are plaintext even when the
container carries ``EIoContainerFlags::Encrypted``: the AES call is applied to
the directory index buffer alone, in
``FIoDirectoryIndexReaderImpl::Initialize``
(``Runtime/Core/Private/IO/IoDirectoryIndex.cpp:322-331``, the ``FAES::DecryptData``
call at line 331), reached from ``FIoStoreReader::Initialize``
(``Runtime/Core/Private/IO/IoStore.cpp:3055``) via
``DirectoryIndexReader.Initialize(TocResource.DirectoryIndexBuffer, DecryptionKey)``
at ``IoStore.cpp:2399``. Corrected 2026-08-23: an earlier version of this comment
cited ``FIoStoreTocResource::Read`` itself, which loads the still-encrypted bytes
but contains no decrypt call at all -- the substantive claim (everything but the
directory index stays plaintext) held, the pointer to *where* the decrypt
happens did not; caught by adversarial review, re-traced by hand before fixing.

That matters for MISERY. ``MISERY-Windows.utoc`` is Encrypted|Indexed and its
directory index cannot be read, which is where the content track stopped. It does
not follow that nothing about the container's contents can be read: the *shape*
of every one of its 19510 chunks -- what KIND of chunk it is, where it sits and
how long it is -- is in the plaintext arrays. This tool reads exactly that, and
nothing else. It decrypts nothing, and it will not attempt the directory index
when the Encrypted flag is set.

Where the layout comes from, field by field
-------------------------------------------
First-party UE 5.4.4 source on this machine, changelist 35576357,
``++UE5+Release-5.4``:

    Core/Public/IO/IoChunkId.h:26-43     EIoChunkType, Invalid..PackageResource
    Core/Public/IO/IoChunkId.h:136-150   CreateIoChunkId: 12 bytes = uint64 id
                                         (LE), uint16 chunk index (BIG endian,
                                         NETWORK_ORDER16), one pad byte, then
                                         the chunk TYPE in byte 11
    Core/Internal/IO/IoOffsetLength.h:10-56
                                         FIoOffsetAndLength: 5-byte big-endian
                                         offset then 5-byte big-endian length
    Core/Internal/IO/IoStore.h:111-166   FIoStoreTocCompressedBlockEntry, 12
                                         bytes: 40-bit offset, 24-bit compressed
                                         size at bit 8 of the second dword,
                                         24-bit uncompressed size and an 8-bit
                                         method index in the third dword
    Core/Internal/IO/IoDirectoryIndex.h:21-48
                                         FIoDirectoryIndexResource: FString
                                         MountPoint, TArray<4 x uint32>
                                         directories, TArray<3 x uint32> files,
                                         TArray<FString> string table
    Core/Private/IO/PackageId.cpp:22-31  FPackageId::FromName = CityHash64 over
                                         the LOWERCASED package name as UTF-16LE.
                                         Recorded here as the named method that
                                         would let a future run turn a candidate
                                         package name into a chunk id and test it
                                         against these plaintext ids. This tool
                                         does not implement it.

The header decode and the section offsets are IMPORTED from
``tools/fingerprint/container_info.py`` rather than re-derived. Two modules with
two opinions about where the chunk id array starts is exactly the failure this
repository has already paid for once.

What the census answers
-----------------------
* which ``EIoChunkType`` values are present, how many of each, and how many bytes
* the size distribution per type
* whether the container is compressed in fact as well as by flag: the sum of the
  compression blocks' compressed sizes against the paired ``.ucas`` size
* whether the block count is explained by the chunk lengths: for an uncompressed
  container the number of blocks must be the sum over chunks of
  ``ceil(length / CompressionBlockSize)``, because each chunk starts a new block.
  This is a falsifiable model, and it is reported as pass/fail with the numbers.
* for a container whose directory index is plaintext: the file path of each named
  chunk, so that the type census can be checked against something with a name.

One output layer, and a pointer to where the other one lives (plan.md 10.3)
--------------------------------------------------------------------------
``census`` / ``checks`` / ``directory_index`` are class **I**: they name fields
and rest on the engine layout, and they are graded once in
``decoded_layer_evidence``. There is deliberately NO class-P literal layer here:
``tools/fingerprint/container_info.py`` owns the header and already emits one
literal record per header field, so a sampled copy of the same arrays under a
second grade would be two tools holding two opinions about one range of bytes.
``literal_layer`` says so in the output.

C-13
----
Emits counts, sizes, offsets, type names and (for a plaintext directory index)
file paths. No payload byte of any container is read: the ``.ucas`` is opened for
its SIZE only.

Standard library only.

CLI
---
    python tools/content/iostore_chunks.py <file.utoc>
    python tools/content/iostore_chunks.py <file.utoc> --out out.json
    python tools/content/iostore_chunks.py <file.utoc> --list-chunks 20

Exit codes: 0 read completed, 2 usage / I/O error / not a TOC.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
for _extra in (os.path.join(_TOOLS, "fingerprint"), os.path.join(_TOOLS, "inventory")):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

import container_info as ci  # noqa: E402  the single opinion about the header

TOOL = "tools/content/iostore_chunks.py"
TOOL_VERSION = "1.0.0"

# EIoChunkType, IoChunkId.h:26-43.
CHUNK_TYPES = {
    0: "Invalid",
    1: "ExportBundleData",
    2: "BulkData",
    3: "OptionalBulkData",
    4: "MemoryMappedBulkData",
    5: "ScriptObjects",
    6: "ContainerHeader",
    7: "ExternalFile",
    8: "ShaderCodeLibrary",
    9: "ShaderCode",
    10: "PackageStoreEntry",
    11: "DerivedData",
    12: "EditorDerivedData",
    13: "PackageResource",
}

IO_CHUNK_ID_SIZE = 12
IO_OFFSET_AND_LENGTH_SIZE = 10
IO_COMPRESSION_BLOCK_SIZE = 12
CONTAINER_FLAG_ENCRYPTED = 0x02  # EIoContainerFlags::Encrypted
MAX_ENTRIES = 5_000_000
MAX_STRING_UNITS = 65536

CONFIDENCE_LITERAL = 0.97
CONFIDENCE_DECODED = 0.90


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class ChunkParseError(Exception):
    pass


def read_at(handle, offset: int, length: int, what: str) -> bytes:
    handle.seek(offset)
    blob = handle.read(length)
    if len(blob) != length:
        raise ChunkParseError("%s: wanted %d bytes at %d, got %d" % (what, length, offset, len(blob)))
    return blob


def decode_chunk_id(raw: bytes) -> dict:
    """IoChunkId.h:136-150."""
    id_value = struct.unpack_from("<Q", raw, 0)[0]
    chunk_index = struct.unpack_from(">H", raw, 8)[0]
    chunk_type = raw[11]
    return {
        "id": "0x%016x" % id_value,
        "id_value": id_value,
        "chunk_index": chunk_index,
        "pad_byte": raw[10],
        "type_value": chunk_type,
        "type": CHUNK_TYPES.get(chunk_type, "Unknown(%d)" % chunk_type),
    }


def decode_offset_length(raw: bytes) -> tuple[int, int]:
    """IoOffsetLength.h:20-38: five big-endian bytes each."""
    offset = int.from_bytes(raw[0:5], "big")
    length = int.from_bytes(raw[5:10], "big")
    return offset, length


def decode_compression_block(raw: bytes) -> dict:
    """IoStore.h:111-166."""
    low = struct.unpack_from("<Q", raw, 0)[0]
    offset = low & ((1 << 40) - 1)
    second = struct.unpack_from("<I", raw, 4)[0]
    compressed = (second >> 8) & ((1 << 24) - 1)
    third = struct.unpack_from("<I", raw, 8)[0]
    uncompressed = third & ((1 << 24) - 1)
    method = third >> 24
    return {"offset": offset, "compressed_size": compressed,
            "uncompressed_size": uncompressed, "method_index": method}


def read_fstring(blob: bytes, pos: int) -> tuple[str, int]:
    count = struct.unpack_from("<i", blob, pos)[0]
    pos += 4
    if count == 0:
        return "", pos
    units = abs(count)
    if units > MAX_STRING_UNITS:
        raise ChunkParseError("directory index string claims %d units" % count)
    if count > 0:
        raw = blob[pos:pos + units]
        pos += units
        text = raw.decode("utf-8", "replace")
    else:
        raw = blob[pos:pos + units * 2]
        pos += units * 2
        text = raw.decode("utf-16-le", "replace")
    return text.rstrip("\x00"), pos


def read_directory_index(blob: bytes) -> dict:
    """IoDirectoryIndex.h:21-48. Only called when the container is NOT encrypted."""
    mount, pos = read_fstring(blob, 0)
    dir_count = struct.unpack_from("<i", blob, pos)[0]
    pos += 4
    if dir_count < 0 or dir_count > MAX_ENTRIES:
        raise ChunkParseError("directory entry count %d" % dir_count)
    directories = []
    for _ in range(dir_count):
        directories.append(struct.unpack_from("<4I", blob, pos))
        pos += 16
    file_count = struct.unpack_from("<i", blob, pos)[0]
    pos += 4
    if file_count < 0 or file_count > MAX_ENTRIES:
        raise ChunkParseError("file entry count %d" % file_count)
    files = []
    for _ in range(file_count):
        files.append(struct.unpack_from("<3I", blob, pos))
        pos += 12
    string_count = struct.unpack_from("<i", blob, pos)[0]
    pos += 4
    if string_count < 0 or string_count > MAX_ENTRIES:
        raise ChunkParseError("string table count %d" % string_count)
    strings = []
    for _ in range(string_count):
        text, pos = read_fstring(blob, pos)
        strings.append(text)

    none = 0xFFFFFFFF

    def name_of(index: int) -> str:
        return strings[index] if 0 <= index < len(strings) else "<name %d>" % index

    paths: dict[int, str] = {}

    def walk(dir_index: int, prefix: str) -> None:
        while dir_index != none:
            name, first_child, next_sibling, first_file = directories[dir_index]
            here = prefix if name == none else prefix + name_of(name) + "/"
            file_index = first_file
            while file_index != none:
                fname, next_file, user_data = files[file_index]
                paths[user_data] = here + name_of(fname)
                file_index = next_file
            if first_child != none:
                walk(first_child, here)
            dir_index = next_sibling

    if directories:
        walk(0, "")
    return {
        "mount_point": mount,
        "directory_entry_count": dir_count,
        "file_entry_count": file_count,
        "string_table_count": string_count,
        "bytes_consumed": pos,
        "chunk_index_to_path": paths,
    }


def census(path: str, list_chunks: int = 0) -> dict:
    file_size = os.path.getsize(path)
    with open(path, "rb", buffering=0) as handle:
        header = read_at(handle, 0, ci.TOC_HEADER_SIZE_EXPECTED, "header")
        if header[:16] != ci.TOC_MAGIC:
            raise ChunkParseError("not an IoStore TOC: magic is %s" % header[:16].hex())
        values = ci.decode_toc_header_fields(header)
        version = values["version"]
        layout = ci.toc_body_layout(values, version)
        entry_count = values["toc_entry_count"]
        if entry_count < 0 or entry_count > MAX_ENTRIES:
            raise ChunkParseError("TocEntryCount %d" % entry_count)
        flags_value = int(values["container_flags"], 16)
        encrypted = bool(flags_value & CONTAINER_FLAG_ENCRYPTED)
        block_size = values["compression_block_size"]

        ids_offset = layout["offsets"]["chunk_ids"]
        ol_offset = layout["offsets"]["chunk_offset_lengths"]
        blocks_offset = layout["offsets"]["compression_blocks"]
        block_count = values["toc_compressed_block_entry_count"]

        ids_raw = read_at(handle, ids_offset, entry_count * IO_CHUNK_ID_SIZE, "chunk ids")
        ol_raw = read_at(handle, ol_offset, entry_count * IO_OFFSET_AND_LENGTH_SIZE,
                         "chunk offsets and lengths")
        blocks_raw = read_at(handle, blocks_offset, block_count * IO_COMPRESSION_BLOCK_SIZE,
                             "compression blocks")

        # No class-P literal layer here, deliberately. The literal layer for a
        # .utoc belongs to tools/fingerprint/container_info.py, which owns the
        # header and already emits one record per header field; a sampled copy of
        # the same arrays here would be a SECOND, separately graded set of records
        # over the same bytes, and the repository has already paid once for two
        # tools holding two opinions about one file. What this module adds is the
        # decoded census, and that is graded once, in decoded_layer_evidence.
        literal_layer_note = (
            "class-P literal reads for this file are produced by "
            "tools/fingerprint/container_info.py, which owns the FIoStoreTocHeader; "
            "this module emits only the decoded census so that one range of bytes "
            "is not graded twice")

        chunks = []
        by_type_count: Counter = Counter()
        by_type_bytes: Counter = Counter()
        by_type_sizes: dict[str, list[int]] = defaultdict(list)
        predicted_blocks = 0
        total_length = 0
        for index in range(entry_count):
            info = decode_chunk_id(ids_raw[index * IO_CHUNK_ID_SIZE:(index + 1) * IO_CHUNK_ID_SIZE])
            offset, length = decode_offset_length(
                ol_raw[index * IO_OFFSET_AND_LENGTH_SIZE:(index + 1) * IO_OFFSET_AND_LENGTH_SIZE])
            info["offset"] = offset
            info["length"] = length
            by_type_count[info["type"]] += 1
            by_type_bytes[info["type"]] += length
            by_type_sizes[info["type"]].append(length)
            total_length += length
            predicted_blocks += math.ceil(length / block_size) if block_size else 0
            if index < list_chunks:
                chunks.append(info)

        blocks = [decode_compression_block(blocks_raw[i * IO_COMPRESSION_BLOCK_SIZE:
                                                      (i + 1) * IO_COMPRESSION_BLOCK_SIZE])
                  for i in range(block_count)]
        method_census = Counter(block["method_index"] for block in blocks)
        compressed_sum = sum(block["compressed_size"] for block in blocks)
        uncompressed_sum = sum(block["uncompressed_size"] for block in blocks)

        directory: dict | None = None
        if not encrypted and values["directory_index_size"] > 0 and not layout["signed"]:
            raw = read_at(handle, layout["directory_index_offset"],
                          values["directory_index_size"], "directory index")
            try:
                directory = read_directory_index(raw)
            except ChunkParseError as exc:
                directory = {"error": str(exc)}

    ucas = os.path.splitext(path)[0] + ".ucas"
    ucas_size = os.path.getsize(ucas) if os.path.exists(ucas) else None

    report = {
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "generated_at": now_iso_utc(),
        "file": {"path": path.replace("\\", "/"), "size": file_size},
        "ucas": {"path": ucas.replace("\\", "/"), "size": ucas_size},
        "header": {
            "version": version,
            "toc_entry_count": entry_count,
            "compression_block_size": block_size,
            "toc_compressed_block_entry_count": block_count,
            "container_flags": values["container_flags"],
            "container_id": values["container_id"],
            "directory_index_size": values["directory_index_size"],
            "encrypted": encrypted,
            "compression_method_name_count": values["compression_method_name_count"],
        },
        "literal_layer": literal_layer_note,
        "census": {
            "chunk_count": entry_count,
            "total_chunk_length": total_length,
            "by_type": {
                name: {
                    "count": by_type_count[name],
                    "bytes": by_type_bytes[name],
                    "min_length": min(by_type_sizes[name]),
                    "max_length": max(by_type_sizes[name]),
                }
                for name in sorted(by_type_count)
            },
            "compression_blocks": {
                "count": block_count,
                "method_index_census": {str(k): v for k, v in sorted(method_census.items())},
                "compressed_size_sum": compressed_sum,
                "uncompressed_size_sum": uncompressed_sum,
            },
        },
        "checks": {
            "block_count_predicted_from_chunk_lengths": predicted_blocks,
            "block_count_in_header": block_count,
            "uncompressed_block_model_holds": predicted_blocks == block_count,
            "uncompressed_sum_equals_total_chunk_length": uncompressed_sum == total_length,
            "compressed_sum_vs_ucas_size": None if ucas_size is None else {
                "compressed_sum": compressed_sum,
                "ucas_size": ucas_size,
                "difference": ucas_size - compressed_sum,
            },
            "note": "for an UNCOMPRESSED container each chunk starts a fresh block, so "
                    "the header's block count must equal the sum over chunks of "
                    "ceil(length / CompressionBlockSize). A compressed container "
                    "satisfies the same identity because the block count is derived "
                    "from the UNcompressed lengths; what changes is compressed_size.",
        },
        "chunks_listed": chunks,
        "decoded_layer_evidence": {
            "evidence_level": "OBSERVED",
            "claim_class": "I",
            "confidence": CONFIDENCE_DECODED,
            "oracle": ["container-metadata", "external-doc"],
            "read_locus": None,
            "sources": [
                {"method": "%s census of the plaintext chunk id and offset/length arrays"
                           % TOOL,
                 "artifact": None,
                 "locator": path.replace("\\", "/").split(":", 1)[-1].lstrip("/"),
                 "note": "field offsets imported from tools/fingerprint/container_info.py, "
                         "not re-derived here"},
                {"method": "block-count arithmetic over the same file",
                 "artifact": None,
                 "locator": path.replace("\\", "/").split(":", 1)[-1].lstrip("/"),
                 "note": "sum over chunks of ceil(length / CompressionBlockSize) compared "
                         "with the header's own block count -- an independent closure that "
                         "fails loudly if the array offsets are wrong"},
            ],
            "note": "grades the decoded layer of this report. If the chunk-id layout were "
                    "misread, the type census would name types outside EIoChunkType and "
                    "the block arithmetic would not close.",
        },
    }
    if directory is not None:
        paths = directory.pop("chunk_index_to_path", {})
        directory["named_chunk_count"] = len(paths)
        directory["sample_paths"] = [paths[k] for k in sorted(paths)[:20]]
        extensions: Counter = Counter()
        for value in paths.values():
            extensions[os.path.splitext(value)[1].lower() or "<none>"] += 1
        directory["extension_histogram"] = dict(sorted(extensions.items()))
        report["directory_index"] = directory
    else:
        report["directory_index"] = {
            "readable": False,
            "reason": "container carries EIoContainerFlags::Encrypted"
                      if int(values["container_flags"], 16) & CONTAINER_FLAG_ENCRYPTED
                      else "no directory index",
        }
    return report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("utoc")
    parser.add_argument("--list-chunks", type=int, default=0,
                        help="include this many decoded chunk records in the output")
    parser.add_argument("--out")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = census(args.utoc, args.list_chunks)
    except (ChunkParseError, OSError, ci.ContainerParseError) as exc:
        sys.stderr.write("%s: %s\n" % (TOOL, exc))
        return 2
    text = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    if args.json or not args.out:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
