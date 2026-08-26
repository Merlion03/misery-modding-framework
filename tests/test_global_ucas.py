#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for tools/reflection/global_ucas.py (method RF-01).

Standard library only, and **no test here ever opens the game installation**.
Every container is built byte by byte in this file, under a temporary directory,
so the suite runs on a machine that has never seen MISERY -- and, more
importantly, so that a decoder tuned to agree with the one real file would still
fail here.

That last point is why the file exists at all. The shipped ``global.utoc``
exercises exactly one shape: ONE chunk, 35 blocks, every block uncompressed,
container flags 0x00, no directory index, no signature, no UTF-16 name, no
unresolved outer. A run against it therefore proves nothing about any other
path through the parser. The builder below is an INDEPENDENT encoder, written
from the field tables in the engine source rather than from the decoder's code,
and it deliberately produces the shapes the real file does not have:

  * a chunk that does not start at block 0 ... test_chunk_offset_inside_block
  * several blocks, assembled in order .... test_multi_block_chunk
  * container flag Encrypted set .......... test_encrypted_container_refused
  * a block naming a compression method ... test_compressed_block_refused
  * container flag Signed set ............. test_signed_container_refused
  * a bad TocHeaderSize / block size ...... test_bad_header_size_refused,
                                            test_bad_block_entry_size_refused
  * a chunk whose stored hash disagrees ... test_chunk_hash_mismatch_refused
  * a header describing more bytes than
    the file holds ....................... test_oversized_layout_refused
  * a file holding more bytes than the
    header describes ..................... test_trailing_bytes_are_reported_not_hidden
  * an empty name batch (Num == 0) ........ test_empty_name_batch
  * UTF-16 names, including an all-ASCII
    name STORED as UTF-16, which hashes
    over two bytes per character ......... test_utf16_names
  * a name-header stride that lies ........ test_name_header_stride_mismatch
  * a Default__ object nested inside
    another CDO, i.e. the inherited
    branch of the CDO rule ............... test_cdo_inherited_branch
  * an FName with a non-zero number ....... test_fname_number_suffix
  * an outer that is not in the container . test_unresolved_outer
  * a global index that does NOT hash ..... test_global_index_mismatch_is_reported
  * the output-path guard ................. test_out_path_inside_install_refused
  * a --jsonl-scope that matches nothing .. test_jsonl_scope_matching_nothing

The two hash functions are tested against oracles that are NOT this module:

``blake3``    the 21 first-party vectors of
              Engine/Source/Runtime/Core/Tests/Hash/Blake3Test.cpp:18-49, which
              the tool also runs on every invocation. test_blake3_self_test
              checks the runner reports them, and
              test_blake3_detects_a_broken_round checks the runner FAILS when
              the implementation is broken -- a self-test that cannot fail is
              not a test.
``cityhash``  frozen (input, expected) pairs recorded below. Their provenance is
              the shipped container's own stored hash fields, which the verified
              run matched 32 797 + 34 912 times; freezing a handful of them
              turns an external oracle into a regression test that needs no game
              installation. They are ordinary CityHash64 values of ordinary
              ASCII strings, so anyone can recompute them with any other
              implementation.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _path in (os.path.join(REPO_ROOT, "tools", "reflection"),
              os.path.join(REPO_ROOT, "tools", "fingerprint"),
              os.path.join(REPO_ROOT, "tools", "inventory")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import global_ucas as gu  # noqa: E402

TOC_MAGIC = b"-==--==--==--==-"
TOC_HEADER_SIZE = 144
BLOCK_ENTRY_SIZE = 12
AES = 16
DEFAULT_BLOCK_SIZE = 256          # small on purpose: multi-block cases stay tiny
NULL_INDEX = 0xFFFFFFFFFFFFFFFF


def align(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


# --------------------------------------------------------------------------- #
# independent encoder: the .utoc / .ucas pair
# --------------------------------------------------------------------------- #

def encode_offset_length(offset: int, length: int) -> bytes:
    """FIoOffsetAndLength: five BIG-endian bytes each (IoOffsetLength.h:40-56)."""
    return offset.to_bytes(5, "big") + length.to_bytes(5, "big")


def encode_block(offset: int, compressed: int, uncompressed: int,
                 method: int) -> bytes:
    """FIoStoreTocCompressedBlockEntry, written from IoStore.h:119-165."""
    return (offset.to_bytes(5, "little") + compressed.to_bytes(3, "little")
            + uncompressed.to_bytes(3, "little") + bytes([method]))


def build_container(payload: bytes, *, chunk_offset: int = 0,
                    block_size: int = DEFAULT_BLOCK_SIZE,
                    flags: int = 0x00, chunk_type: int = 5,
                    chunk_id: bytes | None = None,
                    version: int = 6, header_size: int = TOC_HEADER_SIZE,
                    block_entry_size: int = BLOCK_ENTRY_SIZE,
                    block_method: int = 0, methods: list[str] | None = None,
                    directory_index: bytes = b"",
                    seeds: list[int] | None = None,
                    chunk_hash: bytes | None = None,
                    corrupt_payload_at: int | None = None,
                    partition_size: int = 1 << 40) -> tuple[bytes, bytes]:
    """Return (utoc bytes, ucas bytes) for a single-chunk container.

    ``chunk_offset`` is the chunk's offset in the uncompressed stream, so a
    non-zero value puts the chunk's first byte inside a block rather than at its
    start -- the shape IoStore.cpp:2761 handles and the real file never has.
    """
    stream = bytes(chunk_offset) + payload
    blocks = []
    ucas = bytearray()
    cursor = 0
    for start in range(0, max(len(stream), 1), block_size):
        piece = stream[start:start + block_size]
        blocks.append((cursor, len(piece), len(piece), block_method))
        ucas += piece + bytes(align(len(piece), AES) - len(piece))
        cursor = len(ucas)
    if corrupt_payload_at is not None:
        ucas[corrupt_payload_at] ^= 0xFF

    seeds = seeds if seeds is not None else [-1]
    methods = methods or []
    method_len = 32

    body = bytearray()
    body += (chunk_id if chunk_id is not None
             else bytes(11) + bytes([chunk_type]))
    body += encode_offset_length(chunk_offset, len(payload))
    for seed in seeds:
        body += struct.pack("<i", seed)
    for offset, compressed, uncompressed, method in blocks:
        body += encode_block(offset, compressed, uncompressed, method)
    for name in methods:
        slot = name.encode("ascii")
        body += slot + bytes(method_len - len(slot))
    body += directory_index
    body += (chunk_hash if chunk_hash is not None
             else gu.blake3_160(payload)) + bytes(12) + bytes([0])

    header = bytearray(TOC_HEADER_SIZE)
    header[0:16] = TOC_MAGIC
    header[16] = version
    struct.pack_into("<I", header, 20, header_size)
    struct.pack_into("<I", header, 24, 1)                     # TocEntryCount
    struct.pack_into("<I", header, 28, len(blocks))
    struct.pack_into("<I", header, 32, block_entry_size)
    struct.pack_into("<I", header, 36, len(methods))
    struct.pack_into("<I", header, 40, method_len)
    struct.pack_into("<I", header, 44, block_size)
    struct.pack_into("<I", header, 48, len(directory_index))
    struct.pack_into("<I", header, 52, 1)                     # PartitionCount
    struct.pack_into("<Q", header, 56, 0xFFFFFFFFFFFFFFFF)    # ContainerId
    header[80] = flags
    struct.pack_into("<I", header, 84, len(seeds))
    struct.pack_into("<Q", header, 88, partition_size)
    struct.pack_into("<I", header, 96, 0)
    return bytes(header) + bytes(body), bytes(ucas)


# --------------------------------------------------------------------------- #
# independent encoder: the chunk contents
# --------------------------------------------------------------------------- #

def encode_name_batch(names: list[tuple[str, bool]]) -> bytes:
    """Archive-form name batch, written from UnrealNames.cpp:4435-4470.

    Each entry is (text, store_as_utf16). The hash is
    ``CityHash64(lowercased bytes at the stored width)``.
    """
    if not names:
        return struct.pack("<I", 0)
    hashes = bytearray()
    headers = bytearray()
    strings = bytearray()
    for text, wide in names:
        lowered = gu.ue_to_lower(text)
        raw = lowered.encode("utf-16-le") if wide else lowered.encode("latin-1")
        hashes += struct.pack("<Q", gu.city_hash64(raw))
        length = len(text)
        headers += bytes([(0x80 if wide else 0) | (length >> 8), length & 0xFF])
        strings += (text.encode("utf-16-le") if wide
                    else text.encode("latin-1"))
    return (struct.pack("<II", len(names), len(strings))
            + struct.pack("<Q", gu.FNAME_HASH_ALGORITHM_ID)
            + bytes(hashes) + bytes(headers) + bytes(strings))


def script_index(path: str) -> int:
    """FPackageObjectIndex::FromScriptPath, AsyncLoading2.h:87-90."""
    return (1 << 62) | gu.generate_import_hash_from_object_path(path)


class Obj:
    """One object to encode: its path, its FName number, and its CDO link."""

    def __init__(self, path: str, name: str, outer: str | None = None,
                 number: int = 0, cdo: str | None = None,
                 global_override: int | None = None):
        self.path = path
        self.name = name
        self.outer = outer
        self.number = number
        self.cdo = cdo
        self.global_override = global_override


def encode_script_objects(objects: list[Obj],
                          name_index: dict[str, int]) -> bytes:
    """The int32 count plus the FScriptObjectEntry array (AsyncLoading2.cpp:169)."""
    body = struct.pack("<i", len(objects))
    for obj in objects:
        mapped = name_index[obj.name] | (2 << 30)        # EType::Global
        global_index = (obj.global_override if obj.global_override is not None
                        else script_index(obj.path))
        outer = script_index(obj.outer) if obj.outer else NULL_INDEX
        cdo = script_index(obj.cdo) if obj.cdo else NULL_INDEX
        body += struct.pack("<IIQQQ", mapped, obj.number, global_index, outer, cdo)
    return body


def build_chunk(objects: list[Obj], *,
                extra_names: list[tuple[str, bool]] | None = None) -> bytes:
    """A whole ScriptObjects chunk: a name batch, then the entry array."""
    names: list[tuple[str, bool]] = []
    seen: dict[str, int] = {}
    for obj in objects:
        if obj.name not in seen:
            seen[obj.name] = len(names)
            names.append((obj.name, False))
    for text, wide in (extra_names or []):
        if text not in seen:
            seen[text] = len(names)
            names.append((text, wide))
    return encode_name_batch(names) + encode_script_objects(objects, seen)


def simple_tree() -> list[Obj]:
    """A package, a class with a CDO, a member, and an unclassified sibling."""
    return [
        Obj("/script/testmod", "/Script/TestMod"),
        Obj("/script/testmod/testclass", "TestClass", outer="/script/testmod"),
        Obj("/script/testmod/default__testclass", "Default__TestClass",
            outer="/script/testmod", cdo="/script/testmod/testclass"),
        Obj("/script/testmod/testclass/dosomething", "DoSomething",
            outer="/script/testmod/testclass"),
        Obj("/script/testmod/eteststate", "ETestState", outer="/script/testmod"),
    ]


def write_container(directory: str, utoc: bytes, ucas: bytes,
                    stem: str = "global") -> str:
    utoc_path = os.path.join(directory, stem + ".utoc")
    with open(utoc_path, "wb") as handle:
        handle.write(utoc)
    with open(os.path.join(directory, stem + ".ucas"), "wb") as handle:
        handle.write(ucas)
    return utoc_path


def analyze_bytes(directory: str, utoc: bytes, ucas: bytes, **kwargs) -> dict:
    path = write_container(directory, utoc, ucas)
    return gu.analyze(path, with_timestamp=False, **kwargs)


# --------------------------------------------------------------------------- #
# hash oracles
# --------------------------------------------------------------------------- #

class Blake3Tests(unittest.TestCase):

    def test_blake3_self_test_runs_the_first_party_vectors(self) -> None:
        result = gu.blake3_self_test()
        self.assertEqual(result["vectors"], 21)
        self.assertEqual(result["passed"], 21)
        self.assertTrue(result["all_passed"])
        self.assertEqual(result["failures"], [])

    def test_blake3_detects_a_broken_round(self) -> None:
        """A self-test that cannot fail is decoration, so break the schedule."""
        original = gu._B3_SCHEDULE
        try:
            gu._B3_SCHEDULE = original[:6]      # six rounds instead of seven
            result = gu.blake3_self_test()
            self.assertFalse(result["all_passed"])
            self.assertEqual(result["passed"], 0)
        finally:
            gu._B3_SCHEDULE = original
        self.assertTrue(gu.blake3_self_test()["all_passed"])

    def test_blake3_160_is_the_first_20_bytes(self) -> None:
        data = b"the quick brown fox" * 100
        self.assertEqual(gu.blake3_160(data), gu.blake3_256(data)[:20])
        self.assertEqual(len(gu.blake3_160(data)), 20)


class CityHashTests(unittest.TestCase):
    """Frozen vectors. Provenance is in the module docstring: these are stored
    hash fields of the shipped container that the verified run reproduced, so
    they are an oracle outside this module even though no game file is read
    here. Every length branch of CityHash64 is covered on purpose."""

    # (lowercased name, the uint64 the shipped batch stores next to it).
    # Recorded from the run this suite accompanies; every one is an ordinary
    # CityHash64 of an ordinary ASCII string, and together they cover the
    # HashLen0to16, HashLen17to32 and HashLen33to64 branches.
    VECTORS = (
        ("actor", 0x23988B6D40E88483),                              # 5, <= 16
        ("engine", 0x413DFDD451F74E0A),                             # 6, <= 16
        ("/script/misery", 0x7BB43D7DECB48D70),                      # 14, <= 16
        ("miseryblueprintfunctionlibrary", 0x6C011C7D63873346),      # 30, 17..32
        ("default__miserygameviewportclient", 0x9F08B281E6608F75),   # 33, 33..64
    )

    # (lowercased full path, the low 62 bits of the GlobalIndex the shipped
    # entry stores). This is the FromScriptPath composition -- CityHash64 over
    # UTF-16LE with the top two bits cleared -- not a bare CityHash64.
    PATH_VECTORS = (
        ("/script/misery", 0x2F987697C73D006D),
        ("/script/misery/miseryeditabletext", 0x3695C0D931D50764),
    )

    def test_frozen_vectors(self) -> None:
        for text, expected in self.VECTORS:
            with self.subTest(text=text):
                self.assertEqual(gu.city_hash64(text.encode("latin-1")), expected)

    def test_frozen_path_vectors(self) -> None:
        for path, expected in self.PATH_VECTORS:
            with self.subTest(path=path):
                self.assertEqual(
                    gu.generate_import_hash_from_object_path(path), expected)

    def test_hash_len_16_matches_the_128_to_64_overload(self) -> None:
        """HashLen16(u, v) is defined as CityHash128to64({u, v}) at
        CityHash.cpp:285-287, so the two must never diverge."""
        for u, v in ((0, 0), (1, 2), (0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF)):
            self.assertEqual(gu._hash_len_16(u, v), gu._hash_128_to_64(u, v))

    def test_every_length_branch_is_reachable_and_distinct(self) -> None:
        seen = set()
        for length in (0, 1, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65,
                       127, 128, 129, 1000):
            value = gu.city_hash64(bytes(index % 251 for index in range(length)))
            self.assertLess(value, 1 << 64)
            seen.add(value)
        self.assertEqual(len(seen), 19)

    def test_empty_input_is_k2(self) -> None:
        """HashLen0to16 returns k2 for an empty buffer (CityHash.cpp:323)."""
        self.assertEqual(gu.city_hash64(b""), 0x9AE16A3B2F90404F)

    def test_from_script_path_clears_the_top_two_bits(self) -> None:
        value = gu.generate_import_hash_from_object_path("/Script/Whatever/Thing")
        self.assertEqual(value >> 62, 0)

    def test_from_script_path_folds_dot_and_colon_and_lowercases(self) -> None:
        base = gu.generate_import_hash_from_object_path("/script/mod/class/inner")
        self.assertEqual(gu.generate_import_hash_from_object_path(
            "/Script/Mod.Class:Inner"), base)

    def test_to_lower_is_ascii_only(self) -> None:
        self.assertEqual(gu.ue_to_lower("ABCxyz_09"), "abcxyz_09")
        self.assertEqual(gu.ue_to_lower("\u00c4\u00d6"), "\u00c4\u00d6")


# --------------------------------------------------------------------------- #
# the container walk
# --------------------------------------------------------------------------- #

class ContainerTests(unittest.TestCase):

    def test_round_trip_single_block(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, utoc, ucas,
                                     module_filter="/script/testmod")
        self.assertEqual(document["summary"]["verdict"], "VERIFIED")
        self.assertTrue(document["probes"]["chunk_identity"]["matches"])
        self.assertEqual(document["script_objects"]["count"], 5)
        self.assertEqual(document["chunk"]["chunk_type"], "ScriptObjects")

    def test_multi_block_chunk(self) -> None:
        """Many small blocks: the assembly order and the boundaries must hold."""
        chunk = build_chunk(simple_tree(),
                            extra_names=[("Filler%04d" % n, False)
                                         for n in range(300)])
        utoc, ucas = build_container(chunk, block_size=64)
        self.assertGreater(len(ucas), 64 * 5)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, utoc, ucas,
                                     module_filter="/script/testmod")
        self.assertEqual(document["summary"]["verdict"], "VERIFIED")
        self.assertGreater(document["chunk"]["read"]["block_count"], 5)
        self.assertTrue(document["probes"]["chunk_tiling"]["tiles_exactly"])

    def test_chunk_offset_inside_block(self) -> None:
        """A chunk that does not begin at a block boundary (IoStore.cpp:2761)."""
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=64, chunk_offset=37)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, utoc, ucas,
                                     module_filter="/script/testmod")
        self.assertEqual(document["chunk"]["read"]["offset_in_first_block"], 37)
        self.assertEqual(document["summary"]["verdict"], "VERIFIED")
        self.assertEqual(document["script_objects"]["count"], 5)

    def test_encrypted_container_refused(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096, flags=0x02)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(gu.ContainerParseError) as caught:
                analyze_bytes(directory, utoc, ucas)
        self.assertIn("Encrypted", str(caught.exception))

    def test_signed_container_refused(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096, flags=0x04)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(gu.ContainerParseError) as caught:
                analyze_bytes(directory, utoc, ucas)
        self.assertIn("Signed", str(caught.exception))

    def test_compressed_block_refused(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096, block_method=1,
                                     methods=["Oodle"])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(gu.ContainerParseError) as caught:
                analyze_bytes(directory, utoc, ucas)
        self.assertIn("compression method", str(caught.exception))

    def test_bad_header_size_refused(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096, header_size=160)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(gu.ContainerParseError) as caught:
                analyze_bytes(directory, utoc, ucas)
        self.assertIn("TocHeaderSize", str(caught.exception))

    def test_bad_block_entry_size_refused(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096, block_entry_size=16)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(gu.ContainerParseError) as caught:
                analyze_bytes(directory, utoc, ucas)
        self.assertIn("TocCompressedBlockEntrySize", str(caught.exception))

    def test_not_a_toc_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(gu.ContainerParseError) as caught:
                analyze_bytes(directory, b"not a toc" + bytes(200), b"")
        self.assertIn("magic", str(caught.exception))

    def test_chunk_hash_mismatch_refused(self) -> None:
        """The D-02 identity proof must be able to FAIL, or it proves nothing."""
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096,
                                     corrupt_payload_at=64)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(gu.ContainerParseError) as caught:
                analyze_bytes(directory, utoc, ucas)
        self.assertIn("hashes to", str(caught.exception))

    def test_wrong_chunk_type_is_not_selected(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096, chunk_type=1)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(gu.ContainerParseError) as caught:
                analyze_bytes(directory, utoc, ucas)
        self.assertIn("ScriptObjects", str(caught.exception))

    def test_chunk_id_with_the_right_type_but_wrong_prefix_is_reported(self) -> None:
        chunk = build_chunk(simple_tree())
        odd_id = bytes([7]) + bytes(10) + bytes([5])
        utoc, ucas = build_container(chunk, block_size=4096, chunk_id=odd_id)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, utoc, ucas,
                                     module_filter="/script/testmod")
        self.assertIn("not CreateIoChunkId",
                      document["chunk"]["selection_reason"])
        self.assertEqual(document["summary"]["verdict"], "VERIFIED")

    def test_oversized_layout_refused(self) -> None:
        """Claim a directory index the file does not hold: the header then
        describes bytes that do not exist, and every later offset is invented."""
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096,
                                     directory_index=b"XY", flags=0x08)
        broken = bytearray(utoc)
        struct.pack_into("<I", broken, 48, 64)      # DirectoryIndexSize lies
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(gu.ContainerParseError) as caught:
                analyze_bytes(directory, bytes(broken), ucas)
        self.assertIn("self-inconsistent", str(caught.exception))

    def test_trailing_bytes_are_reported_not_hidden(self) -> None:
        """The other direction: a file LONGER than its header describes still
        parses, and the extra bytes surface as a non-exact tiling."""
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, utoc + b"\x00" * 8, ucas,
                                     module_filter="/script/testmod")
        tiling = document["probes"]["toc_tiling"]
        self.assertEqual(tiling["trailing_bytes"], 8)
        self.assertFalse(tiling["tiles_exactly"])
        self.assertEqual(document["summary"]["verdict"], "CHECKS FAILED")
        self.assertIn("belong to no section", " ".join(document["warnings"]))

    def test_ucas_tiling_reports_both_models(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=64)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, utoc, ucas,
                                     module_filter="/script/testmod")
        tiling = document["probes"]["ucas_tiling"]
        self.assertTrue(tiling["matches_aes_aligned_model"])
        self.assertEqual(tiling["aes_aligned_end"], len(ucas))


# --------------------------------------------------------------------------- #
# the name batch
# --------------------------------------------------------------------------- #

class NameBatchTests(unittest.TestCase):

    def test_empty_name_batch(self) -> None:
        """Num == 0 writes nothing else (UnrealNames.cpp:4441-4443)."""
        chunk = struct.pack("<I", 0) + struct.pack("<i", 0)
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, utoc, ucas)
        self.assertEqual(document["name_table"]["count"], 0)
        self.assertEqual(document["script_objects"]["count"], 0)
        self.assertTrue(document["probes"]["chunk_tiling"]["tiles_exactly"])

    def test_utf16_names(self) -> None:
        """Including an ALL-ASCII name stored as UTF-16: the hash must be taken
        at the STORED width, not the width the characters would have needed."""
        objects = simple_tree()
        chunk = build_chunk(objects, extra_names=[
            ("\u00c4\u00d6\u00dc", True),        # genuinely wide
            ("PlainAsciiStoredWide", True),      # the trap
        ])
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, utoc, ucas,
                                     module_filter="/script/testmod")
        self.assertEqual(document["name_table"]["wide_names"], 2)
        self.assertEqual(document["name_table"]["verification"]["mismatches"], 0)
        self.assertEqual(document["summary"]["verdict"], "VERIFIED")

    def test_name_header_stride_mismatch(self) -> None:
        """A header table that does not consume the declared string bytes is the
        signature of a wrong stride, and UnrealNames.cpp:4614 asserts on it."""
        chunk = bytearray(build_chunk(simple_tree()))
        declared, = struct.unpack_from("<I", chunk, 4)
        struct.pack_into("<I", chunk, 4, declared + 3)
        utoc, ucas = build_container(bytes(chunk), block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(gu.ContainerParseError) as caught:
                analyze_bytes(directory, utoc, ucas)
        self.assertIn("string bytes", str(caught.exception))

    def test_absurd_name_length_refused(self) -> None:
        names = [("Thing", False)]
        batch = bytearray(encode_name_batch(names))
        headers_at = 16 + 8 * len(names)
        batch[headers_at] = 0x7F                    # length 0x7F05, over NAME_SIZE
        utoc, ucas = build_container(bytes(batch) + struct.pack("<i", 0),
                                    block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(gu.ContainerParseError) as caught:
                analyze_bytes(directory, utoc, ucas)
        self.assertIn("NAME_SIZE", str(caught.exception))

    def test_wrong_hash_version_skips_verification_instead_of_passing(self) -> None:
        chunk = bytearray(build_chunk(simple_tree()))
        struct.pack_into("<Q", chunk, 8, 0xDEADBEEF)
        utoc, ucas = build_container(bytes(chunk), block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, bytes(utoc), ucas,
                                     module_filter="/script/testmod")
        verification = document["name_table"]["verification"]
        self.assertIsNotNone(verification["skipped_reason"])
        self.assertEqual(verification["checked"], 0)
        self.assertIn("HashVersion", " ".join(document["warnings"]))
        # all_match is None, not True: an unrun check must not read as a pass.
        self.assertIsNone(verification["all_match"])
        self.assertEqual(document["summary"]["verdict"], "CHECKS FAILED")

    def test_fname_number_suffix(self) -> None:
        """NameTypes.h:138-142: internal 0 means no suffix, N means "_%d" N-1."""
        self.assertEqual(gu.format_fname("Thing", 0), "Thing")
        self.assertEqual(gu.format_fname("Thing", 1), "Thing_0")
        self.assertEqual(gu.format_fname("Thing", 3), "Thing_2")
        self.assertIsNone(gu.format_fname(None, 7))


# --------------------------------------------------------------------------- #
# the script-object map
# --------------------------------------------------------------------------- #

class ScriptObjectTests(unittest.TestCase):

    def analyze_tree(self, objects: list[Obj], directory: str, **kwargs) -> dict:
        chunk = build_chunk(objects)
        utoc, ucas = build_container(chunk, block_size=4096)
        return analyze_bytes(directory, utoc, ucas,
                             module_filter=kwargs.pop("module_filter",
                                                      "/script/testmod"),
                             **kwargs)

    def test_roles_and_outer_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = self.analyze_tree(simple_tree(), directory)
        histogram = document["script_objects"]["role_histogram"]
        self.assertEqual(histogram[gu.ROLE_PACKAGE], 1)
        self.assertEqual(histogram[gu.ROLE_CLASS_WITH_CDO], 1)
        self.assertEqual(histogram[gu.ROLE_CDO], 1)
        self.assertEqual(histogram[gu.ROLE_MEMBER_OF_CLASS], 1)
        self.assertEqual(histogram[gu.ROLE_PACKAGE_MEMBER], 1)
        self.assertEqual(document["probes"]["global_index_verification"]
                         ["mismatches"], 0)

    def test_cdo_inherited_branch(self) -> None:
        """A Default__ object inside another CDO inherits the outer's
        CDOClassIndex (PackageStoreOptimizer.cpp:929) and must NOT be read as
        the CDO of a class whose name follows its own prefix."""
        objects = simple_tree() + [
            Obj("/script/testmod/default__testclass/default__innerdata",
                "Default__InnerData",
                outer="/script/testmod/default__testclass",
                cdo="/script/testmod/testclass"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            document = self.analyze_tree(objects, directory)
        check = document["script_objects"]["cdo_verification"]
        self.assertEqual(check["inherited_branch_checked"], 1)
        self.assertEqual(check["inherited_branch_mismatched"], 0)
        self.assertEqual(check["computed_branch_mismatched"], 0)
        self.assertEqual(document["script_objects"]["role_histogram"]
                         [gu.ROLE_CDO_SUBOBJECT], 1)
        self.assertEqual(document["summary"]["verdict"], "VERIFIED")

    def test_cdo_inherited_branch_mismatch_is_reported(self) -> None:
        """Same shape, but the stored value is NOT the outer's: that is a real
        disagreement with PackageStoreOptimizer.cpp:929 and must show up."""
        objects = simple_tree() + [
            Obj("/script/testmod/default__testclass/default__innerdata",
                "Default__InnerData",
                outer="/script/testmod/default__testclass",
                cdo="/script/testmod/eteststate"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            document = self.analyze_tree(objects, directory)
        check = document["script_objects"]["cdo_verification"]
        self.assertEqual(check["inherited_branch_mismatched"], 1)
        self.assertEqual(document["summary"]["verdict"], "CHECKS FAILED")

    def test_class_is_credited_only_from_a_verified_cdo_link(self) -> None:
        """A Default__X whose stored CDOClassIndex points somewhere else must not
        turn that somewhere else into a class."""
        objects = [
            Obj("/script/testmod", "/Script/TestMod"),
            Obj("/script/testmod/testclass", "TestClass", outer="/script/testmod"),
            Obj("/script/testmod/other", "Other", outer="/script/testmod"),
            Obj("/script/testmod/default__testclass", "Default__TestClass",
                outer="/script/testmod", cdo="/script/testmod/other"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            document = self.analyze_tree(objects, directory)
        histogram = document["script_objects"]["role_histogram"]
        self.assertNotIn(gu.ROLE_CLASS_WITH_CDO, histogram)
        self.assertEqual(document["script_objects"]["cdo_verification"]
                         ["computed_branch_mismatched"], 1)
        self.assertEqual(document["summary"]["verdict"], "CHECKS FAILED")

    def test_global_index_mismatch_is_reported(self) -> None:
        objects = simple_tree()
        objects[1] = Obj("/script/testmod/testclass", "TestClass",
                         outer="/script/testmod",
                         global_override=(1 << 62) | 0x1234)
        with tempfile.TemporaryDirectory() as directory:
            document = self.analyze_tree(objects, directory)
        check = document["probes"]["global_index_verification"]
        self.assertGreaterEqual(check["mismatches"], 1)
        self.assertFalse(check["all_match"])
        self.assertEqual(document["summary"]["verdict"], "CHECKS FAILED")

    def test_unresolved_outer(self) -> None:
        objects = [
            Obj("/script/testmod", "/Script/TestMod"),
            Obj("/script/testmod/orphan", "Orphan", outer="/script/missing"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            document = self.analyze_tree(objects, directory)
        self.assertEqual(document["script_objects"]["unresolved_outer"], 1)
        self.assertEqual(document["script_objects"]["role_histogram"]
                         [gu.ROLE_UNRESOLVED], 1)
        self.assertIn("OuterIndex", " ".join(document["warnings"]))

    def test_shared_name_is_not_a_scan_disagreement(self) -> None:
        """Two objects in different packages sharing a Default__ name: the byte
        scan sees one string, the map has two rows, and the probe must not call
        that a disagreement."""
        objects = [
            Obj("/script/a", "/Script/A"),
            Obj("/script/a/thing", "Thing", outer="/script/a"),
            Obj("/script/a/default__thing", "Default__Thing", outer="/script/a",
                cdo="/script/a/thing"),
            Obj("/script/b", "/Script/B"),
            Obj("/script/b/thing", "Thing", outer="/script/b"),
            Obj("/script/b/default__thing", "Default__Thing", outer="/script/b",
                cdo="/script/b/thing"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            document = self.analyze_tree(objects, directory,
                                         module_filter="/script/a")
        probe = document["probes"]["ascii_default_scan"]
        self.assertEqual(probe["distinct_names_with_this_prefix"], 1)
        self.assertEqual(probe["entities_using_those_names"], 2)
        self.assertEqual(probe["names_shared_by_more_than_one_entity"], 1)
        self.assertTrue(probe["agree"])
        self.assertEqual(document["summary"]["verdict"], "VERIFIED")

    def test_module_rows_and_game_module(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = self.analyze_tree(simple_tree(), directory)
        self.assertEqual(document["module_count"], 1)
        self.assertEqual(document["modules"][0]["package"], "/Script/TestMod")
        self.assertEqual(document["modules"][0]["objects"], 5)
        self.assertTrue(document["game_module"]["present"])
        self.assertEqual(document["game_module"]["entry_count"], 5)

    def test_absent_module_is_reported_as_absent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = self.analyze_tree(simple_tree(), directory,
                                         module_filter="/Script/NotHere")
        self.assertFalse(document["game_module"]["present"])
        self.assertEqual(document["game_module"]["entry_count"], 0)


# --------------------------------------------------------------------------- #
# the evidence layers and the emitted records
# --------------------------------------------------------------------------- #

class EvidenceLayerTests(unittest.TestCase):

    def document(self, directory: str) -> dict:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096)
        return analyze_bytes(directory, utoc, ucas,
                             module_filter="/script/testmod")

    def test_literal_reads_are_class_p_and_reproduced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = self.document(directory)
        self.assertTrue(document["literal_reads"])
        for record in document["literal_reads"]:
            self.assertTrue(record["reproduced"])
            evidence = record["evidence"]
            self.assertEqual(evidence["claim_class"], "P")
            self.assertEqual(evidence["oracle"], ["container-metadata"])
            self.assertEqual(evidence["read_locus"]["length"], record["length"])
            self.assertIn("read a second time", evidence["note"])
            # The claim must state offset AND length and name no field.
            self.assertIn("at offset", record["claim"])
            self.assertIn("byte(s)", record["claim"])

    def test_literal_annotations_are_annotation_shaped(self) -> None:
        """Every key must be one research/schema/kb-record.schema.json's reduced
        annotation envelope defines, or tools/kb/validate.py holds the object to
        the FULL record rules and asks it for a build_key it cannot carry."""
        allowed = {"evidence_level", "claim_class", "confidence", "sources",
                   "oracle", "read_locus", "note"}
        with tempfile.TemporaryDirectory() as directory:
            document = self.document(directory)
        for record in document["literal_reads"]:
            self.assertLessEqual(set(record["evidence"]), allowed)
        self.assertLessEqual(set(document["decoded_evidence"]), allowed)

    def test_no_source_object_carries_a_marker_key(self) -> None:
        """A marker key inside sources[] makes validate.py treat the source as a
        record in its own right -- see the note in tools/fingerprint/
        container_info.py."""
        markers = {"evidence_level", "claim_type", "oracle", "confidence"}
        with tempfile.TemporaryDirectory() as directory:
            document = self.document(directory)
        blocks = [record["evidence"] for record in document["literal_reads"]]
        blocks.append(document["decoded_evidence"])
        for block in blocks:
            for source in block["sources"]:
                self.assertEqual(set(source) & markers, set())

    def test_decoded_layer_is_class_i_and_capped_below_the_literal_layer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = self.document(directory)
        decoded = document["decoded_evidence"]
        self.assertEqual(decoded["claim_class"], "I")
        self.assertLess(decoded["confidence"],
                        document["literal_reads"][0]["evidence"]["confidence"])
        self.assertLessEqual(decoded["confidence"], 0.99)
        self.assertIn("Refutation attempt", decoded["note"])

    def test_reflection_records_carry_the_full_envelope(self) -> None:
        required = {"evidence_level", "confidence", "sources", "oracle",
                    "build_key", "recorded_at"}
        with tempfile.TemporaryDirectory() as directory:
            document = self.document(directory)
        files = gu.emit_reflection_records(
            document, build_key="sha256:" + "0" * 64,
            recorded_at="2026-08-23T00:00:00Z", scope="/script/testmod")
        self.assertEqual(len(files["classes.jsonl"]), 1)
        self.assertEqual(len(files["functions.jsonl"]), 1)
        self.assertEqual(files["enums.jsonl"], [])
        self.assertEqual(files["properties.jsonl"], [])
        for records in files.values():
            for record in records:
                self.assertLessEqual(required, set(record))
                self.assertLessEqual(record["confidence"], 0.99)
                self.assertEqual(record["oracle"], ["global-ucas"])
                self.assertEqual(record["claim_type"], "native-class-exists")

    def test_class_record_states_its_nulls_and_their_reason(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = self.document(directory)
        files = gu.emit_reflection_records(
            document, build_key="sha256:" + "0" * 64,
            recorded_at="2026-08-23T00:00:00Z", scope="/script/testmod")
        record = files["classes.jsonl"][0]
        self.assertEqual(record["kind"], "class")
        self.assertEqual(record["raw_name"], "TestClass")
        self.assertEqual(record["cdo_name"], "Default__TestClass")
        self.assertEqual(record["evidence_level"], "INFERRED")
        for field in ("super", "size", "alignment", "class_flags_raw",
                      "property_count", "function_count", "interfaces"):
            self.assertIsNone(record[field], field)
        self.assertIn("no type tag", record["notes"])

    def test_member_kind_is_a_hypothesis_and_containment_is_split_off(self) -> None:
        """plan.md 10.3: a mixed claim is SPLIT, never averaged. The kind is a
        hypothesis; the ownership is an observation; they are separate rows."""
        with tempfile.TemporaryDirectory() as directory:
            document = self.document(directory)
        files = gu.emit_reflection_records(
            document, build_key="sha256:" + "0" * 64,
            recorded_at="2026-08-23T00:00:00Z", scope="/script/testmod")
        function = files["functions.jsonl"][0]
        self.assertEqual(function["evidence_level"], "HYPOTHESIS")
        self.assertLess(function["confidence"], 0.8)
        # The path is RECONSTRUCTED from the outer chain and the FName strings,
        # so it carries the names' own casing rather than the lowercase form the
        # global index was hashed over.
        owns = [record for record in files["relations.jsonl"]
                if record["relation_type"] == "owns"
                and record["to"] == "/Script/TestMod/TestClass/DoSomething"]
        self.assertEqual(len(owns), 1)
        self.assertEqual(owns[0]["evidence_level"], "OBSERVED")
        self.assertGreater(owns[0]["confidence"], function["confidence"])

    def test_cdo_relation_is_emitted_and_explained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = self.document(directory)
        files = gu.emit_reflection_records(
            document, build_key="sha256:" + "0" * 64,
            recorded_at="2026-08-23T00:00:00Z", scope="/script/testmod")
        cdo = [record for record in files["relations.jsonl"]
               if record["relation_type"] == "default_subobject"]
        self.assertEqual(len(cdo), 1)
        self.assertIn("NOT a component", cdo[0]["notes"])

    def test_scope_all_covers_every_package(self) -> None:
        objects = simple_tree() + [
            Obj("/script/other", "/Script/Other"),
            Obj("/script/other/thing", "Thing", outer="/script/other"),
        ]
        chunk = build_chunk(objects)
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, utoc, ucas,
                                     module_filter="/script/testmod")
        scoped = gu.emit_reflection_records(
            document, build_key="sha256:" + "0" * 64,
            recorded_at="2026-08-23T00:00:00Z", scope="/script/testmod")
        every = gu.emit_reflection_records(
            document, build_key="sha256:" + "0" * 64,
            recorded_at="2026-08-23T00:00:00Z", scope="all")
        self.assertGreater(len(every["relations.jsonl"]),
                           len(scoped["relations.jsonl"]))

    def test_empty_files_have_a_recorded_reason(self) -> None:
        self.assertIn("properties.jsonl", gu.EMPTY_FILE_REASONS)
        self.assertIn("enums.jsonl", gu.EMPTY_FILE_REASONS)
        self.assertIn("FField", gu.EMPTY_FILE_REASONS["properties.jsonl"])

    def test_cannot_be_told_is_stated_in_the_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document = self.document(directory)
        limits = document["cannot_be_told_from_this_container"]
        for key in ("what_kind_of_thing_a_name_is", "properties", "inheritance",
                    "flags", "whether_anything_is_used",
                    "anything_about_game_assets"):
            self.assertIn(key, limits)


# --------------------------------------------------------------------------- #
# determinism, output and the guard
# --------------------------------------------------------------------------- #

class OutputTests(unittest.TestCase):

    def test_two_runs_are_byte_identical(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            path = write_container(directory, utoc, ucas)
            first = gu.dump_json(gu._strip_private(
                gu.analyze(path, with_timestamp=False,
                           module_filter="/script/testmod")))
            second = gu.dump_json(gu._strip_private(
                gu.analyze(path, with_timestamp=False,
                           module_filter="/script/testmod")))
        self.assertEqual(first, second)
        self.assertIsNone(json.loads(first)["generated_at"])

    def test_document_has_no_private_keys_after_stripping(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, utoc, ucas,
                                     module_filter="/script/testmod")
        public = gu._strip_private(document)
        self.assertFalse([key for key in public if key.startswith("_")])
        self.assertIn("_entries", document)

    def test_text_outputs_carry_their_digest(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, utoc, ucas,
                                     module_filter="/script/testmod")
        names = gu.names_text(document)
        objects = gu.objects_text(document)
        self.assertIn(document["name_table"]["digest_sha256"], names)
        self.assertIn(document["script_objects"]["digest_sha256"], objects)
        self.assertIn("/Script/TestMod", names)
        self.assertIn("ffffffffffffffff", objects)
        for line in objects.splitlines():
            self.assertFalse(line.endswith(" "), line)

    def test_summary_text_mentions_every_failed_check(self) -> None:
        chunk = bytearray(build_chunk(simple_tree()))
        struct.pack_into("<Q", chunk, 8, 0xDEADBEEF)     # break HashVersion
        utoc, ucas = build_container(bytes(chunk), block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, utoc, ucas,
                                     module_filter="/script/testmod")
        text = gu.format_summary(document)
        self.assertIn("CHECKS FAILED", text)
        for name in document["summary"]["failed_checks"]:
            self.assertIn(name, text)

    def test_out_path_inside_install_refused(self) -> None:
        """plan.md 1.5 layer 1 / D-01: nothing is ever written into a game
        installation, not even a temp file."""
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            install = os.path.join(directory, "install")
            os.makedirs(os.path.join(install, "MISERY", "Binaries", "Win64"))
            os.makedirs(os.path.join(install, "Engine"))
            with open(os.path.join(install, "MISERY.exe"), "wb") as handle:
                handle.write(b"MZ")
            path = write_container(directory, utoc, ucas)
            code = gu.main([path, "--out", os.path.join(install, "x.json"),
                            "--install-dir", install])
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(os.path.join(install, "x.json")))

    def test_jsonl_dir_requires_a_build_key(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            path = write_container(directory, utoc, ucas)
            code = gu.main([path, "--jsonl-dir",
                            os.path.join(directory, "out")])
        self.assertEqual(code, 2)

    def test_jsonl_scope_matching_nothing_is_refused(self) -> None:
        """Five silently empty files must not look like a successful run: the
        real cause of that was a shell rewriting the scope argument."""
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            path = write_container(directory, utoc, ucas)
            out = os.path.join(directory, "out")
            code = gu.main([path, "--jsonl-dir", out,
                            "--build-key", "sha256:" + "0" * 64,
                            "--jsonl-scope", "C:/Program Files/Git/Script/Nope"])
        self.assertEqual(code, 2)
        self.assertFalse(os.path.isdir(out))

    def test_cli_writes_all_artifacts_and_returns_zero(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            path = write_container(directory, utoc, ucas)
            out = os.path.join(directory, "out")
            code = gu.main([path, "--module", "/script/testmod",
                            "--jsonl-scope", "/script/testmod",
                            "--out", os.path.join(out, "doc.json"),
                            "--names-out", os.path.join(out, "names.txt"),
                            "--objects-out", os.path.join(out, "objects.tsv"),
                            "--modules-out", os.path.join(out, "modules.tsv"),
                            "--jsonl-dir", out,
                            "--build-key", "sha256:" + "0" * 64,
                            "--recorded-at", "2026-08-23T00:00:00Z",
                            "--no-timestamp"])
            self.assertEqual(code, 0)
            for name in ("doc.json", "names.txt", "objects.tsv", "modules.tsv",
                         "classes.jsonl", "functions.jsonl", "relations.jsonl",
                         "enums.jsonl", "properties.jsonl"):
                self.assertTrue(os.path.isfile(os.path.join(out, name)), name)
            with open(os.path.join(out, "classes.jsonl"), encoding="utf-8") as fh:
                lines = [json.loads(line) for line in fh if line.strip()]
            self.assertEqual(len(lines), 1)
            self.assertEqual(os.path.getsize(os.path.join(out, "enums.jsonl")), 0)

    def test_cli_returns_two_when_a_check_fails(self) -> None:
        chunk = bytearray(build_chunk(simple_tree()))
        struct.pack_into("<Q", chunk, 8, 0xDEADBEEF)
        utoc, ucas = build_container(bytes(chunk), block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            path = write_container(directory, utoc, ucas)
            code = gu.main([path, "--module", "/script/testmod"])
        self.assertEqual(code, 2)

    def test_module_runs_as_a_subprocess(self) -> None:
        chunk = build_chunk(simple_tree())
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            path = write_container(directory, utoc, ucas)
            result = subprocess.run(
                [sys.executable,
                 os.path.join(REPO_ROOT, "tools", "reflection", "global_ucas.py"),
                 path, "--module", "/script/testmod"],
                capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VERDICT: VERIFIED", result.stdout)


class HelperTests(unittest.TestCase):

    def test_tile_check_finds_gaps_and_overlaps(self) -> None:
        exact = gu.tile_check([("a", 0, 10), ("b", 10, 5)], 15, "x")
        self.assertTrue(exact["tiles_exactly"])
        gap = gu.tile_check([("a", 0, 10), ("b", 12, 3)], 15, "x")
        self.assertEqual(gap["gap_count"], 1)
        self.assertFalse(gap["tiles_exactly"])
        overlap = gu.tile_check([("a", 0, 10), ("b", 8, 7)], 15, "x")
        self.assertEqual(overlap["overlap_count"], 1)
        trailing = gu.tile_check([("a", 0, 10)], 15, "x")
        self.assertEqual(trailing["trailing_bytes"], 5)
        self.assertFalse(trailing["tiles_exactly"])

    def test_tile_check_ignores_zero_length_sections(self) -> None:
        result = gu.tile_check([("a", 0, 10), ("empty", 10, 0), ("b", 10, 5)],
                               15, "x")
        self.assertTrue(result["tiles_exactly"])

    def test_align_up(self) -> None:
        self.assertEqual(gu.align_up(0, 16), 0)
        self.assertEqual(gu.align_up(1, 16), 16)
        self.assertEqual(gu.align_up(16, 16), 16)
        self.assertEqual(gu.align_up(40935, 16), 40944)

    def test_package_object_index_type(self) -> None:
        self.assertEqual(gu.package_object_index_type(gu.PACKAGE_OBJECT_INDEX_INVALID),
                         "Null")
        self.assertEqual(gu.package_object_index_type((1 << 62) | 5),
                         "ScriptImport")
        self.assertEqual(gu.package_object_index_type(5), "Export")

    def test_module_short_name(self) -> None:
        self.assertEqual(gu.module_short_name("/Script/Engine"), "Engine")
        self.assertEqual(gu.module_short_name("/Game/Thing"), "/Game/Thing")
        self.assertIsNone(gu.module_short_name(None))

    def test_staged_plugin_comparison_reports_both_directions(self) -> None:
        modules = [{"package": "/Script/Paper2D"}, {"package": "/Script/Engine"}]
        with tempfile.TemporaryDirectory() as directory:
            listing = os.path.join(directory, "staged.txt")
            with open(listing, "w", encoding="utf-8") as handle:
                handle.write("Engine/Plugins/2D/Paper2D/Paper2D.uplugin\n")
                handle.write("Engine/Plugins/X/Absent/Absent.uplugin\n")
                handle.write("MISERY/MISERY.uproject\n")
            warnings: list[str] = []
            result = gu.compare_with_staged_plugins(modules, listing, warnings)
        self.assertTrue(result["available"])
        self.assertEqual(result["counts"]["staged_uplugin_names"], 2)
        self.assertEqual(result["name_in_both"], ["Paper2D"])
        self.assertEqual(result["staged_plugin_name_with_no_module_of_that_name"],
                         ["Absent"])
        self.assertEqual(result["counts"]
                         ["module_name_not_a_staged_plugin_name"], 1)
        self.assertIn("not a module", result["reading_rule"])
        # Everything staged here is under Engine/, so the game-side group is
        # empty: the split must come from the PATH, not from the name.
        self.assertEqual(result["staged_plugins_outside_engine_plugins"], [])

    def test_game_side_plugins_are_separated_by_their_path(self) -> None:
        """A .uplugin staged outside Engine/Plugins is project-side, and one
        plugin may declare several differently named modules -- which is why
        the report is per plugin and not a total."""
        modules = [{"package": "/Script/SteamCorePro"},
                   {"package": "/Script/SteamCoreSockets"},
                   {"package": "/Script/OnlineSubsystemSteamCore"}]
        with tempfile.TemporaryDirectory() as directory:
            listing = os.path.join(directory, "staged.txt")
            with open(listing, "w", encoding="utf-8") as handle:
                handle.write("Engine/Plugins/2D/Paper2D/Paper2D.uplugin\n")
                handle.write("MISERY/Plugins/SteamCorePro/SteamCorePro.uplugin\n")
                handle.write("MISERY/Plugins/W_5.4/SIZZ_Menu_Wheel.uplugin\n")
            result = gu.compare_with_staged_plugins(modules, listing, [])
        game_side = result["staged_plugins_outside_engine_plugins"]
        self.assertEqual([row["plugin"] for row in game_side],
                         ["SIZZ_Menu_Wheel", "SteamCorePro"])
        by_name = {row["plugin"]: row for row in game_side}
        self.assertTrue(by_name["SteamCorePro"]["module_of_the_same_name_exists"])
        self.assertFalse(by_name["SIZZ_Menu_Wheel"]
                         ["module_of_the_same_name_exists"])
        self.assertEqual(result["counts"]
                         ["staged_plugins_outside_engine_plugins"], 2)

    def test_staged_plugin_comparison_missing_file_is_a_warning(self) -> None:
        warnings: list[str] = []
        result = gu.compare_with_staged_plugins([], "no/such/file.txt", warnings)
        self.assertFalse(result["available"])
        self.assertEqual(len(warnings), 1)

    def test_role_definitions_cover_every_role_the_classifier_emits(self) -> None:
        chunk = build_chunk(simple_tree() + [
            Obj("/script/testmod/default__testclass/default__innerdata",
                "Default__InnerData",
                outer="/script/testmod/default__testclass",
                cdo="/script/testmod/testclass"),
            Obj("/script/testmod/eteststate/inner", "Inner",
                outer="/script/testmod/eteststate"),
        ])
        utoc, ucas = build_container(chunk, block_size=4096)
        with tempfile.TemporaryDirectory() as directory:
            document = analyze_bytes(directory, utoc, ucas,
                                     module_filter="/script/testmod")
        for role in document["script_objects"]["role_histogram"]:
            self.assertIn(role, gu.ROLE_DEFINITIONS)
        self.assertIn(gu.ROLE_NESTED,
                      document["script_objects"]["role_histogram"])

    def test_payload_policy_names_all_three_gates(self) -> None:
        for fragment in ("Encrypted", "method index 0", "FIoChunkHash"):
            self.assertIn(fragment, gu.PAYLOAD_POLICY)

    def test_engine_source_files_are_present_on_this_machine(self) -> None:
        """The citations must point at text that exists. Skipped where the engine
        tree is not installed, because the tool does not need it to run."""
        root = os.environ.get("UE_SOURCE_ROOT", r"D:\Program Files\UE_5.4")
        if not os.path.isdir(root):
            self.skipTest("engine tree not present at %s" % root)
        for relative in gu.ENGINE_SOURCE_RELPATHS:
            self.assertTrue(os.path.isfile(os.path.join(root, relative)),
                            relative)


if __name__ == "__main__":
    unittest.main()
