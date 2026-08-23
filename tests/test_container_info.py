#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for tools/fingerprint/container_info.py (plan.md task F-02).

Standard library only, and **no test here ever opens the game installation**. Every
container is built byte by byte in this file, under a temporary directory, so the
suite runs on a machine that has never seen MISERY and so that a parser tuned to
agree with the real files would still fail here.

That is the point of the synthetic builders below: they are an INDEPENDENT
implementation of the layout the parser assumes, written from the field table
rather than from the parser's code, and the round trip build -> parse is what
catches a field read at the wrong offset. A test that merely re-ran the parser over
the real .utoc and asserted the numbers it produced would prove nothing at all.

Coverage demanded by the task, and where it lives:
  * a well formed TOC header ............ test_utoc_wellformed_flags_00 / _0a
  * a truncated one ..................... test_utoc_truncated_header,
                                          test_utoc_truncated_body
  * a bad magic ......................... test_utoc_bad_magic
  * an unexpected version byte .......... test_utoc_unexpected_version_warns
  * a pak footer at the right offset .... test_pak_footer_at_right_offset
  * a pak footer at the wrong offset .... test_pak_footer_at_wrong_offset
  * container flags 0x00 and 0x0A ....... test_decode_container_flags_both_states,
                                          and the two well-formed TOC tests
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_FINGERPRINT = os.path.join(REPO_ROOT, "tools", "fingerprint")
TOOLS_INVENTORY = os.path.join(REPO_ROOT, "tools", "inventory")
TOOLS_KB = os.path.join(REPO_ROOT, "tools", "kb")
for _path in (TOOLS_FINGERPRINT, TOOLS_INVENTORY, TOOLS_KB):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import container_info as ci  # noqa: E402
import pathguard  # noqa: E402

SCHEMA_DIR = Path(REPO_ROOT) / "research" / "schema"


# --------------------------------------------------------------------------- #
# synthetic container builders -- an independent model of the layout
# --------------------------------------------------------------------------- #

def _filler(length: int, seed: int = 0) -> bytes:
    """Deterministic non-zero filler, so a misread offset shows up as a wrong value
    rather than as an accidental zero that happens to look plausible."""
    return bytes(((index * 37 + seed * 11 + 1) & 0xFF) for index in range(length))


def build_utoc(
    *,
    version: int = 6,
    magic: bytes = ci.TOC_MAGIC,
    header_size: int = ci.TOC_HEADER_SIZE_EXPECTED,
    entry_count: int = 3,
    block_count: int = 4,
    block_entry_size: int = 12,
    block_size: int = 65536,
    method_names: tuple[str, ...] = (),
    method_slot_length: int = 32,
    directory_index: bytes = b"",
    partition_count: int = 1,
    partition_size: int = 0xFFFFFFFFFFFFFFFF,
    container_id: int = 0xFFFFFFFFFFFFFFFF,
    key_guid: bytes = b"\x00" * 16,
    flags: int = 0x00,
    seeds_count: int | None = None,
    without_perfect_hash: int = 0,
    reserved0: int = 0,
    reserved1: int = 0,
    reserved3: int = 0,
    reserved4: int = 0,
    reserved7: int = 0,
    truncate_to: int | None = None,
) -> bytes:
    """A complete, self-consistent .utoc image whose size the layout arithmetic closes on.

    Written from the published field table, NOT from the parser: the parser is what
    is under test. ``seeds_count`` defaults to ``entry_count`` so the perfect-hash
    array is non-empty and a parser that forgot to skip it would land in the wrong
    place for everything after it.
    """
    if seeds_count is None:
        seeds_count = entry_count

    method_count = len(method_names)
    header = bytearray(header_size)
    header[0:16] = magic.ljust(16, b"\x00")[:16]
    header[16] = version & 0xFF
    header[17] = reserved0 & 0xFF
    struct.pack_into("<H", header, 18, reserved1)
    struct.pack_into("<I", header, 20, header_size)
    struct.pack_into("<I", header, 24, entry_count)
    struct.pack_into("<I", header, 28, block_count)
    struct.pack_into("<I", header, 32, block_entry_size)
    struct.pack_into("<I", header, 36, method_count)
    struct.pack_into("<I", header, 40, method_slot_length)
    struct.pack_into("<I", header, 44, block_size)
    struct.pack_into("<I", header, 48, len(directory_index))
    struct.pack_into("<I", header, 52, partition_count)
    struct.pack_into("<Q", header, 56, container_id)
    header[64:80] = key_guid
    header[80] = flags & 0xFF
    header[81] = reserved3 & 0xFF
    struct.pack_into("<H", header, 82, reserved4)
    struct.pack_into("<I", header, 84, seeds_count)
    struct.pack_into("<Q", header, 88, partition_size)
    struct.pack_into("<I", header, 96, without_perfect_hash)
    struct.pack_into("<I", header, 100, reserved7)
    # reserved8[5] stays zero

    body = bytearray()
    body += _filler(entry_count * ci.IO_CHUNK_ID_SIZE, 1)
    body += _filler(entry_count * ci.IO_OFFSET_AND_LENGTH_SIZE, 2)
    if version >= ci.TOC_VERSION_PERFECT_HASH:
        body += _filler(seeds_count * ci.IO_PERFECT_HASH_SEED_SIZE, 3)
    if version >= ci.TOC_VERSION_PERFECT_HASH_WITH_OVERFLOW:
        body += _filler(without_perfect_hash * ci.IO_PERFECT_HASH_SEED_SIZE, 4)
    body += _filler(block_count * block_entry_size, 5)
    for name in method_names:
        slot = bytearray(method_slot_length)
        encoded = name.encode("ascii")
        slot[0:len(encoded)] = encoded
        body += bytes(slot)
    body += directory_index
    meta_size = (ci.IO_CHUNK_META_SIZE_IOHASH if version >= ci.TOC_VERSION_IO_HASH_META
                 else ci.IO_CHUNK_META_SIZE_HASH32)
    body += _filler(entry_count * meta_size, 6)

    image = bytes(header) + bytes(body)
    if truncate_to is not None:
        image = image[:truncate_to]
    return image


def fstring(text: str) -> bytes:
    """UE FString: int32 length INCLUDING the NUL terminator, then ASCII, then NUL."""
    encoded = text.encode("ascii") + b"\x00"
    return struct.pack("<i", len(encoded)) + encoded


def build_pak_index(mount: str = "../../../", num_entries: int = 3,
                    version: int = 11, path_hash_seed: int = 0x4E5F46A0,
                    sub_blocks: tuple[tuple[bool, int, int], ...] = ((False, 0, 0),
                                                                     (False, 0, 0))) -> bytes:
    """The primary index blob whose sha1 the footer stores.

    ``sub_blocks`` is ((present, offset, size), ...) for the path hash index and the
    full directory index, in that order. Their widths are fixed, so the caller can
    build the blob once with placeholders, learn its length, and rebuild it with the
    real offsets without the length changing.
    """
    blob = bytearray()
    blob += fstring(mount)
    blob += struct.pack("<i", num_entries)
    if version >= ci.PAK_VERSION_PATH_HASH_INDEX:
        blob += struct.pack("<Q", path_hash_seed)
        for present, sub_offset, sub_size in sub_blocks:
            blob += struct.pack("<i", 1 if present else 0)
            if present:
                blob += struct.pack("<qq", sub_offset, sub_size) + _filler(20, 9)
    blob += _filler(64, 7)  # stand-in for the encoded entry table
    return bytes(blob)


def build_pak(*, version: int = 11, mount: str = "../../../", num_entries: int = 3,
              encrypted_index: bool = False, key_guid: bytes = b"\x00" * 16,
              compression_methods: tuple[str, ...] = (),
              magic: int = ci.PAK_MAGIC, corrupt_index_hash: bool = False,
              trailing_garbage: bytes = b"", prefix_bytes: int = 128,
              has_path_hash_index: bool = False,
              has_full_directory_index: bool = False) -> bytes:
    """A complete .pak image: payload, index, footer -- optionally with junk appended.

    ``trailing_garbage`` is how "the footer is at the wrong offset" is expressed: the
    footer is byte-identical and correct, it simply no longer ends the file, and a
    parser that finds it anyway is a parser that would accept a footer-shaped
    sequence anywhere.
    """
    payload = _filler(prefix_bytes, 8)
    index_offset = len(payload)

    # Two passes: the primary index stores the offsets of the two secondary indexes,
    # which sit right behind it, so its own length has to be known first. Every field
    # involved is fixed width, so the second pass cannot change the length.
    sizes = (0 if not has_path_hash_index else 96,
             0 if not has_full_directory_index else 48)
    placeholder = build_pak_index(mount=mount, num_entries=num_entries, version=version,
                                  sub_blocks=((has_path_hash_index, 0, sizes[0]),
                                              (has_full_directory_index, 0, sizes[1])))
    cursor = index_offset + len(placeholder)
    path_hash_offset, cursor = cursor, cursor + sizes[0]
    full_dir_offset, cursor = cursor, cursor + sizes[1]
    index = build_pak_index(
        mount=mount, num_entries=num_entries, version=version,
        sub_blocks=((has_path_hash_index, path_hash_offset, sizes[0]),
                    (has_full_directory_index, full_dir_offset, sizes[1])))
    assert len(index) == len(placeholder)
    sub_payload = _filler(sizes[0], 12) + _filler(sizes[1], 13)
    index_hash = hashlib.sha1(index).digest()
    if corrupt_index_hash:
        index_hash = bytes((index_hash[0] ^ 0xFF,)) + index_hash[1:]

    footer = bytearray()
    if version >= ci.PAK_VERSION_ENCRYPTION_KEY_GUID:
        footer += key_guid
    footer += bytes((1 if encrypted_index else 0,))
    footer += struct.pack("<I", magic)
    footer += struct.pack("<i", version)
    footer += struct.pack("<q", index_offset)
    footer += struct.pack("<q", len(index))
    footer += index_hash
    if version == ci.PAK_VERSION_FROZEN_INDEX:
        footer += b"\x00"
    if version >= ci.PAK_VERSION_FNAME_BASED_COMPRESSION:
        table = bytearray(ci.PAK_MAX_NUM_COMPRESSION_METHODS
                          * ci.PAK_COMPRESSION_METHOD_NAME_LEN)
        for slot, name in enumerate(compression_methods):
            encoded = name.encode("ascii")
            start = slot * ci.PAK_COMPRESSION_METHOD_NAME_LEN
            table[start:start + len(encoded)] = encoded
        footer += bytes(table)
    assert len(footer) == ci.pak_footer_size(version), (
        "the test builder and pak_footer_size disagree for version %d: %d vs %d"
        % (version, len(footer), ci.pak_footer_size(version)))
    return payload + index + sub_payload + bytes(footer) + trailing_garbage


def write_temp(directory: str, name: str, data: bytes) -> str:
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


# --------------------------------------------------------------------------- #
# TOC header
# --------------------------------------------------------------------------- #

class TocHeaderTests(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def parse(self, image: bytes, name: str = "x.utoc"):
        path = write_temp(self.tmp, name, image)
        warnings: list[str] = []
        utoc, literals, diagnostics = ci.parse_utoc(path, name, warnings)
        return utoc, literals, diagnostics, warnings

    def test_utoc_wellformed_flags_00(self) -> None:
        """Flags 0x00: no Indexed bit, no directory index, nothing decoded from it."""
        image = build_utoc(flags=0x00, directory_index=b"", entry_count=2,
                           block_count=3, container_id=0xFFFFFFFFFFFFFFFF)
        utoc, literals, diagnostics, warnings = self.parse(image)
        self.assertEqual(warnings, [])
        self.assertEqual(utoc["toc_magic"], "-==--==--==--==-")
        self.assertEqual(utoc["version"], 6)
        self.assertEqual(utoc["toc_header_size"], 144)
        self.assertEqual(utoc["toc_entry_count"], 2)
        self.assertEqual(utoc["toc_compressed_block_entry_count"], 3)
        self.assertEqual(utoc["toc_compressed_block_entry_size"], 12)
        self.assertEqual(utoc["compression_block_size"], 65536)
        self.assertEqual(utoc["directory_index_size"], 0)
        self.assertEqual(utoc["partition_count"], 1)
        self.assertEqual(utoc["partition_size"], "0xffffffffffffffff")
        self.assertEqual(utoc["container_id"], "0xffffffffffffffff")
        self.assertEqual(utoc["encryption_key_guid"], "0" * 32)
        self.assertEqual(utoc["container_flags"], "0x00")
        self.assertEqual(utoc["container_flags_decoded"], [])
        self.assertFalse(utoc["is_encrypted"])
        self.assertFalse(utoc["has_directory_index"])
        self.assertFalse(utoc["directory_index_readable"])
        self.assertIsNone(utoc["mount_point"])
        self.assertEqual(utoc["compression_method_names"], [])
        self.assertEqual(utoc["reserved8"], ["0x%016x" % 0] * 5)
        # The independent corroboration: the arithmetic closes on the file size.
        self.assertTrue(diagnostics["layout_total_matches_file_size"])
        self.assertEqual(diagnostics["layout_total_computed"], len(image))
        self.assertTrue(literals)

    def test_utoc_wellformed_flags_0a(self) -> None:
        """Flags 0x0A = Encrypted | Indexed, WITHOUT Compressed -- the real container's state."""
        # 512 bytes that cannot parse as an FString mount point, standing in for an
        # encrypted directory index. Not encrypted here, and never decrypted anywhere:
        # what is being tested is that unreadable is reported as unreadable.
        opaque = _filler(512, 42)
        image = build_utoc(flags=0x0A, directory_index=opaque, entry_count=5,
                           block_count=7, container_id=0x3002A7A795855966)
        utoc, _literals, diagnostics, warnings = self.parse(image)
        self.assertEqual(warnings, [])
        self.assertEqual(utoc["container_flags"], "0x0a")
        self.assertEqual(utoc["container_flags_decoded"], ["Encrypted", "Indexed"])
        self.assertNotIn("Compressed", utoc["container_flags_decoded"])
        self.assertTrue(utoc["is_encrypted"])
        self.assertTrue(utoc["has_directory_index"])
        self.assertEqual(utoc["directory_index_size"], 512)
        self.assertEqual(utoc["container_id"], "0x3002a7a795855966")
        # D-02: the index is present, and it stays unread.
        self.assertFalse(utoc["directory_index_readable"])
        self.assertIsNone(utoc["mount_point"])
        self.assertTrue(diagnostics["layout_total_matches_file_size"])
        joined = " ".join(diagnostics["index_notes"])
        self.assertIn("D-02", joined)
        self.assertIn("Encrypted", joined)

    def test_utoc_plaintext_directory_index_is_read(self) -> None:
        """Indexed without Encrypted: the mount point IS recovered, so the negative
        result of the previous test is a measurement and not a hardcoded 'no'."""
        index = fstring("../../../") + _filler(64, 11)
        image = build_utoc(flags=0x08, directory_index=index)
        utoc, _literals, _diag, warnings = self.parse(image)
        self.assertEqual(warnings, [])
        self.assertTrue(utoc["has_directory_index"])
        self.assertTrue(utoc["directory_index_readable"])
        self.assertEqual(utoc["mount_point"], "../../../")
        self.assertFalse(utoc["is_encrypted"])

    def test_utoc_bad_magic(self) -> None:
        image = build_utoc(magic=b"NOTATOCMAGIC0000")
        with self.assertRaises(ci.ContainerParseError) as caught:
            self.parse(image, "bad.utoc")
        message = str(caught.exception)
        self.assertIn("magic", message)
        # The refusal must itself state offset and length -- otherwise the reason the
        # file was rejected is not reproducible as written.
        self.assertIn("16 bytes at offset 0", message)

    def test_utoc_truncated_header(self) -> None:
        image = build_utoc()[:100]
        with self.assertRaises(ci.ContainerParseError) as caught:
            self.parse(image, "short.utoc")
        self.assertIn("shorter than", str(caught.exception))

    def test_utoc_truncated_body(self) -> None:
        """A full header over a body that was cut short: the header still parses (the
        bytes are real), but the arithmetic must NOT close, and it must say so."""
        full = build_utoc(entry_count=4, block_count=6)
        image = full[:len(full) - 40]
        utoc, _literals, diagnostics, warnings = self.parse(image, "cut.utoc")
        self.assertEqual(utoc["toc_entry_count"], 4)
        self.assertFalse(diagnostics["layout_total_matches_file_size"])
        self.assertTrue(any("layout arithmetic does not close" in warning
                            for warning in warnings), warnings)
        self.assertTrue(any("+40" in warning for warning in warnings), warnings)

    def test_utoc_unexpected_version_warns_but_still_reads(self) -> None:
        image = build_utoc(version=99)
        utoc, literals, _diag, warnings = self.parse(image, "future.utoc")
        self.assertEqual(utoc["version"], 99)
        self.assertTrue(any("version byte is 99" in warning for warning in warnings),
                        warnings)
        # The literal layer must be unaffected: bytes are bytes whatever the version.
        version_read = self._read_for(literals, "version")
        self.assertEqual(version_read["bytes_hex"], "63")
        self.assertEqual(version_read["offset"], 16)
        self.assertEqual(version_read["length"], 1)

    def test_utoc_unexpected_header_size_warns(self) -> None:
        image = build_utoc(header_size=160)
        _utoc, _literals, _diag, warnings = self.parse(image, "wide.utoc")
        self.assertTrue(any("TocHeaderSize is 160" in warning for warning in warnings),
                        warnings)

    def test_utoc_compression_method_names(self) -> None:
        image = build_utoc(method_names=("Oodle", "Zlib"))
        utoc, literals, diagnostics, warnings = self.parse(image, "methods.utoc")
        self.assertEqual(warnings, [])
        self.assertEqual(utoc["compression_method_names"], ["Oodle", "Zlib"])
        self.assertEqual(utoc["compression_method_name_count"], 2)
        self.assertEqual(utoc["compression_method_name_length"], 32)
        self.assertTrue(diagnostics["layout_total_matches_file_size"])
        table = self._read_for(literals, "compression_method_names")
        self.assertEqual(table["length"], 64)

    def test_utoc_version_below_perfect_hash_skips_the_seed_array(self) -> None:
        """Version gating is real: at version 3 the seed array is absent even though
        the header still carries a non-zero count, and the arithmetic proves it."""
        image = build_utoc(version=3, seeds_count=7, entry_count=2)
        utoc, _literals, diagnostics, warnings = self.parse(image, "v3.utoc")
        self.assertEqual(utoc["toc_chunk_perfect_hash_seeds_count"], 7)
        self.assertTrue(diagnostics["layout_total_matches_file_size"], warnings)

    def _read_for(self, literals: list[dict], field: str) -> dict:
        matches = [read for read in literals if read["decoded_field"] == field]
        self.assertEqual(len(matches), 1, "expected exactly one read for %r" % field)
        return matches[0]


# --------------------------------------------------------------------------- #
# container flags
# --------------------------------------------------------------------------- #

class ContainerFlagTests(unittest.TestCase):

    def test_decode_container_flags_both_states(self) -> None:
        self.assertEqual(ci.decode_container_flags(0x00), ([], 0))
        self.assertEqual(ci.decode_container_flags(0x0A), (["Encrypted", "Indexed"], 0))

    def test_decode_container_flags_every_known_bit(self) -> None:
        names, unknown = ci.decode_container_flags(0x1F)
        self.assertEqual(names, ["Compressed", "Encrypted", "Signed", "Indexed", "OnDemand"])
        self.assertEqual(unknown, 0)

    def test_decode_container_flags_unknown_bit_is_reported_not_invented(self) -> None:
        names, unknown = ci.decode_container_flags(0x22)
        self.assertEqual(names, ["Encrypted"])
        self.assertEqual(unknown, 0x20)

    def test_unknown_flag_bit_warns_and_stays_in_the_raw_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_temp(tmp, "flags.utoc", build_utoc(flags=0x22))
            warnings: list[str] = []
            utoc, _literals, _diag = ci.parse_utoc(path, "flags.utoc", warnings)
        self.assertEqual(utoc["container_flags"], "0x22")
        self.assertEqual(utoc["container_flags_decoded"], ["Encrypted"])
        self.assertTrue(any("unknown bit" in warning for warning in warnings), warnings)


# --------------------------------------------------------------------------- #
# pak footer
# --------------------------------------------------------------------------- #

class PakFooterTests(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def parse(self, image: bytes, name: str = "x.pak", verify: bool = True):
        path = write_temp(self.tmp, name, image)
        warnings: list[str] = []
        pak, literals, diagnostics = ci.parse_pak(path, name, warnings, verify)
        return pak, literals, diagnostics, warnings

    def test_pak_footer_size_is_version_dependent(self) -> None:
        # 221 is the size that must hold for version 11, and it is pinned because the
        # real MISERY-Windows.pak footer occupies exactly the last 221 bytes.
        self.assertEqual(ci.pak_footer_size(11), 221)
        self.assertEqual(ci.pak_footer_size(10), 221)
        self.assertEqual(ci.pak_footer_size(9), 222)   # + the frozen-index byte
        self.assertEqual(ci.pak_footer_size(8), 221)
        self.assertEqual(ci.pak_footer_size(7), 61)    # no method table
        self.assertEqual(ci.pak_footer_size(6), 45)    # no GUID either

    def test_pak_footer_at_right_offset(self) -> None:
        image = build_pak(version=11, mount="../../../", num_entries=4424)
        pak, _literals, diagnostics, warnings = self.parse(image)
        self.assertEqual(warnings, [])
        self.assertEqual(pak["magic"], "0x5a6f12e1")
        self.assertEqual(pak["pak_version"], 11)
        self.assertEqual(pak["footer_size"], 221)
        self.assertEqual(pak["footer_offset"], len(image) - 221)
        self.assertEqual(pak["encrypted_index"], False)
        self.assertEqual(pak["encryption_key_guid"], "0" * 32)
        self.assertEqual(pak["mount_point"], "../../../")
        self.assertEqual(pak["num_entries"], 4424)
        self.assertTrue(pak["index_readable"])
        self.assertIsNone(pak["index_is_frozen"])
        self.assertTrue(diagnostics["index_hash_verified"])

    def test_pak_footer_at_wrong_offset(self) -> None:
        """The footer is correct but no longer ends the file. It must NOT be found:
        a parser that scans for the magic would happily accept a footer that the
        engine itself would never read."""
        image = build_pak(version=11, trailing_garbage=_filler(64, 3))
        with self.assertRaises(ci.ContainerParseError) as caught:
            self.parse(image, "shifted.pak")
        self.assertIn("no pak footer found", str(caught.exception))

    def test_pak_footer_with_bad_magic_is_refused(self) -> None:
        image = build_pak(version=11, magic=0xDEADBEEF)
        with self.assertRaises(ci.ContainerParseError):
            self.parse(image, "badmagic.pak")

    def _restamp_version(self, image: bytes, layout_version: int,
                         stored_version: int) -> bytes:
        mutable = bytearray(image)
        offsets = dict((name, rel) for name, rel, _length
                       in ci.pak_footer_field_offsets(layout_version))
        footer_start = len(mutable) - ci.pak_footer_size(layout_version)
        struct.pack_into("<i", mutable, footer_start + offsets["pak_version"],
                         stored_version)
        return bytes(mutable)

    def test_pak_version_mismatch_of_size_and_stored_value_is_refused(self) -> None:
        """A v11-sized footer whose stored version needs a DIFFERENT size must be
        refused rather than read with the wrong layout. Version 6 has a 45-byte
        footer, so no candidate layout can agree with both the size and the value."""
        image = self._restamp_version(build_pak(version=11), 11, 6)
        with self.assertRaises(ci.ContainerParseError):
            self.parse(image, "mixed.pak")

    def test_pak_version_8_and_11_share_a_footer_size_and_are_told_apart_by_value(self) -> None:
        """Versions 8, 10 and 11 all serialize to 221 bytes, so the stored value is the
        only thing that distinguishes them -- and it must be the value that wins, not
        the newest candidate tried."""
        self.assertEqual(ci.pak_footer_size(8), ci.pak_footer_size(11))
        image = self._restamp_version(build_pak(version=11), 11, 8)
        pak, _literals, _diag, warnings = self.parse(image, "asv8.pak")
        self.assertEqual(pak["pak_version"], 8)
        self.assertEqual(pak["footer_size"], 221)
        # Version 8 predates the path hash index, so those fields must be null even
        # though the bytes that would hold them are physically present in the index.
        self.assertIsNone(pak["path_hash_seed"])
        self.assertTrue(any("predates the path-hash index" in warning
                            for warning in warnings), warnings)

    def test_pak_encrypted_index_is_not_read(self) -> None:
        """D-02: an encrypted index is recorded as present and unread, with a reason."""
        image = build_pak(version=11, encrypted_index=True)
        pak, _literals, diagnostics, _warnings = self.parse(image, "enc.pak")
        self.assertTrue(pak["encrypted_index"])
        self.assertFalse(pak["index_readable"])
        self.assertIsNone(pak["mount_point"])
        self.assertIn("D-02", " ".join(diagnostics["index_notes"]))

    def test_pak_index_hash_mismatch_is_reported_not_hidden(self) -> None:
        image = build_pak(version=11, corrupt_index_hash=True)
        _pak, _literals, diagnostics, warnings = self.parse(image, "corrupt.pak")
        self.assertFalse(diagnostics["index_hash_verified"])
        self.assertTrue(any("disagree" in warning for warning in warnings), warnings)

    def test_pak_version_7_has_no_compression_method_table(self) -> None:
        image = build_pak(version=7, mount="../../../")
        pak, _literals, _diag, warnings = self.parse(image, "v7.pak")
        self.assertEqual(pak["pak_version"], 7)
        self.assertEqual(pak["footer_size"], 61)
        self.assertIsNone(pak["compression_methods"])
        # Below version 10 the path hash fields do not exist; they must be null with
        # an explanation rather than silently false.
        self.assertIsNone(pak["path_hash_seed"])
        self.assertTrue(any("predates the path-hash index" in warning
                            for warning in warnings), warnings)

    def test_pak_version_9_carries_the_frozen_index_byte(self) -> None:
        image = build_pak(version=9)
        pak, _literals, _diag, _warnings = self.parse(image, "v9.pak")
        self.assertEqual(pak["pak_version"], 9)
        self.assertEqual(pak["footer_size"], 222)
        self.assertIs(pak["index_is_frozen"], False)

    def test_pak_compression_methods_and_sub_indexes(self) -> None:
        image = build_pak(version=11, compression_methods=("Zlib", "Oodle"),
                          has_path_hash_index=True, has_full_directory_index=True)
        pak, _literals, _diag, warnings = self.parse(image, "methods.pak")
        self.assertEqual(warnings, [])
        self.assertEqual(pak["compression_methods"], ["Zlib", "Oodle"])
        self.assertTrue(pak["has_path_hash_index"])
        self.assertTrue(pak["has_full_directory_index"])
        self.assertEqual(pak["path_hash_seed"], "0x000000004e5f46a0")

    def test_pak_region_tiling_catches_a_lying_sub_index_offset(self) -> None:
        """The tiling check is the pak's independent method, so it has to be able to
        fail: move one secondary index by a byte and it must say so rather than
        quietly still reporting a corroborated parse."""
        good = build_pak(version=11, has_path_hash_index=True,
                         has_full_directory_index=True)
        clean_pak, _l, clean_diag, clean_warnings = self.parse(good, "tiled.pak")
        self.assertTrue(clean_diag["layout_tiles_file"], clean_warnings)
        self.assertEqual(len(clean_diag["sub_index_blocks"]), 2)

        # Nudge the path-hash-index offset stored inside the primary index.
        broken = bytearray(good)
        block = clean_diag["sub_index_blocks"][0]
        needle = struct.pack("<qq", block["offset"], block["size"])
        position = bytes(broken).find(needle, clean_pak["index_offset"])
        self.assertGreater(position, 0)
        struct.pack_into("<q", broken, position, block["offset"] + 1)
        _pak, _l2, diag, warnings = self.parse(bytes(broken), "untiled.pak")
        self.assertFalse(diag["layout_tiles_file"])
        self.assertTrue(any("does not tile the file" in warning for warning in warnings),
                        warnings)

    def test_pak_too_small_for_any_footer(self) -> None:
        with self.assertRaises(ci.ContainerParseError):
            self.parse(b"\x00" * 8, "tiny.pak")


# --------------------------------------------------------------------------- #
# FString probe
# --------------------------------------------------------------------------- #

class FStringProbeTests(unittest.TestCase):

    def test_ascii_round_trip(self) -> None:
        value, reason = ci.probe_fstring(fstring("../../../") + b"junk")
        self.assertEqual(value, "../../../")
        self.assertEqual(reason, "ok")

    def test_utf16(self) -> None:
        text = "../../../"
        encoded = text.encode("utf-16-le") + b"\x00\x00"
        value, _reason = ci.probe_fstring(struct.pack("<i", -(len(text) + 1)) + encoded)
        self.assertEqual(value, text)

    def test_high_entropy_bytes_do_not_parse(self) -> None:
        """The probe is what distinguishes 'encrypted' from 'plaintext'. If random
        bytes parsed, the D-02 verdict would be worthless."""
        rejected = 0
        for seed in range(64):
            value, _reason = ci.probe_fstring(_filler(256, seed))
            if value is None:
                rejected += 1
        self.assertEqual(rejected, 64)

    def test_absurd_length_is_refused(self) -> None:
        value, reason = ci.probe_fstring(struct.pack("<i", 1 << 20) + b"\x00" * 16)
        self.assertIsNone(value)
        self.assertIn("plausible", reason)

    def test_missing_terminator_is_refused(self) -> None:
        value, _reason = ci.probe_fstring(struct.pack("<i", 4) + b"abcd")
        self.assertIsNone(value)


# --------------------------------------------------------------------------- #
# the two-layer split -- the point of the task
# --------------------------------------------------------------------------- #

class LayerSplitTests(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        path = write_temp(self.tmp, "x.utoc",
                          build_utoc(flags=0x0A, directory_index=_filler(256, 5),
                                     container_id=0x3002A7A795855966))
        self.warnings: list[str] = []
        self.utoc, self.literals, self.diag = ci.parse_utoc(path, "x.utoc", self.warnings)

    def test_every_header_field_has_a_literal_read_with_offset_and_length(self) -> None:
        by_field = {read["decoded_field"]: read for read in self.literals}
        for name, offset, length, _kind in ci.TOC_HEADER_FIELDS:
            self.assertIn(name, by_field)
            read = by_field[name]
            self.assertEqual(read["offset"], offset)
            self.assertEqual(read["length"], length)
            self.assertEqual(len(read["bytes_hex"].split()), length)

    def test_literal_claim_states_offset_and_length_and_names_nothing(self) -> None:
        read = next(item for item in self.literals
                    if item["decoded_field"] == "directory_index_size")
        self.assertEqual(read["claim"], "4 bytes at offset 48 of x.utoc are 00 01 00 00")
        # The class-P sentence must not name the field. This is the exact rule that
        # splits plan.md row A-07 from row A-07i.
        lowered = read["claim"].lower()
        for forbidden in ("directoryindexsize", "directory_index_size", "field",
                          "fiostoretocheader"):
            self.assertNotIn(forbidden, lowered)

    def test_literal_read_note_is_the_claim_not_a_description_of_it(self) -> None:
        """NEW-07, guarded without invoking the validator.

        tools/kb/validate.py derives the claim class of a REDUCED annotation from
        the ``note`` string alone. A note that talks ABOUT the record instead of
        BEING the claim states no offset and no length of its own, derives class I,
        and drags the 0.99 band's two-independent-methods requirement in with it --
        which is exactly what produced 60 EV-05 + 60 EV-03 on this tool's own
        output. So the graded string has to state the claim, and the pointer to the
        interpretive half has to live outside the graded object.
        """
        for read in self.literals:
            note = read["evidence"]["note"]
            self.assertTrue(note.startswith(read["claim"]), note)
            # naming a structure in this string is exactly what would disqualify the
            # class-P admission of plan.md 10.3 v2.4
            for forbidden in ("FIoStoreTocHeader", "containers[]", " field",
                              "layout", "structure", "signature", "interpretation"):
                self.assertNotIn(forbidden, note)
            # the pointer to the interpretive half lives outside the graded object
            self.assertIn("containers[]", read["interpretation_lives_in"])
            self.assertNotIn("interpretation_lives_in", read["evidence"])

    def test_literal_reads_are_confirmed_by_a_second_read(self) -> None:
        """plan.md 10.3 class-P criterion 2 is executed, not asserted: the attestation
        must appear only after the second read actually happened."""
        warnings: list[str] = []
        # Before confirmation the records must say PENDING rather than claim a re-run.
        fresh = ci.literal_read("x.utoc", "version", 16, b"\x06")
        self.assertIn("PENDING", fresh["evidence"]["sources"][0]["note"])
        self.assertNotIn("re-run and reproduced",
                         fresh["evidence"]["sources"][0]["note"])

        path = write_temp(self.tmp, "confirm.utoc", build_utoc())
        _utoc, literals, _diag = ci.parse_utoc(path, "confirm.utoc", warnings)
        self.assertTrue(ci.confirm_literal_reads(path, literals, "confirm.utoc", warnings))
        self.assertEqual(warnings, [])
        for read in literals:
            self.assertTrue(read["reproduced"])
            self.assertIn("re-run and reproduced", read["evidence"]["sources"][0]["note"])

    def test_a_changed_file_fails_the_confirming_reread(self) -> None:
        """If the second read disagreed, the tool must say so instead of quietly
        keeping the first value -- otherwise criterion 2 would be decoration."""
        path = write_temp(self.tmp, "mutate.utoc", build_utoc())
        warnings: list[str] = []
        _utoc, literals, _diag = ci.parse_utoc(path, "mutate.utoc", warnings)
        with open(path, "r+b") as handle:      # a synthetic file, never a game file
            handle.seek(16)
            handle.write(b"\x07")
        self.assertFalse(ci.confirm_literal_reads(path, literals, "mutate.utoc", warnings))
        self.assertTrue(any("did NOT reproduce" in warning for warning in warnings),
                        warnings)
        version = next(read for read in literals if read["decoded_field"] == "version")
        self.assertFalse(version["reproduced"])
        self.assertIn("NOT reproduced", version["evidence"]["sources"][0]["note"])
        # The first reading is kept as read; the tool never edits it to agree.
        self.assertEqual(version["bytes_hex"], "06")

    def test_literal_evidence_is_class_p_shaped(self) -> None:
        for read in self.literals:
            evidence = read["evidence"]
            self.assertEqual(evidence["evidence_level"], "OBSERVED")
            self.assertEqual(evidence["claim_class"], "P")
            self.assertLessEqual(evidence["confidence"], 0.99)
            self.assertEqual(evidence["oracle"], ["container-metadata"])
            locus = evidence["read_locus"]
            self.assertIsNotNone(locus)
            self.assertIn("offset", locus)
            self.assertIn("length", locus)
            self.assertGreaterEqual(locus["offset"], 0)
            self.assertGreaterEqual(locus["length"], 1)
            self.assertEqual(locus["bytes_hex"], read["bytes_hex"])

    def test_decoded_annotation_is_class_i_and_never_above_the_ceiling(self) -> None:
        corroborated = ci.decoded_annotation("x.utoc", True, "closes")
        single = ci.decoded_annotation("x.utoc", False, "does not close")
        for annotation in (corroborated, single):
            self.assertEqual(annotation["evidence_level"], "INFERRED")
            self.assertEqual(annotation["claim_class"], "I")
            self.assertIn("external-doc", annotation["oracle"])
            self.assertLessEqual(annotation["confidence"], 0.99)
        # plan.md 10.3: two independent methods are required from 0.80 up, so the
        # uncorroborated grade must sit below that band.
        self.assertEqual(corroborated["confidence"], 0.85)
        self.assertLess(single["confidence"], 0.80)
        self.assertEqual(len(corroborated["sources"]), 2)
        self.assertEqual(len(single["sources"]), 1)

    def test_layers_are_separate_structures(self) -> None:
        """The decoded block must not carry offsets and the literal reads must not
        carry decoded values -- a consumer has to be able to cite one without the
        other."""
        for key in self.utoc:
            self.assertNotIn("offset", key)
        for read in self.literals:
            self.assertNotIn("value", read)
            self.assertNotIn("decoded_value", read)


# --------------------------------------------------------------------------- #
# document assembly, schema conformance, determinism, output guard
# --------------------------------------------------------------------------- #

class DocumentTests(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        # A synthetic installation: <root>/MISERY/Content/Paks/{...}
        self.install = os.path.join(self.tmp, "install")
        self.paks = os.path.join(self.install, "MISERY", "Content", "Paks")
        os.makedirs(self.paks)
        write_temp(self.paks, "global.utoc", build_utoc(flags=0x00, entry_count=1,
                                                        block_count=2))
        write_temp(self.paks, "global.ucas", _filler(4096, 1))
        write_temp(self.paks, "MISERY-Windows.utoc",
                   build_utoc(flags=0x0A, directory_index=_filler(1024, 2),
                              entry_count=6, block_count=9,
                              container_id=0x3002A7A795855966))
        write_temp(self.paks, "MISERY-Windows.ucas", _filler(8192, 2))
        write_temp(self.paks, "MISERY-Windows.pak", build_pak(version=11))

    def build(self, **kwargs) -> dict:
        return ci.build_document(install_dir=self.install, **kwargs)

    def test_document_shape(self) -> None:
        document = self.build()
        self.assertEqual(document["container_count"], 5)
        kinds = {entry["path"].rsplit("/", 1)[-1]: entry["kind"]
                 for entry in document["containers"]}
        self.assertEqual(kinds["global.utoc"], "utoc")
        self.assertEqual(kinds["global.ucas"], "ucas")
        self.assertEqual(kinds["MISERY-Windows.pak"], "pak")
        paths = [entry["path"] for entry in document["containers"]]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(document["warnings"], [])
        self.assertTrue(all(check["passed"] for check in document["checks"]),
                        document["checks"])

    def test_corroborated_entries_name_the_second_oracle(self) -> None:
        """A second method on an oracle the record does not name would be uncheckable,
        so the record-level oracle list has to grow with the source list. The oracle of
        each individual source is stated in its note rather than in an "oracle" key --
        see SOURCE_ORACLE_OMITTED."""
        document = self.build()
        for entry in document["containers"]:
            if entry["kind"] not in ("utoc", "pak"):
                continue
            evidence = entry["evidence"]
            self.assertEqual(evidence["confidence"], 0.85, entry["path"])
            self.assertEqual(len(evidence["sources"]), 2, entry["path"])
            named = set(evidence["oracle"])
            self.assertIn("filesystem", named)
            for source in evidence["sources"]:
                self.assertNotIn("oracle", source, entry["path"])
                self.assertTrue(any(name in source["note"] for name in named),
                                (entry["path"], source["note"]))

    def test_no_source_object_carries_an_oracle_key(self) -> None:
        """Populating source.oracle makes tools/kb/validate.py read every source as a
        whole record; measured, it was 40 spurious errors on one fingerprint.json. The
        oracle lives in the note instead, and this test keeps it that way."""
        document = self.build(hash_files=False)
        offenders = []
        def walk(node, pointer="$"):
            if isinstance(node, dict):
                if "method" in node and "oracle" in node:
                    offenders.append(pointer)
                for key, value in node.items():
                    walk(value, "%s.%s" % (pointer, key))
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    walk(value, "%s[%d]" % (pointer, index))
        walk(document)
        self.assertEqual(offenders, [])

    def test_entry_evidence_can_be_switched_off_without_losing_the_literal_layer(self) -> None:
        document = self.build(entry_evidence=False)
        for entry in document["containers"]:
            self.assertIsNone(entry["evidence"])
        self.assertTrue(document["literal_reads"])
        for group in document["literal_reads"]:
            for read in group["reads"]:
                self.assertEqual(read["evidence"]["claim_class"], "P")

    def test_checks_cover_both_pak_cross_checks(self) -> None:
        document = self.build()
        pak_checks = {check["check"]: check for check in document["checks"]
                      if check["target"].endswith(".pak")}
        self.assertEqual(set(pak_checks), {"pak_layout_tiles_file",
                                           "pak_index_sha1_recomputed",
                                           "literal_reads_reproduced"})
        self.assertTrue(all(check["passed"] for check in pak_checks.values()))

    def test_every_parsed_container_reports_a_reproduced_read(self) -> None:
        document = self.build()
        for group in document["literal_reads"]:
            self.assertTrue(group["reads_reproduced"], group["target"])
        reproduced = {check["target"] for check in document["checks"]
                      if check["check"] == "literal_reads_reproduced" and check["passed"]}
        parsed = {entry["path"] for entry in document["containers"]
                  if entry["utoc"] or entry["pak"]}
        self.assertEqual(reproduced, parsed)

    def test_siblings_are_paired(self) -> None:
        document = self.build()
        by_path = {entry["path"]: entry for entry in document["containers"]}
        self.assertEqual(by_path["MISERY/Content/Paks/global.utoc"]["sibling_path"],
                         "MISERY/Content/Paks/global.ucas")
        self.assertEqual(by_path["MISERY/Content/Paks/global.ucas"]["sibling_path"],
                         "MISERY/Content/Paks/global.utoc")
        self.assertIsNone(by_path["MISERY/Content/Paks/MISERY-Windows.pak"]["sibling_path"])

    def test_ucas_is_not_opened_unless_asked(self) -> None:
        """A header parser has no business reading a 4.3 GB data file. The proof is
        that body_entropy stays null and no .ucas read happens by default."""
        document = self.build()
        for entry in document["containers"]:
            if entry["utoc"]:
                self.assertIsNone(entry["utoc"]["body_entropy"])
            if entry["kind"] == "ucas":
                self.assertIsNone(entry["sha256"])

    def test_entropy_sample_is_opt_in_and_bounded(self) -> None:
        document = self.build(ucas_entropy_bytes=4096)
        by_path = {entry["path"]: entry for entry in document["containers"]}
        entropy = by_path["MISERY/Content/Paks/global.utoc"]["utoc"]["body_entropy"]
        self.assertIsNotNone(entropy)
        self.assertGreaterEqual(entropy, 0.0)
        self.assertLessEqual(entropy, 8.0)

    def test_hash_option_fills_sha256(self) -> None:
        document = self.build(hash_files=True)
        for entry in document["containers"]:
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")

    def test_stale_inventory_hash_is_refused(self) -> None:
        inventory = {"files": [
            {"path": "MISERY/Content/Paks/global.utoc", "size": 1, "sha256": "0" * 64},
        ]}
        inv_path = os.path.join(self.tmp, "inv.json")
        with open(inv_path, "w", encoding="utf-8") as handle:
            json.dump(inventory, handle)
        document = self.build(inventory_path=inv_path)
        by_path = {entry["path"]: entry for entry in document["containers"]}
        self.assertIsNone(by_path["MISERY/Content/Paks/global.utoc"]["sha256"])
        self.assertTrue(any("stale" in warning for warning in document["warnings"]),
                        document["warnings"])

    def test_unparseable_container_is_recorded_not_dropped(self) -> None:
        write_temp(self.paks, "broken.utoc", b"NOTATOC" + _filler(400, 9))
        document = self.build()
        by_path = {entry["path"]: entry for entry in document["containers"]}
        broken = by_path["MISERY/Content/Paks/broken.utoc"]
        self.assertIsNone(broken["utoc"])
        self.assertEqual(broken["evidence"]["evidence_level"], "UNKNOWN")
        self.assertIn("parse failed", broken["notes"])
        self.assertTrue(any("broken.utoc" in warning for warning in document["warnings"]))

    def test_two_runs_differ_only_in_generated_at(self) -> None:
        first = self.build()
        second = self.build()
        first.pop("generated_at")
        second.pop("generated_at")
        self.assertEqual(ci.dump_json(first), ci.dump_json(second))

    def test_dump_json_is_deterministic_lf_and_sorted(self) -> None:
        text = ci.dump_json(self.build())
        self.assertNotIn("\r", text)
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.startswith("﻿"))
        reparsed = json.loads(text)
        self.assertEqual(ci.dump_json(reparsed), text)

    def test_write_json_refuses_a_path_inside_the_installation(self) -> None:
        document = self.build()
        target = os.path.join(self.paks, "containers.json")
        with self.assertRaises(pathguard.OutputPathRefused):
            ci.write_json(document, target, install_dir=self.install)
        self.assertFalse(os.path.exists(target))

    def test_write_json_writes_outside_the_installation(self) -> None:
        document = self.build()
        target = os.path.join(self.tmp, "containers.json")
        written = ci.write_json(document, target, install_dir=self.install)
        with open(written, "rb") as handle:
            raw = handle.read()
        self.assertNotIn(b"\r\n", raw)
        self.assertEqual(json.loads(raw.decode("utf-8"))["container_count"], 5)

    def test_containers_validate_against_the_fingerprint_schema(self) -> None:
        """containers[] must be spliceable into fingerprint.json verbatim (task F-03).

        Validated against the PUBLISHED schema, so a field this tool invents or a
        value it spells wrongly fails here rather than in F-03.
        """
        try:
            import validate as kb_validate  # noqa: WPS433
        except Exception as error:  # pragma: no cover - environment dependent
            self.skipTest("tools/kb/validate.py not importable: %s" % error)
        fingerprint = json.loads(
            (SCHEMA_DIR / "fingerprint.schema.json").read_text(encoding="utf-8"))
        schema = {
            "$schema": fingerprint.get("$schema"),
            "$id": fingerprint.get("$id"),
            "$defs": fingerprint["$defs"],
            "type": "array",
            "items": {"$ref": "#/$defs/container_entry"},
        }
        document = self.build(hash_files=True)
        errors, _ignored, _backend = kb_validate.validate_against_schema(
            document["containers"], schema, "$.containers", SCHEMA_DIR)
        self.assertEqual(errors, [], errors)


    def test_emitted_annotations_pass_the_knowledge_base_validator(self) -> None:
        """NEW-07. The evidence apparatus this tool emits has to clear
        tools/kb/validate.py AS IT STANDS -- not after the reader reshapes it.

        This test exists because of a measured defect, and it checks the layer the
        schema test above cannot see: the class-P ``note`` of a literal read used to
        talk ABOUT the record instead of being the claim, the validator derived
        class I from that string, and demanded two independent methods for a
        single-byte read graded 0.99. Running the tool with --out and validating the
        result gave 120 violations -- 60 EV-05 plus 60 EV-03, one pair per literal
        read. Nothing in the schema was red, which is why
        test_containers_validate_against_the_fingerprint_schema stayed green through
        it. This one runs the evidence rules over the WHOLE document, literal layer
        included, so the regression cannot come back silently.
        """
        validate_path = os.path.join(REPO_ROOT, "tools", "kb", "validate.py")
        if not os.path.isfile(validate_path):        # pragma: no cover
            self.skipTest("tools/kb/validate.py is absent")
        target = os.path.join(self.tmp, "emitted-annotations.json")
        import io                                    # noqa: WPS433 - test-only
        import subprocess                            # noqa: WPS433 - test-only
        from contextlib import redirect_stdout       # noqa: WPS433 - test-only
        with redirect_stdout(io.StringIO()):
            code = ci.main(["--install-dir", self.install, "--out", target])
        self.assertEqual(code, 0)

        result = subprocess.run([sys.executable, validate_path, target],
                                capture_output=True, text=True, cwd=REPO_ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("violations: 0", result.stdout, result.stdout)
        # and the literal layer really was in scope: a run that saw no annotations
        # would report 0 violations vacuously
        self.assertIn("reduced evidence annotations:", result.stdout, result.stdout)


class CliTests(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        self.install = os.path.join(self.tmp, "install")
        self.paks = os.path.join(self.install, "MISERY", "Content", "Paks")
        os.makedirs(self.paks)
        write_temp(self.paks, "global.utoc", build_utoc(flags=0x00))

    def run_cli(self, argv: list[str]) -> int:
        import io
        from contextlib import redirect_stderr, redirect_stdout
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = ci.main(argv)
        self.stdout, self.stderr = out.getvalue(), err.getvalue()
        return code

    def test_cli_writes_and_reports(self) -> None:
        target = os.path.join(self.tmp, "out.json")
        code = self.run_cli(["--install-dir", self.install, "--out", target])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(target))
        self.assertEqual(len(self.stdout.strip().splitlines()), 1)
        self.assertIn("containers=1", self.stdout)

    def test_cli_refuses_out_inside_the_installation(self) -> None:
        target = os.path.join(self.paks, "out.json")
        code = self.run_cli(["--install-dir", self.install, "--out", target])
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(target))
        self.assertIn("D-01", self.stderr)

    def test_cli_rejects_a_missing_paks_directory(self) -> None:
        code = self.run_cli(["--install-dir", os.path.join(self.tmp, "nope")])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
