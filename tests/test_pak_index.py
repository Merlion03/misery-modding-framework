#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for tools/content/pak_index.py (CK-01 gating read).

Standard library only, and **no test here ever opens the game installation**. Every
pak is built byte by byte in this file, under a temporary directory, so the suite
runs on a machine that has never seen MISERY -- and, more importantly, so that a
decoder tuned to agree with the one real file would still fail here.

That last point is the whole reason this file exists. The shipped
``MISERY-Windows.pak`` contains exactly ONE distinct entry flag word, ``0xE0400000``:
every entry is uncompressed, unblocked, 32-bit safe and encrypted. So a run against
the real file exercises a single path through ``decode_pak_entry`` and proves nothing
about the others. The builder below is an INDEPENDENT encoder written from the field
table in ``FPakEntry::Encode`` / ``DecodePakEntry`` rather than from the decoder's
code, and it deliberately produces the shapes the real file does not have:

  * uncompressed and unencrypted ........... test_roundtrip_plain
  * uncompressed and encrypted ............. test_roundtrip_encrypted
  * compressed, several blocks ............. test_roundtrip_compressed_multi_block
  * compressed, exactly one block,
    unencrypted -- the case that stores NO
    block array and derives it ............. test_single_unencrypted_block_stores_nothing
  * compressed, exactly one block,
    ENCRYPTED -- the case that DOES store
    the array (C:7079) ..................... test_single_encrypted_block_stores_array
  * the 0x3f block-size escape ............. test_block_size_escape_field
  * 64-bit offset / sizes .................. test_roundtrip_64bit_fields
  * the whole encoded blob tiling .......... test_tiling_probe_detects_gap
  * a wide (UTF-16) FString path ........... test_wide_fstring_path
  * an FPakEntryLocation that is a list
    index or invalid ....................... test_location_classification,
                                             test_unencodable_entries_are_refused
  * the D-02 plaintext proof failing ....... test_bad_index_hash_blocks,
                                             test_encrypted_index_blocks
  * the output-path guard .................. test_out_path_inside_install_refused

The encryption verdict is what the milestone actually rests on, so it is tested from
both directions: a synthetic pak whose entries are all plaintext must NOT be reported
as encrypted (test_all_plain_pak_verdict), and one whose entries are all encrypted
must report zero readable payload entries (test_all_encrypted_pak_verdict). A test
suite that only ever asserted "encrypted" would pass against a decoder that had the
bit hard-wired.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _path in (os.path.join(REPO_ROOT, "tools", "content"),
              os.path.join(REPO_ROOT, "tools", "fingerprint"),
              os.path.join(REPO_ROOT, "tools", "inventory")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import pak_index  # noqa: E402
import pathguard  # noqa: E402

PAK_MAGIC = 0x5A6F12E1
PAK_VERSION = 11
AES = 16
LOCAL_HEADER = 53          # v11, uncompressed: 8+8+8+20+4+1+4


def align(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def fstring(text: str, wide: bool = False) -> bytes:
    """FString on the wire. Count INCLUDES the NUL; negative count means UTF-16LE.

    Written from String.cpp.inl:1763-1847, not from the reader in pak_index.
    """
    if text == "":
        return struct.pack("<i", 0)
    if wide:
        body = (text + "\x00").encode("utf-16-le")
        return struct.pack("<i", -(len(text) + 1)) + body
    return struct.pack("<i", len(text) + 1) + (text + "\x00").encode("ascii")


class Entry:
    """One file to put in the synthetic pak. Payload is filler, never real content."""

    def __init__(self, path: str, size: int, *, encrypted: bool = False,
                 method: int = 0, block_size: int = 0, blocks: int = 0,
                 force_64bit: bool = False, wide_path: bool = False):
        self.path = path
        self.size = size                  # the Size field: compressed length
        self.uncompressed_size = size if method == 0 else size * 2
        self.encrypted = encrypted
        self.method = method
        self.block_size = block_size
        self.blocks = blocks
        self.force_64bit = force_64bit
        self.wide_path = wide_path
        self.offset = 0                   # filled in by build_pak

    @property
    def on_disk_payload(self) -> int:
        return align(self.size, AES) if self.encrypted else self.size

    def block_lengths(self) -> list[int]:
        """Per-block compressed lengths that sum to Size, as the writer would emit."""
        if self.blocks <= 0:
            return []
        base = self.size // self.blocks
        lengths = [base] * self.blocks
        lengths[-1] += self.size - base * self.blocks
        return lengths

    def local_header(self) -> bytes:
        """FPakEntry::Serialize, H:495-544, written independently of the tool.

        Offset is 0 in the local copy (the packer stores offsets only in the index,
        PakFileUtilities.cpp:2749-2750). Field order: Offset, Size,
        UncompressedSize, CompressionMethodIndex, Hash[20], [blocks], Flags,
        CompressionBlockSize.
        """
        raw = struct.pack("<qqq", 0, self.size, self.uncompressed_size)
        raw += struct.pack("<I", self.method)
        raw += bytes(range(20))
        if self.method != 0:
            raw += struct.pack("<i", self.blocks)
            cursor = 0
            for length in self.block_lengths():
                raw += struct.pack("<qq", cursor, cursor + length)
                cursor += align(length, AES if self.encrypted else 1)
        raw += struct.pack("<B", (0x01 if self.encrypted else 0x00))
        raw += struct.pack("<I", self.block_size)
        return raw

    def encoded(self) -> bytes:
        """FPakFile::EncodePakEntry, C:6952-7090, written from the field table.

        Independent of ``decode_pak_entry``: the bit positions come from the comment
        at C:7094-7101 and the assembly at C:7023-7031, and the presence rules for
        the optional fields come from C:7036-7086.
        """
        offset_safe = (not self.force_64bit) and self.offset <= 0xFFFFFFFF
        size_safe = (not self.force_64bit) and self.size <= 0xFFFFFFFF
        uncompressed_safe = (not self.force_64bit) and self.uncompressed_size <= 0xFFFFFFFF

        packed = 0
        if self.blocks > 1:
            packed = (self.block_size >> 11) & 0x3F
            if (packed << 11) != self.block_size:
                packed = 0x3F

        word = 0
        word |= (1 << 31) if offset_safe else 0
        word |= (1 << 30) if uncompressed_safe else 0
        word |= (1 << 29) if size_safe else 0
        word |= self.method << 23
        word |= (1 << 22) if self.encrypted else 0
        word |= self.blocks << 6
        word |= packed

        raw = struct.pack("<I", word)
        if packed == 0x3F:
            raw += struct.pack("<I", self.block_size)
        raw += (struct.pack("<I", self.offset) if offset_safe
                else struct.pack("<q", self.offset))
        raw += (struct.pack("<I", self.uncompressed_size) if uncompressed_safe
                else struct.pack("<q", self.uncompressed_size))
        if self.method != 0:
            raw += (struct.pack("<I", self.size) if size_safe
                    else struct.pack("<q", self.size))
            if self.blocks > 1 or (self.blocks == 1 and self.encrypted):
                for length in self.block_lengths():
                    raw += struct.pack("<I", length)
        return raw


def build_pak(entries: list[Entry], *, mount: str = "../../../",
              encrypted_index: bool = False, corrupt_index_hash: bool = False,
              alignment: int = 1, unencodable: int = 0,
              declared_num_entries: int | None = None,
              inject_gap: int = 0) -> bytes:
    """Assemble a whole pak: payload area, three index blobs, footer.

    The layout is written from the engine source, not from the tool: payload area
    first (each entry a local header followed by its payload bytes, with the payload
    padded to the AES block when encrypted), then the primary index, then the
    path-hash index, then the full directory index, then the footer.
    """
    body = bytearray()
    for entry in entries:
        if alignment > 1:
            while len(body) % alignment:
                body.append(0)
        entry.offset = len(body)
        body += entry.local_header()
        body += bytes((index * 7 + 3) & 0xFF for index in range(entry.on_disk_payload))

    # encoded entry blob, and the location each path resolves to
    encoded = bytearray()
    locations: dict[str, int] = {}
    for entry in entries:
        if inject_gap:
            encoded += bytes(inject_gap)
        locations[entry.path] = len(encoded)
        encoded += entry.encoded()

    # full directory index: TMap<FString, TMap<FString, int32>>
    grouped: dict[str, list[Entry]] = {}
    for entry in entries:
        directory = entry.path.rsplit("/", 1)[0] + "/" if "/" in entry.path else "/"
        grouped.setdefault(directory, []).append(entry)
    directory_index = bytearray(struct.pack("<i", len(grouped)))
    for directory, group in grouped.items():
        directory_index += fstring(directory)
        directory_index += struct.pack("<i", len(group))
        for entry in group:
            name = entry.path.rsplit("/", 1)[-1]
            directory_index += fstring(name, wide=entry.wide_path)
            directory_index += struct.pack("<i", locations[entry.path])

    # path-hash index: a TMap<uint64, int32>, contents irrelevant to this reader
    path_hash_index = bytearray(struct.pack("<i", len(entries)))
    for index, entry in enumerate(entries):
        path_hash_index += struct.pack("<Qi", 0x1000 + index, locations[entry.path])

    # The primary index has to name the file offsets of the two secondary blobs, and
    # those depend on its own length, so it is built once to measure and once for
    # real. Written this way rather than with a patch-up so the second build is a
    # genuine build.
    def primary(path_hash_offset: int, directory_offset: int) -> bytes:
        raw = bytearray()
        raw += fstring(mount)
        raw += struct.pack("<i", len(entries) if declared_num_entries is None
                           else declared_num_entries)
        raw += struct.pack("<Q", 0x4E5F46A0)
        raw += struct.pack("<i", 1)
        raw += struct.pack("<qq", path_hash_offset, len(path_hash_index))
        raw += hashlib.sha1(bytes(path_hash_index)).digest()
        raw += struct.pack("<i", 1)
        raw += struct.pack("<qq", directory_offset, len(directory_index))
        raw += hashlib.sha1(bytes(directory_index)).digest()
        raw += struct.pack("<i", len(encoded))
        raw += bytes(encoded)
        raw += struct.pack("<i", unencodable)
        return bytes(raw)

    probe_length = len(primary(0, 0))
    index_offset = len(body)
    path_hash_offset = index_offset + probe_length
    directory_offset = path_hash_offset + len(path_hash_index)
    primary_index = primary(path_hash_offset, directory_offset)
    assert len(primary_index) == probe_length

    index_hash = hashlib.sha1(primary_index).digest()
    if corrupt_index_hash:
        index_hash = bytes((index_hash[0] ^ 0xFF,)) + index_hash[1:]

    footer = bytearray()
    footer += bytes(16)                                    # EncryptionKeyGuid
    footer += struct.pack("<B", 1 if encrypted_index else 0)
    footer += struct.pack("<I", PAK_MAGIC)
    footer += struct.pack("<i", PAK_VERSION)
    footer += struct.pack("<qq", index_offset, len(primary_index))
    footer += index_hash
    footer += bytes(32 * 5)                                # CompressionMethods table

    return bytes(body) + primary_index + bytes(path_hash_index) + bytes(directory_index) + bytes(footer)


def write_pak(directory: str, name: str, data: bytes) -> str:
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def analyze(data: bytes, **kwargs) -> dict:
    """Build, write and read one synthetic pak in a temporary directory."""
    with tempfile.TemporaryDirectory() as tmp:
        path = write_pak(tmp, "synthetic.pak", data)
        return pak_index.analyze(path, install_root=tmp, **kwargs)


def entry_by_path(document: dict, path: str) -> dict:
    for entry in document["_entries_for_paths"]:
        if entry["path"] == path:
            return entry
    raise AssertionError("no entry %r in the document" % path)


# --------------------------------------------------------------------------- #
# the bitfield round trip -- every shape, including the ones the real file lacks
# --------------------------------------------------------------------------- #

class DecodeRoundTripTests(unittest.TestCase):

    def _roundtrip(self, entry: Entry) -> dict:
        document = analyze(build_pak([entry]))
        self.assertEqual(document["summary"]["verdict"] != "BLOCKED", True,
                         document["summary"])
        return entry_by_path(document, entry.path)

    def test_roundtrip_plain(self):
        entry = Entry("Content/a.ini", 1234)
        decoded = self._roundtrip(entry)
        self.assertFalse(decoded["encrypted"])
        self.assertEqual(decoded["size"], 1234)
        self.assertEqual(decoded["uncompressed_size"], 1234)
        self.assertEqual(decoded["compression_method_index"], 0)
        # Size is NOT on the wire for an uncompressed entry (C:7151/7170); the
        # decoder must derive it, and the record length proves it did not read one.
        self.assertEqual(decoded["encoded_length"], 12)

    def test_roundtrip_encrypted(self):
        entry = Entry("Content/a.ini", 1234, encrypted=True)
        decoded = self._roundtrip(entry)
        self.assertTrue(decoded["encrypted"])
        self.assertEqual(decoded["flag_word"] & (1 << 22), 1 << 22)
        self.assertEqual(decoded["encoded_length"], 12)

    def test_roundtrip_compressed_multi_block(self):
        entry = Entry("Content/big.uasset", 40000, method=2, blocks=3,
                      block_size=65536)
        decoded = self._roundtrip(entry)
        self.assertEqual(decoded["compression_method_index"], 2)
        self.assertEqual(decoded["compression_block_count"], 3)
        self.assertEqual(decoded["compression_block_size"], 65536)
        self.assertEqual(len(decoded["block_sizes"]), 3)
        self.assertEqual(sum(decoded["block_sizes"]), 40000)
        # 4 word + 4 offset + 4 uncompressed + 4 size + 3*4 blocks
        self.assertEqual(decoded["encoded_length"], 28)

    def test_single_unencrypted_block_stores_nothing(self):
        """C:7079 -- one unencrypted block writes no array; C:7201 derives it."""
        entry = Entry("Content/one.uasset", 900, method=1, blocks=1, block_size=65536)
        decoded = self._roundtrip(entry)
        self.assertEqual(decoded["compression_block_count"], 1)
        self.assertEqual(decoded["block_sizes"], [])
        self.assertEqual(decoded["encoded_length"], 16)
        # C:7187-7189 -- a single block reuses UncompressedSize as the block size.
        self.assertEqual(decoded["compression_block_size"], decoded["uncompressed_size"])

    def test_single_encrypted_block_stores_array(self):
        """C:7079 -- one ENCRYPTED block DOES write the array. The asymmetry that a
        remembered layout gets wrong, and that shifts every following field."""
        entry = Entry("Content/one.uasset", 900, method=1, blocks=1, block_size=65536,
                      encrypted=True)
        decoded = self._roundtrip(entry)
        self.assertEqual(decoded["block_sizes"], [900])
        self.assertEqual(decoded["encoded_length"], 20)

    def test_block_size_escape_field(self):
        """A block size that is not a 6-bit multiple of 2048 goes in its own field."""
        entry = Entry("Content/odd.uasset", 30000, method=1, blocks=4, block_size=100000)
        decoded = self._roundtrip(entry)
        self.assertTrue(decoded["block_size_field_present"])
        self.assertEqual(decoded["compression_block_size"], 100000)
        self.assertEqual(decoded["flag_word"] & 0x3F, 0x3F)

    def test_block_size_packed_when_representable(self):
        entry = Entry("Content/even.uasset", 30000, method=1, blocks=4, block_size=2048 * 5)
        decoded = self._roundtrip(entry)
        self.assertFalse(decoded["block_size_field_present"])
        self.assertEqual(decoded["compression_block_size"], 2048 * 5)

    def test_roundtrip_64bit_fields(self):
        """The 64-bit paths (C:7133, C:7146, C:7162) that a 32-bit-only file hides."""
        entry = Entry("Content/huge.bin", 5000, method=1, blocks=2, block_size=2048,
                      force_64bit=True)
        decoded = self._roundtrip(entry)
        self.assertEqual(decoded["size"], 5000)
        self.assertEqual(decoded["uncompressed_size"], 10000)
        # 4 word + 8 offset + 8 uncompressed + 8 size + 2*4 blocks
        self.assertEqual(decoded["encoded_length"], 36)

    def test_wide_fstring_path(self):
        entry = Entry("Content/кирилл.ini", 64)
        entry.wide_path = True
        document = analyze(build_pak([entry]))
        self.assertEqual(
            [item["path"] for item in document["_entries_for_paths"]], [entry.path])


# --------------------------------------------------------------------------- #
# the encryption verdict, from BOTH directions
# --------------------------------------------------------------------------- #

class EncryptionVerdictTests(unittest.TestCase):

    def test_all_plain_pak_verdict(self):
        """A pak of plaintext entries must NOT be reported as encrypted.

        Guards against a decoder with the bit hard-wired, which a suite that only
        ever asserted "encrypted" would happily accept.
        """
        entries = [Entry("Content/a%d.ini" % index, 100 + index) for index in range(5)]
        document = analyze(build_pak(entries))
        self.assertEqual(document["summary"]["verdict"], "NO_ENTRY_ENCRYPTED")
        self.assertEqual(document["entries"]["encrypted"], 0)
        self.assertEqual(document["entries"]["unencrypted"], 5)
        self.assertEqual(document["readable_within_d02"][
            "entries_whose_flag_says_plaintext"], 5)
        self.assertEqual(document["probes"]["layout_probe"]["verdict"],
                         "SUPPORTS_PLAINTEXT")
        self.assertEqual(document["probes"]["local_header_probe"][
            "flags_byte_census"], {"0x00": 5})

    def test_all_encrypted_pak_verdict(self):
        entries = [Entry("Content/a%d.ini" % index, 100 + index, encrypted=True)
                   for index in range(5)]
        document = analyze(build_pak(entries))
        self.assertEqual(document["summary"]["verdict"], "ALL_ENTRIES_ENCRYPTED")
        self.assertEqual(document["entries"]["encrypted"], 5)
        self.assertEqual(document["readable_within_d02"][
            "entries_whose_flag_says_plaintext"], 0)
        self.assertEqual(document["readable_within_d02"]["payloads_read_by_this_run"], 0)
        self.assertEqual(document["probes"]["layout_probe"]["verdict"],
                         "SUPPORTS_ENCRYPTED")
        self.assertEqual(document["probes"]["local_header_probe"][
            "flags_byte_census"], {"0x01": 5})

    def test_mixed_pak_verdict(self):
        entries = [Entry("Content/a.ini", 100, encrypted=True),
                   Entry("Content/b.ini", 200)]
        document = analyze(build_pak(entries))
        self.assertEqual(document["summary"]["verdict"], "MIXED")
        self.assertEqual(document["entries"]["encrypted"], 1)
        self.assertEqual(document["entries"]["unencrypted"], 1)

    def test_local_header_probe_catches_a_disagreeing_flag(self):
        """Flip the local header's flags byte on disk and the cross-check must notice.

        This is the probe earning its place: if it could not detect a disagreement,
        its agreement would mean nothing.
        """
        entries = [Entry("Content/a.ini", 100, encrypted=True)]
        data = bytearray(build_pak(entries))
        data[entries[0].offset + 48] = 0x00        # Flags byte, H:495-544
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pak(tmp, "tampered.pak", bytes(data))
            document = pak_index.analyze(path, install_root=tmp)
        self.assertEqual(document["probes"]["local_header_probe"][
            "disagree_with_index"], 1)
        self.assertFalse(document["summary"]["probes_agree"])


# --------------------------------------------------------------------------- #
# probes
# --------------------------------------------------------------------------- #

class ProbeTests(unittest.TestCase):

    def test_tiling_probe_exact_on_a_well_formed_pak(self):
        entries = [Entry("Content/a%d.ini" % index, 64 + index) for index in range(6)]
        document = analyze(build_pak(entries))
        tiling = document["probes"]["encoded_blob_tiling"]
        self.assertTrue(tiling["tiles_exactly"])
        self.assertEqual(tiling["gaps"], 0)
        self.assertEqual(tiling["overlaps"], 0)

    def test_tiling_probe_detects_gap(self):
        """Padding between encoded records must show up as a gap, not be smoothed."""
        entries = [Entry("Content/a%d.ini" % index, 64 + index) for index in range(4)]
        document = analyze(build_pak(entries, inject_gap=4))
        tiling = document["probes"]["encoded_blob_tiling"]
        self.assertFalse(tiling["tiles_exactly"])
        self.assertGreater(tiling["gaps"], 0)
        self.assertFalse(document["summary"]["probes_agree"])

    def test_layout_probe_tolerates_alignment_and_still_supports_encrypted(self):
        entries = [Entry("Content/a%d.ini" % index, 300 + index * 97, encrypted=True)
                   for index in range(8)]
        document = analyze(build_pak(entries, alignment=2048))
        layout = document["probes"]["layout_probe"]
        self.assertEqual(layout["padded_model_overlaps_next_entry"], 0)
        self.assertEqual(layout["gaps_explained_exactly_by_unpadded_model"], 0)
        self.assertEqual(layout["gaps_explained_by_nothing"], [])
        self.assertEqual(layout["verdict"], "SUPPORTS_ENCRYPTED")
        self.assertIn("2048", layout["remaining_gaps_explained_by_next_offset_alignment"])

    def test_flag_word_census_lists_every_distinct_word(self):
        entries = [Entry("Content/a.ini", 100, encrypted=True),
                   Entry("Content/b.ini", 100, encrypted=True),
                   Entry("Content/c.ini", 100)]
        document = analyze(build_pak(entries))
        census = document["probes"]["entry_flag_word_census"]
        self.assertEqual(census["distinct_flag_words"], 2)
        self.assertFalse(census["refuted"])
        counts = {row["flag_word_hex"]: row["count"] for row in census["flag_words"]}
        self.assertEqual(sorted(counts.values()), [1, 2])

    def test_flag_word_census_refuses_an_unnameable_method(self):
        """A compression method index the footer cannot name refutes the decode.

        The footer of these synthetic paks carries an EMPTY method table, so any
        non-zero index is unnameable -- which is exactly the shape a wrong mask
        produces, and it must not pass silently.
        """
        entries = [Entry("Content/a.uasset", 900, method=3, blocks=2, block_size=2048)]
        document = analyze(build_pak(entries))
        census = document["probes"]["entry_flag_word_census"]
        self.assertTrue(census["refuted"])
        self.assertEqual(census["unnameable_compression_method_indices"], [3])
        self.assertFalse(document["summary"]["probes_agree"])


# --------------------------------------------------------------------------- #
# the D-02 plaintext proof
# --------------------------------------------------------------------------- #

class PlaintextProofTests(unittest.TestCase):

    def test_good_pak_proves_plaintext_for_all_three_blobs(self):
        document = analyze(build_pak([Entry("Content/a.ini", 100)]))
        verdicts = {proof["blob"]: proof["verdict"]
                    for proof in document["plaintext_proofs"]}
        self.assertEqual(verdicts, {"primary_index": "PLAINTEXT_PROVEN",
                                    "path_hash_index": "PLAINTEXT_PROVEN",
                                    "full_directory_index": "PLAINTEXT_PROVEN"})

    def test_bad_index_hash_blocks(self):
        """A stored hash that does not match the raw bytes must BLOCK, not proceed."""
        document = analyze(build_pak([Entry("Content/a.ini", 100)],
                                     corrupt_index_hash=True))
        self.assertEqual(document["summary"]["verdict"], "BLOCKED")
        self.assertNotIn("entries", document)
        self.assertEqual(document["plaintext_proofs"][0]["verdict"], "NOT_PROVEN")

    def test_encrypted_index_blocks(self):
        """bEncryptedIndex set must BLOCK even when the raw bytes happen to hash.

        That combination is a contradiction and is reported as one rather than
        reconciled: under D-02 the tool does not try to work out which half to
        believe.
        """
        document = analyze(build_pak([Entry("Content/a.ini", 100)],
                                     encrypted_index=True))
        self.assertEqual(document["summary"]["verdict"], "BLOCKED")
        self.assertEqual(document["plaintext_proofs"][0]["verdict"], "CONTRADICTORY")

    def test_blocked_document_reads_no_payload_and_names_no_entry(self):
        document = analyze(build_pak([Entry("Content/a.ini", 100)],
                                     corrupt_index_hash=True))
        self.assertNotIn("content", document)
        self.assertNotIn("readable_within_d02", document)
        self.assertIn("D-02", document["payload_policy"])


# --------------------------------------------------------------------------- #
# FPakEntryLocation, and the shapes this reader refuses
# --------------------------------------------------------------------------- #

class LocationTests(unittest.TestCase):

    def test_location_classification(self):
        classify = pak_index.PakEntryLocation.classify
        self.assertEqual(classify(0), ("encoded_offset", 0))
        self.assertEqual(classify(12), ("encoded_offset", 12))
        self.assertEqual(classify(pak_index.PakEntryLocation.MAX_INDEX),
                         ("encoded_offset", pak_index.PakEntryLocation.MAX_INDEX))
        self.assertEqual(classify(-1), ("list_index", 0))
        self.assertEqual(classify(-5), ("list_index", 4))
        self.assertEqual(classify(pak_index.PakEntryLocation.MIN_INT32)[0], "invalid")

    def test_unencodable_entries_are_refused(self):
        """A pak with unencodable FPakEntry records must fail loudly, not partially.

        Reporting 4 of 5 entries as if it were all of them is the failure mode this
        refusal exists to prevent.
        """
        with self.assertRaises(pak_index.ContainerParseError) as caught:
            analyze(build_pak([Entry("Content/a.ini", 100)], unencodable=2))
        self.assertIn("unencodable", str(caught.exception))

    def test_declared_num_entries_mismatch_warns(self):
        document = analyze(build_pak([Entry("Content/a.ini", 100)],
                                     declared_num_entries=7))
        self.assertTrue(any("NumEntries" in warning
                            for warning in document["warnings"]), document["warnings"])


# --------------------------------------------------------------------------- #
# FString reading
# --------------------------------------------------------------------------- #

class FStringTests(unittest.TestCase):

    def test_ansi_and_wide(self):
        reader = pak_index.ArchiveReader(fstring("abc") + fstring("de", wide=True), "t")
        self.assertEqual(reader.fstring(), "abc")
        self.assertEqual(reader.fstring(), "de")
        self.assertEqual(reader.remaining(), 0)

    def test_empty(self):
        reader = pak_index.ArchiveReader(struct.pack("<i", 0), "t")
        self.assertEqual(reader.fstring(), "")

    def test_absurd_length_refused(self):
        reader = pak_index.ArchiveReader(struct.pack("<i", 1 << 30), "t")
        with self.assertRaises(pak_index.ContainerParseError):
            reader.fstring()

    def test_embedded_nul_refused(self):
        """A path with an interior NUL is corruption, not something to tidy away."""
        raw = struct.pack("<i", 5) + b"a\x00b\x00\x00"
        reader = pak_index.ArchiveReader(raw, "t")
        with self.assertRaises(pak_index.ContainerParseError):
            reader.fstring()

    def test_truncated_read_refused(self):
        reader = pak_index.ArchiveReader(b"\x01\x02", "t")
        with self.assertRaises(pak_index.ContainerParseError):
            reader.int32()


# --------------------------------------------------------------------------- #
# classification of the path list
# --------------------------------------------------------------------------- #

class ClassificationTests(unittest.TestCase):

    def test_extension_histogram_and_roots(self):
        entries = [Entry("Engine/Config/a.ini", 10), Entry("Engine/Config/b.ini", 20),
                   Entry("Game/Content/c.png", 30), Entry("Game/d", 40)]
        document = analyze(build_pak(entries))
        histogram = {row["extension"]: row["files"]
                     for row in document["content"]["extension_histogram"]}
        self.assertEqual(histogram, {".ini": 2, ".png": 1, "(none)": 1})
        roots = {row["root"]: row["files"]
                 for row in document["content"]["top_level_roots"]}
        self.assertEqual(roots, {"Engine": 2, "Game": 2})

    def test_cooked_assets_are_found_when_present(self):
        entries = [Entry("Game/Content/a.uasset", 100),
                   Entry("Game/Content/a.uexp", 200, encrypted=True),
                   Entry("Game/Content/b.ini", 10)]
        document = analyze(build_pak(entries))
        content = document["content"]
        self.assertEqual(content["cooked_asset_count"], 2)
        found = {item["path"]: item["encrypted"] for item in content["cooked_assets_found"]}
        self.assertEqual(found, {"Game/Content/a.uasset": False,
                                 "Game/Content/a.uexp": True})

    def test_no_cooked_asset_reported_as_zero_not_omitted(self):
        document = analyze(build_pak([Entry("Engine/Config/a.ini", 10)]))
        self.assertEqual(document["content"]["cooked_asset_count"], 0)
        self.assertEqual(document["content"]["cooked_assets_found"], [])
        # A negative must be a statement about a NAMED surface, not an absence.
        self.assertIn(".usmap", document["content"]["cooked_asset_extensions_looked_for"])

    def test_two_directory_counts_are_distinct_numbers(self):
        """The index counts directory records; the classifier counts directories that
        hold files. Reporting one number for both would be wrong for one of them."""
        entries = [Entry("A/B/C/x.ini", 10), Entry("A/y.ini", 20)]
        document = analyze(build_pak(entries))
        self.assertEqual(document["content"]["distinct_directories_containing_files"], 2)
        self.assertEqual(document["index"]["directory_index"]["directory_count"], 2)
        self.assertTrue(document["index"]["directory_index"]["fully_consumed"])


# --------------------------------------------------------------------------- #
# the two evidence layers
# --------------------------------------------------------------------------- #

class EvidenceLayerTests(unittest.TestCase):

    def setUp(self):
        entries = [Entry("Content/a%d.ini" % index, 100 + index, encrypted=True)
                   for index in range(4)]
        self.document = analyze(build_pak(entries), literal_samples=3)

    def test_literal_claims_state_offset_and_length_and_name_nothing(self):
        for read in self.document["literal_reads"]:
            claim = read["claim"]
            self.assertIn("at offset %d" % read["offset"], claim)
            self.assertIn("%d byte" % read["length"], claim)
            self.assertEqual(read["evidence"]["claim_class"], "P")
            self.assertEqual(read["evidence"]["evidence_level"], "OBSERVED")
            # A class-P claim must not name a field, a type or a layout.
            for forbidden in ("FPakEntry", "flag", "encrypted", "header", "index"):
                self.assertNotIn(forbidden, claim)

    def test_literal_reads_are_reproduced(self):
        self.assertTrue(self.document["literal_reads_reproduced"])
        for read in self.document["literal_reads"]:
            self.assertTrue(read["reproduced"])
            self.assertIn("read a second time", read["evidence"]["note"])

    def test_literal_bytes_match_the_file_at_the_stated_offset(self):
        """The addressing arithmetic, checked outside the tool.

        The tool's own confirming re-read caught this being wrong by four bytes
        once; this test is the standing version of that catch.
        """
        entries = [Entry("Content/a%d.ini" % index, 100 + index, encrypted=True)
                   for index in range(4)]
        data = build_pak(entries)
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pak(tmp, "s.pak", data)
            document = pak_index.analyze(path, install_root=tmp, literal_samples=3)
        for read in document["literal_reads"]:
            actual = data[read["offset"]:read["offset"] + read["length"]]
            self.assertEqual(pak_index.hex_bytes(actual), read["bytes_hex"],
                             "%s at %d" % (read["decoded_field"], read["offset"]))

    def test_literal_sample_cap_is_honoured(self):
        kinds = {}
        for read in self.document["literal_reads"]:
            kinds[read["decoded_field"]] = kinds.get(read["decoded_field"], 0) + 1
        self.assertLessEqual(kinds.get("encoded_entry_record", 0), 3)
        self.assertLessEqual(kinds.get("entry_local_header", 0), 3)

    def test_decoded_layer_is_class_i_and_capped_below_the_literal_layer(self):
        evidence = self.document["decoded_evidence"]
        self.assertEqual(evidence["claim_class"], "I")
        self.assertEqual(evidence["evidence_level"], "INFERRED")
        self.assertLess(evidence["confidence"], pak_index.CONFIDENCE_LITERAL)
        self.assertGreaterEqual(evidence["confidence"], 0.80)
        self.assertEqual(len(evidence["sources"]), 2)
        self.assertIn("external-doc", evidence["oracle"])
        self.assertIn("container-metadata", evidence["oracle"])

    def test_decoded_annotation_fits_the_reduced_annotation_schema(self):
        """additionalProperties: false over seven keys. An extra key would make the
        validator read the object as a full record and demand a build_key it has no
        room for -- which is exactly the defect this assertion pins."""
        allowed = {"claim_class", "confidence", "evidence_level", "note", "oracle",
                   "read_locus", "sources"}
        self.assertTrue(set(self.document["decoded_evidence"]).issubset(allowed),
                        set(self.document["decoded_evidence"]) - allowed)
        for read in self.document["literal_reads"]:
            self.assertTrue(set(read["evidence"]).issubset(allowed),
                            set(read["evidence"]) - allowed)

    def test_no_confidence_reaches_the_forbidden_ceiling(self):
        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "confidence":
                        self.assertLessEqual(value, 0.99)
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)
        walk(self.document)


# --------------------------------------------------------------------------- #
# determinism, safety and the CLI
# --------------------------------------------------------------------------- #

class OutputTests(unittest.TestCase):

    def test_document_is_deterministic_apart_from_the_timestamp(self):
        data = build_pak([Entry("Content/a%d.ini" % index, 50 + index)
                          for index in range(3)])
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pak(tmp, "s.pak", data)
            first = pak_index.analyze(path, install_root=tmp)
            second = pak_index.analyze(path, install_root=tmp)
        first.pop("generated_at")
        second.pop("generated_at")
        self.assertEqual(pak_index.dump_json(pak_index._strip_private(first)),
                         pak_index.dump_json(pak_index._strip_private(second)))

    def test_dumped_json_carries_no_private_keys(self):
        data = build_pak([Entry("Content/a.ini", 50)])
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pak(tmp, "s.pak", data)
            document = pak_index.analyze(path, install_root=tmp)
        text = pak_index.dump_json(pak_index._strip_private(document))
        parsed = json.loads(text)
        self.assertNotIn("_entries_for_paths", parsed)
        self.assertTrue(text.endswith("\n"))

    def test_paths_text_lists_every_entry_with_its_flag(self):
        entries = [Entry("Content/b.ini", 50, encrypted=True),
                   Entry("Content/a.ini", 60)]
        data = build_pak(entries)
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pak(tmp, "s.pak", data)
            document = pak_index.analyze(path, install_root=tmp)
        body = pak_index.paths_text(document, document["_entries_for_paths"])
        rows = [line for line in body.splitlines() if not line.startswith("#")]
        self.assertEqual(len(rows), 2)
        self.assertIn("Content/a.ini", rows[0])       # sorted by path
        self.assertTrue(rows[1].split()[2] == "E")    # b.ini is the encrypted one

    def test_cli_runs_and_writes(self):
        data = build_pak([Entry("Content/a.ini", 50, encrypted=True)])
        # Two temp trees on purpose.  The pak lives in the one declared as the
        # installation; the output lives OUTSIDE it.  Writing the output inside
        # the declared install root is what test_out_path_inside_install_refused
        # below asserts must fail, so doing it here too would have made the two
        # tests contradict each other -- and the guard, not the fixture, would
        # have looked broken.
        with tempfile.TemporaryDirectory() as tmp, \
                tempfile.TemporaryDirectory() as outside:
            path = write_pak(tmp, "s.pak", data)
            out = os.path.join(outside, "out", "doc.json")
            paths_out = os.path.join(outside, "out", "paths.txt")
            os.makedirs(os.path.dirname(out))
            code = pak_index.main([path, "--install-dir", tmp, "--out", out,
                                   "--paths-out", paths_out])
            self.assertEqual(code, 0)
            with open(out, encoding="utf-8") as handle:
                document = json.load(handle)
            self.assertEqual(document["summary"]["verdict"], "ALL_ENTRIES_ENCRYPTED")
            self.assertTrue(os.path.exists(paths_out))

    def test_out_path_inside_install_refused(self):
        """plan.md 1.5 layer 1 / D-01: nothing is written inside an installation.

        The guard is pathguard's, not this tool's; what is tested here is that the
        tool actually calls it before opening anything.
        """
        for root in pathguard.CONFIGURED_INSTALL_ROOTS:
            if os.path.isdir(root):
                install_root = root
                break
        else:
            self.skipTest("no configured installation root on this machine")
        data = build_pak([Entry("Content/a.ini", 50)])
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pak(tmp, "s.pak", data)
            target = os.path.join(install_root, "pak-index-should-not-exist.json")
            code = pak_index.main([path, "--install-dir", install_root, "--out", target])
            self.assertEqual(code, 2)
            self.assertFalse(os.path.exists(target))

    def test_cli_rejects_negative_sample_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pak(tmp, "s.pak", build_pak([Entry("Content/a.ini", 50)]))
            self.assertEqual(pak_index.main([path, "--literal-samples", "-1"]), 2)
            self.assertEqual(pak_index.main([path, "--local-header-samples", "-1"]), 2)


# --------------------------------------------------------------------------- #
# helpers that carry an engine rule of their own
# --------------------------------------------------------------------------- #

class HelperTests(unittest.TestCase):

    def test_local_header_size_matches_the_engine_formula(self):
        # v11 uncompressed: 8+8+8+20 + 4 method + 1 flags + 4 block size
        self.assertEqual(pak_index.local_header_size(11, 0, 0), 53)
        # compressed adds sizeof(FPakCompressedBlock) * N + int32 (H:433-436)
        self.assertEqual(pak_index.local_header_size(11, 1, 3), 53 + 16 * 3 + 4)

    def test_align_up(self):
        self.assertEqual(pak_index.align_up(0, 16), 0)
        self.assertEqual(pak_index.align_up(1, 16), 16)
        self.assertEqual(pak_index.align_up(16, 16), 16)
        self.assertEqual(pak_index.align_up(17, 16), 32)

    def test_decompose_flag_word_matches_the_shipped_word(self):
        """0xE0400000 is the only flag word in the shipped container.

        The expected decomposition is written here from the comment at C:7094-7101,
        so this test would fail if the masks in the tool were changed to something
        that merely happened to agree with itself.
        """
        fields = pak_index.decompose_flag_word(0xE0400000)
        self.assertTrue(fields["bit31_offset_32bit_safe"])
        self.assertTrue(fields["bit30_uncompressed_size_32bit_safe"])
        self.assertTrue(fields["bit29_size_32bit_safe"])
        self.assertEqual(fields["bits28_23_compression_method_index"], 0)
        self.assertTrue(fields["bit22_encrypted"])
        self.assertEqual(fields["bits21_6_compression_block_count"], 0)
        self.assertEqual(fields["bits5_0_compression_block_size_packed"], 0)

    def test_decompose_rejects_the_remembered_mask_error(self):
        """The predecessor's guess read method 32 and encrypted out of this word.

        Method 32 would need bits 28..23 to be 0b100000, i.e. bit 28 set, and this
        word has bit 28 clear. Asserted explicitly so the wrong reading cannot come
        back unnoticed.
        """
        self.assertEqual((0xE0400000 >> 23) & 0x3F, 0)
        self.assertNotEqual((0xE0400000 >> 23) & 0x3F, 32)
        self.assertEqual(0xE0400000 & (1 << 28), 0)


if __name__ == "__main__":
    unittest.main()
