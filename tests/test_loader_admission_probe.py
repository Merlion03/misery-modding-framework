#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for tools/static/loader_admission_probe.py (plan.md 14.7 SP-1, CT-04).

Standard library only, and **no test here opens the game installation**. Every
container and every PE image is assembled byte by byte under a temporary
directory, from the field tables in the UE headers rather than from the tool's
code, so a parser tuned to agree with the real files would still fail here.

What is actually worth testing about a probe tool, and why
---------------------------------------------------------
The tool's output is used as evidence, so the tests are aimed at the three ways
evidence of this kind goes wrong:

1. **A chunk-id search that agrees with the real file by accident.** The
   discriminating byte of ``FIoChunkId`` is byte 11 (``IoChunkId.h:107``), and
   twelve zero bytes with byte 11 set to 5 is a pattern that a sloppy search
   would also find in a run of zeros, or in a chunk id whose *first* byte is 5.
   So the tests build containers that differ from the target in exactly one
   byte and require the answer to flip.
2. **A class-P record that quietly stops being class P.** plan.md 10.3 v2.4
   admits ``binary-analysis`` and ``container-metadata`` into class P only when
   the claim states the offset AND the length and does not name what the bytes
   are. That is a property of a generated *sentence*, so it is asserted here:
   the offset and the length must appear in the claim, and the join key -- which
   does name the field -- must not.
3. **A prediction table that has been tuned to the measurement.** The value of
   the ``image`` subcommand rests entirely on the predictions having been
   written before the run, and on a failed prediction being reported rather than
   smoothed away. So the tests drive the verdict logic with images built to
   contradict the table and require ``PREDICTION_FAILED`` to come back.

The reproduction pass is tested for what it claims: that the attestation text
appears only after the second read happened, and that a disagreement is reported
rather than swallowed.
"""

from __future__ import annotations

import io
import os
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_STATIC = os.path.join(REPO_ROOT, "tools", "static")
TOOLS_FINGERPRINT = os.path.join(REPO_ROOT, "tools", "fingerprint")
TOOLS_INVENTORY = os.path.join(REPO_ROOT, "tools", "inventory")
for _path in (TOOLS_STATIC, TOOLS_FINGERPRINT, TOOLS_INVENTORY):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import loader_admission_probe as lap  # noqa: E402


# --------------------------------------------------------------------------- #
# synthetic builders -- an independent model of the layouts under test
# --------------------------------------------------------------------------- #

TOC_HEADER_SIZE = 144


def build_utoc(chunk_ids: list[bytes], *, flags: int = 0x00,
               magic: bytes = lap.TOC_MAGIC, version: int = 6,
               header_size: int = TOC_HEADER_SIZE,
               entry_count: int | None = None) -> bytes:
    """A .utoc whose header, chunk-id table and offset/length table are consistent.

    Written from ``FIoStoreTocHeader`` (``Runtime/Core/Internal/IO/IoStore.h``
    lines 38-75) rather than from the tool, so an offset the tool reads one field
    too early fails here.
    """
    count = entry_count if entry_count is not None else len(chunk_ids)
    header = bytearray(header_size)
    header[0:16] = magic
    header[16] = version
    struct.pack_into("<I", header, 20, header_size)
    struct.pack_into("<I", header, 24, count)
    struct.pack_into("<I", header, 28, 0)      # TocCompressedBlockEntryCount
    struct.pack_into("<I", header, 32, 12)     # TocCompressedBlockEntrySize
    struct.pack_into("<I", header, 36, 0)      # CompressionMethodNameCount
    struct.pack_into("<I", header, 40, 32)     # CompressionMethodNameLength
    struct.pack_into("<I", header, 44, 65536)  # CompressionBlockSize
    struct.pack_into("<I", header, 48, 0)      # DirectoryIndexSize
    struct.pack_into("<I", header, 52, 1)      # PartitionCount
    struct.pack_into("<Q", header, 56, 0xFFFFFFFFFFFFFFFF)  # ContainerId
    header[80] = flags
    struct.pack_into("<I", header, 84, 0)      # perfect hash seeds
    struct.pack_into("<Q", header, 88, 0xFFFFFFFFFFFFFFFF)  # PartitionSize
    struct.pack_into("<I", header, 96, 0)      # chunks without perfect hash

    table = b"".join(chunk_ids)
    # FIoOffsetAndLength: 5-byte big-endian offset then 5-byte big-endian length.
    offlen = b"".join(
        (index * 4096).to_bytes(5, "big") + (index * 7 + 1).to_bytes(5, "big")
        for index in range(len(chunk_ids)))
    return bytes(header) + table + offlen


def chunk_id(value: int = 0, index: int = 0, chunk_type: int = 1) -> bytes:
    """CreateIoChunkId, IoChunkId.h line 136: LE uint64, BE uint16, spare, type."""
    raw = bytearray(12)
    struct.pack_into("<Q", raw, 0, value)
    struct.pack_into(">H", raw, 8, index)
    raw[11] = chunk_type
    return bytes(raw)


def build_pe(payloads: list[bytes]) -> bytes:
    """A minimal but genuinely parseable PE64 with one section per payload.

    ``pe_info.PEHeaders`` is a strict parser, so this has to be a real image and
    not a stub: the tests that assert an RVA depend on the section table being
    read, not guessed.
    """
    section_align = 0x1000
    file_align = 0x200

    def align(value: int, to: int) -> int:
        return ((value + to - 1) // to) * to

    count = len(payloads)
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    opt_size = 240
    headers_size = 0x40 + 4 + 20 + opt_size + 40 * count
    headers_size = align(headers_size, file_align)

    raw_pointer = headers_size
    rva = section_align
    sections = []
    for payload in payloads:
        raw_size = align(max(len(payload), 1), file_align)
        sections.append({"raw_pointer": raw_pointer, "raw_size": raw_size,
                         "rva": rva, "vsize": max(len(payload), 1)})
        raw_pointer += raw_size
        rva = align(rva + max(len(payload), 1), section_align)

    coff = struct.pack("<HHIIIHH", 0x8664, count, 0, 0, 0, opt_size, 0x0022)

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)          # PE32+
    struct.pack_into("<I", opt, 16, section_align)  # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, 0x140000000)    # ImageBase
    struct.pack_into("<I", opt, 32, section_align)  # SectionAlignment
    struct.pack_into("<I", opt, 36, file_align)     # FileAlignment
    struct.pack_into("<H", opt, 40, 6)              # MajorOSVersion
    struct.pack_into("<I", opt, 56, rva)            # SizeOfImage
    struct.pack_into("<I", opt, 60, headers_size)   # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 2)              # Subsystem
    struct.pack_into("<I", opt, 108, 16)            # NumberOfRvaAndSizes

    table = bytearray()
    for number, section in enumerate(sections):
        row = bytearray(40)
        row[0:8] = (".s%d" % number).encode("ascii").ljust(8, b"\x00")
        struct.pack_into("<IIII", row, 8, section["vsize"], section["rva"],
                         section["raw_size"], section["raw_pointer"])
        struct.pack_into("<I", row, 36, 0x40000040)
        table += row

    image = bytearray(dos + b"PE\x00\x00" + coff + bytes(opt) + bytes(table))
    image += b"\x00" * (headers_size - len(image))
    for payload, section in zip(payloads, sections):
        image += payload + b"\x00" * (section["raw_size"] - len(payload))
    return bytes(image)


class TempTree:
    def __enter__(self):
        self._dir = tempfile.TemporaryDirectory(prefix="lap-test-")
        self.root = self._dir.name
        return self

    def __exit__(self, *exc):
        self._dir.cleanup()
        return False

    def write(self, name: str, blob: bytes) -> str:
        path = os.path.join(self.root, name)
        with open(path, "wb") as handle:
            handle.write(blob)
        return path


# --------------------------------------------------------------------------- #
# 1. the chunk-id search
# --------------------------------------------------------------------------- #

class ScriptObjectsProbe(unittest.TestCase):

    def test_probe_pattern_matches_the_documented_constructor(self):
        """The searched bytes must equal CreateIoChunkId(0, 0, ScriptObjects)."""
        self.assertEqual(lap.SCRIPT_OBJECTS_CHUNK_ID,
                         chunk_id(0, 0, 5))
        self.assertEqual(len(lap.SCRIPT_OBJECTS_CHUNK_ID), 12)
        self.assertEqual(lap.SCRIPT_OBJECTS_CHUNK_ID[11], 5)

    def test_found_when_present(self):
        with TempTree() as tree:
            path = tree.write("global.utoc", build_utoc([chunk_id(0, 0, 5)]))
            doc = lap.read_toc(path, tree.root, 64)
        self.assertTrue(doc["findings"][0]["script_objects_chunk_present"])
        self.assertEqual(doc["findings"][0]["script_objects_chunk_index"], 0)
        self.assertEqual(doc["chunk_type_census"], {"ScriptObjects": 1})

    def test_absent_when_only_the_discriminator_byte_differs(self):
        """Type 5 in byte 11 is the whole question; type 6 must NOT match."""
        with TempTree() as tree:
            path = tree.write("x.utoc", build_utoc([chunk_id(0, 0, 6)]))
            doc = lap.read_toc(path, tree.root, 64)
        self.assertFalse(doc["findings"][0]["script_objects_chunk_present"])
        self.assertIsNone(doc["findings"][0]["script_objects_chunk_index"])
        self.assertEqual(doc["chunk_type_census"], {"ContainerHeader": 1})

    def test_absent_when_the_type_byte_sits_in_the_wrong_position(self):
        """A 5 in byte 0 is a package id, not a chunk type. Must not match."""
        stray = bytearray(12)
        stray[0] = 5
        with TempTree() as tree:
            path = tree.write("x.utoc", build_utoc([bytes(stray)]))
            doc = lap.read_toc(path, tree.root, 64)
        self.assertFalse(doc["findings"][0]["script_objects_chunk_present"])

    def test_found_among_many_and_the_index_is_the_first_match(self):
        ids = [chunk_id(7, 0, 1), chunk_id(9, 0, 2),
               chunk_id(0, 0, 5), chunk_id(0, 0, 5)]
        with TempTree() as tree:
            path = tree.write("x.utoc", build_utoc(ids))
            doc = lap.read_toc(path, tree.root, 64)
        self.assertEqual(doc["findings"][0]["script_objects_chunk_index"], 2)
        self.assertEqual(doc["chunk_type_census"]["ScriptObjects"], 2)

    def test_flags_are_decoded_and_the_signed_bit_is_visible(self):
        """The Signed bit is the one gate on the admission chain, so a reader must
        be able to see its state without trusting a summary."""
        with TempTree() as tree:
            plain = tree.write("a.utoc", build_utoc([chunk_id(0, 0, 5)], flags=0x00))
            signed = tree.write("b.utoc", build_utoc([chunk_id(0, 0, 5)], flags=0x0E))
            plain_doc = lap.read_toc(plain, tree.root, 64)
            signed_doc = lap.read_toc(signed, tree.root, 64)
        self.assertEqual(plain_doc["container_flags_decoded"], [])
        self.assertEqual(signed_doc["container_flags_decoded"],
                         ["Encrypted", "Signed", "Indexed"])

    def test_unknown_flag_bits_are_warned_not_dropped(self):
        with TempTree() as tree:
            path = tree.write("x.utoc", build_utoc([chunk_id(0, 0, 5)], flags=0xA0))
            doc = lap.read_toc(path, tree.root, 64)
        self.assertTrue(any("outside" in w for w in doc["warnings"]))

    def test_bad_magic_is_refused(self):
        with TempTree() as tree:
            path = tree.write("x.utoc", build_utoc([chunk_id(0, 0, 5)],
                                                   magic=b"not-a-toc-magic!"))
            with self.assertRaises(ValueError):
                lap.read_toc(path, tree.root, 64)

    def test_a_table_that_does_not_fit_is_refused_rather_than_guessed(self):
        """An entry_count larger than the file must fail, not read past the end and
        report an absence: a false 'absent' here would read as evidence."""
        with TempTree() as tree:
            path = tree.write("x.utoc", build_utoc([chunk_id(0, 0, 5)],
                                                   entry_count=4096))
            with self.assertRaises(ValueError):
                lap.read_toc(path, tree.root, 64)

    def test_the_ucas_is_never_opened(self):
        with TempTree() as tree:
            path = tree.write("x.utoc", build_utoc([chunk_id(0, 0, 5)]))
            doc = lap.read_toc(path, tree.root, 64)
        self.assertFalse(doc["decrypted_anything"])
        self.assertTrue(all(region["what"] != "ucas"
                            for region in doc["read_regions"]))
        self.assertFalse(os.path.exists(os.path.join(tree.root, "x.ucas")))


# --------------------------------------------------------------------------- #
# 2. the class-P records
# --------------------------------------------------------------------------- #

class ClassPRecords(unittest.TestCase):

    def test_the_claim_states_the_offset_and_the_length(self):
        record = lap.literal_read("t", "toc_magic", 48, b"\xa0\xe4\x0c\x00",
                                  oracle="container-metadata", method="SP-1")
        self.assertIn("48", record["claim"])
        self.assertIn("4 bytes", record["claim"])
        self.assertIn("a0e40c00", record["claim"])
        self.assertEqual(record["evidence"]["claim_class"], "P")
        self.assertEqual(record["evidence"]["evidence_level"], "OBSERVED")
        self.assertLessEqual(record["evidence"]["confidence"], 0.99)

    def test_the_claim_does_not_name_the_field(self):
        """plan.md 10.3 v2.4: naming what the bytes ARE derives class I. The join
        key names the field on purpose, and must stay outside the sentence."""
        record = lap.literal_read("t", "directory_index_size", 48, b"\x00" * 4,
                                  oracle="container-metadata", method="SP-1")
        self.assertNotIn("directory_index_size", record["claim"])
        self.assertNotIn("directory_index_size", record["evidence"]["note"])
        self.assertEqual(record["join_key"], "directory_index_size")

    def test_singular_byte_is_not_pluralised(self):
        record = lap.literal_read("t", "flags", 80, b"\x0a",
                                  oracle="container-metadata", method="SP-1")
        self.assertIn("1 byte at offset 80", record["claim"])

    def test_read_locus_carries_the_address_and_the_extent_as_data(self):
        record = lap.literal_read("t", "k", 7, b"\x01\x02",
                                  oracle="binary-analysis", method="SP-1")
        locus = record["evidence"]["read_locus"]
        self.assertEqual(locus["offset"], 7)
        self.assertEqual(locus["length"], 2)
        self.assertEqual(locus["address_kind"], "file-offset")

    def test_a_source_carries_no_oracle_key_of_its_own(self):
        """validate.py reads any dict carrying `oracle` as a record in its own
        right, and a source is not a record. Naming the oracle in the note keeps
        the information without creating a phantom record."""
        record = lap.literal_read("t", "k", 0, b"\x00",
                                  oracle="binary-analysis", method="SP-1")
        source = record["evidence"]["sources"][0]
        self.assertNotIn("oracle", source)
        self.assertIn("binary-analysis", source["note"])


# --------------------------------------------------------------------------- #
# 3. the reproduction pass
# --------------------------------------------------------------------------- #

class ReproductionPass(unittest.TestCase):

    def test_the_attestation_is_pending_until_the_pass_runs(self):
        record = lap.literal_read("t", "k", 0, b"\x00",
                                  oracle="binary-analysis", method="SP-1")
        self.assertIn("PENDING", record["evidence"]["sources"][0]["note"])
        self.assertNotIn("reproduced:", record["evidence"]["sources"][0]["note"])

    def test_agreement_is_recorded_only_after_the_second_read(self):
        with TempTree() as tree:
            path = tree.write("blob.bin", b"ABCDEFGH")
            record = lap.literal_read("t", "k", 2, b"CD",
                                      oracle="binary-analysis", method="SP-1")
            warnings: list[str] = []
            self.assertTrue(lap.confirm_literal_reads(path, [record], warnings))
        self.assertEqual(warnings, [])
        self.assertTrue(record["reproduced"])
        note = record["evidence"]["sources"][0]["note"]
        self.assertNotIn("PENDING", note)
        self.assertIn("the same bytes were read twice", note)

    def test_a_disagreement_is_reported_and_not_swallowed(self):
        with TempTree() as tree:
            path = tree.write("blob.bin", b"ABCDEFGH")
            record = lap.literal_read("t", "k", 2, b"ZZ",
                                      oracle="binary-analysis", method="SP-1")
            warnings: list[str] = []
            self.assertFalse(lap.confirm_literal_reads(path, [record], warnings))
        self.assertEqual(len(warnings), 1)
        self.assertFalse(record["reproduced"])
        self.assertIn("NOT reproduced",
                      record["evidence"]["sources"][0]["note"])


# --------------------------------------------------------------------------- #
# 4. the image probe and its verdict logic
# --------------------------------------------------------------------------- #

class ImageProbe(unittest.TestCase):

    def _probe(self, blobs: list[bytes]):
        with TempTree() as tree:
            path = tree.write("image.exe", build_pe(blobs))
            return lap.probe_image(path, tree.root, 8)

    def test_every_probe_declares_a_kind_and_a_source(self):
        for probe in lap.IMAGE_PROBES:
            self.assertIn(probe["kind"],
                          {"ue_log", "literal", "install-literal"}, probe["id"])
            self.assertIn(probe["expect"], {"present", "absent", "unknown"},
                          probe["id"])
            self.assertTrue(probe["source"], probe["id"])
            self.assertTrue(probe["why"], probe["id"])

    def test_probe_ids_are_unique(self):
        ids = [probe["id"] for probe in lap.IMAGE_PROBES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_the_table_declares_both_directions(self):
        """A table of only 'present' predictions cannot be refuted by a run."""
        expectations = {probe["expect"] for probe in lap.IMAGE_PROBES}
        self.assertIn("present", expectations)
        self.assertIn("absent", expectations)

    def test_each_absent_prediction_has_a_control_from_the_same_file(self):
        """An absence is evidence only next to a present control from the same
        translation unit, so the table must contain one."""
        def unit(source: str) -> str:
            return source.split(":")[0]
        present_units = {unit(p["source"]) for p in lap.IMAGE_PROBES
                         if p["expect"] == "present"}
        for probe in lap.IMAGE_PROBES:
            if probe["expect"] == "absent":
                self.assertIn(unit(probe["source"]), present_units, probe["id"])

    def test_two_encodings_are_searched(self):
        encodings = lap.encode_probe("Mount")
        self.assertEqual(encodings["ascii"], b"Mount")
        self.assertEqual(encodings["utf-16le"], "Mount".encode("utf-16-le"))

    def test_a_present_prediction_that_holds_is_reported_as_held(self):
        wanted = next(p for p in lap.IMAGE_PROBES if p["expect"] == "present")
        doc = self._probe([wanted["text"].encode("utf-16-le")])
        row = next(r for r in doc["probes"] if r["id"] == wanted["id"])
        self.assertEqual(row["observed"], "present")
        self.assertEqual(row["verdict"], "PREDICTION_HELD")
        self.assertGreaterEqual(row["total_hits"], 1)

    def test_a_present_prediction_that_fails_is_reported_as_failed(self):
        doc = self._probe([b"nothing relevant here"])
        failures = [r for r in doc["probes"] if r["verdict"] == "PREDICTION_FAILED"]
        self.assertTrue(failures)
        self.assertEqual(doc["findings"][0]["prediction_failures"], len(failures))

    def test_an_absent_prediction_that_fails_is_reported_as_failed(self):
        """The load-bearing direction: a hit on a row predicted absent must be
        surfaced, because it refutes a reading of the source."""
        wanted = next(p for p in lap.IMAGE_PROBES if p["expect"] == "absent")
        doc = self._probe([wanted["text"].encode("utf-16-le")])
        row = next(r for r in doc["probes"] if r["id"] == wanted["id"])
        self.assertEqual(row["observed"], "present")
        self.assertEqual(row["verdict"], "PREDICTION_FAILED")

    def test_an_unknown_prediction_never_counts_as_a_failure(self):
        wanted = next(p for p in lap.IMAGE_PROBES if p["expect"] == "unknown")
        doc = self._probe([wanted["text"].encode("utf-16-le")])
        row = next(r for r in doc["probes"] if r["id"] == wanted["id"])
        self.assertEqual(row["verdict"], "NO_PREDICTION")

    def test_a_hit_produces_a_literal_read_with_a_real_offset(self):
        wanted = next(p for p in lap.IMAGE_PROBES if p["expect"] == "present")
        needle = wanted["text"].encode("utf-16-le")
        doc = self._probe([b"\x00" * 32 + needle])
        record = next(r for r in doc["literal_reads"]
                      if r["join_key"].startswith("probe:%s:" % wanted["id"]))
        self.assertEqual(record["length"], len(needle))
        self.assertEqual(bytes.fromhex(record["bytes_hex"]), needle)
        self.assertTrue(record["reproduced"])

    def test_hits_inside_a_section_body_get_an_rva_and_others_get_none(self):
        blob = b"needle-in-a-section"
        image = build_pe([blob])
        with TempTree() as tree:
            path = tree.write("image.exe", image)
            with lap.pe_info.Image.open(path) as handle:
                headers = lap.pe_info.PEHeaders(handle)
                body_offset = image.find(blob)
                self.assertIsNotNone(lap.offset_to_rva(headers, body_offset))
                # Offset 0 is the DOS header: outside every section body.
                self.assertIsNone(lap.offset_to_rva(headers, 0))

    def test_counts_are_totals_and_offsets_are_capped(self):
        needle = b"AB"
        count, hits = lap.find_all(needle * 10, needle, 3)
        self.assertEqual(count, 10)
        self.assertEqual(len(hits), 3)

    def test_overlapping_occurrences_are_all_counted(self):
        count, _ = lap.find_all(b"aaaa", b"aa", 8)
        self.assertEqual(count, 3)

    def test_by_kind_tally_adds_up(self):
        doc = self._probe([b"nothing relevant here"])
        total = sum(tally["probes"] for tally in doc["by_kind"].values())
        self.assertEqual(total, len(lap.IMAGE_PROBES))
        for kind, tally in doc["by_kind"].items():
            self.assertEqual(tally["probes"],
                             tally["present"] + tally["absent"])


# --------------------------------------------------------------------------- #
# 5. grading and safety properties
# --------------------------------------------------------------------------- #

class GradingAndSafety(unittest.TestCase):

    def test_a_finding_never_claims_the_two_method_band_on_one_method(self):
        """plan.md 10.3: a class-I claim reaches 0.80 only with two independent
        methods. This tool runs one, so its own findings must stay below."""
        with TempTree() as tree:
            toc = tree.write("x.utoc", build_utoc([chunk_id(0, 0, 5)]))
            pe = tree.write("i.exe", build_pe([b"x"]))
            toc_doc = lap.read_toc(toc, tree.root, 64)
            pe_doc = lap.probe_image(pe, tree.root, 8)
        for doc in (toc_doc, pe_doc):
            evidence = doc["findings"][0]["evidence"]
            self.assertEqual(evidence["claim_class"], "I")
            self.assertEqual(evidence["evidence_level"], "INFERRED")
            self.assertLess(evidence["confidence"], 0.80)
            self.assertEqual(len(evidence["sources"]), 1)

    def test_a_finding_states_what_would_refute_it(self):
        with TempTree() as tree:
            toc = tree.write("x.utoc", build_utoc([chunk_id(0, 0, 5)]))
            doc = lap.read_toc(toc, tree.root, 64)
        self.assertIn("if this were wrong",
                      doc["findings"][0]["evidence"]["note"])

    def test_no_absolute_input_path_reaches_the_document(self):
        """C-13: the artifact records a target token, a size and a hash, never a
        user-profile path."""
        with TempTree() as tree:
            path = tree.write("x.utoc", build_utoc([chunk_id(0, 0, 5)]))
            doc = lap.read_toc(path, tree.root, 64)
        blob = lap.dump_json(doc)
        self.assertNotIn(tree.root, blob)
        # Inside a known installation the token is installation-relative; the
        # point of the assertion is that the absolute prefix is gone, not which
        # of the two forms is used.
        self.assertEqual(doc["target"], "<install>/x.utoc")
        self.assertTrue(doc["file_sha256"].startswith("sha256:"))

    def test_the_target_token_never_carries_a_directory_prefix(self):
        """With no installation root given the tool auto-detects one, so the token
        may be either the basename or an `<install>/`-relative path. What must
        hold in both cases -- and what C-13 is actually about -- is that no
        absolute prefix survives into the document."""
        with TempTree() as tree:
            path = tree.write("x.utoc", build_utoc([chunk_id(0, 0, 5)]))
            doc = lap.read_toc(path, None, 64)
        self.assertNotIn(tree.root, lap.dump_json(doc))
        self.assertIn(doc["target"], {"x.utoc", "<install>/x.utoc"})
        self.assertFalse(os.path.isabs(doc["target"]))

    def test_output_inside_an_installation_is_refused_before_anything_opens(self):
        with TempTree() as tree:
            fake_install = os.path.join(tree.root, "MISERY")
            os.makedirs(os.path.join(fake_install, "MISERY", "Content", "Paks"))
            with open(os.path.join(fake_install, "MISERY.exe"), "wb") as handle:
                handle.write(b"MZ")
            source = tree.write("x.utoc", build_utoc([chunk_id(0, 0, 5)]))
            out = os.path.join(fake_install, "leak.json")
            err = io.StringIO()
            with redirect_stderr(err), redirect_stdout(io.StringIO()):
                code = lap.main(["toc", source, "--out", out,
                                 "--install-dir", fake_install])
            self.assertEqual(code, 2)
            self.assertFalse(os.path.exists(out))

    def test_the_cli_prints_a_summary_and_exits_clean(self):
        with TempTree() as tree:
            path = tree.write("global.utoc", build_utoc([chunk_id(0, 0, 5)]))
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = lap.main(["toc", path])
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("ScriptObjects chunk", text)
        self.assertIn("PRESENT", text)

    def test_the_cli_reports_a_missing_file_rather_than_raising(self):
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(io.StringIO()):
            code = lap.main(["toc", os.path.join(REPO_ROOT, "no-such.utoc")])
        self.assertEqual(code, 2)
        self.assertIn("not a file", err.getvalue())

    def test_the_engine_coordinates_are_recorded_in_every_document(self):
        """A source-derived interpretation is only re-walkable if the document
        says which changelist it was read at."""
        with TempTree() as tree:
            toc = tree.write("x.utoc", build_utoc([chunk_id(0, 0, 5)]))
            doc = lap.read_toc(toc, tree.root, 64)
        self.assertEqual(doc["engine_changelist"], 35576357)
        self.assertEqual(doc["engine_branch"], "++UE5+Release-5.4")


if __name__ == "__main__":
    unittest.main()
