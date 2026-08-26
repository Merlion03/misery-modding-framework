#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for tools/content/package_summary.py and tools/content/iostore_chunks.py.

Standard library only, and **no test here opens the game installation or the
reference cook on D:**. Every package and every container is built byte by byte in
this file, under a temporary directory, so the suite runs on a machine that has
never seen MISERY and has never run a cook.

That is the point of the synthetic builders below: they are an INDEPENDENT
implementation of the layout the readers assume, written from the field table in
each reader's docstring rather than from its code, and the round trip
build -> parse is what catches a field read at the wrong offset. A test that
re-ran the reader over the real cook output and asserted whatever it printed
would prove nothing.

What is covered, and why each case exists:
  * a cooked package WITHOUT PKG_UnversionedProperties -- export map entries are
    112 bytes wide because ScriptSerialization{Start,End}Offset are written
    (ObjectResource.cpp:208-212), and the payload is a tagged-property chain
  * the same package WITH the flag -- 96-byte entries, and the payload is an
    FUnversionedHeader fragment stream
  * the stride measured from the summary offsets, which must NOT be derived from
    the flag it is used to check: the regression guarded here is the first version
    of the reader, where `agrees_with_package_flag` could not fail
  * a fragment stream decoded into schema indices, including the +1 shift that the
    CK-04 experiment measured
  * the refusal to read anything inside an installation tree
  * the SHAPE of every emitted evidence block against
    research/schema/kb-record.schema.json#/$defs/annotation -- the regression
    guarded here is a grading block that the knowledge-base validator read as a
    whole record and rejected
  * an IoStore TOC census: per-type counts, the block-count model, and a
    directory index that is read when plaintext and refused when the Encrypted
    flag is set
"""

from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _path in (os.path.join(REPO_ROOT, "tools", "content"),
              os.path.join(REPO_ROOT, "tools", "fingerprint"),
              os.path.join(REPO_ROOT, "tools", "inventory")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import container_info as ci  # noqa: E402
import iostore_chunks as ioc  # noqa: E402
import package_summary as ps  # noqa: E402
import pathguard  # noqa: E402

SCHEMA_PATH = Path(REPO_ROOT) / "research" / "schema" / "kb-record.schema.json"

PACKAGE_TAG = 0x9E2A83C1
LEGACY_VERSION = -8
UE4_VERSION = 522
UE5_VERSION = 1012
PKG_COOKED = 0x00000200
PKG_UNVERSIONED_PROPERTIES = 0x00002000
PKG_FILTER_EDITOR_ONLY = 0x80000000


# --------------------------------------------------------------------------- #
# synthetic cooked package -- an independent model of the layout
# --------------------------------------------------------------------------- #

def _fstring(text: str) -> bytes:
    raw = text.encode("ascii") + b"\x00"
    return struct.pack("<i", len(raw)) + raw


def _name_entry(text: str) -> bytes:
    """FString plus the two uint16 hashes the engine reads and discards."""
    return _fstring(text) + struct.pack("<HH", 0, 0)


def _engine_version_zero() -> bytes:
    return struct.pack("<HHHI", 0, 0, 0, 0) + struct.pack("<i", 0)


def build_cooked_package(
    *,
    unversioned_properties: bool,
    names: list[str],
    exports: list[dict],
    imports: int = 1,
    versioned_header: bool = False,
) -> tuple[bytes, bytes]:
    """A cooked .uasset header plus its .uexp, self-consistent by construction.

    ``exports`` entries carry ``name_index`` and ``payload`` (raw bytes). The
    export map is written with the width the *flag* implies, which is exactly the
    property the reader must not assume: the reader measures it from the offsets.
    """
    name_blob = b"".join(_name_entry(text) for text in names)
    import_blob = b""
    for index in range(imports):
        import_blob += struct.pack("<ii", 0, 0)          # ClassPackage FName
        import_blob += struct.pack("<ii", 0, 0)          # ClassName FName
        import_blob += struct.pack("<i", 0)              # OuterIndex
        import_blob += struct.pack("<ii", index % max(len(names), 1), 0)  # ObjectName
        import_blob += struct.pack("<i", 0)              # bImportOptional
    entry_width = 96 if unversioned_properties else 112

    flags = PKG_COOKED | PKG_FILTER_EDITOR_ONLY
    if unversioned_properties:
        flags |= PKG_UNVERSIONED_PROPERTIES

    # Two passes: the offsets depend on the sizes, and the sizes on nothing else.
    def assemble(total_header_size: int) -> tuple[bytes, bytes]:
        head = bytearray()
        head += struct.pack("<I", PACKAGE_TAG)
        head += struct.pack("<i", LEGACY_VERSION)
        head += struct.pack("<i", 864 if versioned_header else 0)     # LegacyUE3Version
        head += struct.pack("<i", UE4_VERSION if versioned_header else 0)
        head += struct.pack("<i", UE5_VERSION if versioned_header else 0)
        head += struct.pack("<i", 0)                                   # licensee
        head += struct.pack("<i", 0)                                   # custom versions
        head += struct.pack("<i", total_header_size)
        head += _fstring("None")                                       # PackageName
        head += struct.pack("<I", flags)
        summary_fixed_start = len(head)
        # placeholders; filled once the offsets are known
        head += b"\x00" * (4 * 2)          # NameCount, NameOffset
        head += b"\x00" * (4 * 2)          # SoftObjectPaths pair
        head += b"\x00" * (4 * 2)          # GatherableTextData pair
        head += b"\x00" * (4 * 2)          # ExportCount, ExportOffset
        head += b"\x00" * (4 * 2)          # ImportCount, ImportOffset
        head += b"\x00" * 4                # DependsOffset
        head += b"\x00" * (4 * 2)          # SoftPackageReferences pair
        head += b"\x00" * 4                # SearchableNamesOffset
        head += b"\x00" * 4                # ThumbnailTableOffset
        head += b"\x00" * 16               # Guid
        head += struct.pack("<i", 0)       # GenerationCount
        head += _engine_version_zero()     # SavedByEngineVersion
        head += _engine_version_zero()     # CompatibleWithEngineVersion
        head += struct.pack("<I", 0)       # CompressionFlags
        head += struct.pack("<i", 0)       # CompressedChunks count
        head += struct.pack("<I", 0)       # PackageSource
        head += struct.pack("<i", 0)       # AdditionalPackagesToCook count
        head += struct.pack("<i", 0)       # AssetRegistryDataOffset
        head += struct.pack("<q", 0)       # BulkDataStartOffset
        head += struct.pack("<i", 0)       # WorldTileInfoDataOffset
        head += struct.pack("<i", 0)       # ChunkIDs count
        head += struct.pack("<ii", 0, 0)   # PreloadDependency pair
        head += struct.pack("<i", len(names))   # NamesReferencedFromExportData
        head += struct.pack("<q", -1)      # PayloadTocOffset
        head += struct.pack("<i", -1)      # DataResourceOffset

        name_offset = len(head)
        import_offset = name_offset + len(name_blob)
        export_offset = import_offset + len(import_blob)
        depends_offset = export_offset + entry_width * len(exports)
        header_size = depends_offset

        fixed = struct.pack(
            "<iiiiiiiiiiiiii",
            len(names), name_offset,
            0, import_offset,          # SoftObjectPaths count/offset
            0, 0,                      # GatherableTextData count/offset
            len(exports), export_offset,
            imports, import_offset,
            depends_offset,
            0, 0,                      # SoftPackageReferences count/offset
            0,                         # SearchableNamesOffset
        ) + struct.pack("<i", 0)       # ThumbnailTableOffset
        head[summary_fixed_start:summary_fixed_start + len(fixed)] = fixed
        struct.pack_into("<i", head, 28, header_size)   # TotalHeaderSize slot

        export_blob = bytearray()
        payload = bytearray()
        for entry in exports:
            serial_offset = header_size + len(payload)
            payload += entry["payload"]
            export_blob += struct.pack("<iiii", -1, 0, -1, 0)          # class/super/template/outer
            export_blob += struct.pack("<ii", entry["name_index"], 0)  # ObjectName
            export_blob += struct.pack("<I", 0x00000009)               # ObjectFlags
            export_blob += struct.pack("<qq", len(entry["payload"]), serial_offset)
            export_blob += struct.pack("<iii", 0, 0, 0)                # three bools
            export_blob += struct.pack("<i", 0)                        # bIsInheritedInstance
            export_blob += struct.pack("<I", 0)                        # PackageFlags
            export_blob += struct.pack("<iii", 0, 1, 0)                # 3 more bools
            export_blob += struct.pack("<iiiii", 0, 0, 0, 0, 0)        # 5 dependency ints
            if not unversioned_properties:
                export_blob += struct.pack("<qq", 0, len(entry["payload"]))
        assert len(export_blob) == entry_width * len(exports)
        return bytes(head) + name_blob + import_blob + bytes(export_blob), bytes(payload)

    uasset, uexp = assemble(0)
    return uasset, uexp


def write_package(directory: str, stem: str, uasset: bytes, uexp: bytes) -> str:
    path = os.path.join(directory, stem + ".uasset")
    with open(path, "wb") as handle:
        handle.write(uasset)
    with open(os.path.join(directory, stem + ".uexp"), "wb") as handle:
        handle.write(uexp)
    return path


def fragment(skip: int, values: int, *, has_zeroes: bool = False, last: bool = False) -> bytes:
    packed = (skip & 0x7F) | (0x0080 if has_zeroes else 0) | (values << 9) \
        | (0x0100 if last else 0)
    return struct.pack("<H", packed)


# --------------------------------------------------------------------------- #
# synthetic IoStore TOC with controlled chunk ids
# --------------------------------------------------------------------------- #

def build_utoc(
    *,
    chunks: list[tuple[int, int, int, int]],
    blocks: list[tuple[int, int, int, int]],
    block_size: int = 65536,
    flags: int = 0x00,
    directory_index: bytes = b"",
    method_names: tuple[str, ...] = (),
    version: int = 6,
) -> bytes:
    """chunks: (id_value, type, offset, length). blocks: (offset, csize, usize, method)."""
    header = bytearray(ci.TOC_HEADER_SIZE_EXPECTED)
    header[0:16] = ci.TOC_MAGIC
    header[16] = version
    struct.pack_into("<I", header, 20, ci.TOC_HEADER_SIZE_EXPECTED)
    struct.pack_into("<I", header, 24, len(chunks))
    struct.pack_into("<I", header, 28, len(blocks))
    struct.pack_into("<I", header, 32, 12)
    struct.pack_into("<I", header, 36, len(method_names))
    struct.pack_into("<I", header, 40, 32)
    struct.pack_into("<I", header, 44, block_size)
    struct.pack_into("<I", header, 48, len(directory_index))
    struct.pack_into("<I", header, 52, 1)
    struct.pack_into("<Q", header, 56, 0xFFFFFFFFFFFFFFFF)
    header[80] = flags
    struct.pack_into("<I", header, 84, 0)          # seeds
    struct.pack_into("<Q", header, 88, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<I", header, 96, 0)          # without perfect hash

    body = bytearray()
    for id_value, chunk_type, _offset, _length in chunks:
        entry = bytearray(12)
        struct.pack_into("<Q", entry, 0, id_value)
        struct.pack_into(">H", entry, 8, 0)
        entry[11] = chunk_type
        body += entry
    for _id, _type, offset, length in chunks:
        body += offset.to_bytes(5, "big") + length.to_bytes(5, "big")
    for offset, csize, usize, method in blocks:
        entry = bytearray(12)
        struct.pack_into("<Q", entry, 0, offset & ((1 << 40) - 1))
        struct.pack_into("<I", entry, 4,
                         struct.unpack_from("<I", entry, 4)[0] | ((csize & 0xFFFFFF) << 8))
        struct.pack_into("<I", entry, 8, (usize & 0xFFFFFF) | (method << 24))
        body += entry
    for name in method_names:
        slot = bytearray(32)
        slot[0:len(name)] = name.encode("ascii")
        body += slot
    body += directory_index
    meta = ci.IO_CHUNK_META_SIZE_IOHASH if version >= ci.TOC_VERSION_IO_HASH_META \
        else ci.IO_CHUNK_META_SIZE_HASH32
    body += bytes(len(chunks) * meta)
    return bytes(header) + bytes(body)


def build_directory_index(mount: str, files: list[tuple[str, int]]) -> bytes:
    """One flat directory holding `files` as (name, chunk index) pairs."""
    strings = [name for name, _ in files]
    blob = bytearray()
    blob += _fstring(mount)
    blob += struct.pack("<i", 1)                  # one directory entry
    blob += struct.pack("<4I", 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    blob += struct.pack("<i", len(files))
    for index, (_name, user_data) in enumerate(files):
        next_file = index + 1 if index + 1 < len(files) else 0xFFFFFFFF
        blob += struct.pack("<3I", index, next_file, user_data)
    blob += struct.pack("<i", len(strings))
    for text in strings:
        blob += _fstring(text)
    return bytes(blob)


# --------------------------------------------------------------------------- #
# tests: package_summary
# --------------------------------------------------------------------------- #

NAMES = ["None", "Default__Thing_C", "InitialLifeSpan", "Thing_C"]


class PackageSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _unversioned(self) -> str:
        payload = (fragment(41, 2) + fragment(11, 1, last=True)
                   + struct.pack("<ff", 22.5, 2.5) + struct.pack("<f", 1.0))
        uasset, uexp = build_cooked_package(
            unversioned_properties=True, names=NAMES,
            exports=[{"name_index": 1, "payload": payload}])
        return write_package(self.tmp, "unversioned", uasset, uexp)

    def _versioned(self) -> str:
        payload = struct.pack("<ii", 2, 0) + b"\x00" * 12   # FName then filler
        uasset, uexp = build_cooked_package(
            unversioned_properties=False, names=NAMES,
            exports=[{"name_index": 1, "payload": payload}])
        return write_package(self.tmp, "versioned", uasset, uexp)

    def test_summary_reads_the_flag_and_the_counts(self) -> None:
        report = ps.read_package(self._unversioned())
        summary = report["summary"]
        self.assertEqual(summary["tag"], "0x9E2A83C1")
        self.assertTrue(summary["uses_unversioned_properties"])
        self.assertIn("PKG_UnversionedProperties", summary["package_flags_decoded"])
        self.assertEqual(summary["name_count"], len(NAMES))
        self.assertEqual(summary["export_count"], 1)
        self.assertTrue(summary["header_saved_unversioned"])
        self.assertEqual(report["names"]["entries"], NAMES)

    def test_versioned_header_versions_are_read_not_assumed(self) -> None:
        uasset, uexp = build_cooked_package(
            unversioned_properties=False, names=NAMES, versioned_header=True,
            exports=[{"name_index": 1, "payload": struct.pack("<ii", 0, 0)}])
        path = write_package(self.tmp, "versioned_header", uasset, uexp)
        summary = ps.read_package(path)["summary"]
        self.assertFalse(summary["header_saved_unversioned"])
        self.assertEqual(summary["file_version_ue4"], UE4_VERSION)
        self.assertEqual(summary["file_version_ue5"], UE5_VERSION)
        self.assertFalse(summary["effective_versions_assumed"])

    def test_export_stride_is_96_without_the_script_offsets(self) -> None:
        report = ps.read_package(self._unversioned())
        stride = report["export_entry_stride"]
        self.assertEqual(stride["measured_from_summary_offsets"], 96)
        self.assertEqual(stride["expected_from_package_flag"], 96)
        self.assertTrue(stride["agrees_with_package_flag"])

    def test_export_stride_is_112_with_them(self) -> None:
        report = ps.read_package(self._versioned())
        stride = report["export_entry_stride"]
        self.assertEqual(stride["measured_from_summary_offsets"], 112)
        self.assertEqual(stride["expected_from_package_flag"], 112)
        self.assertTrue(stride["agrees_with_package_flag"])

    def test_stride_measurement_is_independent_of_the_flag(self) -> None:
        """The regression: a stride derived from the flag can never contradict it.

        Here the file carries 112-byte entries but the flag CLAIMS unversioned. A
        measurement that consults the flag reports 96 and 'agrees'; the offset
        arithmetic reports 112 and disagrees, which is the only useful answer.
        """
        uasset, uexp = build_cooked_package(
            unversioned_properties=False, names=NAMES,
            exports=[{"name_index": 1, "payload": struct.pack("<ii", 0, 0)}])
        patched = bytearray(uasset)
        report_before = ps.read_package(write_package(self.tmp, "honest", bytes(patched), uexp))
        flags_offset = report_before["summary"]["summary_bytes_consumed"]
        # locate the PackageFlags field by searching for its exact value
        needle = struct.pack("<I", PKG_COOKED | PKG_FILTER_EDITOR_ONLY)
        index = patched.find(needle)
        self.assertGreater(index, 0, "PackageFlags not found in the synthetic header")
        struct.pack_into("<I", patched, index,
                         PKG_COOKED | PKG_FILTER_EDITOR_ONLY | PKG_UNVERSIONED_PROPERTIES)
        path = write_package(self.tmp, "lying_flag", bytes(patched), uexp)
        report = ps.read_package(path)
        self.assertTrue(report["summary"]["uses_unversioned_properties"])
        self.assertEqual(report["export_entry_stride"]["measured_from_summary_offsets"], 112)
        self.assertEqual(report["export_entry_stride"]["expected_from_package_flag"], 96)
        self.assertFalse(report["export_entry_stride"]["agrees_with_package_flag"])
        self.assertIn("skipped", report["probes"])
        del flags_offset

    def test_unversioned_payload_decodes_to_schema_indices(self) -> None:
        report = ps.read_package(self._unversioned())
        probe = report["probes"]["entries"][0]
        self.assertEqual(probe["shape"], "unversioned-fragments")
        header = probe["unversioned_header"]
        self.assertEqual(header["fragment_count"], 2)
        self.assertEqual(header["schema_indices_touched"], [[41, 42], [54, 54]])
        self.assertEqual(header["header_bytes"], 4)

    def test_one_more_skip_shifts_every_index_by_one(self) -> None:
        """The CK-04 shape, in miniature: SkipNum + 1 moves all indices by one."""
        payload = (fragment(42, 2) + fragment(11, 1, last=True)
                   + struct.pack("<ff", 22.5, 2.5) + struct.pack("<f", 1.0))
        uasset, uexp = build_cooked_package(
            unversioned_properties=True, names=NAMES,
            exports=[{"name_index": 1, "payload": payload}])
        path = write_package(self.tmp, "shifted", uasset, uexp)
        header = ps.read_package(path)["probes"]["entries"][0]["unversioned_header"]
        self.assertEqual(header["schema_indices_touched"], [[42, 43], [55, 55]])

    def test_versioned_payload_names_its_first_property(self) -> None:
        report = ps.read_package(self._versioned())
        probe = report["probes"]["entries"][0]
        self.assertEqual(probe["shape"], "versioned-tagged-properties")
        self.assertEqual(probe["first_property_tag_name"], "InitialLifeSpan")

    def test_bad_magic_is_refused(self) -> None:
        path = os.path.join(self.tmp, "notapackage.uasset")
        with open(path, "wb") as handle:
            handle.write(b"\x00" * 512)
        with self.assertRaises(ps.ParseError):
            ps.read_package(path)

    def test_package_inside_an_installation_is_refused(self) -> None:
        root = os.path.join(self.tmp, "FakeInstall")
        for marker in pathguard.INSTALL_MARKERS:
            full = os.path.join(root, marker)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as handle:
                handle.write(b"marker")
        self.assertTrue(pathguard.looks_like_install_root(root))
        inside = os.path.join(root, "MISERY", "Content")
        os.makedirs(inside, exist_ok=True)
        uasset, uexp = build_cooked_package(
            unversioned_properties=True, names=NAMES,
            exports=[{"name_index": 1, "payload": fragment(0, 0, last=True)}])
        path = write_package(inside, "refused", uasset, uexp)
        with self.assertRaises(SystemExit):
            ps.read_package(path)


# --------------------------------------------------------------------------- #
# tests: iostore_chunks
# --------------------------------------------------------------------------- #

class IoStoreChunkTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, blob: bytes, ucas_size: int | None = None) -> str:
        path = os.path.join(self.tmp, name + ".utoc")
        with open(path, "wb") as handle:
            handle.write(blob)
        if ucas_size is not None:
            with open(os.path.join(self.tmp, name + ".ucas"), "wb") as handle:
                handle.write(b"\x00" * ucas_size)
        return path

    def test_type_census_and_block_model(self) -> None:
        chunks = [
            (0x1111, 1, 0, 65536),        # ExportBundleData, exactly one block
            (0x2222, 1, 65536, 100),      # ExportBundleData, one partial block
            (0x3333, 2, 131072, 131073),  # BulkData, three blocks
            (0x4444, 5, 262144, 10),      # ScriptObjects
        ]
        blocks = [(0, 100, 100, 0)] * 6   # 1 + 1 + 3 + 1 = 6
        path = self._write("census", build_utoc(chunks=chunks, blocks=blocks), ucas_size=1024)
        report = ioc.census(path)
        by_type = report["census"]["by_type"]
        self.assertEqual(by_type["ExportBundleData"]["count"], 2)
        self.assertEqual(by_type["ExportBundleData"]["bytes"], 65636)
        self.assertEqual(by_type["BulkData"]["count"], 1)
        self.assertEqual(by_type["ScriptObjects"]["count"], 1)
        self.assertEqual(report["checks"]["block_count_predicted_from_chunk_lengths"], 6)
        self.assertTrue(report["checks"]["uncompressed_block_model_holds"])

    def test_block_model_fails_loudly_when_the_count_disagrees(self) -> None:
        chunks = [(0x1111, 1, 0, 65536)]
        blocks = [(0, 10, 10, 0)] * 5     # five blocks for one 64 KiB chunk
        path = self._write("wrong", build_utoc(chunks=chunks, blocks=blocks))
        report = ioc.census(path)
        self.assertEqual(report["checks"]["block_count_predicted_from_chunk_lengths"], 1)
        self.assertEqual(report["checks"]["block_count_in_header"], 5)
        self.assertFalse(report["checks"]["uncompressed_block_model_holds"])

    def test_unknown_chunk_type_is_named_not_hidden(self) -> None:
        path = self._write("weird", build_utoc(chunks=[(1, 200, 0, 1)],
                                               blocks=[(0, 1, 1, 0)]))
        report = ioc.census(path)
        self.assertIn("Unknown(200)", report["census"]["by_type"])

    def test_plaintext_directory_index_names_the_chunks(self) -> None:
        chunks = [(0xAA, 1, 0, 10), (0xBB, 2, 16, 10)]
        index = build_directory_index("../../../", [("Thing.uasset", 0), ("Thing.ubulk", 1)])
        path = self._write("named", build_utoc(chunks=chunks, blocks=[(0, 10, 10, 0)] * 2,
                                               flags=0x08, directory_index=index))
        report = ioc.census(path)
        directory = report["directory_index"]
        self.assertEqual(directory["mount_point"], "../../../")
        self.assertEqual(directory["named_chunk_count"], 2)
        self.assertEqual(directory["extension_histogram"], {".uasset": 1, ".ubulk": 1})

    def test_encrypted_directory_index_is_not_touched(self) -> None:
        chunks = [(0xAA, 1, 0, 10)]
        path = self._write("sealed", build_utoc(chunks=chunks, blocks=[(0, 10, 10, 0)],
                                                flags=0x0A, directory_index=b"\xde" * 64))
        report = ioc.census(path)
        self.assertFalse(report["directory_index"]["readable"])
        self.assertIn("Encrypted", report["directory_index"]["reason"])
        self.assertTrue(report["header"]["encrypted"])

    def test_bad_magic_is_refused(self) -> None:
        path = self._write("bogus", b"\x00" * 400)
        with self.assertRaises(ioc.ChunkParseError):
            ioc.census(path)

    def test_no_literal_layer_is_emitted_here(self) -> None:
        """The literal layer belongs to container_info.py; this module must not
        emit a second, separately graded copy of the same bytes."""
        path = self._write("layers", build_utoc(chunks=[(1, 1, 0, 8)],
                                                blocks=[(0, 8, 8, 0)]))
        report = ioc.census(path)
        self.assertNotIn("literal_reads", report)
        self.assertIn("container_info", report["literal_layer"])


# --------------------------------------------------------------------------- #
# tests: the shape of every evidence block both readers emit
# --------------------------------------------------------------------------- #

class EvidenceShapeTests(unittest.TestCase):
    """The regression guarded here cost 502 validator violations once.

    A grading block that does not match kb-record.schema.json#/$defs/annotation is
    read by tools/kb/validate.py as a WHOLE knowledge-base record, which then
    demands claim_type and build_key that the annotation shape forbids. So the
    keys are checked against the schema itself, not against a copy of them.
    """

    @classmethod
    def setUpClass(cls) -> None:
        with open(SCHEMA_PATH, encoding="utf-8") as handle:
            schema = json.load(handle)
        annotation = schema["$defs"]["annotation"]
        cls.allowed = set(annotation["properties"])
        cls.required = set(annotation["required"])
        cls.levels = set(schema["$defs"]["evidence_level"]["enum"])
        # the oracle vocabulary is expressed as anyOf/const so each value can carry
        # its own description; the set of consts IS the closed list
        cls.oracles = {branch["const"] for branch in schema["$defs"]["oracle"]["anyOf"]}

    def _check(self, block: dict, where: str) -> None:
        self.assertTrue(self.required <= set(block), "%s misses %s"
                        % (where, self.required - set(block)))
        self.assertTrue(set(block) <= self.allowed, "%s has extra key(s) %s"
                        % (where, set(block) - self.allowed))
        self.assertIn(block["evidence_level"], self.levels, where)
        for oracle in block.get("oracle", []):
            self.assertIn(oracle, self.oracles, where)
        confidence = block.get("confidence")
        if confidence is not None:
            self.assertLess(confidence, 1.00, where)
            if confidence >= 0.80:
                self.assertGreaterEqual(len(block.get("sources", [])), 2,
                                        "%s: EV-03 wants two methods at >= 0.80" % where)
        for source in block.get("sources", []):
            self.assertNotIn("oracle", source,
                             "%s: a per-source oracle makes the validator read the "
                             "source as a whole record" % where)

    def test_package_summary_blocks_match_the_annotation_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            uasset, uexp = build_cooked_package(
                unversioned_properties=True, names=NAMES,
                exports=[{"name_index": 1, "payload": fragment(0, 0, last=True)}])
            path = write_package(tmp, "shape", uasset, uexp)
            report = ps.read_package(path)
        for index, record in enumerate(report["literal_reads"]):
            self._check(record["evidence"], "literal_reads[%d]" % index)
        self._check(report["decoded_layer_evidence"], "decoded_layer_evidence")

    def test_iostore_chunks_block_matches_the_annotation_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "shape.utoc")
            with open(path, "wb") as handle:
                handle.write(build_utoc(chunks=[(1, 1, 0, 8)], blocks=[(0, 8, 8, 0)]))
            report = ioc.census(path)
        self._check(report["decoded_layer_evidence"], "decoded_layer_evidence")

    def test_literal_claim_states_offset_and_length_and_nothing_else(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            uasset, uexp = build_cooked_package(
                unversioned_properties=True, names=NAMES,
                exports=[{"name_index": 1, "payload": fragment(0, 0, last=True)}])
            path = write_package(tmp, "claim", uasset, uexp)
            report = ps.read_package(path)
        record = report["literal_reads"][0]
        self.assertIn("offset %d" % record["offset"], record["claim"])
        self.assertIn("%d bytes" % record["length"], record["claim"])
        locus = record["evidence"]["read_locus"]
        self.assertEqual(locus["offset"], record["offset"])
        self.assertEqual(locus["length"], record["length"])
        # C-13: the read locus must not carry a drive letter or a leading separator
        self.assertNotRegex(locus["target"], r"^[A-Za-z]:")
        self.assertFalse(locus["target"].startswith(("/", "\\")))


if __name__ == "__main__":
    unittest.main()
