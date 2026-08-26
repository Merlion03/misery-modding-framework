#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for tools/static/link_path_probe.py (plan.md task CK-04 / SP-1).

Standard library only, and **no test here opens the game installation or the UE
tree**. Every PE and every C++ source file is built byte by byte under a
temporary directory, from the *format* rather than from the tool's code, so the
suite runs on a machine that has never seen MISERY or Unreal Engine.

That independence is the point. The probe's job is to answer "is this code path
in this image?", and the two ways it can be wrong are opposite and both fatal:

* a FALSE POSITIVE -- reporting a needle, or a reference to one, that is not
  there. Then every conclusion drawn from the tool is worthless. Guarded by
  test_absent_needle_is_absent, test_negative_control_passes and
  test_lea_to_a_different_target_is_not_counted.
* a FALSE NEGATIVE -- missing a needle that is there, or missing the reference
  form the compiler actually used. That is how the tool nearly reported a live
  literal as unreferenced: the first version decoded only the RIP-relative LEA
  form and not the static-log-record form that UE 5.4 emits. Guarded by
  test_static_record_reference_is_counted and
  test_any_rex_w_prefix_is_decoded.

Coverage:
  * needle harvested from source with file and line ... test_needle_is_read_from_source
  * a reworded message is reported, not guessed ....... test_reworded_message_is_reported
  * an ambiguous pattern is refused ................... test_ambiguous_pattern_is_refused
  * literal found once, offset and length exact ....... test_needle_found_with_exact_extent
  * class-P claim states offset AND length ............ test_class_p_claim_states_offset_and_length
  * class-P claim names nothing about the bytes ....... test_class_p_claim_names_nothing
  * LEA reference decoded, any REX.W prefix ........... test_any_rex_w_prefix_is_decoded
  * a LEA to a neighbouring address is NOT counted .... test_lea_to_a_different_target_is_not_counted
  * static log record reference decoded ............... test_static_record_reference_is_counted
  * unreferenced literal is reported as such .......... test_unreferenced_literal_is_reported
  * absence is phrased about the tested surface ....... test_absent_needle_is_absent
  * serializer probe reads the streamed members ....... test_serializer_probe_extracts_members
  * serializer probe fails when the offset IS streamed  test_serializer_probe_catches_a_streamed_offset
  * output path inside an installation is refused ..... test_out_path_inside_install_is_refused
"""

from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _path in (os.path.join(REPO_ROOT, "tools", "static"),
              os.path.join(REPO_ROOT, "tools", "fingerprint"),
              os.path.join(REPO_ROOT, "tools", "inventory")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import link_path_probe as lpp  # noqa: E402
import pathguard  # noqa: E402


IMAGE_BASE = 0x140000000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_READ = 0x40000000


# --------------------------------------------------------------------------- #
# a synthetic PE32+ -- built from the format, not from the tool
# --------------------------------------------------------------------------- #

def build_pe(text: bytes, rdata: bytes) -> bytes:
    """A minimal, well-formed PE32+ with one executable and one data section.

    Written from the PE specification field by field so that a tool reading a
    field at the wrong offset fails here rather than agreeing with itself.
    """
    number_of_sections = 2
    # e_magic at 0, e_lfanew (a DWORD) at 0x3c, and the whole stub exactly 0x80
    # bytes so that "PE\0\0" begins where e_lfanew says it does.
    dos = bytearray(b"\x00" * 0x80)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 0x80)
    dos_stub = bytes(dos)

    size_of_headers = 0x400
    text_rva = SECTION_ALIGNMENT
    text_raw = size_of_headers
    text_rsize = ((len(text) + FILE_ALIGNMENT - 1) // FILE_ALIGNMENT) * FILE_ALIGNMENT
    rdata_rva = text_rva + ((len(text) + SECTION_ALIGNMENT - 1)
                            // SECTION_ALIGNMENT) * SECTION_ALIGNMENT
    rdata_raw = text_raw + text_rsize
    rdata_rsize = ((len(rdata) + FILE_ALIGNMENT - 1) // FILE_ALIGNMENT) * FILE_ALIGNMENT

    coff = struct.pack("<HHIIIHH",
                       0x8664,              # Machine: AMD64
                       number_of_sections,
                       0,                   # TimeDateStamp
                       0, 0,                # symbol table
                       240,                 # SizeOfOptionalHeader (PE32+)
                       0x0022)              # Characteristics
    # IMAGE_OPTIONAL_HEADER64, 29 fields, 112 bytes. PE32+ has NO BaseOfData
    # field -- that one is PE32 only, and putting it back would shift ImageBase
    # and every field after it.
    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,                              # Magic: PE32+
        14, 0,                              # linker version
        text_rsize, rdata_rsize, 0,         # code/data sizes
        0x1000,                             # AddressOfEntryPoint
        text_rva,                           # BaseOfCode
        IMAGE_BASE,
        SECTION_ALIGNMENT, FILE_ALIGNMENT,
        6, 0, 0, 0, 6, 0,                   # OS / image / subsystem versions
        0,                                  # Win32VersionValue
        rdata_rva + ((len(rdata) + SECTION_ALIGNMENT - 1)
                     // SECTION_ALIGNMENT) * SECTION_ALIGNMENT,  # SizeOfImage
        size_of_headers,
        0,                                  # CheckSum
        3, 0,                               # Subsystem, DllCharacteristics
        0x100000, 0x1000, 0x100000, 0x1000,
        0,                                  # LoaderFlags
        16)                                 # NumberOfRvaAndSizes
    directories = b"\x00" * (16 * 8)

    def section(name: bytes, vsize, rva, rsize, raw, characteristics):
        return struct.pack("<8sIIIIIIHHI", name, vsize, rva, rsize, raw,
                           0, 0, 0, 0, characteristics)

    sections = (
        section(b".text\x00\x00\x00", len(text), text_rva, text_rsize, text_raw,
                IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)
        + section(b".rdata\x00\x00", len(rdata), rdata_rva, rdata_rsize, rdata_raw,
                  IMAGE_SCN_MEM_READ)
    )

    head = dos_stub + b"PE\x00\x00" + coff + optional + directories + sections
    assert len(head) <= size_of_headers, "headers overflow SizeOfHeaders"
    head = head + b"\x00" * (size_of_headers - len(head))
    return (head
            + text + b"\x00" * (text_rsize - len(text))
            + rdata + b"\x00" * (rdata_rsize - len(rdata)))


def rva_of(kind: str, offset_in_section: int, text_len: int) -> int:
    """RVA of a byte at *offset_in_section*, mirroring build_pe's arithmetic."""
    if kind == "text":
        return SECTION_ALIGNMENT + offset_in_section
    rdata_rva = SECTION_ALIGNMENT + ((text_len + SECTION_ALIGNMENT - 1)
                                     // SECTION_ALIGNMENT) * SECTION_ALIGNMENT
    return rdata_rva + offset_in_section


def lea(rex: int, modrm: int, disp: int) -> bytes:
    return bytes([rex, 0x8D, modrm]) + struct.pack("<i", disp)


# --------------------------------------------------------------------------- #
# a synthetic UE-shaped source tree
# --------------------------------------------------------------------------- #

MESSAGE = "'Struct recursion via arrays is unsupported for properties."
PROPERTY_MESSAGE = "Invalid property size %u when linking property %s of size %d"

CLASS_CPP = '''\
void UStruct::Link(FArchive& Ar, bool bRelinkExistingProperties)
{
\tif (bRelinkExistingProperties)
\t{
\t\tUE_LOG(LogClass, Fatal, TEXT("%s"));
\t}
}

void UStruct::Serialize(FArchive& Ar)
{
\tAr << SuperStruct.GetAccessTrackedObjectPtr();
\tAr << Children;
}

void UClass::Serialize( FArchive& Ar )
{
\tAr << FuncMap;
\tAr << (uint32&)ClassFlags;
}
''' % MESSAGE

PROPERTY_CPP = '''\
namespace UE::CoreUObject::Private
{
\tvoid OnInvalidPropertySize(uint32 InvalidPropertySize, const FProperty* Prop)
\t{
\t\tUE_LOG(LogProperty, Fatal, TEXT("%s"), InvalidPropertySize);
\t}
}

void FProperty::Serialize( FArchive& Ar )
{
\tAr << ArrayDim;
\tAr << ElementSize;
\tAr << RepIndex;
}
''' % PROPERTY_MESSAGE

STRUCT_CPP = '''\
void FStructProperty::LinkInternal(FArchive& Ar)
{
\tUE_LOG(LogProperty, Error, TEXT("Struct type unknown for property '%s'; perhaps the USTRUCT() was renamed or deleted?"), *GetFullName());
}
'''


def write_tree(root: str, class_cpp: str = CLASS_CPP,
               property_cpp: str = PROPERTY_CPP) -> None:
    base = os.path.join(root, "Engine", "Source", "Runtime", "CoreUObject",
                        "Private", "UObject")
    os.makedirs(base, exist_ok=True)
    for name, text in (("Class.cpp", class_cpp),
                       ("Property.cpp", property_cpp),
                       ("PropertyStruct.cpp", STRUCT_CPP)):
        with open(os.path.join(base, name), "w", encoding="utf-8",
                  newline="\n") as handle:
            handle.write(text)
    build = os.path.join(root, "Engine", "Build")
    os.makedirs(build, exist_ok=True)
    with open(os.path.join(build, "Build.version"), "w", encoding="utf-8") as handle:
        json.dump({"MajorVersion": 5, "MinorVersion": 4, "PatchVersion": 4,
                   "Changelist": 35576357, "BranchName": "++UE5+Release-5.4",
                   "IsPromotedBuild": 1}, handle)


class LinkPathProbeTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.ue_root = os.path.join(self.tmp, "UE_5.4")
        write_tree(self.ue_root)

    def tearDown(self):
        self._tmp.cleanup()

    # -- source layer ---------------------------------------------------- #

    def test_needle_is_read_from_source(self):
        warnings = []
        needles = lpp.harvest_needles(self.ue_root, warnings)
        by_id = {needle["id"]: needle for needle in needles}
        relink = by_id["link_relink_branch"]
        self.assertTrue(relink["found_in_source"])
        # The literal is EXTRACTED, never hard-coded in the tool.
        self.assertEqual(relink["text"], MESSAGE)
        self.assertEqual(relink["source_line"], 5)
        self.assertTrue(relink["citation"].endswith("Class.cpp:5"))

    def test_reworded_message_is_reported(self):
        """A tree at another changelist must produce a warning, not a guess."""
        reworded = CLASS_CPP.replace(MESSAGE, "Struct recursion is not allowed here")
        write_tree(self.ue_root, class_cpp=reworded)
        warnings = []
        needles = lpp.harvest_needles(self.ue_root, warnings)
        by_id = {needle["id"]: needle for needle in needles}
        self.assertFalse(by_id["link_relink_branch"]["found_in_source"])
        self.assertIsNone(by_id["link_relink_branch"]["text"])
        self.assertTrue(any("link_relink_branch" in text for text in warnings))

    def test_ambiguous_pattern_is_refused(self):
        """Two candidate source lines mean the citation would be a guess."""
        doubled = CLASS_CPP + "\n" + CLASS_CPP
        write_tree(self.ue_root, class_cpp=doubled)
        warnings = []
        needles = lpp.harvest_needles(self.ue_root, warnings)
        by_id = {needle["id"]: needle for needle in needles}
        record = by_id["link_relink_branch"]
        self.assertFalse(record["found_in_source"])
        self.assertEqual(record["matches_in_file"], 2)
        self.assertTrue(any("ambiguous" in text for text in warnings))

    # -- image layer ----------------------------------------------------- #

    def _image_with(self, text: bytes, rdata: bytes, name: str = "img.exe") -> str:
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as handle:
            handle.write(build_pe(text, rdata))
        return path

    def test_needle_found_with_exact_extent(self):
        blob = MESSAGE.encode("utf-16-le")
        rdata = b"\xcc" * 32 + blob + b"\xcc" * 16
        path = self._image_with(b"\x90" * 64, rdata)
        warnings = []
        needles = lpp.harvest_needles(self.ue_root, warnings)
        probe = lpp.probe_image(path, needles, warnings)
        record = {hit["id"]: hit for hit in probe["hits"]}["link_relink_branch"]
        self.assertEqual(record["occurrences"], 1)
        self.assertEqual(record["encoding"], "utf-16le")
        self.assertEqual(record["byte_length"], len(blob))
        self.assertEqual(record["section"], ".rdata")
        with open(path, "rb") as handle:
            handle.seek(record["offsets"][0])
            self.assertEqual(handle.read(len(blob)), blob)

    def test_class_p_claim_states_offset_and_length(self):
        """plan.md 10.3 v2.4: without both, class P for binary-analysis is void."""
        blob = MESSAGE.encode("utf-16-le")
        path = self._image_with(b"\x90" * 64, b"\xcc" * 32 + blob)
        warnings = []
        needles = lpp.harvest_needles(self.ue_root, warnings)
        probe = lpp.probe_image(path, needles, warnings)
        literals = lpp.build_literal_reads(path, "img.exe", probe["hits"], warnings)
        self.assertTrue(literals)
        for read in literals:
            self.assertIn("offset %d" % read["offset"], read["claim"])
            self.assertIn("%d bytes" % read["length"], read["claim"])
            self.assertEqual(read["evidence"]["claim_class"], "P")
            self.assertEqual(read["evidence"]["evidence_level"], "OBSERVED")
            self.assertLessEqual(read["evidence"]["confidence"], 0.99)
            self.assertTrue(read["reproduced"])

    def test_class_p_claim_names_nothing(self):
        """The graded claim must not name what the bytes ARE."""
        blob = MESSAGE.encode("utf-16-le")
        path = self._image_with(b"\x90" * 64, b"\xcc" * 32 + blob)
        warnings = []
        needles = lpp.harvest_needles(self.ue_root, warnings)
        probe = lpp.probe_image(path, needles, warnings)
        literals = lpp.build_literal_reads(path, "img.exe", probe["hits"], warnings)
        forbidden = ("UStruct", "FProperty", "Link", "literal", "message",
                     "utf-16", "Class.cpp", "structure", "field")
        for read in literals:
            lowered = read["claim"].lower()
            for word in forbidden:
                self.assertNotIn(word.lower(), lowered,
                                 "class-P claim names %r: %s" % (word, read["claim"]))

    def test_any_rex_w_prefix_is_decoded(self):
        """REX.X and REX.B are ignored in RIP-relative addressing, so 0x48..0x4f
        all denote the same LEA and all must be decoded. Missing one is exactly
        how a live literal gets reported as dead."""
        blob = MESSAGE.encode("utf-16-le")
        for rex in range(0x48, 0x50):
            with self.subTest(rex=hex(rex)):
                text = bytearray(b"\x90" * 64)
                rdata_prefix = 32
                path_text_len = len(text)
                target_rva = rva_of("rdata", rdata_prefix, path_text_len)
                instr_offset = 8
                instr_rva = rva_of("text", instr_offset, path_text_len)
                disp = target_rva - (instr_rva + 7)
                text[instr_offset:instr_offset + 7] = lea(rex, 0x0D, disp)
                path = self._image_with(bytes(text),
                                        b"\xcc" * rdata_prefix + blob,
                                        name="img_%02x.exe" % rex)
                warnings = []
                needles = lpp.harvest_needles(self.ue_root, warnings)
                probe = lpp.probe_image(path, needles, warnings)
                record = {h["id"]: h for h in probe["hits"]}["link_relink_branch"]
                self.assertEqual(record["references"], 1, "REX %#x not decoded" % rex)
                self.assertTrue(record["reachable_from_code"])
                self.assertEqual(record["reference_form"], "riprel-lea")

    def test_lea_to_a_different_target_is_not_counted(self):
        """One byte off must be a miss. A tool that rounds is a tool that lies."""
        blob = MESSAGE.encode("utf-16-le")
        text = bytearray(b"\x90" * 64)
        target_rva = rva_of("rdata", 32, len(text))
        instr_rva = rva_of("text", 8, len(text))
        text[8:15] = lea(0x48, 0x0D, target_rva - (instr_rva + 7) - 1)
        path = self._image_with(bytes(text), b"\xcc" * 32 + blob)
        warnings = []
        needles = lpp.harvest_needles(self.ue_root, warnings)
        probe = lpp.probe_image(path, needles, warnings)
        record = {h["id"]: h for h in probe["hits"]}["link_relink_branch"]
        self.assertEqual(record["references"], 0)
        self.assertFalse(record["reachable_from_code"])

    def test_static_record_reference_is_counted(self):
        """UE 5.4's logging emits a static record in .rdata holding a pointer to
        the format string, and addresses the RECORD. This is the form the first
        version of the probe missed on a real image."""
        blob = MESSAGE.encode("utf-16-le")
        text = bytearray(b"\x90" * 64)
        # .rdata layout: [record: 8-byte pointer][padding][the string]
        record_offset = 0
        string_offset = 64
        string_rva = rva_of("rdata", string_offset, len(text))
        record_rva = rva_of("rdata", record_offset, len(text))
        rdata = bytearray(b"\xcc" * 128)
        rdata[record_offset:record_offset + 8] = struct.pack(
            "<Q", IMAGE_BASE + string_rva)
        rdata[string_offset:string_offset + len(blob)] = blob
        instr_rva = rva_of("text", 8, len(text))
        text[8:15] = lea(0x48, 0x0D, record_rva - (instr_rva + 7))
        path = self._image_with(bytes(text), bytes(rdata))
        warnings = []
        needles = lpp.harvest_needles(self.ue_root, warnings)
        probe = lpp.probe_image(path, needles, warnings)
        record = {h["id"]: h for h in probe["hits"]}["link_relink_branch"]
        self.assertEqual(record["references"], 0, "no direct LEA was planted")
        self.assertEqual(len(record["static_record_pointers"]), 1)
        self.assertEqual(record["references_to_static_record"], 1)
        self.assertTrue(record["reachable_from_code"])
        self.assertEqual(record["reference_form"], "static-record")

    def test_unreferenced_literal_is_reported(self):
        blob = MESSAGE.encode("utf-16-le")
        path = self._image_with(b"\x90" * 64, b"\xcc" * 32 + blob)
        warnings = []
        needles = lpp.harvest_needles(self.ue_root, warnings)
        probe = lpp.probe_image(path, needles, warnings)
        record = {h["id"]: h for h in probe["hits"]}["link_relink_branch"]
        self.assertEqual(record["occurrences"], 1)
        self.assertFalse(record["reachable_from_code"])
        serializers = lpp.run_serializer_probes(self.ue_root, [])
        probes = lpp.build_refutation_probes(probe["hits"], probe["control"],
                                            serializers)
        by_id = {item["id"]: item for item in probes}
        self.assertFalse(by_id["required_needles_referenced"]["passed"])
        self.assertIn("link_relink_branch",
                      by_id["required_needles_referenced"]["unreferenced"])
        verdict, _ = lpp.decide_verdict(probes, probe["hits"])
        # setup_offset is absent from this synthetic .rdata, so the missing-needle
        # rule fires before the unreferenced one. Both are honest readings; what
        # must never happen is PATH_PRESENT_AND_REFERENCED.
        self.assertNotEqual(verdict, "PATH_PRESENT_AND_REFERENCED")

    def test_absent_needle_is_absent(self):
        """An image with none of the strings must report zero, and the finding
        must be phrased about the tested surface rather than about the file."""
        path = self._image_with(b"\x90" * 64, b"\xcc" * 256)
        warnings = []
        needles = lpp.harvest_needles(self.ue_root, warnings)
        probe = lpp.probe_image(path, needles, warnings)
        for record in probe["hits"]:
            self.assertEqual(record["occurrences"], 0)
        findings = lpp.build_findings(probe["hits"], None)
        for finding in findings:
            self.assertEqual(finding["state"], "NOT_FOUND_WITHIN_TESTED_SURFACE")
            self.assertIn("searched surface", finding["claim"])

    def test_negative_control_passes(self):
        blob = MESSAGE.encode("utf-16-le")
        path = self._image_with(b"\x90" * 64, b"\xcc" * 32 + blob)
        warnings = []
        needles = lpp.harvest_needles(self.ue_root, warnings)
        probe = lpp.probe_image(path, needles, warnings)
        self.assertIsNotNone(probe["control"])
        self.assertEqual(probe["control"]["occurrences"], 0)
        self.assertTrue(probe["control"]["passed"])

    # -- serializer probe ------------------------------------------------ #

    def test_serializer_probe_extracts_members(self):
        warnings = []
        results = lpp.run_serializer_probes(self.ue_root, warnings)
        by_id = {item["id"]: item for item in results}
        prop = by_id["fproperty_serialize"]
        self.assertTrue(prop["found"])
        self.assertEqual(prop["streams"], ["ArrayDim", "ElementSize", "RepIndex"])
        self.assertEqual(prop["violations"], [])
        self.assertTrue(prop["passed"])
        struct_probe = by_id["ustruct_serialize"]
        self.assertIn("SuperStruct", struct_probe["streams"])
        self.assertNotIn("PropertiesSize", struct_probe["streams"])

    def test_serializer_probe_catches_a_streamed_offset(self):
        """The refutation must be able to FIRE. A probe that cannot fail is a
        decoration, so plant the very thing it looks for."""
        baked = PROPERTY_CPP.replace("\tAr << RepIndex;",
                                     "\tAr << RepIndex;\n\tAr << Offset_Internal;")
        write_tree(self.ue_root, property_cpp=baked)
        warnings = []
        results = lpp.run_serializer_probes(self.ue_root, warnings)
        by_id = {item["id"]: item for item in results}
        prop = by_id["fproperty_serialize"]
        self.assertIn("Offset_Internal", prop["streams"])
        self.assertEqual(prop["violations"], ["Offset_Internal"])
        self.assertFalse(prop["passed"])
        probes = lpp.build_refutation_probes([], None, results)
        by_probe = {item["id"]: item for item in probes}
        self.assertFalse(by_probe["no_serializer_streams_the_offset"]["passed"])
        self.assertIn("fproperty_serialize",
                      by_probe["no_serializer_streams_the_offset"]["violations"])

    # -- safety ---------------------------------------------------------- #

    def test_out_path_inside_install_is_refused(self):
        """plan.md 1.5 layer 1 / D-01: nothing is written near an installation."""
        install = os.path.join(self.tmp, "install")
        os.makedirs(os.path.join(install, "Engine", "Binaries"), exist_ok=True)
        out = os.path.join(install, "probe.json")
        with self.assertRaises(pathguard.OutputPathRefused):
            pathguard.check_output_path(out, install, what="--out")
        self.assertFalse(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
