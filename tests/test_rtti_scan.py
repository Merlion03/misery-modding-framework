#!/usr/bin/env python3
"""Tests for tools/static/rtti_scan.py (task S-10).

Two things have to be tested here and they need different kinds of input, so
this file has two halves.

**The name decoder** is pure text in, text out, and it is tested against
expected strings. Most of the cases are real decorated names lifted from real
MSVC output, because the forms that matter are the ones a compiler actually
emits -- above all the back-reference table, whose scoping rule is the one part
of the grammar that fails *silently* when it is wrong. ``std::allocator<char>``
decoding as ``allocator<char>::allocator<char>`` is a wrong answer that looks
like an answer, so it gets its own test.

**The scanner** is tested against SYNTHETIC PE images assembled byte by byte,
built with the same ``PEBuilder`` as ``tests/test_pe_info.py`` -- imported, not
copied, so there is one definition of "a valid PE" in this suite. No test reads
a game file: decision D-01 makes the installation a read-only research target,
and a test suite that depends on it is neither reproducible on another machine
nor runnable where the game is absent.

The synthetic images matter for a reason beyond hygiene. A scanner whose only
evidence is a run over a 134 MB binary cannot distinguish "this image contains
587 locators" from "this scanner reports 587 of anything". Here the image is
constructed with a KNOWN number of type descriptors, locators, base classes and
vtable slots, so the assertions are against ground truth rather than against the
scanner's own previous output.

Coverage:
  * the decoder: primitives, qualified and nested names, anonymous namespaces,
    templates, integral and function-type template arguments, pointers and
    references, pointer-to-member-function, back-references, and the forms it is
    expected to refuse
  * a positive image: 3 type descriptors, 2 locators, a two-level hierarchy, a
    vtable with a known slot count -- every headline number asserted exactly
  * a negative image: no RTTI at all, and the verdict wording that goes with it
  * near-miss inputs that must NOT be counted: a name with a non-zero spare
    field, a locator whose pSelf is wrong, a locator whose hierarchy does not
    chain, a base class descriptor masquerading as a locator
  * a vtable whose slots do not point at code
  * the ownership attribution rules, one test per rule
  * determinism, the JSONL artifact, the class-P literal layer and its
    re-read attestation, and the pathguard contract on both output paths
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "static"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "fingerprint"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pathguard  # noqa: E402
import rtti_scan  # noqa: E402
from test_pe_info import PEBuilder, write_image  # noqa: E402

RTTI_SCAN_PATH = os.path.join(REPO_ROOT, "tools", "static", "rtti_scan.py")
IMAGE_BASE = 0x140000000

# Section characteristics used by the builders below.
RDATA_FLAGS = 0x40000040          # initialised data, read
DATA_FLAGS = 0xC0000040           # initialised data, read/write
TEXT_FLAGS = 0x60000020           # code, execute, read


# --------------------------------------------------------------------------- #
# 1. the MSVC decorated-name decoder
# --------------------------------------------------------------------------- #

DECODER_CASES = [
    # (mangled, kind, decoded)
    (".?AVFoo@@", "class", "Foo"),
    (".?AUBar@@", "struct", "Bar"),
    (".?ATBaz@@", "union", "Baz"),
    (".?AW4Colour@@", "enum", "Colour"),
    (".?AVtype_info@@", "class", "type_info"),
    # nested classes: innermost first in the encoding, outermost first in output
    (".?AVEOSBlock@Track@mkvparser@@", "class", "mkvparser::Track::EOSBlock"),
    # anonymous namespace, with and without the address suffix
    (".?AVParseDataSink@?A0x03a0a8a6@@", "class",
     "`anonymous namespace'::ParseDataSink"),
    (".?AVDefaultThreadPoolProvider@?A0x00b5bf98@IlmThread_3_2@@", "class",
     "IlmThread_3_2::`anonymous namespace'::DefaultThreadPoolProvider"),
    # simple template with a primitive argument
    (".?AV?$TAutoConsoleVariable@_N@@", "class", "TAutoConsoleVariable<bool>"),
    # THE back-reference case. '2' must resolve to "std", not to the template
    # just memorised. See the module docstring of rtti_scan for the rule.
    (".?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@", "class",
     "std::basic_string<char,std::char_traits<char>,std::allocator<char>>"),
    # two back-references in one argument list, plus a hex-encoded integer
    (".?AV?$wstring_convert@V?$codecvt_utf8@_W$0BAPPPP@$0A@@std@@_W"
     "V?$allocator@_W@2@V?$allocator@D@2@@std@@", "class",
     "std::wstring_convert<std::codecvt_utf8<wchar_t,1114111,0>,wchar_t,"
     "std::allocator<wchar_t>,std::allocator<char>>"),
    # $0<digit> is value+1; $00 is therefore 1, and $0A@ is 0
    (".?AV?$TReferenceControllerBase@$00@SharedPointerInternals@@", "class",
     "SharedPointerInternals::TReferenceControllerBase<1>"),
    # a function type as a template argument, plus an empty parameter pack
    (".?AV?$TCommonDelegateInstanceState@$$A6APEAVIModuleInterface@@XZ"
     "UFDefaultDelegateUserPolicy@@$$V@@", "class",
     "TCommonDelegateInstanceState<IModuleInterface * __cdecl(void),"
     "FDefaultDelegateUserPolicy>"),
    # nested templates three deep
    (".?AV?$TypedAttribute@V?$Box@V?$Vec2@H@Imath_3_1@@@Imath_3_1@@@Imf_3_2@@",
     "class",
     "Imf_3_2::TypedAttribute<Imath_3_1::Box<Imath_3_1::Vec2<int>>>"),
    # an enum as a template argument (W4 in argument position)
    (".?AV?$TypedAttribute@W4Compression@Imf_3_2@@@Imf_3_2@@", "class",
     "Imf_3_2::TypedAttribute<Imf_3_2::Compression>"),
    # pointer to a struct as a template argument
    (".?AU?$DefaultDeleter@PEAU_priv_exr_context_t@@@SharedPointerInternals@@",
     "struct",
     "SharedPointerInternals::DefaultDeleter<_priv_exr_context_t *>"),
]


@pytest.mark.parametrize("mangled,kind,decoded", DECODER_CASES)
def test_decoder_matches_expected_output(mangled, kind, decoded):
    assert rtti_scan.demangle_type_descriptor(mangled) == (kind, decoded)


def test_back_reference_scope_is_per_template_argument_list():
    """The regression this scoping rule exists to prevent, stated as a test.

    If the back-reference table were shared with the enclosing name instead of
    reset for the argument list, index 2 would resolve to the template just
    memorised and the answer would be ``allocator<char>::allocator<char>``: a
    wrong name that reads like a real one.
    """
    _kind, decoded = rtti_scan.demangle_type_descriptor(
        ".?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@")
    assert "std::allocator<char>" in decoded
    assert "allocator<char>::allocator<char>" not in decoded


def test_decoder_handles_pointer_to_member_function():
    kind, decoded = rtti_scan.demangle_type_descriptor(
        ".?AV?$_Binder@U_Unforced@std@@P8Impl@ns@@EAAPEAVBuf@2@XZPEAV34@@std@@")
    assert kind == "class"
    assert "ns::Impl" in decoded
    assert "__cdecl" in decoded


def test_decoder_handles_a_reference_argument():
    _kind, decoded = rtti_scan.demangle_type_descriptor(".?AV?$T@AEBVFoo@@@@")
    assert decoded == "T<Foo const &>"


@pytest.mark.parametrize("mangled", [
    "",
    "Foo",                        # no .?A prefix at all
    ".?A",                        # prefix with no body
    ".?AX Foo@@",                 # unknown descriptor tag
    ".?AVFoo",                    # unterminated scope chain
    ".?AV@@",                     # empty identifier
    ".?AV?$T@9@@",                # back-reference past the end of the table
    ".?AW9Foo@@",                 # enum with a bad underlying type
    ".?AVFoo@@junk",              # trailing bytes after a complete name
])
def test_decoder_refuses_malformed_names(mangled):
    with pytest.raises(rtti_scan.DemangleError):
        rtti_scan.demangle_type_descriptor(mangled)


def test_decoder_refuses_an_absurdly_long_name():
    with pytest.raises(rtti_scan.DemangleError):
        rtti_scan.demangle_type_descriptor(
            ".?AV" + "A" * (rtti_scan.MAX_DEMANGLE_INPUT + 1) + "@@")


def test_decoder_survives_a_deeply_nested_name_without_recursion_error():
    """A hostile name must produce DemangleError, never RecursionError."""
    depth = rtti_scan.MAX_DEMANGLE_DEPTH + 20
    mangled = ".?AV" + "?$T@" * depth + "H" + "@" * depth + "@"
    with pytest.raises(rtti_scan.DemangleError):
        rtti_scan.demangle_type_descriptor(mangled)


def test_decoder_state_is_not_shared_between_names():
    """Two decodes in a row must not see each other's back-reference table."""
    first = rtti_scan.demangle_type_descriptor(
        ".?AV?$char_traits@D@std@@")
    with pytest.raises(rtti_scan.DemangleError):
        # '2' would resolve only if the previous run's table leaked.
        rtti_scan.demangle_type_descriptor(".?AVFoo@2@")
    assert first == ("class", "std::char_traits<char>")


# --------------------------------------------------------------------------- #
# 2. synthetic RTTI images
# --------------------------------------------------------------------------- #

class RttiImageBuilder:
    """A PE32+ image carrying a KNOWN, hand-laid-out MSVC RTTI graph.

    Layout, fixed so the arithmetic in a failing test is readable:

        .text   RVA 0x1000   filler code bytes (targets for vtable slots)
        .rdata  RVA 0x2000   locators, hierarchy descriptors, base class
                             descriptors, base class arrays, vtables
        .data   RVA 0x3000   type descriptors (pVFTable needs a relocation, so
                             MSVC cannot put them in a read-only section)

    The caller adds classes; ``build()`` returns ``(blob, expected)`` where
    ``expected`` carries the ground truth a test asserts against, so no test has
    to re-derive an offset the builder already computed.
    """

    TEXT_RVA = 0x1000
    RDATA_RVA = 0x2000
    DATA_RVA = 0x3000
    TYPE_INFO_VFTABLE_RVA = 0x2010      # somewhere inside .rdata; never read
    SECONDARY_VTABLE_SLOTS = 2          # slots in a secondary-base vtable

    def __init__(self) -> None:
        self.classes: list[dict] = []

    def add_class(self, mangled: str, *, bases: tuple[str, ...] = (),
                  vtable_slots: int = 3, spare: int = 0,
                  break_self_pointer: bool = False,
                  break_hierarchy_signature: bool = False,
                  vtable_points_at_data: bool = False,
                  secondary_offsets: tuple[int, ...] = ()) -> None:
        """Register one class. ``bases`` names classes added earlier.

        The four ``break_*`` / ``spare`` switches exist so a test can produce a
        near miss -- a structure that a naive scanner counts and a correct one
        does not -- without hand-assembling a second image.

        ``secondary_offsets`` gives the class extra locator+vtable pairs whose
        ``offset`` field is non-zero, which is what MSVC emits for a secondary
        base: one complete object locator PER VTABLE, all naming the same type
        descriptor. It exists so a test can tell a locator count from a class
        count on ground truth -- the two are equal only in an image where no
        class has a secondary base, and an image like that cannot show the
        difference at all.
        """
        self.classes.append({
            "mangled": mangled,
            "bases": bases,
            "vtable_slots": vtable_slots,
            "spare": spare,
            "break_self_pointer": break_self_pointer,
            "break_hierarchy_signature": break_hierarchy_signature,
            "vtable_points_at_data": vtable_points_at_data,
            "secondary_offsets": secondary_offsets,
        })

    def build(self) -> tuple[bytes, dict]:
        # ---- .data: type descriptors ----------------------------------- #
        data = bytearray()
        descriptor_rva: dict[str, int] = {}
        for record in self.classes:
            # 8-byte align every descriptor, as a linker does.
            while len(data) % 8:
                data.append(0)
            descriptor_rva[record["mangled"]] = self.DATA_RVA + len(data)
            data += struct.pack("<QQ",
                                IMAGE_BASE + self.TYPE_INFO_VFTABLE_RVA,
                                record["spare"])
            data += record["mangled"].encode("ascii") + b"\x00"

        # ---- .rdata: three passes, because the records point at each other #
        rdata = bytearray(0x40)     # leave room so TYPE_INFO_VFTABLE_RVA is inside

        def place(blob: bytes, alignment: int = 4) -> int:
            nonlocal rdata
            while len(rdata) % alignment:
                rdata.append(0)
            rva = self.RDATA_RVA + len(rdata)
            rdata.extend(blob)
            return rva

        # base class descriptors, one per (class, base) pair including self
        bcd_rva: dict[tuple[str, str], int] = {}
        for record in self.classes:
            chain = (record["mangled"],) + record["bases"]
            for index, name in enumerate(chain):
                bcd_rva[(record["mangled"], name)] = place(struct.pack(
                    "<7I", descriptor_rva[name], len(chain) - index - 1,
                    0, 0, 0, 0, 0))

        # base class arrays
        bca_rva: dict[str, int] = {}
        for record in self.classes:
            chain = (record["mangled"],) + record["bases"]
            bca_rva[record["mangled"]] = place(struct.pack(
                "<%dI" % len(chain),
                *[bcd_rva[(record["mangled"], name)] for name in chain]))

        # class hierarchy descriptors
        chd_rva: dict[str, int] = {}
        for record in self.classes:
            chain = (record["mangled"],) + record["bases"]
            signature = 7 if record["break_hierarchy_signature"] else 0
            chd_rva[record["mangled"]] = place(struct.pack(
                "<4I", signature, 1 if len(chain) > 1 else 0, len(chain),
                bca_rva[record["mangled"]]))

        # complete object locators, then the vtable immediately after each
        locator_rva: dict[str, int] = {}
        vtable_rva: dict[str, int] = {}
        secondary_locator_rva: dict[str, list[int]] = {}
        for record in self.classes:
            # The locator and the vtable are laid out as a pair: the hidden slot
            # in front of a vtable holds image_base + locator_rva.
            while len(rdata) % 8:
                rdata.append(0)
            here = self.RDATA_RVA + len(rdata)
            self_value = here + 4 if record["break_self_pointer"] else here
            rdata.extend(struct.pack("<6I", 1, 0, 0,
                                     descriptor_rva[record["mangled"]],
                                     chd_rva[record["mangled"]], self_value))
            locator_rva[record["mangled"]] = here

            slot_target = (self.DATA_RVA if record["vtable_points_at_data"]
                           else self.TEXT_RVA)
            while len(rdata) % 8:
                rdata.append(0)
            slot_rva = self.RDATA_RVA + len(rdata)
            rdata.extend(struct.pack("<Q", IMAGE_BASE + here))
            vtable_rva[record["mangled"]] = self.RDATA_RVA + len(rdata)
            for index in range(record["vtable_slots"]):
                rdata.extend(struct.pack("<Q", IMAGE_BASE + slot_target + index * 16))
            # a terminator that is not a code address, so the slot walk stops
            rdata.extend(struct.pack("<Q", 0))
            record["_slot_rva"] = slot_rva

            # Secondary bases: one more locator+vtable pair per offset, all
            # pointing at the SAME type descriptor. The slot targets are pushed
            # into their own part of .text so the distinct-function count is
            # ground truth too, not an accident of overlap.
            secondary: list[int] = []
            for ordinal, sub_offset in enumerate(record["secondary_offsets"]):
                while len(rdata) % 8:
                    rdata.append(0)
                sub_here = self.RDATA_RVA + len(rdata)
                rdata.extend(struct.pack("<6I", 1, sub_offset, 0,
                                         descriptor_rva[record["mangled"]],
                                         chd_rva[record["mangled"]], sub_here))
                secondary.append(sub_here)
                while len(rdata) % 8:
                    rdata.append(0)
                rdata.extend(struct.pack("<Q", IMAGE_BASE + sub_here))
                sub_target = self.TEXT_RVA + 0x200 + ordinal * 0x40
                for index in range(self.SECONDARY_VTABLE_SLOTS):
                    rdata.extend(struct.pack("<Q",
                                             IMAGE_BASE + sub_target + index * 16))
                rdata.extend(struct.pack("<Q", 0))
            secondary_locator_rva[record["mangled"]] = secondary

        builder = PEBuilder()
        builder.add_section(".text", self.TEXT_RVA, b"\xC3" * 0x400, TEXT_FLAGS)
        builder.add_section(".rdata", self.RDATA_RVA, bytes(rdata), RDATA_FLAGS)
        builder.add_section(".data", self.DATA_RVA, bytes(data), DATA_FLAGS)
        expected = {
            "descriptor_rva": descriptor_rva,
            "locator_rva": locator_rva,
            "secondary_locator_rva": secondary_locator_rva,
            "vtable_rva": vtable_rva,
            "chd_rva": chd_rva,
            "classes": self.classes,
        }
        return builder.build(), expected


@pytest.fixture()
def positive_image(tmp_path):
    """Three descriptors, three locators, a two-level hierarchy. Known numbers."""
    builder = RttiImageBuilder()
    builder.add_class(".?AVBase@@", vtable_slots=2)
    builder.add_class(".?AVDerived@@", bases=(".?AVBase@@",), vtable_slots=5)
    builder.add_class(".?AV?$Holder@VDerived@@@ns@@",
                      bases=(".?AVDerived@@", ".?AVBase@@"), vtable_slots=1)
    blob, expected = builder.build()
    path = write_image(tmp_path, "positive.exe", blob)
    return path, expected


def test_positive_image_counts_are_exact(positive_image):
    path, expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    summary = document["summary"]
    assert summary["verdict"] == "FOUND"
    assert summary["name_strings_found"] == 3
    assert summary["type_descriptors_structurally_valid"] == 3
    assert summary["complete_object_locators_strict"] == 3
    assert summary["complete_object_locators_loose_validated"] == 3
    assert summary["locators_resolving_to_a_type_descriptor"] == 3
    assert summary["locators_with_coherent_hierarchy"] == 3
    assert summary["locators_with_reachable_vtable"] == 3
    assert summary["type_descriptors_decoded"] == 3
    assert summary["type_descriptors_undecoded"] == 0
    # 2 + 5 + 1 slots, exactly as laid out
    assert summary["vtable_code_slots_total"] == 8
    assert summary["vtable_code_slots_min"] == 1
    assert summary["vtable_code_slots_max"] == 5
    # slots are not functions: the three vtables hold 8 slots between them but
    # address only 5 distinct addresses (0x1000..0x1040, step 0x10)
    assert summary["distinct_virtual_function_rvas"] == 5
    assert summary["distinct_vtables"] == 3
    # no class here has a secondary base, so locators == classes -- stated so a
    # regression that conflates the two is visible on this image as well
    assert summary["distinct_classes_among_locators"] == 3
    assert summary["locators_with_nonzero_offset"] == 0
    assert summary["locators_with_nonzero_cd_offset"] == 0
    assert summary["locators_with_nonstandard_signature"] == 0


@pytest.fixture()
def secondary_base_image(tmp_path):
    """One class with two extra locators at offset 8 and 16, one plain class.

    Ground truth: 3 locators, 2 classes. This is the shape MSVC emits for a
    class with secondary bases, and it is the shape that makes "587 locators"
    and "587 classes" two different claims.
    """
    builder = RttiImageBuilder()
    builder.add_class(".?AVPlain@@", vtable_slots=2)
    builder.add_class(".?AVMulti@@", bases=(".?AVPlain@@",), vtable_slots=3,
                      secondary_offsets=(8, 16))
    blob, expected = builder.build()
    path = write_image(tmp_path, "secondary.exe", blob)
    return path, expected


def test_a_class_with_secondary_bases_is_one_class_and_several_locators(
        secondary_base_image):
    path, expected = secondary_base_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    summary = document["summary"]
    assert summary["complete_object_locators_strict"] == 4
    assert summary["locators_resolving_to_a_type_descriptor"] == 4
    # the number that must NOT follow the locator count
    assert summary["distinct_classes_among_locators"] == 2
    assert summary["locators_with_nonzero_offset"] == 2
    assert summary["locators_with_nonzero_cd_offset"] == 0
    # every locator of the class names the same type descriptor
    multi = [c for c in document["classes"] if c["mangled"] == ".?AVMulti@@"]
    assert len(multi) == 3
    assert len({c["type_descriptor_rva"] for c in multi}) == 1
    assert sorted(c["locator"]["offset"] for c in multi) == [0, 8, 16]
    assert ([c["locator_rva"] for c in multi][1:]
            == expected["secondary_locator_rva"][".?AVMulti@@"])
    # ... and the per-class bucket split counts the class once, the per-locator
    # split counts it three times
    assert sum(summary["by_bucket_classes"].values()) == 2
    assert sum(summary["by_bucket"].values()) == 4


def test_the_coverage_probe_takes_its_share_over_classes(secondary_base_image):
    """P4 asks about classes, so its denominator must be the class count."""
    path, _expected = secondary_base_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    probe = next(p for p in document["refutation_probes"]
                 if p["id"] == "P4-coverage-is-not-of-the-target")
    assert probe["observed"]["distinct_classes"] == 2
    assert probe["observed"]["locators"] == 4


def test_positive_image_addresses_match_the_layout(positive_image):
    path, expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    by_name = {c["mangled"]: c for c in document["classes"]}
    for mangled, locator in expected["locator_rva"].items():
        record = by_name[mangled]
        assert record["locator_rva"] == locator
        assert record["type_descriptor_rva"] == expected["descriptor_rva"][mangled]
        assert record["locator"]["self_rva_matches"] is True
        assert record["vtable"]["vtable_rva"] == expected["vtable_rva"][mangled]


def test_positive_image_hierarchy_chains(positive_image):
    path, expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    by_name = {c["mangled"]: c for c in document["classes"]}
    assert by_name[".?AVBase@@"]["hierarchy"]["base_class_count"] == 1
    assert by_name[".?AVDerived@@"]["hierarchy"]["base_class_count"] == 2
    holder = by_name[".?AV?$Holder@VDerived@@@ns@@"]
    assert holder["hierarchy"]["base_class_count"] == 3
    assert holder["hierarchy"]["first_base_is_self"] is True
    assert holder["hierarchy"]["unknown_base_type_descriptors"] == 0
    assert holder["decoded_name"] == "ns::Holder<Derived>"
    # every base class descriptor names a descriptor the scan already found
    assert set(holder["hierarchy"]["base_type_descriptor_rvas"]) == {
        expected["descriptor_rva"][name] for name in
        (".?AV?$Holder@VDerived@@@ns@@", ".?AVDerived@@", ".?AVBase@@")}


def test_negative_image_says_not_found_within_tested_surface(tmp_path):
    builder = PEBuilder()
    builder.add_section(".text", 0x1000, b"\xC3" * 0x200, TEXT_FLAGS)
    builder.add_section(".rdata", 0x2000, b"nothing to see here" * 8, RDATA_FLAGS)
    builder.add_section(".data", 0x3000, b"\x00" * 0x100, DATA_FLAGS)
    path = write_image(tmp_path, "negative.exe", builder.build())
    document = rtti_scan.analyze(path, want_file_digest=False)
    assert document["summary"]["verdict"] == "NOT FOUND WITHIN TESTED SURFACE"
    assert document["summary"]["name_strings_found"] == 0
    assert document["summary"]["complete_object_locators_strict"] == 0
    # The negative verdict must NAME the surface it is negative over.
    names = [s["name"] for s in
             document["tested_surface"]["type_descriptor_name_sections"]]
    assert ".rdata" in names and ".data" in names
    assert document["tested_surface"]["sections_not_searched"] == [".text"]


def test_a_name_string_alone_is_not_counted_as_rtti(tmp_path):
    """The whole point of S-10: '.?AV' in the file proves nothing.

    Here the string is present but there is no descriptor header in front of it
    and no locator anywhere, so the tool must not report FOUND.
    """
    builder = PEBuilder()
    builder.add_section(".text", 0x1000, b"\xC3" * 0x200, TEXT_FLAGS)
    builder.add_section(".rdata", 0x2000,
                        b"\xAA" * 16 + b".?AVNotReallyRtti@@\x00" + b"\xBB" * 32,
                        RDATA_FLAGS)
    path = write_image(tmp_path, "bait.exe", builder.build())
    document = rtti_scan.analyze(path, want_file_digest=False)
    assert document["summary"]["name_strings_found"] == 1
    assert document["summary"]["complete_object_locators_strict"] == 0
    assert document["summary"]["verdict"] == "UNKNOWN"
    assert "no complete object locator" in document["summary"]["verdict_reason"]


def test_nonzero_spare_field_excludes_a_descriptor(tmp_path):
    builder = RttiImageBuilder()
    builder.add_class(".?AVGood@@")
    builder.add_class(".?AVBadSpare@@", spare=0xDEAD)
    blob, _expected = builder.build()
    path = write_image(tmp_path, "spare.exe", blob)
    document = rtti_scan.analyze(path, want_file_digest=False)
    assert document["summary"]["name_strings_found"] == 2
    assert document["summary"]["type_descriptors_structurally_valid"] == 1
    assert document["type_descriptor_scan"]["nonzero_spare_count"] == 1
    # The locator for BadSpare is still self-identifying, so the strict scan
    # still finds it -- but it must resolve to NO type descriptor rather than
    # borrowing a plausible one. Reporting the orphan is the correct behaviour;
    # silently dropping it would hide a real structural anomaly.
    assert document["summary"]["complete_object_locators_strict"] == 2
    assert document["summary"]["locators_resolving_to_a_type_descriptor"] == 1
    assert sorted(str(c["mangled"]) for c in document["classes"]) == [
        ".?AVGood@@", "None"]


def test_wrong_self_pointer_excludes_a_locator(tmp_path):
    builder = RttiImageBuilder()
    builder.add_class(".?AVGood@@")
    builder.add_class(".?AVBadSelf@@", break_self_pointer=True)
    blob, _expected = builder.build()
    path = write_image(tmp_path, "self.exe", blob)
    document = rtti_scan.analyze(path, want_file_digest=False)
    # The strict predicate drops it; the validated loose predicate, which never
    # looks at pSelf, still finds it -- and the probe must SAY they disagree.
    assert document["summary"]["complete_object_locators_strict"] == 1
    assert document["summary"]["complete_object_locators_loose_validated"] == 2
    probe = next(p for p in document["refutation_probes"]
                 if p["id"] == "P2-locator-predicate-disagreement")
    assert probe["refuted_the_conclusion"] is True
    assert probe["observed"]["loose_only"] == 1


def test_broken_hierarchy_signature_is_reported_not_hidden(tmp_path):
    builder = RttiImageBuilder()
    builder.add_class(".?AVBrokenChd@@", break_hierarchy_signature=True)
    blob, _expected = builder.build()
    path = write_image(tmp_path, "chd.exe", blob)
    document = rtti_scan.analyze(path, want_file_digest=False)
    assert document["summary"]["complete_object_locators_strict"] == 1
    assert document["summary"]["locators_with_coherent_hierarchy"] == 0
    hierarchy = document["classes"][0]["hierarchy"]
    assert hierarchy["signature"] == 7
    assert "signature is 7" in hierarchy["problem"]


def test_a_vtable_whose_slots_are_not_code_does_not_count(tmp_path):
    builder = RttiImageBuilder()
    builder.add_class(".?AVOrphan@@", vtable_points_at_data=True)
    blob, _expected = builder.build()
    path = write_image(tmp_path, "orphan.exe", blob)
    document = rtti_scan.analyze(path, want_file_digest=False)
    assert document["summary"]["complete_object_locators_strict"] == 1
    assert document["summary"]["locators_with_reachable_vtable"] == 0
    assert document["summary"]["verdict"] == "UNKNOWN"
    probe = next(p for p in document["refutation_probes"]
                 if p["id"] == "P3-vtable-reachability")
    assert probe["refuted_the_conclusion"] is True


def test_base_class_descriptors_are_not_miscounted_as_locators(positive_image):
    """The loose predicate's known false positive, measured rather than assumed.

    An RTTIBaseClassDescriptor also begins with a pTypeDescriptor field, so the
    raw candidate set is larger than the truth. The validated set must not be.
    """
    path, expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    scan = document["locator_scan"]
    assert scan["loose_candidate_count"] >= scan["loose_validated_count"]
    assert scan["loose_validated_count"] == scan["strict_count"] == 3


def test_pe32_uses_the_validated_loose_predicate(positive_image):
    """PE32 has no pSelf field, so the document must say which predicate ran."""
    path, _expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    assert document["locator_scan"]["predicate_used"] == "strict"


# --------------------------------------------------------------------------- #
# 3. ownership attribution
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,bucket", [
    ("std::basic_string<char>", rtti_scan.BUCKET_CRT),
    ("type_info", rtti_scan.BUCKET_CRT),
    ("_com_error", rtti_scan.BUCKET_CRT),
    ("icu_64::UnicodeString", rtti_scan.BUCKET_THIRD_PARTY),
    ("Imf_3_2::Attribute", rtti_scan.BUCKET_THIRD_PARTY),
    ("draco::Mesh", rtti_scan.BUCKET_THIRD_PARTY),
    ("mkvparser::Track", rtti_scan.BUCKET_THIRD_PARTY),
    ("CBaseFilter", rtti_scan.BUCKET_THIRD_PARTY),
    ("SharedPointerInternals::TReferenceControllerBase<1>", rtti_scan.BUCKET_UNREAL),
    ("FDefaultModuleImpl", rtti_scan.BUCKET_UNREAL),
    ("IModuleInterface", rtti_scan.BUCKET_UNREAL),
    ("TAutoConsoleVariable<bool>", rtti_scan.BUCKET_UNREAL),
    ("UMyThing", rtti_scan.BUCKET_UNREAL),
    ("`anonymous namespace'::ParseDataSink", rtti_scan.BUCKET_UNATTRIBUTED),
    ("lowercase_thing", rtti_scan.BUCKET_UNATTRIBUTED),
    ("Zzz", rtti_scan.BUCKET_UNATTRIBUTED),
])
def test_attribution_buckets(name, bucket):
    assert rtti_scan.classify_name("class", name)["bucket"] == bucket


def test_attribution_ignores_template_arguments():
    """The owner of a template is decided by the template, not by its arguments.

    ``icu_64::LocaleCacheKey<icu_64::SharedCalendar>`` is ICU's; so is
    ``icu_64::CacheKey<SomethingElse>``. A rule that looked inside the angle
    brackets would attribute an STL container of engine objects to the STL.
    """
    assert rtti_scan.root_identifier(
        "icu_64::LocaleCacheKey<icu_64::SharedCalendar>") == "icu_64"
    assert rtti_scan.root_identifier(
        "TAutoConsoleVariable<std::vector<int>>") == "TAutoConsoleVariable"
    assert rtti_scan.root_identifier("std::vector<a::b::c>") == "std"


def test_c_prefix_is_not_treated_as_an_unreal_prefix():
    """C is the MFC/ATL/DirectShow convention. Unreal never uses it."""
    assert rtti_scan.classify_name("class", "CSomethingUnknown")["bucket"] == \
        rtti_scan.BUCKET_UNATTRIBUTED


def test_ue_source_corroboration_promotes_and_demotes(tmp_path):
    """The second, independent attribution method, in both directions.

    ``FKnownEngineThing`` is declared in the fake tree and must stay
    ``unreal-engine``; ``FNotInTheEngine`` is not and must be promoted to
    ``game-specific-candidate``, which is the only positive test for
    "game-specific" this tool can perform.
    """
    source_root = tmp_path / "EngineSource"
    (source_root / "Runtime").mkdir(parents=True)
    (source_root / "Runtime" / "Thing.h").write_text(
        "class FKnownEngineThing {};\n", encoding="utf-8")

    builder = RttiImageBuilder()
    builder.add_class(".?AVFKnownEngineThing@@")
    builder.add_class(".?AVFNotInTheEngine@@")
    blob, _expected = builder.build()
    path = write_image(tmp_path, "attribution.exe", blob)

    document = rtti_scan.analyze(path, want_file_digest=False,
                                 ue_source_root=str(source_root))
    by_name = {c["decoded_name"]: c["attribution"] for c in document["classes"]}
    assert by_name["FKnownEngineThing"]["bucket"] == rtti_scan.BUCKET_UNREAL
    assert by_name["FKnownEngineThing"]["ue_source_declaration"] == \
        "Runtime/Thing.h"
    assert by_name["FNotInTheEngine"]["bucket"] == rtti_scan.BUCKET_GAME
    assert by_name["FNotInTheEngine"]["ue_source_declaration"] is None
    assert document["ue_source_corroboration"]["available"] is True
    assert document["ue_source_corroboration"]["files_scanned"] == 1


def test_missing_ue_source_root_warns_and_does_not_reclassify(tmp_path):
    builder = RttiImageBuilder()
    builder.add_class(".?AVFSomething@@")
    blob, _expected = builder.build()
    path = write_image(tmp_path, "nosource.exe", blob)
    document = rtti_scan.analyze(
        path, want_file_digest=False,
        ue_source_root=str(tmp_path / "does-not-exist"))
    assert document["ue_source_corroboration"]["available"] is False
    assert any("did not run" in w for w in document["warnings"])
    assert document["classes"][0]["attribution"]["bucket"] == \
        rtti_scan.BUCKET_UNREAL


# --------------------------------------------------------------------------- #
# 4. the class-P literal layer
# --------------------------------------------------------------------------- #

def test_literal_reads_state_offset_and_length_and_nothing_else(positive_image):
    """plan.md 10.3 v2.4: the binary-analysis oracle is class P only at a
    stated offset AND length, and only while the claim does not name the bytes.
    """
    path, _expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    assert document["literal_reads"]
    for read in document["literal_reads"]:
        claim = read["claim"]
        assert "at offset %d" % read["offset"] in claim
        assert claim.startswith("%d byte" % read["length"])
        assert read["bytes_hex"] in claim
        # the interpretation must live in the OTHER layer
        for forbidden in ("TypeDescriptor", "Locator", "vtable", "pVFTable"):
            assert forbidden not in claim
        assert read["evidence"]["claim_class"] == "P"
        assert read["evidence"]["evidence_level"] == "OBSERVED"
        assert read["evidence"]["confidence"] <= 0.99
        assert read["evidence"]["oracle"] == ["binary-analysis"]


def test_literal_reads_are_actually_re_read(positive_image):
    path, _expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    for read in document["literal_reads"]:
        assert read["reproduced"] is True
        assert "re-run and reproduced" in read["evidence"]["sources"][0]["note"]
        assert "PENDING" not in read["evidence"]["sources"][0]["note"]


def test_literal_reads_match_the_file(positive_image):
    """Read the bytes back independently of the tool and compare."""
    path, _expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    with open(path, "rb") as handle:
        for read in document["literal_reads"]:
            handle.seek(read["offset"])
            assert handle.read(read["length"]).hex() == read["bytes_hex"]


def test_failed_reproduction_is_recorded_not_swallowed(tmp_path, positive_image):
    """If the second read disagrees, the record must say so and stay unreproduced."""
    _path, _expected = positive_image
    literals = [rtti_scan.literal_read("x", "field", 0, b"\x01\x02\x03\x04")]
    missing = os.path.join(str(tmp_path), "not-there.bin")
    warnings: list[str] = []
    assert rtti_scan.confirm_literal_reads(missing, literals, "x", warnings) is False
    assert literals[0]["reproduced"] is False
    assert "NOT reproduced" in literals[0]["evidence"]["note"]
    assert warnings


def test_decoded_annotation_is_class_i_and_capped(positive_image):
    path, _expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    annotation = document["decoded_annotation"]
    assert annotation["claim_class"] == "I"
    assert annotation["evidence_level"] == "INFERRED"
    assert annotation["confidence"] <= 0.85
    assert "external-doc" in annotation["oracle"]
    # >= 0.80 requires a second, independent method to be present
    if annotation["confidence"] >= 0.80:
        assert len(annotation["sources"]) >= 2


def test_no_confidence_anywhere_reaches_one(positive_image):
    path, _expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)

    def walk(node):
        if isinstance(node, dict):
            if "confidence" in node and isinstance(node["confidence"], (int, float)):
                assert node["confidence"] <= 0.99
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(document)


def test_literal_sample_is_spread_not_taken_from_the_front():
    items = list(range(100))
    picked = rtti_scan._spread(items, 5)
    assert picked == [0, 25, 50, 74, 99]
    assert rtti_scan._spread(items, 1) == [0]
    assert rtti_scan._spread([], 5) == []
    assert rtti_scan._spread([1, 2], 5) == [1, 2]


# --------------------------------------------------------------------------- #
# 5. robustness
# --------------------------------------------------------------------------- #

def test_hostile_base_class_count_does_not_allocate(tmp_path):
    """numBaseClasses is read from the file and must never be believed."""
    builder = RttiImageBuilder()
    builder.add_class(".?AVHostile@@")
    blob, expected = builder.build()
    data = bytearray(blob)
    # Locate the class hierarchy descriptor and poison numBaseClasses.
    import pe_info
    with pe_info.Image.open(write_image(tmp_path, "probe.exe", bytes(data))) as image:
        headers = pe_info.PEHeaders(image)
        offset = headers.rva_to_offset(expected["chd_rva"][".?AVHostile@@"])
    struct.pack_into("<I", data, offset + 8, 0xFFFFFFFF)
    path = write_image(tmp_path, "hostile.exe", bytes(data))
    document = rtti_scan.analyze(path, want_file_digest=False)
    hierarchy = document["classes"][0]["hierarchy"]
    assert hierarchy["base_class_count"] == 0xFFFFFFFF
    assert "outside [1," in hierarchy["problem"]
    assert document["summary"]["locators_with_coherent_hierarchy"] == 0


def test_base_class_array_pointing_nowhere_is_reported(tmp_path):
    builder = RttiImageBuilder()
    builder.add_class(".?AVNowhere@@")
    blob, expected = builder.build()
    data = bytearray(blob)
    import pe_info
    with pe_info.Image.open(write_image(tmp_path, "probe2.exe", bytes(data))) as image:
        headers = pe_info.PEHeaders(image)
        offset = headers.rva_to_offset(expected["chd_rva"][".?AVNowhere@@"])
    struct.pack_into("<I", data, offset + 12, 0x7F000000)
    path = write_image(tmp_path, "nowhere.exe", bytes(data))
    document = rtti_scan.analyze(path, want_file_digest=False)
    hierarchy = document["classes"][0]["hierarchy"]
    assert hierarchy["base_class_array_readable"] is False
    assert "unreadable" in hierarchy["problem"]


def test_truncation_sweep_never_raises_an_unexpected_exception(positive_image):
    path, _expected = positive_image
    with open(path, "rb") as handle:
        blob = handle.read()
    directory = os.path.dirname(path)
    for keep in range(0x40, len(blob), 61):
        candidate = os.path.join(directory, "trunc.exe")
        with open(candidate, "wb") as handle:
            handle.write(blob[:keep])
        try:
            rtti_scan.analyze(candidate, want_file_digest=False)
        except rtti_scan.PEFormatError:
            pass
        except Exception as error:  # pragma: no cover - the assertion is the point
            pytest.fail("truncation to %d bytes raised %r" % (keep, error))


def test_random_corruption_never_raises_an_unexpected_exception(positive_image):
    import random
    path, _expected = positive_image
    with open(path, "rb") as handle:
        blob = bytearray(handle.read())
    directory = os.path.dirname(path)
    generator = random.Random(20260823)
    for _round in range(40):
        data = bytearray(blob)
        for _hit in range(24):
            data[generator.randrange(0x40, len(data))] = generator.randrange(256)
        candidate = os.path.join(directory, "corrupt.exe")
        with open(candidate, "wb") as handle:
            handle.write(bytes(data))
        try:
            rtti_scan.analyze(candidate, want_file_digest=False)
        except rtti_scan.PEFormatError:
            pass
        except Exception as error:  # pragma: no cover
            pytest.fail("corruption raised %r" % (error,))


def test_analyze_never_reads_the_whole_file_at_once(positive_image, monkeypatch):
    path, _expected = positive_image
    import pe_info
    original = pe_info.Image.read_at
    largest = {"value": 0}

    def spy(self, offset, length, what="read"):
        largest["value"] = max(largest["value"], length)
        return original(self, offset, length, what)

    monkeypatch.setattr(pe_info.Image, "read_at", spy)
    rtti_scan.analyze(path, want_file_digest=False)
    assert largest["value"] <= rtti_scan.SCAN_CHUNK


# --------------------------------------------------------------------------- #
# 6. CLI and artifacts
# --------------------------------------------------------------------------- #

def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, RTTI_SCAN_PATH, *args],
                          capture_output=True, text=True)


def test_cli_human_summary(positive_image):
    path, _expected = positive_image
    result = run_cli(path, "--no-digest")
    assert result.returncode == 0, result.stderr
    assert "VERDICT: FOUND" in result.stdout
    assert "Tested surface" in result.stdout
    assert "Refutation probes" in result.stdout
    assert "ns::Holder<Derived>" in result.stdout


def test_cli_json_is_deterministic(positive_image):
    path, _expected = positive_image
    first = run_cli(path, "--json", "--no-digest")
    second = run_cli(path, "--json", "--no-digest")
    assert first.returncode == second.returncode == 0
    left = json.loads(first.stdout)
    right = json.loads(second.stdout)
    for document in (left, right):
        document.pop("generated_at")
        document.pop("timings_seconds")
    assert left == right


def test_jsonl_artifact_has_one_line_per_class(positive_image):
    path, _expected = positive_image
    result = run_cli(path, "--jsonl", "--no-digest")
    assert result.returncode == 0, result.stderr
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 3
    records = [json.loads(line) for line in lines]
    assert {r["decoded_name"] for r in records} == {
        "Base", "Derived", "ns::Holder<Derived>"}
    for record in records:
        assert record["vtable_code_slots"] >= 1
        assert record["locator_rva"] > 0
        assert record["build_target"] == os.path.basename(path)


def test_cli_writes_both_artifacts(tmp_path, positive_image):
    path, _expected = positive_image
    out = os.path.join(str(tmp_path), "sub", "doc.json")
    jsonl = os.path.join(str(tmp_path), "sub", "rtti.jsonl")
    result = run_cli(path, "--no-digest", "--out", out, "--jsonl-out", jsonl)
    assert result.returncode == 0, result.stderr
    with open(out, encoding="utf-8") as handle:
        document = json.load(handle)
    assert document["summary"]["verdict"] == "FOUND"
    with open(jsonl, encoding="utf-8") as handle:
        assert len([line for line in handle if line.strip()]) == 3
    # deterministic serialisation: LF, no BOM, trailing newline
    with open(out, "rb") as handle:
        raw = handle.read()
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert b"\r\n" not in raw
    assert raw.endswith(b"\n")


@pytest.mark.parametrize("flag", ["--out", "--jsonl-out"])
def test_cli_refuses_output_inside_an_installation(tmp_path, positive_image, flag):
    """D-01 layer 1: neither output path may resolve into an installation."""
    path, _expected = positive_image
    install = tmp_path / "FakeInstall"
    (install / "Engine" / "Binaries" / "Win64").mkdir(parents=True)
    (install / "steam_api64.dll").write_bytes(b"\x00")
    target = str(install / "leak.json")
    result = run_cli(path, "--no-digest", "--install-dir", str(install),
                     flag, target)
    assert result.returncode == 2
    assert not os.path.exists(target)
    assert "refus" in result.stderr.lower() or "install" in result.stderr.lower()


def test_write_text_guard_is_not_bypassable(tmp_path):
    install = tmp_path / "Install2"
    install.mkdir()
    with pytest.raises(pathguard.OutputPathRefused):
        rtti_scan.write_text("x", str(install / "a.json"), str(install), "--out")
    assert not os.path.exists(str(install / "a.json"))


def test_cli_reports_a_broken_file_without_a_traceback(tmp_path):
    path = os.path.join(str(tmp_path), "junk.exe")
    with open(path, "wb") as handle:
        handle.write(b"not a pe at all, not even close")
    result = run_cli(path)
    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert "error:" in result.stderr


def test_cli_missing_file(tmp_path):
    result = run_cli(os.path.join(str(tmp_path), "nope.exe"))
    assert result.returncode == 2
    assert "not a file" in result.stderr


def test_cli_rejects_negative_literal_samples(positive_image):
    path, _expected = positive_image
    result = run_cli(path, "--literal-samples", "-1")
    assert result.returncode == 2


def test_d04_oracle_flag_is_set_only_for_the_oracle_binary(tmp_path, positive_image):
    path, _expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    assert document["d04_oracle_only"] is False
    assert rtti_scan._is_d04_oracle(
        r"D:\Games\Steam\steamapps\common\MISERY\MISERY\Binaries\Win64\MISERY.exe")
    assert not rtti_scan._is_d04_oracle(
        r"D:\Games\...\MISERY\Binaries\Win64\MISERY-Win64-Shipping.exe")


def test_section_restriction_narrows_the_tested_surface(positive_image):
    path, _expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False,
                                 name_sections=(".data",),
                                 locator_sections=(".rdata",))
    names = [s["name"] for s in
             document["tested_surface"]["type_descriptor_name_sections"]]
    assert names == [".data"]
    assert document["summary"]["type_descriptors_structurally_valid"] == 3


def test_attribution_rules_are_published_with_the_results(positive_image):
    """A reviewer must be able to disagree with a rule, not just with a verdict."""
    path, _expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    assert document["attribution_rules"] == list(rtti_scan.ATTRIBUTION_RULES)
    assert len(document["attribution_rules"]) >= 6


# --------------------------------------------------------------------------- #
# 7. the coverage denominator
# --------------------------------------------------------------------------- #

def test_vtable_census_is_off_by_default(positive_image):
    path, _expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    assert document["vtable_census"] is None


def test_vtable_census_counts_runs_and_publishes_its_caveat(positive_image):
    """The census is an approximation and must say so in the artifact.

    The image lays out vtables of 2, 5 and 1 slots, so a threshold of 4 sees
    exactly one run and a threshold of 8 sees none. Asserting both directions is
    the point: a number that silently changes meaning with the threshold is worse
    than no number, which is why three thresholds are reported.
    """
    path, _expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False,
                                 want_vtable_census=True)
    census = document["vtable_census"]
    assert census is not None
    assert census["runs_by_minimum_length"]["4"] == 1
    assert census["runs_by_minimum_length"]["8"] == 0
    assert census["runs_by_minimum_length"]["16"] == 0
    assert census["pointer_slots_addressing_executable_sections"] == 8
    assert "APPROXIMATION" in census["caveat"]
    assert "S-09" in census["caveat"]


def test_explicit_sections_override_the_default_skip_list(positive_image):
    """Naming .text explicitly must actually search it.

    The default surface excludes .text; the refutation that a null result is not
    a scanner failure depends on being able to search it anyway, so a flag that
    silently declined would defeat the purpose.
    """
    path, _expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False,
                                 name_sections=(".text",),
                                 locator_sections=(".text",))
    names = [s["name"] for s in
             document["tested_surface"]["type_descriptor_name_sections"]]
    assert names == [".text"]
    assert document["summary"]["name_strings_found"] == 0
    assert document["summary"]["verdict"] == "NOT FOUND WITHIN TESTED SURFACE"


# --------------------------------------------------------------------------- #
# 8. the tool's own annotations must survive the frozen validator
# --------------------------------------------------------------------------- #

VALIDATE_PATH = os.path.join(REPO_ROOT, "tools", "kb", "validate.py")


def test_emitted_annotations_pass_the_knowledge_base_validator(tmp_path,
                                                               positive_image):
    """The evidence apparatus this tool emits is meant to be spliced into a
    knowledge-base document, so it has to clear tools/kb/validate.py as it
    stands -- not after the reader reshapes it.

    This test exists because of a specific defect. The class-P ``note`` of a
    literal read originally talked ABOUT the record ("the sentence names the
    offset and the length...") instead of BEING the claim. The validator derives
    the claim class of a reduced annotation from that string alone, saw no
    address and no extent in it, derived class I, and then demanded two
    independent methods for a single byte read at confidence 0.99 -- one EV-05
    and one EV-03 violation per literal read. Stating the claim in the field
    that gets graded fixed both.
    """
    path, _expected = positive_image
    document = os.path.join(str(tmp_path), "annotations.json")
    produced = run_cli(path, "--no-digest", "--out", document)
    assert produced.returncode == 0, produced.stderr

    result = subprocess.run([sys.executable, VALIDATE_PATH, document],
                            capture_output=True, text=True, cwd=REPO_ROOT)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "violations: 0" in result.stdout, result.stdout


def test_literal_read_note_is_the_claim_not_a_description_of_it(positive_image):
    """Guard the shape the validator depends on, without invoking it."""
    path, _expected = positive_image
    document = rtti_scan.analyze(path, want_file_digest=False)
    for read in document["literal_reads"]:
        note = read["evidence"]["note"]
        assert note.startswith(read["claim"])
        # naming a structure in this string is exactly what would disqualify the
        # class-P admission of plan.md 10.3 v2.4
        for forbidden in ("TypeDescriptor", "Locator", "ClassHierarchy",
                          " field", "layout", "structure"):
            assert forbidden not in note
        # the pointer to the interpretive half lives outside the graded object
        assert "type_descriptors[]" in read["interpretation_lives_in"]
        assert "interpretation_lives_in" not in read["evidence"]


def test_the_read_locus_is_install_relative_not_a_bare_basename(tmp_path,
                                                               positive_image):
    """A class-P locus must name a determinate location.

    The failure this guards against actually shipped: every read_locus in
    ``research/evidence/S-10/shipping-rtti.json`` named the target as
    ``MISERY-Win64-Shipping.exe``. In THIS installation a basename is not a
    location -- there are two different files called ``MISERY.exe`` -- so the
    locus has to carry the path from the installation root down.
    """
    _path, _expected = positive_image
    fake_root = os.path.join(str(tmp_path), "GameRoot")
    deep = os.path.join(fake_root, "MISERY", "Binaries", "Win64")
    os.makedirs(deep)
    target = os.path.join(deep, "MISERY.exe")
    with open(_path, "rb") as source, open(target, "wb") as sink:
        sink.write(source.read())

    document = rtti_scan.analyze(target, want_file_digest=False,
                                 install_root=fake_root)
    assert document["file"]["install_relative"] == \
        "MISERY/Binaries/Win64/MISERY.exe"
    # the basename stays available under its own key -- the jsonl artifact's
    # build_target is built from it
    assert document["file"]["name"] == "MISERY.exe"
    assert document["literal_reads"]
    for read in document["literal_reads"]:
        assert read["target"] == "MISERY/Binaries/Win64/MISERY.exe"
        assert read["evidence"]["read_locus"]["target"] == \
            "MISERY/Binaries/Win64/MISERY.exe"
        locator = read["evidence"]["sources"][0]["locator"]
        assert locator.startswith("MISERY/Binaries/Win64/MISERY.exe@")
        assert locator.endswith("+%d" % read["length"])
        # and the claim sentence -- the string the validator grades -- says it too
        assert "MISERY/Binaries/Win64/MISERY.exe" in read["claim"]


def test_the_read_locus_falls_back_to_the_basename_outside_an_installation(
        positive_image):
    """No root to be relative to: the basename is what is left, and it is honest.

    Inventing ``../../tmp/x.exe`` would be determinate only for a reader who
    already knows where the root was, which is the defect, not the fix.
    """
    path, _expected = positive_image
    assert rtti_scan.locus_target(path) == os.path.basename(path)
    # an explicit root that does not contain the file is refused, not walked out of
    assert rtti_scan.locus_target(path, install_root=os.path.join(
        os.path.dirname(path), "elsewhere", "deeper")) == os.path.basename(path)


def test_a_locator_straddling_a_chunk_boundary_is_still_found(monkeypatch, tmp_path):
    """The undercount no output would ever show.

    The locator walk streams the image, and a 24-byte record can begin in the
    last five words of a window. Without a step-back overlap that record is
    silently missed -- the counts stay plausible and nothing warns. Shrinking
    SCAN_CHUNK to a size that guarantees a boundary inside the locator block is
    the only way to test the overlap without building a multi-megabyte image.
    """
    builder = RttiImageBuilder()
    for index in range(24):
        builder.add_class(".?AVBoundary%02d@@" % index, vtable_slots=2)
    blob, expected = builder.build()
    path = write_image(tmp_path, "boundary.exe", blob)

    reference = rtti_scan.analyze(path, want_file_digest=False)
    assert reference["summary"]["complete_object_locators_strict"] == 24

    for chunk in (64, 100, 128, 256, 512):
        monkeypatch.setattr(rtti_scan, "SCAN_CHUNK", chunk)
        document = rtti_scan.analyze(path, want_file_digest=False)
        assert document["summary"]["complete_object_locators_strict"] == 24, (
            "SCAN_CHUNK=%d lost a locator" % chunk)
        assert sorted(c["locator_rva"] for c in document["classes"]) == \
            sorted(expected["locator_rva"].values())
        # and it must not double-count the straddling record either
        assert len(document["classes"]) == 24
