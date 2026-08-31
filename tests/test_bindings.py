#!/usr/bin/env python3
"""The binding profile must still equal the runs that measured it.

WHY THIS TEST IS THE POINT OF THE PROFILE
-----------------------------------------
A binding profile is a list of numbers that were true about one executable. The
danger is not that they are wrong today -- they were measured -- but that they
quietly stop matching their source: somebody edits the JSON, or moves a research
constant, and the two copies drift apart with nothing comparing them. That is
exactly how the ModId rule drifted across Stages 2, 3 and 4.

So every fact in the emitted profile is compared here against the file that
measured it. The emitter reads those sources; this test asserts it still does,
and that a hand-edited profile would be caught.

The second half exercises the C++ reader on files this test writes, because
"fail closed" is a claim about what the runtime REFUSES, and refusals are only
proven by handing it something it must refuse.
"""
import copy
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (os.path.join(REPO, "tools", "modplatform"),
           os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import bindings as B                                            # noqa: E402

EXE = os.path.join("D:\\", "Games", "Steam", "steamapps", "common", "MISERY",
                   "MISERY", "Binaries", "Win64", "MISERY-Win64-Shipping.exe")
BUILD_KEY = ("sha256:bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a"
             "81f013331")
SCRATCH = os.path.join("D:\\", "UEScratch", "Stage5", "bindings-tests")
HARNESS = os.path.join(REPO, "workspace", "msvc-stage5", "bindings_harness.exe")


def emitted():
    """The profile for the live installation, or None when it is not here.

    The emitter needs the executable it describes, and a checkout without the
    game installed is a legitimate place to run the rest of the suite.
    """
    if not os.path.isfile(EXE):
        return None
    build_id, engine = B.engine_from_index(BUILD_KEY)
    return B.emit(EXE, build_id, BUILD_KEY, engine,
                  generated_at="1970-01-01T00:00:00Z")


PROFILE = emitted()


@unittest.skipIf(PROFILE is None, "the game is not installed on this machine")
class EmittedProfileMatchesItsSources(unittest.TestCase):
    def test_the_addresses_are_the_research_constants(self):
        import eri
        import cr01c1_controller as c1
        import fts_controller as fts
        want = {
            "guobjectarray": eri.DEFAULT_GUOBJECTARRAY_RVA,
            "namepool": eri.DEFAULT_NAMEPOOL_RVA,
            "name_pool_initialized": eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
            "add_ticker": fts.RVA_ADD_TICKER,
            "get_core_ticker": fts.RVA_GET_CORE_TICKER,
            "fmemory_malloc": fts.RVA_FMEMORY_MALLOC,
        }
        for name, rva in want.items():
            self.assertIn(name, PROFILE["addresses"], name)
            self.assertEqual(rva, PROFILE["addresses"][name]["rva"], name)
        self.assertEqual(c1.PE_SLOT,
                         PROFILE["vtable_slots"]["process_event"]["slot"])

    def test_every_code_address_carries_the_bytes_actually_in_the_exe(self):
        """The guard is the bytes, so the bytes must come from the file."""
        with open(EXE, "rb") as handle:
            image = handle.read()
        code = [(name, entry) for name, entry in PROFILE["addresses"].items()
                if entry["kind"] == "code"]
        self.assertTrue(code, "a profile with no code addresses verifies nothing")
        for name, entry in code:
            raw = B.section_bytes(image, entry["rva"], 16)
            self.assertIsNotNone(raw, name)
            self.assertEqual(raw.hex(), entry["bytes"], name)

    def test_data_addresses_carry_no_bytes(self):
        """There is nothing stable at a live global, so promising bytes there
        would be promising something the runtime could not check."""
        for name, entry in PROFILE["addresses"].items():
            if entry["kind"] == "data":
                self.assertNotIn("bytes", entry, name)

    def test_the_row_struct_offsets_are_the_reflection_dump(self):
        with open(B.STRUCT_DEFS, encoding="utf-8") as handle:
            fields = json.load(handle)[B.ROW_STRUCT_NAME]["fields"]
        by_logical = {f["name"].split("_")[0]: f["offset"] for f in fields}
        for name, offset in PROFILE["row_struct"]["fields"].items():
            self.assertEqual(by_logical[name], offset, name)
        self.assertEqual(2264, PROFILE["row_struct"]["size"])

    def test_the_function_gates_are_the_ones_the_proven_probe_enforced(self):
        """Parsed out of CR-01C5's own gate() calls, not restated.

        The controller is the thing that actually ran these functions in a live
        game. If its expectations and the profile's ever diverge, the profile is
        describing a build the probe never proved.
        """
        source = os.path.join(REPO, "research", "instruments", "ipp",
                              "cr01c5_controller.py")
        with open(source, encoding="utf-8") as handle:
            text = handle.read()
        calls = re.findall(
            r'gate\((\w+),\s*"([^"]+)",\s*(\d+)'
            r'(?:,\s*rvo=(\d+))?(?:,\s*need=(0x[0-9A-Fa-f]+))?\)', text)
        self.assertTrue(calls, "no gate() calls were found to compare against")
        seen = 0
        for _var, label, parms, rvo, need in calls:
            matches = [name for name in PROFILE["functions"]["gates"]
                       if name.split("::", 1)[1] == label]
            self.assertEqual(1, len(matches),
                             "%s: %d profile entries" % (label, len(matches)))
            gate = PROFILE["functions"]["gates"][matches[0]]
            self.assertEqual(int(parms), gate["parms_size"], label)
            self.assertEqual(int(rvo) if rvo else None,
                             gate["return_value_offset"], label)
            self.assertEqual(int(need, 16) if need else 0,
                             gate["require_flags"], label)
            seen += 1
        self.assertEqual(seen, len(PROFILE["functions"]["gates"]),
                         "the profile carries a gate the controller does not")

    def test_the_forbidden_flag_mask_is_the_controllers(self):
        source = os.path.join(REPO, "research", "instruments", "ipp",
                              "cr01c5_controller.py")
        with open(source, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("fl & 0x0138C0C4", text,
                      "the controller's net/authority mask moved")
        self.assertEqual(0x0138C0C4, PROFILE["functions"]["forbid_flags"])

    def test_the_identity_is_recomputed_not_copied(self):
        self.assertEqual(BUILD_KEY, PROFILE["build"]["build_key"])
        self.assertEqual("5.4.4", PROFILE["build"]["engine_version"])
        self.assertEqual(35576357, PROFILE["build"]["engine_cl"])
        self.assertEqual("Shipping", PROFILE["build"]["build_configuration"])

    def test_a_build_key_that_is_not_the_files_digest_is_refused(self):
        build_id, engine = B.engine_from_index(BUILD_KEY)
        with self.assertRaises(B.BindingsError):
            B.emit(EXE, build_id, "sha256:" + "0" * 64, engine)


# --------------------------------------------------------------------------
# VerifyCode, exercised without the game.
#
# VerifyCode is the guard everything else rests on: the RVA is a promise and the
# recorded bytes are what make it checkable. It used to be reachable only by
# launching MISERY, which left the one function that must never be wrong as the
# one function with no offline test.
#
# It does not need MISERY -- it needs a mapped PE and a profile describing it.
# So these tests describe the HARNESS ITSELF and let the real comparison run.
# --------------------------------------------------------------------------
def relocated_rvas(image):
    """Every RVA a base relocation patches at load time.

    This is not a detail to skip. .text is mapped verbatim from file EXCEPT
    where the loader rewrites an absolute address, and the harness is built
    /DYNAMICBASE so it is always rebased. A 16-byte window overlapping a
    relocation therefore differs between file and memory for a completely
    legitimate reason -- and a test that picked such a window would report a
    VerifyCode defect that does not exist.
    """
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    opt = pe + 24
    # Data directory 5 is BaseRelocationTable; for PE32+ the directories start
    # at optional-header offset 112.
    dir_rva, dir_size = struct.unpack_from("<II", image, opt + 112 + 5 * 8)
    if dir_rva == 0 or dir_size == 0:
        return set()
    raw = B.section_bytes(image, dir_rva, dir_size)
    patched = set()
    at = 0
    while at + 8 <= len(raw):
        page_rva, block_size = struct.unpack_from("<II", raw, at)
        if block_size < 8 or at + block_size > len(raw):
            break
        for entry_at in range(at + 8, at + block_size, 2):
            (entry,) = struct.unpack_from("<H", raw, entry_at)
            kind, offset = entry >> 12, entry & 0xFFF
            if kind == 0:            # IMAGE_REL_BASED_ABSOLUTE: padding
                continue
            # A DIR64 relocation rewrites eight bytes.
            width = 8 if kind == 10 else 4
            for byte in range(width):
                patched.add(page_rva + offset + byte)
        at += block_size
    return patched


def clean_code_windows(image, count, width=16):
    """*count* RVAs in an executable section that no relocation touches."""
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    sections = struct.unpack_from("<H", image, pe + 6)[0]
    opt_size = struct.unpack_from("<H", image, pe + 20)[0]
    table = pe + 24 + opt_size
    patched = relocated_rvas(image)
    found = []
    for index in range(sections):
        entry = table + index * 40
        virt_size, virt_addr, raw_size, _raw_ptr = struct.unpack_from(
            "<IIII", image, entry + 8)
        (characteristics,) = struct.unpack_from("<I", image, entry + 36)
        if not characteristics & 0x20000000:            # MEM_EXECUTE
            continue
        usable = min(virt_size, raw_size)
        # Step well inside the section and stride widely, so the windows are
        # spread rather than adjacent.
        for rva in range(virt_addr + 0x40, virt_addr + usable - width, 0x400):
            if any((rva + b) in patched for b in range(width)):
                continue
            if B.section_bytes(image, rva, width) is None:
                continue
            found.append(rva)
            if len(found) == count:
                return found
    return found


def profile_for_self():
    """A profile describing bindings_harness.exe, built the way the reader wants.

    Deliberately assembled here rather than by the production emitter: the
    emitter's whole job is to describe MISERY from measured sources, and
    teaching it to describe an arbitrary PE to satisfy a test would make it
    worse at the thing it exists for.
    """
    with open(HARNESS, "rb") as handle:
        image = handle.read()
    rvas = clean_code_windows(image, 4)
    assert len(rvas) == 4, "no unrelocated code windows found in the harness"
    addresses = {}
    for n, rva in enumerate(rvas):
        addresses["self_code_%d" % n] = {
            "kind": "code", "rva": rva,
            "bytes": B.section_bytes(image, rva, 16).hex(),
            "source": "tests/test_bindings.py: this executable",
        }
    return image, {
        "bindings_version": 1,
        "generated_by": "tests/test_bindings.py",
        "generated_at": "1970-01-01T00:00:00Z",
        "build": {
            "build_id": "bindings-harness-self",
            "build_key": "sha256:" + hashlib.sha256(image).hexdigest(),
            "image_size_bytes": B.image_size(image),
            "file_size_bytes": len(image),
            "engine_version": "5.4.4",
            "engine_cl": 35576357,
            "build_configuration": "Shipping",
        },
        "addresses": addresses,
        "vtable_slots": {"process_event": {"slot": 77, "source": "n/a"}},
        "functions": {"forbid_flags": 0x0138C0C4, "gates": {}},
        "row_struct": {"name": "S_ItemDetails", "size": 2264,
                       "fields": {"Name": 0}, "source": "n/a"},
        "object_layout": {"datatable_rowstruct": 40,
                          "datatable_parent_tables": 176,
                          "ustruct_properties_size": 88},
    }


@unittest.skipUnless(os.path.isfile(HARNESS),
                     "bindings_harness.exe has not been built")
class VerifyCodeComparesAgainstMappedMemory(unittest.TestCase):
    def setUp(self):
        self.image, self.profile = profile_for_self()

    def verify(self, profile):
        os.makedirs(SCRATCH, exist_ok=True)
        path = os.path.join(SCRATCH, "self.json")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(profile, handle, indent=2, sort_keys=True)
        result = subprocess.run(
            [HARNESS, path, profile["build"]["build_key"], "--verify-self"],
            capture_output=True, text=True, timeout=60)
        return json.loads(result.stdout.strip().splitlines()[-1])

    def test_bytes_read_from_the_file_match_the_mapped_image(self):
        out = self.verify(self.profile)
        self.assertTrue(out["ok"], out)
        self.assertEqual(B.image_size(self.image), out["image_size_bytes"])

    def test_one_wrong_byte_is_caught_and_the_address_is_named(self):
        """The case the whole layer exists for, and it is one byte."""
        for name in sorted(self.profile["addresses"]):
            bad = copy.deepcopy(self.profile)
            recorded = bad["addresses"][name]["bytes"]
            flipped = "%02x" % (int(recorded[:2], 16) ^ 0xFF)
            bad["addresses"][name]["bytes"] = flipped + recorded[2:]
            out = self.verify(bad)
            self.assertFalse(out["ok"], name)
            self.assertIn(name, out["error"], name)
            self.assertIn("does not hold the code the profile recorded",
                          out["error"])

    def test_a_wrong_byte_anywhere_in_the_window_is_caught(self):
        """Not just the first: a 16-byte compare that only checked byte 0 would
        pass every test above."""
        name = sorted(self.profile["addresses"])[0]
        for position in (1, 7, 15):
            bad = copy.deepcopy(self.profile)
            recorded = bad["addresses"][name]["bytes"]
            at = position * 2
            flipped = "%02x" % (int(recorded[at:at + 2], 16) ^ 0xFF)
            bad["addresses"][name]["bytes"] = (
                recorded[:at] + flipped + recorded[at + 2:])
            out = self.verify(bad)
            self.assertFalse(out["ok"], "byte %d" % position)
            self.assertIn(name, out["error"])

    def test_an_image_of_another_size_is_refused_before_any_compare(self):
        """A module whose size is not the one described is not the module."""
        bad = copy.deepcopy(self.profile)
        bad["build"]["image_size_bytes"] = B.image_size(self.image) + 0x1000
        out = self.verify(bad)
        self.assertFalse(out["ok"])
        self.assertIn("the profile describes one of", out["error"])

    def test_a_profile_with_no_code_addresses_is_refused(self):
        """Verifying nothing must not read as verifying everything."""
        bad = copy.deepcopy(self.profile)
        for entry in bad["addresses"].values():
            entry["kind"] = "data"
            entry.pop("bytes", None)
        out = self.verify(bad)
        self.assertFalse(out["ok"])
        self.assertIn("no code addresses to verify", out["error"])


def run_harness(profile, key="-"):
    """Write *profile* to a file and ask the C++ reader what it makes of it."""
    os.makedirs(SCRATCH, exist_ok=True)
    path = os.path.join(SCRATCH, "case.json")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        if isinstance(profile, str):
            handle.write(profile)
        else:
            json.dump(profile, handle, indent=2, sort_keys=True)
    result = subprocess.run([HARNESS, path, key], capture_output=True,
                            text=True, timeout=60)
    return json.loads(result.stdout.strip().splitlines()[-1])


@unittest.skipIf(PROFILE is None, "the game is not installed on this machine")
@unittest.skipUnless(os.path.isfile(HARNESS),
                     "bindings_harness.exe has not been built")
class TheReaderRefusesWhatItCannotTrust(unittest.TestCase):
    """Each case hands the reader one specific lie and asserts it says no.

    The assertion is on the REASON as well as the refusal: a reader that
    rejected everything with one generic message would pass a test that only
    checked ok == false, and would tell a user nothing on the day it fires.
    """

    def test_the_real_profile_loads_and_is_fully_populated(self):
        out = run_harness(PROFILE, BUILD_KEY)
        self.assertTrue(out["ok"], out)
        self.assertEqual(BUILD_KEY, out["build_key"])
        self.assertEqual(len(PROFILE["addresses"]), out["addresses"])
        self.assertEqual(6, out["code_addresses"])
        self.assertEqual(len(PROFILE["vtable_slots"]), out["slots"])
        self.assertEqual(len(PROFILE["functions"]["gates"]), out["gates"])
        self.assertEqual(2264, out["row_struct_size"])
        self.assertEqual(95, out["lookup"]["add_row_slot"])
        self.assertEqual(16, out["lookup"]["shortname_offset"])
        self.assertTrue(out["lookup"]["absent_is_refused"])
        self.assertEqual(16, out["gate"]["rvo"])

    def test_a_profile_for_another_build_is_refused(self):
        out = run_harness(PROFILE, "sha256:" + "1" * 64)
        self.assertFalse(out["ok"])
        self.assertIn("hashes to", out["error"])

    def test_an_unknown_bindings_version_is_refused_not_read_leniently(self):
        bad = copy.deepcopy(PROFILE)
        bad["bindings_version"] = 2
        out = run_harness(bad)
        self.assertFalse(out["ok"])
        self.assertIn("bindings_version 2", out["error"])

    def test_another_engine_version_is_refused(self):
        bad = copy.deepcopy(PROFILE)
        bad["build"]["engine_version"] = "5.5.0"
        out = run_harness(bad)
        self.assertFalse(out["ok"])
        self.assertIn("engine 5.5.0", out["error"])

    def test_a_missing_section_is_named(self):
        for section in ("addresses", "vtable_slots", "functions", "row_struct",
                        "object_layout", "build"):
            bad = copy.deepcopy(PROFILE)
            del bad[section]
            out = run_harness(bad)
            self.assertFalse(out["ok"], section)
            self.assertIn(section, out["error"], section)

    def test_an_address_outside_the_image_is_refused(self):
        bad = copy.deepcopy(PROFILE)
        bad["addresses"]["add_ticker"]["rva"] = bad["build"]["image_size_bytes"]
        out = run_harness(bad)
        self.assertFalse(out["ok"])
        self.assertIn("outside the image", out["error"])

    def test_expected_bytes_that_are_not_sixteen_bytes_of_hex_are_refused(self):
        for value in ("48895c", "zzzz" * 8, ""):
            bad = copy.deepcopy(PROFILE)
            bad["addresses"]["add_ticker"]["bytes"] = value
            out = run_harness(bad)
            self.assertFalse(out["ok"], value)
            self.assertIn("add_ticker", out["error"])

    def test_a_code_address_with_no_expected_bytes_is_refused(self):
        bad = copy.deepcopy(PROFILE)
        del bad["addresses"]["add_ticker"]["bytes"]
        out = run_harness(bad)
        self.assertFalse(out["ok"])
        self.assertIn("bytes", out["error"])

    def test_a_layout_constant_that_disagrees_with_the_runtime_is_refused(self):
        """The profile cannot correct a number the runtime compiled in."""
        bad = copy.deepcopy(PROFILE)
        bad["object_layout"]["datatable_rowstruct"] = 48
        out = run_harness(bad)
        self.assertFalse(out["ok"])
        self.assertIn("compiled for 40", out["error"])

    def test_an_implausible_vtable_slot_is_refused(self):
        bad = copy.deepcopy(PROFILE)
        bad["vtable_slots"]["datatable_add_row"]["slot"] = 100000
        out = run_harness(bad)
        self.assertFalse(out["ok"])
        self.assertIn("past any plausible vtable", out["error"])

    def test_a_row_field_offset_outside_the_struct_is_refused(self):
        bad = copy.deepcopy(PROFILE)
        bad["row_struct"]["fields"]["ShortName"] = bad["row_struct"]["size"]
        out = run_harness(bad)
        self.assertFalse(out["ok"])
        self.assertIn("ShortName", out["error"])

    def test_a_gate_without_a_stated_return_value_offset_is_refused(self):
        """`null` means unconstrained; ABSENT means the emitter forgot, and the
        reader must not silently pick one of those meanings."""
        bad = copy.deepcopy(PROFILE)
        gate = "KismetTextLibrary::Conv_StringToText"
        del bad["functions"]["gates"][gate]["return_value_offset"]
        out = run_harness(bad)
        self.assertFalse(out["ok"])
        self.assertIn("return_value_offset", out["error"])

    def test_malformed_json_is_refused_with_a_position(self):
        for text, expect in (
                ('{"bindings_version": 1', "expected ',' or '}'"),
                ('{"build": {"build_id": "unterminated}', "never closed"),
                ('{"bindings_version": 1.5}', "fractional"),
                ('{"bindings_version": 1}  {"and": "more"}', "trailing"),
                ('{"a": 1, "a": 2}', "repeats a key")):
            out = run_harness(text)
            self.assertFalse(out["ok"], text)
            self.assertIn(expect, out["error"], text)


if __name__ == "__main__":
    unittest.main()
