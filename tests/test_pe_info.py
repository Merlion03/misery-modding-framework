#!/usr/bin/env python3
"""Tests for tools/fingerprint/pe_info.py (task F-01).

Every input here is a SYNTHETIC PE image assembled byte by byte in a temporary
directory. No test reads a game file: decision D-01 makes the installation a
read-only research target, and a test suite that depends on it is neither
reproducible on another machine nor runnable in CI where the game is absent.
Building the images by hand also means each test knows the exact value it
expects at the exact offset it wrote, which is what makes a failure diagnosable
rather than merely red.

The builder below is deliberately literal -- it packs the real structures at the
real offsets instead of copying a template blob -- so a test can corrupt exactly
one field (a section count, a directory RVA, a length) and nothing else.

Coverage, matching the F-01 brief:
  * a minimal valid PE64 (headers, section table, checksum round-trip)
  * truncated headers, at three different truncation points
  * a bogus section count
  * an out-of-range data directory RVA
  * a TLS directory with two callbacks
  * an import table with an ordinal-only entry (and a delay-load table)
  * a resource tree with and without VS_VERSIONINFO
  * exports, CodeView debug entry, Rich header, load config
  * the pathguard contract on --out
  * deterministic output
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "fingerprint"))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "inventory"))

import pathguard  # noqa: E402
import pe_info  # noqa: E402

PE_INFO_PATH = os.path.join(REPO_ROOT, "tools", "fingerprint", "pe_info.py")

IMAGE_BASE = 0x140000000
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000


# --------------------------------------------------------------------------- #
# synthetic PE builder
# --------------------------------------------------------------------------- #

def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


class PEBuilder:
    """Assembles a PE32+ image from explicit field values.

    Nothing is inferred that a test might want to break: the caller supplies
    section data and directory entries, and every header field that a test does
    not name gets a plausible constant. ``build()`` is the only place that lays
    out file offsets, and it does so in one pass so the numbers in the produced
    image and the numbers a test asserts on come from the same arithmetic.
    """

    def __init__(self, e_lfanew: int = 0x80) -> None:
        self.e_lfanew = e_lfanew
        self.machine = 0x8664
        self.timestamp = 0x5F000000
        self.characteristics = 0x0022
        self.subsystem = 2
        self.dll_characteristics = 0x8160
        self.entry_point = 0x1000
        self.image_base = IMAGE_BASE
        self.checksum = 0
        self.number_of_sections_override: int | None = None
        self.number_of_rva_and_sizes = 16
        self.sections: list[dict] = []
        self.directories: dict[int, tuple[int, int]] = {}
        self.dos_stub = b""          # bytes between offset 0x40 and e_lfanew

    # -- authoring ---------------------------------------------------------- #

    def add_section(self, name: str, rva: int, data: bytes,
                    characteristics: int = 0x40000040,
                    vsize: int | None = None,
                    raw_size_override: int | None = None) -> None:
        self.sections.append({
            "name": name,
            "rva": rva,
            "data": data,
            "characteristics": characteristics,
            "vsize": len(data) if vsize is None else vsize,
            "raw_size_override": raw_size_override,
        })

    def set_directory(self, index: int, rva: int, size: int) -> None:
        self.directories[index] = (rva, size)

    # -- layout ------------------------------------------------------------- #

    def build(self, *, fix_checksum: bool = False) -> bytes:
        count = (self.number_of_sections_override
                 if self.number_of_sections_override is not None
                 else len(self.sections))
        optional_size = 112 + 8 * self.number_of_rva_and_sizes
        header_end = self.e_lfanew + 24 + optional_size + 40 * len(self.sections)
        size_of_headers = _align(header_end, FILE_ALIGNMENT)

        # Place raw data in section order, each at a file-alignment boundary.
        offset = size_of_headers
        for section in self.sections:
            raw = _align(len(section["data"]), FILE_ALIGNMENT)
            section["raw_pointer"] = offset if raw else 0
            section["raw_size"] = (raw if section["raw_size_override"] is None
                                   else section["raw_size_override"])
            offset += raw
        total = offset

        size_of_image = SECTION_ALIGNMENT
        for section in self.sections:
            size_of_image = max(size_of_image,
                                _align(section["rva"] + max(section["vsize"], 1),
                                       SECTION_ALIGNMENT))

        image = bytearray(total)

        # --- DOS header + stub
        image[0:2] = b"MZ"
        struct.pack_into("<H", image, 2, total % 512)
        struct.pack_into("<I", image, 0x3C, self.e_lfanew)
        if self.dos_stub:
            stub_end = min(0x40 + len(self.dos_stub), self.e_lfanew)
            image[0x40:stub_end] = self.dos_stub[:stub_end - 0x40]

        # --- PE signature + COFF header
        position = self.e_lfanew
        image[position:position + 4] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", image, position + 4,
                         self.machine, count, self.timestamp, 0, 0,
                         optional_size, self.characteristics)

        # --- optional header (PE32+)
        opt = position + 24
        struct.pack_into("<H", image, opt, 0x20B)
        struct.pack_into("<BB", image, opt + 2, 14, 34)
        struct.pack_into("<III", image, opt + 4, 0x1000, 0x1000, 0)
        struct.pack_into("<I", image, opt + 16, self.entry_point)
        struct.pack_into("<I", image, opt + 20, 0x1000)          # BaseOfCode
        struct.pack_into("<Q", image, opt + 24, self.image_base)
        struct.pack_into("<II", image, opt + 32, SECTION_ALIGNMENT, FILE_ALIGNMENT)
        struct.pack_into("<HHHHHH", image, opt + 40, 6, 0, 0, 0, 6, 0)
        struct.pack_into("<I", image, opt + 52, 0)               # Win32VersionValue
        struct.pack_into("<I", image, opt + 56, size_of_image)
        struct.pack_into("<I", image, opt + 60, size_of_headers)
        struct.pack_into("<I", image, opt + 64, self.checksum)
        struct.pack_into("<HH", image, opt + 68, self.subsystem,
                         self.dll_characteristics)
        struct.pack_into("<QQQQ", image, opt + 72,
                         0x100000, 0x1000, 0x100000, 0x1000)
        struct.pack_into("<II", image, opt + 104, 0, self.number_of_rva_and_sizes)
        for index in range(self.number_of_rva_and_sizes):
            rva, size = self.directories.get(index, (0, 0))
            struct.pack_into("<II", image, opt + 112 + index * 8, rva, size)

        # --- section table
        table = opt + optional_size
        for index, section in enumerate(self.sections):
            row = table + index * 40
            image[row:row + 8] = section["name"].encode("ascii")[:8].ljust(8, b"\x00")
            struct.pack_into("<IIII", image, row + 8,
                             section["vsize"], section["rva"],
                             section["raw_size"], section["raw_pointer"])
            struct.pack_into("<IIHH", image, row + 24, 0, 0, 0, 0)
            struct.pack_into("<I", image, row + 36, section["characteristics"])

        # --- section data
        for section in self.sections:
            start = section["raw_pointer"]
            if start:
                image[start:start + len(section["data"])] = section["data"]

        blob = bytes(image)
        if fix_checksum:
            blob = _with_valid_checksum(blob, opt + 64)
        return blob


def _with_valid_checksum(blob: bytes, checksum_offset: int) -> bytes:
    """Return *blob* with a correct PE checksum stored at *checksum_offset*.

    Computed independently of pe_info's implementation (a plain loop over 16-bit
    words) so a test that asserts ``checksum_valid`` is comparing two separate
    derivations of the same algorithm rather than one function against itself.
    """
    data = bytearray(blob)
    data[checksum_offset:checksum_offset + 4] = b"\x00\x00\x00\x00"
    total = 0
    for index in range(0, len(data) - 1, 2):
        total += data[index] | (data[index + 1] << 8)
    if len(data) & 1:
        total += data[-1]
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    total = (total + len(data)) & 0xFFFFFFFF
    struct.pack_into("<I", data, checksum_offset, total)
    return bytes(data)


def write_image(tmp_path, name: str, blob: bytes) -> str:
    path = os.path.join(str(tmp_path), name)
    with open(path, "wb") as handle:
        handle.write(blob)
    return path


# --------------------------------------------------------------------------- #
# structure builders used by several tests
# --------------------------------------------------------------------------- #

def build_import_blob(base_rva: int, modules) -> bytes:
    """An import table (descriptors + ILT + IAT + names) laid out at *base_rva*.

    *modules* is a sequence of ``(dll_name, [entry, ...])`` where an entry is
    either ``("name", "Symbol", hint)`` or ``("ordinal", 1234)``. The ordinal
    form is what sets the high bit of the thunk, and is the case the F-01 brief
    calls out explicitly.
    """
    descriptor_size = 20 * (len(modules) + 1)
    body = bytearray()
    offsets = {}

    def place(data: bytes) -> int:
        offset = descriptor_size + len(body)
        body.extend(data)
        if len(body) % 2:
            body.append(0)
        return offset

    thunks = []
    for name, entries in modules:
        name_offset = place(name.encode("ascii") + b"\x00")
        values = []
        for entry in entries:
            if entry[0] == "ordinal":
                values.append(0x8000000000000000 | (entry[1] & 0xFFFF))
            else:
                hint = entry[2] if len(entry) > 2 else 0
                by_name = struct.pack("<H", hint) + entry[1].encode("ascii") + b"\x00"
                values.append(base_rva + place(by_name))
        thunks.append((name_offset, values))

    ilt_offsets = []
    iat_offsets = []
    for _name_offset, values in thunks:
        while len(body) % 8:
            body.append(0)
        ilt_offsets.append(descriptor_size + len(body))
        for value in values:
            body.extend(struct.pack("<Q", value))
        body.extend(b"\x00" * 8)
        while len(body) % 8:
            body.append(0)
        iat_offsets.append(descriptor_size + len(body))
        for value in values:
            body.extend(struct.pack("<Q", value))
        body.extend(b"\x00" * 8)

    out = bytearray(descriptor_size)
    for index, (name_offset, _values) in enumerate(thunks):
        struct.pack_into("<IIIII", out, index * 20,
                         base_rva + ilt_offsets[index], 0, 0,
                         base_rva + name_offset,
                         base_rva + iat_offsets[index])
    offsets["descriptors"] = descriptor_size
    return bytes(out) + bytes(body)


def build_delay_import_blob(base_rva: int, modules) -> bytes:
    """A delay-load table (ImgDelayDescr) in the modern RVA form (dlattrRva=1)."""
    descriptor_size = 32 * (len(modules) + 1)
    body = bytearray()

    def place(data: bytes) -> int:
        offset = descriptor_size + len(body)
        body.extend(data)
        while len(body) % 2:
            body.append(0)
        return offset

    prepared = []
    for name, entries in modules:
        name_offset = place(name.encode("ascii") + b"\x00")
        values = []
        for entry in entries:
            if entry[0] == "ordinal":
                values.append(0x8000000000000000 | (entry[1] & 0xFFFF))
            else:
                by_name = struct.pack("<H", 0) + entry[1].encode("ascii") + b"\x00"
                values.append(base_rva + place(by_name))
        prepared.append((name_offset, values))

    int_offsets = []
    iat_offsets = []
    for _name_offset, values in prepared:
        while len(body) % 8:
            body.append(0)
        int_offsets.append(descriptor_size + len(body))
        for value in values:
            body.extend(struct.pack("<Q", value))
        body.extend(b"\x00" * 8)
        while len(body) % 8:
            body.append(0)
        iat_offsets.append(descriptor_size + len(body))
        for value in values:
            body.extend(struct.pack("<Q", value))
        body.extend(b"\x00" * 8)

    out = bytearray(descriptor_size)
    for index, (name_offset, _values) in enumerate(prepared):
        struct.pack_into("<IIIIIIII", out, index * 32,
                         1,                                   # grAttrs: dlattrRva
                         base_rva + name_offset,
                         0,
                         base_rva + iat_offsets[index],
                         base_rva + int_offsets[index],
                         0, 0, 0)
    return bytes(out) + bytes(body)


def build_export_blob(base_rva: int, dll_name: str, names, ordinal_base: int = 1) -> bytes:
    """An export directory exporting *names* at synthetic addresses."""
    header = 40
    body = bytearray()

    def place(data: bytes) -> int:
        offset = header + len(body)
        body.extend(data)
        while len(body) % 2:
            body.append(0)
        return offset

    dll_offset = place(dll_name.encode("ascii") + b"\x00")
    name_offsets = [place(name.encode("ascii") + b"\x00") for name in names]

    while len(body) % 4:
        body.append(0)
    functions_offset = header + len(body)
    for index in range(len(names)):
        # Deliberately inside .text: an address that falls INSIDE the
        # export directory is by definition a forwarder, not a function.
        body.extend(struct.pack("<I", 0x1000 + index * 0x10))
    names_offset = header + len(body)
    for offset in name_offsets:
        body.extend(struct.pack("<I", base_rva + offset))
    ordinals_offset = header + len(body)
    for index in range(len(names)):
        body.extend(struct.pack("<H", index))

    out = bytearray(header)
    struct.pack_into("<IIHHIIIIIII", out, 0,
                     0, 0x5F000000, 0, 0,
                     base_rva + dll_offset, ordinal_base,
                     len(names), len(names),
                     base_rva + functions_offset,
                     base_rva + names_offset,
                     base_rva + ordinals_offset)
    return bytes(out) + bytes(body)


def build_tls_blob(base_rva: int, callbacks) -> bytes:
    """IMAGE_TLS_DIRECTORY64 followed by a NULL-terminated callback array."""
    directory_size = 40
    array_offset = directory_size
    out = bytearray(directory_size)
    struct.pack_into("<QQQQII", out, 0,
                     IMAGE_BASE + 0x3000,          # StartAddressOfRawData
                     IMAGE_BASE + 0x3010,          # EndAddressOfRawData
                     IMAGE_BASE + 0x3020,          # AddressOfIndex
                     IMAGE_BASE + base_rva + array_offset,
                     0, 0)
    body = bytearray()
    for callback in callbacks:
        body.extend(struct.pack("<Q", callback))
    body.extend(b"\x00" * 8)
    return bytes(out) + bytes(body)


def build_debug_blob(base_rva: int, pdb_path: str, guid: bytes, age: int) -> bytes:
    """One CODEVIEW IMAGE_DEBUG_DIRECTORY entry plus its RSDS payload."""
    header = 28
    payload = b"RSDS" + guid + struct.pack("<I", age) + pdb_path.encode("ascii") + b"\x00"
    out = bytearray(header)
    struct.pack_into("<IIHHIIII", out, 0,
                     0, 0x5F000000, 0, 0, 2, len(payload),
                     base_rva + header, 0)
    return bytes(out) + payload


# -- resources -------------------------------------------------------------- #

def build_resource_blob(base_rva: int, tree) -> bytes:
    """A three-level .rsrc tree from ``{type_id: {name_id: {lang_id: bytes}}}``.

    Directory-entry offsets are relative to the resource base; the data entry's
    OffsetToData is an absolute RVA. Getting those two conventions the right way
    round is precisely what the parser has to do, so the builder writes them
    literally rather than through a helper that could share a bug with it.
    """
    types = sorted(tree)
    size = 16 + 8 * len(types)
    level2 = {}
    for type_id in types:
        level2[type_id] = size
        size += 16 + 8 * len(tree[type_id])
    level3 = {}
    for type_id in types:
        for name_id in sorted(tree[type_id]):
            level3[(type_id, name_id)] = size
            size += 16 + 8 * len(tree[type_id][name_id])
    data_entries = {}
    for type_id in types:
        for name_id in sorted(tree[type_id]):
            for lang_id in sorted(tree[type_id][name_id]):
                data_entries[(type_id, name_id, lang_id)] = size
                size += 16
    size = _align(size, 4)
    payloads = {}
    for type_id in types:
        for name_id in sorted(tree[type_id]):
            for lang_id in sorted(tree[type_id][name_id]):
                payloads[(type_id, name_id, lang_id)] = size
                size += len(tree[type_id][name_id][lang_id])
                size = _align(size, 4)

    out = bytearray(size)

    def write_directory(offset: int, entries) -> None:
        struct.pack_into("<IIHHHH", out, offset, 0, 0, 0, 0, 0, len(entries))
        for index, (identifier, target, is_directory) in enumerate(entries):
            struct.pack_into("<II", out, offset + 16 + index * 8,
                             identifier,
                             (0x80000000 | target) if is_directory else target)

    write_directory(0, [(type_id, level2[type_id], True) for type_id in types])
    for type_id in types:
        write_directory(level2[type_id],
                        [(name_id, level3[(type_id, name_id)], True)
                         for name_id in sorted(tree[type_id])])
        for name_id in sorted(tree[type_id]):
            write_directory(
                level3[(type_id, name_id)],
                [(lang_id, data_entries[(type_id, name_id, lang_id)], False)
                 for lang_id in sorted(tree[type_id][name_id])])
    for key, offset in data_entries.items():
        blob = tree[key[0]][key[1]][key[2]]
        struct.pack_into("<IIII", out, offset,
                         base_rva + payloads[key], len(blob), 1252, 0)
        out[payloads[key]:payloads[key] + len(blob)] = blob
    return bytes(out)


def vi_block(key: str, value: bytes = b"", value_type: int = 0,
             value_length: int | None = None, children: bytes = b"") -> bytes:
    """One VS_VERSIONINFO member, with the padding rules the format requires."""
    key_bytes = key.encode("utf-16-le") + b"\x00\x00"
    head = 6 + len(key_bytes)
    pad1 = (-head) % 4
    end_of_value = head + pad1 + len(value)
    pad2 = (-end_of_value) % 4
    if value_length is None:
        value_length = len(value) // 2 if value_type == 1 else len(value)
    length = end_of_value + ((pad2 + len(children)) if children else 0)
    out = struct.pack("<HHH", length, value_length, value_type)
    out += key_bytes + b"\x00" * pad1 + value
    if children:
        out += b"\x00" * pad2 + children
    return out


def vi_seq(blocks) -> bytes:
    out = b""
    for block in blocks:
        if out:
            out += b"\x00" * ((-len(out)) % 4)
        out += block
    return out


def vs_fixed_file_info(file_version=(5, 4, 4, 0), product_version=(5, 4, 4, 0),
                       file_flags=0) -> bytes:
    def pair(quad):
        return ((quad[0] << 16) | quad[1], (quad[2] << 16) | quad[3])
    file_ms, file_ls = pair(file_version)
    product_ms, product_ls = pair(product_version)
    return struct.pack("<13I", 0xFEEF04BD, 0x00010000, file_ms, file_ls,
                       product_ms, product_ls, 0x17, file_flags, 4, 1, 0, 0, 0)


def build_version_resource(strings, translations=(("0409", "04b0"),),
                           fixed: bytes | None = None) -> bytes:
    """A complete, well-formed VS_VERSIONINFO resource blob."""
    string_blocks = []
    for name in sorted(strings):
        text = strings[name]
        value = text.encode("utf-16-le") + b"\x00\x00"
        string_blocks.append(vi_block(name, value, value_type=1,
                                      value_length=len(value) // 2))
    table = vi_block("040904b0", children=vi_seq(string_blocks)) if string_blocks else b""
    children = []
    if table:
        children.append(vi_block("StringFileInfo", children=table))
    if translations:
        payload = b"".join(struct.pack("<HH", int(language, 16), int(codepage, 16))
                           for language, codepage in translations)
        children.append(vi_block(
            "VarFileInfo",
            children=vi_block("Translation", payload, value_type=0,
                              value_length=len(payload))))
    return vi_block("VS_VERSION_INFO",
                    value=fixed if fixed is not None else vs_fixed_file_info(),
                    value_type=0,
                    children=vi_seq(children) if children else b"")


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #

def minimal_pe(**kwargs) -> PEBuilder:
    builder = PEBuilder(**kwargs)
    builder.add_section(".text", 0x1000, b"\xcc" * 0x200,
                        characteristics=0x60000020)
    return builder


@pytest.fixture()
def minimal_path(tmp_path):
    return write_image(tmp_path, "minimal.exe",
                       minimal_pe().build(fix_checksum=True))


# --------------------------------------------------------------------------- #
# 1. minimal valid PE64
# --------------------------------------------------------------------------- #

def test_minimal_pe64_headers(minimal_path):
    document = pe_info.analyze(minimal_path)
    pe = document["pe"]
    assert pe["pe_format"] == "PE32+"
    assert pe["machine"] == 0x8664
    assert pe["machine_name"] == "IMAGE_FILE_MACHINE_AMD64"
    assert pe["number_of_sections"] == 1
    assert pe["image_base"] == IMAGE_BASE
    assert pe["entry_point"] == 0x1000
    assert pe["subsystem"] == 2
    assert pe["subsystem_name"] == "IMAGE_SUBSYSTEM_WINDOWS_GUI"
    assert pe["characteristics"] == "0x0022"
    assert "IMAGE_FILE_EXECUTABLE_IMAGE" in pe["characteristics_flags"]
    assert "IMAGE_FILE_LARGE_ADDRESS_AWARE" in pe["characteristics_flags"]
    assert pe["timestamp"] == 0x5F000000
    assert document["pe_extended"]["section_alignment"] == SECTION_ALIGNMENT
    assert document["pe_extended"]["size_of_headers"] == 0x200


def test_minimal_pe64_section_row(minimal_path):
    section = pe_info.analyze(minimal_path)["pe"]["sections"][0]
    assert section["name"] == ".text"
    assert section["rva"] == 0x1000
    assert section["rsize"] == 0x200
    assert section["vsize"] == 0x200
    assert section["raw_pointer"] == 0x200
    assert section["characteristics"] == "0x60000020"
    assert "IMAGE_SCN_MEM_EXECUTE" in section["characteristics_flags"]
    assert section["sha256"] == hashlib.sha256(b"\xcc" * 0x200).hexdigest()
    # 0x200 identical bytes carry no information.
    assert section["entropy"] == 0.0


def test_checksum_round_trip(tmp_path):
    good = write_image(tmp_path, "good.exe", minimal_pe().build(fix_checksum=True))
    assert pe_info.analyze(good)["pe"]["checksum_valid"] is True

    builder = minimal_pe()
    builder.checksum = 0xDEADBEEF
    bad = write_image(tmp_path, "bad.exe", builder.build())
    document = pe_info.analyze(bad)
    assert document["pe"]["checksum"] == 0xDEADBEEF
    assert document["pe"]["checksum_valid"] is False
    assert document["pe_extended"]["checksum_computed"] != 0xDEADBEEF


def test_overlay_is_reported(tmp_path):
    blob = minimal_pe().build() + b"OVERLAY!" * 16
    path = write_image(tmp_path, "overlay.exe", blob)
    document = pe_info.analyze(path)
    assert document["pe"]["overlay_size"] == 128
    assert document["pe_extended"]["overlay"]["overlay_offset"] == len(blob) - 128


def test_all_sixteen_data_directories_are_reported(minimal_path):
    directories = pe_info.analyze(minimal_path)["pe_extended"]["data_directories"]
    assert len(directories) == 16
    assert [entry["name"] for entry in directories] == list(
        pe_info.DATA_DIRECTORY_NAMES)
    for entry in directories:
        assert entry["present"] is False
        assert entry["note"] == "absent: RVA and size are both 0"


def test_truncated_data_directory_array_is_reported(tmp_path):
    builder = minimal_pe()
    builder.number_of_rva_and_sizes = 4
    path = write_image(tmp_path, "fewdirs.exe", builder.build())
    document = pe_info.analyze(path)
    directories = document["pe_extended"]["data_directories"]
    assert len(directories) == 16
    assert directories[3]["present"] is False and directories[3]["rva"] == 0
    assert directories[4]["rva"] is None
    assert "NumberOfRvaAndSizes is 4" in directories[4]["note"]


# --------------------------------------------------------------------------- #
# 2. truncated headers
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("keep, fragment", [
    (0, "too small to hold a DOS header"),
    (32, "too small to hold a DOS header"),
    (0x40, "the PE header is truncated"),
    (0x82, "PE header is truncated"),
])
def test_truncated_file_fails_cleanly(tmp_path, keep, fragment):
    blob = minimal_pe().build()[:keep]
    path = write_image(tmp_path, "truncated_%d.exe" % keep, blob)
    with pytest.raises(pe_info.PEFormatError) as error:
        pe_info.analyze(path)
    assert fragment in str(error.value)


def test_truncated_optional_header_fails_cleanly(tmp_path):
    # Enough for the COFF header to parse, not enough for the optional header.
    blob = minimal_pe().build()[:0x80 + 24 + 40]
    path = write_image(tmp_path, "trunc_opt.exe", blob)
    with pytest.raises(pe_info.PEFormatError) as error:
        pe_info.analyze(path)
    assert "outside the file" in str(error.value) or "truncated" in str(error.value)


def test_not_a_pe_at_all(tmp_path):
    path = write_image(tmp_path, "text.exe", b"this is not a PE image" * 100)
    with pytest.raises(pe_info.PEFormatError) as error:
        pe_info.analyze(path)
    assert "expected 'MZ'" in str(error.value)


def test_mz_without_pe_signature(tmp_path):
    blob = bytearray(minimal_pe().build())
    blob[0x80:0x84] = b"NE\x00\x00"
    path = write_image(tmp_path, "nope.exe", bytes(blob))
    with pytest.raises(pe_info.PEFormatError) as error:
        pe_info.analyze(path)
    assert "no PE signature" in str(error.value)


@pytest.mark.parametrize("value", [0, 0x20, 0xFFFFFFFF, 0x7FFFFFFF])
def test_absurd_e_lfanew_is_refused(tmp_path, value):
    blob = bytearray(minimal_pe().build())
    struct.pack_into("<I", blob, 0x3C, value)
    path = write_image(tmp_path, "elfanew_%08x.exe" % value, bytes(blob))
    with pytest.raises(pe_info.PEFormatError) as error:
        pe_info.analyze(path)
    message = str(error.value)
    assert "e_lfanew" in message


def test_bad_optional_header_magic(tmp_path):
    blob = bytearray(minimal_pe().build())
    struct.pack_into("<H", blob, 0x80 + 24, 0x1234)
    path = write_image(tmp_path, "badmagic.exe", bytes(blob))
    with pytest.raises(pe_info.PEFormatError) as error:
        pe_info.analyze(path)
    assert "Magic" in str(error.value)


# --------------------------------------------------------------------------- #
# 3. bogus section count
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("count", [0xFFFF, 5000, 200])
def test_bogus_section_count_is_refused(tmp_path, count):
    builder = minimal_pe()
    builder.number_of_sections_override = count
    path = write_image(tmp_path, "sections_%d.exe" % count, builder.build())
    with pytest.raises(pe_info.PEFormatError) as error:
        pe_info.analyze(path)
    message = str(error.value)
    assert "NumberOfSections" in message or "section table" in message


def test_bogus_section_count_does_not_allocate(tmp_path):
    """The failure must come from a bounds check, not from a huge read."""
    builder = minimal_pe()
    builder.number_of_sections_override = 0xFFFF
    path = write_image(tmp_path, "sections_max.exe", builder.build())
    image = pe_info.Image.open(path)
    try:
        # 0xFFFF sections is 2.6 MB of table in a ~1.5 KB file; the check must
        # fire on arithmetic, and read_at must independently refuse the range.
        with pytest.raises(pe_info.PEFormatError):
            pe_info.PEHeaders(image)
        with pytest.raises(pe_info.PEFormatError) as error:
            image.read_at(0, 64 << 20, "hostile length")
        assert "refusing a single read" in str(error.value)
    finally:
        image.close()


def test_section_with_raw_range_outside_the_file_warns(tmp_path):
    builder = minimal_pe()
    builder.sections[0]["raw_size_override"] = 0x10000000
    path = write_image(tmp_path, "bigsection.exe", builder.build())
    document = pe_info.analyze(path)
    warnings = document["pe_extended"]["parse_warnings"]
    assert any("leaves the file" in line for line in warnings)
    # The parse still completes and still reports the stored values verbatim.
    assert document["pe"]["sections"][0]["rsize"] == 0x10000000


# --------------------------------------------------------------------------- #
# 4. out-of-range data directory RVA
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("index, key", [
    (pe_info.DIR_IMPORT, "imports"),
    (pe_info.DIR_EXPORT, "exports"),
    (pe_info.DIR_DEBUG, "debug_directory"),
    (pe_info.DIR_DELAY_IMPORT, "delay_imports"),
])
def test_out_of_range_directory_rva_degrades_to_null(tmp_path, index, key):
    builder = minimal_pe()
    builder.set_directory(index, 0x7FFFF000, 0x10000)
    path = write_image(tmp_path, "baddir_%d.exe" % index, builder.build())
    document = pe_info.analyze(path)
    # The directory itself yields null plus a note; nothing else is lost.
    assert document["pe"][key] is None
    assert any("does not map" in note
               for note in document["pe_extended"]["parse_notes"])
    assert document["pe"]["machine"] == 0x8664
    entry = document["pe_extended"]["data_directories"][index]
    assert entry["note"] == "RVA does not map to on-disk data in any section"


def test_hostile_directory_size_is_clamped(tmp_path):
    """A four-gigabyte 'size' must be reduced to what the section really holds."""
    payload = build_import_blob(0x2000, [("A.dll", [("name", "f", 0)])])
    builder = minimal_pe()
    builder.add_section(".idata", 0x2000, payload)
    builder.set_directory(pe_info.DIR_IMPORT, 0x2000, 0xFFFFFFFF)
    path = write_image(tmp_path, "hugeimport.exe", builder.build())
    document = pe_info.analyze(path)
    assert [module["dll"] for module in document["pe"]["imports"]] == ["A.dll"]


def test_exception_directory_count_is_clamped(tmp_path):
    builder = minimal_pe()
    builder.add_section(".pdata", 0x2000, struct.pack("<III", 0x1000, 0x1010, 0x2000) * 4)
    builder.set_directory(pe_info.DIR_EXCEPTION, 0x2000, 0xFFFFFFF0)
    path = write_image(tmp_path, "hugepdata.exe", builder.build())
    exception_data = pe_info.analyze(path)["pe_extended"]["exception_data"]
    # 0x200 bytes of raw section data / 12 == 42, not 0xFFFFFFF0 / 12.
    assert exception_data["function_count"] == 0x200 // 12
    assert len(exception_data["sample"]) == pe_info.PDATA_SAMPLE
    assert exception_data["sample"][0]["begin_address"] == 0x1000


# --------------------------------------------------------------------------- #
# 5. TLS directory with two callbacks
# --------------------------------------------------------------------------- #

def test_tls_directory_with_two_callbacks(tmp_path):
    callbacks = [IMAGE_BASE + 0x1100, IMAGE_BASE + 0x1200]
    payload = build_tls_blob(0x2000, callbacks)
    builder = minimal_pe()
    builder.add_section(".tls", 0x2000, payload)
    builder.set_directory(pe_info.DIR_TLS, 0x2000, 40)
    path = write_image(tmp_path, "tls2.exe", builder.build())
    document = pe_info.analyze(path)

    tls = document["pe"]["tls"]
    assert tls["present"] is True
    assert tls["callback_count"] == 2
    assert tls["callbacks"] == callbacks
    assert tls["address_of_index"] == IMAGE_BASE + 0x3020

    detail = document["pe_extended"]["tls_detail"]
    assert detail["callback_rvas"] == [0x1100, 0x1200]
    assert detail["address_of_callbacks_va"] == IMAGE_BASE + 0x2000 + 40
    assert "VIRTUAL ADDRESSES" in detail["address_convention"]

    text = pe_info.format_summary(document)
    assert "callback count     : 2" in text


def test_tls_absent_reports_zero_not_null(minimal_path):
    tls = pe_info.analyze(minimal_path)["pe"]["tls"]
    assert tls["present"] is False
    assert tls["callback_count"] == 0
    assert tls["callbacks"] == []


def test_tls_callback_array_pointing_nowhere_does_not_hang(tmp_path):
    payload = bytearray(build_tls_blob(0x2000, []))
    struct.pack_into("<Q", payload, 24, IMAGE_BASE + 0x7F000000)  # AddressOfCallBacks
    builder = minimal_pe()
    builder.add_section(".tls", 0x2000, bytes(payload))
    builder.set_directory(pe_info.DIR_TLS, 0x2000, 40)
    path = write_image(tmp_path, "tlsbad.exe", builder.build())
    document = pe_info.analyze(path)
    assert document["pe"]["tls"]["present"] is True
    assert document["pe"]["tls"]["callback_count"] == 0
    assert any("callback array" in note
               for note in document["pe_extended"]["parse_notes"])


def test_unterminated_tls_callback_array_is_capped(tmp_path):
    """A callback array with no NULL terminator must stop at the cap."""
    body = struct.pack("<Q", IMAGE_BASE + 0x1000) * 20000
    payload = bytearray(40) + bytearray(body)
    struct.pack_into("<QQQQII", payload, 0, IMAGE_BASE + 0x3000,
                     IMAGE_BASE + 0x3010, IMAGE_BASE + 0x3020,
                     IMAGE_BASE + 0x2000 + 40, 0, 0)
    builder = minimal_pe()
    builder.add_section(".tls", 0x2000, bytes(payload))
    builder.set_directory(pe_info.DIR_TLS, 0x2000, 40)
    path = write_image(tmp_path, "tlsflood.exe", builder.build())
    document = pe_info.analyze(path)
    assert document["pe"]["tls"]["callback_count"] == pe_info.MAX_TLS_CALLBACKS
    assert any("cap" in note for note in document["pe_extended"]["parse_notes"])


# --------------------------------------------------------------------------- #
# 6. imports, including an ordinal-only entry
# --------------------------------------------------------------------------- #

def test_import_table_with_ordinal_only_entry(tmp_path):
    payload = build_import_blob(0x2000, [
        ("KERNEL32.dll", [("name", "CreateFileW", 7), ("ordinal", 0x1234)]),
        ("WS2_32.dll", [("ordinal", 115)]),
    ])
    builder = minimal_pe()
    builder.add_section(".idata", 0x2000, payload)
    builder.set_directory(pe_info.DIR_IMPORT, 0x2000, 20 * 3)
    path = write_image(tmp_path, "imports.exe", builder.build())
    document = pe_info.analyze(path)

    imports = {module["dll"]: module for module in document["pe"]["imports"]}
    assert set(imports) == {"KERNEL32.dll", "WS2_32.dll"}
    assert imports["KERNEL32.dll"]["function_count"] == 2

    by_name = {function["name"]: function
               for function in imports["KERNEL32.dll"]["functions"]}
    assert by_name["CreateFileW"]["ordinal"] is None
    assert by_name["CreateFileW"]["hint"] == 7
    assert by_name["CreateFileW"]["iat_rva"] is not None

    ordinal_only = [function for function in imports["KERNEL32.dll"]["functions"]
                    if function["name"] is None]
    assert len(ordinal_only) == 1
    assert ordinal_only[0]["ordinal"] == 0x1234

    ws2 = imports["WS2_32.dll"]["functions"]
    assert ws2 == [{"hint": None, "iat_rva": ws2[0]["iat_rva"],
                    "name": None, "ordinal": 115}]


def test_delay_import_table_is_reported_separately(tmp_path):
    normal = build_import_blob(0x2000, [("KERNEL32.dll", [("name", "Sleep", 0)])])
    delayed = build_delay_import_blob(0x3000, [
        ("steam_api64.dll", [("name", "SteamAPI_Init", 0), ("ordinal", 9)]),
    ])
    builder = minimal_pe()
    builder.add_section(".idata", 0x2000, normal)
    builder.add_section(".didat", 0x3000, delayed)
    builder.set_directory(pe_info.DIR_IMPORT, 0x2000, 40)
    builder.set_directory(pe_info.DIR_DELAY_IMPORT, 0x3000, 64)
    path = write_image(tmp_path, "delay.exe", builder.build())
    document = pe_info.analyze(path)

    assert [module["dll"] for module in document["pe"]["imports"]] == ["KERNEL32.dll"]
    delay = document["pe"]["delay_imports"]
    assert [module["dll"] for module in delay] == ["steam_api64.dll"]
    assert delay[0]["function_count"] == 2
    names = sorted(function["name"] or "#%d" % function["ordinal"]
                   for function in delay[0]["functions"])
    assert names == ["#9", "SteamAPI_Init"]
    assert document["pe_extended"]["delay_import_detail"]["addresses_are_rva"] is True


def test_no_import_directory_yields_empty_list_not_null(minimal_path):
    document = pe_info.analyze(minimal_path)
    assert document["pe"]["imports"] == []
    assert document["pe"]["delay_imports"] == []


# --------------------------------------------------------------------------- #
# 7. resources, with and without VS_VERSIONINFO
# --------------------------------------------------------------------------- #

VERSION_STRINGS = {
    "CompanyName": "Epic Games, Inc.",
    "FileDescription": "SYNTHETIC",
    "FileVersion": "5.4.4.0",
    "OriginalFilename": "synthetic.exe",
    "ProductVersion": "++UE5+Release-5.4-CL-35576357",
}


def _pe_with_resources(tmp_path, name, tree):
    payload = build_resource_blob(0x2000, tree)
    builder = minimal_pe()
    builder.add_section(".rsrc", 0x2000, payload)
    builder.set_directory(pe_info.DIR_RESOURCE, 0x2000, len(payload))
    return write_image(tmp_path, name, builder.build())


def test_resource_tree_with_version_info(tmp_path):
    blob = build_version_resource(VERSION_STRINGS)
    path = _pe_with_resources(tmp_path, "withver.exe",
                              {16: {1: {1033: blob}}, 24: {1: {1033: b"<xml/>"}}})
    document = pe_info.analyze(path)

    survey = document["pe_extended"]["resources"]
    assert survey["diagnosis"] == "version-resource-populated"
    assert survey["rt_version_present"] is True
    assert {record["id"] for record in survey["types"]} == {16, 24}
    assert {record["type_name"] for record in survey["types"]} == {"RT_VERSION",
                                                                   "RT_MANIFEST"}

    version_info = document["pe"]["version_info"]
    assert version_info["fixed"]["file_version"] == "5.4.4.0"
    assert version_info["fixed"]["product_version"] == "5.4.4.0"
    assert version_info["fixed"]["file_flags"] == "0x00000000"
    assert version_info["strings"] == VERSION_STRINGS
    assert version_info["translations"] == ["040904b0"]


def test_resource_tree_without_version_info(tmp_path):
    path = _pe_with_resources(tmp_path, "nover.exe",
                              {3: {1: {1033: b"\x00" * 32}},
                               24: {1: {1033: b"<xml/>"}}})
    document = pe_info.analyze(path)
    survey = document["pe_extended"]["resources"]
    assert survey["diagnosis"] == "no-version-resource"
    assert survey["rt_version_present"] is False
    assert survey["data_entry_count"] == 2
    assert document["pe"]["version_info"] is None


def test_no_resource_directory_at_all(minimal_path):
    document = pe_info.analyze(minimal_path)
    assert document["pe_extended"]["resources"]["diagnosis"] == "absent"
    assert document["pe"]["version_info"] is None


def test_version_resource_present_but_empty(tmp_path):
    """RT_VERSION exists and holds a VS_VERSIONINFO with nothing in it.

    This is the state question A-03 hypothesises for the MISERY executables, so
    it has to be distinguishable from both 'absent' and 'populated' rather than
    collapsing into either.
    """
    empty = vi_block("VS_VERSION_INFO")
    path = _pe_with_resources(tmp_path, "emptyver.exe", {16: {1: {1033: empty}}})
    document = pe_info.analyze(path)
    survey = document["pe_extended"]["resources"]
    assert survey["rt_version_present"] is True
    assert survey["diagnosis"] == "version-resource-empty"
    version_info = document["pe"]["version_info"]
    assert version_info["fixed"] is None
    assert version_info["strings"] is None


def test_version_resource_with_zero_length_data_entry(tmp_path):
    path = _pe_with_resources(tmp_path, "zerover.exe", {16: {1: {1033: b""}}})
    document = pe_info.analyze(path)
    survey = document["pe_extended"]["resources"]
    assert survey["rt_version_present"] is True
    assert survey["diagnosis"] == "version-resource-empty"
    assert document["pe"]["version_info"] is None


def test_malformed_version_block_does_not_raise(tmp_path):
    """A wLength that points outside its own block must not escape as an error."""
    broken = bytearray(build_version_resource(VERSION_STRINGS))
    struct.pack_into("<H", broken, 0, 0xFFFF)   # root wLength far past the blob
    path = _pe_with_resources(tmp_path, "brokenver.exe",
                              {16: {1: {1033: bytes(broken)}}})
    document = pe_info.analyze(path)          # must not raise
    assert document["pe_extended"]["resources"]["rt_version_present"] is True


def test_resource_walk_survives_a_cyclic_subdirectory(tmp_path):
    """A directory entry pointing back at the root must terminate the walk."""
    payload = bytearray(build_resource_blob(0x2000, {16: {1: {1033: b"x" * 8}}}))
    # Turn the level-3 (language) entry into a subdirectory pointing at offset 0.
    struct.pack_into("<II", payload, 16, 3, 0x80000000 | 0)
    builder = minimal_pe()
    builder.add_section(".rsrc", 0x2000, bytes(payload))
    builder.set_directory(pe_info.DIR_RESOURCE, 0x2000, len(payload))
    path = write_image(tmp_path, "cyclic.exe", builder.build())
    document = pe_info.analyze(path)          # must terminate and not raise
    assert document["pe_extended"]["resources"]["directory_rva"] == 0x2000


# --------------------------------------------------------------------------- #
# exports, debug directory, load config, Rich header
# --------------------------------------------------------------------------- #

def test_export_directory(tmp_path):
    payload = build_export_blob(0x2000, "synthetic.exe", ["Alpha", "Beta"])
    builder = minimal_pe()
    builder.add_section(".edata", 0x2000, payload)
    builder.set_directory(pe_info.DIR_EXPORT, 0x2000, len(payload))
    path = write_image(tmp_path, "exports.exe", builder.build())
    document = pe_info.analyze(path)

    exports = document["pe"]["exports"]
    assert [entry["name"] for entry in exports] == ["Alpha", "Beta"]
    assert [entry["ordinal"] for entry in exports] == [1, 2]
    assert exports[0]["address"] == 0x1000
    assert exports[0]["forwarder"] is None
    summary = document["pe_extended"]["export_directory"]
    assert summary["present"] is True
    assert summary["dll_name"] == "synthetic.exe"
    assert summary["ordinal_base"] == 1


def test_export_forwarder_is_recognised(tmp_path):
    """An export address inside the export directory is a forwarder string."""
    payload = bytearray(build_export_blob(0x2000, "synthetic.exe", ["Forwarded"]))
    forwarder_offset = len(payload)
    payload.extend(b"OtherDll.OtherSymbol\x00")
    # Point the single export address at the string we just appended.
    functions_rva = struct.unpack_from("<I", payload, 28)[0]
    struct.pack_into("<I", payload, functions_rva - 0x2000, 0x2000 + forwarder_offset)
    builder = minimal_pe()
    builder.add_section(".edata", 0x2000, bytes(payload))
    builder.set_directory(pe_info.DIR_EXPORT, 0x2000, len(payload))
    path = write_image(tmp_path, "forward.exe", builder.build())
    exports = pe_info.analyze(path)["pe"]["exports"]
    assert len(exports) == 1
    assert exports[0]["name"] == "Forwarded"
    assert exports[0]["forwarder"] == "OtherDll.OtherSymbol"


def test_codeview_debug_entry_pdb_path_and_guid(tmp_path):
    guid = bytes(range(16))
    payload = build_debug_blob(0x2000, r"D:\build\++UE5\Sync\MISERY.pdb", guid, 3)
    builder = minimal_pe()
    builder.add_section(".rdata", 0x2000, payload)
    builder.set_directory(pe_info.DIR_DEBUG, 0x2000, 28)
    path = write_image(tmp_path, "debug.exe", builder.build())
    document = pe_info.analyze(path)

    entries = document["pe"]["debug_directory"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["type"] == 2
    assert entry["type_name"] == "IMAGE_DEBUG_TYPE_CODEVIEW"
    assert entry["cv_signature"] == "RSDS"
    assert entry["pdb_age"] == 3
    # Mixed-endian: the first three fields are little-endian, the last eight
    # bytes are a byte string. This is the form symbol servers use.
    assert entry["pdb_guid"] == "03020100-0504-0706-0809-0A0B0C0D0E0F"
    # Reported verbatim: a build-machine path is evidence for plan.md section 4.
    assert entry["pdb_path"] == r"D:\build\++UE5\Sync\MISERY.pdb"
    assert document["pe"]["pdb_path_if_any"] == entry["pdb_path"]


def test_load_config_and_guard_flags(tmp_path):
    payload = bytearray(320)
    struct.pack_into("<I", payload, 0, 320)                    # Size
    struct.pack_into("<Q", payload, 88, IMAGE_BASE + 0x4000)   # SecurityCookie
    struct.pack_into("<Q", payload, 96, IMAGE_BASE + 0x5000)   # SEHandlerTable
    struct.pack_into("<Q", payload, 104, 7)                    # SEHandlerCount
    struct.pack_into("<Q", payload, 112, IMAGE_BASE + 0x6000)  # GuardCFCheckFn
    struct.pack_into("<Q", payload, 128, IMAGE_BASE + 0x7000)  # GuardCFFunctionTable
    struct.pack_into("<Q", payload, 136, 4242)                 # GuardCFFunctionCount
    struct.pack_into("<I", payload, 144, 0x00000100 | 0x00000400)
    builder = minimal_pe()
    builder.add_section(".rdata", 0x2000, bytes(payload))
    builder.set_directory(pe_info.DIR_LOAD_CONFIG, 0x2000, 320)
    builder.dll_characteristics = 0x8160 | 0x4000
    path = write_image(tmp_path, "loadcfg.exe", builder.build())
    load = pe_info.analyze(path)["pe_extended"]["load_config"]

    assert load["declared_size"] == 320
    assert load["security_cookie"] == IMAGE_BASE + 0x4000
    assert load["security_cookie_present"] is True
    assert load["se_handler_count"] == 7
    assert load["safe_seh"] is True
    assert load["guard_flags"] == "0x00000500"
    assert load["guard_flags_decoded"] == ["IMAGE_GUARD_CF_INSTRUMENTED",
                                           "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT"]
    assert load["cfg_instrumented"] is True
    assert load["cfg_function_table_present"] is True
    assert load["guard_cf_function_count"] == 4242
    assert load["cfg_marked_in_dll_characteristics"] is True


def test_short_load_config_yields_nulls_not_garbage(tmp_path):
    payload = bytearray(64)
    struct.pack_into("<I", payload, 0, 64)
    builder = minimal_pe()
    builder.add_section(".rdata", 0x2000, bytes(payload) + b"\xaa" * 512)
    builder.set_directory(pe_info.DIR_LOAD_CONFIG, 0x2000, 64)
    path = write_image(tmp_path, "shortcfg.exe", builder.build())
    load = pe_info.analyze(path)["pe_extended"]["load_config"]
    assert load["declared_size"] == 64
    assert load["security_cookie"] is None       # lives at offset 88, past the end
    assert load["guard_flags"] is None
    assert load["cfg_instrumented"] is None


def _rich_stub(entries, key: int) -> bytes:
    """A DOS stub carrying a Rich header with a correct checksum."""
    # Body: 'DanS' + three padding DWORDs + (comp.id, count) pairs, all XOR key.
    words = [0x536E6144, 0, 0, 0]
    for product_id, build_number, count in entries:
        words.append(((product_id & 0xFFFF) << 16) | (build_number & 0xFFFF))
        words.append(count)
    body = b"".join(struct.pack("<I", word ^ key) for word in words)
    return body + b"Rich" + struct.pack("<I", key)


def test_rich_header_is_decoded(tmp_path):
    entries = [(0x0105, 33130, 12), (0x0102, 31948, 1)]
    # The stub starts at 0x40, so 'DanS' lands at 0x40 and e_lfanew must clear it.
    stub = _rich_stub(entries, 0xDEADBEEF)
    builder = minimal_pe(e_lfanew=0x40 + len(stub) + 8)
    builder.dos_stub = stub
    path = write_image(tmp_path, "rich.exe", builder.build())
    rich = pe_info.analyze(path)["pe"]["rich_header"]

    assert rich["present"] is True
    assert rich["xor_key"] == "0xdeadbeef"
    assert rich["raw_sha256"] is not None
    decoded = {(entry["product_id"], entry["build_number"]): entry["count"]
               for entry in rich["entries"]}
    assert decoded == {(0x0105, 33130): 12, (0x0102, 31948): 1}
    assert {entry["product_name"] for entry in rich["entries"]} == {
        "Utc1900_POGO_I_CPP", "Utc1900_LTCG_C"}
    # The key we chose is not the real checksum of this synthetic stub, so the
    # verification must say so rather than assume the header is authentic.
    assert rich["checksum_valid"] is False


def test_rich_header_absent(minimal_path):
    rich = pe_info.analyze(minimal_path)["pe"]["rich_header"]
    assert rich["present"] is False
    assert rich["entries"] is None
    assert rich["xor_key"] is None


# --------------------------------------------------------------------------- #
# section anomaly flags
# --------------------------------------------------------------------------- #

def test_section_anomalies_are_flagged(tmp_path):
    builder = PEBuilder()
    builder.add_section(".text", 0x1000, b"\xcc" * 0x200, characteristics=0x60000020)
    # W+X, and a name no standard link emits.
    builder.add_section(".weird", 0x2000, b"\x00" * 0x200, characteristics=0xE0000020)
    # Raw size 0: nothing on disk, the loader zero-fills the virtual span.
    builder.add_section(".bss", 0x3000, b"", characteristics=0xC0000080, vsize=0x4000)
    path = write_image(tmp_path, "anomalies.exe", builder.build())
    document = pe_info.analyze(path)

    flags = {anomaly["name"]: anomaly["reasons"]
             for anomaly in document["pe_extended"]["section_anomalies"]}
    assert ".text" not in flags
    assert any("W+X" in reason for reason in flags[".weird"])
    assert any("not one a standard" in reason for reason in flags[".weird"])
    assert any("raw size is 0" in reason for reason in flags[".bss"])
    # A zero-raw section still appears in the section table with its real values.
    bss = [row for row in document["pe"]["sections"] if row["name"] == ".bss"][0]
    assert bss["rsize"] == 0 and bss["vsize"] == 0x4000
    assert bss["sha256"] is None


# --------------------------------------------------------------------------- #
# CLI, pathguard and determinism
# --------------------------------------------------------------------------- #

def run_cli(*args):
    return subprocess.run(
        [sys.executable, PE_INFO_PATH, *args],
        capture_output=True, text=True, cwd=REPO_ROOT)


def test_cli_human_summary(minimal_path):
    result = run_cli(minimal_path)
    assert result.returncode == 0, result.stderr
    assert "COFF header" in result.stdout
    assert "IMAGE_FILE_MACHINE_AMD64" in result.stdout
    assert "Data directories" in result.stdout
    assert "TLS directory" in result.stdout
    assert "Rich header" in result.stdout


def test_cli_json_is_deterministic(minimal_path):
    first = run_cli(minimal_path, "--json")
    second = run_cli(minimal_path, "--json")
    assert first.returncode == second.returncode == 0
    left = json.loads(first.stdout)
    right = json.loads(second.stdout)
    left.pop("generated_at")
    right.pop("generated_at")
    assert left == right
    # Sorted keys, indent 2, LF, trailing newline.
    assert first.stdout.endswith("}\n")
    assert "\r\n" not in first.stdout
    assert json.dumps(left, indent=2, sort_keys=True, ensure_ascii=False) in \
        first.stdout.replace('"generated_at": "%s",\n  ' % json.loads(
            first.stdout)["generated_at"], "")


def test_cli_out_writes_the_same_document(tmp_path, minimal_path):
    out = os.path.join(str(tmp_path), "out.json")
    result = run_cli(minimal_path, "--out", out)
    assert result.returncode == 0, result.stderr
    with open(out, encoding="utf-8") as handle:
        document = json.load(handle)
    assert document["pe"]["machine"] == 0x8664
    with open(out, "rb") as handle:
        raw = handle.read()
    assert b"\r\n" not in raw
    assert not raw.startswith(b"\xef\xbb\xbf")     # no BOM


def test_cli_refuses_output_inside_an_installation(tmp_path, minimal_path):
    """--out inside a directory that satisfies the installation predicate."""
    fake_install = os.path.join(str(tmp_path), "MISERYINSTALL")
    for marker in pathguard.INSTALL_MARKERS:
        target = os.path.join(fake_install, marker)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(b"marker")
    assert pathguard.looks_like_install_root(fake_install)

    out = os.path.join(fake_install, "pe.json")
    result = run_cli(minimal_path, "--out", out)
    assert result.returncode == 2
    assert "refusing to write inside the game installation" in result.stderr
    assert "D-01" in result.stderr
    assert not os.path.exists(out)


def test_write_json_guard_is_not_bypassable(tmp_path, minimal_path):
    """Calling write_json directly must be refused too, not only the CLI path."""
    fake_install = os.path.join(str(tmp_path), "INSTALL2")
    for marker in pathguard.INSTALL_MARKERS:
        target = os.path.join(fake_install, marker)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(b"marker")
    document = pe_info.analyze(minimal_path)
    out = os.path.join(fake_install, "deep", "pe.json")
    with pytest.raises(pathguard.OutputPathRefused):
        pe_info.write_json(document, out, fake_install)
    assert not os.path.exists(out)


def test_cli_reports_a_broken_file_without_a_traceback(tmp_path):
    path = write_image(tmp_path, "junk.bin", b"\x00" * 4096)
    result = run_cli(path)
    assert result.returncode == 2
    assert result.stderr.startswith("error: ")
    assert "Traceback" not in result.stderr


def test_cli_missing_file(tmp_path):
    result = run_cli(os.path.join(str(tmp_path), "nope.exe"))
    assert result.returncode == 2
    assert "not a file" in result.stderr


def test_analyze_never_reads_the_whole_file(tmp_path, monkeypatch):
    """No single read may exceed the bounded buffer, whatever the file claims."""
    builder = minimal_pe()
    builder.add_section(".big", 0x2000, b"\x5a" * (4 << 20))
    path = write_image(tmp_path, "big.exe", builder.build())

    original = pe_info.Image.read_at
    seen = []

    def spy(self, offset, length, what="read"):
        seen.append(length)
        return original(self, offset, length, what)

    monkeypatch.setattr(pe_info.Image, "read_at", spy)
    pe_info.analyze(path)
    assert max(seen) <= pe_info.MAX_SINGLE_READ
    # The 4 MiB section is hashed in bounded chunks, never in one read.
    assert max(seen) < (4 << 20)


def test_no_digests_flag_skips_hashing(minimal_path):
    document = pe_info.analyze(minimal_path, want_digests=False,
                               want_file_digest=False)
    assert document["file"]["sha256"] is None
    assert document["pe"]["sections"][0]["sha256"] is None
    assert document["pe"]["sections"][0]["entropy"] is None


# --------------------------------------------------------------------------- #
# robustness: nothing but PEFormatError may escape
# --------------------------------------------------------------------------- #

def _fully_furnished_pe() -> bytes:
    """One image carrying every optional directory this parser walks."""
    builder = minimal_pe()
    builder.add_section(".idata", 0x2000, build_import_blob(
        0x2000, [("KERNEL32.dll", [("name", "Sleep", 0), ("ordinal", 42)])]))
    builder.add_section(".tls", 0x3000, build_tls_blob(
        0x3000, [IMAGE_BASE + 0x1100, IMAGE_BASE + 0x1200]))
    builder.add_section(".rdata", 0x4000, build_debug_blob(
        0x4000, "synthetic.pdb", bytes(range(16)), 1))
    builder.add_section(".edata", 0x5000, build_export_blob(
        0x5000, "synthetic.exe", ["Alpha", "Beta"]))
    builder.add_section(".rsrc", 0x6000, build_resource_blob(
        0x6000, {16: {1: {1033: build_version_resource(VERSION_STRINGS)}}}))
    builder.add_section(".didat", 0x7000, build_delay_import_blob(
        0x7000, [("steam_api64.dll", [("name", "SteamAPI_Init", 0)])]))
    builder.set_directory(pe_info.DIR_IMPORT, 0x2000, 40)
    builder.set_directory(pe_info.DIR_TLS, 0x3000, 40)
    builder.set_directory(pe_info.DIR_DEBUG, 0x4000, 28)
    builder.set_directory(pe_info.DIR_EXPORT, 0x5000, 128)
    builder.set_directory(pe_info.DIR_RESOURCE, 0x6000, 512)
    builder.set_directory(pe_info.DIR_DELAY_IMPORT, 0x7000, 64)
    builder.set_directory(pe_info.DIR_EXCEPTION, 0x1000, 0x200)
    builder.set_directory(pe_info.DIR_LOAD_CONFIG, 0x4000, 320)
    return builder.build()


def test_random_corruption_never_raises_an_unexpected_exception(tmp_path):
    """Seeded corruption sweep over an image that exercises every walker.

    The contract this defends is narrow and load-bearing: a malformed field may
    make the parse fail, but it must fail as PEFormatError with a message, never
    as struct.error, IndexError, MemoryError, OverflowError or a hang. The seed
    is fixed so a failure is reproducible from the test name alone.
    """
    import random

    base = _fully_furnished_pe()
    rng = random.Random(20260823)
    path = os.path.join(str(tmp_path), "fuzz.exe")

    for iteration in range(300):
        data = bytearray(base)
        for _ in range(rng.randint(1, 12)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        with open(path, "wb") as handle:
            handle.write(bytes(data))
        try:
            document = pe_info.analyze(path, want_entropy=False)
        except pe_info.PEFormatError:
            continue          # the sanctioned failure mode
        except Exception as error:            # noqa: BLE001 - that is the point
            raise AssertionError(
                "iteration %d raised %s (%s), not PEFormatError"
                % (iteration, type(error).__name__, error)) from error
        # A parse that succeeds must still produce a serializable document.
        json.loads(pe_info.dump_json(document))


@pytest.mark.parametrize("poison", [0xFFFFFFFF, 0x80000000, 0x7FFFFFFF])
def test_every_header_dword_set_to_a_hostile_value(tmp_path, poison):
    """Systematic sweep: each aligned DWORD in the mapped structures, poisoned.

    Random corruption mostly lands in section payload; this walks the fields
    that are actually *counts and offsets* -- the headers and the first part of
    every directory-bearing section -- and sets each in turn to a value the
    parser must not believe. Cheaper and far more targeted than fuzzing, and it
    is where an unbounded loop or an allocation from a hostile length would live.
    """
    base = _fully_furnished_pe()
    path = os.path.join(str(tmp_path), "poison.exe")
    # Headers, plus the first 256 bytes of each section's raw data (where the
    # descriptors, directories and tables begin).
    regions = [range(0, 0x200, 4)]
    for start in range(0x200, min(len(base), 0x2000), 0x200):
        regions.append(range(start, min(start + 256, len(base) - 4), 4))

    for region in regions:
        for offset in region:
            data = bytearray(base)
            struct.pack_into("<I", data, offset, poison)
            with open(path, "wb") as handle:
                handle.write(bytes(data))
            try:
                pe_info.analyze(path, want_entropy=False, want_digests=False,
                                want_checksum=False, want_file_digest=False)
            except pe_info.PEFormatError:
                continue
            except Exception as error:        # noqa: BLE001
                raise AssertionError(
                    "poisoning offset %d with 0x%08x raised %s (%s)"
                    % (offset, poison, type(error).__name__, error)) from error


def test_truncation_sweep_never_raises_an_unexpected_exception(tmp_path):
    """Every prefix of a valid image must fail cleanly or parse cleanly."""
    base = _fully_furnished_pe()
    path = os.path.join(str(tmp_path), "cut.exe")
    for keep in range(0, len(base), 97):
        with open(path, "wb") as handle:
            handle.write(base[:keep])
        try:
            pe_info.analyze(path, want_entropy=False)
        except pe_info.PEFormatError:
            continue
        except Exception as error:            # noqa: BLE001
            raise AssertionError(
                "prefix of %d bytes raised %s (%s)"
                % (keep, type(error).__name__, error)) from error


# --------------------------------------------------------------------------- #
# schema conformance
# --------------------------------------------------------------------------- #

def _pe_schema_validator():
    jsonschema = pytest.importorskip("jsonschema")
    sys.path.insert(0, os.path.join(REPO_ROOT, "tools", "kb"))
    import validate as kb_validate  # noqa: WPS433

    import pathlib
    schema_dir = pathlib.Path(REPO_ROOT) / "research" / "schema"
    document = json.loads((schema_dir / "fingerprint.schema.json").read_text(
        encoding="utf-8"))
    registry = kb_validate._jsonschema_registry(schema_dir)
    schema = dict(document)
    for key in ("properties", "required", "additionalProperties", "type"):
        schema.pop(key, None)
    schema["$ref"] = "#/$defs/pe"
    return jsonschema.Draft202012Validator(schema, registry=registry)


def test_pe_block_validates_against_fingerprint_schema(tmp_path):
    """The 'pe' block must fit $defs/pe verbatim, so F-03 can splice it in.

    The schema closes that object with additionalProperties:false, which is why
    everything the schema has no field for lives under 'pe_extended' instead.
    """
    payload_imports = build_import_blob(0x2000, [
        ("KERNEL32.dll", [("name", "Sleep", 0), ("ordinal", 42)])])
    payload_tls = build_tls_blob(0x3000, [IMAGE_BASE + 0x1100, IMAGE_BASE + 0x1200])
    payload_debug = build_debug_blob(0x4000, "synthetic.pdb", bytes(range(16)), 1)
    payload_exports = build_export_blob(0x5000, "synthetic.exe", ["Alpha"])
    payload_resources = build_resource_blob(
        0x6000, {16: {1: {1033: build_version_resource(VERSION_STRINGS)}}})

    builder = minimal_pe()
    builder.add_section(".idata", 0x2000, payload_imports)
    builder.add_section(".tls", 0x3000, payload_tls)
    builder.add_section(".rdata", 0x4000, payload_debug)
    builder.add_section(".edata", 0x5000, payload_exports)
    builder.add_section(".rsrc", 0x6000, payload_resources)
    builder.set_directory(pe_info.DIR_IMPORT, 0x2000, 40)
    builder.set_directory(pe_info.DIR_TLS, 0x3000, 40)
    builder.set_directory(pe_info.DIR_DEBUG, 0x4000, 28)
    builder.set_directory(pe_info.DIR_EXPORT, 0x5000, len(payload_exports))
    builder.set_directory(pe_info.DIR_RESOURCE, 0x6000, len(payload_resources))
    path = write_image(tmp_path, "full.exe", builder.build(fix_checksum=True))

    document = pe_info.analyze(path)
    validator = _pe_schema_validator()
    errors = sorted(validator.iter_errors(document["pe"]),
                    key=lambda error: list(error.path))
    assert errors == [], "\n".join(
        "%s: %s" % (list(error.path), error.message) for error in errors)


def test_pe_block_has_every_required_schema_key(minimal_path):
    required = {
        "machine", "timestamp", "characteristics", "subsystem", "checksum",
        "image_base", "entry_point", "sections", "debug_directory",
        "pdb_path_if_any", "rich_header", "imports", "exports", "tls",
        "has_reloc", "version_info",
    }
    pe = pe_info.analyze(minimal_path)["pe"]
    assert required <= set(pe)
