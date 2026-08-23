#!/usr/bin/env python3
"""Read-only Portable Executable parser (plan.md task F-01).

What this tool is for
---------------------
plan.md 3.1 lists a ``pe.*`` field group for every executable of the build
fingerprint, and task F-01 requires our own parser: no ``pefile``, no
``dumpbin``, no third-party anything. This module is that parser. It is pure
standard library so it runs on a bare CPython on a fresh clone, before any
``pip install``.

Three separate M1 questions read this tool's output:

* **A-03** -- why no ``VS_VERSIONINFO`` field is readable through
  ``Get-Item().VersionInfo`` even though a ``.rsrc`` section exists. The
  resource walker below answers it by reading ``.rsrc`` directly and reporting
  which of three distinguishable states holds: the resource directory absent,
  present but carrying no ``RT_VERSION`` (or an empty one), or present and
  populated. It reports what it finds and nothing else.
* **section 4 (engine version), method V-03** -- the ``VS_VERSIONINFO`` fixed
  block and string table, when populated.
* **section 4, corroboration** -- the CodeView PDB path (a build-machine path
  leak) and the Rich header (which toolchain linked the image). Both are read
  verbatim.

The tool deliberately stops at observation. It reports imports, TLS callbacks,
debug entries and load-config flags; it does **not** conclude anything about
anti-debug or anti-cheat protection. "No import of ``IsDebuggerPresent`` was
found" is a statement this tool may make; "there is no anti-debug protection"
is not, and is a separate Tier A task in a later wave.

Safety properties (plan.md 1.5, decision D-01)
----------------------------------------------
* The input executable is only ever *read*: opened ``"rb"``, never written,
  never renamed, never moved. The installation is a read-only research target.
* The only path this tool writes to is ``--out``, and it is passed through
  ``tools/inventory/pathguard.check_output_path`` **before** anything is opened
  for writing -- imported, never reimplemented, because an inline copy built on
  ``abspath`` is how a junction bypass got in once. The installation root the
  guard is checked against is auto-detected from the input path (the nearest
  ancestor that satisfies the plan.md 2.1 step 6 predicate), falling back to the
  configured root; ``--install-dir`` overrides it.

Memory and robustness
---------------------
The two targets differ by three orders of magnitude -- a 422 KB shim and a
282 MB executable -- and the parser must be equally safe on a deliberately
malformed file.

* **Nothing is read whole.** Every access goes through :meth:`Image.read_at`,
  which bounds the requested offset and length against the real file size and
  against ``MAX_SINGLE_READ`` (8 MiB) before it seeks. Streaming passes (the
  checksum recomputation, per-section digests) reuse one 1 MiB buffer. Peak
  additional memory is a few MiB regardless of input size, far under the 64 MB
  budget of plan.md F-04.
* **No count from the file is trusted.** Section counts, import descriptor
  counts, TLS callback counts, resource entry counts, export counts and
  directory sizes are all clamped against explicit ``MAX_*`` limits *and*
  against what the file can actually contain, so a hostile 0xFFFFFFFF never
  becomes an allocation or an unbounded loop. Every walk is additionally
  depth- and iteration-bounded.
* **No unhandled exception escapes.** ``struct.error``, ``OSError``,
  ``UnicodeError`` and arithmetic on absurd values are converted to
  :class:`PEFormatError` with a message naming the structure and the offset. A
  failure inside one optional directory (say, resources) degrades that
  directory to ``null`` plus a warning instead of losing the whole parse; only
  a broken DOS/PE/COFF header is fatal.

Output shape
------------
``--json`` emits one document:

``file``
    Path, size and, when ``--digests`` is on (the default), the sha256 of the
    whole image.
``pe``
    Exactly the ``$defs/pe`` object of ``research/schema/fingerprint.schema.json``
    -- same keys, same types, nothing more. ``additionalProperties`` is false
    there, so this block can be spliced verbatim into ``fingerprint.json`` by
    task F-03 without reshaping.
``pe_extended``
    Everything F-01 is asked to report that the schema has no field for: the
    sixteen data directories, the load configuration and Control Flow Guard
    flags, the ``.pdata`` / RUNTIME_FUNCTION count and sample, the resource-tree
    survey behind the A-03 answer, the section anomaly flags, and the parse
    warnings. Kept out of ``pe`` on purpose: the schema closes that object, and
    silently widening a frozen M0 schema to fit a parser is the wrong direction
    of accommodation.

Determinism
-----------
JSON with sorted keys, indent 2, LF, UTF-8 without BOM. Two runs over the same
file differ only in ``generated_at``.

Exit codes: 0 success, 2 usage / I/O error / unparseable input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import struct
import sys
from array import array
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_INVENTORY = os.path.join(os.path.dirname(_HERE), "inventory")
if _INVENTORY not in sys.path:
    sys.path.insert(0, _INVENTORY)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never
# reimplemented: pathguard is the single place where "is this path inside the
# game installation" is decided.
import pathguard  # noqa: E402  (sys.path is prepared just above)

GENERATOR_NAME = "tools/fingerprint/pe_info.py"
GENERATOR_VERSION = "1.0.0"

# --------------------------------------------------------------------------- #
# hard limits -- every one of these exists because the corresponding count is
# read from the file being analysed and must never be believed.
# --------------------------------------------------------------------------- #

STREAM_BUFFER = 1 << 20          # bounded streaming buffer (1 MiB)
MAX_SINGLE_READ = 8 << 20        # largest single read_at() a caller may ask for
MAX_E_LFANEW = 1 << 24           # a PE header 16 MiB into the file is nonsense
MAX_SECTIONS = 4096              # PE spec caps the loader at 96; be generous
MAX_OPTIONAL_HEADER = 4096
MAX_DATA_DIRECTORIES = 16        # the format defines exactly sixteen
MAX_IMPORT_DESCRIPTORS = 8192
MAX_FUNCTIONS_PER_DLL = 65536
MAX_IMPORT_FUNCTIONS_TOTAL = 262144
MAX_EXPORTS = 262144
MAX_TLS_CALLBACKS = 4096
MAX_DEBUG_ENTRIES = 256
MAX_STRING_BYTES = 4096          # longest C string / PDB path we will follow
MAX_RESOURCE_DEPTH = 4
MAX_RESOURCE_ENTRIES = 8192      # total nodes visited in the whole .rsrc walk
MAX_VERSION_RESOURCE_BYTES = 1 << 20
MAX_VERSION_CHILDREN = 4096
MAX_RICH_SCAN = 1 << 16          # the Rich block lives in the DOS stub
MAX_RICH_ENTRIES = 1024
PDATA_SAMPLE = 8                 # RUNTIME_FUNCTION rows kept as a sample

# Names a linker normally emits. Anything else is flagged (reported, not judged).
STANDARD_SECTION_NAMES = frozenset({
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata", ".xdata",
    ".reloc", ".rsrc", ".tls", ".debug", ".didat", ".sdata", ".srdata",
    ".gfids", ".00cfg", ".CRT", ".voltbl", ".textbss", ".detourc", ".detourd",
})

# --------------------------------------------------------------------------- #
# name tables. These map raw numbers to public constant names, i.e. they lean on
# published PE layout documentation: any claim built on a *_name field carries
# the external-doc oracle in addition to binary-analysis (plan.md 10.5), while
# the raw number next to it is the literal read.
# --------------------------------------------------------------------------- #

MACHINE_NAMES = {
    0x0000: "IMAGE_FILE_MACHINE_UNKNOWN",
    0x014C: "IMAGE_FILE_MACHINE_I386",
    0x0162: "IMAGE_FILE_MACHINE_R3000",
    0x0166: "IMAGE_FILE_MACHINE_R4000",
    0x0169: "IMAGE_FILE_MACHINE_WCEMIPSV2",
    0x01A2: "IMAGE_FILE_MACHINE_SH3",
    0x01A6: "IMAGE_FILE_MACHINE_SH4",
    0x01C0: "IMAGE_FILE_MACHINE_ARM",
    0x01C2: "IMAGE_FILE_MACHINE_THUMB",
    0x01C4: "IMAGE_FILE_MACHINE_ARMNT",
    0x01F0: "IMAGE_FILE_MACHINE_POWERPC",
    0x0200: "IMAGE_FILE_MACHINE_IA64",
    0x0266: "IMAGE_FILE_MACHINE_MIPS16",
    0x0EBC: "IMAGE_FILE_MACHINE_EBC",
    0x5032: "IMAGE_FILE_MACHINE_RISCV32",
    0x5064: "IMAGE_FILE_MACHINE_RISCV64",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
    0xAA64: "IMAGE_FILE_MACHINE_ARM64",
}

CHARACTERISTICS_FLAGS = (
    (0x0001, "IMAGE_FILE_RELOCS_STRIPPED"),
    (0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE"),
    (0x0004, "IMAGE_FILE_LINE_NUMS_STRIPPED"),
    (0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"),
    (0x0010, "IMAGE_FILE_AGGRESSIVE_WS_TRIM"),
    (0x0020, "IMAGE_FILE_LARGE_ADDRESS_AWARE"),
    (0x0080, "IMAGE_FILE_BYTES_REVERSED_LO"),
    (0x0100, "IMAGE_FILE_32BIT_MACHINE"),
    (0x0200, "IMAGE_FILE_DEBUG_STRIPPED"),
    (0x0400, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "IMAGE_FILE_NET_RUN_FROM_SWAP"),
    (0x1000, "IMAGE_FILE_SYSTEM"),
    (0x2000, "IMAGE_FILE_DLL"),
    (0x4000, "IMAGE_FILE_UP_SYSTEM_ONLY"),
    (0x8000, "IMAGE_FILE_BYTES_REVERSED_HI"),
)

DLL_CHARACTERISTICS_FLAGS = (
    (0x0020, "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA"),
    (0x0040, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"),
    (0x0080, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"),
    (0x0100, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"),
    (0x0200, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"),
    (0x0400, "IMAGE_DLLCHARACTERISTICS_NO_SEH"),
    (0x0800, "IMAGE_DLLCHARACTERISTICS_NO_BIND"),
    (0x1000, "IMAGE_DLLCHARACTERISTICS_APPCONTAINER"),
    (0x2000, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER"),
    (0x4000, "IMAGE_DLLCHARACTERISTICS_GUARD_CF"),
    (0x8000, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"),
)

SECTION_FLAGS = (
    (0x00000008, "IMAGE_SCN_TYPE_NO_PAD"),
    (0x00000020, "IMAGE_SCN_CNT_CODE"),
    (0x00000040, "IMAGE_SCN_CNT_INITIALIZED_DATA"),
    (0x00000080, "IMAGE_SCN_CNT_UNINITIALIZED_DATA"),
    (0x00000200, "IMAGE_SCN_LNK_INFO"),
    (0x00000800, "IMAGE_SCN_LNK_REMOVE"),
    (0x00001000, "IMAGE_SCN_LNK_COMDAT"),
    (0x00008000, "IMAGE_SCN_GPREL"),
    (0x01000000, "IMAGE_SCN_LNK_NRELOC_OVFL"),
    (0x02000000, "IMAGE_SCN_MEM_DISCARDABLE"),
    (0x04000000, "IMAGE_SCN_MEM_NOT_CACHED"),
    (0x08000000, "IMAGE_SCN_MEM_NOT_PAGED"),
    (0x10000000, "IMAGE_SCN_MEM_SHARED"),
    (0x20000000, "IMAGE_SCN_MEM_EXECUTE"),
    (0x40000000, "IMAGE_SCN_MEM_READ"),
    (0x80000000, "IMAGE_SCN_MEM_WRITE"),
)

SUBSYSTEM_NAMES = {
    0: "IMAGE_SUBSYSTEM_UNKNOWN",
    1: "IMAGE_SUBSYSTEM_NATIVE",
    2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    3: "IMAGE_SUBSYSTEM_WINDOWS_CUI",
    5: "IMAGE_SUBSYSTEM_OS2_CUI",
    7: "IMAGE_SUBSYSTEM_POSIX_CUI",
    8: "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
    9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
    10: "IMAGE_SUBSYSTEM_EFI_APPLICATION",
    11: "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
    12: "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
    13: "IMAGE_SUBSYSTEM_EFI_ROM",
    14: "IMAGE_SUBSYSTEM_XBOX",
    16: "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
}

DATA_DIRECTORY_NAMES = (
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
    "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
    "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED",
)

DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION = 0, 1, 2, 3
DIR_SECURITY, DIR_BASERELOC, DIR_DEBUG = 4, 5, 6
DIR_TLS, DIR_LOAD_CONFIG, DIR_DELAY_IMPORT = 9, 10, 13

DEBUG_TYPE_NAMES = {
    0: "IMAGE_DEBUG_TYPE_UNKNOWN",
    1: "IMAGE_DEBUG_TYPE_COFF",
    2: "IMAGE_DEBUG_TYPE_CODEVIEW",
    3: "IMAGE_DEBUG_TYPE_FPO",
    4: "IMAGE_DEBUG_TYPE_MISC",
    5: "IMAGE_DEBUG_TYPE_EXCEPTION",
    6: "IMAGE_DEBUG_TYPE_FIXUP",
    7: "IMAGE_DEBUG_TYPE_OMAP_TO_SRC",
    8: "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC",
    9: "IMAGE_DEBUG_TYPE_BORLAND",
    10: "IMAGE_DEBUG_TYPE_RESERVED10",
    11: "IMAGE_DEBUG_TYPE_CLSID",
    12: "IMAGE_DEBUG_TYPE_VC_FEATURE",
    13: "IMAGE_DEBUG_TYPE_POGO",
    14: "IMAGE_DEBUG_TYPE_ILTCG",
    15: "IMAGE_DEBUG_TYPE_MPX",
    16: "IMAGE_DEBUG_TYPE_REPRO",
    17: "IMAGE_DEBUG_TYPE_SPGO",   # undocumented, seen in MSVC output
    20: "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS",
}

RESOURCE_TYPE_NAMES = {
    1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU", 5: "RT_DIALOG",
    6: "RT_STRING", 7: "RT_FONTDIR", 8: "RT_FONT", 9: "RT_ACCELERATOR",
    10: "RT_RCDATA", 11: "RT_MESSAGETABLE", 12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON", 16: "RT_VERSION", 17: "RT_DLGINCLUDE",
    19: "RT_PLUGPLAY", 20: "RT_VXD", 21: "RT_ANICURSOR", 22: "RT_ANIICON",
    23: "RT_HTML", 24: "RT_MANIFEST",
}
RT_VERSION = 16

GUARD_FLAGS = (
    (0x00000100, "IMAGE_GUARD_CF_INSTRUMENTED"),
    (0x00000200, "IMAGE_GUARD_CFW_INSTRUMENTED"),
    (0x00000400, "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT"),
    (0x00000800, "IMAGE_GUARD_SECURITY_COOKIE_UNUSED"),
    (0x00001000, "IMAGE_GUARD_PROTECT_DELAYLOAD_IAT"),
    (0x00002000, "IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION"),
    (0x00004000, "IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT"),
    (0x00008000, "IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION"),
    (0x00010000, "IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT"),
    (0x00020000, "IMAGE_GUARD_RF_INSTRUMENTED"),
    (0x00040000, "IMAGE_GUARD_RF_ENABLE"),
    (0x00080000, "IMAGE_GUARD_RF_STRICT"),
    (0x00100000, "IMAGE_GUARD_RETPOLINE_PRESENT"),
    (0x00400000, "IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT"),
    (0x00800000, "IMAGE_GUARD_XFG_ENABLED"),
    (0x01000000, "IMAGE_GUARD_CASTGUARD_PRESENT"),
    (0x02000000, "IMAGE_GUARD_MEMCPY_PRESENT"),
)

VS_FF_FLAGS = (
    (0x01, "VS_FF_DEBUG"),
    (0x02, "VS_FF_PRERELEASE"),
    (0x04, "VS_FF_PATCHED"),
    (0x08, "VS_FF_PRIVATEBUILD"),
    (0x10, "VS_FF_INFOINFERRED"),
    (0x20, "VS_FF_SPECIALBUILD"),
)

# Rich header @comp.id product ids. Public reverse-engineered table (oracle:
# external-doc). Deliberately partial: an unknown id yields product_name null
# rather than a guess, because a wrong toolchain name would corroborate the
# engine-version claim of plan.md section 4 with a fabrication.
RICH_PRODUCT_NAMES = {
    0x0000: "Unknown",
    0x0001: "Import0",
    0x0002: "Linker510",
    0x0003: "Cvtomf510",
    0x0004: "Linker600",
    0x0006: "Cvtres500",
    0x000A: "Cvtomf520",
    0x000F: "Masm613",
    0x0013: "Linker511",
    0x0015: "Utc12_C",
    0x0016: "Utc12_CPP",
    0x0019: "Implib700",
    0x001C: "Cvtres700",
    0x001F: "Utc13_Basic",
    0x0020: "Utc13_C",
    0x0021: "Utc13_CPP",
    0x003D: "Linker610",
    0x003F: "Cvtres710p",
    0x0040: "Linker710",
    0x005A: "Linker800",
    0x005B: "Cvtres800",
    0x005C: "Utc1400_C",
    0x005D: "Utc1400_CPP",
    0x0068: "Linker900",
    0x0069: "Export900",
    0x006A: "Implib900",
    0x006B: "Cvtres900",
    0x006D: "Utc1500_C",
    0x006E: "Utc1500_CPP",
    0x0078: "Linker1000",
    0x0079: "Export1000",
    0x007A: "Implib1000",
    0x007B: "Cvtres1000",
    0x007C: "Utc1600_C",
    0x007D: "Utc1600_CPP",
    0x0083: "Linker1010",
    0x0091: "Linker1100",
    0x0092: "Export1100",
    0x0093: "Implib1100",
    0x0094: "Cvtres1100",
    0x0095: "Utc1700_C",
    0x0096: "Utc1700_CPP",
    0x00AA: "Masm1200",
    0x00C9: "Utc1800_C",
    0x00CA: "Utc1800_CPP",
    0x00CE: "Linker1200",
    0x00CF: "Export1200",
    0x00D0: "Implib1200",
    0x00D1: "Cvtres1200",
    0x00DB: "Masm1400",
    0x00E0: "Utc1900_C",
    0x00E1: "Utc1900_CPP",
    0x00E2: "LTCG1900_C",
    0x00E3: "LTCG1900_CPP",
    0x00EB: "Linker1400",
    0x00EC: "Export1400",
    0x00ED: "Implib1400",
    0x00EE: "Cvtres1400",
    0x00FF: "AliasObj1400",
    0x0100: "Utc1900_CVTCIL_C",
    0x0101: "Utc1900_CVTCIL_CPP",
    0x0102: "Utc1900_LTCG_C",
    0x0103: "Utc1900_LTCG_CPP",
    0x0104: "Utc1900_POGO_I_C",
    0x0105: "Utc1900_POGO_I_CPP",
    0x0106: "Utc1900_POGO_O_C",
    0x0107: "Utc1900_POGO_O_CPP",
}


class PEFormatError(Exception):
    """The input is not a PE we can parse, or a structure is out of bounds.

    Raised instead of ``struct.error`` / ``IndexError`` / ``OverflowError`` so a
    caller sees one exception type with a message naming the structure and the
    offset that failed.
    """


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def epoch_to_iso(seconds: int | None) -> str | None:
    """Render a PE TimeDateStamp, or None when it is not a plausible date.

    A deterministic ("/Brepro") build writes a content hash into this field, and
    such a value renders as a date centuries away or fails outright. Returning
    None there keeps a hash from being displayed as a build date; the raw
    integer is always reported next to it, so nothing is lost.
    """
    if seconds is None:
        return None
    # 1980-01-01 .. 2100-01-01. Outside that a TimeDateStamp is not a time.
    if not (315532800 <= int(seconds) <= 4102444800):
        return None
    try:
        return datetime.fromtimestamp(int(seconds), timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def hexword(value: int | None, width: int = 8) -> str | None:
    """Format a bitfield as the schema's ``hex_word`` ('0x' + hex digits)."""
    if value is None:
        return None
    return "0x%0*x" % (width, int(value) & ((1 << (width * 4)) - 1))


def decode_flags(value: int | None, table) -> list[str] | None:
    """Decoded flag names, in table order so the output is deterministic."""
    if value is None:
        return None
    return [name for bit, name in table if value & bit]


def _u(fmt: str, blob: bytes, offset: int, what: str):
    """``struct.unpack_from`` that raises PEFormatError instead of struct.error."""
    try:
        return struct.unpack_from(fmt, blob, offset)
    except struct.error as error:
        raise PEFormatError(
            "%s: cannot read %s at buffer offset %d (%s)"
            % (what, fmt, offset, error)) from error


def _decode_ascii(raw: bytes) -> str:
    """Latin-1-ish decode that never raises and never loses a byte count.

    PE strings are nominally ASCII; a non-ASCII byte is reported as U+FFFD
    rather than aborting the parse, because the surrounding structure is still
    worth reporting.
    """
    return raw.decode("utf-8", errors="replace")


def _decode_utf16(raw: bytes) -> str:
    return raw.decode("utf-16-le", errors="replace")


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _rol32(value: int, count: int) -> int:
    count &= 31
    value &= 0xFFFFFFFF
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF if count else value


# --------------------------------------------------------------------------- #
# bounded image reader
# --------------------------------------------------------------------------- #

class Image:
    """A file handle plus every bounds check the PE format needs.

    Nothing in this module seeks or reads directly. Every access goes through
    :meth:`read_at`, so "the file said offset 0xFFFFFFF0, length 0xFFFFFFFF" can
    only ever produce a :class:`PEFormatError`, never a seek past the end, a
    hang, or a multi-gigabyte allocation.
    """

    def __init__(self, path: str, handle, size: int) -> None:
        self.path = path
        self._handle = handle
        self.size = size

    # -- construction ------------------------------------------------------- #

    @classmethod
    def open(cls, path: str) -> "Image":
        try:
            size = os.path.getsize(path)
            handle = open(path, "rb", buffering=0)
        except OSError as error:
            raise PEFormatError("cannot open %s: %s" % (path, error)) from error
        return cls(path, handle, size)

    def close(self) -> None:
        try:
            self._handle.close()
        except OSError:
            pass

    def __enter__(self) -> "Image":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # -- bounded access ----------------------------------------------------- #

    def read_at(self, offset: int, length: int, what: str = "read") -> bytes:
        """Exactly *length* bytes at *offset*, or PEFormatError.

        Both arguments are validated before the seek: negative, absurd, or
        past-the-end requests are refused by message rather than by exception
        from the OS.
        """
        if length == 0:
            return b""
        if not isinstance(offset, int) or not isinstance(length, int):
            raise PEFormatError("%s: non-integer offset/length" % what)
        if offset < 0 or length < 0:
            raise PEFormatError(
                "%s: negative offset %d or length %d" % (what, offset, length))
        if length > MAX_SINGLE_READ:
            raise PEFormatError(
                "%s: refusing a single read of %d bytes (limit %d) -- a length "
                "field in the file is implausible" % (what, length, MAX_SINGLE_READ))
        if offset > self.size or length > self.size - offset:
            raise PEFormatError(
                "%s: range [%d, %d) lies outside the file (size %d) -- truncated "
                "or hostile" % (what, offset, offset + length, self.size))
        try:
            self._handle.seek(offset)
            data = self._handle.read(length)
        except OSError as error:
            raise PEFormatError("%s: I/O error at offset %d: %s"
                                % (what, offset, error)) from error
        if len(data) != length:
            raise PEFormatError(
                "%s: short read at offset %d (%d of %d bytes)"
                % (what, offset, len(data), length))
        return data

    def read_clamped(self, offset: int, length: int) -> bytes:
        """Up to *length* bytes at *offset*; short or empty rather than raising.

        Used where a truncated tail is informative (string scanning, the Rich
        header scan) instead of fatal.
        """
        if offset < 0 or offset >= self.size or length <= 0:
            return b""
        length = min(length, MAX_SINGLE_READ, self.size - offset)
        try:
            self._handle.seek(offset)
            return self._handle.read(length)
        except OSError:
            return b""

    def cstring_at(self, offset: int, limit: int = MAX_STRING_BYTES) -> str | None:
        """NUL-terminated ASCII string at a file offset, bounded by *limit*."""
        raw = self.read_clamped(offset, limit)
        if not raw:
            return None
        end = raw.find(b"\x00")
        if end < 0:
            # No terminator inside the bound: report what we have and say so by
            # truncation rather than scanning to end of file.
            return _decode_ascii(raw)
        return _decode_ascii(raw[:end])

    # -- streaming passes --------------------------------------------------- #

    def iter_chunks(self, offset: int, length: int, buf_size: int = STREAM_BUFFER):
        """Yield (chunk_offset, memoryview) over [offset, offset+length).

        One buffer is allocated and reused, so peak memory is *buf_size*
        regardless of how big the range is. The range is clamped to the file.
        """
        if offset < 0 or length <= 0 or offset >= self.size:
            return
        length = min(length, self.size - offset)
        buffer = bytearray(min(buf_size, length))
        view = memoryview(buffer)
        remaining = length
        position = offset
        try:
            self._handle.seek(position)
        except OSError as error:
            raise PEFormatError("stream: cannot seek to %d: %s"
                                % (position, error)) from error
        while remaining > 0:
            want = min(len(buffer), remaining)
            try:
                got = self._handle.readinto(view[:want])
            except OSError as error:
                raise PEFormatError("stream: I/O error at %d: %s"
                                    % (position, error)) from error
            if not got:
                return
            yield position, view[:got]
            position += got
            remaining -= got


# --------------------------------------------------------------------------- #
# header parsing
# --------------------------------------------------------------------------- #

class PEHeaders:
    """The parsed, bounds-checked headers. Everything else builds on this."""

    def __init__(self, image: Image) -> None:
        self.image = image
        self.warnings: list[str] = []
        self._parse_dos()
        self._parse_coff()
        self._parse_optional()
        self._parse_sections()

    def warn(self, message: str) -> None:
        # Deduplicated so a repeating malformed structure cannot flood the
        # output (and cannot make two runs differ by warning multiplicity).
        if message not in self.warnings:
            self.warnings.append(message)

    # -- DOS ---------------------------------------------------------------- #

    def _parse_dos(self) -> None:
        image = self.image
        if image.size < 0x40:
            raise PEFormatError(
                "file is %d bytes, too small to hold a DOS header (need 64)"
                % image.size)
        dos = image.read_at(0, 0x40, "IMAGE_DOS_HEADER")
        if dos[:2] != b"MZ":
            raise PEFormatError(
                "not a PE image: bytes at offset 0 are %s, expected 'MZ' (4d5a)"
                % dos[:2].hex())
        self.e_lfanew = _u("<I", dos, 0x3C, "IMAGE_DOS_HEADER.e_lfanew")[0]
        if self.e_lfanew < 0x40 or self.e_lfanew > MAX_E_LFANEW:
            raise PEFormatError(
                "e_lfanew at offset 60 is %d (0x%x), outside the sane range "
                "[64, %d]" % (self.e_lfanew, self.e_lfanew, MAX_E_LFANEW))
        if self.e_lfanew + 24 > image.size:
            raise PEFormatError(
                "e_lfanew points to %d but the file is only %d bytes -- the PE "
                "header is truncated" % (self.e_lfanew, image.size))

    # -- COFF --------------------------------------------------------------- #

    def _parse_coff(self) -> None:
        image = self.image
        signature = image.read_at(self.e_lfanew, 4, "PE signature")
        if signature != b"PE\x00\x00":
            raise PEFormatError(
                "no PE signature at e_lfanew %d: found %s, expected 50450000"
                % (self.e_lfanew, signature.hex()))
        coff = image.read_at(self.e_lfanew + 4, 20, "IMAGE_FILE_HEADER")
        (self.machine, self.number_of_sections, self.timestamp,
         self.pointer_to_symbol_table, self.number_of_symbols,
         self.size_of_optional_header, self.characteristics) = _u(
            "<HHIIIHH", coff, 0, "IMAGE_FILE_HEADER")

        if self.number_of_sections > MAX_SECTIONS:
            raise PEFormatError(
                "NumberOfSections is %d (limit %d) -- refusing to walk a section "
                "table that cannot exist" % (self.number_of_sections, MAX_SECTIONS))
        if self.size_of_optional_header > MAX_OPTIONAL_HEADER:
            raise PEFormatError(
                "SizeOfOptionalHeader is %d (limit %d)"
                % (self.size_of_optional_header, MAX_OPTIONAL_HEADER))
        # A section table of N rows needs 40*N bytes after the optional header.
        table_offset = self.e_lfanew + 24 + self.size_of_optional_header
        need = table_offset + 40 * self.number_of_sections
        if need > image.size:
            raise PEFormatError(
                "section table of %d entries would end at %d but the file is %d "
                "bytes -- NumberOfSections is wrong or the file is truncated"
                % (self.number_of_sections, need, image.size))
        self.section_table_offset = table_offset

    # -- optional header ---------------------------------------------------- #

    def _parse_optional(self) -> None:
        image = self.image
        if self.size_of_optional_header < 2:
            raise PEFormatError(
                "SizeOfOptionalHeader is %d: there is no optional header to read"
                % self.size_of_optional_header)
        base = self.e_lfanew + 24
        blob = image.read_at(base, self.size_of_optional_header,
                             "IMAGE_OPTIONAL_HEADER")
        self.optional_header_offset = base
        self.optional_header_raw = blob
        self.magic = _u("<H", blob, 0, "OptionalHeader.Magic")[0]
        if self.magic == 0x20B:
            self.pe_format = "PE32+"
            self.pointer_size = 8
        elif self.magic == 0x10B:
            self.pe_format = "PE32"
            self.pointer_size = 4
        elif self.magic == 0x107:
            raise PEFormatError(
                "optional header Magic is 0x107 (ROM image); not supported")
        else:
            raise PEFormatError(
                "optional header Magic at offset %d is 0x%04x, expected 0x10b "
                "(PE32) or 0x20b (PE32+)" % (base, self.magic))

        minimum = 112 if self.magic == 0x20B else 96
        if self.size_of_optional_header < minimum:
            raise PEFormatError(
                "SizeOfOptionalHeader is %d but %s needs at least %d bytes"
                % (self.size_of_optional_header, self.pe_format, minimum))

        # Fields common to both forms, at their form-specific offsets.
        (self.major_linker_version, self.minor_linker_version, self.size_of_code,
         self.size_of_initialized_data, self.size_of_uninitialized_data,
         self.entry_point, self.base_of_code) = _u(
            "<BBIIIII", blob, 2, "OptionalHeader (common head)")

        if self.magic == 0x20B:
            self.base_of_data = None
            self.image_base = _u("<Q", blob, 24, "OptionalHeader.ImageBase")[0]
            tail = 32
        else:
            self.base_of_data = _u("<I", blob, 24, "OptionalHeader.BaseOfData")[0]
            self.image_base = _u("<I", blob, 28, "OptionalHeader.ImageBase")[0]
            tail = 32

        (self.section_alignment, self.file_alignment,
         self.major_os_version, self.minor_os_version,
         self.major_image_version, self.minor_image_version,
         self.major_subsystem_version, self.minor_subsystem_version,
         self.win32_version_value, self.size_of_image, self.size_of_headers,
         self.checksum, self.subsystem, self.dll_characteristics) = _u(
            "<IIHHHHHHIIIIHH", blob, tail, "OptionalHeader (windows-specific)")
        self.checksum_field_offset = base + tail + 32

        after = tail + 40
        if self.magic == 0x20B:
            (self.size_of_stack_reserve, self.size_of_stack_commit,
             self.size_of_heap_reserve, self.size_of_heap_commit) = _u(
                "<QQQQ", blob, after, "OptionalHeader (sizes, PE32+)")
            after += 32
        else:
            (self.size_of_stack_reserve, self.size_of_stack_commit,
             self.size_of_heap_reserve, self.size_of_heap_commit) = _u(
                "<IIII", blob, after, "OptionalHeader (sizes, PE32)")
            after += 16
        (self.loader_flags, self.number_of_rva_and_sizes) = _u(
            "<II", blob, after, "OptionalHeader.NumberOfRvaAndSizes")
        after += 8

        declared = self.number_of_rva_and_sizes
        available = max(0, (self.size_of_optional_header - after) // 8)
        count = min(declared, MAX_DATA_DIRECTORIES, available)
        if declared > MAX_DATA_DIRECTORIES:
            self.warn(
                "NumberOfRvaAndSizes is %d; the format defines %d, reading %d"
                % (declared, MAX_DATA_DIRECTORIES, count))
        elif declared > available:
            self.warn(
                "NumberOfRvaAndSizes is %d but only %d directory entries fit in "
                "the optional header; reading %d" % (declared, available, count))
        self.data_directories: list[tuple[int, int]] = []
        for index in range(count):
            rva, size = _u("<II", blob, after + index * 8,
                           "IMAGE_DATA_DIRECTORY[%d]" % index)
            self.data_directories.append((rva, size))

    # -- section table ------------------------------------------------------ #

    def _parse_sections(self) -> None:
        image = self.image
        self.sections: list[dict] = []
        blob = image.read_at(self.section_table_offset,
                             40 * self.number_of_sections, "section table")
        for index in range(self.number_of_sections):
            row = blob[index * 40:(index + 1) * 40]
            raw_name = row[:8]
            name = _decode_ascii(raw_name.rstrip(b"\x00"))
            (vsize, rva, rsize, raw_pointer, reloc_pointer, lineno_pointer,
             reloc_count, lineno_count, characteristics) = _u(
                "<IIIIIIHHI", row, 8, "IMAGE_SECTION_HEADER[%d]" % index)
            self.sections.append({
                "index": index,
                "name": name,
                "name_raw_hex": raw_name.hex(),
                "vsize": vsize,
                "rva": rva,
                "rsize": rsize,
                "raw_pointer": raw_pointer,
                "pointer_to_relocations": reloc_pointer,
                "pointer_to_linenumbers": lineno_pointer,
                "number_of_relocations": reloc_count,
                "number_of_linenumbers": lineno_count,
                "characteristics": characteristics,
            })
            # A raw range that leaves the file is reported, not trusted; the
            # per-section digest pass clamps against the real size.
            if rsize and (raw_pointer > image.size or rsize > image.size - raw_pointer):
                self.warn(
                    "section %d (%s) raw range [%d, %d) leaves the file (size %d)"
                    % (index, name or "<unnamed>", raw_pointer,
                       raw_pointer + rsize, image.size))

    # -- address translation ------------------------------------------------ #

    def directory(self, index: int) -> tuple[int, int]:
        """(rva, size) of data directory *index*, or (0, 0) when absent."""
        if 0 <= index < len(self.data_directories):
            return self.data_directories[index]
        return (0, 0)

    def rva_to_offset(self, rva: int) -> int | None:
        """File offset for *rva*, or None when it maps nowhere on disk.

        A section's on-disk data is ``rsize`` bytes even when ``vsize`` is
        larger (the tail is zero-filled by the loader), so an RVA inside the
        virtual tail has no file offset and must answer None rather than a
        plausible-looking wrong number.
        """
        if not isinstance(rva, int) or rva < 0:
            return None
        for section in self.sections:
            start = section["rva"]
            # The mapped span is aligned up to SectionAlignment; use the larger
            # of vsize and rsize so an RVA in either view is found.
            span = max(section["vsize"], section["rsize"])
            if span == 0:
                continue
            if start <= rva < start + span:
                delta = rva - start
                if delta >= section["rsize"]:
                    return None  # inside the zero-filled virtual tail
                offset = section["raw_pointer"] + delta
                if offset >= self.image.size:
                    return None
                return offset
        # RVAs below SizeOfHeaders are identity-mapped from the file start.
        if rva < min(self.size_of_headers, self.image.size):
            return rva
        return None

    def rva_available(self, rva: int) -> int:
        """How many bytes are readable on disk starting at *rva*.

        Bounds every walk that follows a directory RVA: a size field claiming
        four gigabytes is silently reduced to what the containing section
        actually holds.
        """
        offset = self.rva_to_offset(rva)
        if offset is None:
            return 0
        for section in self.sections:
            start = section["rva"]
            span = max(section["vsize"], section["rsize"])
            if span and start <= rva < start + span:
                on_disk = max(0, section["rsize"] - (rva - start))
                room = max(0, self.image.size - offset)
                return min(on_disk, room)
        return max(0, min(self.size_of_headers, self.image.size) - rva)

    def read_rva(self, rva: int, length: int, what: str) -> bytes:
        offset = self.rva_to_offset(rva)
        if offset is None:
            raise PEFormatError(
                "%s: RVA 0x%x does not map to any section's on-disk data" % (what, rva))
        available = self.rva_available(rva)
        if length > available:
            raise PEFormatError(
                "%s: wants %d bytes at RVA 0x%x but only %d are on disk"
                % (what, length, rva, available))
        return self.image.read_at(offset, length, what)

    def cstring_rva(self, rva: int, limit: int = MAX_STRING_BYTES) -> str | None:
        offset = self.rva_to_offset(rva)
        if offset is None:
            return None
        limit = min(limit, self.rva_available(rva))
        if limit <= 0:
            return None
        return self.image.cstring_at(offset, limit)


# --------------------------------------------------------------------------- #
# checksum
# --------------------------------------------------------------------------- #

def compute_checksum(headers: PEHeaders) -> int:
    """Recompute the PE image checksum, streaming, with the field zeroed.

    Reported next to the stored value so a mismatch is visible: a shipped image
    normally carries a correct checksum, and a mismatch means the file was
    modified after linking (or was never checksummed, which is also common for
    game executables).

    16-bit one's-complement addition is associative, so the words are summed
    into one Python integer and folded once at the end -- same result, one pass,
    no per-chunk state.
    """
    image = headers.image
    field = headers.checksum_field_offset
    total = 0
    little = sys.byteorder == "little"
    leftover = b""
    for position, chunk in image.iter_chunks(0, image.size):
        data = bytearray(leftover) + bytes(chunk)
        start = position - len(leftover)
        # Zero the four CheckSum bytes wherever they fall in this window.
        for byte_index in range(field, field + 4):
            local = byte_index - start
            if 0 <= local < len(data):
                data[local] = 0
        if len(data) & 1:
            leftover = bytes(data[-1:])
            data = data[:-1]
        else:
            leftover = b""
        if data:
            words = array("H")
            words.frombytes(bytes(data))
            if not little:
                words.byteswap()
            total += sum(words)
    if leftover:
        total += leftover[0]  # final odd byte, high half zero-padded
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (total + image.size) & 0xFFFFFFFF


# --------------------------------------------------------------------------- #
# sections
# --------------------------------------------------------------------------- #

def section_digest_and_entropy(image: Image, offset: int, length: int,
                               want_entropy: bool) -> tuple[str | None, float | None]:
    """sha256 and Shannon entropy of a raw section range, in one streaming pass.

    The histogram uses 256 ``bytes.count`` calls per chunk: each runs at memchr
    speed in C, which keeps a 100 MB section to a few seconds, whereas iterating
    the bytes in Python would not finish in a useful time. ``--no-entropy``
    turns it off when only the digest is wanted.
    """
    if length <= 0:
        return None, None
    if offset >= image.size:
        return None, None
    length = min(length, image.size - offset)
    digest = hashlib.sha256()
    histogram = [0] * 256 if want_entropy else None
    total = 0
    for _position, chunk in image.iter_chunks(offset, length):
        digest.update(chunk)
        total += len(chunk)
        if histogram is not None:
            raw = bytes(chunk)
            for value in range(256):
                count = raw.count(value)
                if count:
                    histogram[value] += count
    if total == 0:
        return None, None
    entropy = None
    if histogram is not None:
        entropy = 0.0
        for count in histogram:
            if count:
                probability = count / total
                entropy -= probability * math.log2(probability)
        entropy = round(entropy, 6)
    return digest.hexdigest(), entropy


def build_sections(headers: PEHeaders, want_digests: bool,
                   want_entropy: bool) -> tuple[list[dict], list[dict]]:
    """(schema-shaped section rows, anomaly rows).

    Anomalies are *flags*, not verdicts. A zero raw size, a writable+executable
    section and a non-standard name are each reported with the value that
    triggered them; what any of that means is not decided here.
    """
    rows: list[dict] = []
    anomalies: list[dict] = []
    image = headers.image
    for section in headers.sections:
        sha256 = entropy = None
        if want_digests and section["rsize"] > 0:
            try:
                sha256, entropy = section_digest_and_entropy(
                    image, section["raw_pointer"], section["rsize"], want_entropy)
            except PEFormatError as error:
                headers.warn("section %s: digest skipped: %s"
                             % (section["name"], error))
        rows.append({
            "characteristics": hexword(section["characteristics"]),
            "characteristics_flags": decode_flags(section["characteristics"],
                                                  SECTION_FLAGS),
            "entropy": entropy,
            "name": section["name"],
            "raw_pointer": section["raw_pointer"],
            "rsize": section["rsize"],
            "rva": section["rva"],
            "sha256": sha256,
            "vsize": section["vsize"],
        })

        flags = section["characteristics"]
        reasons = []
        if section["rsize"] == 0:
            reasons.append("raw size is 0 (no bytes on disk; loader zero-fills "
                           "%d virtual bytes)" % section["vsize"])
        if (flags & 0x80000000) and (flags & 0x20000000):
            reasons.append("MEM_WRITE and MEM_EXECUTE are both set (W+X)")
        if section["name"] not in STANDARD_SECTION_NAMES:
            reasons.append("name %r is not one a standard MSVC/clang link emits"
                           % section["name"])
        if section["name"].startswith("/"):
            reasons.append("name is a string-table reference ('/<offset>'), "
                           "an object-file form not normally seen in an image")
        if (flags & 0x20000000) and not (flags & 0x00000020):
            reasons.append("MEM_EXECUTE set without CNT_CODE")
        if section["rsize"] and section["vsize"] and section["rsize"] > section["vsize"] * 2 \
                and section["vsize"] > 0:
            reasons.append("raw size %d is more than twice virtual size %d"
                           % (section["rsize"], section["vsize"]))
        if reasons:
            anomalies.append({
                "characteristics": hexword(flags),
                "index": section["index"],
                "name": section["name"],
                "raw_pointer": section["raw_pointer"],
                "reasons": reasons,
                "rsize": section["rsize"],
                "rva": section["rva"],
                "vsize": section["vsize"],
            })
    return rows, anomalies


def compute_overlay(headers: PEHeaders) -> dict:
    """Bytes after the last section's raw data -- appended, unmapped content."""
    end = min(headers.size_of_headers, headers.image.size)
    for section in headers.sections:
        if section["rsize"] <= 0:
            continue
        candidate = section["raw_pointer"] + section["rsize"]
        if candidate <= headers.image.size:
            end = max(end, candidate)
    overlay = max(0, headers.image.size - end)
    return {"end_of_image_data": end, "overlay_offset": end,
            "overlay_size": overlay}


# --------------------------------------------------------------------------- #
# data directories
# --------------------------------------------------------------------------- #

def build_data_directories(headers: PEHeaders) -> list[dict]:
    """All sixteen, with a note when an entry is absent or unmapped."""
    entries = []
    for index in range(MAX_DATA_DIRECTORIES):
        name = DATA_DIRECTORY_NAMES[index]
        if index >= len(headers.data_directories):
            entries.append({
                "index": index, "name": name, "rva": None, "size": None,
                "present": False,
                "note": "not present: NumberOfRvaAndSizes is %d"
                        % headers.number_of_rva_and_sizes,
                "file_offset": None,
            })
            continue
        rva, size = headers.data_directories[index]
        present = bool(rva or size)
        note = None
        offset = None
        if not present:
            note = "absent: RVA and size are both 0"
        elif index == DIR_SECURITY:
            # The Security directory is the one whose "RVA" is really a file
            # offset -- it points into the overlay, outside any section.
            offset = rva
            note = ("the SECURITY entry stores a FILE OFFSET, not an RVA "
                    "(Authenticode certificate table)")
            if rva + size > headers.image.size:
                note += "; range leaves the file"
            else:
                # A literal 8-byte read of the WIN_CERTIFICATE header it points
                # at. No signature is validated and none is claimed valid; this
                # only says whether the bytes there can be a certificate at all,
                # because a stale directory left behind by a post-link resource
                # rewrite points at ordinary section data and would otherwise be
                # reported as "signature present" with nothing to back it.
                head = headers.image.read_clamped(rva, 8)
                if len(head) == 8:
                    length, revision, cert_type = _u(
                        "<IHH", head, 0, "WIN_CERTIFICATE")
                    note += ("; WIN_CERTIFICATE at that offset reads "
                             "dwLength=%d wRevision=0x%04x wCertificateType=0x%04x"
                             % (length, revision, cert_type))
                    if length != size or revision not in (0x0100, 0x0200) \
                            or cert_type not in (0x0001, 0x0002, 0x0003, 0x0004):
                        note += (" -- these are not the values a WIN_CERTIFICATE "
                                 "header has (expected dwLength == the directory "
                                 "size %d, wRevision 0x0100/0x0200, "
                                 "wCertificateType 0x0001-0x0004)" % size)
        else:
            offset = headers.rva_to_offset(rva)
            if offset is None:
                note = "RVA does not map to on-disk data in any section"
            else:
                available = headers.rva_available(rva)
                if size > available:
                    note = ("declared size %d exceeds the %d bytes on disk from "
                            "this RVA" % (size, available))
        entries.append({
            "file_offset": offset,
            "index": index,
            "name": name,
            "note": note,
            "present": present,
            "rva": rva,
            "size": size,
        })
    return entries


# --------------------------------------------------------------------------- #
# imports
# --------------------------------------------------------------------------- #

def _walk_thunks(headers: PEHeaders, thunk_rva: int, iat_rva: int,
                 dll: str, budget: int) -> tuple[list[dict], str | None]:
    """Walk one thunk array. Returns (functions, error message or None)."""
    functions: list[dict] = []
    size = headers.pointer_size
    ordinal_flag = 1 << (size * 8 - 1)
    available = headers.rva_available(thunk_rva)
    if available < size:
        return functions, ("thunk array at RVA 0x%x is not readable on disk"
                           % thunk_rva)
    limit = min(MAX_FUNCTIONS_PER_DLL, budget, available // size)
    fmt = "<Q" if size == 8 else "<I"
    index = 0
    while index < limit:
        try:
            raw = headers.read_rva(thunk_rva + index * size, size,
                                   "import thunk of %s" % dll)
        except PEFormatError as error:
            return functions, str(error)
        value = _u(fmt, raw, 0, "import thunk")[0]
        if value == 0:
            break
        entry = {"hint": None, "iat_rva": None, "name": None, "ordinal": None}
        if iat_rva:
            entry["iat_rva"] = iat_rva + index * size
        if value & ordinal_flag:
            entry["ordinal"] = value & 0xFFFF
        else:
            name_rva = value & 0x7FFFFFFF
            hint_available = headers.rva_available(name_rva)
            if hint_available >= 2:
                try:
                    entry["hint"] = _u(
                        "<H", headers.read_rva(name_rva, 2, "IMAGE_IMPORT_BY_NAME"),
                        0, "hint")[0]
                    entry["name"] = headers.cstring_rva(name_rva + 2)
                except PEFormatError:
                    entry["name"] = None
            if entry["name"] is None:
                entry["name"] = None
                entry["ordinal"] = None
        functions.append(entry)
        index += 1
    truncated = None
    if index >= limit and limit == MAX_FUNCTIONS_PER_DLL:
        truncated = "stopped at the %d-symbol cap for one module" % MAX_FUNCTIONS_PER_DLL
    return functions, truncated


def parse_imports(headers: PEHeaders) -> tuple[list[dict] | None, list[str]]:
    """The normal import table: one entry per DLL, every symbol listed."""
    notes: list[str] = []
    rva, size = headers.directory(DIR_IMPORT)
    if not rva and not size:
        return [], notes
    available = headers.rva_available(rva)
    if available < 20:
        return None, ["IMPORT directory RVA 0x%x (size %d) does not map to "
                      "readable on-disk data" % (rva, size)]
    max_descriptors = min(MAX_IMPORT_DESCRIPTORS, available // 20)
    if size:
        max_descriptors = min(max_descriptors, max(1, size // 20))
    modules: list[dict] = []
    budget = MAX_IMPORT_FUNCTIONS_TOTAL
    for index in range(max_descriptors):
        try:
            raw = headers.read_rva(rva + index * 20, 20,
                                   "IMAGE_IMPORT_DESCRIPTOR[%d]" % index)
        except PEFormatError as error:
            notes.append(str(error))
            break
        (original_first_thunk, timestamp, forwarder_chain, name_rva,
         first_thunk) = _u("<IIIII", raw, 0, "IMAGE_IMPORT_DESCRIPTOR")
        if not any((original_first_thunk, timestamp, forwarder_chain, name_rva,
                    first_thunk)):
            break
        dll = headers.cstring_rva(name_rva) or ""
        thunk_rva = original_first_thunk or first_thunk
        functions: list[dict] = []
        truncated = None
        if thunk_rva:
            functions, truncated = _walk_thunks(
                headers, thunk_rva, first_thunk, dll or "<unnamed>", budget)
        else:
            truncated = "descriptor has neither OriginalFirstThunk nor FirstThunk"
        if truncated:
            notes.append("%s: %s" % (dll or "<unnamed module>", truncated))
        budget -= len(functions)
        modules.append({
            "dll": dll,
            "function_count": len(functions),
            "functions": sorted(
                functions,
                key=lambda item: (item["name"] is None,
                                  item["name"] or "",
                                  item["ordinal"] if item["ordinal"] is not None else -1)),
            "_bound": bool(timestamp) and timestamp != 0xFFFFFFFF,
            "_first_thunk": first_thunk,
            "_original_first_thunk": original_first_thunk,
            "_timestamp": timestamp,
        })
        if budget <= 0:
            notes.append("stopped after %d imported symbols in total (cap)"
                         % MAX_IMPORT_FUNCTIONS_TOTAL)
            break
    modules.sort(key=lambda item: item["dll"].lower())
    return modules, notes


def parse_delay_imports(headers: PEHeaders) -> tuple[list[dict] | None, list[str], dict]:
    """The delay-load import table (ImgDelayDescr), reported separately.

    A delay-loaded dependency is resolved on first use rather than at image
    load, which is exactly the shape a late-loaded protection or telemetry
    library has. Reporting it apart from the normal table is an observation, not
    a conclusion about what any particular module is for.
    """
    notes: list[str] = []
    detail: dict = {"attributes_hex": None, "descriptor_count": 0,
                    "addresses_are_rva": None}
    rva, size = headers.directory(DIR_DELAY_IMPORT)
    if not rva and not size:
        return [], notes, detail
    available = headers.rva_available(rva)
    if available < 32:
        return None, ["DELAY_IMPORT directory RVA 0x%x (size %d) does not map to "
                      "readable on-disk data" % (rva, size)], detail
    max_descriptors = min(MAX_IMPORT_DESCRIPTORS, available // 32)
    if size:
        max_descriptors = min(max_descriptors, max(1, size // 32))
    modules: list[dict] = []
    budget = MAX_IMPORT_FUNCTIONS_TOTAL
    for index in range(max_descriptors):
        try:
            raw = headers.read_rva(rva + index * 32, 32,
                                   "ImgDelayDescr[%d]" % index)
        except PEFormatError as error:
            notes.append(str(error))
            break
        (attributes, name_field, module_handle, iat, int_table, bound_iat,
         unload_iat, timestamp) = _u("<IIIIIIII", raw, 0, "ImgDelayDescr")
        if not any((attributes, name_field, module_handle, iat, int_table)):
            break
        # dlattrRva (bit 0) says the fields are RVAs. Cleared means the old
        # MSVC 6 form where they are virtual addresses.
        rva_form = bool(attributes & 1)
        detail["attributes_hex"] = hexword(attributes)
        detail["addresses_are_rva"] = rva_form

        def to_rva(value: int) -> int:
            if not value:
                return 0
            if rva_form:
                return value
            return value - headers.image_base if value >= headers.image_base else 0

        dll = headers.cstring_rva(to_rva(name_field)) or ""
        thunk_rva = to_rva(int_table) or to_rva(iat)
        functions: list[dict] = []
        truncated = None
        if thunk_rva:
            functions, truncated = _walk_thunks(
                headers, thunk_rva, to_rva(iat), dll or "<unnamed>", budget)
        else:
            truncated = "descriptor has no import name table and no IAT"
        if truncated:
            notes.append("delay-load %s: %s" % (dll or "<unnamed module>", truncated))
        budget -= len(functions)
        modules.append({
            "dll": dll,
            "function_count": len(functions),
            "functions": sorted(
                functions,
                key=lambda item: (item["name"] is None,
                                  item["name"] or "",
                                  item["ordinal"] if item["ordinal"] is not None else -1)),
        })
        if budget <= 0:
            notes.append("delay-load: stopped after %d symbols in total (cap)"
                         % MAX_IMPORT_FUNCTIONS_TOTAL)
            break
    detail["descriptor_count"] = len(modules)
    modules.sort(key=lambda item: item["dll"].lower())
    return modules, notes, detail


# --------------------------------------------------------------------------- #
# exports
# --------------------------------------------------------------------------- #

def parse_exports(headers: PEHeaders) -> tuple[list[dict] | None, dict, list[str]]:
    notes: list[str] = []
    summary: dict = {"present": False, "dll_name": None, "ordinal_base": None,
                     "number_of_functions": None, "number_of_names": None,
                     "timestamp": None}
    rva, size = headers.directory(DIR_EXPORT)
    if not rva and not size:
        return [], summary, notes
    if headers.rva_available(rva) < 40:
        return None, summary, ["EXPORT directory RVA 0x%x (size %d) does not map "
                               "to readable on-disk data" % (rva, size)]
    try:
        raw = headers.read_rva(rva, 40, "IMAGE_EXPORT_DIRECTORY")
    except PEFormatError as error:
        return None, summary, [str(error)]
    (_flags, timestamp, _major, _minor, name_rva, ordinal_base,
     number_of_functions, number_of_names, functions_rva, names_rva,
     name_ordinals_rva) = _u("<IIHHIIIIIII", raw, 0, "IMAGE_EXPORT_DIRECTORY")

    summary.update({
        "present": True,
        "dll_name": headers.cstring_rva(name_rva),
        "ordinal_base": ordinal_base,
        "number_of_functions": number_of_functions,
        "number_of_names": number_of_names,
        "timestamp": timestamp,
    })
    if number_of_functions > MAX_EXPORTS:
        notes.append("NumberOfFunctions is %d, reading the first %d"
                     % (number_of_functions, MAX_EXPORTS))
    count = min(number_of_functions, MAX_EXPORTS,
                headers.rva_available(functions_rva) // 4)
    addresses: list[int] = []
    for index in range(count):
        try:
            addresses.append(_u("<I", headers.read_rva(
                functions_rva + index * 4, 4, "export address table"), 0,
                "export address")[0])
        except PEFormatError as error:
            notes.append(str(error))
            break

    name_count = min(number_of_names, MAX_EXPORTS,
                     headers.rva_available(names_rva) // 4,
                     headers.rva_available(name_ordinals_rva) // 2)
    by_index: dict[int, str] = {}
    for index in range(name_count):
        try:
            string_rva = _u("<I", headers.read_rva(
                names_rva + index * 4, 4, "export name pointer table"), 0,
                "export name rva")[0]
            ordinal_index = _u("<H", headers.read_rva(
                name_ordinals_rva + index * 2, 2, "export ordinal table"), 0,
                "export ordinal index")[0]
        except PEFormatError as error:
            notes.append(str(error))
            break
        name = headers.cstring_rva(string_rva)
        if name is not None and ordinal_index not in by_index:
            by_index[ordinal_index] = name

    entries: list[dict] = []
    for index, address in enumerate(addresses):
        if address == 0:
            continue  # a hole in the export address table
        forwarder = None
        if rva <= address < rva + size:
            # An export address that lands inside the export directory itself is
            # a forwarder ("OtherDll.OtherSymbol") rather than code. An empty
            # string there is not a forwarder, it is a zero byte, so it stays
            # null instead of being reported as a forward to nowhere.
            forwarder = headers.cstring_rva(address) or None
        entries.append({
            "address": address,
            "forwarder": forwarder,
            "name": by_index.get(index),
            "ordinal": ordinal_base + index,
        })
    entries.sort(key=lambda item: item["ordinal"])
    return entries, summary, notes


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #

def parse_tls(headers: PEHeaders) -> tuple[dict, dict, list[str]]:
    """The TLS directory and its callback array.

    This one matters more than the rest: a TLS callback runs *before* the image
    entry point, so the addresses reported here bound the earliest code that can
    execute in the process. The callback array is walked, not merely counted.
    The array holds virtual addresses; both the VA as stored and the derived RVA
    are reported so no reader has to guess which convention was used.
    """
    notes: list[str] = []
    schema = {"address_of_index": None, "callback_count": None,
              "callbacks": None, "present": False}
    detail = {"address_of_callbacks_va": None, "callbacks_rva": None,
              "callback_rvas": None, "characteristics": None,
              "directory_rva": None, "directory_size": None,
              "end_address_of_raw_data": None, "size_of_zero_fill": None,
              "start_address_of_raw_data": None,
              "address_convention": "callbacks and address_of_index are VIRTUAL "
                                    "ADDRESSES exactly as stored in "
                                    "IMAGE_TLS_DIRECTORY; callback_rvas below are "
                                    "those values minus ImageBase"}
    rva, size = headers.directory(DIR_TLS)
    detail["directory_rva"] = rva
    detail["directory_size"] = size
    if not rva and not size:
        schema["callback_count"] = 0
        schema["callbacks"] = []
        return schema, detail, notes

    pointer = headers.pointer_size
    struct_size = 4 * pointer + 8
    if headers.rva_available(rva) < struct_size:
        notes.append("TLS directory RVA 0x%x does not map to %d readable bytes"
                     % (rva, struct_size))
        schema["present"] = True
        return schema, detail, notes
    try:
        raw = headers.read_rva(rva, struct_size, "IMAGE_TLS_DIRECTORY")
    except PEFormatError as error:
        notes.append(str(error))
        schema["present"] = True
        return schema, detail, notes

    fmt = "<QQQQII" if pointer == 8 else "<IIIIII"
    (start, end, index_va, callbacks_va, zero_fill, characteristics) = _u(
        fmt, raw, 0, "IMAGE_TLS_DIRECTORY")
    schema["present"] = True
    schema["address_of_index"] = index_va
    detail.update({
        "address_of_callbacks_va": callbacks_va,
        "characteristics": hexword(characteristics),
        "end_address_of_raw_data": end,
        "size_of_zero_fill": zero_fill,
        "start_address_of_raw_data": start,
    })

    callbacks: list[int] = []
    callback_rvas: list[int] = []
    if callbacks_va:
        if callbacks_va < headers.image_base:
            notes.append(
                "AddressOfCallBacks 0x%x is below ImageBase 0x%x; not a virtual "
                "address in this image, callback array not walked"
                % (callbacks_va, headers.image_base))
        else:
            array_rva = callbacks_va - headers.image_base
            detail["callbacks_rva"] = array_rva
            available = headers.rva_available(array_rva)
            limit = min(MAX_TLS_CALLBACKS, available // pointer)
            if limit == 0:
                notes.append("TLS callback array at RVA 0x%x is not on disk"
                             % array_rva)
            entry_fmt = "<Q" if pointer == 8 else "<I"
            for slot in range(limit):
                try:
                    value = _u(entry_fmt, headers.read_rva(
                        array_rva + slot * pointer, pointer,
                        "TLS callback slot"), 0, "TLS callback")[0]
                except PEFormatError as error:
                    notes.append(str(error))
                    break
                if value == 0:
                    break
                callbacks.append(value)
                callback_rvas.append(value - headers.image_base
                                     if value >= headers.image_base else value)
            if len(callbacks) == limit == MAX_TLS_CALLBACKS:
                notes.append("TLS callback array stopped at the %d-entry cap"
                             % MAX_TLS_CALLBACKS)
    schema["callbacks"] = callbacks
    schema["callback_count"] = len(callbacks)
    detail["callback_rvas"] = callback_rvas
    return schema, detail, notes


# --------------------------------------------------------------------------- #
# debug directory
# --------------------------------------------------------------------------- #

def _format_pdb_guid(raw: bytes) -> str | None:
    """A CodeView GUID in the canonical 8-4-4-4-12 form (mixed-endian fields)."""
    if len(raw) != 16:
        return None
    data1, data2, data3 = struct.unpack_from("<IHH", raw, 0)
    tail = raw[8:]
    return "%08X-%04X-%04X-%s-%s" % (
        data1, data2, data3, tail[:2].hex().upper(), tail[2:].hex().upper())


def parse_debug(headers: PEHeaders) -> tuple[list[dict] | None, str | None, list[str]]:
    """Every IMAGE_DEBUG_DIRECTORY entry; CodeView payloads decoded verbatim.

    A CodeView PDB path is reported exactly as stored. It routinely leaks the
    build machine's directory layout, which is evidence for plan.md section 4
    (``engine.build_machine_path_leak``) -- so it is never normalized, trimmed
    or prettified here.
    """
    notes: list[str] = []
    rva, size = headers.directory(DIR_DEBUG)
    if not rva and not size:
        return [], None, notes
    available = headers.rva_available(rva)
    if available < 28:
        return None, None, ["DEBUG directory RVA 0x%x (size %d) does not map to "
                            "readable on-disk data" % (rva, size)]
    count = min(MAX_DEBUG_ENTRIES, available // 28, max(1, size // 28) if size else
                MAX_DEBUG_ENTRIES)
    entries: list[dict] = []
    pdb_path: str | None = None
    for index in range(count):
        try:
            raw = headers.read_rva(rva + index * 28, 28,
                                   "IMAGE_DEBUG_DIRECTORY[%d]" % index)
        except PEFormatError as error:
            notes.append(str(error))
            break
        (_characteristics, timestamp, major, minor, dtype, data_size,
         data_rva, data_pointer) = _u("<IIHHIIII", raw, 0,
                                      "IMAGE_DEBUG_DIRECTORY")
        entry = {
            "address_of_raw_data": data_rva,
            "cv_signature": None,
            "major_version": major,
            "minor_version": minor,
            "pdb_age": None,
            "pdb_guid": None,
            "pdb_path": None,
            "pointer_to_raw_data": data_pointer,
            "size": data_size,
            "timestamp": timestamp,
            "type": dtype,
            "type_name": DEBUG_TYPE_NAMES.get(dtype),
        }
        if dtype == 2 and data_size >= 4:
            payload_offset = None
            if data_pointer and data_pointer + min(data_size, MAX_STRING_BYTES) <= headers.image.size:
                payload_offset = data_pointer
            elif data_rva:
                payload_offset = headers.rva_to_offset(data_rva)
            if payload_offset is None:
                notes.append("CodeView entry %d: payload is not readable "
                             "(PointerToRawData %d, AddressOfRawData 0x%x)"
                             % (index, data_pointer, data_rva))
            else:
                payload = headers.image.read_clamped(
                    payload_offset, min(data_size, MAX_STRING_BYTES))
                signature = payload[:4]
                entry["cv_signature"] = _decode_ascii(signature)
                if signature == b"RSDS" and len(payload) >= 24:
                    entry["pdb_guid"] = _format_pdb_guid(payload[4:20])
                    entry["pdb_age"] = _u("<I", payload, 20, "RSDS age")[0]
                    tail = payload[24:]
                    stop = tail.find(b"\x00")
                    entry["pdb_path"] = _decode_ascii(
                        tail if stop < 0 else tail[:stop])
                elif signature == b"NB10" and len(payload) >= 16:
                    entry["pdb_age"] = _u("<I", payload, 12, "NB10 age")[0]
                    tail = payload[16:]
                    stop = tail.find(b"\x00")
                    entry["pdb_path"] = _decode_ascii(
                        tail if stop < 0 else tail[:stop])
                if entry["pdb_path"] and pdb_path is None:
                    pdb_path = entry["pdb_path"]
        entries.append(entry)
    return entries, pdb_path, notes


# --------------------------------------------------------------------------- #
# load configuration / Control Flow Guard
# --------------------------------------------------------------------------- #

def parse_load_config(headers: PEHeaders) -> tuple[dict | None, list[str]]:
    """IMAGE_LOAD_CONFIG_DIRECTORY: security cookie, SEH and CFG tables.

    Every field is read by explicit offset against the *declared* Size, so a
    short (older-toolchain) load config yields nulls for the fields it does not
    contain rather than garbage from the bytes that follow it. Whether Control
    Flow Guard presence makes later instrumentation harder is not decided here;
    the flags are reported.
    """
    notes: list[str] = []
    rva, size = headers.directory(DIR_LOAD_CONFIG)
    if not rva and not size:
        return None, notes
    available = headers.rva_available(rva)
    if available < 4:
        return None, ["LOAD_CONFIG directory RVA 0x%x (size %d) does not map to "
                      "readable on-disk data" % (rva, size)]
    declared = _u("<I", headers.read_rva(rva, 4, "LoadConfig.Size"), 0,
                  "LoadConfig.Size")[0]
    usable = min(declared if declared else size, size if size else declared,
                 available, 1024)
    if usable < 4:
        usable = min(available, 1024)
    blob = headers.read_rva(rva, usable, "IMAGE_LOAD_CONFIG_DIRECTORY")

    pointer = headers.pointer_size
    pfmt = "<Q" if pointer == 8 else "<I"

    def dword(offset: int):
        if offset + 4 > len(blob):
            return None
        return _u("<I", blob, offset, "LoadConfig dword")[0]

    def word(offset: int):
        if offset + 2 > len(blob):
            return None
        return _u("<H", blob, offset, "LoadConfig word")[0]

    def ptr(offset: int):
        if offset + pointer > len(blob):
            return None
        return _u(pfmt, blob, offset, "LoadConfig pointer")[0]

    # Layout differs only in the width of the pointer-sized members; the fixed
    # DWORD prologue is identical in both forms.
    if pointer == 8:
        off = {
            "time_date_stamp": 4, "major_version": 8, "minor_version": 10,
            "global_flags_clear": 12, "global_flags_set": 16,
            "critical_section_default_timeout": 20,
            "process_heap_flags": 72, "csd_version": 76,
            "dependent_load_flags": 78, "edit_list": 80,
            "security_cookie": 88, "se_handler_table": 96,
            "se_handler_count": 104, "guard_cf_check_function_pointer": 112,
            "guard_cf_dispatch_function_pointer": 120,
            "guard_cf_function_table": 128, "guard_cf_function_count": 136,
            "guard_flags": 144, "code_integrity": 148,
            "guard_address_taken_iat_entry_table": 160,
            "guard_address_taken_iat_entry_count": 168,
            "guard_long_jump_target_table": 176,
            "guard_long_jump_target_count": 184,
        }
    else:
        off = {
            "time_date_stamp": 4, "major_version": 8, "minor_version": 10,
            "global_flags_clear": 12, "global_flags_set": 16,
            "critical_section_default_timeout": 20,
            "process_heap_flags": 44, "csd_version": 48,
            "dependent_load_flags": 50, "edit_list": 52,
            "security_cookie": 56, "se_handler_table": 60,
            "se_handler_count": 64, "guard_cf_check_function_pointer": 68,
            "guard_cf_dispatch_function_pointer": 72,
            "guard_cf_function_table": 76, "guard_cf_function_count": 80,
            "guard_flags": 84, "code_integrity": 88,
            "guard_address_taken_iat_entry_table": 100,
            "guard_address_taken_iat_entry_count": 104,
            "guard_long_jump_target_table": 108,
            "guard_long_jump_target_count": 112,
        }

    guard_flags = dword(off["guard_flags"])
    result = {
        "critical_section_default_timeout": dword(off["critical_section_default_timeout"]),
        "csd_version": word(off["csd_version"]),
        "declared_size": declared,
        "dependent_load_flags": hexword(word(off["dependent_load_flags"]), 4),
        "directory_rva": rva,
        "directory_size": size,
        "edit_list": ptr(off["edit_list"]),
        "global_flags_clear": hexword(dword(off["global_flags_clear"])),
        "global_flags_set": hexword(dword(off["global_flags_set"])),
        "guard_address_taken_iat_entry_count": ptr(off["guard_address_taken_iat_entry_count"]),
        "guard_address_taken_iat_entry_table": ptr(off["guard_address_taken_iat_entry_table"]),
        "guard_cf_check_function_pointer": ptr(off["guard_cf_check_function_pointer"]),
        "guard_cf_dispatch_function_pointer": ptr(off["guard_cf_dispatch_function_pointer"]),
        "guard_cf_function_count": ptr(off["guard_cf_function_count"]),
        "guard_cf_function_table": ptr(off["guard_cf_function_table"]),
        "guard_flags": hexword(guard_flags),
        "guard_flags_decoded": decode_flags(guard_flags, GUARD_FLAGS),
        "guard_long_jump_target_count": ptr(off["guard_long_jump_target_count"]),
        "guard_long_jump_target_table": ptr(off["guard_long_jump_target_table"]),
        "major_version": word(off["major_version"]),
        "minor_version": word(off["minor_version"]),
        "process_heap_flags": hexword(dword(off["process_heap_flags"])),
        "se_handler_count": ptr(off["se_handler_count"]),
        "se_handler_table": ptr(off["se_handler_table"]),
        "security_cookie": ptr(off["security_cookie"]),
        "time_date_stamp": dword(off["time_date_stamp"]),
    }
    # Derived booleans, each one a restatement of a bit that is also printed
    # raw above, so a reader can check the derivation.
    dll_chars = headers.dll_characteristics
    result["cfg_marked_in_dll_characteristics"] = bool(dll_chars & 0x4000)
    result["cfg_instrumented"] = (
        bool(guard_flags & 0x00000100) if guard_flags is not None else None)
    result["cfg_function_table_present"] = (
        bool(guard_flags & 0x00000400) if guard_flags is not None else None)
    result["cf_function_table_stride"] = (
        (guard_flags >> 28) & 0xF if guard_flags is not None else None)
    result["security_cookie_present"] = bool(result["security_cookie"])
    result["safe_seh"] = (
        bool(result["se_handler_table"]) and bool(result["se_handler_count"]))
    if declared > available:
        notes.append("load config declares Size %d but only %d bytes are on "
                     "disk from its RVA; fields beyond that are null"
                     % (declared, available))
    return result, notes


# --------------------------------------------------------------------------- #
# exception data (.pdata / RUNTIME_FUNCTION)
# --------------------------------------------------------------------------- #

def parse_exception_data(headers: PEHeaders) -> tuple[dict, list[str]]:
    """Count (and sample) RUNTIME_FUNCTION rows -- this sizes later Ghidra work.

    The rows are counted, never enumerated: a UE shipping image has hundreds of
    thousands of them and listing them would dwarf the rest of the document
    while adding nothing this milestone needs.
    """
    notes: list[str] = []
    rva, size = headers.directory(DIR_EXCEPTION)
    result = {"directory_rva": rva, "directory_size": size, "entry_size": None,
              "function_count": None, "sample": [], "sample_limit": PDATA_SAMPLE,
              "note": None}
    if not rva and not size:
        result["note"] = "EXCEPTION directory is absent (RVA and size are 0)"
        result["function_count"] = 0
        return result, notes
    # 12 bytes per RUNTIME_FUNCTION on AMD64 and on ARM64 in its full form.
    entry_size = 12
    result["entry_size"] = entry_size
    if headers.machine not in (0x8664, 0xAA64, 0x0200):
        result["note"] = ("entry size assumed to be %d bytes (AMD64 layout); "
                          "machine is 0x%04x" % (entry_size, headers.machine))
    available = headers.rva_available(rva)
    usable = min(size, available)
    count = usable // entry_size
    result["function_count"] = count
    if size > available:
        notes.append("EXCEPTION directory declares %d bytes but only %d are on "
                     "disk; count is based on the readable part" % (size, available))
    for index in range(min(PDATA_SAMPLE, count)):
        try:
            raw = headers.read_rva(rva + index * entry_size, entry_size,
                                   "RUNTIME_FUNCTION[%d]" % index)
        except PEFormatError as error:
            notes.append(str(error))
            break
        begin, end, unwind = _u("<III", raw, 0, "RUNTIME_FUNCTION")
        result["sample"].append({"begin_address": begin, "end_address": end,
                                 "index": index, "unwind_info_address": unwind})
    return result, notes


# --------------------------------------------------------------------------- #
# resources and VS_VERSIONINFO  (question A-03)
# --------------------------------------------------------------------------- #

def _read_resource_directory(headers: PEHeaders, base_rva: int, node_rva: int,
                             budget: list[int]) -> tuple[list[dict], str | None]:
    """One IMAGE_RESOURCE_DIRECTORY node -> its entries, as raw tuples."""
    if headers.rva_available(node_rva) < 16:
        return [], "resource directory at RVA 0x%x is not on disk" % node_rva
    raw = headers.read_rva(node_rva, 16, "IMAGE_RESOURCE_DIRECTORY")
    (_characteristics, _timestamp, _major, _minor, named_count,
     id_count) = _u("<IIHHHH", raw, 0, "IMAGE_RESOURCE_DIRECTORY")
    total = named_count + id_count
    available = headers.rva_available(node_rva + 16) // 8
    if total > available:
        total = available
    entries = []
    for index in range(total):
        if budget[0] <= 0:
            return entries, "resource walk stopped at the %d-node cap" % MAX_RESOURCE_ENTRIES
        budget[0] -= 1
        try:
            row = headers.read_rva(node_rva + 16 + index * 8, 8,
                                   "IMAGE_RESOURCE_DIRECTORY_ENTRY")
        except PEFormatError as error:
            return entries, str(error)
        name_field, offset_field = _u("<II", row, 0,
                                      "IMAGE_RESOURCE_DIRECTORY_ENTRY")
        is_named = bool(name_field & 0x80000000)
        name = None
        identifier = None
        if is_named:
            string_rva = base_rva + (name_field & 0x7FFFFFFF)
            if headers.rva_available(string_rva) >= 2:
                length = _u("<H", headers.read_rva(string_rva, 2,
                                                   "IMAGE_RESOURCE_DIR_STRING_U"),
                            0, "resource name length")[0]
                length = min(length, 512)
                if length and headers.rva_available(string_rva + 2) >= length * 2:
                    name = _decode_utf16(headers.read_rva(
                        string_rva + 2, length * 2, "resource name"))
        else:
            identifier = name_field & 0xFFFF
        entries.append({
            "id": identifier,
            "is_directory": bool(offset_field & 0x80000000),
            "name": name,
            "target_rva": base_rva + (offset_field & 0x7FFFFFFF),
        })
    return entries, None


def _read_resource_data_entry(headers: PEHeaders, rva: int) -> dict | None:
    if headers.rva_available(rva) < 16:
        return None
    raw = headers.read_rva(rva, 16, "IMAGE_RESOURCE_DATA_ENTRY")
    data_rva, size, codepage, _reserved = _u("<IIII", raw, 0,
                                             "IMAGE_RESOURCE_DATA_ENTRY")
    return {"codepage": codepage, "data_rva": data_rva, "size": size}


def parse_resources(headers: PEHeaders) -> tuple[dict, dict | None, list[str]]:
    """Walk .rsrc; report the tree, and parse VS_VERSIONINFO when it is there.

    This is the function that answers question A-03 ("why is no version field
    readable through Get-Item().VersionInfo even though .rsrc exists"). It
    distinguishes, and names, four states, and reports whichever it finds
    without guessing between them:

    ``absent``
        No RESOURCE data directory at all.
    ``no-version-resource``
        Resource tree present, but it contains no RT_VERSION (type 16) node.
    ``version-resource-empty``
        RT_VERSION exists but its data entry is zero-length, or its
        VS_VERSIONINFO carries neither a VS_FIXEDFILEINFO nor a StringFileInfo.
    ``version-resource-populated``
        RT_VERSION exists and carries values, which are reported.
    """
    notes: list[str] = []
    survey = {"data_entry_count": 0, "diagnosis": "absent",
              "directory_rva": None, "directory_size": None,
              "rt_version_data_size": None, "rt_version_present": False,
              "types": [], "walk_truncated": None}
    rva, size = headers.directory(DIR_RESOURCE)
    survey["directory_rva"] = rva
    survey["directory_size"] = size
    if not rva and not size:
        return survey, None, notes
    if headers.rva_available(rva) < 16:
        survey["diagnosis"] = "unreadable"
        notes.append("RESOURCE directory RVA 0x%x (size %d) does not map to "
                     "readable on-disk data" % (rva, size))
        return survey, None, notes

    budget = [MAX_RESOURCE_ENTRIES]
    try:
        level1, truncated = _read_resource_directory(headers, rva, rva, budget)
    except PEFormatError as error:
        survey["diagnosis"] = "unreadable"
        notes.append(str(error))
        return survey, None, notes
    if truncated:
        survey["walk_truncated"] = truncated

    version_blob: bytes | None = None
    version_locations: list[dict] = []
    types: list[dict] = []

    for type_entry in level1:
        type_id = type_entry["id"]
        type_record = {
            "count": 0,
            "id": type_id,
            "name": type_entry["name"],
            "type_name": RESOURCE_TYPE_NAMES.get(type_id) if type_id is not None else None,
        }
        if not type_entry["is_directory"]:
            type_record["count"] = 1
            survey["data_entry_count"] += 1
            types.append(type_record)
            continue
        try:
            level2, truncated2 = _read_resource_directory(
                headers, rva, type_entry["target_rva"], budget)
        except PEFormatError as error:
            notes.append(str(error))
            types.append(type_record)
            continue
        if truncated2 and not survey["walk_truncated"]:
            survey["walk_truncated"] = truncated2
        for name_entry in level2:
            if not name_entry["is_directory"]:
                type_record["count"] += 1
                survey["data_entry_count"] += 1
                continue
            try:
                level3, truncated3 = _read_resource_directory(
                    headers, rva, name_entry["target_rva"], budget)
            except PEFormatError as error:
                notes.append(str(error))
                continue
            if truncated3 and not survey["walk_truncated"]:
                survey["walk_truncated"] = truncated3
            for lang_entry in level3:
                if lang_entry["is_directory"]:
                    continue  # a fourth level is not defined by the format
                type_record["count"] += 1
                survey["data_entry_count"] += 1
                if type_id != RT_VERSION:
                    continue
                data = _read_resource_data_entry(headers, lang_entry["target_rva"])
                if data is None:
                    notes.append("RT_VERSION data entry at RVA 0x%x is not readable"
                                 % lang_entry["target_rva"])
                    continue
                version_locations.append({
                    "codepage": data["codepage"],
                    "data_rva": data["data_rva"],
                    "language_id": lang_entry["id"],
                    "name_id": name_entry["id"],
                    "name": name_entry["name"],
                    "size": data["size"],
                })
                if version_blob is None and data["size"]:
                    length = min(data["size"], MAX_VERSION_RESOURCE_BYTES,
                                 headers.rva_available(data["data_rva"]))
                    if length > 0:
                        try:
                            version_blob = headers.read_rva(
                                data["data_rva"], length, "VS_VERSIONINFO")
                        except PEFormatError as error:
                            notes.append(str(error))
        types.append(type_record)

    types.sort(key=lambda item: (item["id"] is None, item["id"] or 0,
                                 item["name"] or ""))
    survey["types"] = types
    survey["rt_version_present"] = bool(version_locations)
    survey["rt_version_locations"] = version_locations
    survey["rt_version_data_size"] = (
        version_locations[0]["size"] if version_locations else None)

    if not version_locations:
        survey["diagnosis"] = "no-version-resource"
        return survey, None, notes
    if version_blob is None:
        survey["diagnosis"] = "version-resource-empty"
        notes.append("RT_VERSION exists but carries no readable bytes "
                     "(data entry size %s)" % survey["rt_version_data_size"])
        return survey, None, notes

    version_info, vi_notes = parse_version_info(version_blob)
    notes.extend(vi_notes)
    has_fixed = bool(version_info and version_info.get("fixed"))
    has_strings = bool(version_info and version_info.get("strings"))
    survey["diagnosis"] = ("version-resource-populated"
                           if (has_fixed or has_strings)
                           else "version-resource-empty")
    return survey, version_info, notes


def _read_wsz(blob: bytes, position: int, end: int) -> tuple[str, int]:
    """UTF-16LE NUL-terminated key at *position*; returns (text, next position)."""
    start = position
    while position + 2 <= end:
        if blob[position] == 0 and blob[position + 1] == 0:
            text = _decode_utf16(blob[start:position])
            return text, position + 2
        position += 2
    return _decode_utf16(blob[start:end]), end


def _parse_vi_header(blob: bytes, position: int, end: int, what: str):
    """Common VS_VERSIONINFO child header -> (key, value slice, children, block end)."""
    if position + 6 > end:
        raise PEFormatError("%s: header at %d runs past the block" % (what, position))
    length, value_length, value_type = _u("<HHH", blob, position, what)
    if length < 6:
        raise PEFormatError("%s: wLength %d at offset %d is impossible"
                            % (what, length, position))
    block_end = min(position + length, end)
    key, after_key = _read_wsz(blob, position + 6, block_end)
    value_start = _align4(after_key)
    value_bytes = value_length * 2 if value_type == 1 else value_length
    value_end = min(value_start + value_bytes, block_end)
    children = _align4(value_end)
    return key, (value_start, value_end), children, block_end


def parse_version_info(blob: bytes) -> tuple[dict | None, list[str]]:
    """Parse a VS_VERSIONINFO resource blob into the schema's shape.

    Everything is read out of one bounded, already-in-memory blob (capped at
    MAX_VERSION_RESOURCE_BYTES), so there is no seeking here and no way for a
    length field to reach outside it.
    """
    notes: list[str] = []
    end = len(blob)
    if end < 6:
        return None, ["VS_VERSIONINFO blob is %d bytes, too small" % end]
    try:
        key, (value_start, value_end), children, block_end = _parse_vi_header(
            blob, 0, end, "VS_VERSIONINFO")
    except PEFormatError as error:
        return None, [str(error)]
    if key != "VS_VERSION_INFO":
        notes.append("VS_VERSIONINFO root key is %r, expected 'VS_VERSION_INFO'"
                     % key)

    fixed = None
    if value_end - value_start >= 52:
        signature = _u("<I", blob, value_start, "VS_FIXEDFILEINFO.dwSignature")[0]
        if signature != 0xFEEF04BD:
            notes.append("VS_FIXEDFILEINFO signature is 0x%08x, expected "
                         "0xfeef04bd; fixed block not decoded" % signature)
        else:
            (_sig, struc_version, file_ms, file_ls, product_ms, product_ls,
             flags_mask, flags, file_os, file_type, file_subtype,
             date_ms, date_ls) = _u("<13I", blob, value_start, "VS_FIXEDFILEINFO")
            quad = lambda ms, ls: "%d.%d.%d.%d" % (
                (ms >> 16) & 0xFFFF, ms & 0xFFFF, (ls >> 16) & 0xFFFF, ls & 0xFFFF)
            fixed = {
                "file_flags": hexword(flags),
                "file_os": hexword(file_os),
                "file_subtype": hexword(file_subtype),
                "file_type": hexword(file_type),
                "file_version": quad(file_ms, file_ls),
                "product_version": quad(product_ms, product_ls),
            }
            notes.append(
                "VS_FIXEDFILEINFO: dwStrucVersion=0x%08x dwFileFlagsMask=0x%08x "
                "dwFileDate=0x%08x%08x flags_decoded=%s"
                % (struc_version, flags_mask, date_ms, date_ls,
                   ",".join(decode_flags(flags, VS_FF_FLAGS)) or "none"))
    elif value_end > value_start:
        notes.append("VS_VERSIONINFO value is %d bytes, too small for a "
                     "VS_FIXEDFILEINFO (52)" % (value_end - value_start))

    strings: dict[str, str] = {}
    tables: list[dict] = []
    translations: list[str] = []
    position = children
    guard = 0
    while position + 6 <= block_end and guard < MAX_VERSION_CHILDREN:
        guard += 1
        try:
            child_key, _child_value, child_children, child_end = _parse_vi_header(
                blob, position, block_end, "VS_VERSIONINFO child")
        except PEFormatError as error:
            notes.append(str(error))
            break
        # Every member of a VS_VERSIONINFO tree starts on a 4-byte boundary, and
        # wLength does NOT cover the padding that gets the *next* sibling back
        # onto one. Advancing by wLength alone lands one or two bytes early and
        # every following header then decodes as garbage -- which shows up as a
        # silently short result ("one string, no translations"), not as an
        # error. Hence _align4 at every sibling step below.
        child_next = _align4(child_end)
        if child_next <= position:
            break
        if child_key == "StringFileInfo":
            inner = child_children
            inner_guard = 0
            while inner + 6 <= child_end and inner_guard < MAX_VERSION_CHILDREN:
                inner_guard += 1
                try:
                    table_key, _tv, table_children, table_end = _parse_vi_header(
                        blob, inner, child_end, "StringTable")
                except PEFormatError as error:
                    notes.append(str(error))
                    break
                table_next = _align4(table_end)
                if table_next <= inner:
                    break
                table = {"key": table_key, "strings": {}}
                item = table_children
                item_guard = 0
                while item + 6 <= table_end and item_guard < MAX_VERSION_CHILDREN:
                    item_guard += 1
                    try:
                        name, (vstart, vend), _c, item_end = _parse_vi_header(
                            blob, item, table_end, "String")
                    except PEFormatError as error:
                        notes.append(str(error))
                        break
                    item_next = _align4(item_end)
                    if item_next <= item:
                        break
                    text = _decode_utf16(blob[vstart:vend]).rstrip("\x00")
                    if name:
                        table["strings"][name] = text
                        strings.setdefault(name, text)
                    item = item_next
                tables.append(table)
                inner = table_next
        elif child_key == "VarFileInfo":
            inner = child_children
            inner_guard = 0
            while inner + 6 <= child_end and inner_guard < MAX_VERSION_CHILDREN:
                inner_guard += 1
                try:
                    var_key, (vstart, vend), _c, var_end = _parse_vi_header(
                        blob, inner, child_end, "Var")
                except PEFormatError as error:
                    notes.append(str(error))
                    break
                var_next = _align4(var_end)
                if var_next <= inner:
                    break
                if var_key == "Translation":
                    cursor = vstart
                    while cursor + 4 <= vend:
                        language, codepage = _u("<HH", blob, cursor, "Translation")
                        translations.append("%04x%04x" % (language, codepage))
                        cursor += 4
                inner = var_next
        position = child_next

    result = {
        "fixed": fixed,
        "strings": strings or None,
        "translations": translations or None,
    }
    if tables:
        notes.append("StringFileInfo tables: %s"
                     % "; ".join("%s(%d entries)" % (table["key"],
                                                     len(table["strings"]))
                                 for table in tables))
    if fixed is None and not strings:
        notes.append("VS_VERSIONINFO is present but carries neither a "
                     "VS_FIXEDFILEINFO nor any StringFileInfo entry")
    return result, notes


# --------------------------------------------------------------------------- #
# Rich header
# --------------------------------------------------------------------------- #

def parse_rich_header(headers: PEHeaders) -> tuple[dict, list[str]]:
    """Decode the XOR-masked 'Rich' block that MSVC puts in the DOS stub.

    It records which compiler and linker builds contributed object files, which
    is independent corroboration for plan.md section 4 (a toolchain generation
    constrains the engine release that could have produced the image). Absence
    is equally informative and is reported as ``present: false``, not as an
    error.
    """
    notes: list[str] = []
    result = {"present": False, "xor_key": None, "checksum_valid": None,
              "raw_sha256": None, "entries": None}
    span = min(headers.e_lfanew, MAX_RICH_SCAN)
    stub = headers.image.read_clamped(0, span)
    if len(stub) < 0x50:
        return result, notes
    marker = stub.rfind(b"Rich")
    if marker < 0 or marker + 8 > len(stub):
        return result, notes
    key = _u("<I", stub, marker + 4, "Rich xor key")[0]

    # Walk backwards in 4-byte steps looking for 'DanS' under the same key.
    dans = None
    position = marker - 4
    while position >= 0:
        word = _u("<I", stub, position, "Rich word")[0]
        if word ^ key == 0x536E6144:  # 'DanS'
            dans = position
            break
        position -= 4
    if dans is None:
        notes.append("a 'Rich' marker was found at offset %d but no matching "
                     "'DanS' start; header not decoded" % marker)
        return result, notes

    raw = stub[dans:marker + 8]
    result["present"] = True
    result["xor_key"] = hexword(key)
    result["raw_sha256"] = hashlib.sha256(raw).hexdigest()

    entries: list[dict] = []
    # After 'DanS' come three XOR-padding DWORDs, then (comp.id, count) pairs.
    cursor = dans + 16
    while cursor + 8 <= marker and len(entries) < MAX_RICH_ENTRIES:
        comp_id = _u("<I", stub, cursor, "Rich comp.id")[0] ^ key
        count = _u("<I", stub, cursor + 4, "Rich count")[0] ^ key
        product_id = (comp_id >> 16) & 0xFFFF
        build_number = comp_id & 0xFFFF
        entries.append({
            "build_number": build_number,
            "count": count,
            "product_id": product_id,
            "product_name": RICH_PRODUCT_NAMES.get(product_id),
        })
        cursor += 8
    entries.sort(key=lambda item: (item["product_id"], item["build_number"]))
    result["entries"] = entries

    # Checksum: rotate-add over the DOS header up to 'DanS' (with e_lfanew
    # treated as zero), then over every @comp.id rotated by its count.
    checksum = dans
    for index in range(dans):
        if 0x3C <= index < 0x40:
            continue
        checksum = (checksum + _rol32(stub[index], index & 0x1F)) & 0xFFFFFFFF
    for entry in entries:
        comp_id = ((entry["product_id"] & 0xFFFF) << 16) | (entry["build_number"] & 0xFFFF)
        checksum = (checksum + _rol32(comp_id, entry["count"] & 0x1F)) & 0xFFFFFFFF
    result["checksum_valid"] = checksum == key
    result["_dans_offset"] = dans
    result["_marker_offset"] = marker
    if not result["checksum_valid"]:
        notes.append("Rich checksum recomputed as 0x%08x but the stored key is "
                     "0x%08x; the DOS stub or the block was modified after "
                     "linking" % (checksum, key))
    return result, notes


# --------------------------------------------------------------------------- #
# top-level analysis
# --------------------------------------------------------------------------- #

def analyze(path: str, *, want_digests: bool = True, want_entropy: bool = True,
            want_checksum: bool = True, want_file_digest: bool = True) -> dict:
    """Parse *path* and return the full document. Read-only, bounded, streaming."""
    with Image.open(path) as image:
        headers = PEHeaders(image)
        notes: list[str] = []

        sections, section_anomalies = build_sections(headers, want_digests,
                                                     want_entropy)
        overlay = compute_overlay(headers)
        directories = build_data_directories(headers)

        imports, import_notes = parse_imports(headers)
        notes.extend(import_notes)
        delay_imports, delay_notes, delay_detail = parse_delay_imports(headers)
        notes.extend(delay_notes)
        exports, export_summary, export_notes = parse_exports(headers)
        notes.extend(export_notes)
        tls, tls_detail, tls_notes = parse_tls(headers)
        notes.extend(tls_notes)
        debug_entries, pdb_path, debug_notes = parse_debug(headers)
        notes.extend(debug_notes)
        load_config, load_notes = parse_load_config(headers)
        notes.extend(load_notes)
        exception_data, exception_notes = parse_exception_data(headers)
        notes.extend(exception_notes)
        resources, version_info, resource_notes = parse_resources(headers)
        notes.extend(resource_notes)
        rich, rich_notes = parse_rich_header(headers)
        notes.extend(rich_notes)

        computed_checksum = compute_checksum(headers) if want_checksum else None
        file_sha256 = None
        if want_file_digest:
            digest = hashlib.sha256()
            for _position, chunk in image.iter_chunks(0, image.size):
                digest.update(chunk)
            file_sha256 = digest.hexdigest()

        reloc_rva, reloc_size = headers.directory(DIR_BASERELOC)
        security_rva, security_size = headers.directory(DIR_SECURITY)

        rich_public = {key: value for key, value in rich.items()
                       if not key.startswith("_")}
        imports_public = None
        if imports is not None:
            imports_public = [
                {key: value for key, value in module.items()
                 if not key.startswith("_")}
                for module in imports
            ]

        pe = {
            "characteristics": hexword(headers.characteristics, 4),
            "characteristics_flags": decode_flags(headers.characteristics,
                                                  CHARACTERISTICS_FLAGS),
            "checksum": headers.checksum,
            "checksum_valid": (None if computed_checksum is None
                               else computed_checksum == headers.checksum),
            "debug_directory": debug_entries,
            "delay_imports": delay_imports,
            "dll_characteristics": hexword(headers.dll_characteristics, 4),
            "entry_point": headers.entry_point,
            "exports": exports,
            "has_authenticode_signature": bool(security_rva and security_size),
            "has_reloc": bool(reloc_rva and reloc_size) or any(
                section["name"] == ".reloc" and section["rsize"]
                for section in headers.sections),
            "image_base": headers.image_base,
            "imports": imports_public,
            "machine": headers.machine,
            "machine_name": MACHINE_NAMES.get(headers.machine),
            "number_of_sections": headers.number_of_sections,
            "overlay_size": overlay["overlay_size"],
            "pdb_path_if_any": pdb_path,
            "pe_format": headers.pe_format,
            "rich_header": rich_public,
            "sections": sections,
            "size_of_image": headers.size_of_image,
            "subsystem": headers.subsystem,
            "subsystem_name": SUBSYSTEM_NAMES.get(headers.subsystem),
            "timestamp": headers.timestamp,
            "timestamp_utc": epoch_to_iso(headers.timestamp),
            "tls": tls,
            "version_info": version_info,
        }

        extended = {
            "base_of_code": headers.base_of_code,
            "base_of_data": headers.base_of_data,
            "checksum_computed": computed_checksum,
            "coff_header_offset": headers.e_lfanew + 4,
            "data_directories": directories,
            "delay_import_detail": delay_detail,
            "dll_characteristics_flags": decode_flags(headers.dll_characteristics,
                                                      DLL_CHARACTERISTICS_FLAGS),
            "e_lfanew": headers.e_lfanew,
            "exception_data": exception_data,
            "export_directory": export_summary,
            "file_alignment": headers.file_alignment,
            "linker_version": "%d.%d" % (headers.major_linker_version,
                                         headers.minor_linker_version),
            "load_config": load_config,
            "number_of_rva_and_sizes": headers.number_of_rva_and_sizes,
            "number_of_symbols": headers.number_of_symbols,
            "optional_header_magic": hexword(headers.magic, 4),
            "optional_header_offset": headers.optional_header_offset,
            "optional_header_size": headers.size_of_optional_header,
            "overlay": overlay,
            "parse_warnings": sorted(set(headers.warnings)),
            "parse_notes": notes,
            "pointer_to_symbol_table": headers.pointer_to_symbol_table,
            "resources": resources,
            "rich_header_offsets": {
                "dans_offset": rich.get("_dans_offset"),
                "marker_offset": rich.get("_marker_offset"),
            },
            "section_alignment": headers.section_alignment,
            "section_anomalies": section_anomalies,
            "section_table_offset": headers.section_table_offset,
            "security_directory": {"file_offset": security_rva,
                                   "size": security_size},
            "size_of_code": headers.size_of_code,
            "size_of_headers": headers.size_of_headers,
            "size_of_heap_commit": headers.size_of_heap_commit,
            "size_of_heap_reserve": headers.size_of_heap_reserve,
            "size_of_initialized_data": headers.size_of_initialized_data,
            "size_of_stack_commit": headers.size_of_stack_commit,
            "size_of_stack_reserve": headers.size_of_stack_reserve,
            "size_of_uninitialized_data": headers.size_of_uninitialized_data,
            "subsystem_version": "%d.%d" % (headers.major_subsystem_version,
                                            headers.minor_subsystem_version),
            "tls_detail": tls_detail,
            "win32_version_value": headers.win32_version_value,
        }

        return {
            "file": {
                "path": os.path.abspath(path),
                "name": os.path.basename(path),
                "size": image.size,
                "sha256": file_sha256,
            },
            "generated_at": now_iso_utc(),
            "generator": GENERATOR_NAME,
            "generator_version": GENERATOR_VERSION,
            "pe": pe,
            "pe_extended": extended,
        }


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def dump_json(document: dict) -> str:
    """Deterministic serialization: sorted keys, indent 2, LF, trailing newline."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def detect_install_root(path: str) -> str:
    """The installation the input file belongs to, for the output-path guard.

    Uses pathguard's own predicate so the answer is the same one the guard
    itself would reach. Falls back to the configured root, because
    ``check_output_path`` requires a non-empty root and refusing to run just
    because the input happens to live outside an installation would be
    backwards.
    """
    try:
        roots = pathguard.structural_install_roots(path)
    except (ValueError, OSError):
        roots = []
    if roots:
        return roots[-1]
    return pathguard.CONFIGURED_INSTALL_ROOTS[0]


def write_json(document: dict, out_path: str, install_root: str) -> str:
    """Write *document* to *out_path*, refusing any path inside an installation.

    The guard runs before the file is opened, so a refused path leaves nothing
    behind -- not even a truncated file.
    """
    target = pathguard.check_output_path(out_path, install_root, what="--out")
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dump_json(document))
    return target


def _fmt_int(value) -> str:
    return "-" if value is None else str(value)


def format_summary(document: dict, function_limit: int = 0) -> str:
    """The default human-readable report."""
    pe = document["pe"]
    ext = document["pe_extended"]
    out: list[str] = []
    add = out.append

    add("%s (%s %s)" % (document["file"]["path"], GENERATOR_NAME,
                        GENERATOR_VERSION))
    add("")
    add("COFF header")
    add("  machine            : 0x%04x  %s" % (pe["machine"],
                                               pe["machine_name"] or "unknown"))
    add("  sections           : %d" % pe["number_of_sections"])
    add("  TimeDateStamp      : %d  %s" % (pe["timestamp"],
                                           pe["timestamp_utc"] or
                                           "(not a plausible date -- may be a "
                                           "deterministic-build hash)"))
    add("  characteristics    : %s  %s" % (pe["characteristics"],
                                           " ".join(pe["characteristics_flags"] or [])))
    add("  symbol table       : ptr %d, %d symbols"
        % (ext["pointer_to_symbol_table"], ext["number_of_symbols"]))
    add("")
    add("Optional header")
    add("  magic              : %s (%s)" % (ext["optional_header_magic"],
                                            pe["pe_format"]))
    add("  linker version     : %s" % ext["linker_version"])
    add("  image base         : 0x%x" % pe["image_base"])
    add("  entry point        : 0x%x (RVA)" % pe["entry_point"])
    add("  section alignment  : 0x%x   file alignment: 0x%x"
        % (ext["section_alignment"], ext["file_alignment"]))
    add("  size of image      : %d" % pe["size_of_image"])
    add("  size of headers    : %d" % ext["size_of_headers"])
    add("  subsystem          : %d  %s" % (pe["subsystem"],
                                           pe["subsystem_name"] or "unknown"))
    add("  DllCharacteristics : %s  %s" % (pe["dll_characteristics"],
                                           " ".join(ext["dll_characteristics_flags"] or [])))
    add("  checksum stored    : 0x%08x" % pe["checksum"])
    add("  checksum computed  : %s  -> %s"
        % ("0x%08x" % ext["checksum_computed"] if ext["checksum_computed"] is not None
           else "not computed",
           "MATCH" if pe["checksum_valid"] else
           ("MISMATCH" if pe["checksum_valid"] is False else "not checked")))
    add("  overlay            : %d bytes after offset %d"
        % (ext["overlay"]["overlay_size"], ext["overlay"]["overlay_offset"]))
    add("")
    add("Sections (%d)" % len(pe["sections"]))
    add("  %-10s %-10s %-10s %-10s %-10s %-10s %s"
        % ("name", "vsize", "rva", "rsize", "raw_ptr", "charact.", "entropy"))
    for section in pe["sections"]:
        add("  %-10s %-10d %-10d %-10d %-10d %-10s %s"
            % (section["name"], section["vsize"], section["rva"],
               section["rsize"], section["raw_pointer"],
               section["characteristics"],
               "-" if section["entropy"] is None else "%.4f" % section["entropy"]))
    if ext["section_anomalies"]:
        add("  flagged:")
        for anomaly in ext["section_anomalies"]:
            for reason in anomaly["reasons"]:
                add("    %-10s %s" % (anomaly["name"], reason))
    else:
        add("  flagged: none")
    add("")
    add("Data directories")
    for entry in ext["data_directories"]:
        add("  %2d %-15s rva 0x%-9x size %-10s %s"
            % (entry["index"], entry["name"],
               entry["rva"] or 0, _fmt_int(entry["size"]),
               entry["note"] or ""))
    add("")
    imports = pe["imports"]
    if imports is None:
        add("Imports: NOT PARSED (see notes)")
    else:
        add("Imports (%d modules, %d symbols)"
            % (len(imports), sum(module["function_count"] for module in imports)))
        for module in imports:
            add("  %-32s %d" % (module["dll"], module["function_count"]))
            if function_limit:
                for function in module["functions"][:function_limit]:
                    add("      %s" % (function["name"] if function["name"]
                                      else "#%s (ordinal)" % function["ordinal"]))
                if len(module["functions"]) > function_limit:
                    add("      ... %d more"
                        % (len(module["functions"]) - function_limit))
    add("")
    delay = pe["delay_imports"]
    if delay is None:
        add("Delayed imports: NOT PARSED (see notes)")
    elif not delay:
        add("Delayed imports: none (DELAY_IMPORT directory absent or empty)")
    else:
        add("Delayed imports (%d modules, %d symbols)"
            % (len(delay), sum(module["function_count"] for module in delay)))
        for module in delay:
            add("  %-32s %d" % (module["dll"], module["function_count"]))
            if function_limit:
                for function in module["functions"][:function_limit]:
                    add("      %s" % (function["name"] if function["name"]
                                      else "#%s (ordinal)" % function["ordinal"]))
    add("")
    exports = pe["exports"]
    summary = ext["export_directory"]
    if exports is None:
        add("Exports: NOT PARSED (see notes)")
    elif not summary["present"]:
        add("Exports: none (EXPORT directory absent)")
    else:
        add("Exports: %d entries, dll name %r, ordinal base %s"
            % (len(exports), summary["dll_name"], summary["ordinal_base"]))
        for entry in exports[:function_limit or 20]:
            add("  #%-6d %-40s %s"
                % (entry["ordinal"], entry["name"] or "<by ordinal>",
                   "-> %s" % entry["forwarder"] if entry["forwarder"]
                   else "0x%x" % entry["address"]))
        if len(exports) > (function_limit or 20):
            add("  ... %d more" % (len(exports) - (function_limit or 20)))
    add("")
    tls = pe["tls"]
    add("TLS directory")
    if not tls["present"]:
        add("  absent")
    else:
        add("  address_of_index   : 0x%x (virtual address as stored)"
            % (tls["address_of_index"] or 0))
        add("  callback array     : 0x%x (VA)"
            % (ext["tls_detail"]["address_of_callbacks_va"] or 0))
        add("  callback count     : %s" % _fmt_int(tls["callback_count"]))
        for index, address in enumerate(tls["callbacks"] or []):
            rvas = ext["tls_detail"]["callback_rvas"] or []
            rva = rvas[index] if index < len(rvas) else None
            add("    [%d] VA 0x%x   RVA 0x%x" % (index, address, rva or 0))
    add("")
    add("Debug directory")
    if not pe["debug_directory"]:
        add("  absent or empty")
    for entry in pe["debug_directory"] or []:
        add("  type %-3d %-32s size %-8d ptr %d"
            % (entry["type"], entry["type_name"] or "unknown", entry["size"],
               entry["pointer_to_raw_data"]))
        if entry["pdb_path"]:
            add("      cv %s  age %s  guid %s"
                % (entry["cv_signature"], entry["pdb_age"], entry["pdb_guid"]))
            add("      pdb %s" % entry["pdb_path"])
    add("")
    add("Load configuration")
    load = ext["load_config"]
    if load is None:
        add("  absent")
    else:
        add("  declared size      : %d" % load["declared_size"])
        add("  security cookie    : %s"
            % ("0x%x" % load["security_cookie"] if load["security_cookie"] else "none"))
        add("  SEH table / count  : %s / %s"
            % (_fmt_int(load["se_handler_table"]), _fmt_int(load["se_handler_count"])))
        add("  GuardFlags         : %s  %s"
            % (load["guard_flags"], " ".join(load["guard_flags_decoded"] or [])))
        add("  CFG check fn ptr   : %s"
            % ("0x%x" % load["guard_cf_check_function_pointer"]
               if load["guard_cf_check_function_pointer"] else "none"))
        add("  CFG function table : %s, %s entries"
            % ("0x%x" % load["guard_cf_function_table"]
               if load["guard_cf_function_table"] else "none",
               _fmt_int(load["guard_cf_function_count"])))
        add("  CFG in DllCharact. : %s" % load["cfg_marked_in_dll_characteristics"])
    add("")
    exception_data = ext["exception_data"]
    add("Exception data (.pdata / RUNTIME_FUNCTION)")
    add("  directory          : rva 0x%x size %d"
        % (exception_data["directory_rva"], exception_data["directory_size"]))
    add("  function count     : %s" % _fmt_int(exception_data["function_count"]))
    for row in exception_data["sample"]:
        add("    [%d] begin 0x%x end 0x%x unwind 0x%x"
            % (row["index"], row["begin_address"], row["end_address"],
               row["unwind_info_address"]))
    add("")
    resources = ext["resources"]
    add("Resources")
    add("  directory          : rva 0x%x size %s"
        % (resources["directory_rva"] or 0, _fmt_int(resources["directory_size"])))
    add("  diagnosis          : %s" % resources["diagnosis"])
    add("  data entries       : %d" % resources["data_entry_count"])
    for record in resources["types"]:
        add("    type %-6s %-16s %d entries"
            % (record["id"] if record["id"] is not None else record["name"],
               record["type_name"] or "", record["count"]))
    version_info = pe["version_info"]
    if version_info is None:
        add("  VS_VERSIONINFO     : NOT FOUND")
    else:
        fixed = version_info["fixed"]
        add("  VS_VERSIONINFO     : present")
        if fixed:
            add("    FileVersion      : %s" % fixed["file_version"])
            add("    ProductVersion   : %s" % fixed["product_version"])
            add("    FileFlags        : %s  FileOS %s  FileType %s  Subtype %s"
                % (fixed["file_flags"], fixed["file_os"], fixed["file_type"],
                   fixed["file_subtype"]))
        else:
            add("    fixed block      : absent")
        if version_info["strings"]:
            for key in sorted(version_info["strings"]):
                add("    %-16s : %s" % (key, version_info["strings"][key]))
        else:
            add("    StringFileInfo   : empty")
        add("    translations     : %s"
            % (", ".join(version_info["translations"] or []) or "none"))
    add("")
    rich = pe["rich_header"]
    add("Rich header")
    if not rich["present"]:
        add("  absent")
    else:
        add("  xor key            : %s   checksum %s"
            % (rich["xor_key"],
               "valid" if rich["checksum_valid"] else "INVALID"))
        add("  raw sha256         : %s" % rich["raw_sha256"])
        add("  offsets            : DanS %s .. 'Rich' %s"
            % (ext["rich_header_offsets"]["dans_offset"],
               ext["rich_header_offsets"]["marker_offset"]))
        for entry in rich["entries"] or []:
            add("    prod 0x%04x %-22s build %-6d count %d"
                % (entry["product_id"], entry["product_name"] or "unknown",
                   entry["build_number"], entry["count"]))
    if ext["parse_warnings"] or ext["parse_notes"]:
        add("")
        add("Parser notes")
        for line in ext["parse_warnings"]:
            add("  WARNING: %s" % line)
        for line in ext["parse_notes"]:
            add("  note: %s" % line)
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pe_info.py",
        description=(
            "Read-only PE parser (plan.md task F-01). Prints a human summary by "
            "default; --json prints the machine-readable document. Refuses any "
            "--out path that resolves inside a game installation (D-01)."
        ),
    )
    parser.add_argument("path", help="the PE image to read (opened read-only)")
    parser.add_argument("--json", action="store_true",
                        help="print the JSON document instead of the summary")
    parser.add_argument("--out", default=None,
                        help=("write the JSON document to this path; refused "
                              "(exit 2) if it resolves inside a game "
                              "installation, before anything is opened"))
    parser.add_argument("--install-dir", default=None,
                        help=("installation root the --out guard checks against "
                              "(default: auto-detected from the input path)"))
    parser.add_argument("--functions", type=int, default=0, metavar="N",
                        help=("list up to N imported/exported symbols per module "
                              "in the human summary (default: counts only)"))
    parser.add_argument("--no-digests", action="store_true",
                        help="skip per-section sha256 and the whole-file sha256")
    parser.add_argument("--no-entropy", action="store_true",
                        help="skip per-section entropy (the slow part on big images)")
    parser.add_argument("--no-checksum", action="store_true",
                        help="skip recomputing the image checksum")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not os.path.isfile(args.path):
        print("error: not a file: %s" % args.path, file=sys.stderr)
        return 2

    install_root = args.install_dir or detect_install_root(args.path)

    # Layer 1 (plan.md 1.5 / D-01) is checked before any parsing so a refused
    # path costs nothing and leaves nothing behind. write_json checks again.
    out_path = None
    if args.out:
        try:
            out_path = pathguard.check_output_path(args.out, install_root,
                                                   what="--out")
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2

    try:
        document = analyze(
            args.path,
            want_digests=not args.no_digests,
            want_entropy=not args.no_entropy and not args.no_digests,
            want_checksum=not args.no_checksum,
            want_file_digest=not args.no_digests,
        )
    except PEFormatError as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2
    except OSError as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2

    if out_path:
        try:
            write_json(document, out_path, install_root)
        except pathguard.OutputPathRefused as error:
            print("error: %s" % error, file=sys.stderr)
            return 2
        except OSError as error:
            print("error: cannot write %s: %s" % (out_path, error), file=sys.stderr)
            return 2

    if args.json:
        sys.stdout.write(dump_json(document))
    else:
        print(format_summary(document, function_limit=args.functions))
        if out_path:
            print("\nwritten: %s" % out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
