#!/usr/bin/env python3
"""Read-only reader for the UE 5.4 pak index: entry flags, and the path list.

The question this tool exists to answer
---------------------------------------
``research/unknowns.md`` CK-01 asks whether the shipped build uses unversioned
property serialization in cooked packages, and the honest way to answer it is to
read a cooked package out of the shipped image rather than to infer it. That put
one question in front of it: is anything in ``MISERY-Windows.pak`` *readable at
all*? Decision D-02 forbids extracting the container encryption key and forbids
decrypting the main container, so a payload may be read only after it has been
PROVEN to be plaintext. The pak footer says the *index* is unencrypted
(``bEncryptedIndex == 0``, ``EncryptionKeyGuid`` all zero), but per-entry
encryption is a **separate flag on each entry** and the footer says nothing
whatever about it.

So this tool answers, in this order:

1. Are the index blobs themselves plaintext? (Proven, not assumed -- see
   *Proving a datum is unencrypted* below.)
2. Per entry: is ``FPakEntry::Flag_Encrypted`` set? Counted, both ways.
3. What paths does the index name, and what are they? (Extension histogram,
   directory tree shape.)
4. Is any cooked asset -- ``.uasset``, ``.uexp``, ``.umap``, ``.usmap`` -- in
   there, and is it plaintext and uncompressed enough to read a header from?

Only after step 2 says an entry is plaintext may its payload be read, and this
tool will not read a payload from an entry whose flag says otherwise. That is
D-02 executed rather than promised: see ``PAYLOAD_POLICY``.

Where the layout comes from, field by field
-------------------------------------------
The authoritative definition is the first-party UE 5.4.4 source tree on this
machine at the SAME changelist the shipped image was built from (35576357,
``++UE5+Release-5.4``; see ``research/unreal/engine-version.json``). Every mask
and every field below carries a file-and-line citation into it. Nothing here is
remembered, and nothing here is guessed -- the previous attempt at this decode
used remembered mask constants and produced an entry claiming compression method
32 and encrypted true, which is precisely the class of error the citations exist
to prevent.

``Engine/Source/Runtime/PakFile/Public/IPlatformFilePak.h`` (header, ``H``) and
``Engine/Source/Runtime/PakFile/Private/IPlatformFilePak.cpp`` (``C``):

    H:381-383    FPakEntry::Flag_None 0x00, Flag_Encrypted 0x01, Flag_Deleted 0x02
    H:563        IsEncrypted() == GetFlag(Flag_Encrypted)
    H:558-561    GetFlag(f) == ((Flags & f) == f)
    H:417-444    FPakEntry::GetSerializedSize -- the LOCAL header size
    H:495-544    FPakEntry::Serialize -- the LOCAL header field order
    H:139-155    FPakInfo version ladder; 11 == PakFile_Version_Fnv64BugFix
    H:583-671    FPakEntryLocation: 0..MaxIndex is a byte offset into the encoded
                 blob, negative is an index into the unencodable Files array,
                 MIN_int32 is invalid
    H:711        FPakDirectory == TMap<FString, FPakEntryLocation>
    H:729        FDirectoryIndex == TMap<FString, FPakDirectory>
    C:6087-6202  FPakFile::LoadIndexInternal -- primary index field order
    C:6489-6500  FPakFile::DecryptAndValidateIndex -- decrypt iff bEncryptedIndex,
                 then SHA1 the buffer and compare with the stored hash
    C:6952-7090  FPakFile::EncodePakEntry -- the writer, i.e. what the bits mean
    C:7092-7227  FPakFile::DecodePakEntry -- the reader this module mirrors

The bitfield, quoting the comment at C:7094-7101 and the assembly at C:7023-7031::

    bit  31      Offset is 32-bit safe            (C:7125)
    bit  30      UncompressedSize is 32-bit safe  (C:7138)
    bit  29      Size is 32-bit safe              (C:7154)
    bits 28..23  CompressionMethodIndex, (Value >> 23) & 0x3f   (C:7118)
    bit  22      Encrypted, (Value & (1 << 22)) != 0            (C:7174)
    bits 21..6   CompressionBlocks count, (Value >> 6) & 0xffff (C:7178)
    bits  5..0   CompressionBlockSize, packed                   (C:7106-7114)

Two asymmetries in that layout are easy to get wrong and are called out because
getting them wrong silently shifts every following field:

* ``Size`` is present **only when CompressionMethodIndex != 0** (C:7151); for an
  uncompressed entry Size is defined to equal UncompressedSize (C:7170).
* the per-block size array is written only when there is more than one block, or
  when there is exactly one block AND the entry is encrypted (C:7079, mirrored by
  the branch at C:7201/7209). One unencrypted block stores nothing and is derived.

The two secondary index blobs and the encoded entry blob are ordinary
``FArchive`` serializations, so three more layouts are needed, and they are also
cited rather than remembered:

    FString                Core/Private/Containers/String.cpp.inl:1763-1847
                           int32 count; count > 0 -> ANSI, count < 0 -> UTF-16LE
                           with -count units; the count INCLUDES the NUL
    TMap<K,V>              Core/Public/Containers/Map.h:1937-1941 -> Set.h:2199
                           -> SparseArray.h:1483-1507: int32 count, then count
                           elements; Set.h:2244-2247 serializes only the pair, and
                           Tuple.h:446-450 serializes Key then Value
    TArray<uint8>          int32 count, then count bytes

Proving a datum is unencrypted (D-02, and the reason this tool is allowed to run)
---------------------------------------------------------------------------------
"The footer says the index is not encrypted" is a *claim by the file about
itself*. It is not proof, and D-02 asks for proof. The proof used here is the one
the engine itself uses at C:6489-6500: ``DecryptAndValidateIndex`` decrypts the
buffer **only if** ``bEncryptedIndex``, and then requires
``SHA1(buffer) == StoredHash``. So if the raw bytes on disk hash to the stored
hash, then the bytes the engine parses are byte-for-byte the bytes we just read,
with no decryption step in between -- otherwise the engine's own load would fail.
That is a positive, falsifiable test with a 160-bit failure margin, and it is run
for all three index blobs (primary, path-hash, full directory) before a single
byte of any of them is interpreted. See ``prove_index_plaintext``.

The same argument does NOT extend to payloads, and this module never pretends it
does: payload bytes have no stored hash we can check without reading them, and
per-entry encryption is a per-entry fact. Hence ``PAYLOAD_POLICY``.

Refutation probes (plan.md 10.3, class-I criterion: try to break the headline)
-----------------------------------------------------------------------------
The headline finding of this tool is a *negative* one -- "every entry is
encrypted, therefore nothing in this container is readable" -- and a negative
finding reached from one bit in one place is exactly the kind that a mask error
fabricates. Three probes run on every invocation, each capable of refuting it:

``entry_flag_word_census``
    Every distinct 32-bit flag word, with its count and its full decomposition.
    A mask error is invisible in a summary and obvious in a census: if the
    encrypted bit were actually the low bit of a wider compression-method field,
    the census would show method values that no ``CompressionMethods`` slot in
    the footer names.

``local_header_probe``
    The LOCAL ``FPakEntry`` header, written at each payload offset by
    ``FPakEntry::Serialize`` (H:495-544; written plaintext by the packer at
    ``Developer/PakFileUtilities/Private/PakFileUtilities.cpp``:2736, where
    encryption is applied to the data buffer only, at :1057 and :1109). It
    carries an INDEPENDENT copy of the same ``Flags`` byte, produced by a
    different serializer and stored at a different place in the file. If the
    index bitfield decode were wrong, the byte at header+48 would disagree. The
    header is metadata, not payload, and it is proven plaintext in its own right
    by the agreement of its Size and UncompressedSize with the index.

``layout_probe``
    A packed-layout test with no reference to any flag at all. An encrypted
    uncompressed entry occupies ``Align(Size, 16)`` bytes on disk while its Size
    field records the plaintext length (PakFileUtilities.cpp:1028, 1044-1060;
    ``FAES::AESBlockSize`` is 16); an unencrypted one occupies exactly ``Size``.
    So the two hypotheses predict two different files. The probe counts, over
    consecutive entries in offset order, how many gaps the padded model explains
    and how many the unpadded model explains, counts any case where the padded
    model would *overlap* the next entry (which would refute it outright), and
    checks where the last payload ends against the start of the index.

Two output layers, never merged (plan.md 10.3)
----------------------------------------------
``literal_reads``
    Class **P**. One record per read: target, file offset, length, raw bytes, and
    a ``claim`` sentence that states the offset and the length and stops there --
    it names no field, no layout and no type, which is what plan.md 10.3 v2.4
    requires of the ``container-metadata`` oracle for class P to apply at all.
    Every range is read a SECOND time through a freshly opened handle before the
    record may say it reproduced. The sample is bounded and deterministic
    (``--literal-samples``): 4424 entries times four reads is a log, not evidence.
    The ``target`` is the INSTALL-RELATIVE path, never a basename.

``index`` / ``entries`` / ``probes`` / ``summary``
    Class **I**. These name fields, apply masks, decode strings and count things.
    Every one of those steps rests on the engine source, which is the
    ``external-doc`` oracle, so the whole layer is class I whatever the offsets
    are, and it is capped below the literal layer.

C-13: what may and may not leave the installation
-------------------------------------------------
Paths, counts, sizes and hashes are findings and are emitted. Payload bytes are
game content and are not, at any size, in any encoding. The literal layer holds
only index and footer and local-header bytes -- structure, not content -- and
even those are capped by ``--literal-samples``.

Memory (plan.md F-04)
---------------------
The three index blobs are read whole; they are 53 KB, 131 KB and 101 KB, and
their sizes are checked against the file size before allocation. Payload data is
never read. Every count taken from the file is clamped before it becomes a loop
bound.

Determinism
-----------
Sorted keys, indent 2, LF, UTF-8 without BOM, trailing newline. Paths are emitted
in ascending index order in ``--paths-out`` and sorted in the histograms. Two
runs over an unchanged file differ only in ``generated_at``.

Standard library only.

CLI
---
    python tools/content/pak_index.py <file.pak>
    python tools/content/pak_index.py <file.pak> --json
    python tools/content/pak_index.py <file.pak> --out research/.../pak-index.json \\
                                                 --paths-out research/.../pak-paths.txt

Exit codes: 0 the read completed (whatever the verdict), 2 usage / I/O error /
unparseable input. "Everything is encrypted" is a successful run, not a failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import struct
import sys
from collections import Counter
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
for _extra in (os.path.join(_TOOLS, "inventory"), os.path.join(_TOOLS, "fingerprint")):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never
# reimplemented: pathguard is the single place where "is this path inside the
# game installation" is decided.
import pathguard  # noqa: E402  (sys.path is prepared just above)

# The footer belongs to F-02. Re-deriving the footer location and the
# version-dependent field offsets here would give this tool a second,
# differently-buggy opinion about where the index is, and the whole point of the
# wave-1 parser is that there is one. What this module adds is everything BEYOND
# the footer: the index blobs and the encoded entries.
import container_info  # noqa: E402

GENERATOR_NAME = "tools/content/pak_index.py"
GENERATOR_VERSION = "1.0.0"

ContainerParseError = container_info.ContainerParseError
hex_bytes = container_info.hex_bytes

# The engine source tree the field citations point into. Recorded in the output so
# a reader can check the citations against the same text this run used, and so a
# run against a DIFFERENT engine tree is visible rather than silent.
ENGINE_SOURCE_RELPATHS = (
    "Engine/Source/Runtime/PakFile/Public/IPlatformFilePak.h",
    "Engine/Source/Runtime/PakFile/Private/IPlatformFilePak.cpp",
)

PAYLOAD_POLICY = (
    "D-02. A payload is read only from an entry whose Flag_Encrypted bit "
    "(IPlatformFilePak.h:382, read per IPlatformFilePak.cpp:7174) is CLEAR. No key "
    "is derived, searched for or used, and no decryption is attempted. When every "
    "entry is encrypted this tool reads no payload at all and reports that as the "
    "finding."
)


# --------------------------------------------------------------------------- #
# hard limits. Each one bounds a number that comes from a file and must
# therefore never be believed.
# --------------------------------------------------------------------------- #

MAX_INDEX_BYTES = 64 << 20        # a pak index is tens of KB; 64 MB is absurd
MAX_DIRECTORIES = 1 << 20         # FDirectoryIndex entry count clamp
MAX_FILES_PER_DIR = 1 << 20       # FPakDirectory entry count clamp
MAX_FSTRING_UNITS = 65535         # C:6139 sanity-checks MountPoint at 65535; the
                                  # same bound is applied to every FString here
MAX_ENTRIES = 1 << 22            # NumEntries clamp
MAX_COMPRESSION_BLOCKS = 1 << 16  # C:6969 -- the writer refuses >= 1 << 16

DEFAULT_LITERAL_SAMPLES = 24

# FPakInfo version ladder, H:139-155. Only the two gates this module needs.
PAK_VERSION_FNAME_BASED_COMPRESSION = 8   # H:146
PAK_VERSION_PATH_HASH_INDEX = 10          # H:148

# FAES::AESBlockSize. Used by the layout probe only, never to decrypt anything.
AES_BLOCK_SIZE = 16

# FSHAHash is 20 raw bytes (H:166 stores one inline; C:6163, C:6176 read them).
SHA_HASH_BYTES = 20

# Confidence bands. The literal layer is a read; the decoded layer is a decode
# resting on external-doc, and is capped below it (plan.md 10.3).
CONFIDENCE_LITERAL = 0.99
CONFIDENCE_DECODED = 0.90

RERUN_CONFIRMED = ("Reproduction: the same range was read a second time through an "
                   "independently opened handle and gave the same bytes.")
RERUN_NOT_CONFIRMED = ("Reproduction: FAILED -- the second read did not agree. This "
                       "reading is NOT confirmed.")

# Cooked-package extensions. The question in CK-01 is about cooked packages, so
# "is there a cooked asset in here" has to be asked of a named set rather than of
# an impression. .usmap is not a cooked package but is the property-name mapping
# that would answer CK-01 outright, so it is in the set.
COOKED_EXTENSIONS = (".uasset", ".uexp", ".umap", ".ubulk", ".uptnl", ".usmap",
                     ".ushaderbytecode", ".utoc", ".ucas")


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def align_up(value: int, alignment: int) -> int:
    """Align(), as the engine's Align() template does it. Used by the layout probe."""
    if alignment <= 0:
        return value
    return ((value + alignment - 1) // alignment) * alignment


def locus_target(path: str, install_root: str | None) -> str:
    """The install-relative path of *path*, or its basename if it is outside one.

    A class-P claim must name a determinate location, and a basename is an
    ambiguity class -- this installation holds more than one file with the same
    basename in different trees. Mirrors tools/static/rtti_scan.py.
    """
    if install_root:
        try:
            relative = os.path.relpath(os.path.abspath(path), os.path.abspath(install_root))
        except ValueError:
            relative = ""
        if relative and not relative.startswith(".."):
            return relative.replace(os.sep, "/")
    return os.path.basename(path)


# --------------------------------------------------------------------------- #
# FArchive reader. Every read is bounded and every count is clamped, because
# every number here came out of a file.
# --------------------------------------------------------------------------- #

class ArchiveReader:
    """A bounded little-endian reader over one in-memory index blob.

    Mirrors the subset of FArchive loading that the pak index uses. It refuses to
    read past the end of the buffer instead of returning short data, so a
    truncated or misread blob fails loudly at the point of the error rather than
    producing plausible nonsense further down.
    """

    def __init__(self, data: bytes, what: str) -> None:
        self.data = data
        self.what = what
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def _take(self, count: int) -> bytes:
        if count < 0 or count > self.remaining():
            raise ContainerParseError(
                "%s: wanted %d bytes at offset %d but only %d remain"
                % (self.what, count, self.pos, self.remaining()))
        chunk = self.data[self.pos:self.pos + count]
        self.pos += count
        return chunk

    def scalar(self, fmt: str) -> int:
        return struct.unpack("<" + fmt, self._take(struct.calcsize("<" + fmt)))[0]

    def int32(self) -> int:
        return self.scalar("i")

    def uint32(self) -> int:
        return self.scalar("I")

    def int64(self) -> int:
        return self.scalar("q")

    def uint64(self) -> int:
        return self.scalar("Q")

    def bool32(self) -> bool:
        """FArchive serializes bool as int32 (C:6158, C:6171 read `bool` members)."""
        value = self.int32()
        if value not in (0, 1):
            raise ContainerParseError(
                "%s: bool at offset %d is %d, not 0 or 1" % (self.what, self.pos - 4, value))
        return bool(value)

    def sha_hash(self) -> bytes:
        return self._take(SHA_HASH_BYTES)

    def fstring(self) -> str:
        """FString, per Core/Private/Containers/String.cpp.inl:1763-1847.

        int32 count. Positive means `count` ANSI chars, negative means `-count`
        UTF-16LE code units; either way the count INCLUDES the terminating NUL,
        which is why the result is stripped of a single trailing NUL rather than
        of all of them -- a path with an embedded NUL is corruption and must not
        be silently tidied into something that looks fine.
        """
        start = self.pos
        count = self.int32()
        if count == 0:
            return ""
        wide = count < 0
        units = -count if wide else count
        if units > MAX_FSTRING_UNITS:
            raise ContainerParseError(
                "%s: FString at offset %d claims %d units, over the %d clamp"
                % (self.what, start, units, MAX_FSTRING_UNITS))
        raw = self._take(units * (2 if wide else 1))
        if wide:
            text = raw.decode("utf-16-le", errors="strict")
        else:
            # ANSI here is a byte-per-char encoding with no failure mode; latin-1
            # is the faithful choice because it round-trips every byte. Guessing
            # UTF-8 would silently mangle any non-ASCII path and could also raise
            # on valid data.
            text = raw.decode("latin-1")
        if text.endswith("\x00"):
            text = text[:-1]
        if "\x00" in text:
            raise ContainerParseError(
                "%s: FString at offset %d contains an embedded NUL" % (self.what, start))
        return text


# --------------------------------------------------------------------------- #
# footer, and the plaintext proof
# --------------------------------------------------------------------------- #

def read_footer(handle, file_size: int) -> dict:
    """Locate and decode the footer through F-02's parser, then return its fields.

    The footer's own location and field offsets come from container_info so that
    there is exactly one opinion in the repository about where a pak footer is.
    """
    version, offset, size, raw = container_info.locate_pak_footer(handle, file_size)
    fields = container_info.pak_footer_field_offsets(version)
    spans = {name: (rel, length) for name, rel, length in fields}

    def span(name: str) -> bytes:
        rel, length = spans[name]
        return raw[rel:rel + length]

    warnings: list[str] = []
    methods = []
    if version >= PAK_VERSION_FNAME_BASED_COMPRESSION:
        methods = container_info.split_method_name_table(
            span("compression_methods"),
            container_info.PAK_MAX_NUM_COMPRESSION_METHODS,
            container_info.PAK_COMPRESSION_METHOD_NAME_LEN,
            warnings, "pak footer", "pak compression method")

    return {
        "version": version,
        "footer_offset": offset,
        "footer_size": size,
        "footer_bytes": raw,
        "field_spans": spans,
        "magic": "0x%08x" % struct.unpack("<I", span("magic"))[0],
        "index_offset": struct.unpack("<q", span("index_offset"))[0],
        "index_size": struct.unpack("<q", span("index_size"))[0],
        "index_hash": span("index_hash"),
        "encrypted_index": bool(span("encrypted_index")[0]),
        "encryption_key_guid": container_info.guid_from_bytes(span("encryption_key_guid")),
        # CompressionMethods[0] is NAME_None and is never serialized (H:184-185,
        # H:295-299), so index 0 in an entry always means "uncompressed" and the
        # names below are indices 1..N.
        "compression_methods": methods,
        "warnings": warnings,
    }


def read_blob(handle, offset: int, size: int, file_size: int, what: str) -> bytes:
    """Read one index blob, bounds-checked exactly as C:6096-6104 checks it."""
    if offset < 0 or size < 0 or offset + size > file_size:
        raise ContainerParseError(
            "%s: claimed range %d+%d does not fit in a %d-byte file"
            % (what, offset, size, file_size))
    if size > MAX_INDEX_BYTES:
        raise ContainerParseError(
            "%s: claimed size %d is over the %d clamp" % (what, size, MAX_INDEX_BYTES))
    handle.seek(offset)
    data = handle.read(size)
    if len(data) != size:
        raise ContainerParseError(
            "%s: short read, wanted %d bytes at %d and got %d" % (what, size, offset, len(data)))
    return data


def prove_index_plaintext(name: str, data: bytes, stored_hash: bytes,
                          encrypted_index_flag: bool) -> dict:
    """The D-02 proof that this blob is plaintext, or the record that it is not.

    The engine's own loader is the oracle here: DecryptAndValidateIndex
    (C:6489-6500) decrypts the buffer if and only if ``Info.bEncryptedIndex``, and
    then requires ``SHA1(buffer) == StoredHash``. Therefore, when the flag is
    clear and the raw bytes on disk hash to the stored hash, the bytes the engine
    parses are the bytes we read, with no decryption in between -- otherwise the
    engine's own load of this file would fail. The margin is 160 bits.

    Returns a record; it never raises. A blob that fails this test is reported as
    unproven and its interpretation is refused by the caller.
    """
    computed = hashlib.sha1(data).digest()
    matches = computed == stored_hash
    proven = matches and not encrypted_index_flag
    if proven:
        verdict = "PLAINTEXT_PROVEN"
        reasoning = (
            "bEncryptedIndex is 0 and SHA1 over the %d bytes as they sit on disk "
            "equals the hash stored for this blob, so DecryptAndValidateIndex "
            "(IPlatformFilePak.cpp:6489-6500) would take its no-decrypt path and "
            "accept exactly these bytes. Reading them is therefore reading "
            "plaintext, not decrypting." % len(data))
    elif matches and encrypted_index_flag:
        # Would be a contradiction: the flag says the engine decrypts before
        # hashing, so raw bytes should not match. Reported, never reconciled.
        verdict = "CONTRADICTORY"
        reasoning = ("bEncryptedIndex is 1 yet the raw bytes already hash to the "
                     "stored hash. The footer flag and the hash disagree; nothing "
                     "is inferred from this and the blob is not interpreted.")
    else:
        verdict = "NOT_PROVEN"
        reasoning = ("SHA1 over the raw bytes does not equal the stored hash, so "
                     "these bytes are not the bytes the engine parses. Under D-02 "
                     "no attempt is made to find out why.")
    return {
        "blob": name,
        "length": len(data),
        "stored_sha1": stored_hash.hex(),
        "computed_sha1_of_raw_bytes": computed.hex(),
        "sha1_matches_raw_bytes": matches,
        "footer_encrypted_index_flag": encrypted_index_flag,
        "verdict": verdict,
        "reasoning": reasoning,
    }


# --------------------------------------------------------------------------- #
# primary index
# --------------------------------------------------------------------------- #

def parse_primary_index(data: bytes, version: int) -> dict:
    """Decode the primary index, mirroring FPakFile::LoadIndexInternal C:6131-6202.

    Field order, and the version gates, exactly as the engine reads them:
    FString MountPoint (C:6135), int32 NumEntries (C:6146), and from version 10
    onwards uint64 PathHashSeed (C:6152), a bool + (int64,int64,FSHAHash) block for
    the path-hash index (C:6158-6165), the same for the full directory index
    (C:6171-6178), TArray<uint8> EncodedPakEntries (C:6181), int32 FilesNum
    (C:6185) and then FilesNum unencodable FPakEntry records (C:6198-6201).
    """
    reader = ArchiveReader(data, "primary index")
    mount_point = reader.fstring()
    num_entries = reader.int32()
    if num_entries < 0 or num_entries > MAX_ENTRIES:
        raise ContainerParseError("primary index: NumEntries is %d" % num_entries)

    result: dict = {
        "mount_point": mount_point,
        "num_entries": num_entries,
        "path_hash_seed": None,
        "path_hash_index": None,
        "full_directory_index": None,
        "encoded_entries_length": None,
        "unencodable_files_count": None,
        "bytes_consumed": None,
        "bytes_available": len(data),
    }

    if version >= PAK_VERSION_PATH_HASH_INDEX:
        result["path_hash_seed"] = "0x%016x" % reader.uint64()
        for key in ("path_hash_index", "full_directory_index"):
            if reader.bool32():
                block_offset = reader.int64()
                block_size = reader.int64()
                block_hash = reader.sha_hash()
                result[key] = {
                    "offset": block_offset,
                    "size": block_size,
                    "sha1": block_hash.hex(),
                    "_sha1_raw": block_hash,
                }

    encoded_length = reader.int32()
    if encoded_length < 0 or encoded_length > MAX_INDEX_BYTES:
        raise ContainerParseError(
            "primary index: EncodedPakEntries length is %d" % encoded_length)
    encoded = reader._take(encoded_length)  # noqa: SLF001 -- same module
    result["encoded_entries_length"] = encoded_length
    result["_encoded"] = encoded

    files_num = reader.int32()
    if files_num < 0 or files_num > MAX_ENTRIES:
        raise ContainerParseError("primary index: FilesNum is %d" % files_num)
    result["unencodable_files_count"] = files_num

    # The unencodable FPakEntry array (C:6198-6201) is not decoded here: this pak
    # has none, and a decoder for a shape no shipped file exercises would be
    # untested code claiming to have been verified. If a future target has any,
    # this is where it fails loudly instead of quietly skipping them.
    if files_num:
        raise ContainerParseError(
            "primary index: %d unencodable FPakEntry records are present and this "
            "reader does not decode them (FPakEntry::Serialize, "
            "IPlatformFilePak.h:495-544). Refusing to report a partial entry set."
            % files_num)

    result["bytes_consumed"] = reader.pos
    result["fully_consumed"] = reader.pos == len(data)
    return result


# --------------------------------------------------------------------------- #
# full directory index
# --------------------------------------------------------------------------- #

def parse_directory_index(data: bytes) -> tuple[list[tuple[str, list[tuple[str, int]]]], dict]:
    """Decode an FDirectoryIndex blob: TMap<FString, TMap<FString, int32>>.

    H:729 gives FDirectoryIndex == TMap<FString, FPakDirectory> and H:711 gives
    FPakDirectory == TMap<FString, FPakEntryLocation>; FPakEntryLocation
    serializes as a bare int32 (H:656-659). The TMap wire form is int32 count then
    that many Key/Value pairs -- Map.h:1937-1941 forwards to the set, Set.h:2199
    forwards to the sparse array, SparseArray.h:1483-1507 writes the count and the
    elements, Set.h:2244-2247 serializes only the pair's value half, and
    Tuple.h:446-450 writes Key before Value. The hash table itself is not on the
    wire; it is rebuilt on load (Set.h:2204-2212), which is why a reader does not
    need to know anything about the hashing.

    Returns (directories, stats). The directory order is the on-wire order and is
    preserved, because it is the only stable identity a directory record has.
    """
    reader = ArchiveReader(data, "full directory index")
    dir_count = reader.int32()
    if dir_count < 0 or dir_count > MAX_DIRECTORIES:
        raise ContainerParseError("directory index: directory count is %d" % dir_count)

    directories: list[tuple[str, list[tuple[str, int]]]] = []
    for _ in range(dir_count):
        dir_name = reader.fstring()
        file_count = reader.int32()
        if file_count < 0 or file_count > MAX_FILES_PER_DIR:
            raise ContainerParseError(
                "directory index: file count %d in directory %r" % (file_count, dir_name))
        files: list[tuple[str, int]] = []
        for _ in range(file_count):
            file_name = reader.fstring()
            location = reader.int32()
            files.append((file_name, location))
        directories.append((dir_name, files))

    stats = {
        "directory_count": dir_count,
        "file_count": sum(len(files) for _, files in directories),
        "bytes_consumed": reader.pos,
        "bytes_available": len(data),
        # A TMap serialization that does not consume its blob exactly is a decode
        # error even when every field looked sane, so the closure is reported as a
        # first-class result rather than checked and forgotten.
        "fully_consumed": reader.pos == len(data),
    }
    return directories, stats


# --------------------------------------------------------------------------- #
# the encoded entry bitfield -- FPakFile::DecodePakEntry, C:7092-7227
# --------------------------------------------------------------------------- #

class PakEntryLocation:
    """FPakEntryLocation semantics, H:583-654.

    0 .. MAX_int32-1  a byte offset into EncodedPakEntries
    MIN_int32         invalid
    negative          -(ListIndex) - 1, an index into the unencodable Files array
    """

    MIN_INT32 = -(1 << 31)
    MAX_INDEX = (1 << 31) - 2

    @staticmethod
    def classify(value: int) -> tuple[str, int]:
        if 0 <= value <= PakEntryLocation.MAX_INDEX:
            return "encoded_offset", value
        if value <= PakEntryLocation.MIN_INT32 or value > PakEntryLocation.MAX_INDEX:
            return "invalid", -1
        return "list_index", -(value + 1)


def decode_pak_entry(blob: bytes, offset: int) -> dict:
    """Mirror of FPakFile::DecodePakEntry (C:7092-7227). Masks cited per field.

    Returns the decoded fields plus ``encoded_length``, the number of bytes this
    record occupied. The length matters as much as the fields: it is what lets the
    caller check that the decoded records TILE the encoded blob exactly, which is
    the strongest available check that the layout above is the layout on disk.
    """
    start = offset
    if offset < 0 or offset + 4 > len(blob):
        raise ContainerParseError(
            "encoded entries: offset %d is outside the %d-byte blob" % (offset, len(blob)))
    (value,) = struct.unpack_from("<I", blob, offset)
    offset += 4

    # bits 5..0 -- CompressionBlockSize, packed. 0x3f is the escape that says the
    # real value follows as a uint32 (C:7106-7110); anything else is a 6-bit
    # multiple of 1 << 11 (C:7114, written at C:7015-7019).
    packed_block_size = value & 0x3f
    block_size_field_present = packed_block_size == 0x3f
    if block_size_field_present:
        (compression_block_size,) = struct.unpack_from("<I", blob, offset)
        offset += 4
    else:
        compression_block_size = packed_block_size << 11

    # bits 28..23 -- CompressionMethodIndex (C:7118).
    method_index = (value >> 23) & 0x3f

    # bit 31 -- Offset is 32-bit safe (C:7125).
    if value & (1 << 31):
        (entry_offset,) = struct.unpack_from("<I", blob, offset)
        offset += 4
    else:
        (entry_offset,) = struct.unpack_from("<q", blob, offset)
        offset += 8

    # bit 30 -- UncompressedSize is 32-bit safe (C:7138).
    if value & (1 << 30):
        (uncompressed_size,) = struct.unpack_from("<I", blob, offset)
        offset += 4
    else:
        (uncompressed_size,) = struct.unpack_from("<q", blob, offset)
        offset += 8

    # Size is on the wire ONLY for a compressed entry (C:7151); for an
    # uncompressed one it is DEFINED to equal UncompressedSize (C:7170). Reading a
    # Size field here for an uncompressed entry is the single easiest way to shift
    # every subsequent field by four bytes, so the branch is spelled out.
    if method_index != 0:
        if value & (1 << 29):                       # bit 29 (C:7154)
            (size,) = struct.unpack_from("<I", blob, offset)
            offset += 4
        else:
            (size,) = struct.unpack_from("<q", blob, offset)
            offset += 8
    else:
        size = uncompressed_size

    # bit 22 -- Encrypted (C:7174), which sets FPakEntry::Flag_Encrypted == 0x01
    # (H:382) through SetEncrypted/SetFlag (H:546-564).
    encrypted = (value & (1 << 22)) != 0

    # bits 21..6 -- CompressionBlocks count (C:7178).
    block_count = (value >> 6) & 0xffff
    if block_count > MAX_COMPRESSION_BLOCKS:
        raise ContainerParseError(
            "encoded entries: block count %d at offset %d" % (block_count, start))

    # The per-block size array is on the wire only for >1 block, or for exactly one
    # block on an ENCRYPTED entry (C:7079; the reader's matching branch is the
    # `else if (Num > 0)` at C:7209, the single-unencrypted-block case being
    # derived at C:7201-7208). It is only written at all when compressed (C:7065).
    block_sizes: list[int] = []
    if method_index != 0 and (block_count > 1 or (block_count == 1 and encrypted)):
        for _ in range(block_count):
            (block,) = struct.unpack_from("<I", blob, offset)
            offset += 4
            block_sizes.append(block)

    # C:7187-7189 -- a single block reuses UncompressedSize as the block size.
    if block_count == 1:
        compression_block_size = uncompressed_size
    elif block_count == 0:
        compression_block_size = 0

    return {
        "flag_word": value,
        "offset": entry_offset,
        "size": size,
        "uncompressed_size": uncompressed_size,
        "compression_method_index": method_index,
        "encrypted": encrypted,
        "compression_block_count": block_count,
        "compression_block_size": compression_block_size,
        "block_size_field_present": block_size_field_present,
        "block_sizes": block_sizes,
        "encoded_length": offset - start,
    }


def decompose_flag_word(value: int) -> dict:
    """Every field of one flag word, for the census. Same citations as the decoder."""
    return {
        "flag_word_hex": "0x%08X" % value,
        "bit31_offset_32bit_safe": bool(value & (1 << 31)),
        "bit30_uncompressed_size_32bit_safe": bool(value & (1 << 30)),
        "bit29_size_32bit_safe": bool(value & (1 << 29)),
        "bits28_23_compression_method_index": (value >> 23) & 0x3f,
        "bit22_encrypted": bool(value & (1 << 22)),
        "bits21_6_compression_block_count": (value >> 6) & 0xffff,
        "bits5_0_compression_block_size_packed": value & 0x3f,
    }


def local_header_size(version: int, method_index: int, block_count: int) -> int:
    """FPakEntry::GetSerializedSize (H:417-444) for the LOCAL header at a payload offset.

    int64 Offset + int64 Size + int64 UncompressedSize + uint8 Hash[20] = 44, plus
    uint32 CompressionMethodIndex from version 8 (H:421-424), plus uint8 Flags and
    uint32 CompressionBlockSize from version 3 (H:430-432), plus, when compressed,
    the block array and its int32 count (H:433-436). For version 11 uncompressed
    that is 53 bytes.
    """
    size = 8 + 8 + 8 + 20
    # H:421-428: from version 8 this is uint32 CompressionMethodIndex, before it an
    # int32 legacy method. Both are 4 bytes, which is why there is no branch here --
    # only the MEANING differs, and this function needs the width.
    size += 4
    size += 1 + 4
    if method_index != 0:
        size += 16 * block_count + 4
    return size


# --------------------------------------------------------------------------- #
# refutation probes
# --------------------------------------------------------------------------- #

def probe_flag_word_census(entries: list[dict], compression_methods: list) -> dict:
    """Every distinct flag word with its decomposition, plus a mask cross-check.

    The cross-check is the part that can refuse: a CompressionMethodIndex is legal
    only if the footer's CompressionMethods table has a slot for it (index 0 is
    NAME_None and is never serialized, H:184-185/H:295-299, so index N names
    CompressionMethods[N-1] of the table). An index the footer cannot name is
    either a corrupt file or a wrong mask, and either way the decode must not be
    believed.
    """
    census = Counter(entry["flag_word"] for entry in entries)
    rows = []
    unnameable = []
    for value, count in sorted(census.items()):
        row = decompose_flag_word(value)
        row["count"] = count
        method = row["bits28_23_compression_method_index"]
        if method == 0:
            row["compression_method_name"] = "None (index 0 is NAME_None, never serialized)"
        elif 1 <= method <= len(compression_methods):
            row["compression_method_name"] = compression_methods[method - 1]
        else:
            row["compression_method_name"] = None
            unnameable.append(method)
        rows.append(row)
    return {
        "what_this_probe_can_refute": (
            "a wrong mask. A summary hides a mask error; a census cannot. If the "
            "encrypted bit were really the low bit of a wider method field, the "
            "method values here would not be nameable from the footer table."),
        "distinct_flag_words": len(census),
        "flag_words": rows,
        "footer_compression_methods": list(compression_methods),
        "unnameable_compression_method_indices": sorted(set(unnameable)),
        "refuted": bool(unnameable),
    }


def probe_encoded_blob_tiling(entries: list[dict], blob_length: int) -> dict:
    """Do the decoded records tile the encoded blob exactly?

    Each entry's location is an independent byte offset, and each decoded record
    has a length that follows from its own flag word. If the layout above were
    wrong, those lengths would not add up: there would be gaps, overlaps, or a
    covered extent different from the blob. Exact tiling with no slack is a strong
    structural check on the whole decode, obtained without reading any payload.
    """
    spans = sorted((entry["location_value"], entry["encoded_length"]) for entry in entries)
    position = 0
    gaps = overlaps = 0
    for offset, length in spans:
        if offset > position:
            gaps += 1
        elif offset < position:
            overlaps += 1
        position = max(position, offset + length)
    return {
        "what_this_probe_can_refute": (
            "the whole bitfield layout. Wrong field widths cannot tile a blob "
            "exactly by accident."),
        "encoded_blob_length": blob_length,
        "distinct_locations": len(set(offset for offset, _ in spans)),
        "records": len(spans),
        "covered_extent": position,
        "gaps": gaps,
        "overlaps": overlaps,
        "tiles_exactly": gaps == 0 and overlaps == 0 and position == blob_length,
    }


def probe_layout(entries: list[dict], version: int, index_offset: int) -> dict:
    """Test the two encryption hypotheses against the packed file layout.

    This probe reads NO flag. The packer writes ``Align(Size, AESBlockSize)``
    payload bytes for an encrypted entry while the Size field keeps the plaintext
    length (PakFileUtilities.cpp:1028 and 1044-1060), and exactly ``Size`` bytes
    for an unencrypted one. So the two hypotheses predict two different files, and
    the file can be asked which it is.

    Three numbers matter, and the third is the sharpest:

    * how many consecutive-entry gaps each model explains exactly;
    * whether the padded model ever OVERLAPS the next entry, which would refute
      it outright;
    * where the last payload ends against the start of the index, which has no
      following entry to absorb slack and therefore no room to be coincidence.

    A gap the padded model does not explain exactly is not evidence against it:
    the packer also aligns entry offsets (``-alignforsize``, patch padding), so
    slack is expected. That is why the unexplained gaps are further tested for
    being explained by alignment of the NEXT offset, and reported either way.

    One subtlety decides whether this probe says anything at all. When a Size
    happens to be a multiple of the AES block, the two models predict the SAME
    end, and that pair distinguishes nothing. Only DISCRIMINATING pairs -- those
    whose Size is not block-aligned -- carry information, so the verdict is formed
    from those alone and the discriminating counts are reported separately from the
    raw ones. Counting an indistinguishable pair as support for either model would
    manufacture confidence out of arithmetic.
    """
    ordered = sorted(entries, key=lambda entry: entry["offset"])
    padded_exact = plain_exact = neither = overlaps = 0
    # The discriminating subset: pairs whose two predicted ends actually differ.
    discriminating = padded_exact_disc = plain_exact_disc = overlaps_disc = 0
    aligned_slack: Counter[int] = Counter()
    unexplained: list[dict] = []

    for current, following in zip(ordered, ordered[1:]):
        header = local_header_size(version, current["compression_method_index"],
                                   current["compression_block_count"])
        payload_start = current["offset"] + header
        padded_end = payload_start + align_up(current["size"], AES_BLOCK_SIZE)
        plain_end = payload_start + current["size"]
        next_offset = following["offset"]
        distinguishes = padded_end != plain_end
        if distinguishes:
            discriminating += 1
        if next_offset < padded_end:
            overlaps += 1
            if distinguishes:
                overlaps_disc += 1
        if next_offset == padded_end:
            padded_exact += 1
            if distinguishes:
                padded_exact_disc += 1
        elif next_offset == plain_end:
            plain_exact += 1
            if distinguishes:
                plain_exact_disc += 1
        else:
            neither += 1
            # Is the slack explained by the next offset sitting on a power-of-two
            # boundary? Tried largest first so the reported alignment is the
            # strongest one that fits.
            explained = 0
            for alignment in (65536, 4096, 2048, 1024, 512, 256, 16):
                if next_offset % alignment == 0 and next_offset >= padded_end:
                    explained = alignment
                    break
            if explained:
                aligned_slack[explained] += 1
            elif len(unexplained) < 8:
                unexplained.append({
                    "offset": current["offset"],
                    "size": current["size"],
                    "padded_end": padded_end,
                    "next_offset": next_offset,
                })

    last = ordered[-1] if ordered else None
    tail: dict = {}
    if last is not None:
        header = local_header_size(version, last["compression_method_index"],
                                   last["compression_block_count"])
        payload_start = last["offset"] + header
        tail = {
            "last_entry_offset": last["offset"],
            "last_entry_size": last["size"],
            "padded_end": payload_start + align_up(last["size"], AES_BLOCK_SIZE),
            "unpadded_end": payload_start + last["size"],
            "index_offset": index_offset,
        }
        tail["padded_end_meets_index"] = tail["padded_end"] == index_offset
        tail["unpadded_end_meets_index"] = tail["unpadded_end"] == index_offset
        # The last payload has no following entry to absorb slack, so when its two
        # predicted ends differ this single comparison is the sharpest signal in the
        # probe: there is no room for it to be coincidence.
        tail["distinguishes"] = tail["padded_end"] != tail["unpadded_end"]

    tail_supports_encrypted = bool(tail.get("distinguishes")
                                   and tail.get("padded_end_meets_index"))
    tail_supports_plaintext = bool(tail.get("distinguishes")
                                   and tail.get("unpadded_end_meets_index"))

    # Evidence is weighed on the discriminating subset only. An overlap under the
    # padded model makes that model impossible, so it cancels any support for it.
    for_plaintext = bool(plain_exact_disc) or tail_supports_plaintext
    for_encrypted = ((bool(padded_exact_disc) or tail_supports_encrypted)
                     and overlaps_disc == 0)

    if for_encrypted and not for_plaintext:
        verdict = "SUPPORTS_ENCRYPTED"
    elif for_plaintext and not for_encrypted:
        verdict = "SUPPORTS_PLAINTEXT"
    elif overlaps_disc and not for_plaintext:
        # The padded model is impossible here, but nothing supports the other one
        # either -- which is a refutation, not a conclusion.
        verdict = "REFUTES_ENCRYPTED"
    else:
        verdict = "INCONCLUSIVE"

    return {
        "what_this_probe_can_refute": (
            "the encrypted verdict, without consulting any flag. An encrypted "
            "uncompressed entry occupies Align(Size, 16) bytes on disk and an "
            "unencrypted one occupies Size, so the two hypotheses predict "
            "different files."),
        "aes_block_size": AES_BLOCK_SIZE,
        "consecutive_pairs": max(len(ordered) - 1, 0),
        # Pairs whose Size is not block-aligned, and which therefore predict
        # different ends under the two models. Only these carry information.
        "discriminating_pairs": discriminating,
        "gaps_explained_exactly_by_padded_model": padded_exact,
        "gaps_explained_exactly_by_unpadded_model": plain_exact,
        "discriminating_gaps_explained_by_padded_model": padded_exact_disc,
        "discriminating_gaps_explained_by_unpadded_model": plain_exact_disc,
        "gaps_explained_by_neither": neither,
        "padded_model_overlaps_next_entry": overlaps,
        "padded_model_overlaps_a_discriminating_next_entry": overlaps_disc,
        "remaining_gaps_explained_by_next_offset_alignment":
            {str(k): v for k, v in sorted(aligned_slack.items())},
        "gaps_explained_by_nothing": unexplained,
        "tail": tail,
        "verdict": verdict,
    }


def probe_local_headers(handle, entries: list[dict], version: int,
                        sample_limit: int) -> dict:
    """Read the LOCAL FPakEntry header of each entry and compare it with the index.

    The local header is written at the payload offset by FPakEntry::Serialize
    (H:495-544), by the packer at PakFileUtilities.cpp:2736, and it is written
    PLAINTEXT: encryption in that packer touches the data buffer only, at :1057
    (uncompressed) and :1109 (compressed). It carries a second, independent copy
    of Flags, CompressionMethodIndex, Size and UncompressedSize, produced by a
    different serializer and stored somewhere else in the file.

    That makes this a real cross-check rather than a restatement. It also carries
    its own plaintext proof: if these bytes were ciphertext, the Size and
    UncompressedSize they hold would not agree with the index for every entry, and
    the Offset field would not be the 0 the packer writes there (it stores offsets
    "only in index", :2749-2750).

    Field offsets within the header, from H:495-544 in order: Offset 0, Size 8,
    UncompressedSize 16, CompressionMethodIndex 24, Hash 28..47, then (compressed
    only) the block array, then Flags, then CompressionBlockSize. For an
    uncompressed version-11 entry: Flags at 48, CompressionBlockSize at 49.
    """
    flags_census: Counter[int] = Counter()
    method_census: Counter[int] = Counter()
    agree = disagree = 0
    disagreements: list[dict] = []
    read = 0

    ordered = sorted(entries, key=lambda entry: entry["offset"])
    for entry in ordered:
        if sample_limit and read >= sample_limit:
            break
        if entry["compression_method_index"] != 0:
            # The flags offset moves when the block array is present; this pak has
            # no compressed entry, so rather than carry untested arithmetic the
            # compressed case is skipped and counted.
            continue
        size = local_header_size(version, 0, 0)
        handle.seek(entry["offset"])
        raw = handle.read(size)
        read += 1
        if len(raw) != size:
            disagree += 1
            continue
        header_offset, header_size, header_uncompressed = struct.unpack_from("<qqq", raw, 0)
        (header_method,) = struct.unpack_from("<I", raw, 24)
        header_flags = raw[48]
        (header_block_size,) = struct.unpack_from("<I", raw, 49)
        flags_census[header_flags] += 1
        method_census[header_method] += 1
        consistent = (header_offset == 0
                      and header_size == entry["size"]
                      and header_uncompressed == entry["uncompressed_size"]
                      and header_method == entry["compression_method_index"]
                      and header_block_size == 0
                      and bool(header_flags & 0x01) == entry["encrypted"])
        if consistent:
            agree += 1
        else:
            disagree += 1
            if len(disagreements) < 8:
                disagreements.append({
                    "entry_offset": entry["offset"],
                    "index_size": entry["size"],
                    "header_size": header_size,
                    "index_encrypted": entry["encrypted"],
                    "header_flags": header_flags,
                })

    return {
        "what_this_probe_can_refute": (
            "the index bitfield decode. The local header is a second copy of the "
            "same flag, written by a different serializer at a different place in "
            "the file; a wrong mask would disagree with it."),
        "headers_read": read,
        "sample_limit": sample_limit or None,
        "agree_with_index": agree,
        "disagree_with_index": disagree,
        "disagreements": disagreements,
        "flags_byte_census": {"0x%02x" % k: v for k, v in sorted(flags_census.items())},
        "compression_method_index_census":
            {str(k): v for k, v in sorted(method_census.items())},
        "flag_bit_meaning": ("FPakEntry::Flag_Encrypted == 0x01 and "
                             "Flag_Deleted == 0x02, IPlatformFilePak.h:381-383"),
        # This is the header's own plaintext argument, stated so that a reader can
        # see it was made rather than assumed.
        "why_these_bytes_are_plaintext": (
            "the packer writes this header with FPakEntry::Serialize and encrypts "
            "only the payload buffer (PakFileUtilities.cpp:2736 vs :1057/:1109), and "
            "the bytes read here carry Offset 0 and Size/UncompressedSize equal to "
            "the index for every header read. Ciphertext would not."),
    }


# --------------------------------------------------------------------------- #
# classification of the path list
# --------------------------------------------------------------------------- #

def classify_paths(entries: list[dict]) -> dict:
    """Extension histogram, directory tree shape, and the cooked-asset question.

    Paths, counts and sizes only. No payload is touched here, and none could be:
    this function never sees the file.
    """
    extensions: Counter[str] = Counter()
    extension_bytes: Counter[str] = Counter()
    roots: Counter[str] = Counter()
    root_bytes: Counter[str] = Counter()
    depths: Counter[int] = Counter()
    cooked: list[dict] = []

    for entry in entries:
        path = entry["path"]
        extension = posixpath.splitext(path)[1].lower() or "(none)"
        extensions[extension] += 1
        extension_bytes[extension] += entry["size"]
        root = path.split("/")[0] if "/" in path else "(root)"
        roots[root] += 1
        root_bytes[root] += entry["size"]
        depths[path.count("/")] += 1
        if extension in COOKED_EXTENSIONS:
            cooked.append({
                "path": path,
                "size": entry["size"],
                "uncompressed_size": entry["uncompressed_size"],
                "encrypted": entry["encrypted"],
                "compression_method_index": entry["compression_method_index"],
            })

    # NOT the same number as the directory index's own directory count: the index
    # carries a record for every directory on the path, including ones that hold no
    # file of their own, and this counts only the ones a file actually sits in.
    # Reporting one number for both would be reporting a wrong number for one.
    directories = sorted({posixpath.dirname(entry["path"]) for entry in entries})
    return {
        "extension_histogram": [
            {"extension": extension, "files": count, "bytes": extension_bytes[extension]}
            for extension, count in sorted(extensions.items(),
                                           key=lambda item: (-item[1], item[0]))],
        "top_level_roots": [
            {"root": root, "files": count, "bytes": root_bytes[root]}
            for root, count in sorted(roots.items(), key=lambda item: (-item[1], item[0]))],
        "path_depth_histogram": {str(k): v for k, v in sorted(depths.items())},
        "distinct_directories_containing_files": len(directories),
        "cooked_asset_extensions_looked_for": list(COOKED_EXTENSIONS),
        "cooked_assets_found": cooked,
        "cooked_asset_count": len(cooked),
    }


def readable_payload_entries(entries: list[dict]) -> list[dict]:
    """Entries whose flag says plaintext -- the only ones whose payload may be read.

    D-02 lives here. This is the gate: anything not returned by this function is
    never opened for its content by this tool, regardless of how interesting it
    looks. An uncompressed plaintext entry is the readable case; a compressed
    plaintext entry would need decompression, which is not decryption and is
    allowed, but is not implemented here and is reported as such rather than
    silently counted as readable.
    """
    return [entry for entry in entries if not entry["encrypted"]]


# --------------------------------------------------------------------------- #
# class-P literal layer
# --------------------------------------------------------------------------- #

def literal_read(target: str, decoded_field: str, offset: int, raw: bytes,
                 note: str | None = None) -> dict:
    """One class-P record: a literal read at a determinate place, and nothing more.

    ``claim`` states the offset and the length -- which plan.md 10.3 v2.4 makes
    MANDATORY for the container-metadata oracle to be class P at all -- and stops
    short of naming what the bytes are. ``decoded_field`` is a join key into the
    decoded layer for a consumer that wants both halves; it is deliberately
    OUTSIDE the graded object, because naming a structure inside the graded note
    is exactly what would disqualify class P.

    Shape follows tools/fingerprint/container_info.py deliberately: the same
    consumer reads both, and a second shape for the same idea would be a second
    thing to keep correct.
    """
    length = len(raw)
    plural = "byte" if length == 1 else "bytes"
    claim = "%d %s at offset %d of %s are %s" % (
        length, plural, offset, target, hex_bytes(raw))
    return {
        "decoded_field": decoded_field,
        "interpretation_lives_in": (
            "the matching field of index/entries in the same document -- plan.md "
            "10.3, the A-07 / A-07i split"),
        "target": target,
        "offset": offset,
        "length": length,
        "bytes_hex": hex_bytes(raw),
        "claim": claim,
        "evidence": {
            "evidence_level": "OBSERVED",
            "claim_class": "P",
            "confidence": CONFIDENCE_LITERAL,
            "oracle": ["container-metadata"],
            "sources": [{
                # The per-source "oracle" key of kb-record.schema.json#/$defs/source
                # is deliberately NOT set -- see the note in container_info.py: the
                # key is legal in the schema and makes tools/kb/validate.py misread
                # every source object as a whole record. The oracle is stated in the
                # note instead, and the record-level list above is unaffected.
                "method": "CK-01 pak index read",
                "artifact": None,
                "locator": "%s@%d+%d" % (target, offset, length),
                "note": ("oracle container-metadata. Read by %s, read-only. "
                         "Reproduction: PENDING." % GENERATOR_NAME),
            }],
            "read_locus": {
                "target": target,
                "address_kind": "file-offset",
                "offset": offset,
                "length": length,
                "bytes_hex": hex_bytes(raw),
                "note": note,
            },
            "note": ("%s. This record gives the position and the extent, and "
                     "nothing else." % claim),
        },
    }


def confirm_literal_reads(path: str, literals: list[dict], target: str,
                          warnings: list[str]) -> bool:
    """Perform every literal read a SECOND time and stamp the result onto each record.

    plan.md 10.3 class-P criterion 2 executed rather than asserted. The second pass
    uses a freshly opened handle and seeks independently. On any disagreement
    nothing is adjusted: the failure is recorded and the reading stands as
    unreproduced.
    """
    reproduced = True
    try:
        with open(path, "rb", buffering=0) as handle:
            for read in literals:
                handle.seek(read["offset"])
                again = handle.read(read["length"])
                if hex_bytes(again) != read["bytes_hex"]:
                    reproduced = False
                    warnings.append(
                        "%s: the second read of %d bytes at offset %d gave %s but the "
                        "first gave %s -- the reading did NOT reproduce"
                        % (target, read["length"], read["offset"], hex_bytes(again),
                           read["bytes_hex"]))
    except OSError as error:
        reproduced = False
        warnings.append("%s: the confirming re-read could not be performed: %s"
                        % (target, error))

    attestation = RERUN_CONFIRMED if reproduced else RERUN_NOT_CONFIRMED
    for read in literals:
        read["reproduced"] = reproduced
        read["evidence"]["sources"][0]["note"] = (
            "oracle container-metadata. Read by %s, read-only. %s"
            % (GENERATOR_NAME, attestation))
        read["evidence"]["note"] = "%s %s" % (read["evidence"]["note"], attestation)
    return reproduced


def decoded_annotation(methods_note: str) -> dict:
    """The class-I annotation for the decoded layer.

    This is the REDUCED evidence annotation of
    ``research/schema/kb-record.schema.json#/$defs/annotation`` -- the shape a
    document attaches to one of its own sub-objects -- and that schema is
    ``additionalProperties: false`` over exactly seven keys. So the two independent
    methods are NAMED inside ``sources`` and restated in ``note`` rather than given
    a key of their own: a key the schema forbids would make the whole object be read
    as a full knowledge-base record, and then demand a ``claim_type`` and a
    ``build_key`` that this shape has no room for. The enclosing document states the
    build identity once, in ``target``.

    Two independent methods are required at 0.80 and above (plan.md 10.3), and they
    are named because an extra oracle is not a method, an artifact path is not a
    method, and a clause of reasoning is not a method.
    """
    return {
        "evidence_level": "INFERRED",
        "claim_class": "I",
        "confidence": CONFIDENCE_DECODED,
        "oracle": ["container-metadata", "external-doc"],
        "sources": [
            {
                "method": "CK-01 pak index decode",
                "artifact": None,
                "locator": "FPakFile::DecodePakEntry / FPakFile::LoadIndexInternal",
                "note": ("oracle external-doc: the field order and every mask come "
                         "from the first-party UE 5.4.4 source tree at the changelist "
                         "this build was made from, cited to file and line in the "
                         "module docstring of %s and again at the point of use in the "
                         "decoder." % GENERATOR_NAME),
            },
            {
                "method": "CK-01 packed-layout and local-header probes",
                "artifact": None,
                "locator": "probes.layout_probe / probes.local_header_probe",
                "independent_of": ["CK-01 pak index decode"],
                "note": ("oracle container-metadata. Second, independent method: the "
                         "file's own packed layout and the independent copy of the "
                         "flags byte in each local entry header, neither of which "
                         "consults the index bitfield."),
            },
        ],
        "read_locus": None,
        "note": ("Class I: these fields name what the bytes ARE and rest on an "
                 "external layout, so they are capped below the literal layer "
                 "whatever the offsets are. The primitive half is in "
                 "literal_reads[]. Two independent methods: %s" % methods_note),
    }


# --------------------------------------------------------------------------- #
# the analysis
# --------------------------------------------------------------------------- #

def analyze(path: str, literal_samples: int = DEFAULT_LITERAL_SAMPLES,
            install_root: str | None = None,
            local_header_samples: int = 0) -> dict:
    """Read one pak and answer the four CK-01 gating questions. Read-only throughout."""
    file_size = os.path.getsize(path)
    target = locus_target(path, install_root or _detect_install_root(path))
    warnings: list[str] = []
    literals: list[dict] = []

    with open(path, "rb", buffering=0) as handle:
        footer = read_footer(handle, file_size)
        warnings.extend(footer["warnings"])

        # Literal layer: the footer fields that carry the encryption answer. These
        # come first because they are what the interpretive layer below rests on.
        for name in ("encryption_key_guid", "encrypted_index", "magic", "pak_version",
                     "index_offset", "index_size", "index_hash"):
            if name not in footer["field_spans"]:
                continue
            rel, length = footer["field_spans"][name]
            literals.append(literal_read(
                target, name, footer["footer_offset"] + rel,
                footer["footer_bytes"][rel:rel + length],
                note="inside the %d-byte v%d pak footer at %d"
                     % (footer["footer_size"], footer["version"], footer["footer_offset"])))

        # --- the D-02 proof, before anything is interpreted ------------------- #
        primary_raw = read_blob(handle, footer["index_offset"], footer["index_size"],
                                file_size, "primary index")
        proofs = [prove_index_plaintext("primary_index", primary_raw,
                                        footer["index_hash"], footer["encrypted_index"])]
        if proofs[0]["verdict"] != "PLAINTEXT_PROVEN":
            return _blocked_document(path, target, file_size, footer, proofs, literals,
                                     warnings, "the primary index is not proven plaintext")

        index = parse_primary_index(primary_raw, footer["version"])
        if not index["fully_consumed"]:
            warnings.append(
                "primary index: consumed %d of %d bytes. A TMap/TArray serialization "
                "that does not close exactly is a decode error, not a rounding issue."
                % (index["bytes_consumed"], index["bytes_available"]))

        for key in ("path_hash_index", "full_directory_index"):
            block = index.get(key)
            if not block:
                continue
            raw = read_blob(handle, block["offset"], block["size"], file_size, key)
            proofs.append(prove_index_plaintext(key, raw, block["_sha1_raw"],
                                                footer["encrypted_index"]))
            block["_raw"] = raw

        full = index.get("full_directory_index")
        if not full:
            return _blocked_document(path, target, file_size, footer, proofs, literals,
                                     warnings, "this pak carries no full directory index")
        full_proof = next(p for p in proofs if p["blob"] == "full_directory_index")
        if full_proof["verdict"] != "PLAINTEXT_PROVEN":
            return _blocked_document(path, target, file_size, footer, proofs, literals,
                                     warnings,
                                     "the full directory index is not proven plaintext")

        literals.append(literal_read(
            target, "full_directory_index_head", full["offset"],
            full["_raw"][:min(32, len(full["_raw"]))],
            note="the leading bytes of the range the footer chain names at %d"
                 % full["offset"]))

        directories, dir_stats = parse_directory_index(full["_raw"])
        if not dir_stats["fully_consumed"]:
            warnings.append(
                "full directory index: consumed %d of %d bytes -- the TMap did not "
                "close exactly" % (dir_stats["bytes_consumed"], dir_stats["bytes_available"]))

        # --- decode every entry ---------------------------------------------- #
        encoded = index["_encoded"]
        entries: list[dict] = []
        unresolved: list[dict] = []
        for dir_name, files in directories:
            for file_name, location in files:
                kind, resolved = PakEntryLocation.classify(location)
                path_in_pak = dir_name + file_name
                if kind != "encoded_offset":
                    unresolved.append({"path": path_in_pak, "location_kind": kind,
                                       "location_value": location})
                    continue
                decoded = decode_pak_entry(encoded, resolved)
                decoded["path"] = path_in_pak
                decoded["directory"] = dir_name
                decoded["location_value"] = resolved
                entries.append(decoded)

        if len(entries) + len(unresolved) != index["num_entries"]:
            warnings.append(
                "the directory index names %d files but the primary index declares "
                "NumEntries %d" % (len(entries) + len(unresolved), index["num_entries"]))

        # A sample of the encoded records, as literal reads. Bounded and
        # deterministic: the first N in offset order.
        # The file offset at which the EncodedPakEntries DATA begins. bytes_consumed
        # is the position after the int32 FilesNum that follows the blob (C:6181,
        # C:6185), so the data starts four bytes plus the blob's own length before
        # it. This arithmetic is exactly what the confirming re-read in
        # confirm_literal_reads exists to catch when it is wrong -- and it caught it
        # being wrong by four bytes once already.
        encoded_blob_file_offset = (footer["index_offset"] + index["bytes_consumed"]
                                    - 4 - index["encoded_entries_length"])
        for entry in sorted(entries, key=lambda item: item["location_value"])[:literal_samples]:
            start = encoded_blob_file_offset + entry["location_value"]
            literals.append(literal_read(
                target, "encoded_entry_record", start,
                encoded[entry["location_value"]:
                        entry["location_value"] + entry["encoded_length"]],
                note="one record inside the range the footer chain names at %d"
                     % encoded_blob_file_offset))

        # --- probes ----------------------------------------------------------- #
        probes = {
            "entry_flag_word_census": probe_flag_word_census(
                entries, footer["compression_methods"]),
            "encoded_blob_tiling": probe_encoded_blob_tiling(
                entries, index["encoded_entries_length"]),
            "layout_probe": probe_layout(entries, footer["version"],
                                         footer["index_offset"]),
            "local_header_probe": probe_local_headers(
                handle, entries, footer["version"], local_header_samples),
        }

        # Local-header literal reads: the flags byte itself, at its own address.
        for entry in sorted(entries, key=lambda item: item["offset"])[:literal_samples]:
            if entry["compression_method_index"] != 0:
                continue
            size = local_header_size(footer["version"], 0, 0)
            handle.seek(entry["offset"])
            raw = handle.read(size)
            if len(raw) == size:
                literals.append(literal_read(
                    target, "entry_local_header", entry["offset"], raw,
                    note="a %d-byte range beginning at a position the index names" % size))

        reproduced = confirm_literal_reads(path, literals, target, warnings)

    classification = classify_paths(entries)
    readable = readable_payload_entries(entries)
    encrypted_count = sum(1 for entry in entries if entry["encrypted"])

    methods_note = (
        "(1) the field order and every mask read from the first-party UE 5.4.4 "
        "source at the build's own changelist, cited per field; (2) the file's own "
        "packed layout plus the independent copy of the flags byte in each local "
        "entry header, neither of which reads the index bitfield. The two agree: "
        "%d of %d entries carry Flag_Encrypted in the index, the layout probe "
        "returns %s, and the local-header probe found %d disagreements."
        % (encrypted_count, len(entries), probes["layout_probe"]["verdict"],
           probes["local_header_probe"]["disagree_with_index"]))

    document = {
        "schema": "pak-index/1",
        "generated_at": now_iso_utc(),
        "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
        "target": {
            "path_relative_to_install": target,
            "file_size": file_size,
            "sha256": container_info.stream_sha256(path),
        },
        "engine_source": {
            "citation_files": list(ENGINE_SOURCE_RELPATHS),
            "note": ("every field and every mask in this document is cited to file "
                     "and line in the module docstring of %s and again at the point "
                     "of use in the decoder." % GENERATOR_NAME),
        },
        "payload_policy": PAYLOAD_POLICY,
        "footer": {
            "version": footer["version"],
            "offset": footer["footer_offset"],
            "size": footer["footer_size"],
            "magic": footer["magic"],
            "index_offset": footer["index_offset"],
            "index_size": footer["index_size"],
            "index_sha1": footer["index_hash"].hex(),
            "encrypted_index": footer["encrypted_index"],
            "encryption_key_guid": footer["encryption_key_guid"],
            "compression_methods": footer["compression_methods"],
        },
        "plaintext_proofs": [_strip_private(proof) for proof in proofs],
        "index": {
            "mount_point": index["mount_point"],
            "num_entries_declared": index["num_entries"],
            "path_hash_seed": index["path_hash_seed"],
            "path_hash_index": _strip_private(index.get("path_hash_index")),
            "full_directory_index": _strip_private(index.get("full_directory_index")),
            "encoded_entries_length": index["encoded_entries_length"],
            "unencodable_files_count": index["unencodable_files_count"],
            "primary_index_fully_consumed": index["fully_consumed"],
            "directory_index": dir_stats,
        },
        "entries": {
            "decoded": len(entries),
            "unresolved_locations": unresolved,
            "encrypted": encrypted_count,
            "unencrypted": len(entries) - encrypted_count,
            "encrypted_flag_source": (
                "bit 22 of the encoded flag word, IPlatformFilePak.cpp:7174, which "
                "sets FPakEntry::Flag_Encrypted == 0x01, IPlatformFilePak.h:382"),
            "compression_method_index_histogram": {
                str(k): v for k, v in sorted(
                    Counter(entry["compression_method_index"] for entry in entries).items())},
            "compression_block_count_histogram": {
                str(k): v for k, v in sorted(
                    Counter(entry["compression_block_count"] for entry in entries).items())},
            "total_size_bytes": sum(entry["size"] for entry in entries),
            "total_uncompressed_size_bytes": sum(entry["uncompressed_size"] for entry in entries),
            "largest": [
                {"path": entry["path"], "size": entry["size"],
                 "uncompressed_size": entry["uncompressed_size"],
                 "encrypted": entry["encrypted"]}
                for entry in sorted(entries, key=lambda item: -item["size"])[:20]],
        },
        "content": classification,
        "readable_within_d02": {
            "entries_whose_flag_says_plaintext": len(readable),
            "of_those_uncompressed": sum(
                1 for entry in readable if entry["compression_method_index"] == 0),
            "paths": [entry["path"] for entry in readable[:200]],
            "payloads_read_by_this_run": 0,
            "note": ("No payload byte was read by this run. Under D-02 a payload may "
                     "be read only from an entry whose Flag_Encrypted bit is clear, "
                     "and %d of %d entries have it set."
                     % (encrypted_count, len(entries))),
        },
        "probes": probes,
        "literal_reads": literals,
        "literal_reads_reproduced": reproduced,
        "decoded_evidence": decoded_annotation(methods_note),
        "warnings": warnings,
    }
    document["summary"] = build_summary(document)
    # Working field, stripped before the document is written or printed. The path
    # list needs every entry; the JSON document deliberately does not carry 4424
    # decoded records, because the paths artifact is where that belongs.
    document["_entries_for_paths"] = entries
    return document


def _detect_install_root(path: str) -> str:
    """The installation *path* belongs to, via pathguard's own predicate."""
    try:
        roots = pathguard.structural_install_roots(path)
    except (ValueError, OSError):
        roots = []
    if roots:
        return roots[-1]
    return pathguard.CONFIGURED_INSTALL_ROOTS[0]


def _strip_private(value):
    """Drop the `_`-prefixed working fields so the document is JSON-serialisable."""
    if isinstance(value, dict):
        return {k: _strip_private(v) for k, v in value.items() if not k.startswith("_")}
    if isinstance(value, list):
        return [_strip_private(item) for item in value]
    return value


def _blocked_document(path: str, target: str, file_size: int, footer: dict,
                      proofs: list[dict], literals: list[dict],
                      warnings: list[str], reason: str) -> dict:
    """A BLOCKED result: what was proven, why it stops here, and nothing decoded.

    A blocked run is a finding, not a failure, and it must not be able to
    masquerade as an empty success -- hence the explicit verdict and the absence
    of any decoded layer.
    """
    confirm_literal_reads(path, literals, target, warnings)
    return {
        "schema": "pak-index/1",
        "generated_at": now_iso_utc(),
        "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
        "target": {"path_relative_to_install": target, "file_size": file_size},
        "payload_policy": PAYLOAD_POLICY,
        "footer": {
            "version": footer["version"],
            "offset": footer["footer_offset"],
            "index_offset": footer["index_offset"],
            "index_size": footer["index_size"],
            "encrypted_index": footer["encrypted_index"],
            "encryption_key_guid": footer["encryption_key_guid"],
        },
        "plaintext_proofs": [_strip_private(proof) for proof in proofs],
        "literal_reads": literals,
        "warnings": warnings,
        "summary": {
            "verdict": "BLOCKED",
            "reason": reason,
            "note": ("Nothing was decoded and nothing was decrypted. Under D-02 a "
                     "datum must be proven unencrypted before it is read, and the "
                     "proof did not close."),
        },
    }


def build_summary(document: dict) -> dict:
    """The headline answers, each one traceable to a field above it."""
    entries = document["entries"]
    content = document["content"]
    probes = document["probes"]
    total = entries["decoded"]
    encrypted = entries["encrypted"]

    if total and encrypted == total:
        verdict = "ALL_ENTRIES_ENCRYPTED"
    elif encrypted == 0:
        verdict = "NO_ENTRY_ENCRYPTED"
    else:
        verdict = "MIXED"

    return {
        "verdict": verdict,
        "entries_total": total,
        "entries_encrypted": encrypted,
        "entries_unencrypted": entries["unencrypted"],
        "cooked_assets_present": content["cooked_asset_count"],
        "readable_payload_entries": document["readable_within_d02"][
            "entries_whose_flag_says_plaintext"],
        "probes_agree": (
            not probes["entry_flag_word_census"]["refuted"]
            and probes["encoded_blob_tiling"]["tiles_exactly"]
            and probes["local_header_probe"]["disagree_with_index"] == 0
            and probes["layout_probe"]["verdict"] in
                ("SUPPORTS_ENCRYPTED", "SUPPORTS_PLAINTEXT")),
        "layout_probe_verdict": probes["layout_probe"]["verdict"],
        "what_this_does_not_settle": (
            "whether the cooked packages in the IoStore containers use unversioned "
            "property serialization. This pak holds no cooked package at all, so "
            "CK-01 cannot be answered from it either way."),
    }


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def dump_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def paths_text(document: dict, entries_source: list[dict]) -> str:
    """The path list as text: size, encrypted flag, method index, path. One per line."""
    lines = [
        "# %s %s -- path list of %s" % (GENERATOR_NAME, GENERATOR_VERSION,
                                        document["target"]["path_relative_to_install"]),
        "# mount point %s, %d entries. Columns: size, uncompressed, enc, method, path."
        % (document["index"]["mount_point"], len(entries_source)),
        "# 'enc' is FPakEntry::Flag_Encrypted (IPlatformFilePak.h:382) as read from "
        "bit 22 of the encoded flag word (IPlatformFilePak.cpp:7174).",
        "# Paths and sizes only. No payload byte was read.",
    ]
    for entry in sorted(entries_source, key=lambda item: item["path"]):
        lines.append("%12d %12d %s %2d %s" % (
            entry["size"], entry["uncompressed_size"],
            "E" if entry["encrypted"] else "-",
            entry["compression_method_index"], entry["path"]))
    return "\n".join(lines) + "\n"


def write_text(body: str, out_path: str, install_root: str | None, what: str) -> str:
    """Write *body*, refusing any path inside an installation. Guard runs first."""
    target = pathguard.check_output_path(out_path, install_root, what=what)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(body)
    return target


def format_summary(document: dict) -> str:
    lines: list[str] = []
    summary = document["summary"]
    lines.append("target: %s (%d bytes)" % (document["target"]["path_relative_to_install"],
                                            document["target"]["file_size"]))
    if summary["verdict"] == "BLOCKED":
        lines.append("VERDICT: BLOCKED -- %s" % summary["reason"])
        lines.append(summary["note"])
        return "\n".join(lines)

    footer = document["footer"]
    lines.append("footer: v%d at %d, index %d+%d, bEncryptedIndex=%s, key guid %s"
                 % (footer["version"], footer["offset"], footer["index_offset"],
                    footer["index_size"], footer["encrypted_index"],
                    footer["encryption_key_guid"]))
    lines.append("")
    lines.append("D-02 plaintext proofs (SHA1 of the raw bytes vs the stored hash):")
    for proof in document["plaintext_proofs"]:
        lines.append("  %-22s %-18s %d bytes" % (proof["blob"], proof["verdict"],
                                                 proof["length"]))
    lines.append("")
    entries = document["entries"]
    lines.append("entries: %d decoded, %d ENCRYPTED, %d unencrypted"
                 % (entries["decoded"], entries["encrypted"], entries["unencrypted"]))
    lines.append("  flag source: %s" % entries["encrypted_flag_source"])
    lines.append("  compression method index histogram: %s"
                 % entries["compression_method_index_histogram"])
    lines.append("")
    lines.append("probes:")
    census = document["probes"]["entry_flag_word_census"]
    lines.append("  flag word census: %d distinct word(s), refuted=%s"
                 % (census["distinct_flag_words"], census["refuted"]))
    for row in census["flag_words"]:
        lines.append("    %s x%d  method=%d encrypted=%s blocks=%d"
                     % (row["flag_word_hex"], row["count"],
                        row["bits28_23_compression_method_index"],
                        row["bit22_encrypted"],
                        row["bits21_6_compression_block_count"]))
    tiling = document["probes"]["encoded_blob_tiling"]
    lines.append("  encoded blob tiling: %d records cover %d of %d bytes, gaps %d, "
                 "overlaps %d, exact=%s"
                 % (tiling["records"], tiling["covered_extent"],
                    tiling["encoded_blob_length"], tiling["gaps"], tiling["overlaps"],
                    tiling["tiles_exactly"]))
    layout = document["probes"]["layout_probe"]
    lines.append("  packed layout: %d of %d pairs discriminate; padded model explains "
                 "%d of them exactly, unpadded model %d, overlaps %d -> %s"
                 % (layout["discriminating_pairs"], layout["consecutive_pairs"],
                    layout["discriminating_gaps_explained_by_padded_model"],
                    layout["discriminating_gaps_explained_by_unpadded_model"],
                    layout["padded_model_overlaps_a_discriminating_next_entry"],
                    layout["verdict"]))
    if layout["tail"]:
        tail = layout["tail"]
        lines.append("    last payload: padded end %d, unpadded end %d, index at %d "
                     "(padded meets index: %s)"
                     % (tail["padded_end"], tail["unpadded_end"], tail["index_offset"],
                        tail["padded_end_meets_index"]))
    header = document["probes"]["local_header_probe"]
    lines.append("  local headers: %d read, %d agree, %d disagree, flags census %s"
                 % (header["headers_read"], header["agree_with_index"],
                    header["disagree_with_index"], header["flags_byte_census"]))
    lines.append("")
    content = document["content"]
    lines.append("content: %d directory records in the index, %d of them "
                 "holding files; extensions:"
                 % (document["index"]["directory_index"]["directory_count"],
                    content["distinct_directories_containing_files"]))
    for row in content["extension_histogram"]:
        lines.append("  %-20s %5d files  %12d bytes" % (row["extension"], row["files"],
                                                        row["bytes"]))
    lines.append("  top-level roots: %s"
                 % ", ".join("%s=%d" % (row["root"], row["files"])
                             for row in content["top_level_roots"]))
    lines.append("  cooked assets (%s): %d"
                 % (" ".join(content["cooked_asset_extensions_looked_for"]),
                    content["cooked_asset_count"]))
    lines.append("")
    lines.append("VERDICT: %s -- %d of %d entries encrypted; %d payload entries "
                 "readable within D-02; %d payloads read"
                 % (summary["verdict"], summary["entries_encrypted"],
                    summary["entries_total"], summary["readable_payload_entries"],
                    document["readable_within_d02"]["payloads_read_by_this_run"]))
    lines.append("probes agree: %s" % summary["probes_agree"])
    if document["warnings"]:
        lines.append("")
        lines.append("warnings:")
        for warning in document["warnings"]:
            lines.append("  %s" % warning)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read a UE 5.4 pak index read-only: per-entry encryption flag, "
                    "path list, and whether any cooked asset is readable.")
    parser.add_argument("path", help="the .pak file to read")
    parser.add_argument("--json", action="store_true", help="print the whole document")
    parser.add_argument("--out", help="write the JSON document here")
    parser.add_argument("--paths-out", help="write the path list here as text")
    parser.add_argument("--literal-samples", type=int, default=DEFAULT_LITERAL_SAMPLES,
                        help="how many encoded records and local headers to record as "
                             "class-P literal reads (default %d)" % DEFAULT_LITERAL_SAMPLES)
    parser.add_argument("--local-header-samples", type=int, default=0,
                        help="how many local entry headers the cross-check reads; "
                             "0 means all of them (default 0)")
    parser.add_argument("--install-dir", help="the installation root, for the "
                                              "output-path guard and the read locus")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.literal_samples < 0:
        print("error: --literal-samples must not be negative", file=sys.stderr)
        return 2
    if args.local_header_samples < 0:
        print("error: --local-header-samples must not be negative", file=sys.stderr)
        return 2

    install_root = args.install_dir or _detect_install_root(args.path)

    # Layer 1 (plan.md 1.5 / D-01) is checked before any parsing, so a refused
    # path costs nothing and leaves nothing behind. write_text checks again.
    checked: dict[str, str] = {}
    for flag, value in (("--out", args.out), ("--paths-out", args.paths_out)):
        if not value:
            continue
        try:
            checked[flag] = pathguard.check_output_path(value, install_root, what=flag)
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2

    try:
        document = analyze(args.path, literal_samples=args.literal_samples,
                           install_root=args.install_dir,
                           local_header_samples=args.local_header_samples)
    except ContainerParseError as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2
    except OSError as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2

    written: list[str] = []
    try:
        if "--out" in checked:
            written.append(write_text(dump_json(_strip_private(document)),
                                      checked["--out"], install_root, "--out"))
        if "--paths-out" in checked:
            if document["summary"]["verdict"] == "BLOCKED":
                print("error: --paths-out asked for a path list but the run is BLOCKED",
                      file=sys.stderr)
                return 2
            body = paths_text(document, document["_entries_for_paths"])
            written.append(write_text(body, checked["--paths-out"], install_root,
                                      "--paths-out"))
    except pathguard.OutputPathRefused as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except OSError as error:
        print("error: cannot write: %s" % error, file=sys.stderr)
        return 2

    if args.json:
        sys.stdout.write(dump_json(_strip_private(document)))
    else:
        print(format_summary(document))
        for out_path in written:
            print("\nwritten: %s" % out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
