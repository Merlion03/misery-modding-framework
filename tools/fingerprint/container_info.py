#!/usr/bin/env python3
"""Read-only parser for IoStore ``.utoc`` headers and legacy ``.pak`` footers (plan.md F-02).

What this tool produces, and why it produces it TWICE
-----------------------------------------------------
plan.md 10.3 grades a claim by its *nature*, not by its oracle, and the canonical
example of a correctly split record is exactly this data: Appendix A row **A-07**
(the bytes) and row **A-07i** (what the bytes are). A-07 is class **P**, OBSERVED,
oracle ``container-metadata``, confidence 0.99, and it is class P only because the
claim states the offset AND the length. A-07i is class **I**, INFERRED, oracle
``container-metadata`` + ``external-doc``, confidence 0.85, because naming a byte
range ``DirectoryIndexSize`` leans on the public ``FIoStoreTocHeader`` layout, which
is an external document about *vanilla* UE and not about this build.

A tool that emitted one flattened dict per container would force every consumer to
re-derive that split by hand, and the plan's own history shows what happens then:
the numbers and the names got averaged into a single OBSERVED 1.00 cell in
``decisions.md``. So this tool emits two parallel structures and never merges them:

``literal_reads``
    One record per read, carrying ``target``, ``offset``, ``length``, ``bytes_hex``
    and a ready-to-cite ``claim`` sentence that names the offset and the length and
    stops there. This is class-P material. The sentence deliberately does NOT name
    what the bytes are; the join key ``decoded_field`` is a pointer into the other
    layer, not part of the claim.

``containers``
    One record per container file, in the shape of
    ``research/schema/fingerprint.schema.json#/$defs/container_entry``, so that
    task F-03 can splice the array into ``fingerprint.json`` verbatim. This is the
    class-I layer: it names fields and interprets values.

A consumer can cite ``literal_reads`` without dragging any interpretation along,
which is the whole point of the exercise.

Grading is computed, not asserted
---------------------------------
The class-I annotation attached to each container is 0.85 only when a **second,
independent** method actually confirmed the layout, and 0.79 otherwise. The second
method is the layout arithmetic: with the field meanings assumed, the whole file is
accounted for as

    TocHeaderSize
  + TocEntryCount * 12                         (FIoChunkId)
  + TocEntryCount * 10                         (FIoOffsetAndLength)
  + TocChunkPerfectHashSeedsCount * 4          (version >= 4)
  + TocChunksWithoutPerfectHashCount * 4       (version >= 5)
  + TocCompressedBlockEntryCount * TocCompressedBlockEntrySize
  + CompressionMethodNameCount * CompressionMethodNameLength
  + signature block                            (only when the Signed flag is set)
  + DirectoryIndexSize
  + TocEntryCount * sizeof(FIoStoreTocEntryMeta)

and the total is compared with the size on disk. An exact match is a real,
independent corroboration: twenty-odd numbers read at fixed offsets have to close
to the byte against a size obtained from the filesystem, which a misread field or a
wrong layout would break. A mismatch is reported as a warning and the confidence
drops -- the tool never adjusts itself until it agrees.

Safety properties (decisions D-01 and D-02)
-------------------------------------------
* Every container is opened ``"rb"`` and only ever read. Nothing in the game folder
  is created, modified, moved or deleted.
* The only path this tool writes is ``--out``, and it goes through the shared guard
  ``tools/inventory/pathguard.check_output_path`` before any file is opened. The
  guard is imported, never reimplemented: an inline copy built on ``abspath`` is how
  a junction bypass got in once.
* **D-02: the encryption key is never extracted and no container content is ever
  decrypted.** The directory index of ``MISERY-Windows.utoc`` carries the Encrypted
  flag. This tool performs one bounded *plaintext plausibility probe* at the
  directory-index offset -- it reads the first bytes and asks whether they parse as
  an ``FString`` mount point -- and when they do not, it records
  ``directory_index_readable: false`` with a reason. That is a read, not an attack:
  no key is derived, guessed or applied.

Memory (plan.md F-04)
---------------------
Parsing a header touches 144 bytes; the whole read budget for one container is a few
kilobytes. The 4.3 GB ``MISERY-Windows.ucas`` is **not opened at all** unless the
caller asks for ``--hash`` (whole-file sha256) or ``--ucas-entropy-bytes`` (a bounded
prefix sample). Both stream through a single reused 1 MiB buffer via ``readinto``, so
peak additional memory is the buffer regardless of file size.

Determinism
-----------
Sorted keys, indent 2, LF, UTF-8 without BOM, trailing newline. Two runs over an
unchanged tree differ only in ``generated_at``.

Standard library only. These parsers must run on a bare CPython on a fresh clone,
before anything is installed.

Layout sources
--------------
The field offsets below are the public ``FIoStoreTocHeader`` and ``FPakInfo``
layouts of UE 5.x. That is the ``external-doc`` oracle, and per plan.md 10.5 it
proves how the format works in *vanilla* UE and nothing about this build. It is why
the decoded layer is capped at 0.85 and why the literal layer exists separately.

CLI
---
    python tools/fingerprint/container_info.py --out <path under the repository>

Exit codes: 0 ok, 2 refused/failed (bad arguments, refused ``--out``, unreadable
tree). A container that fails to parse does not fail the run: it is emitted with a
``parse_error`` and counted, because "this file did not parse" is itself a finding.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import struct
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_INVENTORY = os.path.join(os.path.dirname(_HERE), "inventory")
if _INVENTORY not in sys.path:
    sys.path.insert(0, _INVENTORY)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never inlined.
import pathguard  # noqa: E402  (sys.path is prepared just above)

GENERATOR_NAME = "tools/fingerprint/container_info.py"
GENERATOR_VERSION = "1.0.0"
SCHEMA_ID = "misery.container-info/1"

DEFAULT_INSTALL_DIR = r"D:\Games\Steam\steamapps\common\MISERY"
PAKS_RELDIR = "MISERY/Content/Paks"

# Bounded streaming buffer, same size and same reason as snapshot_install.py.
DEFAULT_BUFFER_BYTES = 1 << 20

# Confidence values. Both come straight from plan.md Appendix A: A-07 for the
# literal layer, A-07i for the decoded layer. 1.00 is forbidden and so is anything
# above 0.99 (plan.md 10.2 v2.3).
CONFIDENCE_LITERAL = 0.99
CONFIDENCE_DECODED_CORROBORATED = 0.85
CONFIDENCE_DECODED_SINGLE_METHOD = 0.79

# SOURCE_ORACLE_OMITTED -- why the source objects below carry no "oracle" key.
#
# kb-record.schema.json#/$defs/source defines an optional per-source "oracle" and says
# it "lets the linter check that the record-level oracle list is actually backed by
# sources". Populating it makes tools/kb/validate.py treat every source object as a
# whole knowledge-base record, because validate.py MARKER_KEYS contains "oracle" and
# is_record() fires on any dict carrying one. Measured on a fingerprint.json holding
# these annotations: 51 errors with the key, 11 without it, 1 with no evidence at all.
# The 40-error difference is entirely EV-03/EV-04/EV-BUILD/EV-CONF/EV-LEVEL demanded of
# objects that are not records. Fixing that belongs to validate.py or to the schema and
# is out of scope for task F-02, so the oracle is stated in the source's note instead:
# nothing is lost, and a downstream fingerprint.json is not buried in noise.
#
# The 11 that remain are NOT caused by this choice and cannot be avoided from here:
# validate.py also treats each container_entry.evidence annotation as a full record and
# demands claim_type and build_key, two properties that
# kb-record.schema.json#/$defs/annotation does not define and, being
# additionalProperties:false, forbids. That is a standing contradiction between the
# validator and the schema, and it will meet task F-03 head on.
SOURCE_ORACLE_OMITTED = True


# --------------------------------------------------------------------------- #
# IoStore TOC -- public FIoStoreTocHeader layout (UE 5.x)
# --------------------------------------------------------------------------- #

TOC_MAGIC = b"-==--==--==--==-"
TOC_HEADER_SIZE_EXPECTED = 144

# EIoStoreTocVersion, public names for the numbers we gate on. Only the NUMBERS are
# used in code; the names are here so the gating can be read.
#   1 Initial, 2 DirectoryIndex, 3 PartitionSize, 4 PerfectHash,
#   5 PerfectHashWithOverflow, 6 OnDemandMetaData, 7 RemovedOnDemandMetaData,
#   8 ReplaceIoChunkHashWithIoHash
TOC_VERSION_DIRECTORY_INDEX = 2
TOC_VERSION_PARTITION_SIZE = 3
TOC_VERSION_PERFECT_HASH = 4
TOC_VERSION_PERFECT_HASH_WITH_OVERFLOW = 5
TOC_VERSION_IO_HASH_META = 8
# The highest version whose 144-byte header layout this parser was written against.
# A higher byte is parsed anyway -- the bytes are still bytes -- but it raises a
# warning, because a layout change would silently move every field.
TOC_VERSION_MAX_KNOWN = 8

# Sizes of the fixed-width records that follow the header. These are the numbers the
# layout-arithmetic corroboration rests on.
IO_CHUNK_ID_SIZE = 12            # FIoChunkId
IO_OFFSET_AND_LENGTH_SIZE = 10   # FIoOffsetAndLength, 5-byte BE offset + 5-byte BE length
IO_PERFECT_HASH_SEED_SIZE = 4    # int32
IO_CHUNK_META_SIZE_HASH32 = 33   # FIoChunkHash[32] + EIoStoreTocEntryMetaFlags
IO_CHUNK_META_SIZE_IOHASH = 21   # FIoHash[20] + flags, version >= 8

# EIoContainerFlags. The names are also the closed enum of
# fingerprint.schema.json#/$defs/utoc_header/container_flags_decoded, so a bit we do
# not know about must NOT be invented into that array -- it becomes a warning.
IO_CONTAINER_FLAGS = (
    (0x01, "Compressed"),
    (0x02, "Encrypted"),
    (0x04, "Signed"),
    (0x08, "Indexed"),
    (0x10, "OnDemand"),
)
IO_CONTAINER_FLAGS_KNOWN_MASK = 0x1F

# (decoded field name, offset, length, kind). ONE table drives BOTH layers: the
# literal reads take the offset and the length from here, the decoded values take
# the kind. They cannot drift apart because there is nothing to drift.
TOC_HEADER_FIELDS: tuple[tuple[str, int, int, str], ...] = (
    ("toc_magic", 0, 16, "magic"),
    ("version", 16, 1, "u8"),
    ("reserved0", 17, 1, "u8"),
    ("reserved1", 18, 2, "u16"),
    ("toc_header_size", 20, 4, "u32"),
    ("toc_entry_count", 24, 4, "u32"),
    ("toc_compressed_block_entry_count", 28, 4, "u32"),
    ("toc_compressed_block_entry_size", 32, 4, "u32"),
    ("compression_method_name_count", 36, 4, "u32"),
    ("compression_method_name_length", 40, 4, "u32"),
    ("compression_block_size", 44, 4, "u32"),
    ("directory_index_size", 48, 4, "u32"),
    ("partition_count", 52, 4, "u32"),
    ("container_id", 56, 8, "u64hex"),
    ("encryption_key_guid", 64, 16, "guid"),
    ("container_flags", 80, 1, "u8hex"),
    ("reserved3", 81, 1, "u8"),
    ("reserved4", 82, 2, "u16"),
    ("toc_chunk_perfect_hash_seeds_count", 84, 4, "u32"),
    ("partition_size", 88, 8, "u64hex"),
    ("toc_chunks_without_perfect_hash_count", 96, 4, "u32"),
    ("reserved7", 100, 4, "u32"),
    ("reserved8", 104, 40, "u64array"),
)


# --------------------------------------------------------------------------- #
# Legacy pak -- public FPakInfo layout
# --------------------------------------------------------------------------- #

PAK_MAGIC = 0x5A6F12E1

# EPakFileVersion, the numbers this parser gates on:
#   4 IndexEncryption, 7 EncryptionKeyGuid, 8 FNameBasedCompressionMethod,
#   9 FrozenIndex, 10 PathHashIndex, 11 Fnv64BugFix
PAK_VERSION_ENCRYPTION_KEY_GUID = 7
PAK_VERSION_FNAME_BASED_COMPRESSION = 8
PAK_VERSION_FROZEN_INDEX = 9
PAK_VERSION_PATH_HASH_INDEX = 10
PAK_VERSION_MAX_KNOWN = 11

PAK_MAX_NUM_COMPRESSION_METHODS = 5
PAK_COMPRESSION_METHOD_NAME_LEN = 32

# Candidate versions, newest first. The footer size depends on the version, so the
# footer is located by trying each candidate layout and demanding that BOTH the
# magic and the stored version agree with the assumption. Hardcoding one size is
# what plan.md 3.1 warns against ("our parser must not hardcode a single value").
PAK_CANDIDATE_VERSIONS = tuple(range(PAK_VERSION_MAX_KNOWN, 0, -1))

# How much of a pak index is read to recover its header fields. The index of
# MISERY-Windows.pak is 53 KB; only the first hundred bytes are header.
PAK_INDEX_PROBE_BYTES = 4096
# Same, for the plaintext plausibility probe of an IoStore directory index.
TOC_DIRECTORY_INDEX_PROBE_BYTES = 4096
# Longest FString this parser will accept as a mount point before calling the
# buffer implausible. A real mount point is a handful of characters.
MAX_PLAUSIBLE_MOUNT_POINT_CHARS = 1024


class ContainerParseError(Exception):
    """A container could not be parsed. Carries a human-readable reason."""


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hex_bytes(raw: bytes) -> str:
    """Lowercase hex, one space between bytes -- the form read_locus.bytes_hex wants."""
    return " ".join("%02x" % byte for byte in raw)


def relative_posix(root: str, path: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/").replace("\\", "/")


def _ascii_or_none(raw: bytes) -> str | None:
    """Decode *raw* as printable ASCII, or None when it is not printable ASCII."""
    if not all(32 <= byte < 127 for byte in raw):
        return None
    return raw.decode("ascii")


def guid_from_bytes(raw: bytes) -> str:
    """FGuid (four little-endian uint32 A,B,C,D) as 32 lowercase hex characters.

    This is the ``EGuidFormats::Digits`` spelling UE itself prints, and it is one of
    the two forms accepted by fingerprint.schema.json#/$defs/guid.
    """
    if len(raw) != 16:
        raise ValueError("an FGuid is 16 bytes, got %d" % len(raw))
    return "%08x%08x%08x%08x" % struct.unpack("<IIII", raw)


def decode_container_flags(value: int) -> tuple[list[str], int]:
    """(names of the set known bits, mask of the set UNKNOWN bits).

    Unknown bits are returned rather than named: the schema closes
    ``container_flags_decoded`` at five values, so inventing a sixth name would make
    the document invalid and would be a guess besides. The raw value is kept in
    ``container_flags`` regardless, which is why nothing is lost.
    """
    names = [name for bit, name in IO_CONTAINER_FLAGS if value & bit]
    return names, value & ~IO_CONTAINER_FLAGS_KNOWN_MASK


def _read_at(handle, offset: int, length: int, what: str) -> bytes:
    """Read exactly *length* bytes at *offset*, or raise ContainerParseError."""
    if offset < 0 or length < 0:
        raise ContainerParseError("%s: negative offset/length (%d, %d)" % (what, offset, length))
    handle.seek(offset)
    raw = handle.read(length)
    if len(raw) != length:
        raise ContainerParseError(
            "%s: wanted %d bytes at offset %d, got %d (file truncated?)"
            % (what, length, offset, len(raw))
        )
    return raw


def stream_sha256(path: str, buf_size: int = DEFAULT_BUFFER_BYTES) -> str:
    """sha256 of a whole file, one reused bounded buffer, readinto -- no whole-file read."""
    digest = hashlib.sha256()
    buffer = bytearray(buf_size)
    view = memoryview(buffer)
    with open(path, "rb", buffering=0) as handle:
        while True:
            read = handle.readinto(buffer)
            if not read:
                break
            digest.update(view[:read])
    return digest.hexdigest()


def stream_sha1_range(path: str, offset: int, length: int,
                      buf_size: int = DEFAULT_BUFFER_BYTES) -> str | None:
    """sha1 over [offset, offset+length) of *path*, streamed. None when out of range."""
    if offset < 0 or length < 0:
        return None
    digest = hashlib.sha1()
    remaining = length
    buffer = bytearray(min(buf_size, max(length, 1)))
    view = memoryview(buffer)
    with open(path, "rb", buffering=0) as handle:
        handle.seek(offset)
        while remaining > 0:
            read = handle.readinto(view[:min(len(buffer), remaining)])
            if not read:
                return None
            digest.update(view[:read])
            remaining -= read
    return digest.hexdigest()


def stream_entropy(path: str, sample_bytes: int,
                   buf_size: int = DEFAULT_BUFFER_BYTES) -> tuple[float | None, int]:
    """(Shannon entropy in bits/byte over the first *sample_bytes*, bytes actually read).

    A 256-bin histogram is the whole state, so this stays bounded no matter how big
    the sample or the file is. High entropy is CONSISTENT with encryption and proves
    nothing on its own -- the ContainerFlags bit is what carries that claim.
    """
    if sample_bytes <= 0:
        return None, 0
    histogram = [0] * 256
    total = 0
    buffer = bytearray(min(buf_size, sample_bytes))
    view = memoryview(buffer)
    with open(path, "rb", buffering=0) as handle:
        while total < sample_bytes:
            want = min(len(buffer), sample_bytes - total)
            read = handle.readinto(view[:want])
            if not read:
                break
            chunk = bytes(view[:read])
            for byte in chunk:
                histogram[byte] += 1
            total += read
    if total == 0:
        return None, 0
    entropy = 0.0
    for count in histogram:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy, total


# --------------------------------------------------------------------------- #
# literal layer (class P)
# --------------------------------------------------------------------------- #

# plan.md 10.3 class-P criterion 2 makes "the method was re-run and reproduced" MANDATORY
# for the whole 0.80-0.99 band, and tools/kb/validate.py checks that the record SAYS so.
# A record may only say it if it is true, so every literal read really is performed
# twice -- see confirm_literal_reads. These two strings are the two things the tool is
# entitled to say, and which one it uses is decided by the second read, not by the author.
RERUN_CONFIRMED = (
    "Method re-run and reproduced within this run: every range in this group was read "
    "a second time through a second, independently opened file handle and the two "
    "reads agree byte for byte. The limit of that attestation, stated plainly: it is a "
    "re-read of the same file on the same machine, so it catches a transient read, a "
    "seek error and a bookkeeping mistake -- it does not catch reading the wrong file."
)
RERUN_NOT_CONFIRMED = (
    "Method NOT reproduced: the second read of this range disagreed with the first, or "
    "could not be performed. plan.md 10.3 criterion 2 is therefore unmet and this "
    "reading must not be relied on until it is explained."
)


def literal_read(target: str, decoded_field: str, offset: int, raw: bytes,
                 note: str | None = None) -> dict:
    """One class-P record: a literal read at a determinate place, and nothing more.

    ``claim`` is the citable sentence. It states the offset and the length -- which
    plan.md 10.3 v2.4 makes MANDATORY for the container-metadata oracle to be class P
    at all -- and it stops short of naming what the bytes are. ``decoded_field`` is a
    join key into the decoded layer for a consumer that wants both halves; it is not
    part of the claim.
    """
    length = len(raw)
    plural = "byte" if length == 1 else "bytes"
    claim = "%d %s at offset %d of %s are %s" % (
        length, plural, offset, target, hex_bytes(raw))
    return {
        "decoded_field": decoded_field,
        "interpretation_lives_in": (
            "the matching entry of containers[] in the same document -- plan.md 10.3, "
            "the A-07 / A-07i split"),
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
                "method": "F-02",
                "artifact": None,
                "locator": "%s@%d+%d" % (target, offset, length),
                # NOTE: the per-source "oracle" key of
                # kb-record.schema.json#/$defs/source is deliberately NOT set. See
                # SOURCE_ORACLE_OMITTED at the top of this module -- the key is legal
                # in the schema and makes tools/kb/validate.py misread every source
                # object as a whole knowledge-base record, which produced 40 spurious
                # errors on a fingerprint.json carrying these annotations. The oracle
                # is stated in the note instead, and the record-level "oracle" list
                # above is unaffected.
                #
                # The reproduction clause is filled in by confirm_literal_reads once
                # the second read has actually happened. Never pre-filled: an
                # attestation written before the check is a claim about the author's
                # intention, not about the file.
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
            # NEW-07. The note IS the claim, on purpose, and this is the defect the
            # entry in research/unknowns.md measures: tools/kb/validate.py derives the
            # claim class of a REDUCED annotation from this string alone, and
            # plan.md 10.3 v2.4 admits container-metadata into class P only when the
            # claim states a determinate address AND an extent and does not name what
            # the bytes are. The previous note talked ABOUT the record ("the sentence
            # names the offset and the length ...") -- it stated no offset and no
            # length of its own, so the grading saw class I and dragged the 0.99
            # band's two-independent-methods requirement in with it: 60 EV-05 plus 60
            # EV-03 on this tool's own output, one pair per literal read. The pointer
            # to the interpretive half lives in `interpretation_lives_in` above,
            # OUTSIDE the graded object, because naming a structure inside this string
            # is exactly what would disqualify class P.
            "note": ("%s. This record gives the position and the extent, and "
                     "nothing else." % claim),
        },
    }


def confirm_literal_reads(path: str, literals: list[dict], target: str,
                          warnings: list[str]) -> bool:
    """Perform every literal read a SECOND time and stamp the result onto each record.

    This is plan.md 10.3 class-P criterion 2 executed rather than asserted. The second
    pass uses a freshly opened handle and seeks independently, so it does not reuse
    the first pass's file position or buffer. Returns True when every range
    reproduced. On any disagreement the tool does NOT adjust anything: it records the
    failure on the record, warns, and lets the reading stand as unreproduced.
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


def decoded_annotation(target: str, corroborated: bool, corroboration_note: str,
                       corroboration_oracle: str = "filesystem") -> dict:
    """The class-I annotation for a decoded container record.

    INFERRED, therefore class I unconditionally (plan.md 10.3 v2.3), whatever the
    offsets are. 0.85 only when the layout arithmetic actually closed, because
    plan.md 10.3 wants two independent methods from 0.80 up and one of them has to be
    something other than re-reading the same bytes.
    """
    # The per-source "oracle" key is omitted on purpose -- see SOURCE_ORACLE_OMITTED.
    sources = [{
        "method": "F-02",
        "artifact": None,
        "locator": target,
        "note": ("oracle container-metadata + external-doc. Field decode against the "
                 "public FIoStoreTocHeader / FPakInfo layout."),
    }]
    oracles = ["container-metadata", "external-doc"]
    if corroborated:
        sources.append({
            "method": "F-02",
            "artifact": None,
            "locator": target,
            "independent_of": ["F-02/field-decode"],
            "note": ("oracle %s. Second, independent method: %s"
                     % (corroboration_oracle, corroboration_note)),
        })
        if corroboration_oracle not in oracles:
            # The record-level oracle list must be backed by the sources; a second
            # method on an oracle the record does not name would be uncheckable.
            oracles.append(corroboration_oracle)
    return {
        "evidence_level": "INFERRED",
        "claim_class": "I",
        "confidence": (CONFIDENCE_DECODED_CORROBORATED if corroborated
                       else CONFIDENCE_DECODED_SINGLE_METHOD),
        "oracle": sorted(oracles),
        "sources": sources,
        "read_locus": None,
        "note": (
            "Interpretive: this record NAMES the byte ranges and decodes them, which "
            "leans on the public UE layout (external-doc -- proves vanilla UE, not "
            "this build). The primitive half is in literal_reads[]. %s"
            % corroboration_note
        ),
    }


# --------------------------------------------------------------------------- #
# IoStore .utoc
# --------------------------------------------------------------------------- #

def decode_toc_header_fields(header: bytes) -> dict:
    """Decode the 144-byte header into the field names of the schema.

    *header* must be at least 144 bytes. Nothing here is version dependent: the
    header is a fixed-size struct, and every member is present whatever the version
    is -- older versions simply leave the later ones zero. Version gating belongs to
    the BODY layout, where a missing array really does move everything after it.
    """
    values: dict = {}
    for name, offset, length, kind in TOC_HEADER_FIELDS:
        raw = header[offset:offset + length]
        if kind == "magic":
            values[name] = _ascii_or_none(raw)
        elif kind == "u8":
            values[name] = raw[0]
        elif kind == "u8hex":
            values[name] = "0x%02x" % raw[0]
        elif kind == "u16":
            values[name] = struct.unpack("<H", raw)[0]
        elif kind == "u32":
            values[name] = struct.unpack("<I", raw)[0]
        elif kind == "u64hex":
            values[name] = "0x%016x" % struct.unpack("<Q", raw)[0]
        elif kind == "guid":
            values[name] = guid_from_bytes(raw)
        elif kind == "u64array":
            values[name] = ["0x%016x" % word
                            for word in struct.unpack("<%dQ" % (length // 8), raw)]
        else:  # pragma: no cover - the table is a literal, this cannot happen
            raise AssertionError("unknown field kind %r" % kind)
    return values


def toc_body_layout(values: dict, version: int) -> dict:
    """Offsets and sizes of everything that follows the header, per *version*.

    Returns a dict with the section sizes, the offsets of the two sections this tool
    actually reads (the compression method table and the directory index), and
    ``total`` -- the size the whole file must have if every field means what the
    public layout says it means. ``total`` is the corroboration.

    Version gating (EIoStoreTocVersion):
      * < 4 (PerfectHash): no perfect-hash seed array.
      * < 5 (PerfectHashWithOverflow): no overflow array.
      * >= 8 (ReplaceIoChunkHashWithIoHash): FIoStoreTocEntryMeta shrinks from a
        32-byte hash to a 20-byte FIoHash.
    A version above TOC_VERSION_MAX_KNOWN is computed with the newest rules known
    here and flagged by the caller, never silently.
    """
    entry_count = values["toc_entry_count"]
    header_size = values["toc_header_size"]
    seeds = (values["toc_chunk_perfect_hash_seeds_count"]
             if version >= TOC_VERSION_PERFECT_HASH else 0)
    overflow = (values["toc_chunks_without_perfect_hash_count"]
                if version >= TOC_VERSION_PERFECT_HASH_WITH_OVERFLOW else 0)
    meta_size = (IO_CHUNK_META_SIZE_IOHASH if version >= TOC_VERSION_IO_HASH_META
                 else IO_CHUNK_META_SIZE_HASH32)

    sections: list[tuple[str, int]] = [
        ("chunk_ids", entry_count * IO_CHUNK_ID_SIZE),
        ("chunk_offset_lengths", entry_count * IO_OFFSET_AND_LENGTH_SIZE),
        ("perfect_hash_seeds", seeds * IO_PERFECT_HASH_SEED_SIZE),
        ("chunks_without_perfect_hash", overflow * IO_PERFECT_HASH_SEED_SIZE),
        ("compression_blocks", (values["toc_compressed_block_entry_count"]
                                * values["toc_compressed_block_entry_size"])),
        ("compression_method_names", (values["compression_method_name_count"]
                                      * values["compression_method_name_length"])),
    ]

    offset = header_size
    offsets: dict[str, int] = {}
    for name, size in sections:
        offsets[name] = offset
        offset += size

    # The signature block sits between the method names and the directory index and
    # only exists when the Signed flag is set. Its size depends on a hash size stored
    # in the file, so it is left as None here and resolved by the caller, which has
    # the file handle. Our containers are not signed.
    flags_value = int(values["container_flags"], 16)
    signed = bool(flags_value & 0x04)

    return {
        "sections": dict(sections),
        "offsets": offsets,
        "signed": signed,
        "meta_size": meta_size,
        "directory_index_offset": offset,      # valid only when not signed
        "directory_index_size": values["directory_index_size"],
        "chunk_metas_size": entry_count * meta_size,
        "total": offset + values["directory_index_size"] + entry_count * meta_size,
    }


def split_method_name_table(raw: bytes, count: int, slot_length: int,
                            warnings: list[str], target: str, what: str) -> list[str]:
    """Split a fixed-slot compression-method-name table. Empty slots are dropped."""
    names = []
    for index in range(count):
        slot = raw[index * slot_length:(index + 1) * slot_length]
        text = slot.split(b"\x00", 1)[0]
        if not text:
            continue
        decoded = _ascii_or_none(text)
        if decoded is None:
            warnings.append("%s: %s slot %d is not printable ASCII (%s)"
                            % (target, what, index, hex_bytes(slot[:16])))
            continue
        names.append(decoded)
    return names


def probe_fstring(buffer: bytes) -> tuple[str | None, str]:
    """Try to read an FString from the start of *buffer*. Returns (value, reason).

    Used as a PLAINTEXT PLAUSIBILITY PROBE, not as a decryption attempt (D-02):
    ciphertext will not parse as a length-prefixed, NUL-terminated printable string,
    so a failure here is exactly the evidence that the region is not plaintext.
    Positive length = ASCII including the terminator; negative = UTF-16, character
    count including the terminator.
    """
    if len(buffer) < 4:
        return None, "fewer than 4 bytes available"
    (length,) = struct.unpack_from("<i", buffer, 0)
    if length == 0:
        return "", "empty string"
    if abs(length) > MAX_PLAUSIBLE_MOUNT_POINT_CHARS:
        return None, ("leading int32 is %d, which is not a plausible string length "
                      "(limit %d)" % (length, MAX_PLAUSIBLE_MOUNT_POINT_CHARS))
    if length > 0:
        need = length
        if len(buffer) < 4 + need:
            return None, "buffer too short for the declared %d-byte string" % need
        raw = buffer[4:4 + need]
        if not raw.endswith(b"\x00"):
            return None, "declared ASCII string is not NUL terminated"
        text = _ascii_or_none(raw[:-1])
        if text is None:
            return None, "declared ASCII string is not printable ASCII"
        return text, "ok"
    need = (-length) * 2
    if len(buffer) < 4 + need:
        return None, "buffer too short for the declared %d-byte UTF-16 string" % need
    raw = buffer[4:4 + need]
    if not raw.endswith(b"\x00\x00"):
        return None, "declared UTF-16 string is not NUL terminated"
    try:
        text = raw[:-2].decode("utf-16-le")
    except UnicodeDecodeError:
        return None, "declared UTF-16 string does not decode"
    if any(ord(char) < 32 for char in text):
        return None, "declared UTF-16 string contains control characters"
    return text, "ok"


def parse_utoc(path: str, target: str, warnings: list[str]) -> tuple[dict, list[dict], dict]:
    """Parse one ``.utoc``. Returns (utoc block, literal reads, diagnostics).

    Raises ContainerParseError when the file is not a TOC at all or is too short to
    hold a header -- those are the two cases where continuing would mean inventing
    numbers. A version we do not recognise is a WARNING, not an error: the bytes are
    still bytes, and refusing to record them would lose the very observation that
    tells us the format moved.
    """
    diagnostics: dict = {"parse_error": None}
    file_size = os.path.getsize(path)
    literals: list[dict] = []

    with open(path, "rb", buffering=0) as handle:
        if file_size < TOC_HEADER_SIZE_EXPECTED:
            raise ContainerParseError(
                "file is %d bytes, shorter than the %d-byte FIoStoreTocHeader"
                % (file_size, TOC_HEADER_SIZE_EXPECTED))
        header = _read_at(handle, 0, TOC_HEADER_SIZE_EXPECTED, "%s header" % target)

        if header[:16] != TOC_MAGIC:
            # Emit the magic read anyway: "the 16 bytes at offset 0 are <not the
            # magic>" is a perfectly good class-P observation, and it is the evidence
            # for the refusal.
            raise ContainerParseError(
                "bad TOC magic: 16 bytes at offset 0 are %s, expected %s (%r)"
                % (hex_bytes(header[:16]), hex_bytes(TOC_MAGIC), TOC_MAGIC.decode("ascii")))

        values = decode_toc_header_fields(header)
        for name, offset, length, _kind in TOC_HEADER_FIELDS:
            literals.append(literal_read(target, name, offset, header[offset:offset + length]))

        version = values["version"]
        if version > TOC_VERSION_MAX_KNOWN or version < 1:
            warnings.append(
                "%s: TOC version byte is %d; this parser was written against versions "
                "1..%d, so the decoded field names may be wrong. The literal reads are "
                "unaffected." % (target, version, TOC_VERSION_MAX_KNOWN))
        if values["toc_header_size"] != TOC_HEADER_SIZE_EXPECTED:
            warnings.append(
                "%s: TocHeaderSize is %d, not %d. Every field offset in this parser "
                "assumes the %d-byte layout, so the decoded values are suspect; the "
                "literal reads are unaffected."
                % (target, values["toc_header_size"], TOC_HEADER_SIZE_EXPECTED,
                   TOC_HEADER_SIZE_EXPECTED))

        flags_value = int(values["container_flags"], 16)
        flag_names, unknown_bits = decode_container_flags(flags_value)
        if unknown_bits:
            warnings.append(
                "%s: ContainerFlags 0x%02x carries unknown bit(s) 0x%02x; they are kept "
                "in the raw value but cannot be named (the schema enum is closed)"
                % (target, flags_value, unknown_bits))

        layout = toc_body_layout(values, version)

        # --- compression method names -------------------------------------
        methods_offset = layout["offsets"]["compression_method_names"]
        method_count = values["compression_method_name_count"]
        slot_length = values["compression_method_name_length"]
        methods: list[str] = []
        table_bytes = method_count * slot_length
        if method_count > 0 and slot_length > 0:
            # A sane table is a handful of 32-byte slots; refuse an absurd one rather
            # than allocating whatever the file asks for.
            if table_bytes > (1 << 20):
                warnings.append("%s: compression method table claims %d bytes, refusing "
                                "to read it" % (target, table_bytes))
            elif methods_offset + table_bytes > file_size:
                warnings.append("%s: compression method table [%d, +%d) would end past "
                                "the %d-byte EOF" % (target, methods_offset, table_bytes,
                                                     file_size))
            else:
                raw_table = _read_at(handle, methods_offset, table_bytes,
                                     "%s compression method table" % target)
                methods = split_method_name_table(
                    raw_table, method_count, slot_length, warnings, target,
                    "compression method")
                literals.append(literal_read(
                    target, "compression_method_names", methods_offset, raw_table,
                    note="fixed %d-byte slots, %d of them" % (slot_length, method_count)))

        # --- signature block, only when Signed ----------------------------
        directory_index_offset = layout["directory_index_offset"]
        signature_size = 0
        if layout["signed"]:
            sig_offset = methods_offset + method_count * slot_length
            try:
                raw = _read_at(handle, sig_offset, 4, "%s signature size" % target)
                hash_size = struct.unpack("<i", raw)[0]
                blocks = values["toc_compressed_block_entry_count"]
                signature_size = 4 + hash_size * 2 + blocks * hash_size
                directory_index_offset = sig_offset + signature_size
                literals.append(literal_read(target, "signature_hash_size", sig_offset, raw))
            except ContainerParseError as error:
                warnings.append("%s: Signed flag set but the signature block could not "
                                "be measured: %s" % (target, error))
                directory_index_offset = None

        # --- layout arithmetic: the independent corroboration --------------
        computed_total = None
        layout_matches = False
        if directory_index_offset is not None:
            computed_total = (directory_index_offset + values["directory_index_size"]
                              + layout["chunk_metas_size"])
            layout_matches = computed_total == file_size
        if computed_total is not None and not layout_matches:
            warnings.append(
                "%s: layout arithmetic does not close -- header+sections+index+metas = "
                "%d but the file is %d bytes (difference %+d). The field meanings are "
                "therefore NOT independently corroborated for this container."
                % (target, computed_total, file_size, computed_total - file_size))

        # --- directory index: presence, and a plaintext probe (D-02) -------
        directory_index_size = values["directory_index_size"]
        indexed = "Indexed" in flag_names
        encrypted = "Encrypted" in flag_names
        has_directory_index = bool(indexed and directory_index_size > 0)
        directory_index_readable = False
        mount_point = None
        index_note_parts: list[str] = []

        if not has_directory_index:
            index_note_parts.append(
                "no directory index (Indexed=%s, DirectoryIndexSize=%d)"
                % (indexed, directory_index_size))
        elif directory_index_offset is None:
            index_note_parts.append("directory index offset unknown (signature block "
                                    "could not be measured)")
        elif encrypted:
            # D-02. We do NOT decrypt. We do read the first bytes and record that they
            # do not parse as plaintext, which is an observation and not an attack.
            probe_len = min(TOC_DIRECTORY_INDEX_PROBE_BYTES, directory_index_size)
            try:
                probe = _read_at(handle, directory_index_offset, probe_len,
                                 "%s directory index probe" % target)
            except ContainerParseError as error:
                probe = b""
                index_note_parts.append("directory index probe failed: %s" % error)
            if probe:
                literals.append(literal_read(
                    target, "directory_index_first_bytes", directory_index_offset,
                    probe[:16],
                    note="first bytes of the directory index region; read only, never decrypted"))
                _value, reason = probe_fstring(probe)
                index_note_parts.append(
                    "directory index carries the Encrypted flag and is NOT read: "
                    "decision D-02 forbids extracting the key or decrypting container "
                    "content. Plaintext plausibility probe at offset %d says: %s. "
                    "The %d bytes of the index are recorded as present and unreadable."
                    % (directory_index_offset, reason, directory_index_size))
                if directory_index_size % 16 == 0:
                    index_note_parts.append(
                        "index size %d is a multiple of 16, consistent with AES block "
                        "padding (consistent with, not proof of)" % directory_index_size)
        else:
            probe_len = min(TOC_DIRECTORY_INDEX_PROBE_BYTES, directory_index_size)
            probe = _read_at(handle, directory_index_offset, probe_len,
                             "%s directory index" % target)
            literals.append(literal_read(
                target, "directory_index_first_bytes", directory_index_offset, probe[:16]))
            value, reason = probe_fstring(probe)
            if value is None:
                index_note_parts.append(
                    "directory index is not flagged Encrypted but does not parse as "
                    "plaintext: %s" % reason)
            else:
                directory_index_readable = True
                mount_point = value

    utoc = {
        "toc_magic": values["toc_magic"],
        "version": values["version"],
        "reserved0": values["reserved0"],
        "reserved1": values["reserved1"],
        "toc_header_size": values["toc_header_size"],
        "toc_entry_count": values["toc_entry_count"],
        "toc_compressed_block_entry_count": values["toc_compressed_block_entry_count"],
        "toc_compressed_block_entry_size": values["toc_compressed_block_entry_size"],
        "compression_method_name_count": values["compression_method_name_count"],
        "compression_method_name_length": values["compression_method_name_length"],
        "compression_block_size": values["compression_block_size"],
        "directory_index_size": values["directory_index_size"],
        "partition_count": values["partition_count"],
        "container_id": values["container_id"],
        "encryption_key_guid": values["encryption_key_guid"],
        "container_flags": values["container_flags"],
        "container_flags_decoded": flag_names,
        "reserved3": values["reserved3"],
        "reserved4": values["reserved4"],
        "toc_chunk_perfect_hash_seeds_count": values["toc_chunk_perfect_hash_seeds_count"],
        "partition_size": values["partition_size"],
        "toc_chunks_without_perfect_hash_count":
            values["toc_chunks_without_perfect_hash_count"],
        "reserved7": values["reserved7"],
        "reserved8": values["reserved8"],
        "compression_method_names": methods,
        "is_encrypted": encrypted,
        "has_directory_index": has_directory_index,
        "directory_index_readable": directory_index_readable,
        "mount_point": mount_point,
        "body_entropy": None,
    }
    diagnostics.update({
        "layout_total_computed": computed_total,
        "layout_total_matches_file_size": layout_matches,
        "directory_index_offset": directory_index_offset,
        "compression_method_table_offset": methods_offset,
        "signature_block_size": signature_size,
        "index_notes": index_note_parts,
        "file_size": file_size,
    })
    return utoc, literals, diagnostics


# --------------------------------------------------------------------------- #
# legacy .pak
# --------------------------------------------------------------------------- #

def pak_footer_size(version: int) -> int:
    """Serialized size of FPakInfo for *version*, mirroring FPakInfo::GetSerializedSize."""
    size = 4 + 4 + 8 + 8 + 20 + 1  # magic, version, index offset, index size, hash, flag
    if version >= PAK_VERSION_ENCRYPTION_KEY_GUID:
        size += 16
    if version == PAK_VERSION_FROZEN_INDEX:
        size += 1
    if version >= PAK_VERSION_FNAME_BASED_COMPRESSION:
        size += PAK_MAX_NUM_COMPRESSION_METHODS * PAK_COMPRESSION_METHOD_NAME_LEN
    return size


def pak_footer_field_offsets(version: int) -> list[tuple[str, int, int]]:
    """(name, offset within the footer, length) for *version*, in file order."""
    fields: list[tuple[str, int, int]] = []
    offset = 0
    if version >= PAK_VERSION_ENCRYPTION_KEY_GUID:
        fields.append(("encryption_key_guid", offset, 16))
        offset += 16
    fields.append(("encrypted_index", offset, 1))
    offset += 1
    fields.append(("magic", offset, 4))
    offset += 4
    fields.append(("pak_version", offset, 4))
    offset += 4
    fields.append(("index_offset", offset, 8))
    offset += 8
    fields.append(("index_size", offset, 8))
    offset += 8
    fields.append(("index_hash", offset, 20))
    offset += 20
    if version == PAK_VERSION_FROZEN_INDEX:
        fields.append(("index_is_frozen", offset, 1))
        offset += 1
    if version >= PAK_VERSION_FNAME_BASED_COMPRESSION:
        fields.append(("compression_methods", offset,
                       PAK_MAX_NUM_COMPRESSION_METHODS * PAK_COMPRESSION_METHOD_NAME_LEN))
    return fields


def locate_pak_footer(handle, file_size: int) -> tuple[int, int, int, bytes]:
    """Find the footer by trying each candidate version's layout, newest first.

    Returns (version, footer offset, footer size, footer bytes). A candidate is
    accepted only when the magic AND the stored version both agree with the assumed
    layout, so a stray 0x5A6F12E1 in the tail cannot win and a footer of the wrong
    size cannot be read as the right one. The footer size is version dependent and is
    never hardcoded (plan.md 3.1: "our parser must not hardcode a single value").
    """
    tried: list[str] = []
    for version in PAK_CANDIDATE_VERSIONS:
        size = pak_footer_size(version)
        if size > file_size:
            continue
        offset = file_size - size
        handle.seek(offset)
        raw = handle.read(size)
        if len(raw) != size:
            continue
        fields = dict((name, rel) for name, rel, _length in
                      pak_footer_field_offsets(version))
        (magic,) = struct.unpack_from("<I", raw, fields["magic"])
        (stored_version,) = struct.unpack_from("<i", raw, fields["pak_version"])
        tried.append("v%d@%d: magic=0x%08x version=%d"
                     % (version, offset, magic, stored_version))
        if magic == PAK_MAGIC and stored_version == version:
            return version, offset, size, raw
    raise ContainerParseError(
        "no pak footer found. Tried every known version layout: %s" % "; ".join(tried))


def parse_pak_index_header(raw: bytes, version: int) -> tuple[dict, list[tuple[str, int, int]]]:
    """Decode the primary index header. Returns (values, (name, rel offset, length) list).

    Layout (FPakFile::LoadIndexInternal): FString MountPoint, int32 NumEntries, and
    from version 10 (PathHashIndex) onwards uint64 PathHashSeed, a bool+block for the
    path hash index and a bool+block for the full directory index.
    """
    reads: list[tuple[str, int, int]] = []
    values: dict = {
        "mount_point": None,
        "num_entries": None,
        "path_hash_seed": None,
        "has_path_hash_index": None,
        "has_full_directory_index": None,
        # Where the two secondary indexes live. They have no home in
        # fingerprint.schema.json#/$defs/pak_footer, so they never reach the decoded
        # layer -- they exist so the layout arithmetic can close on the file size.
        "sub_index_blocks": [],
    }
    if len(raw) < 4:
        raise ContainerParseError("pak index shorter than 4 bytes")
    (length,) = struct.unpack_from("<i", raw, 0)
    mount, reason = probe_fstring(raw)
    if mount is None:
        raise ContainerParseError("pak index mount point does not parse: %s" % reason)
    consumed = 4 + (length if length > 0 else (-length) * 2)
    reads.append(("mount_point", 0, consumed))
    values["mount_point"] = mount

    offset = consumed
    if len(raw) < offset + 4:
        raise ContainerParseError("pak index truncated before NumEntries")
    values["num_entries"] = struct.unpack_from("<i", raw, offset)[0]
    reads.append(("num_entries", offset, 4))
    offset += 4

    if version >= PAK_VERSION_PATH_HASH_INDEX:
        if len(raw) < offset + 8:
            raise ContainerParseError("pak index truncated before PathHashSeed")
        values["path_hash_seed"] = "0x%016x" % struct.unpack_from("<Q", raw, offset)[0]
        reads.append(("path_hash_seed", offset, 8))
        offset += 8
        for name in ("has_path_hash_index", "has_full_directory_index"):
            if len(raw) < offset + 4:
                raise ContainerParseError("pak index truncated before %s" % name)
            present = struct.unpack_from("<i", raw, offset)[0]
            values[name] = bool(present)
            reads.append((name, offset, 4))
            offset += 4
            if present:
                if len(raw) < offset + 36:
                    raise ContainerParseError("pak index truncated inside the %s block" % name)
                sub_offset, sub_size = struct.unpack_from("<qq", raw, offset)
                values["sub_index_blocks"].append(
                    {"name": name, "offset": sub_offset, "size": sub_size})
                offset += 8 + 8 + 20  # int64 offset, int64 size, FSHAHash[20]
    return values, reads


def parse_pak(path: str, target: str, warnings: list[str],
              verify_index_hash: bool) -> tuple[dict, list[dict], dict]:
    """Parse one ``.pak`` footer and, when the index is plaintext, its index header."""
    diagnostics: dict = {"parse_error": None}
    file_size = os.path.getsize(path)
    literals: list[dict] = []

    with open(path, "rb", buffering=0) as handle:
        version, footer_offset, footer_size, raw = locate_pak_footer(handle, file_size)
        fields = pak_footer_field_offsets(version)

        values: dict = {
            "magic": None, "pak_version": None, "index_offset": None, "index_size": None,
            "index_hash": None, "encrypted_index": None, "encryption_key_guid": None,
            "compression_methods": None, "index_is_frozen": None,
        }
        for name, rel, length in fields:
            chunk = raw[rel:rel + length]
            literals.append(literal_read(target, name, footer_offset + rel, chunk,
                                         note="inside the %d-byte v%d pak footer at %d"
                                              % (footer_size, version, footer_offset)))
            if name == "encryption_key_guid":
                values[name] = guid_from_bytes(chunk)
            elif name == "encrypted_index":
                values[name] = bool(chunk[0])
                if chunk[0] not in (0, 1):
                    warnings.append("%s: bEncryptedIndex byte is 0x%02x, not 0 or 1"
                                    % (target, chunk[0]))
            elif name == "magic":
                values[name] = "0x%08x" % struct.unpack("<I", chunk)[0]
            elif name == "pak_version":
                values[name] = struct.unpack("<i", chunk)[0]
            elif name in ("index_offset", "index_size"):
                values[name] = struct.unpack("<q", chunk)[0]
            elif name == "index_hash":
                values[name] = chunk.hex()
            elif name == "index_is_frozen":
                values[name] = bool(chunk[0])
            elif name == "compression_methods":
                values[name] = split_method_name_table(
                    chunk, PAK_MAX_NUM_COMPRESSION_METHODS,
                    PAK_COMPRESSION_METHOD_NAME_LEN, warnings, target,
                    "pak compression method")

        if version < PAK_VERSION_PATH_HASH_INDEX:
            warnings.append(
                "%s: pak version %d predates the path-hash index (version %d), so "
                "path_hash_seed / has_path_hash_index / has_full_directory_index are "
                "null because the format has no such fields, not because they failed "
                "to read" % (target, version, PAK_VERSION_PATH_HASH_INDEX))

        index_offset = values["index_offset"] or 0
        index_size = values["index_size"] or 0
        index_readable = False
        index_notes: list[str] = []
        index_values = {"mount_point": None, "num_entries": None, "path_hash_seed": None,
                        "has_path_hash_index": None, "has_full_directory_index": None,
                        "sub_index_blocks": []}

        if index_offset + index_size > file_size or index_size <= 0:
            index_notes.append("index [%d, +%d) does not lie inside a %d-byte file"
                               % (index_offset, index_size, file_size))
        elif values["encrypted_index"]:
            index_notes.append(
                "bEncryptedIndex is set: the index is NOT read. Decision D-02 forbids "
                "extracting the key or decrypting container content.")
        else:
            probe_len = min(PAK_INDEX_PROBE_BYTES, index_size)
            probe = _read_at(handle, index_offset, probe_len, "%s index header" % target)
            try:
                index_values, index_reads = parse_pak_index_header(probe, version)
                index_readable = True
                for name, rel, length in index_reads:
                    literals.append(literal_read(
                        target, "index." + name, index_offset + rel, probe[rel:rel + length],
                        note="inside the pak index, which starts at offset %d" % index_offset))
            except ContainerParseError as error:
                index_notes.append("index header did not parse: %s" % error)

        # Cross-check 1: the footer stores the sha1 of the index. Recomputing it over
        # the index bytes confirms that index_offset and index_size were read right.
        index_hash_verified = None
        if verify_index_hash and index_size > 0 and index_offset + index_size <= file_size:
            computed = stream_sha1_range(path, index_offset, index_size)
            index_hash_verified = (computed == values["index_hash"])
            if not index_hash_verified:
                warnings.append(
                    "%s: recomputed sha1 of the index at [%d, +%d) is %s but the footer "
                    "stores %s -- they disagree"
                    % (target, index_offset, index_size, computed, values["index_hash"]))

        # Cross-check 2, on a different oracle: with the field meanings assumed, the
        # regions have to tile the file exactly -- primary index, then each secondary
        # index at the offset the previous one ends on, then the footer, then EOF.
        # The size on disk is a filesystem read, so this is a genuinely second source
        # and not a second reading of the same bytes.
        layout_steps: list[str] = []
        layout_closes = None
        if index_readable:
            cursor = index_offset + index_size
            layout_steps.append("index %d+%d ends at %d" % (index_offset, index_size, cursor))
            layout_closes = True
            for block in index_values["sub_index_blocks"]:
                if block["offset"] != cursor:
                    layout_closes = False
                    layout_steps.append("%s starts at %d, expected %d"
                                        % (block["name"], block["offset"], cursor))
                    break
                cursor = block["offset"] + block["size"]
                layout_steps.append("%s %d+%d ends at %d"
                                    % (block["name"], block["offset"], block["size"], cursor))
            if layout_closes:
                if cursor != footer_offset:
                    layout_closes = False
                    layout_steps.append("footer starts at %d, expected %d"
                                        % (footer_offset, cursor))
                else:
                    layout_steps.append("footer %d+%d ends at %d, file is %d bytes"
                                        % (footer_offset, footer_size,
                                           footer_offset + footer_size, file_size))
            if not layout_closes:
                warnings.append("%s: pak region layout does not tile the file -- %s"
                                % (target, "; ".join(layout_steps)))

    pak = {
        "magic": values["magic"],
        "pak_version": values["pak_version"],
        "footer_offset": footer_offset,
        "footer_size": footer_size,
        "index_offset": values["index_offset"],
        "index_size": values["index_size"],
        "index_hash": values["index_hash"],
        "encrypted_index": values["encrypted_index"],
        "encryption_key_guid": values["encryption_key_guid"],
        "compression_methods": values["compression_methods"],
        "mount_point": index_values["mount_point"],
        "num_entries": index_values["num_entries"],
        "path_hash_seed": index_values["path_hash_seed"],
        "has_path_hash_index": index_values["has_path_hash_index"],
        "has_full_directory_index": index_values["has_full_directory_index"],
        "index_is_frozen": values["index_is_frozen"],
        "index_readable": index_readable,
    }
    diagnostics.update({
        "index_hash_verified": index_hash_verified,
        "layout_tiles_file": layout_closes,
        "layout_steps": layout_steps,
        "sub_index_blocks": index_values["sub_index_blocks"],
        "index_notes": index_notes,
        "file_size": file_size,
    })
    return pak, literals, diagnostics


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #

KIND_BY_SUFFIX = {".utoc": "utoc", ".ucas": "ucas", ".pak": "pak", ".usig": "usig"}


def classify(name: str) -> str:
    return KIND_BY_SUFFIX.get(os.path.splitext(name)[1].lower(), "other")


def find_containers(paks_dir: str) -> list[str]:
    """Absolute paths of every file in *paks_dir*, sorted. Read-only, no recursion
    surprises: containers live flat in Paks/, and a subdirectory is walked too so a
    chunked layout would not be missed."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(paks_dir, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            found.append(os.path.join(dirpath, name))
    return sorted(found)


def sibling_for(relative: str, kind: str, known: set[str]) -> str | None:
    """Paired .ucas for a .utoc and vice versa, when the partner exists."""
    stem, _ = os.path.splitext(relative)
    if kind == "utoc":
        candidate = stem + ".ucas"
    elif kind == "ucas":
        candidate = stem + ".utoc"
    else:
        return None
    return candidate if candidate in known else None


def load_inventory_hashes(path: str) -> dict[str, dict]:
    """{relative path: row} from an install-inventory.json, so sizes and sha256 can be
    reused instead of rehashing 4.3 GB that snapshot_install already hashed."""
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    rows = document.get("files") or []
    return {row["path"]: row for row in rows if isinstance(row, dict) and "path" in row}


def build_document(install_dir: str, paks_dir: str | None = None,
                   inventory_path: str | None = None, hash_files: bool = False,
                   ucas_entropy_bytes: int = 0, verify_index_hash: bool = True,
                   buf_size: int = DEFAULT_BUFFER_BYTES,
                   entry_evidence: bool = True) -> dict:
    """Scan the Paks directory and produce the two-layer document.

    *entry_evidence* controls only the annotation attached to each ``containers[]``
    entry -- see SOURCE_ORACLE_OMITTED for why a consumer might want it off. The
    class-P ``literal_reads[]`` layer always carries its evidence: dropping that would
    defeat the purpose of the tool.
    """
    install_dir = os.path.abspath(install_dir)
    if paks_dir is None:
        paks_dir = os.path.join(install_dir, *PAKS_RELDIR.split("/"))
    if not os.path.isdir(paks_dir):
        raise OSError("not a directory: %s" % paks_dir)

    inventory = load_inventory_hashes(inventory_path) if inventory_path else {}
    warnings: list[str] = []
    paths = find_containers(paks_dir)
    relatives = {relative_posix(install_dir, path) for path in paths}

    containers: list[dict] = []
    literal_groups: list[dict] = []
    checks: list[dict] = []

    for path in paths:
        relative = relative_posix(install_dir, path)
        kind = classify(os.path.basename(path))
        size = os.path.getsize(path)

        sha256 = None
        if hash_files:
            sha256 = stream_sha256(path, buf_size=buf_size)
        elif relative in inventory:
            sha256 = inventory[relative].get("sha256")
            recorded = inventory[relative].get("size")
            if recorded is not None and recorded != size:
                warnings.append(
                    "%s: size on disk is %d but the inventory records %d -- the "
                    "inventory is stale, so its sha256 was NOT copied"
                    % (relative, size, recorded))
                sha256 = None

        entry: dict = {
            "path": relative,
            "kind": kind,
            "size": size,
            "sha256": sha256,
            "sibling_path": sibling_for(relative, kind, relatives),
            "utoc": None,
            "pak": None,
            "evidence": None,
            "notes": None,
        }
        note_parts: list[str] = []
        literals: list[dict] = []
        diagnostics: dict = {}
        corroborated = False
        corroboration_note = ""
        corroboration_oracle = "filesystem"
        extra_checks: list[dict] = []

        try:
            if kind == "utoc":
                entry["utoc"], literals, diagnostics = parse_utoc(path, relative, warnings)
                corroborated = bool(diagnostics.get("layout_total_matches_file_size"))
                corroboration_note = (
                    "header + chunk ids + offset/lengths + perfect-hash arrays + "
                    "compression blocks + method table + directory index + chunk metas "
                    "= %s, file size = %d%s"
                    % (diagnostics.get("layout_total_computed"), size,
                       "" if corroborated else " (MISMATCH)"))
                note_parts.extend(diagnostics.get("index_notes") or [])
            elif kind == "pak":
                entry["pak"], literals, diagnostics = parse_pak(
                    path, relative, warnings, verify_index_hash)
                verified = diagnostics.get("index_hash_verified")
                tiles = diagnostics.get("layout_tiles_file")
                # The independent method is the region tiling, because it closes
                # against a filesystem read (the size on disk). The sha1 recomputation
                # is a strong integrity check but stays on the same oracle, so it is
                # reported separately and does not by itself buy the 0.85.
                corroborated = tiles is True
                corroboration_oracle = "filesystem"
                corroboration_note = (
                    "the pak regions tile the file exactly: %s"
                    % "; ".join(diagnostics.get("layout_steps") or ["not computed"]))
                if verified is not None:
                    # Only reported when it was actually run: a check the caller opted
                    # out of must not be listed as failed.
                    extra_checks.append({
                        "target": relative,
                        "check": "pak_index_sha1_recomputed",
                        "passed": verified,
                        "detail": ("the sha1 the footer stores for the index was "
                                   "recomputed from the index bytes and %s"
                                   % ("matches" if verified else "DOES NOT match")),
                    })
                note_parts.extend(diagnostics.get("index_notes") or [])
            elif kind == "ucas":
                note_parts.append(
                    "IoStore data file: it has no header of its own and is described by "
                    "its paired .utoc. Not opened by this tool unless --hash or "
                    "--ucas-entropy-bytes was given.")
            else:
                note_parts.append("not an IoStore or pak container; recorded for completeness")
        except (ContainerParseError, OSError, struct.error) as error:
            warnings.append("%s: %s" % (relative, error))
            note_parts.append("parse failed: %s" % error)
            entry["evidence"] = {
                "evidence_level": "UNKNOWN",
                "claim_class": "I",
                "confidence": 0.0,
                "oracle": ["container-metadata"],
                "sources": [{"method": "F-02", "artifact": None, "locator": relative,
                             "note": "oracle container-metadata. Parse failed: %s"
                                     % error}],
                "read_locus": None,
                "note": "This container did not parse. That is a finding, not a gap.",
            }

        if entry["evidence"] is None and kind in ("utoc", "pak"):
            entry["evidence"] = decoded_annotation(
                relative, corroborated, corroboration_note, corroboration_oracle)
            checks.append({
                "target": relative,
                "check": ("utoc_layout_arithmetic" if kind == "utoc"
                          else "pak_layout_tiles_file"),
                "passed": corroborated,
                "detail": corroboration_note,
            })
            checks.extend(extra_checks)
        elif entry["evidence"] is None:
            # Path and size only, on the filesystem oracle. Class P at 0.99 still owes
            # criterion 2, so the stat is genuinely repeated instead of being asserted.
            restat = os.stat(path)
            size_reproduced = int(restat.st_size) == size
            if not size_reproduced:
                warnings.append("%s: the size changed between the two stat calls (%d "
                                "then %d) -- the tree is not stable under this run"
                                % (relative, size, restat.st_size))
            entry["evidence"] = {
                "evidence_level": "OBSERVED",
                "claim_class": "P",
                "confidence": CONFIDENCE_LITERAL,
                "oracle": ["filesystem"],
                "sources": [{
                    "method": "F-02", "artifact": None, "locator": relative,
                    "note": ("oracle filesystem. Path and size only; no header was "
                             "parsed. Method re-run "
                             "and reproduced: the size was stat'ed twice in this run "
                             "and both calls agree."
                             if size_reproduced else
                             "path and size only. Method NOT reproduced: two stat calls "
                             "in this run disagreed."),
                }],
                "read_locus": None,
                "note": "Path, kind and size only. No format claim is made about this file.",
            }

        # Optional entropy sample of the paired .ucas body. Off by default: a header
        # parser has no reason to open a 4.3 GB file.
        if kind == "utoc" and entry["utoc"] is not None and ucas_entropy_bytes > 0:
            sibling = entry["sibling_path"]
            if sibling:
                # Derived from the container's own directory, not from install_dir:
                # --paks-dir may point outside the installation tree, in which case
                # the relative path is not resolvable against the root.
                sibling_abs = os.path.join(os.path.dirname(path),
                                           sibling.rsplit("/", 1)[-1])
                entropy, read = stream_entropy(sibling_abs, ucas_entropy_bytes, buf_size)
                entry["utoc"]["body_entropy"] = (None if entropy is None
                                                 else round(entropy, 6))
                note_parts.append(
                    "body_entropy measured over the first %d bytes of %s; high entropy "
                    "is consistent with encryption and proves nothing on its own"
                    % (read, sibling))

        if literals:
            # plan.md 10.3 criterion 2, performed before the records are emitted so
            # that what each record says about reproduction is a result, not a hope.
            reproduced = confirm_literal_reads(path, literals, relative, warnings)
            literal_groups.append({
                "target": relative,
                "kind": kind,
                "file_size": size,
                "reads_reproduced": reproduced,
                "reads": literals,
            })
            checks.append({
                "target": relative,
                "check": "literal_reads_reproduced",
                "passed": reproduced,
                "detail": ("all %d literal ranges were read a second time through a "
                           "second file handle and %s"
                           % (len(literals), "agree" if reproduced else "DISAGREE")),
            })
        entry["notes"] = " ".join(note_parts) if note_parts else None
        if not entry_evidence:
            entry["evidence"] = None
        containers.append(entry)

    containers.sort(key=lambda item: item["path"])
    literal_groups.sort(key=lambda item: item["target"])
    checks.sort(key=lambda item: (item["target"], item["check"]))

    return {
        "schema": SCHEMA_ID,
        "generated_at": now_iso_utc(),
        "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
        "install_dir": install_dir,
        "paks_dir": relative_posix(install_dir, paks_dir),
        "container_count": len(containers),
        "containers": containers,
        "literal_reads": literal_groups,
        "checks": checks,
        "warnings": sorted(warnings),
        "notes": (
            "Two layers, deliberately not merged (plan.md 10.3, rows A-07 / A-07i). "
            "literal_reads[] is class P: offset, length and raw bytes, with a claim "
            "sentence that states both and names nothing. containers[] is class I: it "
            "names the fields and decodes them against the public FIoStoreTocHeader / "
            "FPakInfo layout, which is the external-doc oracle and is why it is capped "
            "at 0.85. containers[] has the shape of "
            "fingerprint.schema.json#/$defs/container_entry so task F-03 can splice it "
            "into fingerprint.json unchanged. Decision D-02: no key was extracted and "
            "no container content was decrypted."
        ),
    }


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def dump_json(document: dict) -> str:
    """Serialize deterministically: sorted keys, indent 2, LF, trailing newline."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_json(document: dict, out_path: str, install_dir: str | None = None) -> str:
    """Write *document*, refusing any path inside the installation (D-01, layer 1)."""
    root = install_dir or document.get("install_dir") or DEFAULT_INSTALL_DIR
    target = pathguard.check_output_path(out_path, root, what="--out")
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dump_json(document))
    return target


def _print_summary(document: dict, out_path: str | None) -> None:
    say = lambda line: print(line, file=sys.stderr)
    say("container-info (%s %s)" % (GENERATOR_NAME, GENERATOR_VERSION))
    say("  install_dir : %s" % document["install_dir"])
    say("  paks_dir    : %s" % document["paks_dir"])
    say("  containers  : %d" % document["container_count"])
    for entry in document["containers"]:
        say("  - %s  [%s]  %d bytes" % (entry["path"], entry["kind"], entry["size"]))
        utoc = entry.get("utoc")
        pak = entry.get("pak")
        if utoc:
            say("      version=%s header=%s entries=%s blocks=%s block_size=%s"
                % (utoc["version"], utoc["toc_header_size"], utoc["toc_entry_count"],
                   utoc["toc_compressed_block_entry_count"], utoc["compression_block_size"]))
            say("      dir_index=%s partitions=%s partition_size=%s seeds=%s"
                % (utoc["directory_index_size"], utoc["partition_count"],
                   utoc["partition_size"], utoc["toc_chunk_perfect_hash_seeds_count"]))
            say("      container_id=%s flags=%s %s key_guid=%s methods=%s"
                % (utoc["container_id"], utoc["container_flags"],
                   utoc["container_flags_decoded"], utoc["encryption_key_guid"],
                   utoc["compression_method_names"]))
            say("      encrypted=%s indexed=%s index_readable=%s mount=%r"
                % (utoc["is_encrypted"], utoc["has_directory_index"],
                   utoc["directory_index_readable"], utoc["mount_point"]))
        if pak:
            say("      magic=%s version=%s footer=%s+%s"
                % (pak["magic"], pak["pak_version"], pak["footer_offset"], pak["footer_size"]))
            say("      index=%s+%s hash=%s encrypted=%s key_guid=%s"
                % (pak["index_offset"], pak["index_size"], pak["index_hash"],
                   pak["encrypted_index"], pak["encryption_key_guid"]))
            say("      mount=%r entries=%s seed=%s path_hash=%s full_dir=%s"
                % (pak["mount_point"], pak["num_entries"], pak["path_hash_seed"],
                   pak["has_path_hash_index"], pak["has_full_directory_index"]))
    say("  checks:")
    for check in document["checks"]:
        say("    [%s] %s %s -- %s" % ("PASS" if check["passed"] else "FAIL",
                                      check["target"], check["check"], check["detail"]))
    say("  literal reads: %d"
        % sum(len(group["reads"]) for group in document["literal_reads"]))
    say("  output      : %s" % (out_path if out_path else "<not written>"))
    for warning in document["warnings"]:
        say("  WARNING: %s" % warning)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="container_info.py",
        description=(
            "Read-only parser for IoStore .utoc headers and legacy .pak footers "
            "(plan.md task F-02). Emits a class-P literal layer and a class-I decoded "
            "layer side by side. Refuses any --out path inside the game folder "
            "(plan.md D-01, safety model 1.5 layer 1). Never decrypts anything (D-02)."
        ),
    )
    parser.add_argument("--install-dir", default=DEFAULT_INSTALL_DIR,
                        help="game installation root (default: %(default)s)")
    parser.add_argument("--paks-dir", default=None,
                        help="directory holding the containers (default: <install-dir>/%s)"
                             % PAKS_RELDIR)
    parser.add_argument("--out", default=None,
                        help="JSON file to write; when omitted nothing is written. A path "
                             "inside the installation is refused (exit 2) before any work")
    parser.add_argument("--inventory", default=None,
                        help="install-inventory.json to copy size/sha256 from, instead of "
                             "rehashing files snapshot_install.py already hashed")
    parser.add_argument("--hash", action="store_true",
                        help="compute sha256 of every container by streaming it. This is "
                             "the only option that opens the 4.3 GB .ucas in full; peak "
                             "memory stays at one --buffer-bytes buffer")
    parser.add_argument("--ucas-entropy-bytes", type=int, default=0,
                        help="sample this many bytes from the head of each paired .ucas and "
                             "record the Shannon entropy (default: 0 = do not open it)")
    parser.add_argument("--no-verify-index-hash", action="store_true",
                        help="skip recomputing the sha1 of a plaintext pak index (that "
                             "recomputation is the pak's independent corroboration)")
    parser.add_argument("--no-entry-evidence", action="store_true",
                        help="omit the evidence annotation from each containers[] entry. "
                             "The annotation is what grades the decoded layer class I at "
                             "0.85, so this is a loss -- it exists because "
                             "tools/kb/validate.py currently reads such an annotation as "
                             "a whole knowledge-base record and demands claim_type and "
                             "build_key, which the annotation schema forbids. The "
                             "class-P literal_reads[] layer is never affected")
    parser.add_argument("--buffer-bytes", type=int, default=DEFAULT_BUFFER_BYTES,
                        help="streaming buffer size in bytes (default: %(default)s)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.buffer_bytes <= 0:
        print("--buffer-bytes must be positive", file=sys.stderr)
        return 2
    if args.ucas_entropy_bytes < 0:
        print("--ucas-entropy-bytes must not be negative", file=sys.stderr)
        return 2

    # Layer 1 first: refusing after the scan would waste the scan and, worse, would
    # let a wrong --out look survivable.
    out_path = None
    if args.out:
        try:
            out_path = pathguard.check_output_path(args.out, args.install_dir, what="--out")
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2

    try:
        document = build_document(
            install_dir=args.install_dir,
            paks_dir=args.paks_dir,
            inventory_path=args.inventory,
            hash_files=args.hash,
            ucas_entropy_bytes=args.ucas_entropy_bytes,
            verify_index_hash=not args.no_verify_index_hash,
            buf_size=args.buffer_bytes,
            entry_evidence=not args.no_entry_evidence,
        )
    except (OSError, ValueError) as error:
        print("error: %s" % error, file=sys.stderr)
        return 2

    if out_path:
        try:
            write_json(document, out_path, install_dir=args.install_dir)
        except pathguard.OutputPathRefused as error:
            print("error: %s" % error, file=sys.stderr)
            return 2
        except OSError as error:
            print("error: cannot write %s: %s" % (out_path, error), file=sys.stderr)
            return 2

    _print_summary(document, out_path)
    failed = [check for check in document["checks"] if not check["passed"]]
    # stdout carries exactly one machine-readable line, and it is the last thing printed.
    print("containers=%d literal_reads=%d checks_failed=%d warnings=%d"
          % (document["container_count"],
             sum(len(group["reads"]) for group in document["literal_reads"]),
             len(failed), len(document["warnings"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
