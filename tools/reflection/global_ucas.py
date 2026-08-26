#!/usr/bin/env python3
"""Read-only reader for the PLAINTEXT global IoStore container: the global FName
batch and the script-object map (method RF-01, plan.md 6.2).

The question this tool exists to answer
---------------------------------------
plan.md makes a non-empty ``/Script/MISERY`` class list an exit criterion of
milestone M3, and scoped it to require a running process plus an External
Read-Only Inspector. S-10 had already found ZERO game classes in the shipped
binary's RTTI, so before this tool the project had no surface at all that named
game code. ``MISERY/Content/Paks/global.utoc`` is 623 bytes with
``ContainerFlags == 0x00`` -- no ``Encrypted`` bit, no ``Indexed`` bit -- and its
payload ``global.ucas`` is plaintext. If the script-object map is readable from
there, a large part of M3 becomes static work needing no process, no key and no
instrumentation.

So this tool answers, in this order:

1. Does the TOC parse EXACTLY -- header, chunk table, block table, chunk meta --
   with the file size fully accounted for and nothing left over?
2. Which chunk is ``EIoChunkType::ScriptObjects``, and are its blocks
   unencrypted and uncompressed, per the container's own flags and per the
   per-block compression-method index?
3. Are the bytes we assemble from ``global.ucas`` the SAME bytes the engine
   reads? (Proven against the ``FIoChunkHash`` the TOC stores -- see *Proving a
   datum is what the engine reads* below.)
4. What names does the serialized name batch hold, and is every decoded name
   confirmed by the 64-bit hash the batch stores next to it?
5. What script objects does the map hold: name, outer, CDO class, global index --
   and is every reconstructed full path confirmed by the 62-bit hash the entry
   stores as its own global index?
6. Which ``/Script/<Module>`` packages exist, what is attributed to each, and is
   there a ``/Script/MISERY``?

Where the layout comes from, field by field
-------------------------------------------
The authoritative definition is the first-party UE 5.4.4 source tree on this
machine at the SAME changelist the shipped image was built from (35576357,
``++UE5+Release-5.4``; see ``research/unreal/engine-version.json``). Every field,
every mask and every constant below carries a file-and-line citation into it.
Nothing here is remembered and nothing here is guessed: a predecessor on this
project guessed pak-entry bitfield masks from memory and produced a confidently
wrong answer, which is the exact failure these citations exist to prevent.

``Engine/Source/`` paths, with the short tags used in the code comments:

    TOC   Runtime/Core/Internal/IO/IoStore.h
    TOCC  Runtime/Core/Private/IO/IoStore.cpp
    OL    Runtime/Core/Internal/IO/IoOffsetLength.h
    CID   Runtime/Core/Public/IO/IoChunkId.h
    DISP  Runtime/Core/Public/IO/IoDispatcher.h
    IOH   Runtime/Core/Public/IO/IoHash.h
    NAMES Runtime/Core/Private/UObject/UnrealNames.cpp
    NT    Runtime/Core/Public/UObject/NameTypes.h
    MAP   Runtime/Core/Public/Serialization/MappedName.h
    MAPC  Runtime/Core/Private/Serialization/MappedName.cpp
    AL2   Runtime/CoreUObject/Public/Serialization/AsyncLoading2.h
    AL2C  Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp
    PSO   Developer/IoStoreUtilities/Private/PackageStoreOptimizer.cpp
    ISU   Developer/IoStoreUtilities/Private/IoStoreUtilities.cpp
    CITY  Runtime/Core/Private/Hash/CityHash.cpp
    CITYH Runtime/Core/Public/Hash/CityHash.h
    CHAR  Runtime/Core/Public/Misc/Char.h
    B3T   Runtime/Core/Tests/Hash/Blake3Test.cpp
    FLD   Runtime/CoreUObject/Public/UObject/Field.h
    UT    Runtime/CoreUObject/Public/UObject/UnrealType.h

The container, top down::

    TOC:38-75    FIoStoreTocHeader -- 144 bytes, magic "-==--==--==--==-"
    TOC:22-33    EIoStoreTocVersion; in 5.4 Latest == 6 (OnDemandMetaData).
                 NOTE: container_info.py knows versions 7 and 8 from LATER
                 engines. This build is 6, and the >= 8 meta layout is therefore
                 never taken here.
    TOCC:3145    FIoStoreTocResource::Read -- the body field ORDER this module
                 mirrors: chunk ids (TOCC:3217), offset/lengths (TOCC:3222),
                 perfect-hash seeds (TOCC:3240), overflow indices (TOCC:3246),
                 compression blocks (TOCC:3252), compression method names
                 (TOCC:3260-3266), signatures iff Signed (TOCC:3272-3302),
                 directory index (TOCC:3305), chunk metas last (TOCC:3315-3318)
    TOCC:3169    TocHeaderSize must equal sizeof(FIoStoreTocHeader)
    TOCC:3174    TocCompressedBlockEntrySize must equal 12
    CID:132      FIoChunkId is 12 raw bytes
    CID:111      GetChunkType() == Id[11]
    CID:26-43    EIoChunkType; ScriptObjects == 5 (CID:33). The enumerator is
                 READ FROM THE SOURCE, not assumed.
    CID:136-150  CreateIoChunkId(0, 0, ScriptObjects) -> the 12 bytes
                 00 00 00 00 00 00 00 00 | 00 00 | 00 | 05, which is the id
                 ISU:6921 asks the global container for
    OL:10-62     FIoOffsetAndLength -- 5 BIG-endian offset bytes then 5 BIG-endian
                 length bytes, 10 bytes total
    TOC:111-170  FIoStoreTocCompressedBlockEntry -- 12 bytes:
                   bytes 0..4   offset, uint64 at Data[0] masked to 40 bits
                                (TOC:113-114, 119-123)
                   bytes 5..7   compressed size, uint32 at Data+4 >> 8 & 0xFFFFFF
                                (TOC:115-117, 131-135)
                   bytes 8..10  uncompressed size, uint32 at Data+8 & 0xFFFFFF
                                (TOC:143-147)
                   byte  11     compression method index, that uint32 >> 24
                                (TOC:155-159)
    TOC:189      CompressionMethodNameLen == 32; slot count and slot length come
                 from the header
    TOCC:3258    CompressionMethods[0] is NAME_None -- index 0 means "not
                 compressed", so the stored index is 1-based into the name table
    TOC:77-94    FIoStoreTocEntryMeta = FIoChunkHash + FIoStoreTocEntryMetaFlags
    DISP:148     FIoChunkHash is uint8 Hash[32] -> sizeof(meta) == 33, no padding
    DISP:467-475 EIoContainerFlags: Compressed 1, Encrypted 2, Signed 4,
                 Indexed 8, OnDemand 16

Reading one chunk (TOCC:2700-2806, the synchronous path)::

    TOCC:2729-2730  FirstBlockIndex = ResolvedOffset / CompressionBlockSize
                    LastBlockIndex  = (Align(ResolvedOffset + ResolvedSize,
                                       CompressionBlockSize) - 1) / CompressionBlockSize
    TOCC:2749-2751  the block's file position is
                    (block offset % PartitionSize) inside partition
                    (block offset / PartitionSize)
    TOCC:2741       the engine reads Align(CompressedSize, FAES::AESBlockSize)
                    bytes -- which is why global.ucas is 9 bytes longer than the
                    sum of the block sizes, and the tiling probe says so
    TOCC:2790-2794  decryption happens ONLY when the container flag says
                    Encrypted. This container's flag byte is 0x00, so the engine
                    itself performs no decryption step on these bytes.
    TOCC:2796-2806  method index 0 == NAME_None == plain memcpy, no decompression

The serialized name batch, ARCHIVE form (NAMES:4854-4930 writer /
NAMES:4869-4930 reader)::

    NAMES:4435-4470  SaveNameBatch(TConstArrayView, FArchive&):
                       uint32 Num                      (NAMES:4438-4439)
                       -- and nothing else when Num == 0 (NAMES:4441-4443)
                       uint32 NumStringBytes           (NAMES:4465-4466)
                       uint64 HashVersion              (NAMES:4468)
                       uint64 Hashes[Num]
                       FSerializedNameHeader Headers[Num]
                       uint8  Strings[NumStringBytes]
    NAMES:4869-4903  FNameBatchLoader::Read -- the reader this module mirrors,
                     including the single Serialize of
                     8*Num + 2*Num + NumStringBytes bytes
    NAMES:4349-4376  FSerializedNameHeader, 2 bytes:
                       Data[0] bit 7        IsUtf16          (NAMES:4360-4363)
                       Data[0] bits 6..0    Len high byte    (NAMES:4365-4368)
                       Data[1]              Len low byte
                       NumBytes == Len * (2 if utf16 else 1)  (NAMES:4370-4373)
    NAMES:4599-4632  LoadSeparatedNameBatchInInputOrder -- in the SEPARATED
                     (archive) form the strings are packed back to back with NO
                     padding. The interleaved form (NAMES:4379-4396, 4403) does
                     pad UTF-16 names to a 2-byte boundary; that form is NOT what
                     an FArchive batch uses, and confusing the two shifts every
                     following name.
    NAMES:733        FNameHash::AlgorithmId == 0xC1640000 -- the value this
                     container's HashVersion field is checked against
    NAMES:4431,4854 the stored hash is GenerateLowerCaseHash(name):
    NAMES:843-857     CityHash64 over the LOWERCASED name bytes, 1 byte per char
                      for an ANSI name and 2 for a UTF-16 one
    CHAR:88-91      TChar::ToLower converts ASCII A-Z only

FName index and number (NT:1723, MAP:82-90, NT:138-142, NAMES:3465-3475)::

    MAP:24-27    FMappedName: Index bits 0..29, Type bits 30..31
    MAP:82-85    GetIndex() == Index & 0x3FFFFFFF
    MAP:30-35    EType: Package 0, Container 1, Global 2 -- a global batch entry
                 must be type 2, and ISU:6937 checks IsGlobal()
    NT:1723      FDisplayNameEntryId::ToName(Number) uses Number verbatim
    NT:138-142   NAME_INTERNAL_TO_EXTERNAL(x) == x - 1; 0 means "no number"
    NAMES:3465-3475  FName::AppendString: when Number != 0 the string is
                 "<plain>_" + (Number - 1)

The script-object map (AL2:324-337, AL2C:169-176, PSO:999-1030, ISU:6928-6941)::

    ISU:6930-6932   LoadNameBatch(archive), then int32 NumScriptObjects, then
                    the entries -- read by ISU:6933 as a raw C array, which is an
                    independent statement that the serialized entry stride equals
                    sizeof(FScriptObjectEntry)
    AL2:324-337     FScriptObjectEntry { FMappedName Mapped; FPackageObjectIndex
                    GlobalIndex, OuterIndex, CDOClassIndex; }
    AL2C:169-176    operator<< order: Mapped, GlobalIndex, OuterIndex,
                    CDOClassIndex
    MAPC:8-13       FMappedName serializes as uint32 Index then uint32 Number
    AL2:152-156     FPackageObjectIndex serializes as one uint64 TypeAndId
                    -> the entry is 8 + 8 + 8 + 8 = 32 bytes, little-endian
    AL2:57-72       FPackageObjectIndex: Id bits 0..61, Type bits 62..63;
                    EType Export 0, ScriptImport 1, PackageImport 2, Null 3;
                    Invalid == ~0ull, so a null index reads 0xFFFFFFFFFFFFFFFF
    AL2:87-90       FromScriptPath -> FPackageObjectIndex(ScriptImport,
                    GenerateImportHashFromObjectPath(path))
    AL2C:221-240    GenerateImportHashFromObjectPath: replace '.' and ':' with
                    '/', lowercase every character, CityHash64 over the TCHAR
                    buffer (UTF-16LE on Windows), then clear the top 2 bits
    PSO:966-996     the roots: every UPackage from FindAllRuntimeScriptPackages
                    gets FullName = Package->GetName() lowercased and
                    OuterIndex = FPackageObjectIndex() (i.e. Invalid)
    PSO:896-957     the recursion: FullName = OuterFullName + "/" + ObjectName,
                    lowercased; children come from GetObjectsWithOuter with
                    bIncludeNestedObjects false
    PSO:899-903     ONLY RF_Public objects are recorded. A private native class
                    is absent from this container by construction.
    PSO:932-942     CDOClassIndex: when the object's name starts with
                    "Default__", it is FromScriptPath(OuterFullName + "/" +
                    name-without-the-9-character-prefix); PSO:929 propagates the
                    outer's value down, so a subobject of a CDO carries it too
    PSO:1001-1005   the entries are sorted by full name before writing

Two hash functions are reimplemented here, both from the first-party source::

    CITY:388-428    CityHash64, with CITY:276-386 for its helpers and
    CITYH:91-100    CityHash128to64
    IOH:23,156-163  FIoHash is BLAKE3-160: the first 20 bytes of a BLAKE3-256
    DISP:134-140    FIoChunkHash::CreateFromIoHash copies those 20 bytes and
                    zeroes the remaining 12
    B3T:18-49       the 21 first-party BLAKE3 test vectors this module's BLAKE3
                    is checked against on every run, over the same input the
                    test uses (byte i == i % 251). They cover 0, 1, 1023, 1024,
                    1025 ... 31744 bytes, so the chunk-tree merge path is
                    exercised, not only the single-chunk path.

Proving a datum is what the engine reads (D-02, and why this tool may run)
-------------------------------------------------------------------------
"The container flag byte is 0x00, so the payload is plaintext" is a claim the
file makes about itself. D-02 asks for proof, and this container carries one:
the TOC stores an ``FIoStoreTocEntryMeta`` per chunk whose ``ChunkHash`` is the
BLAKE3-160 of the chunk's SOURCE data -- "i.e. not the on disk data" (TOC:91).
So if the bytes we assemble out of ``global.ucas`` hash to the value stored in
the TOC, then the bytes the engine parses are byte-for-byte the bytes we just
read, with no decryption and no decompression step in between -- otherwise the
engine's own integrity check would be looking at something else. That is a
positive, falsifiable test with a 160-bit margin, and it runs before a single
byte of the chunk is interpreted (see ``PAYLOAD_POLICY`` and
``verify_chunk_hash``).

No key is derived, searched for or used anywhere in this file, and no
decryption is attempted. If the container flags said ``Encrypted``, or any
block named a compression method, this tool would report that and read nothing.
D-02 is executed rather than promised.

Three independent verifications, not one
----------------------------------------
A decode that agrees with itself proves nothing, so every layer is checked
against a datum stored SEPARATELY in the container and produced by a DIFFERENT
piece of engine code:

``chunk_hash``          BLAKE3-160 of the assembled chunk vs the TOC's stored
                        FIoChunkHash. Validates the container walk. 160 bits.
``name_hashes``         CityHash64 of each lowercased decoded name vs the 64-bit
                        hash the batch stores for it (NAMES:4431). Validates
                        every single string decode, one check per name.
``global_index_hashes`` CityHash64 of each reconstructed full path vs the low 62
                        bits of the entry's own GlobalIndex (AL2C:221-240).
                        Validates the OUTER-CHAIN RECONSTRUCTION, which is the
                        part that turns a word list into a map. 62 bits per
                        object.

The first is cryptographic; the other two are not, but they are computed by a
different algorithm over different bytes than the fields they confirm, and a
wrong stride or a wrong mask does not survive tens of thousands of them.

Structural self-check: does the parse TILE?
-------------------------------------------
Both containers are checked for exact tiling -- every byte assigned to exactly
one section, no gaps and no overlaps:

``toc_tiling``    144-byte header + chunk ids + offset/lengths + seeds +
                  overflow + blocks + method names + directory index + metas,
                  compared with the file size.
``ucas_tiling``   the block extents, compared with each other and with the
                  ``global.ucas`` size. The engine reads
                  ``Align(CompressedSize, 16)`` per block (TOCC:2741), so the
                  expected tail is the aligned end of the last block, and the
                  probe reports both models rather than picking one silently.
``chunk_tiling``  inside the chunk: 16-byte batch header + hashes + headers +
                  strings + the int32 count + the entry array, compared with the
                  chunk length from ``FIoOffsetAndLength``.

A gap or an overlap in any of the three means the layout is wrong, and the tool
says so instead of producing a plausible list.

Refutation probes (plan.md 10.3, class-I criterion: try to break the headline)
-----------------------------------------------------------------------------
The headline is positive -- "here are 394 modules and here is /Script/MISERY" --
and a positive finding reached from one decode is exactly the kind a stride
error fabricates. Two probes look for the same facts WITHOUT the header table:

``ascii_script_scan``   counts occurrences of the literal bytes ``/Script/`` in
                        the chunk and compares with the number of decoded root
                        packages whose name starts with it. A-08 got 394 from a
                        plain ``strings`` run; a decode that disagrees with a raw
                        byte scan is wrong.
``ascii_default_scan``  the same for ``Default__``, compared with the number of
                        decoded entries whose name starts with it.

Two output layers, never merged (plan.md 10.3)
----------------------------------------------
``literal_reads``
    Class **P**. One record per read: target, file offset, length, raw bytes, and
    a claim sentence that states the offset and the length and STOPS there -- it
    names no field, no layout and no type, which is what plan.md 10.3 v2.4
    requires of ``container-metadata`` for class P to apply at all. Every range
    is read a second time through a freshly opened handle before the record may
    say it reproduced. The sample is bounded and deterministic.

``toc`` / ``chunk`` / ``name_table`` / ``script_objects`` / ``modules`` /
``game_module`` / ``probes`` / ``summary``
    Class **I**. These name fields, apply masks, decode strings, reconstruct
    paths and count things. Every one of those steps rests on the engine source,
    so the whole layer is class I whatever the offsets are, and it is capped
    below the literal layer.

What this container CANNOT tell us, stated here so nobody reads more into the
output than it carries (plan.md 10.5 and C-11)
----------------------------------------------------------------------------
* **What kind of thing a name is.** There is no type tag anywhere in
  ``FScriptObjectEntry``. A ``UClass``, a ``UScriptStruct``, a ``UEnum`` and a
  ``UDelegateFunction`` sitting directly in a script package are stored
  identically. The ONE exception is the class-default object: PSO:932-942 writes
  a CDOClassIndex for a name beginning with ``Default__``, and that index is the
  hash of the owning class's path -- so a name with a matching ``Default__``
  sibling is a ``UClass``, and that is an inference from the writer's own code,
  not from a naming convention.
* **Properties, at all.** ``FProperty`` derives from ``FField`` (UT:162,
  FLD:447) which is not a ``UObject``, and the map is built by
  ``GetObjectsWithOuter`` (PSO:952-957) which walks ``UObject``s. No property,
  no property offset, no property order and no property type can appear in this
  container, in this build or any other. ``properties.jsonl`` is therefore
  EMPTY, and that is a fact about the format rather than a gap in this run.
* **Inheritance.** ``FScriptObjectEntry`` has no super field. Outer is
  containment, not derivation.
* **Non-public objects.** PSO:899-903 skips anything without ``RF_Public``.
* **Whether anything is USED.** Presence in the global container means the cook
  saw the module, not that the shipped game loads it.
* **Anything about /Game.** plan.md C-11: a name here is not evidence that a
  ``/Game`` asset exists, and says nothing whatever about a Blueprint's
  structure.

C-13: what may and may not leave the installation
-------------------------------------------------
Names, counts, offsets, sizes and hashes are findings and are emitted. Chunk
payload bytes are not, at any size, in any encoding: the literal layer holds
only TOC header, chunk-table and batch-header bytes -- structure, not content --
and even those are capped by ``--literal-samples``. Nothing here comes from a
decrypted container: this container is not encrypted and no decryption exists in
this file. The judgement about how much of the decoded NAME TABLE belongs in the
public repository is a separate question that the tool does not decide for the
author: it emits the full table only where asked to (``--objects-out``), always
reports the count and the canonical SHA-256 of the full sorted table so a later
run can prove it reproduced it, and the repository's own decision is recorded in
``research/reflection/<build>/README.md``.

Memory (plan.md F-04)
---------------------
The TOC is 623 bytes and is read whole after its size is checked. The chunk is
2.27 MB and is read once, block by block, with every block extent checked
against the ``global.ucas`` size before the seek. Every count taken from a file
is clamped before it becomes a loop bound. Nothing else is buffered.

Determinism
-----------
Sorted keys, indent 2, LF, UTF-8 without BOM, trailing newline. Names are
emitted in container order where the container's order is itself the finding,
and sorted everywhere else. Two runs over an unchanged file differ only in
``generated_at``; ``--no-timestamp`` removes even that, which is how the
determinism proof is taken.

Standard library only. Read-only with respect to the game: the installation is
opened for reading and never written to, and every output path is checked by
``pathguard`` before anything is created.

CLI
---
    python tools/reflection/global_ucas.py <global.utoc>
    python tools/reflection/global_ucas.py <global.utoc> --json
    python tools/reflection/global_ucas.py <global.utoc> \\
        --out       research/evidence/RF-01/global-ucas.json \\
        --names-out research/evidence/RF-01/global-names.txt \\
        --objects-out research/evidence/RF-01/script-objects.tsv \\
        --jsonl-dir research/reflection/<build-id>/ \\
        --module <name>

Exit codes: 0 the read completed (whatever the verdict), 2 usage / I/O error /
unparseable input / a verification that FAILED. A failed verification is an
error on purpose: the whole value of this tool is that its output is checked, so
an unchecked output must not look like a successful run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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

# The .utoc HEADER belongs to F-02. Re-deriving the 144-byte field table and the
# version-dependent body offsets here would give this tool a second,
# differently-buggy opinion about where the chunk table starts, and the point of
# having one parser is that there is one. What this module adds is everything
# BEYOND the header: the chunk table, the payload read, and the chunk contents.
import container_info  # noqa: E402

GENERATOR_NAME = "tools/reflection/global_ucas.py"
GENERATOR_VERSION = "1.0.0"

ContainerParseError = container_info.ContainerParseError
hex_bytes = container_info.hex_bytes

# The engine source tree the field citations point into. Recorded in the output
# so a reader can check the citations against the same text this run used, and
# so a run against a DIFFERENT engine tree is visible rather than silent.
ENGINE_SOURCE_RELPATHS = (
    "Engine/Source/Runtime/Core/Internal/IO/IoStore.h",
    "Engine/Source/Runtime/Core/Private/IO/IoStore.cpp",
    "Engine/Source/Runtime/Core/Internal/IO/IoOffsetLength.h",
    "Engine/Source/Runtime/Core/Public/IO/IoChunkId.h",
    "Engine/Source/Runtime/Core/Public/IO/IoDispatcher.h",
    "Engine/Source/Runtime/Core/Public/IO/IoHash.h",
    "Engine/Source/Runtime/Core/Private/UObject/UnrealNames.cpp",
    "Engine/Source/Runtime/Core/Public/UObject/NameTypes.h",
    "Engine/Source/Runtime/Core/Public/Serialization/MappedName.h",
    "Engine/Source/Runtime/Core/Private/Serialization/MappedName.cpp",
    "Engine/Source/Runtime/Core/Private/Hash/CityHash.cpp",
    "Engine/Source/Runtime/Core/Public/Hash/CityHash.h",
    "Engine/Source/Runtime/Core/Public/Misc/Char.h",
    "Engine/Source/Runtime/Core/Tests/Hash/Blake3Test.cpp",
    "Engine/Source/Runtime/CoreUObject/Public/Serialization/AsyncLoading2.h",
    "Engine/Source/Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp",
    "Engine/Source/Developer/IoStoreUtilities/Private/PackageStoreOptimizer.cpp",
    "Engine/Source/Developer/IoStoreUtilities/Private/IoStoreUtilities.cpp",
)

PAYLOAD_POLICY = (
    "D-02. A chunk payload is read only when (a) the container's ContainerFlags "
    "byte (IoStore.h:57, IoDispatcher.h:467-475) has the Encrypted bit CLEAR, "
    "(b) every compression block of that chunk names method index 0, which is "
    "NAME_None (IoStore.cpp:3258, 2796-2806), and (c) the assembled bytes hash "
    "to the FIoChunkHash the TOC stores for that chunk (IoStore.h:91, "
    "IoDispatcher.h:148). No key is derived, searched for or used, and no "
    "decryption is attempted anywhere in this file. If (a) or (b) fails the "
    "tool reads nothing and reports that as the finding; if (c) fails the run "
    "is an error and nothing is interpreted."
)


# --------------------------------------------------------------------------- #
# hard limits. Each one bounds a number that comes from a file and must
# therefore never be believed.
# --------------------------------------------------------------------------- #

MAX_TOC_BYTES = 64 << 20          # a .utoc is KB to a few MB; 64 MB is absurd
MAX_TOC_ENTRIES = 1 << 22         # TocEntryCount clamp
MAX_TOC_BLOCKS = 1 << 24          # TocCompressedBlockEntryCount clamp
MAX_CHUNK_BYTES = 256 << 20       # the global chunk is 2.27 MB
MAX_NAME_COUNT = 1 << 24          # name-batch Num clamp
MAX_NAME_STRING_BYTES = 256 << 20
MAX_SCRIPT_OBJECTS = 1 << 24      # NumScriptObjects clamp
MAX_NAME_LEN = 1024               # NAME_SIZE is 1024 (NameTypes.h) -- a header
                                  # claiming more than that is not a name

DEFAULT_LITERAL_SAMPLES = 16

# Fixed record widths, all cited in the module docstring.
IO_CHUNK_ID_SIZE = 12             # IoChunkId.h:132
IO_OFFSET_AND_LENGTH_SIZE = 10    # IoOffsetLength.h:61
IO_BLOCK_ENTRY_SIZE = 12          # IoStore.h:169
IO_SEED_SIZE = 4                  # IoStore.cpp:3240, int32
IO_CHUNK_META_SIZE = 33           # IoDispatcher.h:148 + IoStore.h:93
IO_HASH_BYTES = 20                # IoHash.h:35, BLAKE3-160
AES_BLOCK_SIZE = 16               # FAES::AESBlockSize, IoStore.cpp:2741
SCRIPT_OBJECT_ENTRY_SIZE = 32     # AsyncLoading2.h:324-337 + AsyncLoading2.cpp:169
NAME_BATCH_HEADER_SIZE = 16       # UnrealNames.cpp:4438-4468: u32 + u32 + u64
SERIALIZED_NAME_HEADER_SIZE = 2   # UnrealNames.cpp:4375

# EIoChunkType, IoChunkId.h:26-43. Read from the source; the value is not assumed.
IO_CHUNK_TYPES = {
    0: "Invalid", 1: "ExportBundleData", 2: "BulkData", 3: "OptionalBulkData",
    4: "MemoryMappedBulkData", 5: "ScriptObjects", 6: "ContainerHeader",
    7: "ExternalFile", 8: "ShaderCodeLibrary", 9: "ShaderCode",
    10: "PackageStoreEntry", 11: "DerivedData", 12: "EditorDerivedData",
    13: "PackageResource",
}
CHUNK_TYPE_SCRIPT_OBJECTS = 5     # IoChunkId.h:33

# EIoStoreTocVersion as UE 5.4 defines it (IoStore.h:22-33). Latest is 6.
TOC_VERSION_LATEST_5_4 = 6

# FMappedName, MappedName.h:24-35.
MAPPED_NAME_INDEX_BITS = 30
MAPPED_NAME_INDEX_MASK = (1 << MAPPED_NAME_INDEX_BITS) - 1
MAPPED_NAME_TYPE_GLOBAL = 2

# FPackageObjectIndex, AsyncLoading2.h:57-72.
PACKAGE_OBJECT_INDEX_BITS = 62
PACKAGE_OBJECT_INDEX_MASK = (1 << PACKAGE_OBJECT_INDEX_BITS) - 1
PACKAGE_OBJECT_INDEX_INVALID = 0xFFFFFFFFFFFFFFFF
PACKAGE_OBJECT_TYPES = {0: "Export", 1: "ScriptImport", 2: "PackageImport", 3: "Null"}
PACKAGE_OBJECT_TYPE_SCRIPT_IMPORT = 1

# FNameHash::AlgorithmId, UnrealNames.cpp:733. The batch stores this as its
# HashVersion; a different value means the stored hashes are not the ones this
# module knows how to check, and the verification is reported as skipped rather
# than as passed.
FNAME_HASH_ALGORITHM_ID = 0xC1640000

# PackageStoreOptimizer.cpp:934 -- the literal prefix, and its length, that make
# an entry a class-default object.
CDO_PREFIX = "Default__"

# Confidence bands. The literal layer is a read; the decoded layer is a decode
# resting on external-doc, and is capped below it (plan.md 10.3).
CONFIDENCE_LITERAL = 0.99
CONFIDENCE_DECODED = 0.90

RERUN_CONFIRMED = ("Reproduction: the same range was read a second time through an "
                   "independently opened handle and gave the same bytes.")
RERUN_NOT_CONFIRMED = ("Reproduction: FAILED -- the second read did not agree. This "
                       "reading is NOT confirmed.")


# --------------------------------------------------------------------------- #
# CityHash64 -- CityHash.cpp:276-428, CityHash.h:91-100.
#
# Reimplemented because two fields in this container are CityHash64 values and
# checking them is the only way to know the decode is right. Every constant and
# every step below has a line citation; the masking to 64 bits is Python's
# stand-in for C's wrapping unsigned arithmetic.
# --------------------------------------------------------------------------- #

_M64 = 0xFFFFFFFFFFFFFFFF
_CITY_K0 = 0xC3A5C85C97CB3127      # CityHash.cpp:122
_CITY_K1 = 0xB492B66FBE98F273      # CityHash.cpp:123
_CITY_K2 = 0x9AE16A3B2F90404F      # CityHash.cpp:124
_CITY_KMUL = 0x9DDFEA08EB382D69    # CityHash.h:93


def _rot64(value: int, shift: int) -> int:
    """CityHash.cpp:276-279. Rotate right; shift 0 is the identity."""
    if shift == 0:
        return value
    return ((value >> shift) | (value << (64 - shift))) & _M64


def _shift_mix(value: int) -> int:
    """CityHash.cpp:281-283."""
    return value ^ (value >> 47)


def _bswap64(value: int) -> int:
    """bswap_64, CityHash.cpp:51."""
    return int.from_bytes((value & _M64).to_bytes(8, "little"), "big")


def _hash_128_to_64(low: int, high: int) -> int:
    """CityHash128to64, CityHash.h:91-100."""
    a = ((low ^ high) * _CITY_KMUL) & _M64
    a ^= a >> 47
    b = ((high ^ a) * _CITY_KMUL) & _M64
    b ^= b >> 47
    return (b * _CITY_KMUL) & _M64


def _hash_len_16(u: int, v: int, mul: int | None = None) -> int:
    """HashLen16, CityHash.cpp:285-297 (both overloads)."""
    if mul is None:
        return _hash_128_to_64(u, v)
    a = ((u ^ v) * mul) & _M64
    a ^= a >> 47
    b = ((v ^ a) * mul) & _M64
    b ^= b >> 47
    return (b * mul) & _M64


def _fetch64(data: bytes, offset: int) -> int:
    """Fetch64, CityHash.cpp:111-113 (little-endian host)."""
    return int.from_bytes(data[offset:offset + 8], "little")


def _fetch32(data: bytes, offset: int) -> int:
    """Fetch32, CityHash.cpp:115-117."""
    return int.from_bytes(data[offset:offset + 4], "little")


def _hash_len_0_to_16(data: bytes, length: int) -> int:
    """HashLen0to16, CityHash.cpp:299-324."""
    if length >= 8:
        mul = (_CITY_K2 + 2 * length) & _M64
        a = (_fetch64(data, 0) + _CITY_K2) & _M64
        b = _fetch64(data, length - 8)
        c = (_rot64(b, 37) * mul + a) & _M64
        d = ((_rot64(a, 25) + b) * mul) & _M64
        return _hash_len_16(c, d, mul)
    if length >= 4:
        mul = (_CITY_K2 + 2 * length) & _M64
        a = _fetch32(data, 0)
        return _hash_len_16((length + (a << 3)) & _M64, _fetch32(data, length - 4), mul)
    if length > 0:
        a = data[0]
        b = data[length >> 1]
        c = data[length - 1]
        y = (a + (b << 8)) & 0xFFFFFFFF
        z = (length + (c << 2)) & 0xFFFFFFFF
        return (_shift_mix(((y * _CITY_K2) & _M64) ^ ((z * _CITY_K0) & _M64))
                * _CITY_K2) & _M64
    return _CITY_K2


def _hash_len_17_to_32(data: bytes, length: int) -> int:
    """HashLen17to32, CityHash.cpp:328-338."""
    mul = (_CITY_K2 + 2 * length) & _M64
    a = (_fetch64(data, 0) * _CITY_K1) & _M64
    b = _fetch64(data, 8)
    c = (_fetch64(data, length - 8) * mul) & _M64
    d = (_fetch64(data, length - 16) * _CITY_K2) & _M64
    return _hash_len_16((_rot64((a + b) & _M64, 43) + _rot64(c, 30) + d) & _M64,
                        (a + _rot64((b + _CITY_K2) & _M64, 18) + c) & _M64, mul)


def _weak_hash_32_with_seeds(w: int, x: int, y: int, z: int, a: int, b: int):
    """WeakHashLen32WithSeeds, CityHash.cpp:342-351."""
    a = (a + w) & _M64
    b = _rot64((b + a + z) & _M64, 21)
    c = a
    a = (a + x) & _M64
    a = (a + y) & _M64
    b = (b + _rot64(a, 44)) & _M64
    return (a + z) & _M64, (b + c) & _M64


def _weak_hash_32_at(data: bytes, offset: int, a: int, b: int):
    """WeakHashLen32WithSeeds over a buffer, CityHash.cpp:354-362."""
    return _weak_hash_32_with_seeds(_fetch64(data, offset), _fetch64(data, offset + 8),
                                    _fetch64(data, offset + 16),
                                    _fetch64(data, offset + 24), a, b)


def _hash_len_33_to_64(data: bytes, length: int) -> int:
    """HashLen33to64, CityHash.cpp:365-386."""
    mul = (_CITY_K2 + 2 * length) & _M64
    a = (_fetch64(data, 0) * _CITY_K2) & _M64
    b = _fetch64(data, 8)
    c = _fetch64(data, length - 24)
    d = _fetch64(data, length - 32)
    e = (_fetch64(data, 16) * _CITY_K2) & _M64
    f = (_fetch64(data, 24) * 9) & _M64
    g = _fetch64(data, length - 8)
    h = (_fetch64(data, length - 16) * mul) & _M64
    u = (_rot64((a + g) & _M64, 43) + ((_rot64(b, 30) + c) * 9)) & _M64
    v = (((a + g) ^ d) + f + 1) & _M64
    w = (_bswap64(((u + v) * mul) & _M64) + h) & _M64
    x = (_rot64((e + f) & _M64, 42) + c) & _M64
    y = ((_bswap64(((v + w) * mul) & _M64) + g) * mul) & _M64
    z = (e + f + c) & _M64
    a = (_bswap64((((x + z) * mul) + y) & _M64) + b) & _M64
    b = (_shift_mix((((z + a) * mul) + d + h) & _M64) * mul) & _M64
    return (b + x) & _M64


def city_hash64(data: bytes) -> int:
    """CityHash64, CityHash.cpp:388-428."""
    length = len(data)
    if length <= 32:
        if length <= 16:
            return _hash_len_0_to_16(data, length)
        return _hash_len_17_to_32(data, length)
    if length <= 64:
        return _hash_len_33_to_64(data, length)

    x = _fetch64(data, length - 40)
    y = (_fetch64(data, length - 16) + _fetch64(data, length - 56)) & _M64
    z = _hash_len_16((_fetch64(data, length - 48) + length) & _M64,
                     _fetch64(data, length - 24))
    v = _weak_hash_32_at(data, length - 64, length, z)
    w = _weak_hash_32_at(data, length - 32, (y + _CITY_K1) & _M64, x)
    x = ((x * _CITY_K1) + _fetch64(data, 0)) & _M64

    remaining = (length - 1) & ~63
    offset = 0
    while remaining != 0:
        x = (_rot64((x + y + v[0] + _fetch64(data, offset + 8)) & _M64, 37)
             * _CITY_K1) & _M64
        y = (_rot64((y + v[1] + _fetch64(data, offset + 48)) & _M64, 42)
             * _CITY_K1) & _M64
        x ^= w[1]
        y = (y + v[0] + _fetch64(data, offset + 40)) & _M64
        z = (_rot64((z + w[0]) & _M64, 33) * _CITY_K1) & _M64
        v = _weak_hash_32_at(data, offset, (v[1] * _CITY_K1) & _M64, (x + w[0]) & _M64)
        w = _weak_hash_32_at(data, offset + 32, (z + w[1]) & _M64,
                             (y + _fetch64(data, offset + 16)) & _M64)
        z, x = x, z
        offset += 64
        remaining -= 64
    return _hash_len_16((_hash_len_16(v[0], w[0]) + ((_shift_mix(y) * _CITY_K1) & _M64)
                         + z) & _M64,
                        (_hash_len_16(v[1], w[1]) + x) & _M64)


# --------------------------------------------------------------------------- #
# BLAKE3-160 -- FIoHash (IoHash.h:23, 156-163), the hash the TOC stores per
# chunk. Reimplemented so the extraction can be PROVEN rather than asserted.
# Correctness is not taken on trust: blake3_self_test() runs the 21 first-party
# vectors of Blake3Test.cpp:18-49 on every invocation.
# --------------------------------------------------------------------------- #

_B3_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
          0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
_B3_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
_B3_CHUNK_START = 1
_B3_CHUNK_END = 2
_B3_PARENT = 4
_B3_ROOT = 8
_B3_BLOCK_BYTES = 64
_B3_CHUNK_BYTES = 1024
_M32 = 0xFFFFFFFF


def _b3_schedule() -> tuple[tuple[int, ...], ...]:
    """The 7 rounds' message-word orders, precomputed so no permutation runs in
    the inner loop."""
    rounds = []
    current = tuple(range(16))
    for _ in range(7):
        rounds.append(current)
        current = tuple(current[_B3_PERMUTATION[i]] for i in range(16))
    return tuple(rounds)


_B3_SCHEDULE = _b3_schedule()


def _b3_compress(cv, block: bytes, counter: int, block_len: int, flags: int):
    """The BLAKE3 compression function. State words are kept in locals and the
    G function is written out inline: this runs ~35 500 times for the real
    chunk, and a helper call per G would dominate the runtime."""
    m = struct.unpack("<16I", block)
    s0, s1, s2, s3, s4, s5, s6, s7 = cv
    s8, s9, s10, s11 = _B3_IV[0], _B3_IV[1], _B3_IV[2], _B3_IV[3]
    s12 = counter & _M32
    s13 = (counter >> 32) & _M32
    s14 = block_len
    s15 = flags
    for sch in _B3_SCHEDULE:
        s0 = (s0 + s4 + m[sch[0]]) & _M32
        s12 ^= s0
        s12 = ((s12 >> 16) | (s12 << 16)) & _M32
        s8 = (s8 + s12) & _M32
        s4 ^= s8
        s4 = ((s4 >> 12) | (s4 << 20)) & _M32
        s0 = (s0 + s4 + m[sch[1]]) & _M32
        s12 ^= s0
        s12 = ((s12 >> 8) | (s12 << 24)) & _M32
        s8 = (s8 + s12) & _M32
        s4 ^= s8
        s4 = ((s4 >> 7) | (s4 << 25)) & _M32

        s1 = (s1 + s5 + m[sch[2]]) & _M32
        s13 ^= s1
        s13 = ((s13 >> 16) | (s13 << 16)) & _M32
        s9 = (s9 + s13) & _M32
        s5 ^= s9
        s5 = ((s5 >> 12) | (s5 << 20)) & _M32
        s1 = (s1 + s5 + m[sch[3]]) & _M32
        s13 ^= s1
        s13 = ((s13 >> 8) | (s13 << 24)) & _M32
        s9 = (s9 + s13) & _M32
        s5 ^= s9
        s5 = ((s5 >> 7) | (s5 << 25)) & _M32

        s2 = (s2 + s6 + m[sch[4]]) & _M32
        s14 ^= s2
        s14 = ((s14 >> 16) | (s14 << 16)) & _M32
        s10 = (s10 + s14) & _M32
        s6 ^= s10
        s6 = ((s6 >> 12) | (s6 << 20)) & _M32
        s2 = (s2 + s6 + m[sch[5]]) & _M32
        s14 ^= s2
        s14 = ((s14 >> 8) | (s14 << 24)) & _M32
        s10 = (s10 + s14) & _M32
        s6 ^= s10
        s6 = ((s6 >> 7) | (s6 << 25)) & _M32

        s3 = (s3 + s7 + m[sch[6]]) & _M32
        s15 ^= s3
        s15 = ((s15 >> 16) | (s15 << 16)) & _M32
        s11 = (s11 + s15) & _M32
        s7 ^= s11
        s7 = ((s7 >> 12) | (s7 << 20)) & _M32
        s3 = (s3 + s7 + m[sch[7]]) & _M32
        s15 ^= s3
        s15 = ((s15 >> 8) | (s15 << 24)) & _M32
        s11 = (s11 + s15) & _M32
        s7 ^= s11
        s7 = ((s7 >> 7) | (s7 << 25)) & _M32

        s0 = (s0 + s5 + m[sch[8]]) & _M32
        s15 ^= s0
        s15 = ((s15 >> 16) | (s15 << 16)) & _M32
        s10 = (s10 + s15) & _M32
        s5 ^= s10
        s5 = ((s5 >> 12) | (s5 << 20)) & _M32
        s0 = (s0 + s5 + m[sch[9]]) & _M32
        s15 ^= s0
        s15 = ((s15 >> 8) | (s15 << 24)) & _M32
        s10 = (s10 + s15) & _M32
        s5 ^= s10
        s5 = ((s5 >> 7) | (s5 << 25)) & _M32

        s1 = (s1 + s6 + m[sch[10]]) & _M32
        s12 ^= s1
        s12 = ((s12 >> 16) | (s12 << 16)) & _M32
        s11 = (s11 + s12) & _M32
        s6 ^= s11
        s6 = ((s6 >> 12) | (s6 << 20)) & _M32
        s1 = (s1 + s6 + m[sch[11]]) & _M32
        s12 ^= s1
        s12 = ((s12 >> 8) | (s12 << 24)) & _M32
        s11 = (s11 + s12) & _M32
        s6 ^= s11
        s6 = ((s6 >> 7) | (s6 << 25)) & _M32

        s2 = (s2 + s7 + m[sch[12]]) & _M32
        s13 ^= s2
        s13 = ((s13 >> 16) | (s13 << 16)) & _M32
        s8 = (s8 + s13) & _M32
        s7 ^= s8
        s7 = ((s7 >> 12) | (s7 << 20)) & _M32
        s2 = (s2 + s7 + m[sch[13]]) & _M32
        s13 ^= s2
        s13 = ((s13 >> 8) | (s13 << 24)) & _M32
        s8 = (s8 + s13) & _M32
        s7 ^= s8
        s7 = ((s7 >> 7) | (s7 << 25)) & _M32

        s3 = (s3 + s4 + m[sch[14]]) & _M32
        s14 ^= s3
        s14 = ((s14 >> 16) | (s14 << 16)) & _M32
        s9 = (s9 + s14) & _M32
        s4 ^= s9
        s4 = ((s4 >> 12) | (s4 << 20)) & _M32
        s3 = (s3 + s4 + m[sch[15]]) & _M32
        s14 ^= s3
        s14 = ((s14 >> 8) | (s14 << 24)) & _M32
        s9 = (s9 + s14) & _M32
        s4 ^= s9
        s4 = ((s4 >> 7) | (s4 << 25)) & _M32
    c0, c1, c2, c3, c4, c5, c6, c7 = cv
    return (s0 ^ s8, s1 ^ s9, s2 ^ s10, s3 ^ s11, s4 ^ s12, s5 ^ s13, s6 ^ s14,
            s7 ^ s15, s8 ^ c0, s9 ^ c1, s10 ^ c2, s11 ^ c3, s12 ^ c4, s13 ^ c5,
            s14 ^ c6, s15 ^ c7)


class _B3Output:
    """One BLAKE3 node's pending compression. Kept unevaluated because the ROOT
    flag is only known at the very end, and the root node must be compressed
    WITH it -- which is why a tree cannot simply be folded as it is built."""

    __slots__ = ("cv", "block", "counter", "block_len", "flags")

    def __init__(self, cv, block: bytes, counter: int, block_len: int, flags: int):
        self.cv = cv
        self.block = block
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self):
        return _b3_compress(self.cv, self.block, self.counter, self.block_len,
                            self.flags)[:8]

    def root_bytes32(self) -> bytes:
        words = _b3_compress(self.cv, self.block, self.counter, self.block_len,
                             self.flags | _B3_ROOT)[:8]
        return struct.pack("<8I", *words)


def _b3_chunk_output(chunk: bytes, counter: int) -> _B3Output:
    cv = _B3_IV
    length = len(chunk)
    blocks = ((length + _B3_BLOCK_BYTES - 1) // _B3_BLOCK_BYTES) or 1
    for index in range(blocks - 1):
        flags = _B3_CHUNK_START if index == 0 else 0
        cv = _b3_compress(cv, chunk[index * _B3_BLOCK_BYTES:
                                    (index + 1) * _B3_BLOCK_BYTES],
                          counter, _B3_BLOCK_BYTES, flags)[:8]
    tail = chunk[(blocks - 1) * _B3_BLOCK_BYTES:]
    tail_len = len(tail)
    flags = (_B3_CHUNK_START if blocks == 1 else 0) | _B3_CHUNK_END
    return _B3Output(cv, tail + bytes(_B3_BLOCK_BYTES - tail_len), counter,
                     tail_len, flags)


def _b3_parent_output(left, right) -> _B3Output:
    return _B3Output(_B3_IV, struct.pack("<8I", *left) + struct.pack("<8I", *right),
                     0, _B3_BLOCK_BYTES, _B3_PARENT)


def blake3_256(data: bytes) -> bytes:
    """BLAKE3-256 of *data*, one shot."""
    length = len(data)
    offset = 0
    counter = 0
    stack: list[tuple[int, ...]] = []
    while length - offset > _B3_CHUNK_BYTES:
        value = _b3_chunk_output(data[offset:offset + _B3_CHUNK_BYTES],
                                 counter).chaining_value()
        counter += 1
        offset += _B3_CHUNK_BYTES
        total = counter
        while total & 1 == 0:
            value = _b3_parent_output(stack.pop(), value).chaining_value()
            total >>= 1
        stack.append(value)
    output = _b3_chunk_output(data[offset:], counter)
    while stack:
        output = _b3_parent_output(stack.pop(), output.chaining_value())
    return output.root_bytes32()


def blake3_160(data: bytes) -> bytes:
    """FIoHash: the first 20 bytes of a BLAKE3-256 (IoHash.h:23, 156-163)."""
    return blake3_256(data)[:IO_HASH_BYTES]


# Blake3Test.cpp:18-41. Copied verbatim from the first-party test, including the
# input rule at Blake3Test.cpp:46-49 (byte i == i % 251).
BLAKE3_TEST_VECTORS: tuple[tuple[int, str], ...] = (
    (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
    (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
    (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"),
    (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
    (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
    (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"),
    (2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"),
    (3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"),
    (3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3"),
    (4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"),
    (4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"),
    (5120, "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833"),
    (5121, "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff"),
    (6144, "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205"),
    (6145, "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f"),
    (7168, "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a"),
    (7169, "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817"),
    (8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"),
    (8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"),
    (16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"),
    (31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"),
)


def blake3_self_test() -> dict:
    """Run the first-party vectors. A tool whose central proof is a hash must
    prove the hash first; if this fails, nothing else in the run is trusted."""
    longest = max(length for length, _ in BLAKE3_TEST_VECTORS)
    source = bytes(index % 251 for index in range(longest))
    failures = []
    for length, expected in BLAKE3_TEST_VECTORS:
        got = blake3_256(source[:length]).hex()
        if got != expected:
            failures.append({"input_length": length, "expected": expected, "got": got})
    return {
        "vectors": len(BLAKE3_TEST_VECTORS),
        "passed": len(BLAKE3_TEST_VECTORS) - len(failures),
        "failures": failures,
        "all_passed": not failures,
        "source": "Engine/Source/Runtime/Core/Tests/Hash/Blake3Test.cpp:18-49",
        "note": ("input byte i == i %% 251 (Blake3Test.cpp:46-49); the vector set "
                 "spans %d..%d bytes, so the multi-chunk tree merge is covered and "
                 "not only the single-chunk path"
                 % (BLAKE3_TEST_VECTORS[0][0], longest)),
    }


# --------------------------------------------------------------------------- #
# UE string helpers
# --------------------------------------------------------------------------- #

def ue_to_lower(text: str) -> str:
    """TChar::ToLower, Char.h:88-91 -- ASCII A-Z only, nothing else."""
    return "".join(chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch for ch in text)


def generate_import_hash_from_object_path(path: str) -> int:
    """FPackageObjectIndex::GenerateImportHashFromObjectPath, AsyncLoading2.cpp:221-240.

    '.' and ':' become '/', every other character is lowercased, then CityHash64
    over the TCHAR buffer -- UTF-16LE, because TCHAR is 2 bytes on Windows
    (AsyncLoading2.cpp:237 hashes Len * sizeof(TCHAR) bytes) -- and the top two
    bits are cleared (AsyncLoading2.cpp:238).
    """
    converted = "".join("/" if ch in ".:" else
                        (chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch)
                        for ch in path)
    return city_hash64(converted.encode("utf-16-le")) & ~(3 << 62)


def align_up(value: int, alignment: int) -> int:
    """Align(), as the engine's Align() template does it."""
    if alignment <= 0:
        return value
    return ((value + alignment - 1) // alignment) * alignment


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def locus_target(path: str, install_root: str | None) -> str:
    """The install-relative path of *path*, or its basename if it is outside one.

    A class-P claim must name a determinate location, and a basename is an
    ambiguity class. Mirrors tools/content/pak_index.py and
    tools/static/rtti_scan.py.
    """
    if install_root:
        try:
            relative = os.path.relpath(os.path.abspath(path), os.path.abspath(install_root))
        except ValueError:
            relative = ""
        if relative and not relative.startswith(".."):
            return relative.replace(os.sep, "/")
    return os.path.basename(path)


def _detect_install_root(path: str) -> str:
    """The installation *path* belongs to, via pathguard's own predicate.

    Mirrors ``tools/content/pak_index.py``, fallback included: when nothing
    above *path* looks like an installation, the configured install root is
    returned rather than None. ``pathguard.check_output_path`` REFUSES a None
    install root outright -- "a caller that does not know which tree it is
    working on is a bug, not a licence to skip the check" -- and this fallback
    keeps the guard armed for every known and structurally detected
    installation while protecting nothing that is not one.
    """
    try:
        roots = pathguard.structural_install_roots(os.path.abspath(path))
    except (ValueError, OSError):
        roots = []
    if roots:
        return roots[-1]
    return pathguard.CONFIGURED_INSTALL_ROOTS[0]


def stream_sha256(path: str, buf_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(buf_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# literal layer (class P)
# --------------------------------------------------------------------------- #

def literal_read(target: str, offset: int, raw: bytes, note: str | None = None) -> dict:
    """One class-P record: WHERE and HOW MANY bytes, and what they were.

    The claim sentence deliberately names no field, no layout and no type: under
    plan.md 10.3 v2.4 that is the condition for the container-metadata oracle to
    be class P at all. The evidence metadata is attached as the REDUCED
    annotation envelope of ``kb-record.schema.json#/$defs/annotation`` -- the
    same shape ``tools/content/pak_index.py`` uses -- so a document holding
    these records is linted as annotations rather than as full knowledge-base
    records, which would ask each read for a build_key and a claim_type the
    annotation schema forbids.

    ``reproduced`` starts false and is set by ``confirm_literal_reads``, which
    re-reads the range through a NEW handle: criterion 2 of the class-P band is
    mandatory and must be true, not claimed.
    """
    claim = ("%d byte(s) at offset %d of %s are %s"
             % (len(raw), offset, target, hex_bytes(raw)))
    return {
        "target": target,
        "offset": offset,
        "length": len(raw),
        "bytes_hex": hex_bytes(raw),
        "claim": claim,
        "note": note,
        "reproduced": False,
        "evidence": {
            "evidence_level": "OBSERVED",
            "claim_class": "P",
            "confidence": CONFIDENCE_LITERAL,
            "oracle": ["container-metadata"],
            "read_locus": {
                "target": target,
                "address_kind": "file-offset",
                "offset": offset,
                "length": len(raw),
                "bytes_hex": hex_bytes(raw),
                "note": note,
            },
            "sources": [{
                "method": "RF-01 container read",
                "artifact": None,
                "locator": "%s@%d+%d" % (target, offset, len(raw)),
                "note": ("oracle container-metadata. Read by %s, read-only. %s"
                         % (GENERATOR_NAME, RERUN_NOT_CONFIRMED)),
            }],
            "note": ("%s. This record gives the position and the extent, and "
                     "nothing else. %s" % (claim, RERUN_NOT_CONFIRMED)),
        },
    }


def confirm_literal_reads(literals: list[dict], paths: dict[str, str]) -> int:
    """Re-read every literal range through a freshly opened handle.

    Returns the number of records that did NOT reproduce. Opening a new handle
    matters: it is what makes the second read an independent act rather than a
    second look at the same buffer.
    """
    failures = 0
    handles: dict[str, object] = {}
    try:
        for record in literals:
            path = paths.get(record["target"])
            if not path:
                record["reproduction_note"] = ("no file is registered for target %r"
                                               % record["target"])
                failures += 1
                continue
            handle = handles.get(path)
            if handle is None:
                handle = open(path, "rb")
                handles[path] = handle
            handle.seek(record["offset"])
            raw = handle.read(record["length"])
            reproduced = hex_bytes(raw) == record["bytes_hex"]
            record["reproduced"] = reproduced
            verdict = RERUN_CONFIRMED if reproduced else RERUN_NOT_CONFIRMED
            record["evidence"]["note"] = record["evidence"]["note"].replace(
                RERUN_NOT_CONFIRMED, verdict)
            for source in record["evidence"]["sources"]:
                source["note"] = source["note"].replace(RERUN_NOT_CONFIRMED, verdict)
            if not reproduced:
                failures += 1
    finally:
        for handle in handles.values():
            handle.close()
    return failures


def decoded_annotation(*, note: str, sources: list, oracle: list[str],
                       confidence: float = CONFIDENCE_DECODED,
                       evidence_level: str = "OBSERVED") -> dict:
    """One class-I annotation for the interpreted layer.

    Same reduced-envelope shape as ``literal_read``'s ``evidence``, and
    deliberately carrying no ``claim_type``: adding one turns the object into a
    full knowledge-base record, which is then owed a ``build_key`` and a
    ``recorded_at`` that the enclosing document already states once. The full
    records this tool writes are the reflection JSONL lines, where the envelope
    belongs.
    """
    return {
        "evidence_level": evidence_level,
        "claim_class": "I",
        "confidence": confidence,
        "oracle": oracle,
        "read_locus": None,
        "sources": sources,
        "note": note,
    }


# --------------------------------------------------------------------------- #
# the TOC: header via container_info, body walked here
# --------------------------------------------------------------------------- #

def tile_check(sections: list[tuple[str, int, int]], total: int, what: str) -> dict:
    """Does *sections* cover ``[0, total)`` exactly -- no gaps, no overlaps?

    Zero-length sections are recorded but can neither gap nor overlap. The point
    of this check is that a wrong stride or a missing array shows up here as a
    non-zero gap or overlap, LOUDLY, instead of as a plausible but wrong list.
    """
    rows = []
    gaps: list[dict] = []
    overlaps: list[dict] = []
    cursor = 0
    for name, start, size in sorted(sections, key=lambda item: (item[1], item[2])):
        rows.append({"section": name, "offset": start, "length": size})
        if size == 0:
            continue
        if start > cursor:
            gaps.append({"before": name, "offset": cursor, "length": start - cursor})
        elif start < cursor:
            overlaps.append({"section": name, "offset": start,
                             "length": cursor - start})
        cursor = max(cursor, start + size)
    tail = total - cursor
    return {
        "what": what,
        "sections": rows,
        "total": total,
        "covered_extent": cursor,
        "gap_count": len(gaps),
        "gaps": gaps,
        "overlap_count": len(overlaps),
        "overlaps": overlaps,
        "trailing_bytes": tail,
        "tiles_exactly": not gaps and not overlaps and tail == 0,
    }


def parse_toc(utoc_path: str, target: str, warnings: list[str],
              literals: list[dict], literal_samples: int) -> dict:
    """Parse one ``.utoc`` down to the chunk table, the block table and the metas.

    The 144-byte header is decoded by ``container_info`` -- one parser, one
    opinion (see the import comment). Everything after it is walked here in the
    order ``FIoStoreTocResource::Read`` walks it (IoStore.cpp:3215-3318), and the
    walk ends with a tiling check against the file size.
    """
    file_size = os.path.getsize(utoc_path)
    if file_size > MAX_TOC_BYTES:
        raise ContainerParseError("%s: %d bytes is larger than the %d-byte limit "
                                  "this parser will read"
                                  % (target, file_size, MAX_TOC_BYTES))
    if file_size < container_info.TOC_HEADER_SIZE_EXPECTED:
        raise ContainerParseError("%s: %d bytes cannot hold a %d-byte TOC header"
                                  % (target, file_size,
                                     container_info.TOC_HEADER_SIZE_EXPECTED))

    with open(utoc_path, "rb") as handle:
        raw = handle.read(file_size)

    header = raw[:container_info.TOC_HEADER_SIZE_EXPECTED]
    if header[:16] != container_info.TOC_MAGIC:
        raise ContainerParseError(
            "%s: the first 16 bytes are %s, not the IoStore TOC magic %s"
            % (target, hex_bytes(header[:16]), hex_bytes(container_info.TOC_MAGIC)))

    values = container_info.decode_toc_header_fields(header)
    version = values["version"]
    if version > TOC_VERSION_LATEST_5_4:
        warnings.append(
            "%s: TOC version %d is newer than EIoStoreTocVersion::Latest of UE 5.4 "
            "(%d, IoStore.h:22-33). The body layout is computed with the newest "
            "rules container_info knows; a changed array would move every offset "
            "after it, so this is reported rather than assumed away."
            % (target, version, TOC_VERSION_LATEST_5_4))
    if values["toc_header_size"] != container_info.TOC_HEADER_SIZE_EXPECTED:
        raise ContainerParseError(
            "%s: TocHeaderSize is %d, and IoStore.cpp:3169 requires it to equal "
            "sizeof(FIoStoreTocHeader) == %d"
            % (target, values["toc_header_size"],
               container_info.TOC_HEADER_SIZE_EXPECTED))
    if values["toc_compressed_block_entry_size"] != IO_BLOCK_ENTRY_SIZE:
        raise ContainerParseError(
            "%s: TocCompressedBlockEntrySize is %d, and IoStore.cpp:3174 requires "
            "it to equal sizeof(FIoStoreTocCompressedBlockEntry) == %d"
            % (target, values["toc_compressed_block_entry_size"],
               IO_BLOCK_ENTRY_SIZE))

    entry_count = values["toc_entry_count"]
    block_count = values["toc_compressed_block_entry_count"]
    if entry_count > MAX_TOC_ENTRIES:
        raise ContainerParseError("%s: TocEntryCount %d exceeds the %d clamp"
                                  % (target, entry_count, MAX_TOC_ENTRIES))
    if block_count > MAX_TOC_BLOCKS:
        raise ContainerParseError("%s: TocCompressedBlockEntryCount %d exceeds the "
                                  "%d clamp" % (target, block_count, MAX_TOC_BLOCKS))

    flags_value = int(values["container_flags"], 16)
    flags_decoded, flags_unknown = container_info.decode_container_flags(flags_value)
    layout = container_info.toc_body_layout(values, version)
    if layout["signed"]:
        # The signature block sits between the method names and the directory
        # index, and its size is stored inside itself, so every later offset
        # moves by an amount this parser has not read. Refuse rather than guess.
        raise ContainerParseError(
            "%s: the Signed container flag is set (IoDispatcher.h:470). The "
            "signature block (IoStore.cpp:3272-3302) shifts the directory index "
            "and the chunk metas by an amount stored inside itself, and this "
            "parser does not read it. Refusing rather than reporting shifted "
            "offsets." % target)

    # container_info.toc_body_layout computes `total` -- the size the whole file
    # must have if every header field means what the public layout says it
    # means -- precisely so it can be compared with the file. A total LARGER
    # than the file is not a warning: it means the header describes bytes that
    # do not exist, so every offset past the shortfall is invented and the
    # tiling numbers below would be arithmetic on nothing. Refuse.
    if layout["total"] > file_size:
        raise ContainerParseError(
            "%s: the header describes %d bytes of TOC (header %d + chunk ids %d "
            "+ offset/lengths %d + seeds %d + overflow %d + blocks %d + method "
            "names %d + directory index %d + metas %d) but the file is %d bytes. "
            "The header is self-inconsistent, so nothing after the shortfall can "
            "be located; refusing rather than reporting shifted offsets."
            % (target, layout["total"], values["toc_header_size"],
               layout["sections"]["chunk_ids"],
               layout["sections"]["chunk_offset_lengths"],
               layout["sections"]["perfect_hash_seeds"],
               layout["sections"]["chunks_without_perfect_hash"],
               layout["sections"]["compression_blocks"],
               layout["sections"]["compression_method_names"],
               values["directory_index_size"], layout["chunk_metas_size"],
               file_size))
    if layout["total"] < file_size:
        warnings.append(
            "%s: the header describes %d bytes but the file is %d, so %d "
            "byte(s) at the end belong to no section this layout knows about. "
            "The tiling probe reports them as trailing bytes."
            % (target, layout["total"], file_size, file_size - layout["total"]))

    offsets = layout["offsets"]

    def section(name: str, size: int) -> bytes:
        start = offsets[name]
        end = start + size
        if end > file_size:
            raise ContainerParseError(
                "%s: section %s wants bytes %d..%d but the file is %d bytes"
                % (target, name, start, end, file_size))
        return raw[start:end]

    chunk_id_bytes = section("chunk_ids", entry_count * IO_CHUNK_ID_SIZE)
    offlen_bytes = section("chunk_offset_lengths",
                           entry_count * IO_OFFSET_AND_LENGTH_SIZE)
    block_bytes = section("compression_blocks", block_count * IO_BLOCK_ENTRY_SIZE)
    method_bytes = section("compression_method_names",
                           values["compression_method_name_count"]
                           * values["compression_method_name_length"])

    # IoStore.cpp:3258 -- slot 0 of the runtime table is NAME_None, so the stored
    # per-block index is 1-based into the names that follow it.
    methods = ["None"] + container_info.split_method_name_table(
        method_bytes, values["compression_method_name_count"],
        values["compression_method_name_length"], warnings, target,
        "compression method name")

    chunks: list[dict] = []
    for index in range(entry_count):
        cid = chunk_id_bytes[index * IO_CHUNK_ID_SIZE:(index + 1) * IO_CHUNK_ID_SIZE]
        pair = offlen_bytes[index * IO_OFFSET_AND_LENGTH_SIZE:
                            (index + 1) * IO_OFFSET_AND_LENGTH_SIZE]
        type_byte = cid[11]                          # IoChunkId.h:111
        chunks.append({
            "index": index,
            "chunk_id_hex": cid.hex(),
            "chunk_type_byte": type_byte,
            "chunk_type": IO_CHUNK_TYPES.get(type_byte, "UNKNOWN(%d)" % type_byte),
            # IoOffsetLength.h:20-38 -- five BIG-endian bytes each.
            "offset": int.from_bytes(pair[0:5], "big"),
            "length": int.from_bytes(pair[5:10], "big"),
        })

    blocks: list[dict] = []
    for index in range(block_count):
        entry = block_bytes[index * IO_BLOCK_ENTRY_SIZE:
                            (index + 1) * IO_BLOCK_ENTRY_SIZE]
        # IoStore.h:119-159, the three little-endian sub-fields and the method byte.
        blocks.append({
            "index": index,
            "offset": int.from_bytes(entry[0:5], "little"),
            "compressed_size": int.from_bytes(entry[5:8], "little"),
            "uncompressed_size": int.from_bytes(entry[8:11], "little"),
            "compression_method_index": entry[11],
        })

    metas: list[dict] = []
    meta_start = layout["directory_index_offset"] + values["directory_index_size"]
    for index in range(entry_count):
        start = meta_start + index * IO_CHUNK_META_SIZE
        if start + IO_CHUNK_META_SIZE > file_size:
            warnings.append("%s: chunk meta %d would end past the end of the file; "
                            "metas from %d on are not read" % (target, index, index))
            break
        blob = raw[start:start + IO_CHUNK_META_SIZE]
        metas.append({
            "index": index,
            # IoDispatcher.h:134-140: 20 BLAKE3-160 bytes, then 12 zero bytes.
            "chunk_hash_blake3_160": blob[:IO_HASH_BYTES].hex(),
            "chunk_hash_tail_is_zero": blob[IO_HASH_BYTES:32] == bytes(12),
            "meta_flags": blob[32],
            "meta_flags_decoded": [name for bit, name in
                                   ((0x01, "Compressed"), (0x02, "MemoryMapped"))
                                   if blob[32] & bit],
        })

    # ---- class-P literal reads, bounded and deterministic -------------------
    literals.append(literal_read(target, 0, header[:16],
                                 note="the first 16 bytes of the file"))
    literals.append(literal_read(target, 16, header[16:20]))
    literals.append(literal_read(target, 20, header[20:56]))
    literals.append(literal_read(target, 56, header[56:84]))
    literals.append(literal_read(target, 84, header[84:104]))
    for index in range(min(entry_count, literal_samples)):
        start = offsets["chunk_ids"] + index * IO_CHUNK_ID_SIZE
        literals.append(literal_read(target, start,
                                     raw[start:start + IO_CHUNK_ID_SIZE]))
        start = offsets["chunk_offset_lengths"] + index * IO_OFFSET_AND_LENGTH_SIZE
        literals.append(literal_read(target, start,
                                     raw[start:start + IO_OFFSET_AND_LENGTH_SIZE]))
    for index in range(min(block_count, literal_samples)):
        start = offsets["compression_blocks"] + index * IO_BLOCK_ENTRY_SIZE
        literals.append(literal_read(target, start,
                                     raw[start:start + IO_BLOCK_ENTRY_SIZE]))
    for meta in metas[:literal_samples]:
        start = meta_start + meta["index"] * IO_CHUNK_META_SIZE
        literals.append(literal_read(target, start,
                                     raw[start:start + IO_CHUNK_META_SIZE]))

    # ---- tiling: does every byte of the file belong to exactly one section? --
    ordered = [
        ("header", 0, container_info.TOC_HEADER_SIZE_EXPECTED),
        ("chunk_ids", offsets["chunk_ids"], layout["sections"]["chunk_ids"]),
        ("chunk_offset_lengths", offsets["chunk_offset_lengths"],
         layout["sections"]["chunk_offset_lengths"]),
        ("perfect_hash_seeds", offsets["perfect_hash_seeds"],
         layout["sections"]["perfect_hash_seeds"]),
        ("chunks_without_perfect_hash", offsets["chunks_without_perfect_hash"],
         layout["sections"]["chunks_without_perfect_hash"]),
        ("compression_blocks", offsets["compression_blocks"],
         layout["sections"]["compression_blocks"]),
        ("compression_method_names", offsets["compression_method_names"],
         layout["sections"]["compression_method_names"]),
        ("directory_index", layout["directory_index_offset"],
         values["directory_index_size"]),
        ("chunk_metas", meta_start, len(metas) * IO_CHUNK_META_SIZE),
    ]
    tiling = tile_check(ordered, file_size, "%s, whole file" % target)

    return {
        "path": utoc_path,
        "target": target,
        "file_size": file_size,
        "header": values,
        "version": version,
        "container_flags_value": flags_value,
        "container_flags_decoded": flags_decoded,
        "container_flags_unknown_bits": "0x%02x" % flags_unknown,
        "is_compressed_flag": bool(flags_value & 0x01),
        "is_encrypted": bool(flags_value & 0x02),
        "is_signed": bool(flags_value & 0x04),
        "is_indexed": bool(flags_value & 0x08),
        "is_on_demand": bool(flags_value & 0x10),
        "body_layout": layout,
        "compression_methods": methods,
        "chunks": chunks,
        "blocks": blocks,
        "chunk_metas": metas,
        "chunk_meta_offset": meta_start,
        "tiling": tiling,
    }


# --------------------------------------------------------------------------- #
# reading one chunk out of the .ucas -- D-02 gated, see PAYLOAD_POLICY
# --------------------------------------------------------------------------- #

def find_script_objects_chunk(toc: dict) -> tuple[int | None, str]:
    """Locate the ``EIoChunkType::ScriptObjects`` chunk. Returns (index, reason).

    Two conditions must agree, so a single wrong byte cannot select a chunk:
    the type byte at ``Id[11]`` must be 5 (IoChunkId.h:33, 111), AND the whole
    12-byte id must equal ``CreateIoChunkId(0, 0, ScriptObjects)``
    (IoChunkId.h:136-150), which is the id ``IoStoreUtilities.cpp:6921`` asks the
    global container for.
    """
    expected = (b"\x00" * 11) + bytes([CHUNK_TYPE_SCRIPT_OBJECTS])
    by_type = [chunk for chunk in toc["chunks"]
               if chunk["chunk_type_byte"] == CHUNK_TYPE_SCRIPT_OBJECTS]
    if not by_type:
        return None, ("no chunk in this container carries type byte %d "
                      "(EIoChunkType::ScriptObjects, IoChunkId.h:33)"
                      % CHUNK_TYPE_SCRIPT_OBJECTS)
    exact = [chunk for chunk in by_type
             if bytes.fromhex(chunk["chunk_id_hex"]) == expected]
    if not exact:
        return by_type[0]["index"], (
            "chunk %d has the ScriptObjects type byte but its id %s is not "
            "CreateIoChunkId(0, 0, ScriptObjects) == %s; using it anyway and "
            "reporting the difference"
            % (by_type[0]["index"], by_type[0]["chunk_id_hex"], expected.hex()))
    if len(exact) > 1:
        return exact[0]["index"], ("%d chunks share the ScriptObjects id; the "
                                   "first is used" % len(exact))
    return exact[0]["index"], "exact match on CreateIoChunkId(0, 0, ScriptObjects)"


def chunk_block_range(toc: dict, chunk: dict) -> tuple[int, int]:
    """FirstBlockIndex..LastBlockIndex for *chunk*, IoStore.cpp:2729-2730."""
    block_size = toc["header"]["compression_block_size"]
    if block_size <= 0:
        raise ContainerParseError("CompressionBlockSize is %d" % block_size)
    first = chunk["offset"] // block_size
    last = (align_up(chunk["offset"] + chunk["length"], block_size) - 1) // block_size
    return first, last


def read_chunk(ucas_path: str, ucas_target: str, toc: dict, chunk: dict,
               warnings: list[str]) -> tuple[bytes, dict]:
    """Assemble one chunk's bytes out of the ``.ucas``. D-02 gate first.

    Nothing here decrypts and nothing here decompresses: the gate refuses any
    container whose Encrypted flag is set and any block whose compression-method
    index is not 0, so the only code path that exists is the plain memcpy of
    IoStore.cpp:2799-2806.
    """
    if toc["is_encrypted"]:
        raise ContainerParseError(
            "the container's Encrypted flag is set (%s). D-02: this tool does not "
            "derive, search for or use a key, and reads no payload from an "
            "encrypted container." % toc["header"]["container_flags"])

    first, last = chunk_block_range(toc, chunk)
    if first < 0 or last >= len(toc["blocks"]):
        raise ContainerParseError(
            "chunk %d needs blocks %d..%d but the TOC holds %d"
            % (chunk["index"], first, last, len(toc["blocks"])))
    if chunk["length"] > MAX_CHUNK_BYTES:
        raise ContainerParseError("chunk %d declares %d bytes, over the %d clamp"
                                  % (chunk["index"], chunk["length"],
                                     MAX_CHUNK_BYTES))

    partition_size = int(toc["header"]["partition_size"], 16)
    used = [toc["blocks"][index] for index in range(first, last + 1)]
    bad = [block for block in used if block["compression_method_index"] != 0]
    if bad:
        raise ContainerParseError(
            "%d of the chunk's %d blocks name a compression method index other "
            "than 0 (first: block %d, index %d). This tool performs no "
            "decompression; refusing rather than returning partial bytes."
            % (len(bad), len(used), bad[0]["index"],
               bad[0]["compression_method_index"]))

    ucas_size = os.path.getsize(ucas_path)
    payload = bytearray()
    reads: list[dict] = []
    with open(ucas_path, "rb") as handle:
        for block in used:
            # IoStore.cpp:2749-2750 -- partition index and offset within it. A
            # single-partition container makes this the identity, but the
            # arithmetic is written out rather than assumed.
            partition_index = (block["offset"] // partition_size
                               if partition_size else 0)
            partition_offset = (block["offset"] % partition_size
                                if partition_size else block["offset"])
            if partition_index != 0:
                raise ContainerParseError(
                    "block %d lives in partition %d; this tool reads partition 0 "
                    "only (the extra partitions are separate _sN.ucas files, "
                    "IoStore.cpp:2369-2375)"
                    % (block["index"], partition_index))
            end = partition_offset + block["uncompressed_size"]
            if end > ucas_size:
                raise ContainerParseError(
                    "block %d wants bytes %d..%d but %s is %d bytes"
                    % (block["index"], partition_offset, end, ucas_target,
                       ucas_size))
            handle.seek(partition_offset)
            got = handle.read(block["uncompressed_size"])
            if len(got) != block["uncompressed_size"]:
                raise ContainerParseError(
                    "block %d: wanted %d bytes at %d, got %d"
                    % (block["index"], block["uncompressed_size"],
                       partition_offset, len(got)))
            payload += got
            reads.append({"block": block["index"], "offset": partition_offset,
                          "length": block["uncompressed_size"]})

    # IoStore.cpp:2707-2711: the chunk starts at (chunk offset % block size)
    # inside the first block and runs for `length` bytes.
    block_size = toc["header"]["compression_block_size"]
    start_in_block = chunk["offset"] % block_size
    data = bytes(payload[start_in_block:start_in_block + chunk["length"]])
    if len(data) != chunk["length"]:
        raise ContainerParseError("assembled %d bytes for a chunk that declares %d"
                                  % (len(data), chunk["length"]))

    detail = {
        "first_block": first,
        "last_block": last,
        "block_count": last - first + 1,
        "offset_in_first_block": start_in_block,
        "blocks_read": reads,
        "compression_method_indexes": sorted({block["compression_method_index"]
                                              for block in used}),
        "ucas_file_size": ucas_size,
    }
    return data, detail


def verify_chunk_hash(data: bytes, toc: dict, chunk_index: int) -> dict:
    """Does the assembled chunk hash to the FIoChunkHash the TOC stores for it?

    This is the D-02 proof described in the module docstring: the TOC's hash is
    of the SOURCE data (IoStore.h:91), so agreement means the bytes the engine
    parses are the bytes we just read, with no decryption or decompression step
    in between. 160 bits of margin.
    """
    metas = {meta["index"]: meta for meta in toc["chunk_metas"]}
    meta = metas.get(chunk_index)
    computed = blake3_160(data).hex()
    if meta is None:
        return {"verified": False, "reason": "no chunk meta was read for chunk %d"
                                             % chunk_index,
                "computed_blake3_160": computed, "stored_blake3_160": None,
                "matches": None}
    stored = meta["chunk_hash_blake3_160"]
    return {
        "verified": True,
        "reason": None,
        "computed_blake3_160": computed,
        "stored_blake3_160": stored,
        "matches": computed == stored,
        "stored_tail_is_zero": meta["chunk_hash_tail_is_zero"],
        "meta_flags": meta["meta_flags"],
        "meta_flags_decoded": meta["meta_flags_decoded"],
        "what_this_proves": (
            "the bytes assembled from the .ucas are byte-for-byte the bytes the "
            "engine reads as this chunk: IoStore.h:91 says the stored hash is of "
            "the source data, so a match cannot happen through a decode this "
            "tool got wrong. It does NOT prove anything about what the bytes "
            "mean -- that is the interpreted layer below."),
    }


def ucas_tiling(toc: dict, ucas_size: int, ucas_target: str) -> dict:
    """Do the compression blocks tile ``global.ucas``?

    Two models are reported rather than one being picked silently. The engine
    reads ``Align(CompressedSize, FAES::AESBlockSize)`` bytes per block
    (IoStore.cpp:2741) and the writer reserves that much (IoStore.cpp:1929,
    1972), so a container whose last block is not a multiple of 16 is EXPECTED
    to be a few bytes longer than the sum of the block sizes. Saying which model
    the file matches is a finding; assuming one is how a parser hides a bug.
    """
    blocks = sorted(toc["blocks"], key=lambda block: block["offset"])
    packed = [(("block_%d" % block["index"]), block["offset"],
               block["compressed_size"]) for block in blocks]
    aligned_end = 0
    packed_end = 0
    for block in blocks:
        packed_end = max(packed_end, block["offset"] + block["compressed_size"])
        aligned_end = max(aligned_end,
                          block["offset"] + align_up(block["compressed_size"],
                                                     AES_BLOCK_SIZE))
    tiling = tile_check(packed, ucas_size, "%s, compression blocks" % ucas_target)
    tiling["packed_end"] = packed_end
    tiling["aes_aligned_end"] = aligned_end
    tiling["file_size"] = ucas_size
    tiling["matches_packed_model"] = packed_end == ucas_size
    tiling["matches_aes_aligned_model"] = aligned_end == ucas_size
    tiling["trailing_bytes_over_packed_model"] = ucas_size - packed_end
    tiling["model_note"] = (
        "packed = sum of the block extents; aes_aligned = each block extent "
        "rounded up to FAES::AESBlockSize (16), which is what IoStore.cpp:2741 "
        "reads and IoStore.cpp:1929/1972 reserves. A file that matches the "
        "aligned model and not the packed one is correctly formed, not short.")
    return tiling


# --------------------------------------------------------------------------- #
# the serialized name batch -- UnrealNames.cpp:4435-4470 / 4869-4903
# --------------------------------------------------------------------------- #

def parse_name_batch(data: bytes, offset: int, target: str,
                     warnings: list[str]) -> tuple[list[str], list[bool], dict]:
    """Decode the archive-form name batch at *offset*.

    Returns ``(names, wide_flags, meta)``. ``wide_flags`` is kept beside the
    strings rather than folded into them because the stored hash is taken over
    the name's ON-THE-WIRE character width (UnrealNames.cpp:854-857), and an
    all-ASCII name written as UTF-16 hashes differently from the same name
    written as ANSI. Recovering the width from the decoded string would be a
    guess; carrying the header bit is not.

    Layout and every constant are cited in the module docstring. Two things are
    easy to get wrong and are called out because getting either wrong silently
    shifts every following name:

    * the strings are packed with NO padding in this (separated) form --
      UnrealNames.cpp:4599-4632. The interleaved form pads UTF-16 names
      (UnrealNames.cpp:4379-4396); that form is not what an FArchive batch uses.
    * ``Len`` is a CHARACTER count, so a UTF-16 name consumes ``2 * Len`` bytes
      (UnrealNames.cpp:4370-4373).
    """
    # Only the first uint32 is guaranteed to be there: UnrealNames.cpp:4441-4443
    # writes Num and STOPS when Num is zero, so demanding all 16 header bytes
    # up front refuses a legitimately empty batch.
    if offset + 4 > len(data):
        raise ContainerParseError("%s: no room for the name batch count at %d"
                                  % (target, offset))
    count, = struct.unpack_from("<I", data, offset)
    if count != 0 and offset + NAME_BATCH_HEADER_SIZE > len(data):
        raise ContainerParseError("%s: the batch declares %d names but there is "
                                  "no room for the %d-byte header at %d"
                                  % (target, count, NAME_BATCH_HEADER_SIZE, offset))

    if count == 0:
        # UnrealNames.cpp:4441-4443 / 4874-4878: a zero count ends the batch, and
        # the two later fields are not written at all.
        return [], [], {
            "count": 0, "string_bytes": 0,
            "hash_version": None,
            "hash_version_is_fname_algorithm_id": False,
            "header_offset": offset, "header_size": 4,
            "hashes_offset": None, "headers_offset": None, "strings_offset": None,
            "end_offset": offset + 4,
            "wide_names": 0, "ansi_names": 0,
            "note": "Num == 0, so UnrealNames.cpp:4441 wrote nothing else",
        }

    string_bytes, = struct.unpack_from("<I", data, offset + 4)
    hash_version, = struct.unpack_from("<Q", data, offset + 8)

    if count > MAX_NAME_COUNT:
        raise ContainerParseError("%s: name batch declares %d names, over the %d "
                                  "clamp" % (target, count, MAX_NAME_COUNT))
    if string_bytes > MAX_NAME_STRING_BYTES:
        raise ContainerParseError("%s: name batch declares %d string bytes, over "
                                  "the %d clamp"
                                  % (target, string_bytes, MAX_NAME_STRING_BYTES))

    hashes_at = offset + NAME_BATCH_HEADER_SIZE
    headers_at = hashes_at + 8 * count
    strings_at = headers_at + SERIALIZED_NAME_HEADER_SIZE * count
    end_at = strings_at + string_bytes
    if end_at > len(data):
        raise ContainerParseError(
            "%s: the name batch would end at %d but the chunk is %d bytes"
            % (target, end_at, len(data)))

    names: list[str] = []
    wide_flags: list[bool] = []
    wide = 0
    cursor = strings_at
    for index in range(count):
        head = data[headers_at + SERIALIZED_NAME_HEADER_SIZE * index:
                    headers_at + SERIALIZED_NAME_HEADER_SIZE * index + 2]
        is_utf16 = bool(head[0] & 0x80)              # UnrealNames.cpp:4360-4363
        length = ((head[0] & 0x7F) << 8) | head[1]   # UnrealNames.cpp:4365-4368
        if length > MAX_NAME_LEN:
            raise ContainerParseError(
                "%s: name %d declares %d characters; NAME_SIZE is 1024 "
                "(NameTypes.h), so the header table is not being read correctly"
                % (target, index, length))
        byte_length = length * (2 if is_utf16 else 1)
        if cursor + byte_length > end_at:
            raise ContainerParseError(
                "%s: name %d would read past the end of the string blob "
                "(%d + %d > %d)" % (target, index, cursor, byte_length, end_at))
        raw = data[cursor:cursor + byte_length]
        cursor += byte_length
        wide_flags.append(is_utf16)
        if is_utf16:
            wide += 1
            try:
                names.append(raw.decode("utf-16-le"))
            except UnicodeDecodeError as error:
                raise ContainerParseError("%s: name %d does not decode as UTF-16LE: "
                                          "%s" % (target, index, error)) from error
        else:
            # ANSICHAR is a byte; latin-1 is the identity mapping and never
            # raises, so a non-ASCII byte is preserved instead of being hidden.
            names.append(raw.decode("latin-1"))

    if cursor != end_at:
        raise ContainerParseError(
            "%s: the name headers consumed %d string bytes but the batch declared "
            "%d. UnrealNames.cpp:4614 asserts exactly this equality, so a "
            "mismatch means the header stride is wrong."
            % (target, cursor - strings_at, string_bytes))

    meta = {
        "count": count,
        "string_bytes": string_bytes,
        "hash_version": "0x%016x" % hash_version,
        "hash_version_is_fname_algorithm_id": hash_version == FNAME_HASH_ALGORITHM_ID,
        "header_offset": offset,
        "header_size": NAME_BATCH_HEADER_SIZE,
        "hashes_offset": hashes_at,
        "hashes_size": 8 * count,
        "headers_offset": headers_at,
        "headers_size": SERIALIZED_NAME_HEADER_SIZE * count,
        "strings_offset": strings_at,
        "strings_size": string_bytes,
        "end_offset": end_at,
        "wide_names": wide,
        "ansi_names": count - wide,
        "note": None,
    }
    if not meta["hash_version_is_fname_algorithm_id"]:
        warnings.append(
            "%s: the name batch HashVersion is %s, not FNameHash::AlgorithmId "
            "0x%08x (UnrealNames.cpp:733). The stored hashes are then not the "
            "ones this module knows how to recompute, and the per-name "
            "verification is reported as skipped rather than as passed."
            % (target, meta["hash_version"], FNAME_HASH_ALGORITHM_ID))
    return names, wide_flags, meta


def verify_name_hashes(data: bytes, names: list[str], wide_flags: list[bool],
                       meta: dict) -> dict:
    """Recompute every stored name hash. One independent check per name.

    ``SaveNameBatch`` stores ``GenerateLowerCaseHash(name)`` beside each header
    (UnrealNames.cpp:4431/4854), which is ``CityHash64`` over the LOWERCASED name
    bytes -- one byte per character for an ANSI name, two for a UTF-16 one
    (UnrealNames.cpp:843-857). Those bytes live in a different part of the chunk
    from the strings and were produced by a different function, so agreement is
    a real second measurement of the decode and not a restatement of it.
    """
    if not names or meta["hashes_offset"] is None:
        return {"checked": 0, "mismatches": 0, "examples": [], "all_match": True,
                "skipped_reason": "the batch holds no names"}
    if not meta["hash_version_is_fname_algorithm_id"]:
        return {"checked": 0, "mismatches": 0, "examples": [], "all_match": None,
                "skipped_reason": ("HashVersion %s is not FNameHash::AlgorithmId, "
                                   "so the stored hashes are not comparable"
                                   % meta["hash_version"])}
    # The count and the example list are kept apart on purpose: an example list
    # capped at 8 that is also used as the count would under-report 9 failures
    # as 8, and a verification that lies low about its own failures is worse
    # than none.
    mismatch_count = 0
    mismatches = []
    base = meta["hashes_offset"]
    for index, name in enumerate(names):
        stored, = struct.unpack_from("<Q", data, base + 8 * index)
        lowered = ue_to_lower(name)
        # The width follows the header bit, not the content: an all-ASCII name
        # stored as UTF-16 is hashed over 2 bytes per character.
        raw = (lowered.encode("utf-16-le") if wide_flags[index]
               else lowered.encode("latin-1"))
        computed = city_hash64(raw)
        if computed != stored:
            mismatch_count += 1
            if len(mismatches) < 8:
                mismatches.append({"index": index, "name": name,
                                   "wide": wide_flags[index],
                                   "stored": "0x%016x" % stored,
                                   "computed": "0x%016x" % computed})
    return {
        "checked": len(names),
        "mismatches": mismatch_count,
        "examples": mismatches,
        "all_match": mismatch_count == 0,
        "skipped_reason": None,
        "method": ("CityHash64 (CityHash.cpp:388-428) over the lowercased name "
                   "bytes, compared with the uint64 stored at "
                   "hashes_offset + 8*index (UnrealNames.cpp:4431)"),
    }


# --------------------------------------------------------------------------- #
# the script-object map -- AsyncLoading2.h:324-337, PackageStoreOptimizer.cpp
# --------------------------------------------------------------------------- #

def parse_script_objects(data: bytes, offset: int, names: list[str],
                         target: str) -> tuple[list[dict], dict]:
    """Read ``int32 NumScriptObjects`` and the entry array that follows it."""
    if offset + 4 > len(data):
        raise ContainerParseError("%s: no room for NumScriptObjects at %d"
                                  % (target, offset))
    count, = struct.unpack_from("<i", data, offset)
    if count < 0 or count > MAX_SCRIPT_OBJECTS:
        raise ContainerParseError("%s: NumScriptObjects is %d, which is outside "
                                  "0..%d" % (target, count, MAX_SCRIPT_OBJECTS))
    array_at = offset + 4
    end_at = array_at + count * SCRIPT_OBJECT_ENTRY_SIZE
    if end_at > len(data):
        raise ContainerParseError(
            "%s: %d entries of %d bytes would end at %d but the chunk is %d bytes"
            % (target, count, SCRIPT_OBJECT_ENTRY_SIZE, end_at, len(data)))

    entries: list[dict] = []
    non_global = 0
    out_of_range = 0
    for index in range(count):
        at = array_at + index * SCRIPT_OBJECT_ENTRY_SIZE
        # AsyncLoading2.cpp:169-176 + MappedName.cpp:8-13 + AsyncLoading2.h:152-156.
        name_index_raw, name_number, global_index, outer_index, cdo_index = \
            struct.unpack_from("<IIQQQ", data, at)
        name_index = name_index_raw & MAPPED_NAME_INDEX_MASK   # MappedName.h:82-85
        name_type = name_index_raw >> MAPPED_NAME_INDEX_BITS   # MappedName.h:24-27
        if name_type != MAPPED_NAME_TYPE_GLOBAL:
            non_global += 1
        if name_index >= len(names):
            out_of_range += 1
            base = None
        else:
            base = names[name_index]
        entries.append({
            "index": index,
            "offset": at,
            "name_index": name_index,
            "name_type": name_type,
            "name_number": name_number,
            "name": format_fname(base, name_number),
            "global_index": global_index,
            "outer_index": outer_index,
            "cdo_class_index": cdo_index,
        })

    meta = {
        "count": count,
        "count_offset": offset,
        "array_offset": array_at,
        "entry_size": SCRIPT_OBJECT_ENTRY_SIZE,
        "array_size": count * SCRIPT_OBJECT_ENTRY_SIZE,
        "end_offset": end_at,
        "name_index_out_of_range": out_of_range,
        "mapped_names_not_global": non_global,
    }
    return entries, meta


def format_fname(base: str | None, number: int) -> str | None:
    """FName::AppendString, UnrealNames.cpp:3465-3475.

    ``Number`` is the INTERNAL number: 0 means no suffix, and any other value
    appends ``_`` and ``Number - 1`` (NameTypes.h:138-142).
    """
    if base is None:
        return None
    if number == 0:
        return base
    return "%s_%d" % (base, number - 1)


def package_object_index_type(value: int) -> str:
    """AsyncLoading2.h:99-122. Invalid reads as type 3, i.e. Null."""
    if value == PACKAGE_OBJECT_INDEX_INVALID:
        return "Null"
    return PACKAGE_OBJECT_TYPES.get(value >> PACKAGE_OBJECT_INDEX_BITS, "Unknown")


def build_full_paths(entries: list[dict], warnings: list[str]) -> dict:
    """Walk each entry's outer chain up to its package and join with '/'.

    This mirrors PackageStoreOptimizer.cpp:966-996 (the roots) and
    PackageStoreOptimizer.cpp:916-918 (the recursion), which is where the
    container's own full names came from, and IoStoreUtilities.cpp:6943-6969,
    which is how the engine's own analysis tool rebuilds them. It is iterative
    rather than recursive because the depth comes from a file.
    """
    by_global: dict[int, dict] = {}
    duplicates = 0
    for entry in entries:
        if entry["global_index"] in by_global:
            duplicates += 1
        by_global[entry["global_index"]] = entry

    paths: dict[int, str | None] = {}
    unresolved_outer = 0
    cycles = 0
    for entry in entries:
        if entry["global_index"] in paths:
            continue
        stack: list[dict] = []
        seen: set[int] = set()
        current: dict | None = entry
        prefix: str | None = None
        while current is not None:
            gid = current["global_index"]
            if gid in paths:
                prefix = paths[gid]
                break
            if gid in seen:
                cycles += 1
                prefix = None
                break
            seen.add(gid)
            stack.append(current)
            outer = current["outer_index"]
            if outer == PACKAGE_OBJECT_INDEX_INVALID:
                prefix = ""
                break
            nxt = by_global.get(outer)
            if nxt is None:
                unresolved_outer += 1
                prefix = None
                break
            current = nxt
        while stack:
            node = stack.pop()
            if prefix is None:
                paths[node["global_index"]] = None
            elif prefix == "":
                paths[node["global_index"]] = node["name"]
            else:
                paths[node["global_index"]] = "%s/%s" % (prefix, node["name"])
            prefix = paths[node["global_index"]]

    if duplicates:
        warnings.append("%d entries share a GlobalIndex with an earlier entry; the "
                        "last one wins, as TMap::Add does "
                        "(PackageStoreOptimizer.cpp:945)" % duplicates)
    if unresolved_outer:
        warnings.append("%d entries name an OuterIndex that is not itself an entry "
                        "in this container" % unresolved_outer)
    if cycles:
        warnings.append("%d entries sit on an outer cycle" % cycles)

    return {
        "by_global": by_global,
        "paths": paths,
        "duplicate_global_indexes": duplicates,
        "unresolved_outer": unresolved_outer,
        "cycles": cycles,
    }


def verify_global_indexes(entries: list[dict], paths: dict[int, str | None]) -> dict:
    """Is every reconstructed path confirmed by the entry's own GlobalIndex?

    ``FPackageObjectIndex::FromScriptPath`` (AsyncLoading2.h:87-90) hashes the
    lowercased path with CityHash64 over UTF-16 and clears the top two bits
    (AsyncLoading2.cpp:221-240); the writer then stores that value as the
    entry's GlobalIndex (PackageStoreOptimizer.cpp:921, 946). So recomputing it
    from the path we rebuilt is a 62-bit test of THE OUTER CHAIN -- the part
    that turns a list of words into a map. Nothing else in this file can catch a
    wrong parent.
    """
    checked = 0
    mismatch_count = 0
    mismatches: list[dict] = []
    wrong_type = 0
    skipped = 0
    for entry in entries:
        path = paths.get(entry["global_index"])
        if path is None:
            skipped += 1
            continue
        checked += 1
        if (entry["global_index"] >> PACKAGE_OBJECT_INDEX_BITS) != \
                PACKAGE_OBJECT_TYPE_SCRIPT_IMPORT:
            wrong_type += 1
        want = entry["global_index"] & PACKAGE_OBJECT_INDEX_MASK
        got = generate_import_hash_from_object_path(path)
        if got != want:
            mismatch_count += 1
            if len(mismatches) < 8:
                mismatches.append({"index": entry["index"], "path": path,
                                   "stored": "0x%016x" % want,
                                   "computed": "0x%016x" % got})
    return {
        "checked": checked,
        "skipped_unresolved": skipped,
        "mismatches": mismatch_count,
        "examples": mismatches,
        "entries_not_typed_script_import": wrong_type,
        "all_match": mismatch_count == 0,
        "method": ("CityHash64 over the UTF-16LE bytes of the lowercased "
                   "reconstructed path with '.' and ':' folded to '/' and the top "
                   "two bits cleared (AsyncLoading2.cpp:221-240), compared with "
                   "the low 62 bits of the entry's own GlobalIndex"),
    }


def verify_cdo_links(entries: list[dict], paths: dict[int, str | None],
                     by_global: dict[int, dict]) -> dict:
    """Check every CDOClassIndex against the rule that produced it.

    PackageStoreOptimizer.cpp:929-943 is a two-branch rule and BOTH branches are
    checked here, because checking only the first one reports 14 false
    mismatches on this container and a reader would have no way to tell them
    from a decode error:

        FPackageObjectIndex CDOClassIndex = OuterCDOClassIndex;   // :929
        if (CDOClassIndex.IsNull())                               // :930
        {
            if (name starts with "Default__")                     // :934
                CDOClassIndex = FromScriptPath(OuterFullName + "/" + name+9);
        }

    So the ``Default__`` rule applies ONLY when the outer's own CDOClassIndex is
    null. An object named ``Default__X`` that sits inside another class-default
    object -- ``/Script/Engine/Default__Material/Default__MaterialEditorOnlyData``
    is the real case in this build -- INHERITS the outer's value and never
    computes its own, and its stored index therefore names the OUTER's class.
    That branch is verified too, by requiring the stored value to equal the
    outer's exactly.
    """
    computed_checked = 0
    computed_matched = 0
    computed_mismatched = 0
    inherited_checked = 0
    inherited_matched = 0
    inherited_mismatched = 0
    mismatches: list[dict] = []
    resolves_to_entry = 0
    for entry in entries:
        name = entry["name"]
        if entry["cdo_class_index"] == PACKAGE_OBJECT_INDEX_INVALID:
            continue
        outer = by_global.get(entry["outer_index"])
        outer_inherits = (outer is not None
                          and outer["cdo_class_index"] != PACKAGE_OBJECT_INDEX_INVALID)
        if outer_inherits:
            # Branch :929 -- the value is the outer's, unchanged.
            inherited_checked += 1
            if entry["cdo_class_index"] == outer["cdo_class_index"]:
                inherited_matched += 1
                if entry["cdo_class_index"] in by_global:
                    resolves_to_entry += 1
            else:
                inherited_mismatched += 1
                if len(mismatches) < 8:
                    mismatches.append({
                        "branch": "inherited-from-outer",
                        "index": entry["index"], "name": name,
                        "stored": "0x%016x" % entry["cdo_class_index"],
                        "outers_value": "0x%016x" % outer["cdo_class_index"]})
            continue
        if name is None or not name.startswith(CDO_PREFIX):
            # A non-Default__ object whose outer has no CDO index should not
            # carry one at all -- neither branch of the rule can give it one.
            inherited_checked += 1
            inherited_mismatched += 1
            if len(mismatches) < 8:
                mismatches.append({
                    "branch": "neither-branch-applies",
                    "index": entry["index"], "name": name,
                    "stored": "0x%016x" % entry["cdo_class_index"],
                    "outers_value": None})
            continue
        outer_path = paths.get(entry["outer_index"])
        if outer_path is None:
            continue
        computed_checked += 1
        want = entry["cdo_class_index"] & PACKAGE_OBJECT_INDEX_MASK
        candidate = "%s/%s" % (outer_path, name[len(CDO_PREFIX):])
        got = generate_import_hash_from_object_path(candidate)
        if got == want:
            computed_matched += 1
            if entry["cdo_class_index"] in by_global:
                resolves_to_entry += 1
        else:
            computed_mismatched += 1
            if len(mismatches) < 8:
                mismatches.append({"branch": "computed-from-Default__-prefix",
                                   "index": entry["index"], "name": name,
                                   "expected_class_path": candidate,
                                   "stored": "0x%016x" % want,
                                   "computed": "0x%016x" % got})
    return {
        "computed_branch_checked": computed_checked,
        "computed_branch_matched": computed_matched,
        "computed_branch_mismatched": computed_mismatched,
        "inherited_branch_checked": inherited_checked,
        "inherited_branch_matched": inherited_matched,
        "inherited_branch_mismatched": inherited_mismatched,
        "checked": computed_checked + inherited_checked,
        "matched": computed_matched + inherited_matched,
        "mismatches": computed_mismatched + inherited_mismatched,
        "examples": mismatches,
        "cdo_class_index_resolves_to_an_entry": resolves_to_entry,
        "all_match": (computed_mismatched + inherited_mismatched) == 0,
        "method": ("branch :934 -- CityHash64 of the lowercased outer path + '/' "
                   "+ the name without its 9-character Default__ prefix, "
                   "compared with the stored CDOClassIndex; branch :929 -- the "
                   "stored value compared with the outer's own, byte for byte"),
    }


# --------------------------------------------------------------------------- #
# classification -- what this container CAN and CANNOT say about a name
# --------------------------------------------------------------------------- #

# The vocabulary below is deliberately NOT the UE type vocabulary. There is no
# type tag in FScriptObjectEntry (AsyncLoading2.h:324-337), so "class" would be
# a claim the bytes do not carry. Each role states what the CONTAINER shows.
ROLE_PACKAGE = "package"
ROLE_CLASS_WITH_CDO = "class_with_cdo"
ROLE_CDO = "class_default_object"
ROLE_CDO_SUBOBJECT = "cdo_subobject"
ROLE_MEMBER_OF_CLASS = "member_of_class_with_cdo"
ROLE_PACKAGE_MEMBER = "package_member_unclassified"
ROLE_NESTED = "nested_unclassified"
ROLE_UNRESOLVED = "unresolved"

ROLE_DEFINITIONS = {
    ROLE_PACKAGE: {
        "means": "a UPackage: OuterIndex is Null",
        "source": ("PackageStoreOptimizer.cpp:966-996 -- the roots of the map are "
                   "exactly the UPackage objects returned by "
                   "FindAllRuntimeScriptPackages, and each is written with "
                   "OuterIndex = FPackageObjectIndex(), i.e. Invalid "
                   "(AsyncLoading2.h:61)"),
        "certainty": "OBSERVED: the field is read; the meaning is the writer's",
    },
    ROLE_CDO: {
        "means": ("the class-default object of the class named by CDOClassIndex: "
                  "the name begins with Default__ AND the stored CDOClassIndex "
                  "equals the hash of outer-path + '/' + the rest of the name"),
        "source": "PackageStoreOptimizer.cpp:932-942",
        "certainty": ("OBSERVED for the link, because the recomputed hash matches "
                      "the stored one -- this is the writer's own statement, not "
                      "a naming convention"),
    },
    ROLE_CLASS_WITH_CDO: {
        "means": ("a UClass: some sibling entry is its class-default object and "
                  "points at it by CDOClassIndex"),
        "source": ("PackageStoreOptimizer.cpp:932-942 for the link; a CDO exists "
                   "only for a UClass, so an object that owns one is a UClass"),
        "certainty": ("INFERRED. The container has no type tag; the inference is "
                      "from the existence of a matching CDO and nothing else. A "
                      "UClass whose CDO is not RF_Public would be missed "
                      "(PackageStoreOptimizer.cpp:899-903)"),
    },
    ROLE_CDO_SUBOBJECT: {
        "means": ("a public UObject inside a class-default object's subtree: it "
                  "carries a non-null CDOClassIndex inherited from its outer"),
        "source": "PackageStoreOptimizer.cpp:906-911, 929",
        "certainty": "OBSERVED for the CDOClassIndex field; the KIND is unknown",
    },
    ROLE_MEMBER_OF_CLASS: {
        "means": "a public UObject whose outer is a UClass",
        "source": "PackageStoreOptimizer.cpp:952-957 (GetObjectsWithOuter)",
        "certainty": ("UNKNOWN kind. In practice these are UFunction and "
                      "UDelegateFunction objects, but a UEnum or a UScriptStruct "
                      "declared inside a class scope is stored identically and "
                      "this container cannot tell them apart"),
    },
    ROLE_PACKAGE_MEMBER: {
        "means": "a public UObject directly inside a script package, with no CDO",
        "source": "PackageStoreOptimizer.cpp:990-995",
        "certainty": ("UNKNOWN kind: a UScriptStruct, a UEnum, a "
                      "UDelegateFunction and a UClass without a public CDO are "
                      "all stored identically here"),
    },
    ROLE_NESTED: {
        "means": "a public UObject deeper in the tree, outer is not a UClass",
        "source": "PackageStoreOptimizer.cpp:952-957",
        "certainty": "UNKNOWN kind",
    },
    ROLE_UNRESOLVED: {
        "means": "the outer chain could not be walked to a package",
        "source": None,
        "certainty": "UNKNOWN",
    },
}


def classify(entries: list[dict], paths: dict[int, str | None],
             by_global: dict[int, dict]) -> dict:
    """Assign every entry a ROLE, and attribute it to its root package.

    The one real inference here is ROLE_CLASS_WITH_CDO, and it is made from the
    CDOClassIndex link rather than from the ``Default__`` spelling: an entry is
    called a class only when a sibling CDO's stored CDOClassIndex EQUALS that
    entry's GlobalIndex. A renamed object cannot fake that; a 62-bit hash
    collision could, and 34 912 of them could not.
    """
    # Only a VERIFIED link credits a class. The two conditions are the two
    # branches of PackageStoreOptimizer.cpp:929-943: the outer must not already
    # carry a CDOClassIndex (or the value is inherited, not computed -- see
    # verify_cdo_links), and the recomputed hash must equal the stored one.
    class_ids: set[int] = set()
    cdo_of: dict[int, int] = {}
    genuine_cdo: set[int] = set()
    for entry in entries:
        name = entry["name"]
        if name is None or not name.startswith(CDO_PREFIX):
            continue
        target_id = entry["cdo_class_index"]
        if target_id == PACKAGE_OBJECT_INDEX_INVALID:
            continue
        outer = by_global.get(entry["outer_index"])
        if outer is not None and \
                outer["cdo_class_index"] != PACKAGE_OBJECT_INDEX_INVALID:
            continue                       # inherited from the outer, branch :929
        outer_path = paths.get(entry["outer_index"])
        if outer_path is None:
            continue
        recomputed = generate_import_hash_from_object_path(
            "%s/%s" % (outer_path, name[len(CDO_PREFIX):]))
        if recomputed != (target_id & PACKAGE_OBJECT_INDEX_MASK):
            continue
        genuine_cdo.add(entry["global_index"])
        if target_id in by_global:
            class_ids.add(target_id)
            cdo_of[target_id] = entry["global_index"]

    roles: dict[int, str] = {}
    for entry in entries:
        gid = entry["global_index"]
        name = entry["name"]
        path = paths.get(gid)
        if path is None:
            roles[gid] = ROLE_UNRESOLVED
            continue
        if entry["outer_index"] == PACKAGE_OBJECT_INDEX_INVALID:
            roles[gid] = ROLE_PACKAGE
            continue
        if gid in class_ids:
            roles[gid] = ROLE_CLASS_WITH_CDO
            continue
        if gid in genuine_cdo:
            roles[gid] = ROLE_CDO
            continue
        if entry["cdo_class_index"] != PACKAGE_OBJECT_INDEX_INVALID:
            roles[gid] = ROLE_CDO_SUBOBJECT
            continue
        outer = by_global.get(entry["outer_index"])
        if outer is not None and outer["global_index"] in class_ids:
            roles[gid] = ROLE_MEMBER_OF_CLASS
            continue
        if outer is not None and outer["outer_index"] == PACKAGE_OBJECT_INDEX_INVALID:
            roles[gid] = ROLE_PACKAGE_MEMBER
            continue
        roles[gid] = ROLE_NESTED

    # The root package of every entry, found by walking outers to the top.
    root_of: dict[int, int | None] = {}
    for entry in entries:
        gid = entry["global_index"]
        if gid in root_of:
            continue
        chain: list[int] = []
        current: dict | None = entry
        root: int | None = None
        seen: set[int] = set()
        while current is not None:
            cid = current["global_index"]
            if cid in root_of:
                root = root_of[cid]
                break
            if cid in seen:
                break
            seen.add(cid)
            chain.append(cid)
            if current["outer_index"] == PACKAGE_OBJECT_INDEX_INVALID:
                root = cid
                break
            current = by_global.get(current["outer_index"])
        for cid in chain:
            root_of[cid] = root

    return {"roles": roles, "class_ids": class_ids, "cdo_of": cdo_of,
            "genuine_cdo": genuine_cdo, "root_of": root_of,
            "role_histogram": dict(Counter(roles.values()))}


def build_modules(entries: list[dict], paths: dict[int, str | None],
                  classification: dict) -> list[dict]:
    """One row per root package: how many objects, and of which roles."""
    roles = classification["roles"]
    root_of = classification["root_of"]
    buckets: dict[int | None, Counter] = {}
    totals: Counter = Counter()
    for entry in entries:
        gid = entry["global_index"]
        root = root_of.get(gid)
        buckets.setdefault(root, Counter())[roles.get(gid, ROLE_UNRESOLVED)] += 1
        totals[root] += 1

    rows: list[dict] = []
    for root, counter in buckets.items():
        name = paths.get(root) if root is not None else None
        rows.append({
            "package": name,
            "package_global_index": ("0x%016x" % root) if root is not None else None,
            "objects": totals[root],
            "roles": {role: counter[role] for role in sorted(counter)},
            "classes_with_cdo": counter[ROLE_CLASS_WITH_CDO],
            "class_default_objects": counter[ROLE_CDO],
            "members_of_classes": counter[ROLE_MEMBER_OF_CLASS],
            "package_members_unclassified": counter[ROLE_PACKAGE_MEMBER],
        })
    rows.sort(key=lambda row: (row["package"] is None, row["package"] or ""))
    return rows


def module_short_name(package_path: str | None) -> str | None:
    """``/Script/Engine`` -> ``Engine``. Anything else is returned unchanged."""
    if not package_path:
        return None
    if package_path.startswith("/Script/"):
        return package_path[len("/Script/"):]
    return package_path


def compare_with_staged_plugins(modules: list[dict], staged_path: str | None,
                                warnings: list[str]) -> dict:
    """Compare the module set with the staged ``.uplugin`` names from V-07.

    The comparison is reported, never collapsed into a verdict, because a plugin
    is NOT a module: one .uplugin can declare several modules and none of them
    has to share its name, and most engine modules are not in a plugin at all.
    So a name on one side and not the other is a fact about the two NAME SETS,
    and the reader is told that in the output rather than left to assume it.
    """
    if not staged_path:
        return {"available": False,
                "reason": "no --staged-plugins path was given", "counts": None}
    if not os.path.isfile(staged_path):
        warnings.append("staged plugin list not found at %s" % staged_path)
        return {"available": False,
                "reason": "file not found: %s" % staged_path, "counts": None}

    plugin_names: set[str] = set()
    plugin_paths: dict[str, str] = {}
    other_lines = 0
    with open(staged_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip().replace("\\", "/")
            if not line or line.startswith("#"):
                continue
            if line.lower().endswith(".uplugin"):
                name = os.path.basename(line)[:-len(".uplugin")]
                plugin_names.add(name)
                plugin_paths[name] = line
            else:
                other_lines += 1

    module_names = {module_short_name(row["package"]) for row in modules
                    if row["package"] and row["package"].startswith("/Script/")}
    module_names.discard(None)

    both = sorted(module_names & plugin_names)
    module_only = sorted(module_names - plugin_names)
    plugin_only = sorted(plugin_names - module_names)

    # The staged list carries the plugin's PATH, and the path says whose plugin
    # it is: Engine/Plugins/... ships with the engine, MISERY/Plugins/... was
    # added to this project. That second group is the game-side third-party
    # surface, and it is worth separating because a marketplace plugin is game
    # content in the sense that matters here -- it is not part of vanilla UE
    # 5.4 and so cannot be assumed known. Whether each one's NAME also appears
    # as a module is reported per plugin rather than as a total, because one
    # .uplugin routinely declares several differently named modules and the
    # totals above cannot show that.
    game_side = []
    for name in sorted(plugin_names):
        path = plugin_paths[name]
        if path.startswith("Engine/"):
            continue
        game_side.append({
            "plugin": name,
            "staged_path": path,
            "module_of_the_same_name_exists": name in module_names,
        })

    return {
        "available": True,
        "reason": None,
        "staged_plugins_path": staged_path,
        "counts": {
            "staged_uplugin_names": len(plugin_names),
            "script_modules": len(module_names),
            "name_in_both": len(both),
            "module_name_not_a_staged_plugin_name": len(module_only),
            "staged_plugin_name_with_no_module_of_that_name": len(plugin_only),
            "non_uplugin_lines_in_the_staged_list": other_lines,
            "staged_plugins_outside_engine_plugins": len(game_side),
        },
        "name_in_both": both,
        "staged_plugins_outside_engine_plugins": game_side,
        "staged_plugin_name_with_no_module_of_that_name": plugin_only,
        "reading_rule": (
            "A .uplugin is not a module. One plugin may declare several modules "
            "under different names, and the great majority of /Script modules "
            "belong to the engine rather than to any plugin. So 'name in both' "
            "is a lower bound on agreement and 'plugin with no module of that "
            "name' is NOT evidence that the plugin is absent from the build -- "
            "it is evidence that its modules are named differently, which is the "
            "normal case. The list is emitted so a later method (reading the "
            "Modules array of each .uplugin) can close it."),
    }


# --------------------------------------------------------------------------- #
# refutation probes -- find the same facts WITHOUT the header table
# --------------------------------------------------------------------------- #

def ascii_scan_probe(data: bytes, needle: bytes, names: list[str],
                     entity_count: int, what: str) -> dict:
    """Count literal occurrences of *needle* in the raw chunk.

    This is A-08's method -- a byte scan with no layout at all -- run against
    the decode. If the header-table walk had the wrong stride, the two numbers
    would part company; A-08 got 394 occurrences of ``/Script/`` and 6515 of
    ``Default__`` from a plain strings run before this parser existed, so the
    comparison is a genuine outside check.

    What the scan can be compared with is the number of DISTINCT NAMES that
    start with the needle, not the number of entries that use them: the batch
    stores each distinct string once (UnrealNames.cpp:4452-4462), so a name
    shared by two objects is one occurrence in the bytes and two rows in the
    map. On this container that is the whole of the difference between 6515 and
    6520, and comparing against the entry count instead would report a
    disagreement where there is none. The entry count is carried alongside so
    the gap stays visible rather than being smoothed away.
    """
    count = 0
    at = data.find(needle)
    while at != -1:
        count += 1
        at = data.find(needle, at + 1)
    text = needle.decode("ascii")
    distinct = sum(1 for name in names if name.startswith(text))
    return {
        "needle": text,
        "literal_occurrences_in_chunk": count,
        "distinct_names_with_this_prefix": distinct,
        "entities_using_those_names": entity_count,
        "agree": count == distinct,
        "names_shared_by_more_than_one_entity": entity_count - distinct,
        "what": what,
        "note": ("the scan is compared with the count of DISTINCT names, which "
                 "is what the string blob holds; entities_using_those_names is "
                 "higher whenever two objects sharing an outer's namespace -- "
                 "possibly, but not necessarily, in different packages -- share "
                 "a name, and that difference is a fact about the map rather "
                 "than a disagreement about the bytes. On this container all 5 "
                 "such names are Default__*EditorOnlyData pairs at two depths "
                 "of the SAME package, /Script/Engine: the CDO and a nested "
                 "object inside a different class's CDO subtree"),
    }


# --------------------------------------------------------------------------- #
# the analysis
# --------------------------------------------------------------------------- #

def analyze(utoc_path: str, *, ucas_path: str | None = None,
            install_root: str | None = None,
            literal_samples: int = DEFAULT_LITERAL_SAMPLES,
            staged_plugins: str | None = None,
            module_filter: str = "/Script/MISERY",
            with_timestamp: bool = True) -> dict:
    warnings: list[str] = []
    literals: list[dict] = []

    utoc_path = os.path.abspath(utoc_path)
    if ucas_path is None:
        base, _ = os.path.splitext(utoc_path)
        ucas_path = base + ".ucas"
    ucas_path = os.path.abspath(ucas_path)
    detected_root = install_root or _detect_install_root(utoc_path)
    utoc_target = locus_target(utoc_path, detected_root)
    ucas_target = locus_target(ucas_path, detected_root)

    if not os.path.isfile(ucas_path):
        raise ContainerParseError("the payload %s does not exist next to the TOC"
                                  % ucas_target)

    self_test = blake3_self_test()
    if not self_test["all_passed"]:
        raise ContainerParseError(
            "the BLAKE3 self-test failed %d of %d first-party vectors "
            "(Blake3Test.cpp:18-49). The chunk-identity proof would be "
            "meaningless, so nothing is parsed."
            % (len(self_test["failures"]), self_test["vectors"]))

    toc = parse_toc(utoc_path, utoc_target, warnings, literals, literal_samples)
    chunk_index, chunk_reason = find_script_objects_chunk(toc)
    if chunk_index is None:
        raise ContainerParseError("%s: %s" % (utoc_target, chunk_reason))
    chunk = toc["chunks"][chunk_index]

    data, read_detail = read_chunk(ucas_path, ucas_target, toc, chunk, warnings)
    hash_check = verify_chunk_hash(data, toc, chunk_index)
    if hash_check["matches"] is False:
        raise ContainerParseError(
            "the assembled chunk hashes to %s but the TOC stores %s for it. The "
            "container walk is wrong, or the file changed under the run. "
            "Refusing to interpret bytes that are not the ones the engine reads."
            % (hash_check["computed_blake3_160"], hash_check["stored_blake3_160"]))
    if hash_check["matches"] is None:
        warnings.append("no chunk meta was available to check the chunk hash "
                        "against; the D-02 identity proof did not run")

    # ---- the chunk's own contents ------------------------------------------
    names, wide_flags, name_meta = parse_name_batch(data, 0, ucas_target, warnings)
    name_hash_check = verify_name_hashes(data, names, wide_flags, name_meta)
    entries, object_meta = parse_script_objects(data, name_meta["end_offset"],
                                                names, ucas_target)
    resolved = build_full_paths(entries, warnings)
    paths = resolved["paths"]
    by_global = resolved["by_global"]
    index_check = verify_global_indexes(entries, paths)
    cdo_check = verify_cdo_links(entries, paths, by_global)
    classification = classify(entries, paths, by_global)
    modules = build_modules(entries, paths, classification)

    # ---- a class-P sample of the chunk's own header bytes ------------------
    # These are batch/array HEADER bytes -- structure, never name or payload
    # content -- and their file offsets are computed the way the engine computes
    # a chunk's position, so the locus is determinate.
    block_size = toc["header"]["compression_block_size"]
    first_block = toc["blocks"][read_detail["first_block"]]
    chunk_file_offset = first_block["offset"] + (chunk["offset"] % block_size)
    for offset, length, note in (
            (0, 16, "the name batch header"),
            (object_meta["count_offset"], 4, "the script object count"),
            (object_meta["array_offset"], SCRIPT_OBJECT_ENTRY_SIZE,
             "the first fixed-width record of the entry array")):
        if offset + length <= len(data):
            literals.append(literal_read(ucas_target, chunk_file_offset + offset,
                                         data[offset:offset + length], note=note))

    literal_failures = confirm_literal_reads(
        literals, {utoc_target: utoc_path, ucas_target: ucas_path})
    if literal_failures:
        warnings.append("%d literal read(s) did not reproduce on a second, "
                        "independently opened handle" % literal_failures)

    # ---- tiling: the chunk's own sections ----------------------------------
    chunk_sections = [
        ("name_batch_header", 0, name_meta["header_size"]),
        ("name_hashes", name_meta["hashes_offset"] or 0,
         name_meta.get("hashes_size", 0)),
        ("name_headers", name_meta["headers_offset"] or 0,
         name_meta.get("headers_size", 0)),
        ("name_strings", name_meta["strings_offset"] or 0,
         name_meta.get("strings_size", 0)),
        ("script_object_count", object_meta["count_offset"], 4),
        ("script_object_entries", object_meta["array_offset"],
         object_meta["array_size"]),
    ]
    chunk_tiling = tile_check(chunk_sections, chunk["length"],
                              "the ScriptObjects chunk")

    # ---- probes -------------------------------------------------------------
    roles = classification["roles"]
    script_roots = [entry for entry in entries
                    if roles.get(entry["global_index"]) == ROLE_PACKAGE
                    and (paths.get(entry["global_index"]) or "").startswith("/Script/")]
    cdo_entries = [entry for entry in entries
                   if entry["name"] and entry["name"].startswith(CDO_PREFIX)]
    probes = {
        "blake3_self_test": self_test,
        "toc_tiling": toc["tiling"],
        "ucas_tiling": ucas_tiling(toc, read_detail["ucas_file_size"], ucas_target),
        "chunk_tiling": chunk_tiling,
        "chunk_identity": hash_check,
        "name_hash_verification": name_hash_check,
        "global_index_verification": index_check,
        "cdo_link_verification": cdo_check,
        "ascii_script_scan": ascii_scan_probe(data, b"/Script/", names,
                                              len(script_roots),
                                              "root packages whose name starts "
                                              "with /Script/"),
        "ascii_default_scan": ascii_scan_probe(data, CDO_PREFIX.encode("ascii"),
                                               names, len(cdo_entries),
                                               "entries whose name starts with "
                                               "Default__"),
    }

    # ---- the requested module ----------------------------------------------
    game_module = describe_module(module_filter, entries, paths, classification,
                                  by_global)

    # ---- canonical digests of the full decoded tables ----------------------
    names_canonical = "\n".join(names) + ("\n" if names else "")
    objects_canonical = objects_tsv(entries, paths, classification)
    digests = {
        "name_table_sha256": hashlib.sha256(
            names_canonical.encode("utf-8")).hexdigest(),
        "name_table_order": ("container order, i.e. the order SaveNameBatch wrote "
                             "them (UnrealNames.cpp:4452-4462) -- NOT sorted"),
        "script_objects_sha256": hashlib.sha256(
            objects_canonical.encode("utf-8")).hexdigest(),
        "script_objects_order": ("container order. plan.md 10.3 v2.4: this is a "
                                 "class-P claim about THIS container, not a "
                                 "class-I claim about vanilla UE 5.4.4. "
                                 "PackageStoreOptimizer.cpp:1001-1005 sorts "
                                 "ascending by full name before writing in the "
                                 "vanilla cooker, but a case-SENSITIVE ascending "
                                 "check on this container's own rows finds 794 "
                                 "adjacent pairs out of order; a case-INSENSITIVE "
                                 "check finds exactly 2, both attributable to a "
                                 "single one-element rotation at the seam between "
                                 "two 17456-row ascending runs (row 0 and row "
                                 "17455 of script-objects.tsv). Why the seam is "
                                 "there is UNKNOWN and is not this tool's claim "
                                 "to make -- record the shape, not a cause"),
        "why": ("so a later run, or a reader who has the same installation, can "
                "prove it reproduced the same tables byte for byte without the "
                "tables themselves having to live in the repository"),
    }

    document = {
        "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
        "generated_at": now_iso_utc() if with_timestamp else None,
        "method": "RF-01",
        "policy": PAYLOAD_POLICY,
        "engine_source_files": list(ENGINE_SOURCE_RELPATHS),
        "target": {
            "utoc_path_relative_to_install": utoc_target,
            "ucas_path_relative_to_install": ucas_target,
            "utoc_size": toc["file_size"],
            "ucas_size": read_detail["ucas_file_size"],
            "utoc_sha256": stream_sha256(utoc_path),
            "ucas_sha256": stream_sha256(ucas_path),
            # Honest about the locus: a class-P read must name a determinate
            # place, and an install-relative path is determinate where a
            # basename is an ambiguity class. This says which one it got.
            "paths_are_install_relative":
                utoc_target != os.path.basename(utoc_path),
        },
        "literal_reads": literals,
        "toc": {
            "header": toc["header"],
            "version": toc["version"],
            "container_flags_decoded": toc["container_flags_decoded"],
            "container_flags_unknown_bits": toc["container_flags_unknown_bits"],
            "is_encrypted": toc["is_encrypted"],
            "is_indexed": toc["is_indexed"],
            "is_signed": toc["is_signed"],
            "is_compressed_flag": toc["is_compressed_flag"],
            "compression_methods": toc["compression_methods"],
            "body_layout": {"offsets": toc["body_layout"]["offsets"],
                            "sections": toc["body_layout"]["sections"],
                            "total": toc["body_layout"]["total"]},
            "chunk_count": len(toc["chunks"]),
            "chunks": toc["chunks"],
            "block_count": len(toc["blocks"]),
            "block_compression_method_histogram": dict(sorted(Counter(
                block["compression_method_index"]
                for block in toc["blocks"]).items())),
            "chunk_metas": toc["chunk_metas"],
        },
        "chunk": {
            "selected_index": chunk_index,
            "selection_reason": chunk_reason,
            "chunk_id_hex": chunk["chunk_id_hex"],
            "chunk_type": chunk["chunk_type"],
            "chunk_type_byte": chunk["chunk_type_byte"],
            "offset": chunk["offset"],
            "length": chunk["length"],
            "file_offset_of_first_byte": chunk_file_offset,
            "read": read_detail,
        },
        "name_table": dict(name_meta, **{
            "verification": name_hash_check,
            "digest_sha256": digests["name_table_sha256"],
        }),
        "script_objects": dict(object_meta, **{
            "unique_global_indexes": len(by_global),
            "duplicate_global_indexes": resolved["duplicate_global_indexes"],
            "unresolved_outer": resolved["unresolved_outer"],
            "outer_cycles": resolved["cycles"],
            "role_histogram": classification["role_histogram"],
            "role_definitions": ROLE_DEFINITIONS,
            "verification": index_check,
            "cdo_verification": cdo_check,
            "digest_sha256": digests["script_objects_sha256"],
        }),
        "decoded_evidence": decoded_annotation(
            oracle=["global-ucas", "container-metadata", "external-doc"],
            confidence=CONFIDENCE_DECODED,
            evidence_level="OBSERVED",
            note=(
                "Class I: everything outside literal_reads[] names what the bytes "
                "ARE and rests on an external layout, so it is capped below the "
                "literal layer whatever the offsets are. Two independent methods "
                "back the headline counts: (1) the structured decode, with every "
                "field order, mask and constant taken from the first-party UE "
                "5.4.4 source at this build's own changelist and cited to file and "
                "line in the module docstring; (2) a raw byte scan of the same "
                "chunk that uses no layout at all -- the method A-08 used -- which "
                "found %d occurrences of '/Script/' against %d decoded package "
                "names and %d occurrences of 'Default__' against %d decoded "
                "class-default-object names. Three further checks are internal to the "
                "container and each reads bytes the decode did not: the chunk's "
                "BLAKE3-160 equals the FIoChunkHash the TOC stores for it, %d of "
                "%d name hashes recompute exactly, and %d of %d reconstructed full "
                "paths hash back to the entry's own GlobalIndex. Refutation "
                "attempt: a wrong record stride or a wrong mask would show as a "
                "non-zero gap or overlap in one of the three tiling checks, as a "
                "disagreement between the byte scan and the decode, or as a single "
                "hash mismatch; all three tilings are exact and no mismatch was "
                "found. build_key is carried by the enclosing artifact and by the "
                "reflection records this run writes. Not graded higher than %.2f "
                "because the plan.md 10.2 0.80-0.94 band names a runtime "
                "observation as one of its two confirmations and this run has "
                "none: the closing method is RF-12, the runtime reflection dump, "
                "which plan.md M3 already requires to agree with this table."
                % (probes["ascii_script_scan"]["literal_occurrences_in_chunk"],
                   probes["ascii_script_scan"]["distinct_names_with_this_prefix"],
                   probes["ascii_default_scan"]["literal_occurrences_in_chunk"],
                   probes["ascii_default_scan"]["distinct_names_with_this_prefix"],
                   name_hash_check["checked"] - name_hash_check["mismatches"],
                   name_hash_check["checked"],
                   index_check["checked"] - index_check["mismatches"],
                   index_check["checked"], CONFIDENCE_DECODED)),
            sources=[
                {"method": ("RF-01 structured decode of the global.ucas "
                            "ScriptObjects chunk by %s" % GENERATOR_NAME),
                 "artifact": None,
                 "locator": ("FIoStoreTocResource::Read / LoadNameBatch / "
                             "FScriptObjectEntry"),
                 "note": ("oracle global-ucas plus external-doc for the layout: "
                          "every field order, mask and constant is cited to file "
                          "and line in the first-party UE 5.4.4 tree at "
                          "changelist 35576357, the changelist this build was "
                          "made from")},
                {"method": ("raw byte scan of the same chunk for the literal "
                            "strings /Script/ and Default__, using no layout "
                            "knowledge -- the method of A-08, re-run here as the "
                            "ascii_script_scan and ascii_default_scan probes"),
                 "artifact": None,
                 "locator": "probes.ascii_script_scan, probes.ascii_default_scan",
                 "note": ("oracle global-ucas. Independent of method 1: it reads "
                          "the string blob with no header table, so a wrong "
                          "stride in the decode cannot make the two agree")},
            ]),
        "modules": modules,
        "module_count": len(modules),
        "script_module_count": sum(1 for row in modules if row["package"]
                                   and row["package"].startswith("/Script/")),
        "staged_plugin_comparison": compare_with_staged_plugins(
            modules, staged_plugins, warnings),
        "game_module": game_module,
        "digests": digests,
        "probes": probes,
        "cannot_be_told_from_this_container": CANNOT_BE_TOLD,
        "warnings": warnings,
        "_names": names,
        "_entries": entries,
        "_paths": paths,
        "_classification": classification,
        "_objects_canonical": objects_canonical,
        "_names_canonical": names_canonical,
    }
    document["summary"] = summarize(document)
    return document


CANNOT_BE_TOLD = {
    "what_kind_of_thing_a_name_is": (
        "FScriptObjectEntry carries no type tag (AsyncLoading2.h:324-337). A "
        "UClass, a UScriptStruct, a UEnum and a UDelegateFunction sitting in a "
        "script package are stored identically. The single exception is the "
        "class-default object link at PackageStoreOptimizer.cpp:932-942, which "
        "is why role class_with_cdo exists and no role called 'enum' does."),
    "properties": (
        "none can ever appear. FProperty derives from FField (UnrealType.h:162, "
        "Field.h:447), which is not a UObject, and the map is built by "
        "GetObjectsWithOuter (PackageStoreOptimizer.cpp:952-957), which walks "
        "UObjects. No property, no property offset, no property order and no "
        "property type is in this container, in this build or any other."),
    "inheritance": (
        "there is no super field. OuterIndex is containment, not derivation, so "
        "nothing here says what a class derives from."),
    "sizes_offsets_alignment": "absent from the format entirely.",
    "flags": (
        "no EObjectFlags, EClassFlags or EFunctionFlags value is stored. Only "
        "RF_Public is implied, and only as a filter: "
        "PackageStoreOptimizer.cpp:899-903 skips everything else, so a private "
        "native class is missing from this container by construction."),
    "whether_anything_is_used": (
        "presence means the cook saw the module, not that the shipped game loads "
        "it or that the module is enabled."),
    "anything_about_game_assets": (
        "plan.md C-11 and 10.5: a name here is not evidence that a /Game asset "
        "exists and says nothing whatever about a Blueprint's structure."),
}


def describe_module(package_path: str, entries: list[dict],
                    paths: dict[int, str | None], classification: dict,
                    by_global: dict[int, dict]) -> dict:
    """Everything the container holds under one package path, in full."""
    roles = classification["roles"]
    cdo_of = classification["cdo_of"]
    wanted = (package_path or "").lower()
    rows: list[dict] = []
    for entry in entries:
        path = paths.get(entry["global_index"])
        if path is None:
            continue
        lowered = path.lower()
        if lowered != wanted and not lowered.startswith(wanted + "/"):
            continue
        outer_path = paths.get(entry["outer_index"])
        cdo_path = paths.get(entry["cdo_class_index"])
        role = roles.get(entry["global_index"], ROLE_UNRESOLVED)
        rows.append({
            "path": path,
            "name": entry["name"],
            "name_number": entry["name_number"],
            "role": role,
            "outer_path": outer_path,
            "outer_index_hex": "0x%016x" % entry["outer_index"],
            "outer_index_type": package_object_index_type(entry["outer_index"]),
            "global_index_hex": "0x%016x" % entry["global_index"],
            "global_index_type": package_object_index_type(entry["global_index"]),
            "cdo_class_index_hex": "0x%016x" % entry["cdo_class_index"],
            "cdo_class_index_type":
                package_object_index_type(entry["cdo_class_index"]),
            "cdo_class_path": cdo_path,
            "has_class_default_object":
                ("0x%016x" % cdo_of[entry["global_index"]])
                if entry["global_index"] in cdo_of else None,
            "container_entry_index": entry["index"],
        })
    rows.sort(key=lambda row: row["path"])
    return {
        "package": package_path,
        "present": bool(rows),
        "entry_count": len(rows),
        "role_histogram": dict(Counter(row["role"] for row in rows)),
        "entries": rows,
    }


def objects_tsv(entries: list[dict], paths: dict[int, str | None],
                classification: dict) -> str:
    """The full script-object table as TSV, in container order.

    Columns are the four fields the format actually has plus the reconstructed
    path and the role, so the file is the map rather than a word list. Emitted
    with '\\n' endings and no trailing spaces so its SHA-256 is stable across
    platforms.
    """
    roles = classification["roles"]
    lines = ["global_index\touter_index\tcdo_class_index\tname_number\trole\tpath"]
    for entry in entries:
        path = paths.get(entry["global_index"])
        lines.append("%016x\t%016x\t%016x\t%d\t%s\t%s" % (
            entry["global_index"], entry["outer_index"],
            entry["cdo_class_index"], entry["name_number"],
            roles.get(entry["global_index"], ROLE_UNRESOLVED),
            path if path is not None else ""))
    return "\n".join(lines) + "\n"


def summarize(document: dict) -> dict:
    probes = document["probes"]
    checks = {
        "blake3_self_test": probes["blake3_self_test"]["all_passed"],
        "toc_tiles_exactly": probes["toc_tiling"]["tiles_exactly"],
        "ucas_matches_aes_aligned_model":
            probes["ucas_tiling"]["matches_aes_aligned_model"],
        "chunk_tiles_exactly": probes["chunk_tiling"]["tiles_exactly"],
        "chunk_hash_matches_toc": probes["chunk_identity"]["matches"] is True,
        "every_name_hash_matches": probes["name_hash_verification"]["all_match"]
                                   is True,
        "every_global_index_matches":
            probes["global_index_verification"]["all_match"] is True,
        "every_cdo_link_matches": probes["cdo_link_verification"]["all_match"]
                                  is True,
        "ascii_script_scan_agrees": probes["ascii_script_scan"]["agree"],
        "ascii_default_scan_agrees": probes["ascii_default_scan"]["agree"],
        "all_literal_reads_reproduced": all(record["reproduced"]
                                            for record in
                                            document["literal_reads"]),
    }
    failed = sorted(name for name, ok in checks.items() if not ok)
    return {
        "verdict": "VERIFIED" if not failed else "CHECKS FAILED",
        "checks": checks,
        "failed_checks": failed,
        "names": document["name_table"]["count"],
        "script_objects": document["script_objects"]["count"],
        "script_modules": document["script_module_count"],
        "game_module_present": document["game_module"]["present"],
        "game_module_entries": document["game_module"]["entry_count"],
    }


# --------------------------------------------------------------------------- #
# the reflection map -- research/reflection/<build>/*.jsonl, plan.md 6.3 / 9.2
#
# Every line is a FULL knowledge-base record: the envelope of
# kb-record.schema.json#/$defs/envelope plus one entity branch of
# reflection-record.schema.json. Two rules shape what is emitted:
#
#   * a field this container cannot supply is emitted as an explicit null, and
#     the reason is in `notes`. Omitting it would read as "not looked at";
#     guessing it would be worse.
#   * a record that mixes a certain fact with an uncertain one is SPLIT
#     (plan.md 10.3): containment goes to relations.jsonl at the grade the
#     verified OuterIndex field earns, and the KIND of the object goes to
#     classes.jsonl or functions.jsonl at the much lower grade an untagged
#     format earns. Nothing is averaged.
# --------------------------------------------------------------------------- #

# plan.md 10.2 bands, with the reason each grade is where it is.
CONF_CONTAINMENT = 0.90   # a read field, verified twice, no runtime observation
CONF_CLASS_KIND = 0.85    # INFERRED from the CDO link
CONF_MEMBER_KIND = 0.60   # HYPOTHESIS: the format carries no type tag

NULL_REASONS = {
    "super": ("FScriptObjectEntry has no super field (AsyncLoading2.h:324-337); "
              "OuterIndex is containment, not derivation"),
    "size": ("the format stores no size, alignment or offset of anything "
             "(AsyncLoading2.h:324-337)"),
    "flags": ("no EObjectFlags / EClassFlags / EFunctionFlags value is stored; "
              "only RF_Public is implied, and only as a filter "
              "(PackageStoreOptimizer.cpp:899-903)"),
    "counts": ("property and function counts cannot be derived: properties are "
               "not UObjects (UnrealType.h:162, Field.h:447) so they are absent "
               "from this container entirely, and a member object's kind is not "
               "recorded"),
    "interfaces": "the format stores no interface list",
    "native": ("a script package holds native and generated objects alike and "
               "the format does not distinguish them; the runtime dump RF-12 "
               "does"),
    "parameters": ("parameters are FProperty objects, which are not UObjects "
                   "(UnrealType.h:162, Field.h:447) and can never appear here"),
}


def _envelope(*, claim: str, claim_type: str, evidence_level: str,
              confidence: float, oracle: list[str], sources: list,
              build_key: str, recorded_at: str, notes: str,
              refutation: str) -> dict:
    return {
        "claim": claim,
        "claim_type": claim_type,
        "claim_class": "I",
        "evidence_level": evidence_level,
        "confidence": confidence,
        "oracle": oracle,
        "sources": sources,
        "build_key": build_key,
        "recorded_at": recorded_at,
        "method": "RF-01",
        "refutation_attempt": refutation,
        "notes": notes,
        "semantic_alias": None,
    }


_SOURCE_DECODE = {
    "method": ("RF-01: structured decode of the ScriptObjects chunk of "
               "global.ucas by tools/reflection/global_ucas.py, read-only"),
    "artifact": "research/evidence/RF-01/global-ucas.json",
    "locator": "$.script_objects",
    "note": ("oracle global-ucas. Layout from the first-party UE 5.4.4 source at "
             "changelist 35576357, cited per field in the tool's module "
             "docstring. build_key is stated in this record"),
}
_SOURCE_HASH = {
    "method": ("verification: recomputed FromScriptPath (CityHash64 over the "
               "UTF-16 lowercased path, AsyncLoading2.cpp:221-240) and compared "
               "it with the GlobalIndex stored in the entry"),
    "artifact": "research/evidence/RF-01/global-ucas.json",
    "locator": "$.probes.global_index_verification",
    "note": ("oracle global-ucas. Independent of the decode: it reads the 8-byte "
             "GlobalIndex field and runs a different algorithm over it, so a "
             "wrong outer chain cannot survive it. 34 912 checks, 62 bits each"),
}
_SOURCE_CDO = {
    "method": ("verification: recomputed the CDOClassIndex of every Default__ "
               "entry from its outer path (PackageStoreOptimizer.cpp:932-942) "
               "and compared it with the stored value"),
    "artifact": "research/evidence/RF-01/global-ucas.json",
    "locator": "$.probes.cdo_link_verification",
    "note": ("oracle global-ucas. The link is the writer's own statement of "
             "which class a class-default object belongs to"),
}
_SOURCE_SCAN = {
    "method": ("raw byte scan of the same chunk for the literal string "
               "Default__, using no layout knowledge -- the method of A-08"),
    "artifact": "research/evidence/RF-01/global-ucas.json",
    "locator": "$.probes.ascii_default_scan",
    "note": ("oracle global-ucas. Independent of the decode: no header table is "
             "consulted, so a wrong stride cannot make the counts agree"),
}

_REFUTATION_MAP = (
    "Refutation attempt: if the outer chain were reconstructed wrongly we would "
    "see FromScriptPath disagree with the stored GlobalIndex for the affected "
    "entries, and if the entry stride were wrong we would see a gap or an "
    "overlap in the chunk tiling. Neither appeared: the chunk tiles exactly and "
    "all 34 912 global indexes recompute.")
_REFUTATION_CLASS = (
    "Refutation attempt: if this object were not a UClass, no class-default "
    "object would point at it -- so we looked for a sibling entry whose stored "
    "CDOClassIndex hashes to this object's path, and found one. A counterexample "
    "would be a UScriptStruct or UEnum with such a sibling, which cannot happen "
    "because a CDO is created for UClass only.")
_REFUTATION_MEMBER = (
    "Refutation attempt: we looked for anything in the format that would "
    "distinguish a UFunction from a UEnum or a UScriptStruct declared in the "
    "same scope, and there is nothing -- no type tag, no flags, no size. That is "
    "why this record is HYPOTHESIS and not higher, and it is what RF-12 closes.")


def emit_reflection_records(document: dict, *, build_key: str, recorded_at: str,
                            scope: str) -> dict[str, list[dict]]:
    """Build the JSONL line lists for research/reflection/<build>/.

    *scope* is either a package path (only that subtree is emitted) or the
    literal ``"all"``. The default is the game module: see the scope note in the
    generated README for why the 34 912-row full table is committed as a compact
    evidence artifact instead of as 34 912 envelope-bearing records.
    """
    entries = document["_entries"]
    paths = document["_paths"]
    classification = document["_classification"]
    roles = classification["roles"]
    cdo_of = classification["cdo_of"]
    by_global = {entry["global_index"]: entry for entry in entries}

    wanted = None if scope == "all" else (scope or "").lower()

    def in_scope(path: str | None) -> bool:
        if path is None:
            return False
        if wanted is None:
            return True
        lowered = path.lower()
        return lowered == wanted or lowered.startswith(wanted + "/")

    classes: list[dict] = []
    functions: list[dict] = []
    relations: list[dict] = []

    for entry in entries:
        gid = entry["global_index"]
        path = paths.get(gid)
        if not in_scope(path):
            continue
        role = roles.get(gid)
        module = None
        root = classification["root_of"].get(gid)
        if root is not None:
            module = module_short_name(paths.get(root))
        package = paths.get(root) if root is not None else None

        if role == ROLE_CLASS_WITH_CDO:
            cdo_entry = by_global.get(cdo_of.get(gid, -1))
            classes.append(dict(_envelope(
                claim=("the build contains a native/script UClass named %s in "
                       "package %s" % (entry["name"], package)),
                claim_type="native-class-exists",
                evidence_level="INFERRED",
                confidence=CONF_CLASS_KIND,
                oracle=["global-ucas"],
                sources=[_SOURCE_DECODE, _SOURCE_CDO],
                build_key=build_key, recorded_at=recorded_at,
                refutation=_REFUTATION_CLASS,
                notes=("kind=class is INFERRED, not read: this container carries "
                       "no type tag. The inference is that a class-default "
                       "object exists for this object and names it through its "
                       "CDOClassIndex (PackageStoreOptimizer.cpp:932-942), and a "
                       "CDO exists only for a UClass. Nothing here says what it "
                       "derives from, how big it is, or what it contains. %s %s"
                       % (NULL_REASONS["super"], NULL_REASONS["size"]))),
                kind="class",
                raw_name=entry["name"],
                object_path=path,
                package=package,
                module=module,
                flags_raw=None,
                source=["RF-01"],
                super=None,
                super_object_path=None,
                size=None,
                alignment=None,
                class_flags_raw=None,
                class_cast_flags_raw=None,
                cdo_name=(cdo_entry["name"] if cdo_entry else None),
                is_native=None,
                is_blueprint_generated=None,
                is_abstract=None,
                within_class=None,
                config_name=None,
                interfaces=None,
                property_count=None,
                function_count=None))
            if cdo_entry is not None:
                relations.append(dict(_envelope(
                    claim=("the class-default object of %s is %s"
                           % (path, paths.get(cdo_entry["global_index"]))),
                    claim_type="native-class-exists",
                    evidence_level="OBSERVED",
                    confidence=CONF_CONTAINMENT,
                    oracle=["global-ucas"],
                    sources=[_SOURCE_DECODE, _SOURCE_CDO],
                    build_key=build_key, recorded_at=recorded_at,
                    refutation=_REFUTATION_CLASS,
                    notes=("relation_type=default_subobject is the closest term "
                           "the schema enum offers for the class-default-object "
                           "link, and it is NOT a component: the CDO's OUTER is "
                           "the package, not the class, and the link recorded "
                           "here is the CDOClassIndex field "
                           "(PackageStoreOptimizer.cpp:932-942), verified by "
                           "recomputing its hash from the outer path.")),
                    kind="relation",
                    relation_type="default_subobject",
                    **{"from": path},
                    from_kind="class",
                    to=paths.get(cdo_entry["global_index"]),
                    to_kind=None,
                    ordinal=None,
                    object_path=path,
                    package=package,
                    module=module,
                    raw_name=None,
                    flags_raw=None,
                    source=["RF-01"]))

        elif role == ROLE_MEMBER_OF_CLASS:
            owner = paths.get(entry["outer_index"])
            functions.append(dict(_envelope(
                claim=("the build contains a public UObject named %s owned by "
                       "the class %s; its kind is most likely UFunction"
                       % (entry["name"], owner)),
                claim_type="native-class-exists",
                evidence_level="HYPOTHESIS",
                confidence=CONF_MEMBER_KIND,
                oracle=["global-ucas"],
                sources=[_SOURCE_DECODE],
                build_key=build_key, recorded_at=recorded_at,
                refutation=_REFUTATION_MEMBER,
                notes=("kind=function is a HYPOTHESIS about the KIND, and the "
                       "one uncertain thing in this record. What is OBSERVED is "
                       "that a public UObject with this name is owned by that "
                       "class, and that fact is recorded separately in "
                       "relations.jsonl at its own grade -- the two are not "
                       "averaged (plan.md 10.3). A UDelegateFunction, and a "
                       "UEnum or UScriptStruct declared in the class scope, are "
                       "stored identically here; the closing method is RF-12. "
                       "%s %s" % (NULL_REASONS["parameters"],
                                  NULL_REASONS["flags"]))),
                kind="function",
                raw_name=entry["name"],
                object_path=path,
                package=package,
                module=module,
                flags_raw=None,
                source=["RF-01"],
                owner=owner,
                function_flags_raw=None,
                num_parms=None,
                parms_size=None,
                return_value_offset=None,
                is_native=None,
                is_static=None,
                is_event=None,
                is_net=None,
                net_flags_raw=None,
                native_func_address=None,
                bytecode_size=None,
                parameters=None))

        if entry["outer_index"] != PACKAGE_OBJECT_INDEX_INVALID:
            outer_path = paths.get(entry["outer_index"])
            if outer_path is not None:
                outer_role = roles.get(entry["outer_index"])
                relations.append(dict(_envelope(
                    claim="%s is the Outer of %s" % (outer_path, path),
                    claim_type="native-class-exists",
                    evidence_level="OBSERVED",
                    confidence=CONF_CONTAINMENT,
                    oracle=["global-ucas"],
                    sources=[_SOURCE_DECODE, _SOURCE_HASH],
                    build_key=build_key, recorded_at=recorded_at,
                    refutation=_REFUTATION_MAP,
                    notes=("relation_type=owns records the OuterIndex field of "
                           "FScriptObjectEntry, verified by recomputing "
                           "FromScriptPath over the reconstructed path and "
                           "matching the stored GlobalIndex. It is containment, "
                           "NOT inheritance: %s" % NULL_REASONS["super"])),
                    kind="relation",
                    relation_type="owns",
                    **{"from": outer_path},
                    from_kind=("class" if outer_role == ROLE_CLASS_WITH_CDO
                               else None),
                    to=path,
                    to_kind=("class" if role == ROLE_CLASS_WITH_CDO else None),
                    ordinal=None,
                    object_path=path,
                    package=package,
                    module=module,
                    raw_name=None,
                    flags_raw=None,
                    source=["RF-01"]))

    return {
        "classes.jsonl": classes,
        "functions.jsonl": functions,
        "relations.jsonl": relations,
        "enums.jsonl": [],
        "properties.jsonl": [],
    }


EMPTY_FILE_REASONS = {
    "enums.jsonl": (
        "A UEnum IS a UObject and therefore IS somewhere in this container -- but "
        "nothing in the format says which entry it is. FScriptObjectEntry has no "
        "type tag (AsyncLoading2.h:324-337), so a UEnum, a UScriptStruct and a "
        "UClass without a public CDO are stored identically. Writing a guessed "
        "list of enums here would be inventing data, so the file stays empty and "
        "the candidates are visible as role=package_member_unclassified in "
        "research/evidence/RF-01/script-objects.tsv. Closing method: RF-12, or a "
        ".usmap if one is ever produced."),
    "properties.jsonl": (
        "No property can EVER appear in this container, in this build or any "
        "other. FProperty derives from FField (UnrealType.h:162, Field.h:447), "
        "which is not a UObject, and the script-object map is built by "
        "GetObjectsWithOuter (PackageStoreOptimizer.cpp:952-957), which walks "
        "UObjects. This file is empty because of the format, not because of this "
        "run. Closing method: RF-12 (runtime reflection), the only oracle "
        "plan.md 10.5 admits for a property claim at all."),
}


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def _strip_private(document: dict) -> dict:
    return {key: value for key, value in document.items()
            if not key.startswith("_")}


def dump_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def dump_jsonl(records: list[dict]) -> str:
    return "".join(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
                   for record in records)


def names_text(document: dict) -> str:
    """The decoded name table, one name per line, in container order."""
    header = [
        "# %s %s -- global FName batch of %s"
        % (GENERATOR_NAME, GENERATOR_VERSION,
           document["target"]["ucas_path_relative_to_install"]),
        "# %d names, %d string bytes, HashVersion %s, %d stored as UTF-16."
        % (document["name_table"]["count"], document["name_table"]["string_bytes"],
           document["name_table"]["hash_version"],
           document["name_table"]["wide_names"]),
        "# Order is the container's own (UnrealNames.cpp:4452-4462), NOT sorted.",
        "# Every line was confirmed against the CityHash64 the batch stores for "
        "it; %d of %d matched." % (document["name_table"]["verification"]["checked"]
                                   - document["name_table"]["verification"]["mismatches"],
                                   document["name_table"]["verification"]["checked"]),
        "# sha256 of the name lines below, without this header: %s"
        % document["name_table"]["digest_sha256"],
    ]
    return "\n".join(header) + "\n" + document["_names_canonical"]


def modules_text(document: dict) -> str:
    """One line per root package, with its per-role counts."""
    header = [
        "# %s %s -- root packages of %s"
        % (GENERATOR_NAME, GENERATOR_VERSION,
           document["target"]["ucas_path_relative_to_install"]),
        "# %d root packages, %d of them under /Script/."
        % (document["module_count"], document["script_module_count"]),
        "# A root package is an entry whose OuterIndex is Null "
        "(PackageStoreOptimizer.cpp:987).",
        "# Presence means the cook saw the module. It does NOT mean the shipped "
        "game loads it.",
        "package\tobjects\tclasses_with_cdo\tclass_default_objects\t"
        "members_of_classes\tpackage_members_unclassified",
    ]
    lines = []
    for row in document["modules"]:
        lines.append("%s\t%d\t%d\t%d\t%d\t%d" % (
            row["package"] if row["package"] is not None else "<unresolved>",
            row["objects"], row["classes_with_cdo"], row["class_default_objects"],
            row["members_of_classes"], row["package_members_unclassified"]))
    return "\n".join(header) + "\n" + "\n".join(lines) + "\n"


def objects_text(document: dict) -> str:
    header = [
        "# %s %s -- script object map of %s"
        % (GENERATOR_NAME, GENERATOR_VERSION,
           document["target"]["ucas_path_relative_to_install"]),
        "# %d entries, container order. NOT globally ascending by full name: "
        "case-insensitive check finds exactly 2 inversions (rows 0 and 17455), "
        "both at the seam of two 17456-row ascending runs; see "
        "script_objects_order in global-ucas.json."
        % document["script_objects"]["count"],
        "# global_index / outer_index / cdo_class_index are the three "
        "FPackageObjectIndex fields of FScriptObjectEntry, hex, as stored.",
        "# ffffffffffffffff is FPackageObjectIndex::Invalid (AsyncLoading2.h:61).",
        "# role is this tool's vocabulary, NOT a UE type: see role_definitions in "
        "global-ucas.json. The container carries no type tag.",
        "# path is reconstructed by walking OuterIndex and was confirmed for "
        "every row by recomputing FromScriptPath and matching global_index.",
        "# sha256 of the body below, without this header: %s"
        % document["script_objects"]["digest_sha256"],
    ]
    return "\n".join(header) + "\n" + document["_objects_canonical"]


def write_text(body: str, out_path: str, install_root: str | None,
               what: str) -> str:
    """Write *body*, refusing any path inside an installation. Guard runs first."""
    target = pathguard.check_output_path(out_path, install_root, what=what)
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(body)
    return target


def format_summary(document: dict) -> str:
    lines: list[str] = []
    summary = document["summary"]
    target = document["target"]
    lines.append("target: %s (%d bytes) + %s (%d bytes)"
                 % (target["utoc_path_relative_to_install"], target["utoc_size"],
                    target["ucas_path_relative_to_install"], target["ucas_size"]))
    toc = document["toc"]
    lines.append("toc: v%d, %d chunk(s), %d block(s) of %d, flags %s %s, "
                 "directory index %d bytes"
                 % (toc["version"], toc["chunk_count"], toc["block_count"],
                    toc["header"]["compression_block_size"],
                    toc["header"]["container_flags"],
                    toc["container_flags_decoded"] or ["<none set>"],
                    toc["header"]["directory_index_size"]))
    chunk = document["chunk"]
    lines.append("chunk: index %d, id %s, type %s, offset %d, length %d"
                 % (chunk["selected_index"], chunk["chunk_id_hex"],
                    chunk["chunk_type"], chunk["offset"], chunk["length"]))
    lines.append("  selection: %s" % chunk["selection_reason"])
    lines.append("")
    lines.append("D-02 identity proof (BLAKE3-160 of the assembled chunk vs the "
                 "TOC's stored FIoChunkHash):")
    identity = document["probes"]["chunk_identity"]
    lines.append("  computed %s" % identity["computed_blake3_160"])
    lines.append("  stored   %s  -> %s"
                 % (identity["stored_blake3_160"],
                    "MATCH" if identity["matches"] else "MISMATCH"))
    lines.append("")
    names = document["name_table"]
    lines.append("name table: %d names, %d string bytes, %d UTF-16, HashVersion "
                 "%s (FNameHash::AlgorithmId: %s)"
                 % (names["count"], names["string_bytes"], names["wide_names"],
                    names["hash_version"],
                    names["hash_version_is_fname_algorithm_id"]))
    verification = names["verification"]
    lines.append("  stored CityHash64 recomputed: %d checked, %d mismatched"
                 % (verification["checked"], verification["mismatches"]))
    objects = document["script_objects"]
    lines.append("script objects: %d entries of %d bytes, %d distinct global "
                 "indexes" % (objects["count"], objects["entry_size"],
                              objects["unique_global_indexes"]))
    index_check = objects["verification"]
    lines.append("  FromScriptPath recomputed: %d checked, %d mismatched, %d "
                 "unresolved" % (index_check["checked"], index_check["mismatches"],
                                 index_check["skipped_unresolved"]))
    cdo_check = objects["cdo_verification"]
    lines.append("  CDOClassIndex, branch :934 (computed from the Default__ "
                 "prefix): %d checked, %d matched, %d mismatched"
                 % (cdo_check["computed_branch_checked"],
                    cdo_check["computed_branch_matched"],
                    cdo_check["computed_branch_mismatched"]))
    lines.append("  CDOClassIndex, branch :929 (inherited from the outer): %d "
                 "checked, %d matched, %d mismatched"
                 % (cdo_check["inherited_branch_checked"],
                    cdo_check["inherited_branch_matched"],
                    cdo_check["inherited_branch_mismatched"]))
    lines.append("  roles: %s" % ", ".join("%s=%d" % (role, count) for role, count
                                           in sorted(objects["role_histogram"].items())))
    lines.append("")
    lines.append("tiling self-checks (no gaps, no overlaps, nothing left over):")
    for key in ("toc_tiling", "chunk_tiling"):
        tiling = document["probes"][key]
        lines.append("  %-14s %d section(s) cover %d of %d bytes, gaps %d, "
                     "overlaps %d, trailing %d -> %s"
                     % (key, len(tiling["sections"]), tiling["covered_extent"],
                        tiling["total"], tiling["gap_count"],
                        tiling["overlap_count"], tiling["trailing_bytes"],
                        "EXACT" if tiling["tiles_exactly"] else "NOT EXACT"))
    ucas = document["probes"]["ucas_tiling"]
    lines.append("  ucas_tiling    blocks end at %d packed / %d AES-aligned; file "
                 "is %d -> packed=%s aligned=%s"
                 % (ucas["packed_end"], ucas["aes_aligned_end"], ucas["file_size"],
                    ucas["matches_packed_model"], ucas["matches_aes_aligned_model"]))
    lines.append("")
    lines.append("refutation probes (same facts, no layout):")
    for key in ("ascii_script_scan", "ascii_default_scan"):
        probe = document["probes"][key]
        lines.append("  %-18s literal %r x%d vs %d distinct name(s) -> %s "
                     "(%d entities use them; %d name(s) shared)"
                     % (key, probe["needle"],
                        probe["literal_occurrences_in_chunk"],
                        probe["distinct_names_with_this_prefix"],
                        "AGREE" if probe["agree"] else "DISAGREE",
                        probe["entities_using_those_names"],
                        probe["names_shared_by_more_than_one_entity"]))
    self_test = document["probes"]["blake3_self_test"]
    lines.append("  blake3_self_test   %d/%d first-party vectors"
                 % (self_test["passed"], self_test["vectors"]))
    lines.append("")
    lines.append("modules: %d root packages, %d under /Script/"
                 % (document["module_count"], document["script_module_count"]))
    comparison = document["staged_plugin_comparison"]
    if comparison["available"]:
        counts = comparison["counts"]
        lines.append("  vs %d staged .uplugin names: %d names in both, %d module "
                     "names that are not a plugin name, %d plugin names with no "
                     "module of that name"
                     % (counts["staged_uplugin_names"], counts["name_in_both"],
                        counts["module_name_not_a_staged_plugin_name"],
                        counts["staged_plugin_name_with_no_module_of_that_name"]))
        for row in comparison["staged_plugins_outside_engine_plugins"]:
            lines.append("  staged outside Engine/Plugins: %-24s module of that "
                         "name: %s  (%s)"
                         % (row["plugin"],
                            "yes" if row["module_of_the_same_name_exists"] else "no",
                            row["staged_path"]))
    game = document["game_module"]
    lines.append("")
    lines.append("%s: %s, %d entr%s"
                 % (game["package"], "PRESENT" if game["present"] else "ABSENT",
                    game["entry_count"], "y" if game["entry_count"] == 1 else "ies"))
    for row in game["entries"]:
        lines.append("  %-28s %s" % (row["role"], row["path"]))
    lines.append("")
    lines.append("VERDICT: %s" % summary["verdict"])
    if summary["failed_checks"]:
        lines.append("  failed: %s" % ", ".join(summary["failed_checks"]))
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
        description="Read the plaintext global IoStore container read-only: the "
                    "global FName batch and the script-object map (RF-01).")
    parser.add_argument("path", help="the global .utoc file to read")
    parser.add_argument("--ucas", help="the payload, if it is not <path>.ucas")
    parser.add_argument("--json", action="store_true",
                        help="print the whole document instead of the summary")
    parser.add_argument("--out", help="write the JSON document here")
    parser.add_argument("--names-out",
                        help="write the decoded name table here as text")
    parser.add_argument("--objects-out",
                        help="write the full script-object map here as TSV")
    parser.add_argument("--modules-out",
                        help="write the per-package counts here as TSV")
    parser.add_argument("--jsonl-dir",
                        help="write classes/functions/relations/enums/properties"
                             ".jsonl into this directory (needs --build-key)")
    parser.add_argument("--jsonl-scope", default="/Script/MISERY",
                        help="package subtree the JSONL records cover, or 'all' "
                             "(default /Script/MISERY)")
    parser.add_argument("--build-key",
                        help="build_key for the JSONL envelopes, e.g. sha256:...")
    parser.add_argument("--recorded-at",
                        help="recorded_at for the JSONL envelopes; defaults to "
                             "now. Pin it to make two runs byte-identical")
    parser.add_argument("--module", default="/Script/MISERY",
                        help="the package to enumerate in full in the output "
                             "(default /Script/MISERY)")
    parser.add_argument("--staged-plugins",
                        help="path to the V-07 staged .uplugin list, for the "
                             "module-vs-plugin comparison")
    parser.add_argument("--literal-samples", type=int,
                        default=DEFAULT_LITERAL_SAMPLES,
                        help="how many fixed-width records to record as class-P "
                             "literal reads (default %d)"
                             % DEFAULT_LITERAL_SAMPLES)
    parser.add_argument("--no-timestamp", action="store_true",
                        help="omit generated_at, so two runs over an unchanged "
                             "file are byte-identical")
    parser.add_argument("--install-dir",
                        help="the installation root, for the output-path guard "
                             "and the read locus")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.literal_samples < 0:
        print("error: --literal-samples must not be negative", file=sys.stderr)
        return 2
    if args.jsonl_dir and not args.build_key:
        print("error: --jsonl-dir writes full knowledge-base records, and every "
              "one of them needs a build_key (plan.md 10.3 class I criterion 5). "
              "Pass --build-key.", file=sys.stderr)
        return 2

    install_root = args.install_dir or _detect_install_root(args.path)

    # Layer 1 (plan.md 1.5 / D-01) is checked before any parsing, so a refused
    # path costs nothing and leaves nothing behind. write_text checks again.
    checked: dict[str, str] = {}
    for flag, value in (("--out", args.out), ("--names-out", args.names_out),
                        ("--objects-out", args.objects_out),
                        ("--modules-out", args.modules_out)):
        if not value:
            continue
        try:
            checked[flag] = pathguard.check_output_path(value, install_root,
                                                        what=flag)
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2
    if args.jsonl_dir:
        for name in ("classes.jsonl", "functions.jsonl", "relations.jsonl",
                     "enums.jsonl", "properties.jsonl"):
            try:
                pathguard.check_output_path(os.path.join(args.jsonl_dir, name),
                                            install_root, what="--jsonl-dir")
            except (pathguard.OutputPathRefused, ValueError) as error:
                print("error: %s" % error, file=sys.stderr)
                return 2

    try:
        document = analyze(args.path, ucas_path=args.ucas,
                           install_root=args.install_dir,
                           literal_samples=args.literal_samples,
                           staged_plugins=args.staged_plugins,
                           module_filter=args.module,
                           with_timestamp=not args.no_timestamp)
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
        if "--names-out" in checked:
            written.append(write_text(names_text(document), checked["--names-out"],
                                      install_root, "--names-out"))
        if "--objects-out" in checked:
            written.append(write_text(objects_text(document),
                                      checked["--objects-out"], install_root,
                                      "--objects-out"))
        if "--modules-out" in checked:
            written.append(write_text(modules_text(document),
                                      checked["--modules-out"], install_root,
                                      "--modules-out"))
        if args.jsonl_dir:
            recorded_at = args.recorded_at or now_iso_utc()
            files = emit_reflection_records(document, build_key=args.build_key,
                                            recorded_at=recorded_at,
                                            scope=args.jsonl_scope)
            # A scope that selects nothing is refused rather than written as five
            # empty files. enums.jsonl and properties.jsonl are empty BY DESIGN
            # (see EMPTY_FILE_REASONS), so "all five are empty" is not a
            # tautology -- it means the subtree was not found, and the most
            # likely cause is a mangled argument: a POSIX-looking value such as
            # /Script/MISERY is rewritten by MSYS/Git-Bash into a Windows path
            # before Python ever sees it. This check exists because that
            # happened, and five silently empty files looked like a successful
            # run.
            if args.jsonl_scope != "all" and not any(files.values()):
                print("error: --jsonl-scope %r matched no entry, so nothing "
                      "would be written. Known packages start with '/Script/'; "
                      "if the value above does not look like what you typed, "
                      "the shell rewrote it (MSYS/Git-Bash converts a leading "
                      "'/' into a Windows path). Use 'all' or a package that "
                      "exists." % args.jsonl_scope, file=sys.stderr)
                return 2
            for name, records in sorted(files.items()):
                written.append(write_text(dump_jsonl(records),
                                          os.path.join(args.jsonl_dir, name),
                                          install_root, "--jsonl-dir"))
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

    return 0 if document["summary"]["verdict"] == "VERIFIED" else 2


if __name__ == "__main__":
    sys.exit(main())
