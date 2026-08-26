#!/usr/bin/env python3
"""Read-only byte-pattern signature generator (plan.md task S-06).

The question this tool exists to answer
---------------------------------------
plan.md 7.3 row S-06 asks for a byte-pattern signature for a function, "с маской
для relocations/immediates". Together with ``tools/static/sigscan.py`` (S-07)
this is the mechanism by which a finding recorded against a code address in this
build survives the next game patch: the address is worthless after a rebuild, the
signature is what re-finds it.

Because the pair carries every later finding, the honest failure mode matters
more than the happy path. Three ways a signature tool can be worse than nothing:

1. it emits a pattern that matches **two** places, and a caller takes the first;
2. it emits a pattern that matches only because most of it is **wildcards**;
3. it emits a pattern for a range that is not a **function**.

All three are refusals here, not warnings. Every signature carries
``accepted``, and a rejected one carries machine-readable ``rejections`` naming
which threshold it failed and by how much. ``sigscan`` skips rejected entries by
default. The counts are published in ``summary`` so a document cannot claim more
signatures than the artifact holds.

The boundary oracle: the PE exception directory, and its exact limits
--------------------------------------------------------------------
There is no disassembler in Phase 1, and function boundaries are needed anyway.
They come from the ``IMAGE_DIRECTORY_ENTRY_EXCEPTION`` table -- ``.pdata`` -- which
on AMD64 is an array of ``RUNTIME_FUNCTION``::

    +0x00  DWORD  BeginAddress      RVA, inclusive
    +0x04  DWORD  EndAddress        RVA, exclusive
    +0x08  DWORD  UnwindInfoAddress RVA of the UNWIND_INFO

``tools/fingerprint/pe_info.py`` already counts this table; this module walks it.
The layout above is the published Microsoft x64 exception-handling ABI, which is
the ``external-doc`` oracle: it proves how the Microsoft toolchain lays the table
out and nothing about this build, which is why everything derived from it is
class I.

**A RUNTIME_FUNCTION range is not a compiler function.** This is not a caveat
appended for form; it is measured, and the measurements are in
``boundary_oracle.census`` of every document this tool writes. Four distinct
discrepancies exist and each is counted rather than assumed away.

Sized on the image this repository studies -- these are the numbers, not an
illustration, and they are re-derived on every run rather than quoted from
here:

===============================  ==========  ==========================
discrepancy                      measured    share
===============================  ==========  ==========================
records that are NOT entry       169 032     41.09% of 411 385 records
points (UNW_FLAG_CHAININFO)
primary ranges owning >= 1       77 846      32.12% of 242 353 primaries
continuation chunk
adjacent pairs End[i]==           179 628     43.66% of the records
Begin[i+1]
records sharing an               222 934     54.19% of the records; one
UnwindInfoAddress with                       address is shared by 46 543
another record
executable bytes NOT covered     16 658 307  16.94% of 98 343 936
by any range
===============================  ==========  ==========================

Two of those deserve emphasis because they are larger than a reader would
guess. **Two records in five are not function starts at all.** And the
uncovered-bytes figure is the *lower-bound* character of the table made
concrete: an independently labelled set of 2 178 function entry points (the
vtable slot targets of ``research/evidence/S-10``) put 605 of them -- 27.78% --
at an address with no ``RUNTIME_FUNCTION`` record whatsoever, and not one of
those 605 fell inside another record's range. They are leaf functions the
compiler gave no unwind data. Every one is refused ``boundary_unknown``.

*Chunked functions.* MSVC splits a function into hot and cold ranges. Every
range past the first gets its own ``RUNTIME_FUNCTION`` whose ``UNWIND_INFO``
carries ``UNW_FLAG_CHAININFO`` (flags bit 2) and ends with a
``RUNTIME_FUNCTION`` pointing at the primary range. Such a record is
**not a function start**, and a signature cut from one would be a signature of a
code fragment attributed to the wrong entry point. This tool reads the unwind
flags of every record and refuses a chained one with
``chunk_not_function_start``. The reverse index is built too, so a primary can
report how many chunks belong to it and that its signature covers only the
first.

*Shared unwind info.* Several ranges may point at one ``UNWIND_INFO`` -- most
often the canonical "no prologue" record shared by thousands of leaf thunks.
That is normal and harmless for boundaries, but it means an unwind address is
**not** an identity for a function, and any future code tempted to use it as one
is wrong. Counted as ``unwind_info_addresses_shared`` /
``max_records_per_unwind_info``.

*Adjacent ranges.* ``End[i] == Begin[i+1]`` happens both for two separate
functions laid out back to back and for one function whose ranges the compiler
described separately. From ``.pdata`` alone the two are indistinguishable, so
``End`` is an upper bound on the function's first range and not a proven
function end. Counted as ``adjacent_ranges``.

*Missing records.* A leaf function that touches no non-volatile register and
allocates no stack needs no unwind data and gets **no** ``.pdata`` row at all.
The exception directory is therefore not a function inventory: it is a lower
bound. A requested address with no record is refused with
``boundary_unknown`` -- refused rather than guessed, because guessing an end
address is precisely how a signature ends up spanning the next function.

The mask policy, and the part that cannot be solved without a disassembler
-------------------------------------------------------------------------
A signature must not compare bytes that a rebuild changes even when the source
did not. Two families of such bytes exist in x86-64 code and this tool treats
them completely differently, because it can prove one and cannot prove the other.

**Relocated positions are exact.** The base relocation table (``.reloc``,
``IMAGE_DIRECTORY_ENTRY_BASERELOC``) enumerates every position the loader
patches when the image is not at its preferred base. Its layout is published::

    IMAGE_BASE_RELOCATION:  DWORD VirtualAddress; DWORD SizeOfBlock;
                            WORD entries[]  -- type = entry >> 12,
                                               offset = entry & 0xFFF

Type 10 (``IMAGE_REL_BASED_DIR64``) covers 8 bytes, type 3 (``HIGHLOW``) 4,
types 1 and 2 two, type 0 (``ABSOLUTE``) is block padding and covers nothing.
Every byte a relocation covers is masked. This is an enumeration, not a
heuristic: there is no guessing involved and no false positives.

**Non-relocated immediates cannot be located without decoding instructions, and
this tool does not pretend otherwise.** RIP-relative displacements
(``mov rax, [rip+disp32]``) and rel32 call/jump targets (``E8``/``E9 disp32``)
are position-independent *within* an image, so the loader never patches them and
``.reloc`` never lists them -- yet they are exactly the bytes a rebuild moves.
Finding them requires knowing where each instruction begins, which requires a
decoder, which Phase 1 does not have.

The measured consequence, for the image this repository studies, is worth
stating plainly because it inverts the naive expectation: **the base relocation
table masks nothing in ``.text``.** All 941 132 relocations of
``MISERY-Win64-Shipping.exe`` fall in ``.rdata`` and ``.data``; the count inside
executable sections is zero. That is normal for x86-64 -- code is
position-independent -- and it means the relocation oracle, though exact, is
*empty over the surface where functions live*. A tool that advertised
"relocation-masked signatures" and stopped there would be advertising a mask
that does not exist. The number is measured on every run and published as a
refutation probe (``reloc-oracle-covers-code``) so it cannot be quietly assumed
to be otherwise on another image.

Given that, the conservative choice is to **mask nothing that cannot be proven**:

``--mask-mode reloc`` (the default)
    Mask exactly the relocation-covered bytes. Consequence: a signature may
    contain a displacement that a rebuild changes, so on a new build it comes
    back ``absent``. That is the safe failure direction -- ``absent`` sends the
    operator back to re-locate the function, whereas an over-masked pattern that
    matches something else hands them a wrong address that looks right.

``--mask-mode reloc+rel32`` (opt-in, labelled heuristic on every record)
    Additionally mask the four bytes following any ``E8`` or ``E9`` byte whose
    implied target lands inside the image. This is a **guess**: without decoding,
    an ``E8`` byte may be the middle of some other instruction, and a real call
    whose target happens to leave the image is missed. It is offered because a
    reviewer may want to compare the two populations, and the mode is stamped on
    every signature so the two can never be silently mixed.

Whichever mode runs, two fragility numbers are computed and published for every
signature, because they are what a reader needs in order to judge how likely a
future ``absent`` is:

``rel32_candidates``
    positions where an ``E8``/``E9`` byte is followed by a displacement that
    resolves into the image. An over-count.
``disp32_windows_resolving_into_image``
    every 4-byte window whose value, read as a signed displacement from the end
    of the window, resolves into the image. A strict upper bound on the number
    of RIP-relative displacements the pattern could contain, obtained without
    decoding anything.

Neither is used to mask by default. They are the honest statement of what is
unknown, sized.

The bound has a computable null baseline, and it should be quoted with one. A
uniformly random 4-byte window resolves into the image with probability
``size_of_image / 2**32`` -- for the 138 403 840-byte image this repository
studies that is 3.22%, not something to be waved at as "most windows".
Measured over the 1 530 accepted signatures of the whole-RTTI evidence run,
3 342 of 30 288 windows resolved, which is 11.03%: about 3.4x the null rate, so
the bound is carrying real displacements and is not pure arithmetic noise. What
it cannot do is say WHICH windows those are.

How a length is chosen
----------------------
``--mode grow`` (default) tries an ascending ladder of lengths and keeps the
**shortest** one that is unique on the searched surface, because every extra
byte is another chance to include a build-varying immediate. ``--mode whole``
takes the whole ``RUNTIME_FUNCTION`` range, capped at ``--max-length``. Both
report ``length_chosen``, ``lengths_tried`` and ``range_length`` so the choice is
inspectable. Trailing ``CC``/``00`` padding is trimmed and the trimmed count is
published: alignment filler is not part of a function and including it makes a
signature depend on the next function's alignment.

Uniqueness is checked, never assumed
------------------------------------
Every candidate is counted on the source image by ``sigscan.scan_surface`` -- the
same matcher ``sigscan`` will later use, imported rather than reimplemented, so
"unique when made" and "unique when checked" cannot disagree for reasons of
having two matchers. A pattern found twice is rejected ``not_unique``. A pattern
found *zero* times is rejected ``absent_in_source`` and is a bug report about
this tool, never a fact about the image.

What the refusals look like when the tool is actually run
---------------------------------------------------------
The gate is worth nothing if it never fires, so here is what it did on the
2 178 independently labelled targets of the whole-RTTI evidence run
(``research/evidence/S-06/signatures-all-rtti.json``). 1 530 accepted, 648
refused:

``boundary_unknown``  605   no ``RUNTIME_FUNCTION`` record at the address
``not_unique``         41   the pattern still matched 2 to 7 places at 96 bytes
``too_short``           2   the whole function is 11 and 6 bytes long

The 41 matter most, because they are the failure this pair exists to prevent
made visible. One example: the 37-byte body of an ICU
``LocaleCacheKey<...>::operator==`` occurs **seven** times in ``.text`` at seven
distinct RVAs, byte for byte, and the first of the seven is the requested
address -- so a tool that returned the first hit would have looked right here
and been wrong for the other six. There is no length that fixes it; the
function is only 37 bytes long and all 37 are duplicated. The signature is
refused and the address stays unfindable by this method, which is the correct
answer.

Four rejection codes -- ``too_masked``, ``anchor_too_short``, ``low_variety``
and ``chunk_not_function_start`` -- did not fire on that run at all. The first
three cannot fire while the mask is empty (see the mask policy below: a
fully literal pattern has an anchor as long as itself), and the fourth cannot
fire on vtable slot targets, which point at entry points by construction. They
are exercised only by the synthetic controls of the
``gate-refuses-a-non-signature`` probe, and that is stated here rather than
left for a reader to discover that a code has never been seen to fire.

Two output layers, never merged (plan.md 10.3)
----------------------------------------------
``literal_reads``
    Class **P**. The covered byte range of a sample of signatures, read back
    through a second, independently opened handle, with a claim that states the
    offset and the length and names nothing about what the bytes are -- plan.md
    10.3 v2.4 lists a *signature* among the things naming which forces class I,
    so these claims do not use the word.
``signatures`` / ``boundary_oracle`` / ``mask_policy`` / ``summary``
    Class **I**. Function boundaries from a published ABI, masks from a published
    relocation format, and the assertion that a range *is* a function.

C-13 (the repository is public)
-------------------------------
A signature is a fingerprint and it necessarily contains bytes of the target.
``--max-length`` caps how many (default 96 bytes, hard ceiling 256), the same way
a hash and a size stand in for a file elsewhere in this repository. The plan
sanctions the artifact explicitly (7.3 row S-06, ``signatures/<name>.json``); it
does not sanction dumping function bodies, and the cap is what keeps the
distinction.

Memory (plan.md F-04)
---------------------
Nothing is read whole. ``.pdata`` is read in one bounded pass; the unwind flag
of every record and the chain tail of every chained record are collected by two
sorted, streaming gather passes; ``.reloc`` is walked block by block. Peak
additional memory on the 134 MB target measured a few tens of megabytes.

Determinism
-----------
Sorted keys, indent 2, LF, UTF-8 without BOM, trailing newline. Signatures are
emitted in ascending source-RVA order. Two runs over an unchanged image differ
only in ``generated_at`` and in ``timings_seconds``.

Standard library only.

CLI
---
    python tools/static/sigmake.py <image.exe> --rva 0xf4d8e0
    python tools/static/sigmake.py <image.exe> --rva 0xf4d8e0=IModuleInterface::slot0
    python tools/static/sigmake.py <image.exe> --from-rtti research/evidence/S-10/shipping-rtti.json \\
                                               --rtti-bucket unreal-engine \\
                                               --out research/evidence/S-06/signatures.json

Exit codes: 0 the run completed (whatever the acceptance rate), 2 usage / I/O
error / unparseable input. A run in which every signature was refused is a
successful run with an honest answer, not a failure.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import struct
import sys
import time
from array import array

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
for _extra in (os.path.join(_TOOLS, "inventory"), os.path.join(_TOOLS, "fingerprint")):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never
# reimplemented.
import pathguard  # noqa: E402

# The PE layer is F-01's.
import pe_info  # noqa: E402

# The matcher and the pattern grammar belong to S-07. Importing them is what
# makes "unique when it was made" and "unique when it is checked" the same
# question answered by the same code.
import sigscan  # noqa: E402

GENERATOR_NAME = "tools/static/sigmake.py"
GENERATOR_VERSION = "1.0.0"

PEFormatError = pe_info.PEFormatError
Pattern = sigscan.Pattern


# --------------------------------------------------------------------------- #
# hard limits. Every one of these bounds a number that is READ FROM THE FILE or
# supplied by a caller, and must therefore never be believed.
# --------------------------------------------------------------------------- #

RUNTIME_FUNCTION_SIZE = 12       # AMD64 and ARM64 full form
MAX_RUNTIME_FUNCTIONS = 1 << 21  # 2 097 152; the target has 411 385
MAX_RELOC_BLOCKS = 1 << 18
MAX_RELOC_ENTRIES = 1 << 24      # 16 777 216; the target has 941 132
MAX_UNWIND_CODES = 255           # the field is a byte
MAX_CHAIN_DEPTH = 8              # nested CHAININFO; bounded, and reported
MAX_TARGETS = 4096
GATHER_CHUNK = 4 << 20
DEFAULT_LITERAL_SAMPLES = 6

# Signature geometry. These are the numbers the justification gate enforces and
# every one of them is published on the document next to the results, so a
# reviewer can disagree with a threshold instead of with a verdict.
DEFAULT_MIN_LENGTH = 12          # bytes in the pattern
DEFAULT_MAX_LENGTH = 96          # also the C-13 publication cap by default
HARD_MAX_LENGTH = 256            # --max-length may not exceed this
MIN_LITERAL_BYTES = 10           # bytes actually compared
MAX_MASKED_FRACTION = 0.30
MIN_ANCHOR_BYTES = 6             # longest run of consecutive literal bytes
MIN_DISTINCT_LITERAL_VALUES = 4  # a run of CC is not a fingerprint

# The ladder --mode grow walks. Ascending, so the first length that is unique is
# the shortest one tried; clipped to the function's own length.
LENGTH_LADDER = (12, 16, 20, 24, 32, 40, 48, 64, 80, 96, 128, 160, 192, 224, 256)

PADDING_BYTES = frozenset((0xCC, 0x00))

# UNWIND_INFO flags (published Microsoft x64 ABI).
UNW_FLAG_EHANDLER = 0x1
UNW_FLAG_UHANDLER = 0x2
UNW_FLAG_CHAININFO = 0x4

# IMAGE_REL_BASED_* -> how many bytes the fixup covers. Only the types that
# occur in a linked PE are listed; anything else is counted as unknown and
# reported rather than assumed to cover nothing.
RELOC_WIDTH = {
    0: 0,        # ABSOLUTE -- block padding, covers nothing
    1: 2,        # HIGH
    2: 2,        # LOW
    3: 4,        # HIGHLOW
    4: 4,        # HIGHADJ (followed by an extra WORD operand)
    10: 8,       # DIR64
}
RELOC_NAME = {0: "ABSOLUTE", 1: "HIGH", 2: "LOW", 3: "HIGHLOW", 4: "HIGHADJ",
              5: "MIPS_JMPADDR", 10: "DIR64"}

MASK_MODE_RELOC = "reloc"
MASK_MODE_RELOC_REL32 = "reloc+rel32"
MASK_MODES = (MASK_MODE_RELOC, MASK_MODE_RELOC_REL32)

MODE_GROW = "grow"
MODE_WHOLE = "whole"
MODES = (MODE_GROW, MODE_WHOLE)

# Confidence ceiling is 0.99 (plan.md 10.2); 1.00 is forbidden anywhere.
CONFIDENCE_LITERAL = 0.99
CONFIDENCE_INTERPRETED_CORROBORATED = 0.85
CONFIDENCE_INTERPRETED_SINGLE_METHOD = 0.79

# Rejection codes. Closed vocabulary: a caller may branch on these, and a new
# reason must be added here rather than smuggled in as prose.
REJECTIONS = {
    "boundary_unknown": (
        "no RUNTIME_FUNCTION record begins at this address, so the end of the "
        "function is unknown. The exception directory is a lower bound on the "
        "function inventory -- a leaf function that needs no unwind data has no "
        "record -- and an end address invented here would let the pattern run "
        "into whatever follows"),
    "chunk_not_function_start": (
        "the RUNTIME_FUNCTION at this address carries UNW_FLAG_CHAININFO: it is a "
        "continuation chunk of another function, not an entry point. A signature "
        "cut here would be attributed to the wrong function"),
    "range_not_on_disk": (
        "the byte range does not map to on-disk data (it is in a section's "
        "zero-filled virtual tail, or past the end of the file)"),
    "range_not_executable": (
        "the byte range does not lie in a section whose characteristics carry "
        "IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_CNT_CODE, so it is not code and a "
        "code signature must not be cut from it"),
    "too_short": (
        "the usable range is shorter than the minimum signature length. A pattern "
        "that short is not evidence of identity even when it happens to be unique "
        "today"),
    "too_few_literal_bytes": (
        "too few positions are actually compared once the mask is applied"),
    "too_masked": (
        "the masked fraction is above the limit: most of this pattern is holes, "
        "and a pattern that is mostly holes matches by accident"),
    "anchor_too_short": (
        "the longest run of consecutive literal bytes is too short. Scattered "
        "single literal bytes do not discriminate, and there is nothing long "
        "enough for the matcher to search on"),
    "low_variety": (
        "the literal positions take too few distinct byte values -- a run of "
        "padding or of one repeated opcode is not a fingerprint"),
    "not_unique": (
        "the pattern occurs more than once on the searched surface of the very "
        "image it was cut from, so it does not identify a location"),
    "absent_in_source": (
        "the pattern was not found in the image it was cut from. That is a defect "
        "in this tool, not a fact about the image, and it must be explained"),
}


# --------------------------------------------------------------------------- #
# small shared helpers
# --------------------------------------------------------------------------- #

def hex_bytes(raw: bytes) -> str:
    return raw.hex()


def dump_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _fmt_int(value) -> str:
    if value is None:
        return "-"
    return "{:,}".format(value).replace(",", " ")


def gather(handle, requests: list[tuple[int, int]]) -> dict[int, bytes]:
    """Read many small ranges in one forward pass over the file.

    ``requests`` is a list of ``(file_offset, length)``. The pass is sorted and
    streaming, which is what keeps 400 000 twelve-byte reads from becoming
    400 000 seeks; the buffer is reused, so peak memory is one chunk plus the
    result.

    Ranges that straddle a chunk boundary are re-read individually rather than
    stitched, because stitching is where an off-by-one in this kind of helper
    hides. There are few such ranges by construction (the chunk is 4 MiB and the
    ranges are a handful of bytes).
    """
    result: dict[int, bytes] = {}
    if not requests:
        return result
    ordered = sorted(set(requests))
    index = 0
    while index < len(ordered):
        base = ordered[index][0]
        handle.seek(base)
        buf = handle.read(GATHER_CHUNK)
        if not buf:
            break
        end = base + len(buf)
        progressed = False
        while index < len(ordered):
            offset, length = ordered[index]
            if offset + length > end:
                break
            result[offset] = buf[offset - base:offset - base + length]
            index += 1
            progressed = True
        if index < len(ordered) and not progressed:
            # One range longer than what the read returned (or a short read at
            # the end of the file): satisfy it directly and move on.
            offset, length = ordered[index]
            handle.seek(offset)
            direct = handle.read(length)
            if len(direct) == length:
                result[offset] = direct
            index += 1
    return result


# --------------------------------------------------------------------------- #
# the boundary oracle: .pdata plus the unwind flags
# --------------------------------------------------------------------------- #

class BoundaryTable:
    """The ``RUNTIME_FUNCTION`` table, with the chunk relation resolved.

    Three parallel arrays plus, when the chain scan ran, the unwind flag byte of
    every record and the RVA of the primary range every chained record belongs
    to. Arrays rather than a list of dicts, and ``bisect`` over the begin column
    rather than a dict keyed by begin: 411 385 records is where a dict of
    Python ints starts costing tens of megabytes for a lookup that a binary
    search does for free.

    ``census`` is the part a reader should look at before believing any boundary
    in this repository. It counts, on the image at hand, each of the four ways a
    ``RUNTIME_FUNCTION`` range differs from a compiler function.
    """

    def __init__(self, headers, warnings: list[str], *, want_chain_scan: bool = True):
        self.headers = headers
        self.warnings = warnings
        self.begins = array("I")
        self.ends = array("I")
        self.unwinds = array("I")
        self.flags: bytearray | None = None
        self.chain_primary: array | None = None
        self.chain_scan_ran = False
        self.truncated = False
        self.directory_rva, self.directory_size = headers.directory(3)
        self._load()
        self._sorted = all(self.begins[i] <= self.begins[i + 1]
                           for i in range(len(self.begins) - 1))
        if not self._sorted and self.begins:
            warnings.append(
                "the exception directory is not sorted by BeginAddress; lookups "
                "use a sorted copy of the begin column")
            order = sorted(range(len(self.begins)), key=lambda i: self.begins[i])
            self._order = order
            self._keys = [self.begins[i] for i in order]
        else:
            self._order = None
            self._keys = self.begins
        if want_chain_scan:
            self._scan_chains()
        self.census = self._census()

    # -- loading ------------------------------------------------------------ #

    def _load(self) -> None:
        rva, size = self.directory_rva, self.directory_size
        if not rva or not size:
            self.warnings.append(
                "the PE exception directory is absent (RVA and size are 0); there "
                "is no boundary oracle and every target will be refused with "
                "boundary_unknown")
            return
        if self.headers.machine not in (0x8664, 0xAA64):
            self.warnings.append(
                "machine is 0x%04x; the 12-byte RUNTIME_FUNCTION layout assumed "
                "here is the AMD64/ARM64 one and the boundary oracle may be "
                "misread" % self.headers.machine)
        available = self.headers.rva_available(rva)
        usable = min(size, available)
        if size > available:
            self.warnings.append(
                "the exception directory declares %d bytes but only %d are on "
                "disk; the boundary table is built from the readable part"
                % (size, available))
        count = usable // RUNTIME_FUNCTION_SIZE
        if count > MAX_RUNTIME_FUNCTIONS:
            self.warnings.append(
                "the exception directory holds %d records, over the %d limit; the "
                "table is truncated and a target past the cut will be refused"
                % (count, MAX_RUNTIME_FUNCTIONS))
            count = MAX_RUNTIME_FUNCTIONS
            self.truncated = True
        offset = self.headers.rva_to_offset(rva)
        if offset is None:
            self.warnings.append("the exception directory RVA maps nowhere on disk")
            return
        # One streaming pass; struct.iter_unpack keeps the per-record cost in C.
        remaining = count * RUNTIME_FUNCTION_SIZE
        with open(self.headers.image.path, "rb", buffering=0) as handle:
            handle.seek(offset)
            while remaining > 0:
                want = min(GATHER_CHUNK - GATHER_CHUNK % RUNTIME_FUNCTION_SIZE,
                           remaining)
                blob = handle.read(want)
                if len(blob) < RUNTIME_FUNCTION_SIZE:
                    break
                whole = len(blob) - len(blob) % RUNTIME_FUNCTION_SIZE
                for begin, end, unwind in struct.iter_unpack("<III", blob[:whole]):
                    self.begins.append(begin)
                    self.ends.append(end)
                    self.unwinds.append(unwind)
                remaining -= whole

    def _scan_chains(self) -> None:
        """Read the unwind flag of every record, then resolve every chain.

        Two sorted gather passes. The first collects the four-byte
        ``UNWIND_INFO`` head of every DISTINCT unwind address -- 197 872 of them
        for 411 385 records on the target, so de-duplicating first halves the
        work. The second reads the twelve-byte ``RUNTIME_FUNCTION`` tail of the
        chained ones, whose position follows from the head::

            tail = unwind + 4 + 2 * ((CountOfCodes + 1) & ~1)

        A chain may itself be chained, so the primary is resolved by following
        the relation up to :data:`MAX_CHAIN_DEPTH` steps; anything deeper (or
        cyclic) is counted as unresolved rather than followed forever.
        """
        if not self.begins:
            return
        headers = self.headers
        distinct = sorted(set(self.unwinds))
        requests = []
        for unwind in distinct:
            offset = headers.rva_to_offset(unwind)
            if offset is not None and headers.rva_available(unwind) >= 4:
                requests.append((offset, 4))
        with open(headers.image.path, "rb", buffering=0) as handle:
            heads = gather(handle, requests)

            head_by_unwind: dict[int, bytes] = {}
            for unwind in distinct:
                offset = headers.rva_to_offset(unwind)
                if offset is not None and offset in heads:
                    head_by_unwind[unwind] = heads[offset]
            del heads

            self.flags = bytearray(len(self.begins))
            tail_requests: list[tuple[int, int]] = []
            tail_offset_of: dict[int, int] = {}
            for unwind, head in head_by_unwind.items():
                flags = head[0] >> 3
                if not flags & UNW_FLAG_CHAININFO:
                    continue
                codes = head[2]
                if codes > MAX_UNWIND_CODES:
                    continue
                tail_rva = unwind + 4 + 2 * ((codes + 1) & ~1)
                offset = headers.rva_to_offset(tail_rva)
                if offset is None or headers.rva_available(tail_rva) < RUNTIME_FUNCTION_SIZE:
                    continue
                tail_offset_of[unwind] = offset
                tail_requests.append((offset, RUNTIME_FUNCTION_SIZE))
            tails = gather(handle, tail_requests)

        primary_of_unwind: dict[int, int] = {}
        for unwind, offset in tail_offset_of.items():
            blob = tails.get(offset)
            if blob is None or len(blob) < RUNTIME_FUNCTION_SIZE:
                continue
            primary_of_unwind[unwind] = struct.unpack_from("<I", blob, 0)[0]
        del tails

        self.chain_primary = array("I", bytes(4 * len(self.begins)))
        for index in range(len(self.begins)):
            head = head_by_unwind.get(self.unwinds[index])
            if head is None:
                continue
            self.flags[index] = head[0] >> 3
            if self.flags[index] & UNW_FLAG_CHAININFO:
                self.chain_primary[index] = primary_of_unwind.get(
                    self.unwinds[index], 0)
        self.chain_scan_ran = True

    # -- lookups ------------------------------------------------------------ #

    def index_of_begin(self, rva: int) -> int | None:
        """The record whose BeginAddress is exactly *rva*, or None."""
        position = bisect.bisect_left(self._keys, rva)
        if position >= len(self._keys) or self._keys[position] != rva:
            return None
        return self._order[position] if self._order is not None else position

    def index_containing(self, rva: int) -> int | None:
        """The record whose [Begin, End) contains *rva*, or None.

        Only meaningful when the table is sorted and the ranges do not nest,
        which is the normal case; used to explain a ``boundary_unknown`` rather
        than to place a signature.
        """
        if not self._keys:
            return None
        position = bisect.bisect_right(self._keys, rva) - 1
        if position < 0:
            return None
        index = self._order[position] if self._order is not None else position
        if self.begins[index] <= rva < self.ends[index]:
            return index
        return None

    def record(self, index: int) -> dict:
        flags = None if self.flags is None else self.flags[index]
        primary = None
        if self.chain_primary is not None and flags and flags & UNW_FLAG_CHAININFO:
            primary = self.chain_primary[index] or None
        return {
            "index": index,
            "begin_address": self.begins[index],
            "end_address": self.ends[index],
            "unwind_info_address": self.unwinds[index],
            "range_length": max(0, self.ends[index] - self.begins[index]),
            "unwind_flags": flags,
            "unwind_flags_decoded": _decode_unwind_flags(flags),
            "is_chunk": None if flags is None else bool(flags & UNW_FLAG_CHAININFO),
            "chain_primary_begin_address": primary,
        }

    def chunks_of(self, begin_rva: int) -> list[dict]:
        """Every record that chains (transitively) to the range starting at *begin_rva*.

        One linear pass over the chain column, deliberately: a dict from primary
        to chunk list would hold a hundred thousand entries for the benefit of
        the handful of addresses a run actually asks about.
        """
        if self.chain_primary is None:
            return []
        direct = {begin_rva}
        found: set[int] = set()
        for _ in range(MAX_CHAIN_DEPTH):
            added = False
            for index in range(len(self.begins)):
                if index in found:
                    continue
                primary = self.chain_primary[index]
                if primary and primary in direct:
                    found.add(index)
                    direct.add(self.begins[index])
                    added = True
            if not added:
                break
        return [self.record(index) for index in sorted(found)]

    # -- census ------------------------------------------------------------- #

    def _census(self) -> dict:
        total = len(self.begins)
        distinct_begins = len(set(self.begins)) if total else 0
        adjacent = sum(1 for i in range(total - 1)
                       if self.ends[i] == self.begins[i + 1])
        covered = sum(max(0, self.ends[i] - self.begins[i]) for i in range(total))
        by_unwind: dict[int, int] = {}
        for unwind in self.unwinds:
            by_unwind[unwind] = by_unwind.get(unwind, 0) + 1
        shared = sum(1 for count in by_unwind.values() if count > 1)
        shared_records = sum(count for count in by_unwind.values() if count > 1)
        chunks = None
        primaries_with_chunks = None
        unresolved = None
        with_handler = None
        if self.flags is not None:
            chunks = sum(1 for f in self.flags if f & UNW_FLAG_CHAININFO)
            with_handler = sum(1 for f in self.flags
                               if f & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER))
            parents = set()
            unresolved = 0
            for index in range(total):
                if not (self.flags[index] & UNW_FLAG_CHAININFO):
                    continue
                primary = self.chain_primary[index]
                if primary:
                    parents.add(primary)
                else:
                    unresolved += 1
            primaries_with_chunks = len(parents)
        exec_bytes = sum(section["rsize"] for section in self.headers.sections
                         if section["rsize"] > 0
                         and section["characteristics"]
                         & (sigscan.IMAGE_SCN_MEM_EXECUTE | sigscan.IMAGE_SCN_CNT_CODE))
        return {
            "directory_rva": self.directory_rva,
            "directory_size": self.directory_size,
            "entry_size": RUNTIME_FUNCTION_SIZE,
            "runtime_function_count": total,
            "table_truncated": self.truncated,
            "distinct_begin_addresses": distinct_begins,
            "duplicate_begin_addresses": total - distinct_begins,
            "adjacent_ranges": adjacent,
            "bytes_covered_by_ranges": covered,
            "executable_bytes_on_disk": exec_bytes,
            "coverage_fraction_of_executable_bytes": (
                round(covered / exec_bytes, 6) if exec_bytes else None),
            "distinct_unwind_info_addresses": len(by_unwind),
            "unwind_info_addresses_shared": shared,
            "records_sharing_unwind_info": shared_records,
            "max_records_per_unwind_info": (max(by_unwind.values())
                                            if by_unwind else 0),
            "chain_scan_ran": self.chain_scan_ran,
            "records_with_chaininfo": chunks,
            "records_with_exception_handler": with_handler,
            "primary_ranges": None if chunks is None else total - chunks,
            "primaries_with_at_least_one_chunk": primaries_with_chunks,
            "chained_records_with_unresolved_primary": unresolved,
            "discrepancies_named": {
                "chunked_functions": (
                    "records_with_chaininfo of the %d records are continuation "
                    "chunks, not function entry points" % total),
                "shared_unwind_info": (
                    "an UnwindInfoAddress is not an identity for a function: "
                    "max_records_per_unwind_info records share one"),
                "adjacent_ranges": (
                    "adjacent_ranges pairs have End[i] == Begin[i+1]; from .pdata "
                    "alone that is indistinguishable from one function described "
                    "in two rows, so End is an upper bound and not a proven end"),
                "missing_records": (
                    "a leaf function needing no unwind data has no record at all, "
                    "so this table is a LOWER BOUND on the function inventory; "
                    "coverage_fraction_of_executable_bytes sizes the gap"),
            },
        }


def _decode_unwind_flags(flags: int | None) -> list[str] | None:
    if flags is None:
        return None
    names = []
    if flags & UNW_FLAG_EHANDLER:
        names.append("UNW_FLAG_EHANDLER")
    if flags & UNW_FLAG_UHANDLER:
        names.append("UNW_FLAG_UHANDLER")
    if flags & UNW_FLAG_CHAININFO:
        names.append("UNW_FLAG_CHAININFO")
    return names


# --------------------------------------------------------------------------- #
# the relocation oracle: .reloc
# --------------------------------------------------------------------------- #

class RelocationTable:
    """Every position the loader patches, as an exact sorted list.

    Stored as two parallel arrays -- the RVA and the width in bytes -- because
    941 132 entries as tuples in a list is an order of magnitude more memory for
    a lookup that ``bisect`` over one array performs directly.

    ``census`` breaks the entries down by section, and that breakdown is the
    single most important number this class produces: for an x86-64 image it is
    normally **zero** inside the executable sections, which means this exact
    oracle masks nothing at all in code. See the module docstring.
    """

    def __init__(self, headers, warnings: list[str]) -> None:
        self.headers = headers
        self.warnings = warnings
        self.rvas = array("I")
        self.widths = bytearray()
        self.by_type: dict[int, int] = {}
        self.blocks = 0
        self.truncated = False
        self.directory_rva, self.directory_size = headers.directory(5)
        self._load()
        self.census = self._census()

    def _load(self) -> None:
        rva, size = self.directory_rva, self.directory_size
        if not rva or not size:
            self.warnings.append(
                "the base relocation directory is absent (RVA and size are 0); no "
                "position can be proven relocated and every mask will be empty")
            return
        available = self.headers.rva_available(rva)
        usable = min(size, available)
        if size > available:
            self.warnings.append(
                "the base relocation directory declares %d bytes but only %d are "
                "on disk; the table is built from the readable part"
                % (size, available))
        offset = self.headers.rva_to_offset(rva)
        if offset is None:
            self.warnings.append("the base relocation directory RVA maps nowhere")
            return
        with open(self.headers.image.path, "rb", buffering=0) as handle:
            handle.seek(offset)
            blob = handle.read(usable)
        position = 0
        entries = 0
        while position + 8 <= len(blob):
            page_rva, block_size = struct.unpack_from("<II", blob, position)
            if block_size < 8:
                self.warnings.append(
                    "relocation block at offset %d declares SizeOfBlock %d (<8); "
                    "the walk stops here" % (position, block_size))
                break
            if position + block_size > len(blob):
                self.warnings.append(
                    "relocation block at offset %d declares %d bytes but only %d "
                    "remain; the walk stops here"
                    % (position, block_size, len(blob) - position))
                break
            self.blocks += 1
            if self.blocks > MAX_RELOC_BLOCKS:
                self.warnings.append("more than %d relocation blocks; the table is "
                                     "truncated" % MAX_RELOC_BLOCKS)
                self.truncated = True
                break
            count = (block_size - 8) // 2
            skip_next = False
            for slot in range(count):
                entry, = struct.unpack_from("<H", blob, position + 8 + slot * 2)
                if skip_next:
                    # HIGHADJ carries an extra WORD operand that is not an entry.
                    skip_next = False
                    continue
                kind = entry >> 12
                self.by_type[kind] = self.by_type.get(kind, 0) + 1
                if kind == 4:
                    skip_next = True
                width = RELOC_WIDTH.get(kind)
                if width is None:
                    self.warnings.append(
                        "relocation type %d is not one this tool knows the width "
                        "of; its positions are NOT masked and the mask is "
                        "therefore incomplete for this image" % kind)
                    continue
                if width == 0:
                    continue
                entries += 1
                if entries > MAX_RELOC_ENTRIES:
                    self.warnings.append(
                        "more than %d relocation entries; the table is truncated "
                        "and masks may be incomplete" % MAX_RELOC_ENTRIES)
                    self.truncated = True
                    break
                self.rvas.append(page_rva + (entry & 0xFFF))
                self.widths.append(width)
            if self.truncated:
                break
            position += block_size
        # The blocks are page-ordered in every linker output, but the mask lookup
        # is a binary search and cannot assume it.
        if any(self.rvas[i] > self.rvas[i + 1] for i in range(len(self.rvas) - 1)):
            order = sorted(range(len(self.rvas)), key=lambda i: self.rvas[i])
            self.rvas = array("I", (self.rvas[i] for i in order))
            self.widths = bytearray(self.widths[i] for i in order)

    def covered_positions(self, rva: int, length: int) -> list[int]:
        """Offsets within ``[rva, rva+length)`` that a relocation covers.

        The search starts a little before *rva* because a fixup beginning just
        before the range can still extend into it -- eight bytes back is enough
        for the widest type this format has.
        """
        if not self.rvas or length <= 0:
            return []
        start = bisect.bisect_left(self.rvas, rva - 8)
        positions: list[int] = []
        for index in range(start, len(self.rvas)):
            entry = self.rvas[index]
            if entry >= rva + length:
                break
            width = self.widths[index]
            for byte in range(entry, entry + width):
                if rva <= byte < rva + length:
                    positions.append(byte - rva)
        return sorted(set(positions))

    def _census(self) -> dict:
        # A merge walk over two sorted sequences rather than a lookup per entry:
        # 941 132 entries times a per-entry section search is several seconds of
        # pure Python for a number that one linear pass produces.
        spans = sorted(
            ((section["rva"], section["rva"] + max(section["vsize"], section["rsize"]),
              section["name"] or "<unnamed>")
             for section in self.headers.sections
             if max(section["vsize"], section["rsize"]) > 0),
            key=lambda row: row[0])
        per_section: dict[str, int] = {}
        cursor = 0
        outside = 0
        for index in range(len(self.rvas)):
            rva = self.rvas[index]
            while cursor < len(spans) and rva >= spans[cursor][1]:
                cursor += 1
            if cursor < len(spans) and spans[cursor][0] <= rva < spans[cursor][1]:
                name = spans[cursor][2]
            else:
                # Either before the first span or in a hole between two of them.
                # Not folded into a neighbour: an entry outside every section is
                # a malformed table and has to stay visible.
                name = self._section_name(rva)
                if name == "<outside every section>":
                    outside += 1
            per_section[name] = per_section.get(name, 0) + 1
        if outside:
            self.warnings.append(
                "%d base relocation entries point outside every section; the table "
                "is malformed and those positions cannot be masked" % outside)
        exec_names = {section["name"] or "<unnamed>"
                      for section in self.headers.sections
                      if section["characteristics"]
                      & (sigscan.IMAGE_SCN_MEM_EXECUTE | sigscan.IMAGE_SCN_CNT_CODE)}
        in_exec = sum(count for name, count in per_section.items()
                      if name in exec_names)
        return {
            "directory_rva": self.directory_rva,
            "directory_size": self.directory_size,
            "block_count": self.blocks,
            "entry_count": len(self.rvas),
            "table_truncated": self.truncated,
            "by_type": {("%d (%s)" % (kind, RELOC_NAME.get(kind, "unknown"))): count
                        for kind, count in sorted(self.by_type.items())},
            "entries_per_section": dict(sorted(per_section.items())),
            "executable_sections": sorted(exec_names),
            "entries_in_executable_sections": in_exec,
            "what_zero_in_executable_sections_means": (
                "the relocation oracle is exact but EMPTY over code: no byte of any "
                "function is provably relocated, so a relocation-derived mask masks "
                "nothing there and cannot be cited as making a code signature "
                "build-stable. This is the normal case for x86-64, where code "
                "addresses data RIP-relatively and the loader patches nothing in "
                ".text"),
        }

    def _section_name(self, rva: int) -> str:
        for section in self.headers.sections:
            span = max(section["vsize"], section["rsize"])
            if span and section["rva"] <= rva < section["rva"] + span:
                return section["name"] or "<unnamed>"
        return "<outside every section>"


# --------------------------------------------------------------------------- #
# fragility metrics: what cannot be detected without decoding instructions
# --------------------------------------------------------------------------- #

def fragility(body: bytes, rva: int, size_of_image: int) -> dict:
    """Upper bounds on the build-varying immediates a range may contain.

    Neither number is a mask and neither is used as one by default. They exist
    because "we did not mask the displacements" is only an honest statement if it
    comes with a size, and both can be computed without decoding anything:

    ``rel32_candidates``
        every position holding ``E8`` or ``E9`` whose following four bytes, read
        as a signed displacement from the end of the instruction, resolve inside
        the image. An over-count: without instruction boundaries an ``E8`` byte
        may be the ModRM or an immediate of something else. Also an under-count
        for calls whose target lies outside the image, which for a self-contained
        ``.text`` is rare but is not impossible.
    ``disp32_windows_resolving_into_image``
        every 4-byte window whose value, read as a signed displacement from the
        end of the window, resolves inside the image. This is the strict upper
        bound on the RIP-relative displacements the range could contain. It is
        large by construction: a uniformly random window resolves with
        probability ``size_of_image / 2**32`` (3.22% for the 138 403 840-byte
        image this repository studies), so a share of these windows is pure
        arithmetic. Reported as a bound, never as a count of real
        displacements; compare it against that null rate before reading
        anything into it.
    """
    rel32: list[int] = []
    for position in range(0, max(0, len(body) - 4)):
        if body[position] not in (0xE8, 0xE9):
            continue
        displacement = struct.unpack_from("<i", body, position + 1)[0]
        target = rva + position + 5 + displacement
        if 0 <= target < size_of_image:
            rel32.append(position)
    windows = 0
    for position in range(0, max(0, len(body) - 3)):
        displacement = struct.unpack_from("<i", body, position)[0]
        target = rva + position + 4 + displacement
        if 0 <= target < size_of_image:
            windows += 1
    return {
        "rel32_candidates": len(rel32),
        "rel32_candidate_offsets": rel32,
        "disp32_windows_resolving_into_image": windows,
        "disp32_windows_examined": max(0, len(body) - 3),
        "method": ("byte-window arithmetic only -- no instruction was decoded, so "
                   "rel32_candidates is an over-count and "
                   "disp32_windows_resolving_into_image is a strict upper bound"),
        "not_detected": ("a RIP-relative displacement cannot be distinguished from "
                         "an unrelated 4-byte window without knowing where the "
                         "instruction starts; Phase 1 has no decoder and this tool "
                         "does not guess"),
    }


# --------------------------------------------------------------------------- #
# candidate construction and the justification gate
# --------------------------------------------------------------------------- #

def build_mask(length: int, reloc_positions: list[int],
               rel32_offsets: list[int], mask_mode: str) -> tuple[bytes, dict]:
    """The mask for a range, plus a breakdown of where each hole came from.

    ``mask[i] == 1`` means "compare this byte". The breakdown is published on
    every signature: a reader must be able to see that a hole is there because a
    relocation *proved* the byte moves, and not because something guessed.
    """
    mask = bytearray(b"\x01" * length)
    by_reloc = 0
    for position in reloc_positions:
        if 0 <= position < length and mask[position]:
            mask[position] = 0
            by_reloc += 1
    by_rel32 = 0
    if mask_mode == MASK_MODE_RELOC_REL32:
        for position in rel32_offsets:
            for byte in range(position + 1, position + 5):
                if 0 <= byte < length and mask[byte]:
                    mask[byte] = 0
                    by_rel32 += 1
    breakdown = {
        "mask_mode": mask_mode,
        "masked_by_base_relocation": by_reloc,
        "masked_by_rel32_heuristic": by_rel32,
        "masked_total": by_reloc + by_rel32,
        "base_relocation_is_exact": True,
        "rel32_is_a_heuristic": mask_mode == MASK_MODE_RELOC_REL32,
        "heuristic_note": (
            "the rel32 holes are GUESSED: no instruction was decoded, so an E8/E9 "
            "byte that is part of another instruction produces a hole that should "
            "not be there" if mask_mode == MASK_MODE_RELOC_REL32
            else "no heuristic masking was applied; every hole is a proven "
                 "relocation"),
    }
    return bytes(mask), breakdown


def justify(pattern: Pattern, *, min_length: int, max_masked_fraction: float,
            min_literal_bytes: int, min_anchor_bytes: int,
            min_distinct_values: int) -> list[dict]:
    """Every geometric reason this pattern must not be emitted as a signature.

    Returns a list, not a first failure: a pattern that is both too short and
    too masked should say both, because fixing one would still leave it
    unusable and a reader deserves the whole diagnosis at once.
    """
    problems: list[dict] = []

    def fail(code: str, measured, threshold) -> None:
        problems.append({"code": code, "reason": REJECTIONS[code],
                         "measured": measured, "threshold": threshold})

    if pattern.length < min_length:
        fail("too_short", pattern.length, min_length)
    if pattern.literal_bytes < min_literal_bytes:
        fail("too_few_literal_bytes", pattern.literal_bytes, min_literal_bytes)
    if pattern.masked_fraction > max_masked_fraction:
        fail("too_masked", pattern.masked_fraction, max_masked_fraction)
    if pattern.anchor_length < min_anchor_bytes:
        fail("anchor_too_short", pattern.anchor_length, min_anchor_bytes)
    if pattern.distinct_literal_values < min_distinct_values:
        fail("low_variety", pattern.distinct_literal_values, min_distinct_values)
    return problems


def trim_padding(body: bytes) -> tuple[bytes, int]:
    """Drop a trailing run of ``CC``/``00`` and say how many bytes went.

    Alignment filler is not part of a function, and a signature that reached
    into it would depend on how the *next* function happens to be aligned. The
    trim is only at the tail: a ``CC`` inside a range is an ``int3`` that the
    compiler put there on purpose.
    """
    end = len(body)
    while end > 0 and body[end - 1] in PADDING_BYTES:
        end -= 1
    return body[:end], len(body) - end


# --------------------------------------------------------------------------- #
# target selection
# --------------------------------------------------------------------------- #

def parse_rva_argument(text: str) -> tuple[int, str | None]:
    """``0xf4d8e0`` or ``0xf4d8e0=some::label``."""
    label = None
    body = text
    if "=" in text:
        body, label = text.split("=", 1)
        label = label.strip() or None
    body = body.strip()
    try:
        value = int(body, 16) if body.lower().startswith("0x") else int(body, 0)
    except ValueError:
        raise ValueError("%r is not a number; write an RVA as 0x1234 or 4660"
                         % body) from None
    if value < 0:
        raise ValueError("an RVA cannot be negative (%d)" % value)
    return value, label


def targets_from_rtti(path: str, image_sha256: str | None, buckets: tuple[str, ...] | None,
                      warnings: list[str]) -> list[dict]:
    """Derive targets from a ``tools/static/rtti_scan.py`` document.

    Why this adapter exists rather than a hand-written address list: S-06 has to
    be demonstrated on functions whose identity was established by some *other*
    method, or the demonstration is circular. The RTTI scan produces exactly
    that -- named classes whose vtable slots point at code -- so a slot target is
    a function with a name attached, and the whole evidence run becomes one
    reproducible command instead of a list of magic numbers.

    The document's own source image is checked against this run's target by
    digest. A mismatch is a warning and not a refusal, because comparing a
    signature ladder across two images is a legitimate thing to want; but it has
    to be visible, because vtable slot RVAs from one build mean nothing in
    another.
    """
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    source = (document.get("file") or {})
    if image_sha256 and source.get("sha256") and source["sha256"] != image_sha256:
        warnings.append(
            "--from-rtti %s was produced from a DIFFERENT image (sha256 %s) than "
            "the one being read now (%s); its RVAs do not describe this image"
            % (os.path.basename(path), str(source.get("sha256"))[:16],
               image_sha256[:16]))
    classes = document.get("classes")
    if not isinstance(classes, list):
        raise ValueError("%s has no 'classes' list; it is not an rtti_scan document"
                         % path)
    # target rva -> every (class, slot) that points at it. A slot target used by
    # several classes is one function, and it gets one signature with every user
    # recorded, rather than N signatures with identical patterns and different
    # names (which would collide in the uniqueness check and be rejected as
    # not_unique for a reason that is about the naming and not about the bytes).
    users: dict[int, list[tuple[str, int]]] = {}
    for record in classes:
        vtable = record.get("vtable")
        if not vtable:
            continue
        bucket = (record.get("attribution") or {}).get("bucket")
        if buckets is not None and bucket not in buckets:
            continue
        name = record.get("decoded_name") or record.get("mangled") or "?"
        for slot, rva in enumerate(vtable.get("code_slot_target_rvas") or []):
            if isinstance(rva, int) and rva > 0:
                users.setdefault(rva, []).append((name, slot))
    targets: list[dict] = []
    for rva in sorted(users):
        rows = sorted(users[rva])
        name, slot = rows[0]
        targets.append({
            "rva": rva,
            "label": "%s::vtable_slot_%d" % (name, slot),
            "origin": "rtti vtable slot",
            "identified_by": {
                "method": "S-10",
                "artifact": os.path.basename(path),
                "note": ("this address is the target of virtual function table slot "
                         "%d of %s, which the RTTI scan reached through a complete "
                         "object locator; the identity of the function is therefore "
                         "established independently of anything in this document"
                         % (slot, name)),
                "vtable_users": ["%s::vtable_slot_%d" % (n, s) for n, s in rows],
                "vtable_user_count": len(rows),
            },
        })
    if len(targets) > MAX_TARGETS:
        warnings.append("--from-rtti yielded %d targets; only the first %d were "
                        "used" % (len(targets), MAX_TARGETS))
        targets = targets[:MAX_TARGETS]
    return targets


# --------------------------------------------------------------------------- #
# evidence layers (identical contract to sigscan; the helpers are shared)
# --------------------------------------------------------------------------- #

def literal_read(target: str, join_key: str, offset: int, raw: bytes) -> dict:
    """One class-P record. See ``sigscan.literal_read`` for the full reasoning.

    The only difference is the method name on the source: this reading was taken
    by S-06.
    """
    record = sigscan.literal_read(target, join_key, offset, raw)
    record["evidence"]["sources"][0]["method"] = "S-06"
    record["evidence"]["sources"][0]["note"] = (
        "oracle binary-analysis. Read by %s, read-only. Reproduction: PENDING."
        % GENERATOR_NAME)
    return record


def confirm_literal_reads(path: str, literals: list[dict], target: str,
                          warnings: list[str]) -> bool:
    """plan.md 10.3 class-P criterion 2, executed. See the sigscan twin."""
    reproduced = True
    try:
        with open(path, "rb", buffering=0) as handle:
            for read in literals:
                handle.seek(read["offset"])
                again = handle.read(read["length"])
                if hex_bytes(again) != read["bytes_hex"]:
                    reproduced = False
                    warnings.append(
                        "%s: the second read of %d bytes at offset %d gave %s but "
                        "the first gave %s -- the reading did NOT reproduce"
                        % (target, read["length"], read["offset"], hex_bytes(again),
                           read["bytes_hex"]))
    except OSError as error:
        reproduced = False
        warnings.append("%s: the confirming re-read could not be performed: %s"
                        % (target, error))
    attestation = (sigscan.RERUN_CONFIRMED if reproduced
                   else sigscan.RERUN_NOT_CONFIRMED)
    for read in literals:
        read["reproduced"] = reproduced
        read["evidence"]["sources"][0]["note"] = (
            "oracle binary-analysis. Read by %s, read-only. %s"
            % (GENERATOR_NAME, attestation))
        read["evidence"]["note"] = "%s %s" % (read["evidence"]["note"], attestation)
    return reproduced


def signature_annotation(target: str, boundary_corroborated: bool) -> dict:
    """The class-I annotation for the interpretive layer.

    The first method is the boundary decode: ``.pdata`` plus the published x64
    unwind ABI say where the function begins and ends. The second, when it is
    available, is the independent identification of the address -- an RTTI vtable
    slot, from a different oracle path and a different tool -- which is what
    licenses 0.85 instead of 0.79. Re-reading the same table twice would not be
    a second method (plan.md 10.3).
    """
    sources = [{
        "method": "S-06",
        "artifact": None,
        "locator": target,
        "note": ("oracle binary-analysis + external-doc. Function extent from the "
                 "PE exception directory decoded against the published Microsoft "
                 "x64 unwind ABI (RUNTIME_FUNCTION, UNWIND_INFO, "
                 "UNW_FLAG_CHAININFO), mask positions from the published PE base "
                 "relocation format."),
    }]
    oracles = ["binary-analysis", "external-doc"]
    if boundary_corroborated:
        sources.append({
            "method": "S-10",
            "artifact": None,
            "locator": target,
            "independent_of": ["S-06/boundary-decode"],
            "note": ("oracle binary-analysis. Second, independent method: the "
                     "address was reached as a virtual function table slot target "
                     "through the MSVC RTTI graph, which is a different structure, "
                     "a different directory of the image and a different tool from "
                     "the exception directory used for the extent."),
        })
    return {
        "evidence_level": "INFERRED",
        "claim_class": "I",
        "confidence": (CONFIDENCE_INTERPRETED_CORROBORATED if boundary_corroborated
                       else CONFIDENCE_INTERPRETED_SINGLE_METHOD),
        "oracle": sorted(oracles),
        "sources": sources,
        "read_locus": None,
        "note": (
            "Interpretive: this layer says a byte range IS a function, that a "
            "masked position is one a rebuild would move, and that the emitted "
            "pattern will re-find the same function in a future build. The first "
            "rests on a published ABI (external-doc -- it proves how the Microsoft "
            "toolchain describes functions, not what this build contains); the "
            "second is exact for relocations and explicitly UNSOLVED for "
            "non-relocated displacements; the third is untested here, because this "
            "repository has only one build of this game. The primitive half -- the "
            "bytes at the offsets -- is in literal_reads[]."
        ),
    }


# --------------------------------------------------------------------------- #
# refutation probes
# --------------------------------------------------------------------------- #

def build_refutation_probes(path: str, surface: dict, relocs: RelocationTable,
                            boundaries: BoundaryTable, signatures: list[dict],
                            *, chunk_size: int) -> list[dict]:
    """Checks whose PURPOSE is to break this tool's own headline claims."""
    probes: list[dict] = []
    accepted = [s for s in signatures if s["accepted"]]

    # Probe 1: the claim under most pressure. "Signatures are masked against
    # relocations" is only meaningful if relocations touch code at all.
    in_exec = relocs.census["entries_in_executable_sections"]
    probes.append({
        "id": "reloc-oracle-covers-code",
        "question": ("does the exact masking oracle -- the base relocation table -- "
                     "cover any byte of any executable section in this image?"),
        "would_refute": ("a NON-zero count refutes the finding below and would mean "
                         "relocation masking really does protect code signatures in "
                         "this image"),
        "entries_in_executable_sections": in_exec,
        "entries_total": relocs.census["entry_count"],
        "entries_per_section": relocs.census["entries_per_section"],
        "refuted": in_exec > 0,
        "finding": (
            "the relocation oracle is exact and EMPTY over code (%d of %d entries "
            "fall in an executable section), so no code signature in this document "
            "is made build-stable by relocation masking; the build-varying bytes in "
            "code are the non-relocated displacements, which Phase 1 cannot locate"
            % (in_exec, relocs.census["entry_count"])),
        "note": ("%d of %d relocation entries are in an executable section"
                 % (in_exec, relocs.census["entry_count"])),
    })

    # Probe 2: the boundary oracle is a lower bound, and here is by how much.
    total = boundaries.census["runtime_function_count"]
    chunks = boundaries.census["records_with_chaininfo"]
    refused_boundary = sum(1 for s in signatures
                           if any(r["code"] in ("boundary_unknown",
                                                "chunk_not_function_start")
                                  for r in s["rejections"]))
    probes.append({
        "id": "boundary-oracle-is-not-a-function-inventory",
        "question": ("how far is a RUNTIME_FUNCTION range from a compiler function "
                     "in this image, measured rather than asserted?"),
        "would_refute": ("zero chained records, full coverage of the executable "
                         "bytes and no requested address missing from the table "
                         "would mean the two notions coincide here and the caveat "
                         "is unnecessary"),
        "runtime_function_count": total,
        "records_with_chaininfo": chunks,
        "adjacent_ranges": boundaries.census["adjacent_ranges"],
        "max_records_per_unwind_info": boundaries.census["max_records_per_unwind_info"],
        "coverage_fraction_of_executable_bytes":
            boundaries.census["coverage_fraction_of_executable_bytes"],
        "requested_addresses_refused_on_boundary_grounds": refused_boundary,
        "refuted": bool(chunks == 0 and refused_boundary == 0),
        "note": ("%s of %s records are continuation chunks; %d requested addresses "
                 "were refused because the table could not place them"
                 % (_fmt_int(chunks), _fmt_int(total), refused_boundary)),
    })

    # Probe 3: the gate must be able to say no. Feed it something that is
    # obviously not a signature and check that it is refused. A gate that never
    # refuses anything is decoration, and this probe is what proves it is not.
    controls = []
    for length, values, mask, expect in (
        (32, bytes(32), bytes(32), "too_few_literal_bytes"),
        (32, b"\xcc" * 32, b"\x01" * 32, "low_variety"),
        (4, b"\x48\x89\x5c\x24", b"\x01" * 4, "too_short"),
    ):
        pattern = Pattern(values, mask, label="control")
        problems = justify(pattern, min_length=DEFAULT_MIN_LENGTH,
                           max_masked_fraction=MAX_MASKED_FRACTION,
                           min_literal_bytes=MIN_LITERAL_BYTES,
                           min_anchor_bytes=MIN_ANCHOR_BYTES,
                           min_distinct_values=MIN_DISTINCT_LITERAL_VALUES)
        codes = [item["code"] for item in problems]
        controls.append({"length": length, "expected_code": expect,
                         "codes": codes, "rejected": bool(problems),
                         "expected_code_present": expect in codes})
    probes.append({
        "id": "gate-refuses-a-non-signature",
        "question": ("does the justification gate reject an all-wildcard pattern, a "
                     "run of padding bytes and a four-byte fragment?"),
        "would_refute": ("any of the three being accepted would mean the gate does "
                         "not bind and every 'accepted' in this document is "
                         "meaningless"),
        "controls": controls,
        "refuted": not all(c["rejected"] and c["expected_code_present"]
                           for c in controls),
        "note": "%d of %d control patterns were rejected for the expected reason"
                % (sum(1 for c in controls
                       if c["rejected"] and c["expected_code_present"]),
                   len(controls)),
    })

    # Probe 4: the strongest available check that an accepted signature is
    # discriminating rather than lucky. Invert one literal byte; the pattern must
    # vanish from the image it was cut from.
    flipped: list[Pattern] = []
    labels: list[str] = []
    for record in accepted:
        pattern = sigscan.parse_pattern(record["pattern"], label=record["label"])
        index = next((i for i in range(pattern.length) if pattern.mask[i]), None)
        if index is None:
            continue
        values = bytearray(pattern.values)
        values[index] ^= 0xFF
        flipped.append(Pattern(bytes(values), pattern.mask, label=record["label"]))
        labels.append(record["label"])
    probe = {
        "id": "one-byte-flip-control",
        "question": ("with one literal byte inverted, does every accepted signature "
                     "disappear from the source image?"),
        "would_refute": ("a flipped pattern that still matches would mean the "
                         "pattern is not identifying the bytes it claims to"),
        "patterns_flipped": len(flipped),
        "refuted": None,
    }
    if flipped:
        got = sigscan.scan_surface(path, surface, flipped, hit_limit=2, count_cap=8,
                                   chunk_size=chunk_size)
        survivors = [{"label": labels[i], "occurrences": c.count}
                     for i, c in enumerate(got) if c.count]
        probe["survivors"] = survivors
        probe["refuted"] = bool(survivors)
        probe["note"] = ("%d of %d flipped patterns still matched the source image"
                         % (len(survivors), len(flipped)))
    else:
        probe["note"] = "no accepted signature had a literal byte to flip"
    probes.append(probe)

    # Probe 5: the denominator, so an acceptance count cannot be quoted alone.
    probes.append({
        "id": "acceptance-population",
        "question": "how many requested addresses produced a usable signature?",
        "would_refute": ("nothing on its own; this probe exists so the headline "
                         "count cannot be quoted without its denominator"),
        "requested": len(signatures),
        "accepted": len(accepted),
        "rejected": len(signatures) - len(accepted),
        "rejection_codes": _rejection_histogram(signatures),
        "refuted": False,
        "note": "%d of %d requested addresses produced an accepted signature"
                % (len(accepted), len(signatures)),
    })
    return probes


def _rejection_histogram(signatures: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for record in signatures:
        for rejection in record["rejections"]:
            counts[rejection["code"]] = counts.get(rejection["code"], 0) + 1
    return dict(sorted(counts.items()))


# --------------------------------------------------------------------------- #
# the run
# --------------------------------------------------------------------------- #

def _is_d04_oracle(path: str) -> bool:
    normalised = os.path.abspath(path).replace("\\", "/").lower()
    return normalised.endswith("/binaries/win64/misery.exe")


def _file_digest(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(sigscan.SCAN_CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _ladder(range_length: int, min_length: int, max_length: int) -> list[int]:
    """The ascending list of lengths --mode grow will try."""
    limit = min(range_length, max_length)
    lengths = [value for value in LENGTH_LADDER if min_length <= value <= limit]
    if limit >= min_length and (not lengths or lengths[-1] != limit):
        lengths.append(limit)
    return sorted(set(lengths))


def analyze(path: str, targets: list[dict], *,
            mode: str = MODE_GROW,
            mask_mode: str = MASK_MODE_RELOC,
            min_length: int = DEFAULT_MIN_LENGTH,
            max_length: int = DEFAULT_MAX_LENGTH,
            max_masked_fraction: float = MAX_MASKED_FRACTION,
            min_literal_bytes: int = MIN_LITERAL_BYTES,
            min_anchor_bytes: int = MIN_ANCHOR_BYTES,
            min_distinct_values: int = MIN_DISTINCT_LITERAL_VALUES,
            want_chain_scan: bool = True,
            want_chunk_index: bool = False,
            want_probes: bool = True,
            want_file_digest: bool = True,
            literal_samples: int = DEFAULT_LITERAL_SAMPLES,
            chunk_size: int = sigscan.SCAN_CHUNK,
            install_root: str | None = None,
            extra_warnings: list[str] | None = None) -> dict:
    """Cut a signature for every target and assemble the document."""
    started = time.monotonic()
    warnings: list[str] = list(extra_warnings or [])
    timings: dict[str, float] = {}

    image = pe_info.Image.open(path)
    try:
        headers = pe_info.PEHeaders(image)
        warnings.extend(headers.warnings)

        mark = time.monotonic()
        boundaries = BoundaryTable(headers, warnings, want_chain_scan=want_chain_scan)
        timings["boundary_table"] = round(time.monotonic() - mark, 3)
        mark = time.monotonic()
        relocs = RelocationTable(headers, warnings)
        timings["relocation_table"] = round(time.monotonic() - mark, 3)

        surface = sigscan.build_surface(headers, sigscan.SURFACE_EXEC, None,
                                       image.size, warnings)
        wide_surface = sigscan.build_surface(headers, sigscan.SURFACE_INITIALIZED,
                                            None, image.size, [])

        # --- stage 1: place every target, read its bytes, gate every rung --- #
        gate = {
            "max_masked_fraction": max_masked_fraction,
            "min_literal_bytes": min_literal_bytes,
            "min_anchor_bytes": min_anchor_bytes,
            "min_distinct_values": min_distinct_values,
        }
        candidates: list[dict] = []
        for target in targets:
            candidates.append(_place(target, headers, boundaries, relocs, image,
                                     mask_mode=mask_mode, mode=mode,
                                     min_length=min_length, max_length=max_length,
                                     gate=gate, want_chunk_index=want_chunk_index,
                                     warnings=warnings))

        # --- stage 2: uniqueness, by the same matcher sigscan will use ------ #
        mark = time.monotonic()
        _resolve_uniqueness(path, surface, candidates, mode=mode,
                            chunk_size=chunk_size)
        timings["uniqueness_passes"] = round(time.monotonic() - mark, 3)

        # A second count over every initialised section, so that "unique in
        # code" is not later confused with "unique in the file". A byte sequence
        # that also sits in .rdata is still a usable code signature -- but only
        # for a scanner that searches code, and the number belongs on the record.
        mark = time.monotonic()
        accepted_patterns = [p for p in (chosen_pattern(c) for c in candidates
                                         if not c["rejections"]) if p is not None]
        if accepted_patterns:
            wide = sigscan.scan_surface(path, wide_surface, accepted_patterns,
                                        hit_limit=4, count_cap=64,
                                        chunk_size=chunk_size)
            for collector in wide:
                for candidate in candidates:
                    if candidate["label"] == collector.pattern.label:
                        candidate["occurrences_initialized_surface"] = collector.count
                        candidate["occurrences_initialized_truncated"] = (
                            collector.truncated)
        timings["initialized_surface_pass"] = round(time.monotonic() - mark, 3)

        digest = _file_digest(path) if want_file_digest else None
        target_name = sigscan.locus_target(path, install_root)

        signatures = [_public(candidate) for candidate in candidates]
        signatures.sort(key=lambda item: (item["source_rva"], item["label"]))

        probes: list[dict] = []
        if want_probes:
            mark = time.monotonic()
            probes = build_refutation_probes(path, surface, relocs, boundaries,
                                             signatures, chunk_size=chunk_size)
            timings["refutation_probes"] = round(time.monotonic() - mark, 3)

        literals: list[dict] = []
        sampled = _spread([s for s in signatures
                           if s["accepted"] and s["source_file_offset"] is not None],
                          literal_samples)
        for record in sampled:
            raw = image.read_clamped(record["source_file_offset"], record["length"])
            if len(raw) != record["length"]:
                warnings.append("the covered range of %s could not be read back in "
                                "full" % record["label"])
                continue
            literals.append(literal_read(target_name, record["label"],
                                         record["source_file_offset"], raw))
        literals.sort(key=lambda item: (item["offset"], item["length"]))
        if literals:
            confirm_literal_reads(path, literals, target_name, warnings)

        accepted = [s for s in signatures if s["accepted"]]
        fractions = sorted(s["masked_fraction"] for s in accepted)
        summary = {
            "targets_requested": len(targets),
            "signatures_accepted": len(accepted),
            "signatures_rejected": len(signatures) - len(accepted),
            "rejection_codes": _rejection_histogram(signatures),
            "accepted_unique_in_code": sum(
                1 for s in accepted if s["self_scan"]["verdict"]
                == sigscan.VERDICT_UNIQUE),
            "accepted_also_unique_over_initialized_sections": sum(
                1 for s in accepted
                if s.get("occurrences_initialized_surface") == 1),
            "accepted_appearing_more_than_once_over_initialized_sections": sum(
                1 for s in accepted
                if (s.get("occurrences_initialized_surface") or 0) > 1),
            "length_min": min((s["length"] for s in accepted), default=None),
            "length_max": max((s["length"] for s in accepted), default=None),
            "masked_fraction_min": fractions[0] if fractions else None,
            "masked_fraction_max": fractions[-1] if fractions else None,
            "masked_fraction_mean": (round(sum(fractions) / len(fractions), 6)
                                     if fractions else None),
            "masked_fraction_histogram": _fraction_histogram(fractions),
            "accepted_with_zero_masked_bytes": sum(1 for s in accepted
                                                   if s["masked_bytes"] == 0),
            "accepted_with_rel32_candidates": sum(
                1 for s in accepted if s["fragility"]["rel32_candidates"] > 0),
            "boundary_targets_without_a_record": sum(
                1 for s in signatures
                if any(r["code"] == "boundary_unknown" for r in s["rejections"])),
            "boundary_targets_that_are_chunks": sum(
                1 for s in signatures
                if any(r["code"] == "chunk_not_function_start"
                       for r in s["rejections"])),
        }
        timings["total"] = round(time.monotonic() - started, 3)

        corroborated = any(t.get("identified_by") for t in targets)
        return {
            "task": "S-06",
            "generator": GENERATOR_NAME,
            "generator_version": GENERATOR_VERSION,
            "generated_at": pe_info.now_iso_utc(),
            "d04_oracle_only": _is_d04_oracle(path),
            "source_image": {
                "name": os.path.basename(os.path.abspath(path)),
                "path": os.path.abspath(path),
                "install_relative": target_name,
                "size": image.size,
                "sha256": digest,
                "pe_format": headers.pe_format,
                "machine": headers.machine,
                "image_base": headers.image_base,
                "size_of_image": headers.size_of_image,
                "timestamp": headers.timestamp,
            },
            "mode": {
                "length_mode": mode,
                "length_ladder": list(LENGTH_LADDER),
                "definition": {
                    MODE_GROW: ("the shortest length on the ladder that is unique on "
                                "the searched surface; shorter is preferred because "
                                "every extra byte is another chance to include a "
                                "build-varying immediate"),
                    MODE_WHOLE: ("the whole RUNTIME_FUNCTION range, capped at "
                                 "max_length"),
                }[mode],
            },
            "mask_policy": _mask_policy(mask_mode, relocs),
            "thresholds": {
                "min_length": min_length,
                "max_length": max_length,
                "hard_max_length": HARD_MAX_LENGTH,
                "min_literal_bytes": min_literal_bytes,
                "max_masked_fraction": max_masked_fraction,
                "min_anchor_bytes": min_anchor_bytes,
                "min_distinct_literal_values": min_distinct_values,
                "note": ("published with the results so a reviewer can disagree with "
                         "a threshold instead of with a verdict"),
            },
            "rejection_vocabulary": dict(sorted(REJECTIONS.items())),
            "boundary_oracle": {
                "source": ("IMAGE_DIRECTORY_ENTRY_EXCEPTION (.pdata), decoded "
                           "against the published Microsoft x64 unwind ABI"),
                "caveat": ("a RUNTIME_FUNCTION range is NOT a compiler function; see "
                           "census.discrepancies_named, every clause of which is "
                           "counted on this image"),
                "census": boundaries.census,
            },
            "relocation_oracle": relocs.census,
            "surface": surface,
            "initialized_surface": {
                "kind": wide_surface["kind"],
                "bytes_searched": wide_surface["bytes_searched"],
                "range_count": wide_surface["range_count"],
                "why": ("accepted signatures are counted here as well, so that "
                        "'unique in code' can never be quoted as 'unique in the "
                        "file'"),
            },
            "signatures": signatures,
            "summary": summary,
            "refutation_probes": probes,
            "literal_reads": literals,
            "interpreted_annotation": signature_annotation(target_name, corroborated),
            "timings_seconds": timings,
            "warnings": sorted(set(warnings)),
        }
    finally:
        image.close()


def _mask_policy(mask_mode: str, relocs: RelocationTable) -> dict:
    return {
        "mask_mode": mask_mode,
        "exact_component": {
            # NOT spelled "oracle": tools/kb/validate.py treats any object
            # carrying an "oracle" key as a graded evidence record (its
            # MARKER_KEYS), and this object is descriptive prose with no grade
            # on it. Naming it "source" -- as boundary_oracle already does --
            # keeps the validator's record detector from inventing a record
            # here and then correctly complaining that it has no
            # evidence_level. The graded records of this document are
            # literal_reads[] and interpreted_annotation, and nothing else.
            "source": "the PE base relocation table (.reloc)",
            "what_it_proves": ("every position the loader patches when the image is "
                              "not at its preferred base; an enumeration, so no "
                              "false positives and no guessing"),
            "entries_total": relocs.census["entry_count"],
            "entries_in_executable_sections":
                relocs.census["entries_in_executable_sections"],
            "consequence_for_code": relocs.census[
                "what_zero_in_executable_sections_means"],
        },
        "unsolved_component": {
            "what": ("RIP-relative displacements and rel32 call/jump targets -- the "
                     "bytes a rebuild actually moves in x86-64 code"),
            "why_not_masked": ("they are position-independent within the image, so "
                               "the loader never patches them and the relocation "
                               "table never lists them; locating them requires "
                               "knowing where each instruction begins, which requires "
                               "an instruction decoder, which Phase 1 does not have"),
            "chosen_side": ("conservative: mask nothing that cannot be proven. The "
                            "cost is a signature that comes back ABSENT on a rebuilt "
                            "image, which sends the operator back to re-locate the "
                            "function. The alternative -- masking on a guess -- buys "
                            "a match that may be the wrong function, which is the "
                            "failure this tool pair exists to prevent"),
            "sized_by": ("fragility.rel32_candidates and "
                         "fragility.disp32_windows_resolving_into_image on every "
                         "signature; both are upper bounds obtained without decoding"),
            "opt_in_heuristic": ("--mask-mode reloc+rel32 masks the four bytes after "
                                 "an E8/E9 byte whose target resolves into the image. "
                                 "A GUESS, stamped on every record it touches so the "
                                 "two populations cannot be silently mixed"),
        },
    }


def _fraction_histogram(fractions: list[float]) -> dict:
    """Masked-byte fraction distribution in fixed decile buckets."""
    buckets = {"0.00": 0, "0.00-0.05": 0, "0.05-0.10": 0, "0.10-0.20": 0,
               "0.20-0.30": 0, "0.30+": 0}
    for value in fractions:
        if value == 0:
            buckets["0.00"] += 1
        elif value < 0.05:
            buckets["0.00-0.05"] += 1
        elif value < 0.10:
            buckets["0.05-0.10"] += 1
        elif value < 0.20:
            buckets["0.10-0.20"] += 1
        elif value <= 0.30:
            buckets["0.20-0.30"] += 1
        else:
            buckets["0.30+"] += 1
    return buckets


def _place(target: dict, headers, boundaries: BoundaryTable,
           relocs: RelocationTable, image, *, mask_mode: str, mode: str,
           min_length: int, max_length: int, gate: dict, want_chunk_index: bool,
           warnings: list[str]) -> dict:
    """Resolve one requested address to a byte range, a mask and a candidate ladder.

    Everything that can refuse the target refuses it here, before any pattern is
    built, so a rejected candidate carries no pattern to be quoted out of
    context.
    """
    rva = target["rva"]
    label = target.get("label") or ("rva_0x%x" % rva)
    candidate: dict = {
        "label": label,
        "source_rva": rva,
        "source_file_offset": None,
        "section": None,
        "origin": target.get("origin"),
        "identified_by": target.get("identified_by"),
        "rejections": [],
        "boundary": None,
        "chunks": None,
        "range_length": None,
        "trailing_padding_trimmed": 0,
        "mask_breakdown": None,
        "fragility": None,
        "lengths_tried": [],
        "lengths_refused_by_the_geometry_gate": [],
        "self_scan": None,
        "occurrences_initialized_surface": None,
        "occurrences_initialized_truncated": None,
        "range_fragility": None,
        "_pattern_objects": [],
        "_mask_breakdowns": [],
        "_fragilities": [],
    }

    def reject(code: str, measured=None, threshold=None) -> dict:
        candidate["rejections"].append({"code": code, "reason": REJECTIONS[code],
                                        "measured": measured,
                                        "threshold": threshold})
        return candidate

    index = boundaries.index_of_begin(rva)
    if index is None:
        containing = boundaries.index_containing(rva)
        detail = None
        if containing is not None:
            detail = {
                "nearest_enclosing_range": boundaries.record(containing),
                "offset_into_that_range": rva - boundaries.begins[containing],
                "note": ("the address lies INSIDE another range: it is either a "
                         "branch target within a function or a leaf function that "
                         "the enclosing record's compiler folded; either way the "
                         "exception directory does not describe it as an entry "
                         "point"),
            }
        else:
            detail = {"nearest_enclosing_range": None,
                      "note": ("no range contains the address either, which is what "
                               "a leaf function needing no unwind data looks like")}
        candidate["boundary"] = detail
        return reject("boundary_unknown", "no record begins at 0x%x" % rva,
                      "an exact BeginAddress match")

    record = boundaries.record(index)
    candidate["boundary"] = record
    if record["is_chunk"]:
        return reject("chunk_not_function_start", record["unwind_flags_decoded"],
                      "a record without UNW_FLAG_CHAININFO")
    if want_chunk_index and boundaries.chain_primary is not None:
        candidate["chunks"] = boundaries.chunks_of(rva)

    length = max(0, record["end_address"] - record["begin_address"])
    candidate["range_length"] = length
    offset = headers.rva_to_offset(rva)
    if offset is None or headers.rva_available(rva) < min(length, min_length):
        return reject("range_not_on_disk",
                      "RVA 0x%x maps to %s, %d bytes available"
                      % (rva, offset, headers.rva_available(rva)),
                      "at least %d readable bytes" % min_length)
    candidate["source_file_offset"] = offset

    section = next((s for s in headers.sections
                    if s["rsize"] and s["rva"] <= rva
                    < s["rva"] + max(s["vsize"], s["rsize"])), None)
    if section is None or not (section["characteristics"]
                              & (sigscan.IMAGE_SCN_MEM_EXECUTE
                                 | sigscan.IMAGE_SCN_CNT_CODE)):
        return reject("range_not_executable",
                      (section["name"] if section else "outside every section"),
                      "a section with IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_CNT_CODE")
    candidate["section"] = section["name"]

    want = min(length, max(max_length, min_length), headers.rva_available(rva))
    body = image.read_clamped(offset, want)
    body, trimmed = trim_padding(body)
    candidate["trailing_padding_trimmed"] = trimmed
    if len(body) < min_length:
        return reject("too_short", len(body), min_length)

    # Fragility of the WHOLE usable range, published as range_fragility. The
    # per-signature fragility is the one for the length actually emitted and is
    # computed per rung below: a 12-byte prefix and a 96-byte pattern do not
    # contain the same number of displacement candidates, and quoting the
    # range's number next to a 12-byte pattern would overstate its fragility.
    window = fragility(body, rva, headers.size_of_image)
    candidate["range_fragility"] = window
    reloc_positions = relocs.covered_positions(rva, len(body))
    rel32_offsets = window["rel32_candidate_offsets"]

    lengths = (_ladder(len(body), min_length, max_length) if mode == MODE_GROW
               else [len(body)])
    candidate["lengths_tried"] = lengths

    # The geometry gate is applied PER RUNG, not once to the longest one. The
    # masked fraction, the anchor length and the byte variety of a 12-byte prefix
    # are not those of a 96-byte one, and grading the ladder by its top rung
    # would either admit a rung that fails the thresholds or refuse one that
    # passes them. Rungs that fail are dropped, with their reasons kept.
    refused: list[dict] = []
    for take in lengths:
        mask, breakdown = build_mask(take, [p for p in reloc_positions if p < take],
                                     [p for p in rel32_offsets if p + 4 < take],
                                     mask_mode)
        pattern = Pattern(body[:take], mask, label=label)
        problems = justify(pattern, min_length=min_length,
                          max_masked_fraction=gate["max_masked_fraction"],
                          min_literal_bytes=gate["min_literal_bytes"],
                          min_anchor_bytes=gate["min_anchor_bytes"],
                          min_distinct_values=gate["min_distinct_values"])
        if problems:
            refused.append({"length": take,
                            "codes": [item["code"] for item in problems],
                            "problems": problems})
            continue
        candidate["_pattern_objects"].append(pattern)
        candidate["_mask_breakdowns"].append(breakdown)
        candidate["_fragilities"].append(
            fragility(body[:take], rva, headers.size_of_image))
    candidate["lengths_refused_by_the_geometry_gate"] = [
        {"length": row["length"], "codes": row["codes"]} for row in refused]
    if not candidate["_pattern_objects"]:
        if refused:
            # Report the diagnosis of the longest rung tried: it had the most
            # bytes to work with, so its complaints are the ones a caller could
            # not fix by asking for more length.
            candidate["rejections"].extend(refused[-1]["problems"])
        else:
            reject("too_short", len(body), min_length)
        return candidate
    return candidate


def _resolve_uniqueness(path: str, surface: dict, candidates: list[dict], *,
                        mode: str, chunk_size: int) -> None:
    """Count every candidate on the source image, growing the ambiguous ones.

    One pass per rung of the ladder, with every still-unresolved candidate in the
    same pass -- the matcher takes a list of patterns, so N candidates cost one
    traversal of the surface and not N. A candidate is resolved when its count is
    exactly 1 (accepted), when the ladder runs out (rejected ``not_unique``), or
    when the count is 0 (rejected ``absent_in_source``, which is a bug report
    about this tool).
    """
    live = [c for c in candidates if not c["rejections"] and c["_pattern_objects"]]
    rung = 0
    passes = 0
    while live:
        batch = [c for c in live if rung < len(c["_pattern_objects"])]
        if not batch:
            break
        patterns = [c["_pattern_objects"][rung] for c in batch]
        collectors = sigscan.scan_surface(path, surface, patterns, hit_limit=8,
                                         count_cap=256, chunk_size=chunk_size)
        passes += 1
        still: list[dict] = []
        for candidate, collector in zip(batch, collectors):
            verdict = sigscan.verdict_of(collector)
            pattern = collector.pattern
            candidate["self_scan"] = {
                "verdict": verdict,
                "occurrences": collector.count,
                "occurrences_truncated": collector.truncated,
                "hit_file_offsets": list(collector.offsets),
                "hit_rvas": [_offset_to_rva(surface, o) for o in collector.offsets],
                "length": pattern.length,
                "ladder_rung": rung,
                "passes_used": passes,
                "surface_bytes": surface["bytes_searched"],
            }
            # The emitted pattern is always the rung that was actually verified,
            # never the longest one that was built.
            candidate["_chosen_rung"] = rung
            if verdict == sigscan.VERDICT_UNIQUE:
                continue
            if verdict == sigscan.VERDICT_ABSENT:
                candidate["rejections"].append({
                    "code": "absent_in_source",
                    "reason": REJECTIONS["absent_in_source"],
                    "measured": 0, "threshold": 1})
                continue
            if rung + 1 < len(candidate["_pattern_objects"]) and mode == MODE_GROW:
                still.append(candidate)
                continue
            candidate["rejections"].append({
                "code": "not_unique",
                "reason": REJECTIONS["not_unique"],
                "measured": ("%d+" % collector.count if collector.truncated
                             else collector.count),
                "threshold": 1})
        live = still
        rung += 1


def _offset_to_rva(surface: dict, offset: int) -> int | None:
    for entry in surface["ranges"]:
        if entry["rva"] is None:
            continue
        if entry["file_offset"] <= offset < entry["file_offset"] + entry["length"]:
            return entry["rva"] + (offset - entry["file_offset"])
    return None


def chosen_index(candidate: dict) -> int | None:
    """Which rung of ``_pattern_objects`` this candidate's verdict is about.

    ``_resolve_uniqueness`` stamps ``_chosen_rung`` with the rung it actually
    counted, and that rung -- not the longest one that was built -- is the
    pattern this tool may publish. Emitting the longest would contradict
    ``--mode grow``'s whole reason to exist (shorter is safer: every extra byte
    is another chance to include a build-varying immediate) and would attach a
    ``self_scan`` whose ``length`` disagreed with the pattern beside it.

    The fallback to the last rung exists only for a candidate that never reached
    the uniqueness stage -- a rejected one, whose pattern is published for review
    and never used.
    """
    patterns = candidate["_pattern_objects"]
    if not patterns:
        return None
    index = candidate.get("_chosen_rung")
    if index is None or not 0 <= index < len(patterns):
        return len(patterns) - 1
    return index


def chosen_pattern(candidate: dict) -> Pattern | None:
    index = chosen_index(candidate)
    return None if index is None else candidate["_pattern_objects"][index]


def _public(candidate: dict) -> dict:
    """One signature record, with every internal working field dropped.

    A rejected candidate keeps its pattern: a reviewer checking that a rejection
    was right needs the bytes, ``sigscan --include-rejected`` scans them on
    request, and ``accepted: false`` is what keeps them out of everything else.

    The parallel per-rung lists are dropped rather than published. Publishing
    them would put the bytes of every rung of the ladder in the artifact, which
    is a copy of the function body by instalments and exactly what the C-13
    ``--max-length`` cap exists to prevent.
    """
    index = chosen_index(candidate)
    patterns = candidate.pop("_pattern_objects")
    breakdowns = candidate.pop("_mask_breakdowns")
    fragilities = candidate.pop("_fragilities")
    candidate.pop("_chosen_rung", None)
    record = dict(candidate)
    record["accepted"] = not candidate["rejections"]
    if index is not None:
        record["emitted_ladder_index"] = index
        record.update(patterns[index].facts())
        record["mask_breakdown"] = breakdowns[index]
        record["fragility"] = fragilities[index]
    else:
        record["emitted_ladder_index"] = None
        record.update({"pattern": None, "length": 0, "literal_bytes": 0,
                       "masked_bytes": 0, "masked_fraction": None,
                       "anchor_offset": 0, "anchor_length": 0, "anchor_hex": None,
                       "distinct_literal_values": 0,
                       "sha256_of_pattern_text": None})
    record["rejections"] = sorted(candidate["rejections"],
                                  key=lambda item: item["code"])
    return record


def _spread(items: list, count: int) -> list:
    if count <= 0 or not items:
        return []
    if len(items) <= count:
        return list(items)
    step = (len(items) - 1) / (count - 1) if count > 1 else 1
    picked = []
    seen = set()
    for index in range(count):
        position = min(int(round(index * step)), len(items) - 1)
        if position not in seen:
            seen.add(position)
            picked.append(items[position])
    return picked


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def jsonl_lines(document: dict) -> list[str]:
    """One flat JSON object per signature -- the joinable artifact of S-06."""
    lines = []
    for record in document["signatures"]:
        lines.append(json.dumps({
            "build_target": document["source_image"]["install_relative"],
            "build_sha256": document["source_image"]["sha256"],
            "label": record["label"],
            "accepted": record["accepted"],
            "rejection_codes": [r["code"] for r in record["rejections"]],
            "source_rva": record["source_rva"],
            "source_file_offset": record["source_file_offset"],
            "range_length": record["range_length"],
            "pattern": record["pattern"],
            "length": record["length"],
            "masked_bytes": record["masked_bytes"],
            "masked_fraction": record["masked_fraction"],
            "mask_mode": document["mask_policy"]["mask_mode"],
            "self_scan_verdict": (record["self_scan"] or {}).get("verdict"),
            "self_scan_occurrences": (record["self_scan"] or {}).get("occurrences"),
            "occurrences_initialized_surface":
                record["occurrences_initialized_surface"],
            "rel32_candidates": ((record["fragility"] or {})
                                 .get("rel32_candidates")),
        }, sort_keys=True, ensure_ascii=False))
    return lines


def library_document(document: dict) -> dict:
    """The portable subset: accepted signatures plus the provenance sigscan needs."""
    return {
        "task": "S-06",
        "generator": document["generator"],
        "generator_version": document["generator_version"],
        "generated_at": document["generated_at"],
        "source_image": document["source_image"],
        "mask_policy": {"mask_mode": document["mask_policy"]["mask_mode"]},
        "signatures": [
            {"label": record["label"], "pattern": record["pattern"],
             "accepted": True, "source_rva": record["source_rva"],
             "source_file_offset": record["source_file_offset"],
             "length": record["length"], "masked_bytes": record["masked_bytes"],
             "masked_fraction": record["masked_fraction"]}
            for record in document["signatures"] if record["accepted"]
        ],
    }


def safe_filename(label: str) -> str:
    """A filename for a label, deterministic and collision-resistant.

    Template names run to two hundred characters and contain ``<``, ``>``, ``*``
    and ``:``, none of which a Windows filename may hold, so the readable part is
    sanitised and truncated and a digest of the FULL label is appended. Without
    the digest two different templates would truncate to the same name and one
    would overwrite the other.
    """
    keep = []
    for char in label:
        keep.append(char if (char.isalnum() or char in "._-") else "_")
    stem = "".join(keep).strip("_")[:80] or "signature"
    digest = hashlib.sha256(label.encode("utf-8")).hexdigest()[:8]
    return "%s.%s.json" % (stem, digest)


def write_text(text: str, out_path: str, install_root: str, what: str) -> str:
    target = pathguard.check_output_path(out_path, install_root, what=what)
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return target


def format_summary(document: dict, limit: int = 40) -> str:
    """The human summary. Every number printed here is a field of the document."""
    lines: list[str] = []
    image = document["source_image"]
    summary = document["summary"]
    census = document["boundary_oracle"]["census"]
    reloc = document["relocation_oracle"]
    lines.append("sigmake %s (%s)" % (GENERATOR_VERSION, document["task"]))
    lines.append("image:    %s" % image["install_relative"])
    lines.append("          %s bytes, %s, sha256 %s"
                 % (_fmt_int(image["size"]), image["pe_format"],
                    (image["sha256"] or "not computed")[:32]))
    if document["d04_oracle_only"]:
        lines.append("          D-04 read-only oracle: a conclusion reached here "
                     "must be re-verified on the Shipping image")
    lines.append("")
    lines.append("boundary oracle (.pdata, and what it is NOT):")
    lines.append("          %s RUNTIME_FUNCTION records, %s distinct BeginAddress"
                 % (_fmt_int(census["runtime_function_count"]),
                    _fmt_int(census["distinct_begin_addresses"])))
    lines.append("          %s carry UNW_FLAG_CHAININFO -> continuation chunks, "
                 "NOT function starts" % _fmt_int(census["records_with_chaininfo"]))
    lines.append("          %s primaries own at least one chunk; %s adjacent pairs "
                 "End[i]==Begin[i+1]"
                 % (_fmt_int(census["primaries_with_at_least_one_chunk"]),
                    _fmt_int(census["adjacent_ranges"])))
    lines.append("          %s distinct UnwindInfoAddress; one is shared by up to %s "
                 "records" % (_fmt_int(census["distinct_unwind_info_addresses"]),
                              _fmt_int(census["max_records_per_unwind_info"])))
    lines.append("          ranges cover %s of %s executable bytes on disk (%s) -- "
                 "the rest is functions with no record at all"
                 % (_fmt_int(census["bytes_covered_by_ranges"]),
                    _fmt_int(census["executable_bytes_on_disk"]),
                    ("%.3f" % census["coverage_fraction_of_executable_bytes"])
                    if census["coverage_fraction_of_executable_bytes"] is not None
                    else "-"))
    lines.append("")
    lines.append("mask policy: %s" % document["mask_policy"]["mask_mode"])
    lines.append("          .reloc: %s entries, %s of them in an executable section"
                 % (_fmt_int(reloc["entry_count"]),
                    _fmt_int(reloc["entries_in_executable_sections"])))
    lines.append("          per section: %s"
                 % ", ".join("%s %s" % (name, _fmt_int(count))
                             for name, count in reloc["entries_per_section"].items()))
    lines.append("          NOT masked: RIP-relative displacements and rel32 "
                 "targets (no instruction decoder in Phase 1)")
    lines.append("")
    lines.append("surface:  %s bytes over %d range(s) -- %s"
                 % (_fmt_int(document["surface"]["bytes_searched"]),
                    document["surface"]["range_count"],
                    document["surface"]["kind"]))
    lines.append("")
    lines.append("accepted %d of %d requested (%d rejected)"
                 % (summary["signatures_accepted"], summary["targets_requested"],
                    summary["signatures_rejected"]))
    if summary["rejection_codes"]:
        for code, count in summary["rejection_codes"].items():
            lines.append("          %-28s %d" % (code, count))
    if summary["masked_fraction_mean"] is not None:
        lines.append("          length %d..%d; masked fraction min %.3f mean %.3f "
                     "max %.3f"
                     % (summary["length_min"], summary["length_max"],
                        summary["masked_fraction_min"],
                        summary["masked_fraction_mean"],
                        summary["masked_fraction_max"]))
        lines.append("          masked-fraction histogram: %s"
                     % ", ".join("%s:%d" % (k, v) for k, v
                                 in summary["masked_fraction_histogram"].items()))
        lines.append("          %d accepted signatures have ZERO masked bytes"
                     % summary["accepted_with_zero_masked_bytes"])
    lines.append("          also unique over every initialised section: %d; "
                 "appearing more than once there: %d"
                 % (summary["accepted_also_unique_over_initialized_sections"],
                    summary["accepted_appearing_more_than_once_over_initialized_sections"]))
    lines.append("")
    lines.append("%-3s %-11s %5s %5s %5s %5s %-6s %s"
                 % ("ok", "rva", "range", "len", "mask", "rel32", "occ", "label"))
    for record in document["signatures"][:limit]:
        self_scan = record["self_scan"] or {}
        lines.append("%-3s 0x%-9x %5s %5s %5s %5s %-6s %s"
                     % ("yes" if record["accepted"] else "NO",
                        record["source_rva"],
                        _fmt_int(record["range_length"]),
                        record["length"] or "-",
                        record["masked_bytes"] if record["pattern"] else "-",
                        ((record["fragility"] or {}).get("rel32_candidates")
                         if record["fragility"] else "-"),
                        self_scan.get("occurrences", "-"),
                        _shorten(record["label"], 58)))
        if not record["accepted"]:
            lines.append("      -> %s" % ", ".join(r["code"]
                                                   for r in record["rejections"]))
    if len(document["signatures"]) > limit:
        lines.append("... %d more (see the artifact)"
                     % (len(document["signatures"]) - limit))
    lines.append("")
    lines.append("refutation probes:")
    for probe in document["refutation_probes"]:
        state = ("REFUTED" if probe.get("refuted") else
                 "not refuted" if probe.get("refuted") is False else "not run")
        lines.append("  [%s] %s" % (state, probe["id"]))
        lines.append("      %s" % probe.get("note", ""))
        if probe.get("finding"):
            lines.append("      finding: %s" % probe["finding"])
    if document["literal_reads"]:
        lines.append("")
        lines.append("class-P literal reads: %d, %s"
                     % (len(document["literal_reads"]),
                        "reproduced" if all(r.get("reproduced")
                                            for r in document["literal_reads"])
                        else "NOT all reproduced"))
    if document["warnings"]:
        lines.append("")
        lines.append("warnings:")
        for warning in document["warnings"]:
            lines.append("  - %s" % warning)
    return "\n".join(lines)


def _shorten(text: str, width: int) -> str:
    if text is None:
        return "-"
    return text if len(text) <= width else text[:width - 3] + "..."


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigmake.py",
        description=(
            "Generate byte-pattern signatures for functions in a PE image, with a "
            "mask over the positions a relocation proves unstable (plan.md task "
            "S-06). Read-only. Refuses to emit a signature it cannot justify and "
            "says why. Refuses any output path inside a game installation (D-01)."),
    )
    parser.add_argument("path", help="the PE image to read (opened read-only)")
    parser.add_argument("--rva", action="append", default=None, metavar="ADDR[=LABEL]",
                        help="a function RVA, e.g. 0xf4d8e0 or 0xf4d8e0=MyFunc; "
                             "repeatable")
    parser.add_argument("--from-rtti", default=None, metavar="JSON",
                        help=("take targets from a tools/static/rtti_scan.py "
                              "document: every distinct vtable slot target becomes "
                              "one target whose identity is established by S-10"))
    parser.add_argument("--rtti-bucket", default=None, metavar="A,B",
                        help=("restrict --from-rtti to these attribution buckets, "
                              "e.g. unreal-engine"))
    parser.add_argument("--mode", choices=MODES, default=MODE_GROW,
                        help=("grow: the shortest unique length on the ladder "
                              "(default); whole: the whole range up to --max-length"))
    parser.add_argument("--mask-mode", choices=MASK_MODES, default=MASK_MODE_RELOC,
                        help=("reloc: mask only proven relocations (default); "
                              "reloc+rel32: also mask suspected rel32 targets -- a "
                              "HEURISTIC, stamped on every record"))
    parser.add_argument("--min-length", type=int, default=DEFAULT_MIN_LENGTH,
                        metavar="N", help="shortest acceptable pattern")
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH,
                        metavar="N",
                        help=("longest pattern to emit; also the C-13 publication "
                              "cap (hard ceiling %d)" % HARD_MAX_LENGTH))
    parser.add_argument("--max-masked-fraction", type=float,
                        default=MAX_MASKED_FRACTION, metavar="F",
                        help="reject a pattern with more holes than this")
    parser.add_argument("--min-literal-bytes", type=int, default=MIN_LITERAL_BYTES,
                        metavar="N", help="reject a pattern comparing fewer bytes")
    parser.add_argument("--min-anchor-bytes", type=int, default=MIN_ANCHOR_BYTES,
                        metavar="N",
                        help="reject a pattern whose longest literal run is shorter")
    parser.add_argument("--min-distinct-values", type=int,
                        default=MIN_DISTINCT_LITERAL_VALUES, metavar="N",
                        help="reject a pattern with fewer distinct literal values")
    parser.add_argument("--no-chain-scan", action="store_true",
                        help=("skip reading the unwind flags. Faster, and it makes "
                              "the tool unable to tell a function start from a "
                              "continuation chunk -- so every such refusal is lost"))
    parser.add_argument("--chunk-index", action="store_true",
                        help=("for each accepted target, list the continuation "
                              "chunks that chain to it (one linear pass each)"))
    parser.add_argument("--no-probes", action="store_true",
                        help="skip the refutation probes")
    parser.add_argument("--no-digest", action="store_true",
                        help="skip the whole-file sha256")
    parser.add_argument("--literal-samples", type=int,
                        default=DEFAULT_LITERAL_SAMPLES, metavar="N",
                        help="how many covered ranges to record as class-P reads")
    parser.add_argument("--json", action="store_true",
                        help="print the JSON document instead of the summary")
    parser.add_argument("--jsonl", action="store_true",
                        help="print the per-signature JSONL artifact to stdout")
    parser.add_argument("--out", default=None, help="write the JSON document here")
    parser.add_argument("--jsonl-out", default=None,
                        help="write the per-signature JSONL artifact here")
    parser.add_argument("--library-out", default=None,
                        help=("write the portable accepted-only library here (what "
                              "sigscan consumes on a later build)"))
    parser.add_argument("--split-out", default=None, metavar="DIR",
                        help=("also write one file per accepted signature into DIR "
                              "-- plan.md 7.3 signatures/<name>.json"))
    parser.add_argument("--install-dir", default=None,
                        help="installation root the output guard checks against")
    parser.add_argument("--limit", type=int, default=40, metavar="N",
                        help="signatures printed in the human summary")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not os.path.isfile(args.path):
        print("error: not a file: %s" % args.path, file=sys.stderr)
        return 2
    if not args.rva and not args.from_rtti:
        print("error: nothing to make a signature for: pass --rva or --from-rtti",
              file=sys.stderr)
        return 2
    if args.min_length < 1:
        print("error: --min-length must be at least 1", file=sys.stderr)
        return 2
    if args.max_length < args.min_length:
        print("error: --max-length (%d) is below --min-length (%d)"
              % (args.max_length, args.min_length), file=sys.stderr)
        return 2
    if args.max_length > HARD_MAX_LENGTH:
        print("error: --max-length %d exceeds the hard ceiling of %d bytes. The "
              "ceiling is a C-13 publication limit, not a technical one: a "
              "signature is a fingerprint, and a longer one starts being a copy of "
              "the function body" % (args.max_length, HARD_MAX_LENGTH),
              file=sys.stderr)
        return 2
    if not 0.0 <= args.max_masked_fraction <= 1.0:
        print("error: --max-masked-fraction must be between 0 and 1",
              file=sys.stderr)
        return 2
    for name, value in (("--min-literal-bytes", args.min_literal_bytes),
                        ("--min-anchor-bytes", args.min_anchor_bytes),
                        ("--min-distinct-values", args.min_distinct_values),
                        ("--literal-samples", args.literal_samples)):
        if value < 0:
            print("error: %s must not be negative" % name, file=sys.stderr)
            return 2

    install_root = args.install_dir or pe_info.detect_install_root(args.path)

    checked: dict[str, str] = {}
    for flag, value in (("--out", args.out), ("--jsonl-out", args.jsonl_out),
                        ("--library-out", args.library_out),
                        ("--split-out", args.split_out)):
        if not value:
            continue
        try:
            checked[flag] = pathguard.check_output_path(value, install_root,
                                                        what=flag)
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2

    warnings: list[str] = []
    targets: list[dict] = []
    digest = None if args.no_digest else _file_digest(args.path)
    if args.from_rtti:
        try:
            targets.extend(targets_from_rtti(
                args.from_rtti, digest,
                tuple(part.strip() for part in args.rtti_bucket.split(","))
                if args.rtti_bucket else None,
                warnings))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print("error: --from-rtti %s: %s" % (args.from_rtti, error),
                  file=sys.stderr)
            return 2
    for text in args.rva or []:
        try:
            rva, label = parse_rva_argument(text)
        except ValueError as error:
            print("error: --rva %s: %s" % (text, error), file=sys.stderr)
            return 2
        targets.append({"rva": rva, "label": label, "origin": "--rva",
                        "identified_by": None})
    if not targets:
        print("error: no targets (--from-rtti matched nothing; check --rtti-bucket)",
              file=sys.stderr)
        return 2
    # A duplicate label would make two records join to the same verdict later.
    seen: dict[str, int] = {}
    deduped: list[dict] = []
    for target in targets:
        label = target.get("label") or ("rva_0x%x" % target["rva"])
        seen[label] = seen.get(label, 0) + 1
        if seen[label] > 1:
            label = "%s#%d" % (label, seen[label])
            warnings.append("duplicate label %r; the later target was renamed to %r"
                            % (target.get("label"), label))
        target = dict(target)
        target["label"] = label
        deduped.append(target)
    targets = deduped

    try:
        document = analyze(
            args.path, targets,
            mode=args.mode,
            mask_mode=args.mask_mode,
            min_length=args.min_length,
            max_length=args.max_length,
            max_masked_fraction=args.max_masked_fraction,
            min_literal_bytes=args.min_literal_bytes,
            min_anchor_bytes=args.min_anchor_bytes,
            min_distinct_values=args.min_distinct_values,
            want_chain_scan=not args.no_chain_scan,
            want_chunk_index=args.chunk_index,
            want_probes=not args.no_probes,
            want_file_digest=not args.no_digest,
            literal_samples=args.literal_samples,
            install_root=args.install_dir,
            extra_warnings=warnings,
        )
    except PEFormatError as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2
    except OSError as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2

    if args.no_digest:
        document["source_image"]["sha256"] = None
    else:
        document["source_image"]["sha256"] = digest

    written: list[str] = []
    try:
        if "--out" in checked:
            written.append(write_text(dump_json(document), checked["--out"],
                                      install_root, "--out"))
        if "--jsonl-out" in checked:
            body = "".join(line + "\n" for line in jsonl_lines(document))
            written.append(write_text(body, checked["--jsonl-out"], install_root,
                                      "--jsonl-out"))
        if "--library-out" in checked:
            written.append(write_text(dump_json(library_document(document)),
                                      checked["--library-out"], install_root,
                                      "--library-out"))
        if "--split-out" in checked:
            base = library_document(document)
            for record in base["signatures"]:
                one = dict(base)
                one["signatures"] = [record]
                path = os.path.join(checked["--split-out"],
                                    safe_filename(record["label"]))
                written.append(write_text(dump_json(one), path, install_root,
                                          "--split-out"))
    except pathguard.OutputPathRefused as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except OSError as error:
        print("error: cannot write: %s" % error, file=sys.stderr)
        return 2

    if args.json:
        sys.stdout.write(dump_json(document))
    elif args.jsonl:
        for line in jsonl_lines(document):
            sys.stdout.write(line + "\n")
    else:
        print(format_summary(document, limit=args.limit))
        for path in written[:8]:
            print("\nwritten: %s" % path)
        if len(written) > 8:
            print("... and %d more files" % (len(written) - 8))
    return 0


if __name__ == "__main__":
    sys.exit(main())
