#!/usr/bin/env python3
"""Read-only vtable census for a PE image (plan.md task S-09).

The question this tool exists to answer
---------------------------------------
plan.md 7.3 row S-09 asks for the vtable inventory of the shipped image: the
candidates in the read-only data sections, found by looking for runs of pointers
into executable sections, emitted as ``vtables.jsonl``. S-10 already answered
the neighbouring question and answered it narrowly: MSVC RTTI is present but
names 580 classes out of a polymorphic population its own side-measurement puts
near 7 400, and **zero** of those 580 are game classes. So if the game's own
classes are anywhere in this image, they are in the vtables that carry no RTTI
name, and this tool is the only instrument that can see them.

This is deliberately a SECOND, INDEPENDENT implementation of a measurement the
project already relies on. ``tools/static/rtti_scan.py`` performs a bounded
vtable census internally (``vtable_census``, three thresholds, published as
``runs_by_minimum_length``) and the whole S-10 coverage ratio rests on it. That
number had exactly one implementation and no control. This file was written
without reusing its logic -- different segmentation, different data structures,
a different definition of a run boundary -- specifically so that the two can be
made to disagree. Where they overlap they must agree exactly; ``--rtti-json``
performs that comparison mechanically and puts the result in the artifact rather
than in a paragraph. See ``cross_check`` in the output.

WHAT A VTABLE CANDIDATE IS HERE
-------------------------------
Stated as a rule, because the whole value of the number depends on the rule and
not on the count:

1. The **surface** is every section that has raw bytes on disk, is not marked
   executable, and is not one of ``.pdata`` / ``.reloc`` / ``.rsrc`` (three
   tables whose contents are known not to be object data). The surface is
   printed, not assumed: a count is only meaningful next to the range it was
   taken over.
2. A **slot** is a pointer-sized, pointer-aligned little-endian value in the
   surface. Alignment is taken from the section start, and the section start's
   own alignment is checked and reported -- a section whose RVA is not a
   multiple of the pointer size would silently shift every slot.
3. A slot is **code-addressing** when its value lies in
   ``[image_base, image_base + size_of_image)`` and the RVA it implies falls
   inside a section marked executable.
4. A slot is **relocated** when its own RVA appears in the base-relocation
   table as a pointer-width fixup (``IMAGE_REL_BASED_DIR64`` on PE32+,
   ``HIGHLOW`` on PE32). This is the single cheapest and strongest filter in
   the file and it comes from a different table than everything else: in an
   image with a relocation table, a datum that is genuinely an absolute code
   address MUST have a fixup, so a code-addressing slot with no fixup is not a
   pointer at all -- it is an integer that happens to look like one. On this
   build that filter removes 21 slots, and every one of them is visibly a
   constant rather than an address (``0x140a00000``, ``0x141200000``, and one
   0x142656e67 whose low bytes spell ASCII).
5. A **raw run** is a maximal sequence of consecutive slots that are both
   code-addressing and relocated.
6. A **cut point** is any address in the surface that some instruction takes the
   address of (see the code-reference pass below). A raw run is split at every
   interior cut point, and each resulting piece is a **candidate**. This step is
   what separates this tool from a run-length census: two vtables emitted
   back to back with no padding are ONE run and TWO candidates, and on this
   build 17 441 interior cut points fall inside runs.
7. Each candidate is put in one of three **tiers**, and the tier -- not the
   count -- is what a downstream reader should filter on:

   ``code-stored``
       the candidate's first address is loaded by a RIP-relative ``lea`` whose
       result is immediately stored through a pointer into memory. That is the
       shape of ``lea rax, [vtable]; mov [rcx], rax`` -- a constructor writing a
       vtable pointer into an object -- and it is the strongest positive signal
       available without a disassembler.
   ``code-referenced``
       the first address is the target of a RIP-relative ``lea``, but no
       adjacent store was recognised. A jump-table base, a function-pointer
       array being indexed, and a vtable whose store the pattern matcher missed
       all land here.
   ``unreferenced``
       nothing in the executable sections takes the address of this candidate's
       first slot. Almost all of these are single slots: individual callback
       fields, not tables.

WHERE THIS RULE ERRS, MEASURED RATHER THAN CONCEDED
---------------------------------------------------
A run of pointers into executable code is also the shape of several things that
are not vtables, and the honest treatment is to name each one and say what
actually happens to it:

* **MSVC x64 switch jump tables** are NOT a false-positive source in this file
  and the reason is structural: the Microsoft x64 compiler emits switch tables
  as arrays of 32-bit image-relative offsets, not of absolute 64-bit pointers,
  so they are neither pointer-width nor relocated and step 4 and step 2 both
  reject them. (external-doc: the MSVC codegen convention. What is *observed*
  here is the consequence -- see ``refutation_probes``.)
* **The import address table** holds, on disk, RVAs of hint/name records in
  read-only data, not code addresses, so ordinary IAT entries fail step 3. The
  **delay-load** IAT is different: on disk it points at the delay-load thunks,
  which ARE code. Those ranges are computed from the import directories and
  reported as ``known_pointer_tables``, and every candidate that overlaps one is
  flagged in its own row -- flagged, not deleted, because deleting evidence
  because of a prediction is how a scanner starts agreeing with itself.
* **The TLS callback array** is a genuine run of code pointers and is flagged
  the same way, from the TLS directory.
* **Static tables of function pointers** -- CRT initialiser lists, dispatch
  tables, generated parser tables -- are real vtable look-alikes and no
  structural rule in this file separates them from a vtable. This is the tool's
  main residual error and it is quantified two ways rather than argued about:
  by the tier split above, and by a control run on a binary whose class layout
  can be checked against its own RTTI (``research/evidence/S-09/`` records
  MSVCP140.dll, the same positive control S-10 used).
* **A vtable this tool cannot see at all**: one whose entries the loader has to
  patch differently, one in a section with no raw bytes, one below the alignment
  assumption, and -- the real one -- a vtable in an image with the relocation
  table stripped, where step 4 would reject everything. The tool checks for a
  stripped relocation table and says so instead of returning a silent zero.
* **Recall is measured, not assumed.** On this build, all 587 vtables that S-10
  reached through RTTI are recovered here as candidates with byte-identical slot
  counts; 545 of them (0.928) fall in ``code-stored`` and 586 (0.998) in
  ``code-stored`` + ``code-referenced``. The one that is in neither is a vtable
  whose address no ``lea`` in the image takes -- which is exactly the shape of
  the miss this rule has, made concrete.

WHAT THE POPULATION LOOKS LIKE
------------------------------
The characterisation questions S-09 has to answer about the RTTI-less majority
are answered from measurements this tool takes, and each answer is a field:

* size distribution -- ``statistics.slot_count_histogram`` and percentiles, per
  tier, because "how long is a vtable" has a different answer per tier and a
  single histogram would hide that;
* whether slot targets are shared between candidates --
  ``statistics.shared_slot_targets``: a target used by more than one candidate
  is an inherited or thunked implementation, and the sharing rate is a direct
  measure of how much of the population is related by inheritance;
* whether candidates sit in contiguous runs -- ``statistics.clusters``: a chain
  of candidates that are exactly back to back with no padding is one linker
  contribution, which is one object file. The premise behind reading anything
  into that is itself testable and this tool tests it: with ``--rtti-json``,
  ``cross_check.owner_adjacency`` measures how often two ADJACENT vtables with
  known owners have the SAME owner, against the chance level computed from the
  owner frequencies. On this build that is 0.949 against a chance level of
  0.360, so vtable order in this image is strongly grouped by origin and
  position carries real information;
* whether any of them relate to the Unreal build-machine source-path literals --
  ``source_path_literals`` finds those literals in the surface, and every
  candidate row carries the nearest one and the DISTANCE to it. The distance is
  the point. Two independent measurements on this build say the relation is
  weak, and they are reported as such: the same-function join (a literal and a
  vtable referenced from one ``.pdata`` function) connects 3 of 587, and the
  RTTI-bearing vtables occupy a 5.1 MB span that the literals barely enter.

Two output layers, never merged (plan.md 10.3)
----------------------------------------------
As in ``tools/fingerprint/container_info.py`` and ``tools/static/rtti_scan.py``:

``literal_reads``
    Class **P**. One record per read: an install-relative target, a file offset,
    a length, the raw bytes, and a claim sentence that states the offset and the
    length and names nothing about what the bytes are. Every range is read a
    second time through a second, independently opened handle before the record
    is allowed to say it reproduced.

``candidates`` / ``statistics`` / ``summary`` / ``cross_check``
    Class **I**. These say that a range of bytes IS a vtable, which is an
    inference from a layout convention plus a heuristic instruction decode. The
    grading says so and is capped accordingly.

Safety (plan.md 1.5, decisions D-01 and D-04)
---------------------------------------------
* The target is opened ``"rb"`` and only ever read.
* ``--out`` and ``--jsonl-out`` go through ``tools/inventory/pathguard`` BEFORE
  any file is opened. The guard is imported, never reimplemented.
* D-04: ``MISERY/Binaries/Win64/MISERY.exe`` is stamped ``d04_oracle_only`` when
  it is the target, because a conclusion reached there must be re-verified on
  ``MISERY-Win64-Shipping.exe`` before it counts.

Memory and time (plan.md F-04)
------------------------------
Nothing is read whole. The surface's slot values are held once as a packed
``array`` -- 29 MB for this image, not 29 MB of Python objects -- and every
other per-address fact is a bitmap over the surface, one bit per byte or per
slot. The executable sections are streamed through one reused window. Every
count taken from the file is clamped before it becomes a loop bound. The full
run over the 134 MB target takes about 25 seconds.

Determinism
-----------
Sorted keys, indent 2, LF, UTF-8 without BOM, trailing newline. Candidates are
emitted in ascending RVA order. Two runs over an unchanged file differ only in
``generated_at`` and in ``timings_seconds``.

Standard library only.

CLI
---
    python tools/static/vtable_scan.py <image.exe>
    python tools/static/vtable_scan.py <image.exe> --json
    python tools/static/vtable_scan.py <image.exe> \\
        --rtti-json research/evidence/S-10/shipping-rtti.json \\
        --out workspace/vtables/x.json --jsonl-out workspace/vtables/vtables.jsonl

Exit codes: 0 the scan completed (whatever it found), 2 usage / I/O error /
unparseable input. Finding nothing is a successful run.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import struct
import sys
import time
from array import array
from collections import Counter, defaultdict
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
for _extra in (os.path.join(_TOOLS, "inventory"), os.path.join(_TOOLS, "fingerprint")):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never
# reimplemented.
import pathguard  # noqa: E402

# The PE layer is F-01's. Headers, section table and RVA translation come from
# there so that this tool cannot hold a second, differently-buggy opinion about
# where .rdata is. Everything above the section table -- relocations, the
# runtime-function table, the slot surface -- is this file's own work.
import pe_info  # noqa: E402

GENERATOR_NAME = "tools/static/vtable_scan.py"
GENERATOR_VERSION = "1.1.0"

PEFormatError = pe_info.PEFormatError


# --------------------------------------------------------------------------- #
# hard limits. Every one of these bounds a number that is READ FROM THE FILE
# and must therefore never be believed.
# --------------------------------------------------------------------------- #

READ_CHUNK = 4 << 20             # streaming window; a multiple of 8 and of 12
MAX_SURFACE_SLOTS = 1 << 25      # 33 554 432 slots = 256 MB of surface
MAX_RELOC_BLOCKS = 1 << 20
MAX_RUNTIME_FUNCTIONS = 1 << 23
MAX_CANDIDATES = 1 << 21
MAX_SEGMENT_CUTS = 1 << 16       # interior cut points inside ONE run
MAX_REFERENCE_SITES = 8          # code sites recorded per candidate
MAX_LITERAL_BYTES = 320          # longest source-path literal followed
MAX_SOURCE_PATH_LITERALS = 1 << 16
DEFAULT_LITERAL_SAMPLES = 6
DEFAULT_SAMPLE_ROWS = 12
HISTOGRAM_CAP = 64               # slot counts above this share one bucket

# Confidence ceiling is 0.99 (plan.md 10.2); 1.00 is forbidden anywhere.
CONFIDENCE_LITERAL = 0.99
CONFIDENCE_INTERPRETED_TWO_METHODS = 0.85
CONFIDENCE_INTERPRETED_ONE_METHOD = 0.79

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_FILE_RELOCS_STRIPPED = 0x0001

# Base-relocation types (external-doc: the PE/COFF specification).
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10

# Sections excluded from the default surface by NAME rather than by
# characteristics. All three are tables whose contents are known not to be
# object data, and all three are marked read-only initialised data, so
# characteristics alone would not exclude them.
DEFAULT_SKIP_SECTIONS = (".pdata", ".reloc", ".rsrc")

# The thresholds rtti_scan.py's internal census publishes. Reproduced here on
# purpose: they are the comparison surface between the two implementations.
CENSUS_THRESHOLDS = (4, 8, 16)

TIER_STORED = "code-stored"
TIER_REFERENCED = "code-referenced"
TIER_UNREFERENCED = "unreferenced"
TIER_ORDER = (TIER_STORED, TIER_REFERENCED, TIER_UNREFERENCED)

# The Unreal build-machine source-path literal. Anchored on the '++UE5' sync
# root rather than on 'Engine' so it cannot match a runtime content path, and
# tolerant of both separators because the image carries both.
SOURCE_PATH_RE = re.compile(
    rb"[A-Za-z]:[\\/]build[\\/]\+\+UE5[\\/]Sync[\\/][ -~]{1,%d}?\x00"
    % MAX_LITERAL_BYTES)
SOURCE_PATH_PREFIX_RE = re.compile(r"^[A-Za-z]:[\\/]build[\\/]\+\+UE5[\\/]Sync[\\/]")

# A RIP-relative lea with a 64-bit operand size: REX.W (with any of B/X/R set)
# followed by opcode 0x8D and a ModRM whose mod=00 and r/m=101. The two-byte
# prefix is the scan pattern; the ModRM test rejects the rest.
LEA_PREFIX_RE = re.compile(rb"[\x48\x49\x4c\x4d]\x8d")
LEA_LENGTH = 7                   # REX + opcode + ModRM + disp32
STORE_WINDOW = 12                # bytes after the lea searched for the store

# plan.md 10.3 class-P criterion 2 is MANDATORY for the whole 0.80-0.99 band and
# tools/kb/validate.py checks that the record SAYS the method was re-run. A
# record may only say it if it is true, so every literal read really is
# performed twice -- see confirm_literal_reads.
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


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hex_bytes(raw: bytes) -> str:
    return raw.hex()


def dump_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def percentiles(values: list[int], points=(50, 90, 99)) -> dict:
    """Percentiles by nearest rank -- no interpolation, no float in the answer.

    Interpolating between two slot counts would produce a vtable length that no
    vtable has, which is precisely the kind of number that later gets quoted.
    """
    if not values:
        return {str(p): None for p in points}
    ordered = sorted(values)
    out = {}
    for point in points:
        index = min(len(ordered) - 1, max(0, int(round(point / 100.0 * len(ordered))) - 1))
        out[str(point)] = ordered[index]
    return out


def histogram(values, cap: int = HISTOGRAM_CAP) -> dict:
    """A slot-count histogram whose tail is one labelled bucket, not a long tail."""
    counter: Counter = Counter()
    for value in values:
        counter[value if value <= cap else -1] += 1
    out = {}
    for key in sorted(k for k in counter if k >= 0):
        out[str(key)] = counter[key]
    if counter.get(-1):
        out["gt_%d" % cap] = counter[-1]
    return out


def _spread(items: list, count: int) -> list:
    """A deterministic, evenly spaced sample -- never just the first N.

    The first N candidates all come from the same region of one section, which
    is a sample of one linker contribution rather than of the image.
    """
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


class Bitmap:
    """One bit per unit over a half-open range, addressed by absolute unit index.

    Deliberately not a set. The surfaces here have millions of addressable units
    and a Python set of ints would cost two orders of magnitude more memory than
    the whole rest of the run.
    """

    __slots__ = ("size", "bits")

    def __init__(self, size: int) -> None:
        self.size = max(0, size)
        self.bits = bytearray(self.size // 8 + 1)

    def set(self, index: int) -> None:
        if 0 <= index < self.size:
            self.bits[index >> 3] |= 1 << (index & 7)

    def get(self, index: int) -> bool:
        if 0 <= index < self.size:
            return bool(self.bits[index >> 3] >> (index & 7) & 1)
        return False

    def count(self) -> int:
        total = 0
        for byte in self.bits:
            total += bin(byte).count("1")
        return total


# --------------------------------------------------------------------------- #
# address model
# --------------------------------------------------------------------------- #

class AddressModel:
    """RVA -> section, and the executable-range predicate, over sorted ranges.

    ``pe_info`` answers RVA -> file offset. What the scan needs on every single
    slot is "is this RVA inside a section marked executable", tens of millions
    of times, so the ranges are flattened into two sorted arrays and answered by
    bisect. That is a different implementation from the linear walk in
    ``rtti_scan.SectionMap`` on purpose: if both tools shared the predicate they
    would share its bugs, and agreement between them would prove nothing.
    """

    def __init__(self, headers) -> None:
        self.headers = headers
        self.pointer_size = headers.pointer_size
        self.image_base = headers.image_base
        self.image_limit = headers.image_base + max(headers.size_of_image, 0)
        self.sections = [s for s in headers.sections if s["rsize"] > 0]
        executable = sorted(
            (s["rva"], s["rva"] + max(s["vsize"], s["rsize"]))
            for s in headers.sections
            if s["characteristics"] & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)
        )
        # Merge touching ranges so the bisect answer is unambiguous.
        merged: list[list[int]] = []
        for start, end in executable:
            if merged and start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        self.exec_starts = [r[0] for r in merged]
        self.exec_ends = [r[1] for r in merged]
        self.exec_names = [s["name"] for s in headers.sections
                           if s["characteristics"] & (IMAGE_SCN_MEM_EXECUTE
                                                      | IMAGE_SCN_CNT_CODE)]

    def is_executable_rva(self, rva: int) -> bool:
        index = bisect.bisect_right(self.exec_starts, rva) - 1
        return index >= 0 and rva < self.exec_ends[index]

    def section_of_rva(self, rva: int) -> dict | None:
        for section in self.sections:
            span = max(section["vsize"], section["rsize"])
            if span and section["rva"] <= rva < section["rva"] + span:
                return section
        return None


def select_surface(headers, names: tuple[str, ...] | None,
                   skip: tuple[str, ...]) -> tuple[list[dict], list[str]]:
    """The sections the slot scan will actually read, and the ones it will not.

    Returned rather than assumed so that the document can PRINT the surface.
    When *names* is given it wins outright, including over the executable test:
    scanning ``.text`` on purpose is how a reader checks that this tool's null
    results are null over a named range rather than over a convenient one.
    """
    kept: list[dict] = []
    dropped: list[str] = []
    for section in headers.sections:
        if section["rsize"] <= 0:
            dropped.append(section["name"])
            continue
        if names is not None:
            (kept if section["name"] in names else dropped).append(
                section if section["name"] in names else section["name"])
            continue
        if section["name"] in skip:
            dropped.append(section["name"])
            continue
        if section["characteristics"] & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE):
            dropped.append(section["name"])
            continue
        kept.append(section)
    return kept, sorted(set(dropped))


def describe_sections(sections: list[dict]) -> list[dict]:
    return [{
        "name": section["name"],
        "rva": section["rva"],
        "file_offset": section["raw_pointer"],
        "raw_size": section["rsize"],
        "virtual_size": section["vsize"],
        "characteristics": "0x%08x" % section["characteristics"],
    } for section in sections]


# --------------------------------------------------------------------------- #
# the slot surface
# --------------------------------------------------------------------------- #

class Surface:
    """The pointer-aligned slots of the scanned sections, held once, packed.

    ``values[name]`` is the raw slot values of one section as a packed array,
    which for the 29 MB surface of the shipping image is 29 MB of memory rather
    than the 300 MB a list of Python ints would cost. Everything else about a
    slot -- relocated, code-addressing -- is a bitmap over the same index space.
    Byte-granular facts (an instruction takes the address of something that is
    not slot-aligned, such as a string literal) get their own byte-indexed
    bitmaps.
    """

    def __init__(self, sections: list[dict], pointer_size: int) -> None:
        self.pointer_size = pointer_size
        self.sections = sections
        self.slot_counts = {}
        self.values: dict[str, array] = {}
        self.byte_sizes = {}
        for section in sections:
            usable = section["rsize"] - section["rsize"] % pointer_size
            self.slot_counts[section["name"]] = usable // pointer_size
            self.byte_sizes[section["name"]] = section["rsize"]
        self.total_slots = sum(self.slot_counts.values())

    # -- loading ------------------------------------------------------------ #

    def load(self, image, warnings: list[str]) -> None:
        code = "Q" if self.pointer_size == 8 else "I"
        for section in self.sections:
            name = section["name"]
            values = array(code)
            total = self.slot_counts[name] * self.pointer_size
            position = 0
            step = READ_CHUNK - READ_CHUNK % self.pointer_size
            while position < total:
                want = min(step, total - position)
                block = image.read_at(section["raw_pointer"] + position, want,
                                      "surface %s" % name)
                if len(block) != want:
                    warnings.append(
                        "%s: only %d of %d bytes were readable at file offset %d; "
                        "the surface is truncated there"
                        % (name, len(block), want,
                           section["raw_pointer"] + position))
                    block = block[:len(block) - len(block) % self.pointer_size]
                chunk = array(code)
                chunk.frombytes(block)
                values.extend(chunk)
                position += want
            if sys.byteorder != "little":       # pragma: no cover
                values.byteswap()
            self.values[name] = values
            if len(values) != self.slot_counts[name]:
                self.slot_counts[name] = len(values)
        self.total_slots = sum(self.slot_counts.values())

    # -- addressing --------------------------------------------------------- #

    def locate(self, rva: int) -> tuple[dict, int] | None:
        """The section holding *rva* and the byte offset within its raw data."""
        for section in self.sections:
            offset = rva - section["rva"]
            if 0 <= offset < self.byte_sizes[section["name"]]:
                return section, offset
        return None

    def slot_at(self, rva: int) -> int | None:
        """The slot value at *rva*, or None when *rva* is off-surface or unaligned."""
        found = self.locate(rva)
        if found is None:
            return None
        section, offset = found
        if offset % self.pointer_size:
            return None
        index = offset // self.pointer_size
        if index >= self.slot_counts[section["name"]]:
            return None
        return self.values[section["name"]][index]

    def new_slot_bitmaps(self) -> dict[str, Bitmap]:
        return {s["name"]: Bitmap(self.slot_counts[s["name"]]) for s in self.sections}

    def new_byte_bitmaps(self) -> dict[str, Bitmap]:
        return {s["name"]: Bitmap(self.byte_sizes[s["name"]]) for s in self.sections}

    def mark_byte(self, bitmaps: dict[str, Bitmap], rva: int) -> bool:
        found = self.locate(rva)
        if found is None:
            return False
        section, offset = found
        bitmaps[section["name"]].set(offset)
        return True

    def get_byte(self, bitmaps: dict[str, Bitmap], rva: int) -> bool:
        found = self.locate(rva)
        if found is None:
            return False
        section, offset = found
        return bitmaps[section["name"]].get(offset)


# --------------------------------------------------------------------------- #
# pass 1 -- the base-relocation table
# --------------------------------------------------------------------------- #

def parse_base_relocations(image, headers, surface: Surface,
                           warnings: list[str]) -> dict:
    """Mark every surface slot that carries a pointer-width relocation fixup.

    Why this pass exists at all: it is the only cheap way to tell a pointer from
    an integer that looks like one. The relocation table is written by the
    linker for the loader's benefit and lists every absolute address that has to
    be adjusted when the image is not loaded at its preferred base. A datum in
    the surface that is genuinely an absolute code address therefore MUST appear
    here, and a code-addressing value that does not appear here is not an
    address.

    The limit of the method is equally plain and is reported: an image whose
    relocation table was stripped gives this pass nothing, and then the filter
    has to be disabled (``--no-relocation-filter``) or every candidate would be
    rejected.
    """
    result = {
        "directory_rva": None, "directory_size": None,
        "relocations_stripped": bool(headers.characteristics
                                     & IMAGE_FILE_RELOCS_STRIPPED),
        "blocks": 0, "entries": 0, "by_type": {},
        "pointer_width_type": (IMAGE_REL_BASED_DIR64 if surface.pointer_size == 8
                              else IMAGE_REL_BASED_HIGHLOW),
        "pointer_width_entries": 0,
        "pointer_width_entries_in_surface": 0,
        "misaligned_in_surface": 0,
        "usable": False,
        "note": None,
    }
    bitmaps = surface.new_slot_bitmaps()
    rva, size = headers.directory(pe_info.DIR_BASERELOC)
    result["directory_rva"] = rva
    result["directory_size"] = size
    if not rva or not size:
        result["note"] = ("the base-relocation directory is absent, so no slot can "
                          "be confirmed to hold a relocated pointer")
        return {"summary": result, "bitmaps": bitmaps}

    available = headers.rva_available(rva)
    usable = min(size, available)
    if size > available:
        warnings.append(
            "the base-relocation directory declares %d bytes but only %d are on "
            "disk; the pass reads the readable part" % (size, available))
    by_type: Counter = Counter()
    offset = 0
    blocks = 0
    total_entries = 0
    pointer_entries = 0
    in_surface = 0
    misaligned = 0
    want_type = result["pointer_width_type"]
    while offset + 8 <= usable and blocks < MAX_RELOC_BLOCKS:
        header = headers.read_rva(rva + offset, 8, "relocation block header")
        page, block_size = struct.unpack("<II", header)
        if block_size < 8 or offset + block_size > usable:
            warnings.append(
                "relocation block %d at directory offset %d declares size %d, "
                "which does not fit the directory; the walk stops here"
                % (blocks, offset, block_size))
            break
        entries = (block_size - 8) // 2
        body = headers.read_rva(rva + offset + 8, entries * 2, "relocation entries")
        words = array("H")
        words.frombytes(body)
        if sys.byteorder != "little":           # pragma: no cover
            words.byteswap()
        for word in words:
            kind = word >> 12
            by_type[kind] += 1
            total_entries += 1
            if kind != want_type:
                continue
            pointer_entries += 1
            target = page + (word & 0xFFF)
            found = surface.locate(target)
            if found is None:
                continue
            section, byte_offset = found
            in_surface += 1
            if byte_offset % surface.pointer_size:
                misaligned += 1
                continue
            bitmaps[section["name"]].set(byte_offset // surface.pointer_size)
        offset += block_size
        blocks += 1
    if blocks >= MAX_RELOC_BLOCKS:
        warnings.append("the relocation walk stopped at the %d-block cap"
                        % MAX_RELOC_BLOCKS)
    result["blocks"] = blocks
    result["entries"] = total_entries
    result["by_type"] = {str(k): v for k, v in sorted(by_type.items())}
    result["pointer_width_entries"] = pointer_entries
    result["pointer_width_entries_in_surface"] = in_surface
    result["misaligned_in_surface"] = misaligned
    result["usable"] = pointer_entries > 0
    if not result["usable"]:
        result["note"] = ("the relocation table carries no pointer-width fixup, so "
                          "it cannot distinguish a pointer from an integer here")
    return {"summary": result, "bitmaps": bitmaps}


# --------------------------------------------------------------------------- #
# pass 2 -- the runtime-function table (.pdata)
# --------------------------------------------------------------------------- #

def parse_runtime_functions(headers, warnings: list[str]) -> dict:
    """Function starts and extents from the EXCEPTION directory.

    Two separate uses, and they must not be confused with each other:

    * a slot whose target equals a function START is pointing at the beginning of
      a function, which is what a vtable slot does and what a jump-table entry
      does not (a jump-table entry points at a label inside one);
    * a code address can be mapped BACK to the function containing it, which is
      what lets a reference site be named.

    The coverage limit is real and stated: on x64 a leaf function with no
    prologue needs no unwind data and may be absent from this table entirely, so
    "target is not a function start" is weak evidence and is never used to reject
    a candidate. On this build 0.539 of the slots of the RTTI-confirmed vtables
    hit a function start, which is the honest ceiling for this signal.
    """
    result = {"directory_rva": None, "directory_size": None, "entry_size": 12,
              "function_count": 0, "distinct_starts": 0, "note": None}
    starts = array("I")
    ends = array("I")
    rva, size = headers.directory(pe_info.DIR_EXCEPTION)
    result["directory_rva"] = rva
    result["directory_size"] = size
    if not rva or not size:
        result["note"] = "the EXCEPTION directory is absent; no function table"
        return {"summary": result, "starts": starts, "ends": ends}
    if headers.machine not in (0x8664, 0xAA64):
        result["note"] = ("entry size assumed to be 12 bytes (AMD64 layout); "
                          "machine is 0x%04x" % headers.machine)
    available = headers.rva_available(rva)
    usable = min(size, available)
    count = min(usable // 12, MAX_RUNTIME_FUNCTIONS)
    if size > available:
        warnings.append("the EXCEPTION directory declares %d bytes but only %d "
                        "are on disk" % (size, available))
    position = 0
    step = READ_CHUNK - READ_CHUNK % 12
    total = count * 12
    while position < total:
        want = min(step, total - position)
        block = headers.read_rva(rva + position, want, "runtime functions")
        words = array("I")
        words.frombytes(block[:len(block) - len(block) % 4])
        if sys.byteorder != "little":           # pragma: no cover
            words.byteswap()
        for index in range(0, len(words) - 2, 3):
            starts.append(words[index])
            ends.append(words[index + 1])
        position += want
    order = sorted(range(len(starts)), key=lambda i: starts[i])
    sorted_starts = array("I", (starts[i] for i in order))
    sorted_ends = array("I", (ends[i] for i in order))
    result["function_count"] = len(sorted_starts)
    result["distinct_starts"] = len(set(sorted_starts))
    return {"summary": result, "starts": sorted_starts, "ends": sorted_ends}


class FunctionIndex:
    """Answers "is this RVA a function start" and "which function contains it"."""

    def __init__(self, starts: array, ends: array) -> None:
        self.starts = starts
        self.ends = ends
        self.start_set = starts        # sorted; membership by bisect

    def is_start(self, rva: int) -> bool:
        index = bisect.bisect_left(self.starts, rva)
        return index < len(self.starts) and self.starts[index] == rva

    def containing(self, rva: int) -> int | None:
        index = bisect.bisect_right(self.starts, rva) - 1
        if index >= 0 and rva < self.ends[index]:
            return self.starts[index]
        return None


# --------------------------------------------------------------------------- #
# pass 3 -- what the code takes the address of
# --------------------------------------------------------------------------- #

def scan_code_references(image, headers, address: AddressModel, surface: Surface,
                         sections: list[dict], warnings: list[str]) -> dict:
    """Mark every surface address some ``lea`` in the executable sections forms.

    THIS IS A PATTERN MATCH, NOT A DISASSEMBLER, and the difference matters
    enough to state before the code: the scan finds every byte position that
    *looks like* ``REX.W 8D ModRM(mod=00,r/m=101) disp32`` and computes
    ``next_instruction + disp32``. It does not know where instructions begin, so
    a matching sequence can also be the tail of some other instruction's operand
    -- a false reference. Two properties keep that from mattering:

    * a false reference has to land exactly on a candidate's first address to
      change any conclusion, and the surface is 29 MB wide;
    * a reference is only ever used to PROMOTE a candidate or to SPLIT a run,
      never to reject anything, so a spurious reference costs precision on a
      tier and never costs recall.

    The store test is the second, narrower signal. ``lea reg, [X]`` followed
    within a few bytes by ``REX.W 89 /r`` with a memory destination and the same
    source register is the constructor idiom ``mov [this], vtable``. Recall for
    that pattern is measured against RTTI ground truth rather than assumed: 545
    of 587 on this build.
    """
    lea_bitmaps = surface.new_byte_bitmaps()
    store_bitmaps = surface.new_byte_bitmaps()
    stats = {"sections": [s["name"] for s in sections], "bytes_scanned": 0,
             "lea_shaped_sequences": 0, "lea_targets_in_surface": 0,
             "store_idiom_targets_in_surface": 0,
             "targets_outside_surface": 0}
    overlap = LEA_LENGTH + STORE_WINDOW + 4
    for section in sections:
        total = section["rsize"]
        position = 0
        tail = b""
        while position < total:
            want = min(READ_CHUNK, total - position)
            block = image.read_at(section["raw_pointer"] + position, want,
                                  "code reference scan")
            buffer = tail + block
            buffer_rva = section["rva"] + (position - len(tail))
            limit = len(buffer)
            for match in LEA_PREFIX_RE.finditer(buffer):
                index = match.start()
                if index + LEA_LENGTH > limit:
                    continue
                modrm = buffer[index + 2]
                if modrm & 0xC7 != 0x05:
                    continue
                stats["lea_shaped_sequences"] += 1
                displacement = struct.unpack_from("<i", buffer, index + 3)[0]
                target = buffer_rva + index + LEA_LENGTH + displacement
                if not surface.mark_byte(lea_bitmaps, target):
                    stats["targets_outside_surface"] += 1
                    continue
                stats["lea_targets_in_surface"] += 1
                register = ((modrm >> 3) & 7) | ((buffer[index] & 4) << 1)
                if _has_store(buffer, index + LEA_LENGTH, register, limit):
                    surface.mark_byte(store_bitmaps, target)
                    stats["store_idiom_targets_in_surface"] += 1
            position += want
            stats["bytes_scanned"] += want
            tail = buffer[-overlap:] if len(buffer) > overlap else b""
    stats["distinct_lea_targets_in_surface"] = sum(
        bitmap.count() for bitmap in lea_bitmaps.values())
    stats["distinct_store_targets_in_surface"] = sum(
        bitmap.count() for bitmap in store_bitmaps.values())
    return {"summary": stats, "lea": lea_bitmaps, "store": store_bitmaps}


def _has_store(buffer: bytes, position: int, register: int, limit: int) -> bool:
    """Is the instruction at *position* ``mov [mem], <register>`` (64-bit)?

    Only the instruction IMMEDIATELY after the lea is examined. Widening the
    window would raise recall a little and precision a lot less: the further the
    store is from the lea, the weaker the claim that the two belong together.
    """
    if position + 3 > limit:
        return False
    rex = buffer[position]
    if not 0x48 <= rex <= 0x4F or buffer[position + 1] != 0x89:
        return False
    modrm = buffer[position + 2]
    if (modrm >> 6) == 3:               # register destination: not a store
        return False
    source = ((modrm >> 3) & 7) | ((rex & 4) << 1)
    return source == register


def collect_reference_sites(image, address: AddressModel, sections: list[dict],
                            wanted: set[int], warnings: list[str]) -> dict:
    """A second pass that records WHERE a named set of addresses is referenced.

    Separated from :func:`scan_code_references` because the first pass answers a
    yes/no question for 3.6 million addresses and this one answers "which
    instructions" for a few tens of thousands. Keeping the site lists for every
    address would cost hundreds of megabytes to answer a question about 0.4 % of
    them.
    """
    sites: dict[int, list[int]] = defaultdict(list)
    if not wanted:
        return sites
    overlap = LEA_LENGTH + 4
    for section in sections:
        total = section["rsize"]
        position = 0
        tail = b""
        while position < total:
            want = min(READ_CHUNK, total - position)
            buffer = tail + image.read_at(section["raw_pointer"] + position, want,
                                          "reference site scan")
            buffer_rva = section["rva"] + (position - len(tail))
            limit = len(buffer)
            for match in LEA_PREFIX_RE.finditer(buffer):
                index = match.start()
                if index + LEA_LENGTH > limit:
                    continue
                if buffer[index + 2] & 0xC7 != 0x05:
                    continue
                displacement = struct.unpack_from("<i", buffer, index + 3)[0]
                target = buffer_rva + index + LEA_LENGTH + displacement
                if target in wanted:
                    bucket = sites[target]
                    if len(bucket) < MAX_REFERENCE_SITES:
                        bucket.append(buffer_rva + index)
            position += want
            tail = buffer[-overlap:] if len(buffer) > overlap else b""
    return sites


# --------------------------------------------------------------------------- #
# pass 4 -- runs of code-addressing slots
# --------------------------------------------------------------------------- #

def scan_runs(surface: Surface, address: AddressModel, reloc_bitmaps: dict,
              use_relocation_filter: bool, warnings: list[str]) -> dict:
    """Maximal runs of code-addressing slots, with and without the fixup filter.

    Both populations are computed in the SAME pass and both are reported,
    because they are the two halves of one cross-check. The filtered runs are
    what this tool builds candidates from. The unfiltered run-length counts at
    thresholds 4/8/16 are what ``rtti_scan.py``'s internal census publishes, and
    publishing them here from an independent implementation is the only way the
    project's coverage denominator gets a second opinion.
    """
    pointer_size = surface.pointer_size
    base = address.image_base
    limit = address.image_limit
    is_exec = address.is_executable_rva
    runs: list[tuple[int, int]] = []            # (start_rva, slot_count)
    run_targets: list[array] = []
    census: Counter = Counter()                 # unfiltered run lengths
    stats = {
        "slots_examined": 0,
        "slots_addressing_executable_sections": 0,
        "slots_addressing_executable_and_relocated": 0,
        "slots_addressing_executable_not_relocated": 0,
        "unaligned_section_starts": [],
        "relocation_filter_applied": use_relocation_filter,
    }
    unrelocated_examples: list[dict] = []

    for section in surface.sections:
        name = section["name"]
        if section["rva"] % pointer_size:
            stats["unaligned_section_starts"].append(name)
            warnings.append(
                "section %s starts at RVA %d, which is not a multiple of the "
                "pointer size %d; slot alignment in it is taken from the section "
                "start and may not match the loader's"
                % (name, section["rva"], pointer_size))
        values = surface.values[name]
        reloc = reloc_bitmaps[name]
        base_rva = section["rva"]
        current_start = None
        current: array | None = None
        census_run = 0
        for index in range(len(values)):
            value = values[index]
            code_addressing = False
            relocated = False
            if base < value < limit and is_exec(value - base):
                code_addressing = True
                relocated = reloc.get(index)
            stats["slots_examined"] += 1
            if code_addressing:
                stats["slots_addressing_executable_sections"] += 1
                if relocated:
                    stats["slots_addressing_executable_and_relocated"] += 1
                else:
                    stats["slots_addressing_executable_not_relocated"] += 1
                    if len(unrelocated_examples) < 32:
                        unrelocated_examples.append({
                            "section": name,
                            "slot_rva": base_rva + index * pointer_size,
                            "value_hex": "0x%x" % value,
                            "implied_target_rva": value - base,
                        })
                census_run += 1
            else:
                if census_run:
                    for threshold in CENSUS_THRESHOLDS:
                        if census_run >= threshold:
                            census[threshold] += 1
                census_run = 0
            keep = code_addressing and (relocated or not use_relocation_filter)
            if keep:
                if current_start is None:
                    current_start = base_rva + index * pointer_size
                    current = array("I")
                current.append(value - base)
            elif current_start is not None:
                runs.append((current_start, len(current)))
                run_targets.append(current)
                current_start = None
                current = None
            if len(runs) > MAX_CANDIDATES:
                warnings.append("the run scan stopped at the %d-run cap"
                                % MAX_CANDIDATES)
                break
        if census_run:
            for threshold in CENSUS_THRESHOLDS:
                if census_run >= threshold:
                    census[threshold] += 1
        if current_start is not None:
            runs.append((current_start, len(current)))
            run_targets.append(current)

    stats["runs"] = len(runs)
    stats["census_without_relocation_filter"] = {
        "sections": [s["name"] for s in surface.sections],
        "pointer_slots_addressing_executable_sections":
            stats["slots_addressing_executable_sections"],
        "runs_by_minimum_length": {str(t): census.get(t, 0)
                                   for t in CENSUS_THRESHOLDS},
        "definition": (
            "a run is a maximal sequence of consecutive pointer-aligned slots each "
            "holding a value inside a section marked executable; no relocation "
            "filter, no segmentation. This is the definition rtti_scan.py's "
            "internal census uses, reproduced by an independent implementation so "
            "the two can be compared."),
    }
    stats["code_addressing_slots_rejected_by_relocation_filter_examples"] = \
        unrelocated_examples
    return {"summary": stats, "runs": runs, "targets": run_targets}


# --------------------------------------------------------------------------- #
# pass 5 -- segmentation into candidates
# --------------------------------------------------------------------------- #

def segment_runs(surface: Surface, runs: list[tuple[int, int]],
                 targets: list[array], lea_bitmaps: dict, store_bitmaps: dict,
                 use_code_references: bool,
                 warnings: list[str]) -> tuple[list[dict], dict]:
    """Split each run at interior referenced addresses and tier the pieces.

    A run is not a vtable. Two vtables emitted back to back with no padding are
    one run, and the giveaway is that something in the code takes the address of
    the second one's first slot -- nothing takes the address of the middle of a
    vtable. Splitting there is the whole difference between a run-length census
    and an inventory.
    """
    pointer_size = surface.pointer_size
    candidates: list[dict] = []
    stats = {"raw_runs": len(runs), "interior_cut_points": 0,
             "runs_split": 0, "segments": 0,
             "code_references_used": use_code_references}
    for (start, count), slot_targets in zip(runs, targets):
        cuts = [0]
        if use_code_references and count > 1:
            for step in range(1, count):
                if len(cuts) >= MAX_SEGMENT_CUTS:
                    warnings.append(
                        "the run at RVA %d hit the %d-cut cap; the tail is left "
                        "unsegmented" % (start, MAX_SEGMENT_CUTS))
                    break
                if surface.get_byte(lea_bitmaps, start + step * pointer_size):
                    cuts.append(step)
        if len(cuts) > 1:
            stats["runs_split"] += 1
            stats["interior_cut_points"] += len(cuts) - 1
        for position, cut in enumerate(cuts):
            end = cuts[position + 1] if position + 1 < len(cuts) else count
            rva = start + cut * pointer_size
            referenced = (use_code_references
                          and surface.get_byte(lea_bitmaps, rva))
            stored = (use_code_references
                      and surface.get_byte(store_bitmaps, rva))
            tier = (TIER_STORED if stored else
                    TIER_REFERENCED if referenced else TIER_UNREFERENCED)
            candidates.append({
                "vtable_rva": rva,
                "slot_count": end - cut,
                "tier": tier,
                "run_rva": start,
                "run_slot_count": count,
                "is_run_start": cut == 0,
                "slot_target_rvas": slot_targets[cut:end],
            })
    stats["segments"] = len(candidates)
    candidates.sort(key=lambda row: row["vtable_rva"])
    return candidates, stats


# --------------------------------------------------------------------------- #
# pass 6 -- the slot before a candidate, and independent RTTI detection
# --------------------------------------------------------------------------- #

def classify_prior_slot(surface: Surface, address: AddressModel,
                        reloc_bitmaps: dict, candidate: dict) -> dict:
    """What sits in the slot immediately before a candidate's first slot.

    In an MSVC image compiled with RTTI on, that slot holds a pointer to the
    class's ``RTTICompleteObjectLocator``, and the locator is self-identifying:
    its first DWORD is 1 and its sixth DWORD is its own image-relative address.
    Checking that here gives this tool its OWN count of RTTI-bearing vtables,
    derived from the vtable side rather than from a name search, which is a
    genuinely independent estimate of the number ``rtti_scan.py`` reports from
    the ``.?A`` side.

    For everything else the classification stays deliberately coarse -- absent,
    zero, a data pointer, a non-pointer -- because naming what a non-locator
    value IS would be an interpretation this pass has no evidence for.
    """
    pointer_size = surface.pointer_size
    rva = candidate["vtable_rva"] - pointer_size
    out = {"prior_slot_rva": rva, "prior_slot_kind": "off-surface",
           "rtti_locator_rva": None}
    value = surface.slot_at(rva)
    if value is None:
        return out
    if value == 0:
        out["prior_slot_kind"] = "zero"
        return out
    if not (address.image_base < value < address.image_limit):
        out["prior_slot_kind"] = "not-an-image-address"
        return out
    target = value - address.image_base
    if address.is_executable_rva(target):
        # The previous slot is itself code-addressing, which means this candidate
        # begins inside a longer run: it exists because something referenced it.
        out["prior_slot_kind"] = "code-address"
        return out
    out["prior_slot_kind"] = "data-address"
    # Try the complete-object-locator predicate. Two DWORDs read from the
    # surface, no external table consulted.
    header = _read_dwords(surface, target, 6)
    if header is None:
        return out
    signature, _offset, _cd, _type_descriptor, _class_descriptor, self_rva = header
    expected_signature = 1 if pointer_size == 8 else 0
    if signature == expected_signature and self_rva == target and pointer_size == 8:
        out["prior_slot_kind"] = "rtti-complete-object-locator"
        out["rtti_locator_rva"] = target
    elif signature == expected_signature and pointer_size == 4:
        # PE32 has no pSelf, so the predicate is much weaker and is labelled so.
        out["prior_slot_kind"] = "rtti-locator-candidate-pe32"
        out["rtti_locator_rva"] = target
    return out


def _read_dwords(surface: Surface, rva: int, count: int) -> tuple | None:
    """*count* little-endian DWORDs at *rva*, read from the loaded surface only."""
    found = surface.locate(rva)
    if found is None:
        return None
    section, offset = found
    if offset % 4:
        return None
    name = section["name"]
    values = surface.values[name]
    per_slot = surface.pointer_size // 4
    words: list[int] = []
    for index in range(count):
        position = offset + index * 4
        slot_index = position // surface.pointer_size
        if slot_index >= len(values):
            return None
        slot = values[slot_index]
        shift = (position % surface.pointer_size) * 8
        words.append((slot >> shift) & 0xFFFFFFFF if per_slot > 1 else slot)
    return tuple(words)


# --------------------------------------------------------------------------- #
# pass 7 -- tables that are known NOT to be vtables
# --------------------------------------------------------------------------- #

def known_pointer_tables(headers, warnings: list[str]) -> list[dict]:
    """Ranges of pointer-width slots this image declares to be something else.

    Computed from the import, delay-import and TLS directories, which is to say
    from the image's own declarations rather than from a guess. Candidates
    overlapping one of these get a flag, never a deletion: a rule that removes
    its own counter-examples cannot be checked.
    """
    tables: list[dict] = []
    try:
        imports, notes = pe_info.parse_imports(headers)
    except PEFormatError as error:                     # pragma: no cover
        imports, notes = None, [str(error)]
    warnings.extend(notes or [])
    for module in imports or []:
        rvas = [f["iat_rva"] for f in module.get("functions") or []
                if f.get("iat_rva")]
        if rvas:
            tables.append({"kind": "import-address-table",
                           "name": module.get("dll"),
                           "start_rva": min(rvas),
                           "end_rva": max(rvas) + headers.pointer_size})
    try:
        delayed, notes, _extra = pe_info.parse_delay_imports(headers)
    except PEFormatError as error:                     # pragma: no cover
        delayed, notes = None, [str(error)]
    warnings.extend(notes or [])
    for module in delayed or []:
        rvas = [f["iat_rva"] for f in module.get("functions") or []
                if f.get("iat_rva")]
        if rvas:
            tables.append({"kind": "delay-load-import-address-table",
                           "name": module.get("dll"),
                           "start_rva": min(rvas),
                           "end_rva": max(rvas) + headers.pointer_size})
    tls_rva, tls_size = headers.directory(pe_info.DIR_TLS)
    if tls_rva and tls_size:
        # AddressOfCallBacks is the fourth pointer of IMAGE_TLS_DIRECTORY64.
        try:
            raw = headers.read_rva(tls_rva + 3 * headers.pointer_size,
                                   headers.pointer_size, "TLS AddressOfCallBacks")
            fmt = "<Q" if headers.pointer_size == 8 else "<I"
            array_va = struct.unpack(fmt, raw)[0]
            if array_va > headers.image_base:
                start = array_va - headers.image_base
                count = 0
                while count < 64:
                    entry = headers.read_rva(start + count * headers.pointer_size,
                                             headers.pointer_size, "TLS callback")
                    if struct.unpack(fmt, entry)[0] == 0:
                        break
                    count += 1
                if count:
                    tables.append({"kind": "tls-callback-array", "name": None,
                                   "start_rva": start,
                                   "end_rva": start + count * headers.pointer_size})
        except PEFormatError as error:
            warnings.append("the TLS callback array could not be read: %s" % error)
    tables.sort(key=lambda row: (row["start_rva"], row["kind"]))
    return tables


def build_table_lookup(tables: list[dict]):
    starts = [t["start_rva"] for t in tables]

    def lookup(rva: int, slots: int, pointer_size: int) -> str | None:
        end = rva + slots * pointer_size
        index = bisect.bisect_right(starts, rva) - 1
        for probe in (index, index + 1):
            if 0 <= probe < len(tables):
                table = tables[probe]
                if rva < table["end_rva"] and end > table["start_rva"]:
                    return table["kind"]
        return None

    return lookup


# --------------------------------------------------------------------------- #
# pass 8 -- Unreal build-machine source-path literals
# --------------------------------------------------------------------------- #

def find_source_path_literals(image, surface: Surface,
                              warnings: list[str]) -> list[dict]:
    """Every ``X:\\build\\++UE5\\Sync\\...`` literal in the surface, with its RVA.

    These are the strings the Unreal build machine's ``__FILE__`` expansions left
    behind, and they are the only thing in this image that names a translation
    unit in plain text. Whether they say anything about where a vtable came from
    is a question this tool MEASURES rather than assumes -- see
    ``statistics.source_path_relation``.
    """
    found: list[dict] = []
    seen: set[int] = set()
    overlap = MAX_LITERAL_BYTES + 32
    for section in surface.sections:
        total = section["rsize"]
        position = 0
        tail = b""
        while position < total:
            want = min(READ_CHUNK, total - position)
            buffer = tail + image.read_at(section["raw_pointer"] + position, want,
                                          "source-path literal scan")
            buffer_rva = section["rva"] + (position - len(tail))
            for match in SOURCE_PATH_RE.finditer(buffer):
                rva = buffer_rva + match.start()
                if rva in seen:
                    continue
                seen.add(rva)
                try:
                    text = match.group()[:-1].decode("ascii")
                except UnicodeDecodeError:              # pragma: no cover
                    continue
                found.append({
                    "rva": rva,
                    "section": section["name"],
                    "length": len(text),
                    "path": SOURCE_PATH_PREFIX_RE.sub("", text).replace("\\", "/"),
                })
                if len(found) >= MAX_SOURCE_PATH_LITERALS:
                    warnings.append("the source-path literal scan stopped at the "
                                    "%d-literal cap" % MAX_SOURCE_PATH_LITERALS)
                    return sorted(found, key=lambda row: row["rva"])
            position += want
            tail = buffer[-overlap:] if len(buffer) > overlap else b""
    return sorted(found, key=lambda row: row["rva"])


def nearest_literal(literal_rvas: list[int], literals: list[dict],
                    rva: int) -> dict:
    """The closest source-path literal to *rva*, and the DISTANCE to it.

    The distance is the whole point of the field. A candidate 300 bytes from a
    literal and a candidate 4 MB from one are not the same claim, and a field
    that reported only the nearest path would make them look identical.
    """
    if not literal_rvas:
        return {"nearest_source_path": None, "nearest_source_path_rva": None,
                "nearest_source_path_distance": None}
    index = bisect.bisect_left(literal_rvas, rva)
    best = None
    for probe in (index - 1, index):
        if 0 <= probe < len(literal_rvas):
            distance = abs(literal_rvas[probe] - rva)
            if best is None or distance < best[0]:
                best = (distance, probe)
    distance, probe = best
    return {"nearest_source_path": literals[probe]["path"],
            "nearest_source_path_rva": literals[probe]["rva"],
            "nearest_source_path_distance": distance}


# --------------------------------------------------------------------------- #
# statistics
# --------------------------------------------------------------------------- #

def build_statistics(candidates: list[dict], surface: Surface,
                     functions: FunctionIndex, literals: list[dict],
                     pointer_size: int) -> dict:
    """Everything the characterisation questions of S-09 need, as fields.

    Split by tier throughout. A single distribution over all candidates would
    average a population whose halves this tool can tell apart, and the whole
    reason for the tiers is that the halves behave differently.
    """
    by_tier = {tier: [c for c in candidates if c["tier"] == tier]
               for tier in TIER_ORDER}
    stats: dict = {"by_tier": {}, "totals": {}}
    for tier in TIER_ORDER:
        rows = by_tier[tier]
        lengths = [row["slot_count"] for row in rows]
        stats["by_tier"][tier] = {
            "candidates": len(rows),
            "candidates_with_at_least_2_slots": sum(1 for n in lengths if n >= 2),
            "slot_total": sum(lengths),
            "slot_count_min": min(lengths) if lengths else None,
            "slot_count_max": max(lengths) if lengths else None,
            "slot_count_percentiles": percentiles(lengths),
            "slot_count_histogram": histogram(lengths),
        }
    stats["totals"] = {
        "candidates": len(candidates),
        "slot_total": sum(c["slot_count"] for c in candidates),
        "sections": dict(sorted(Counter(
            (surface.locate(c["vtable_rva"]) or ({"name": None},))[0]["name"]
            for c in candidates).items(), key=lambda kv: str(kv[0]))),
    }

    # -- shared slot targets ------------------------------------------------ #
    # A target used by two candidates is one implementation reached through two
    # class layouts: inheritance, or a shared thunk. The rate is a direct
    # measure of how related the population is.
    target_users: Counter = Counter()
    for candidate in candidates:
        for target in set(candidate["slot_target_rvas"]):
            target_users[target] += 1
    shared = [t for t, n in target_users.items() if n > 1]
    most = target_users.most_common(8)
    stats["shared_slot_targets"] = {
        "distinct_slot_targets": len(target_users),
        "targets_used_by_more_than_one_candidate": len(shared),
        "share_of_targets_that_are_shared": (
            round(len(shared) / len(target_users), 4) if target_users else None),
        "most_shared_targets": [
            {"target_rva": rva, "candidate_count": count,
             "is_function_start": functions.is_start(rva)}
            for rva, count in most],
    }

    # -- slot targets that are function starts ------------------------------ #
    slot_total = 0
    function_start_slots = 0
    for candidate in candidates:
        for target in candidate["slot_target_rvas"]:
            slot_total += 1
            if functions.is_start(target):
                function_start_slots += 1
    stats["slot_targets_at_function_starts"] = {
        "slots": slot_total,
        "at_a_runtime_function_start": function_start_slots,
        "share": round(function_start_slots / slot_total, 4) if slot_total else None,
        "caveat": (
            "a leaf function with no unwind data need not appear in the runtime "
            "function table at all, so a slot target that is NOT a function start "
            "is weak evidence and is never used here to reject a candidate"),
    }

    # -- clusters: candidates that are exactly back to back ----------------- #
    # One linker contribution is one object file, so a chain of candidates with
    # no padding between them is the shape of one translation unit's vtables.
    for tier_group, label in ((TIER_ORDER, "all_tiers"), ((TIER_STORED,), TIER_STORED)):
        rows = sorted((c for c in candidates if c["tier"] in tier_group),
                      key=lambda c: c["vtable_rva"])
        sizes = []
        current = 1
        for index in range(len(rows) - 1):
            here = rows[index]
            if here["vtable_rva"] + here["slot_count"] * pointer_size \
                    == rows[index + 1]["vtable_rva"]:
                current += 1
            else:
                sizes.append(current)
                current = 1
        if rows:
            sizes.append(current)
        stats.setdefault("clusters", {})[label] = {
            "candidates": len(rows),
            "clusters": len(sizes),
            "largest_cluster": max(sizes) if sizes else None,
            "candidates_in_a_cluster_of_2_or_more": sum(n for n in sizes if n >= 2),
            "cluster_size_histogram": histogram(sizes, cap=16),
            "definition": ("a cluster is a maximal chain of candidates where each "
                           "one's last slot is immediately followed by the next "
                           "one's first slot, with no padding between them"),
        }

    # -- relation to the source-path literals ------------------------------- #
    literal_rvas = [row["rva"] for row in literals]
    distances = []
    for candidate in candidates:
        near = nearest_literal(literal_rvas, literals, candidate["vtable_rva"])
        if near["nearest_source_path_distance"] is not None:
            distances.append(near["nearest_source_path_distance"])
    stats["source_path_relation"] = {
        "literals": len(literals),
        "literal_rva_span": ([literal_rvas[0], literal_rvas[-1]]
                             if literal_rvas else None),
        "candidate_rva_span": ([candidates[0]["vtable_rva"],
                                candidates[-1]["vtable_rva"]]
                               if candidates else None),
        "distance_percentiles": percentiles(distances),
        "candidates_within_4096_bytes_of_a_literal":
            sum(1 for d in distances if d <= 4096),
        "candidates_within_65536_bytes_of_a_literal":
            sum(1 for d in distances if d <= 65536),
        "what_this_does_and_does_not_show": (
            "a small distance means the candidate and the literal are in the same "
            "region of the section, which for MSVC output means a nearby linker "
            "contribution and therefore a nearby object file. It is NOT a claim "
            "that the candidate belongs to that file: string literals and vtables "
            "are placed by different grouping rules, and the same-function join "
            "reported alongside is the stronger test."),
    }

    stats["rtti_split"] = characterise_rtti_split(candidates, functions,
                                                  pointer_size)
    return stats


def _subpopulation_shape(rows: list[dict], functions: FunctionIndex,
                         pointer_size: int) -> dict:
    """Size, sharing and contiguity for one subpopulation. No names, no owners.

    Deliberately restricted to the three questions S-09 can answer about a
    vtable whose class name is not in the image: how long it is, whether its
    slots are reached from other vtables too, and whether it is packed against
    its neighbours. Anything about WHAT the class is would need a name, and the
    absence of the name is the defining property of this population.
    """
    lengths = [row["slot_count"] for row in rows]

    target_users: Counter = Counter()
    for row in rows:
        for target in set(row["slot_target_rvas"]):
            target_users[target] += 1
    shared = sum(1 for count in target_users.values() if count > 1)

    ordered = sorted(rows, key=lambda r: r["vtable_rva"])
    sizes: list[int] = []
    current = 1
    for index in range(len(ordered) - 1):
        here = ordered[index]
        if here["vtable_rva"] + here["slot_count"] * pointer_size \
                == ordered[index + 1]["vtable_rva"]:
            current += 1
        else:
            sizes.append(current)
            current = 1
    if ordered:
        sizes.append(current)

    slot_total = sum(lengths)
    function_start_slots = sum(1 for row in rows
                               for target in row["slot_target_rvas"]
                               if functions.is_start(target))
    return {
        "candidates": len(rows),
        "candidates_with_at_least_2_slots": sum(1 for n in lengths if n >= 2),
        "slot_total": slot_total,
        "slot_count_min": min(lengths) if lengths else None,
        "slot_count_max": max(lengths) if lengths else None,
        "slot_count_percentiles": percentiles(lengths),
        "slot_count_histogram": histogram(lengths),
        "distinct_slot_targets": len(target_users),
        "slot_targets_shared_within_this_subpopulation": shared,
        "share_of_targets_that_are_shared": (
            round(shared / len(target_users), 4) if target_users else None),
        "slot_targets_at_a_function_start": function_start_slots,
        "share_of_slots_at_a_function_start": (
            round(function_start_slots / slot_total, 4) if slot_total else None),
        "contiguous_runs": len(sizes),
        "largest_contiguous_run": max(sizes) if sizes else None,
        "candidates_in_a_contiguous_run_of_2_or_more":
            sum(n for n in sizes if n >= 2),
        "contiguous_run_size_histogram": histogram(sizes, cap=16),
    }


def characterise_rtti_split(candidates: list[dict], functions: FunctionIndex,
                            pointer_size: int) -> dict:
    """Characterise the candidates that carry NO RTTI locator, against those that do.

    Why the comparison and not just the description: S-10 found that MSVC RTTI in
    this image names 580 classes and ZERO of them game classes, so if game
    classes are anywhere they are in the population with no locator. That
    population cannot be described against ground truth -- there is none, that
    is what "no RTTI" means. It can only be described against a REFERENCE
    population from the same image whose members are known to be vtables, which
    is exactly the RTTI-bearing set. So every figure below is reported twice,
    once for each side of the split, and the reader compares them.

    What agreement between the two shapes would license, and what it would not:
    if the no-locator candidates have the same length distribution, the same
    slot-sharing rate and the same packing as the locator-bearing ones, that is
    consistent with their being vtables of the same compiler's output -- it is
    NOT proof that any of them is a vtable, still less that any is a game class.
    A run of function pointers emitted by the same compiler for another purpose
    has every one of these properties too. The tier is the stronger evidence and
    it is kept orthogonal here: the split is reported per tier as well as
    overall, because "code-stored and no locator" is a much narrower claim than
    "no locator".
    """
    with_rtti = [c for c in candidates if c["rtti_locator_rva"] is not None]
    without = [c for c in candidates if c["rtti_locator_rva"] is None]

    result: dict = {
        "definition_of_the_split": (
            "the slot immediately before the candidate is followed and accepted as "
            "an RTTI complete-object-locator only when the first DWORD of the "
            "record it points at is 1 and its sixth DWORD equals that record's own "
            "image-relative address; anything else counts as NO locator"),
        "what_the_comparison_can_and_cannot_show": (
            "the locator-bearing side is the only subpopulation of this image whose "
            "members are independently known to be vtables, so it is used as the "
            "reference shape. Matching it is consistent with being vtables of the "
            "same toolchain and is not evidence of being one; not matching it is "
            "the informative outcome, and is reported rather than explained away"),
        "contiguity_is_confounded_across_this_split": (
            "READ THE CONTIGUITY FIGURES WITH THIS IN MIND. A candidate spans its "
            "slots only, and an RTTI-bearing vtable always has its locator pointer "
            "in the slot immediately before it. Two RTTI-bearing candidates are "
            "therefore separated by that pointer BY CONSTRUCTION and can never be "
            "adjacent under the definition used here, which forces the "
            "locator-bearing side to a largest run of 1 whatever the image looks "
            "like. The difference in contiguity between the two sides is thus an "
            "artefact of the definition and is NOT evidence that the two "
            "populations are laid out differently. Contiguity WITHIN the "
            "no-locator side remains meaningful; contiguity ACROSS the split does "
            "not, and no conclusion is drawn from it here"),
        "with_an_rtti_locator": _subpopulation_shape(with_rtti, functions,
                                                    pointer_size),
        "without_an_rtti_locator": _subpopulation_shape(without, functions,
                                                        pointer_size),
        "by_tier": {},
    }
    for tier in TIER_ORDER:
        rows_with = [c for c in with_rtti if c["tier"] == tier]
        rows_without = [c for c in without if c["tier"] == tier]
        result["by_tier"][tier] = {
            "with_an_rtti_locator": _subpopulation_shape(rows_with, functions,
                                                         pointer_size),
            "without_an_rtti_locator": _subpopulation_shape(rows_without,
                                                            functions,
                                                            pointer_size),
        }

    # Do the two sides share implementations with EACH OTHER? A slot target used
    # both by a named vtable and by an unnamed candidate is the single most
    # useful cross-link this tool can offer M3: it is an override table reached
    # from a class the image does name, which is a place to start reading.
    named_targets = set()
    for row in with_rtti:
        named_targets.update(row["slot_target_rvas"])
    crossing = 0
    crossing_targets = set()
    for row in without:
        hit = named_targets.intersection(row["slot_target_rvas"])
        if hit:
            crossing += 1
            crossing_targets.update(hit)
    result["cross_link"] = {
        "candidates_without_a_locator_sharing_a_slot_target_with_a_named_vtable":
            crossing,
        "distinct_shared_targets": len(crossing_targets),
        "share_of_the_no_locator_population": (
            round(crossing / len(without), 4) if without else None),
        "what_it_means": (
            "a slot address that occurs both in an RTTI-named vtable and in an "
            "unnamed candidate. Most such hits will be a shared compiler-emitted "
            "thunk or a pure-virtual stub rather than a real inherited override, "
            "so the count is an upper bound on 'unnamed vtables related to a named "
            "class' and must not be read as that number"),
    }
    return result


def source_path_same_function_join(candidates: list[dict], literals: list[dict],
                                  sites: dict, functions: FunctionIndex,
                                  bound: int) -> dict:
    """Which candidates are referenced by a function that also names a source file.

    The strongest attribution available without a decompiler: if one function
    both takes the address of a candidate and takes the address of a
    ``__FILE__`` literal, that function is compiled from that file, and the
    candidate it stores is very likely declared there. The reason this is
    reported as a measurement and not sold as a feature is that on this build it
    connects almost nothing, and the number has to be allowed to say so.
    """
    literal_by_rva = {row["rva"]: row["path"] for row in literals}
    paths_by_function: dict[int, set[str]] = defaultdict(set)
    for rva, path in literal_by_rva.items():
        for site in sites.get(rva, ()):
            owner = functions.containing(site)
            if owner is not None:
                paths_by_function[owner].add(path)
    joined = []
    for candidate in candidates:
        owners = set()
        for site in sites.get(candidate["vtable_rva"], ()):
            owner = functions.containing(site)
            if owner is not None:
                owners.add(owner)
        paths: set[str] = set()
        for owner in owners:
            paths |= paths_by_function.get(owner, set())
        if paths:
            joined.append({"vtable_rva": candidate["vtable_rva"],
                           "tier": candidate["tier"],
                           "slot_count": candidate["slot_count"],
                           "source_paths": sorted(paths)[:4]})
    return {
        "functions_referencing_a_source_path_literal": len(paths_by_function),
        "candidates_joined_to_a_source_path": len(joined),
        "candidates_considered": len(candidates),
        "examples": _spread(joined, bound),
        "method": (
            "a candidate and a source-path literal are joined when ONE runtime "
            "function (from the EXCEPTION directory) contains a RIP-relative lea "
            "of both. Reference sites per address are capped at %d, so a candidate "
            "referenced from more places than that can be missed."
            % MAX_REFERENCE_SITES),
    }


# --------------------------------------------------------------------------- #
# cross-check against the S-10 artifact
# --------------------------------------------------------------------------- #

def cross_check_rtti(path: str, candidates: list[dict], run_stats: dict,
                     independent_locator_count: int,
                     warnings: list[str]) -> dict:
    """Compare this tool's measurements with rtti_scan.py's, mechanically.

    Four comparisons, and each one can fail:

    1. the unfiltered run-length census at 4/8/16 must match theirs exactly, and
       so must the count of slots addressing executable sections. Two
       independent implementations of one definition either agree on the number
       or one of them is wrong;
    2. every vtable S-10 reached through RTTI must appear here as a candidate;
    3. its slot count must be identical, slot for slot;
    4. this tool's own count of RTTI-bearing candidates -- reached from the
       vtable side, through the locator's self-pointer -- must match the count
       S-10 reached from the ``.?A`` name side.

    A fifth measurement is not a comparison but a test of a premise: whether two
    ADJACENT vtables tend to have the same owner. If they do not, then nothing
    positional in this tool's output means anything.
    """
    result = {"artifact": path, "readable": False, "note": None}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as error:
        result["note"] = "the RTTI artifact could not be read: %s" % error
        warnings.append(result["note"])
        return result
    result["readable"] = True
    result["rtti_generator"] = document.get("generator")
    result["rtti_generator_version"] = document.get("generator_version")
    result["rtti_target"] = (document.get("file") or {}).get("install_relative") \
        or (document.get("file") or {}).get("name")
    result["rtti_sha256"] = (document.get("file") or {}).get("sha256")

    theirs = document.get("vtable_census") or {}
    mine = run_stats["census_without_relocation_filter"]
    their_runs = theirs.get("runs_by_minimum_length") or {}
    census = {
        "their_slots": theirs.get("pointer_slots_addressing_executable_sections"),
        "my_slots": mine["pointer_slots_addressing_executable_sections"],
        "their_runs_by_minimum_length": their_runs,
        "my_runs_by_minimum_length": mine["runs_by_minimum_length"],
    }
    census["slots_agree"] = (census["their_slots"] == census["my_slots"]
                             if census["their_slots"] is not None else None)
    census["runs_agree"] = (
        {str(k): v for k, v in their_runs.items()} == mine["runs_by_minimum_length"]
        if their_runs else None)
    census["their_sections"] = theirs.get("sections")
    census["my_sections"] = mine["sections"]
    census["comparison_is_valid_only_if_the_sections_match"] = (
        sorted(theirs.get("sections") or []) == sorted(mine["sections"]))
    result["census"] = census

    known = {}
    for row in document.get("classes") or []:
        vtable = row.get("vtable") or {}
        if vtable.get("vtable_rva") is not None:
            known[vtable["vtable_rva"]] = {
                "slot_count": vtable.get("code_slot_count"),
                "owner": (row.get("attribution") or {}).get("owner"),
                "name": row.get("decoded_name"),
            }
    index = {c["vtable_rva"]: c for c in candidates}
    recovered = [rva for rva in known if rva in index]
    mismatched = [{"vtable_rva": rva,
                   "rtti_slot_count": known[rva]["slot_count"],
                   "my_slot_count": index[rva]["slot_count"]}
                  for rva in sorted(recovered)
                  if index[rva]["slot_count"] != known[rva]["slot_count"]]
    missing = sorted(rva for rva in known if rva not in index)
    by_tier = Counter(index[rva]["tier"] for rva in recovered)
    result["known_vtables"] = {
        "in_the_rtti_artifact": len(known),
        "recovered_as_a_candidate": len(recovered),
        "recall": round(len(recovered) / len(known), 4) if known else None,
        "slot_count_disagreements": len(mismatched),
        "slot_count_disagreement_examples": mismatched[:16],
        "not_recovered": missing[:16],
        "recovered_by_tier": {tier: by_tier.get(tier, 0) for tier in TIER_ORDER},
        "recall_code_stored": (round(by_tier.get(TIER_STORED, 0) / len(known), 4)
                               if known else None),
        "recall_code_stored_or_referenced": (
            round((by_tier.get(TIER_STORED, 0) + by_tier.get(TIER_REFERENCED, 0))
                  / len(known), 4) if known else None),
    }
    result["independent_rtti_locator_count"] = {
        "found_from_the_vtable_side": independent_locator_count,
        "found_by_rtti_scan_from_the_name_side": (
            (document.get("summary") or {}).get("distinct_vtables")),
        "agree": (independent_locator_count
                  == (document.get("summary") or {}).get("distinct_vtables")),
        "method": ("the slot before each candidate is followed and the record it "
                   "points at is accepted only when its first DWORD is 1 and its "
                   "sixth DWORD equals its own image-relative address"),
    }

    # -- the premise test: is vtable order grouped by origin? --------------- #
    ordered = sorted(known.items())
    pairs = len(ordered) - 1
    same_owner = sum(1 for i in range(pairs)
                     if ordered[i][1]["owner"] == ordered[i + 1][1]["owner"])
    owners = Counter(v["owner"] for _, v in ordered)
    total = sum(owners.values())
    chance = sum((n / total) ** 2 for n in owners.values()) if total else None
    blocks = 1 if ordered else 0
    for index_ in range(pairs):
        if ordered[index_][1]["owner"] != ordered[index_ + 1][1]["owner"]:
            blocks += 1
    result["owner_adjacency"] = {
        "adjacent_pairs": pairs,
        "adjacent_pairs_with_the_same_owner": same_owner,
        "observed_rate": round(same_owner / pairs, 4) if pairs else None,
        "chance_rate_from_owner_frequencies": round(chance, 4) if chance else None,
        "distinct_owners": len(owners),
        "contiguous_same_owner_blocks": blocks,
        "rva_span": [ordered[0][0], ordered[-1][0]] if ordered else None,
        "what_it_tests": (
            "whether vtable ORDER in this image carries information about origin. "
            "An observed rate near the chance rate would mean that nothing "
            "positional in this tool's output -- clusters, nearest literal, "
            "neighbourhood -- can be read as evidence of anything."),
    }
    return result


# --------------------------------------------------------------------------- #
# evidence layer 1 (class P): literal reads
# --------------------------------------------------------------------------- #

def locus_target(path: str, install_root: str | None = None) -> str:
    """The spelling a class-P read locus uses for *path*: install-relative, '/'.

    A bare basename is not a determinate location: this installation holds two
    different files called ``MISERY.exe``, so ``MISERY.exe@123+8`` names an
    ambiguity class rather than a range of bytes. Same rule as
    ``rtti_scan.locus_target`` and for the same reason; the implementation is
    kept here rather than imported because importing it would make this tool
    depend on the module it is supposed to be independent of.
    """
    absolute = os.path.abspath(path)
    root = install_root
    if root is None:
        try:
            roots = pathguard.structural_install_roots(absolute)
        except (ValueError, OSError):
            roots = []
        root = roots[-1] if roots else None
    if not root:
        return os.path.basename(absolute)
    try:
        relative = os.path.relpath(absolute, os.path.abspath(root))
    except ValueError:                  # different drives on Windows
        return os.path.basename(absolute)
    relative = relative.replace("\\", "/")
    if relative.startswith("../") or relative in ("..", ".") or ":" in relative:
        return os.path.basename(absolute)
    return relative


def literal_read(target: str, join_key: str, offset: int, raw: bytes,
                 note: str | None = None) -> dict:
    """One class-P record: a literal read at a determinate place, and no more.

    ``claim`` states the offset AND the length -- which plan.md 10.3 v2.4 makes
    mandatory for ``binary-analysis`` to be class P at all -- and stops there. It
    does not say the bytes are a vtable, a pointer, or anything else.
    """
    length = len(raw)
    plural = "byte" if length == 1 else "bytes"
    claim = "%d %s at offset %d of %s are %s" % (
        length, plural, offset, target, hex_bytes(raw))
    return {
        "join_key": join_key,
        "interpretation_lives_in": (
            "the candidate row with the same RVA in vtables.jsonl, and the "
            "statistics of this document -- plan.md 10.3, the A-07 / A-07i split"),
        "target": target,
        "offset": offset,
        "length": length,
        "bytes_hex": hex_bytes(raw),
        "claim": claim,
        "evidence": {
            "evidence_level": "OBSERVED",
            "claim_class": "P",
            "confidence": CONFIDENCE_LITERAL,
            "oracle": ["binary-analysis"],
            "sources": [{
                "method": "S-09",
                "artifact": None,
                "locator": "%s@%d+%d" % (target, offset, length),
                # Filled in by confirm_literal_reads once the second read has
                # actually happened. Never pre-filled: an attestation written
                # before the check is a claim about intention, not about a file.
                "note": ("oracle binary-analysis. Read by %s, read-only. "
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
            # The note IS the claim. tools/kb/validate.py derives the claim class
            # of a reduced annotation from this string alone, and a note that
            # talked ABOUT the record instead of stating it would derive class I.
            "note": ("%s. This record gives the position and the extent, and "
                     "nothing else." % claim),
        },
    }


def confirm_literal_reads(path: str, literals: list[dict], target: str,
                          warnings: list[str]) -> bool:
    """Perform every literal read a SECOND time and stamp the result on each record.

    plan.md 10.3 class-P criterion 2 executed rather than asserted. A fresh
    handle, an independent seek. On disagreement nothing is adjusted: the
    failure is recorded and the reading stands as unreproduced.
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
                        "%s: the second read of %d bytes at offset %d gave %s but "
                        "the first gave %s -- the reading did NOT reproduce"
                        % (target, read["length"], read["offset"],
                           hex_bytes(again), read["bytes_hex"]))
    except OSError as error:
        reproduced = False
        warnings.append("%s: the confirming re-read could not be performed: %s"
                        % (target, error))
    attestation = RERUN_CONFIRMED if reproduced else RERUN_NOT_CONFIRMED
    for read in literals:
        read["reproduced"] = reproduced
        read["evidence"]["sources"][0]["note"] = (
            "oracle binary-analysis. Read by %s, read-only. %s"
            % (GENERATOR_NAME, attestation))
        read["evidence"]["note"] = "%s %s" % (read["evidence"]["note"], attestation)
    return reproduced


def interpreted_annotation(target: str, second_method: str | None) -> dict:
    """The class-I annotation for the interpretive layer.

    INFERRED, therefore class I unconditionally (plan.md 10.3), whatever the
    offsets are. 0.85 only when a second, independent method actually
    corroborated the reading; 0.79 otherwise, because re-reading the same bytes
    is not a second method and an extra oracle is not a method either.
    """
    sources = [{
        "method": "S-09",
        "artifact": None,
        "locator": target,
        "note": ("oracle binary-analysis + external-doc. A run of relocated, "
                 "pointer-aligned values addressing executable sections is read "
                 "as a virtual function table, which rests on the MSVC object "
                 "layout convention (external-doc: it proves how the Microsoft "
                 "toolchain lays a vtable out, not what this build contains) and "
                 "on a pattern match over instruction bytes that is not a "
                 "disassembler."),
    }]
    oracles = ["binary-analysis", "external-doc"]
    if second_method:
        sources.append({
            "method": "S-09",
            "artifact": None,
            "locator": target,
            "independent_of": ["S-09/run-and-reference-scan"],
            "note": "oracle binary-analysis. Second, independent method: %s"
                    % second_method,
        })
    return {
        "evidence_level": "INFERRED",
        "claim_class": "I",
        "confidence": (CONFIDENCE_INTERPRETED_TWO_METHODS if second_method
                       else CONFIDENCE_INTERPRETED_ONE_METHOD),
        "oracle": sorted(oracles),
        "sources": sources,
        "read_locus": None,
        "note": (
            "Interpretive: this layer says that named byte ranges ARE virtual "
            "function tables, counts them and describes their population, all of "
            "which decodes and attributes rather than reads. The primitive half "
            "is in literal_reads[]. %s"
            % (("Second method: %s" % second_method) if second_method
               else "No second, independent method was available in this run, so "
                    "the confidence stays below the 0.80 band that plan.md 10.3 "
                    "opens only to two independent methods.")
        ),
    }


# --------------------------------------------------------------------------- #
# refutation probes
# --------------------------------------------------------------------------- #

def build_refutation_probes(surface: Surface, address: AddressModel,
                            reloc_bitmaps: dict, candidates: list[dict],
                            run_stats: dict, tables: list[dict],
                            table_lookup, statistics: dict) -> list[dict]:
    """Probes designed to BREAK the headline, not to support it.

    Each one states what result would have refuted what, and then reports what
    actually happened. A probe that cannot fail is decoration.
    """
    probes: list[dict] = []
    pointer_size = surface.pointer_size

    # 1. The misalignment control. If the candidate population were an artefact
    #    of scanning rather than a property of the image, then scanning the same
    #    bytes at a deliberately wrong alignment would find a comparable
    #    population. Structure that survives a half-pointer shift is noise.
    shifted_runs = 0
    shifted_slots = 0
    offset = pointer_size // 2
    for section in surface.sections:
        name = section["name"]
        values = surface.values[name]
        run = 0
        # Re-read the same section shifted by half a pointer, reconstructing the
        # misaligned words from the aligned ones by shifting.
        half = pointer_size * 4
        mask = (1 << (pointer_size * 8)) - 1
        for index in range(len(values) - 1):
            value = ((values[index] >> half)
                     | ((values[index + 1] << half) & mask))
            if address.image_base < value < address.image_limit \
                    and address.is_executable_rva(value - address.image_base):
                run += 1
                shifted_slots += 1
            else:
                if run >= 4:
                    shifted_runs += 1
                run = 0
        if run >= 4:
            shifted_runs += 1
    aligned_runs = run_stats["census_without_relocation_filter"][
        "runs_by_minimum_length"]["4"]
    probes.append({
        "probe": "misalignment control",
        "what_would_refute": (
            "if scanning the same bytes at a deliberately wrong alignment (shifted "
            "by half a pointer) produced a comparable number of runs, the "
            "population reported here would be an artefact of the scan rather than "
            "a property of the image"),
        "aligned_runs_of_at_least_4": aligned_runs,
        "misaligned_runs_of_at_least_4": shifted_runs,
        "misaligned_slots_addressing_executable_sections": shifted_slots,
        "ratio": (round(shifted_runs / aligned_runs, 4) if aligned_runs else None),
        "result": ("REFUTATION FAILED (the population survives): the misaligned "
                   "scan finds %d runs against %d aligned"
                   % (shifted_runs, aligned_runs)) if shifted_runs < aligned_runs \
            else ("REFUTATION SUCCEEDED: the misaligned scan finds at least as "
                  "many runs as the aligned one, so the alignment is carrying no "
                  "information and the candidate population must not be relied on"),
    })

    # 2. Known non-vtable tables. The image itself declares ranges of code
    #    pointers that are not vtables. If many candidates -- and especially many
    #    code-stored candidates -- fell inside them, the tiering would be
    #    measuring something other than what it claims.
    overlapping = Counter()
    for candidate in candidates:
        kind = table_lookup(candidate["vtable_rva"], candidate["slot_count"],
                            pointer_size)
        if kind:
            overlapping[(kind, candidate["tier"])] += 1
    probes.append({
        "probe": "declared non-vtable pointer tables",
        "what_would_refute": (
            "the import, delay-import and TLS directories declare ranges of "
            "pointer-width slots that are not vtables. A large overlap with the "
            "code-stored tier would show the tier is not selecting what it claims"),
        "tables_found": len(tables),
        "table_kinds": sorted({t["kind"] for t in tables}),
        "overlapping_candidates": {"%s/%s" % (kind, tier): count
                                   for (kind, tier), count
                                   in sorted(overlapping.items())},
        "overlapping_total": sum(overlapping.values()),
        "result": ("%d candidates overlap a declared non-vtable table; they are "
                   "FLAGGED in their rows and left in the population, because "
                   "deleting a counter-example is how a scanner starts agreeing "
                   "with itself" % sum(overlapping.values())),
    })

    # 3. Degenerate candidates. A run of identical pointers is a filled array,
    #    not a vtable, and a candidate whose every slot is the same value would
    #    be a false positive this tool ought to be able to see.
    degenerate = [c for c in candidates
                  if c["slot_count"] >= 4 and len(set(c["slot_target_rvas"])) == 1]
    probes.append({
        "probe": "degenerate candidates (all slots identical)",
        "what_would_refute": (
            "a candidate of 4 or more slots all holding the SAME address is a "
            "filled array, not a vtable. A large count would mean the run rule is "
            "picking up initialised tables in bulk"),
        "candidates_of_4_or_more_slots": sum(1 for c in candidates
                                             if c["slot_count"] >= 4),
        "degenerate": len(degenerate),
        "degenerate_by_tier": dict(sorted(Counter(
            c["tier"] for c in degenerate).items())),
        "examples": [{"vtable_rva": c["vtable_rva"], "slot_count": c["slot_count"],
                      "target_rva": c["slot_target_rvas"][0]}
                     for c in _spread(degenerate, 4)],
    })

    # 4. The relocation filter has to earn its place. If it rejected nothing, it
    #    would be a claim about method with no measurement behind it.
    rejected = run_stats["slots_addressing_executable_not_relocated"]
    probes.append({
        "probe": "does the relocation filter do anything",
        "what_would_refute": (
            "if the relocation table rejected no code-addressing slot at all, the "
            "filter would be a claim about method with nothing behind it, and the "
            "difference between this tool and a plain run-length census would be "
            "smaller than stated"),
        "code_addressing_slots": run_stats["slots_addressing_executable_sections"],
        "rejected_as_not_relocated": rejected,
        "examples": run_stats[
            "code_addressing_slots_rejected_by_relocation_filter_examples"][:6],
        "result": ("the filter rejects %d of %d code-addressing slots"
                   % (rejected, run_stats["slots_addressing_executable_sections"])),
    })

    # 5. The positional premise. Every positional statement in the output --
    #    clusters, nearest literal -- depends on candidates being laid out in an
    #    order that means something. Without the RTTI artifact this cannot be
    #    tested, and the probe says so instead of quietly passing.
    clusters = (statistics.get("clusters") or {}).get(TIER_STORED) or {}
    probes.append({
        "probe": "positional premise",
        "what_would_refute": (
            "if candidates were scattered rather than grouped, the cluster and "
            "nearest-literal fields would carry no information. The decisive test "
            "needs known owners and therefore needs --rtti-json; see "
            "cross_check.owner_adjacency"),
        "code_stored_candidates": clusters.get("candidates"),
        "clusters": clusters.get("clusters"),
        "candidates_in_a_cluster_of_2_or_more":
            clusters.get("candidates_in_a_cluster_of_2_or_more"),
        "decisive_test_available": None,
    })
    return probes


# --------------------------------------------------------------------------- #
# analysis
# --------------------------------------------------------------------------- #

def analyze(path: str, *, sections: tuple[str, ...] | None = None,
            skip_sections: tuple[str, ...] = DEFAULT_SKIP_SECTIONS,
            use_relocation_filter: bool = True,
            use_code_references: bool = True,
            want_source_paths: bool = True,
            rtti_json: str | None = None,
            literal_samples: int = DEFAULT_LITERAL_SAMPLES,
            sample_rows: int = DEFAULT_SAMPLE_ROWS,
            want_file_digest: bool = True,
            install_root: str | None = None) -> dict:
    """The whole scan, as one document. Read-only from first byte to last."""
    warnings: list[str] = []
    timings: dict[str, float] = {}
    started = time.monotonic()

    def lap(name: str) -> None:
        timings[name] = round(time.monotonic() - started - sum(timings.values()), 3)

    with pe_info.Image.open(path) as image:
        headers = pe_info.PEHeaders(image)
        warnings.extend(headers.warnings)
        address = AddressModel(headers)
        chosen, excluded = select_surface(headers, sections, skip_sections)
        if not chosen:
            warnings.append("no section was selected for the scan; every count "
                            "below is a statement about an empty surface")
        surface = Surface(chosen, headers.pointer_size)
        if surface.total_slots > MAX_SURFACE_SLOTS:
            raise PEFormatError(
                "the selected surface holds %d slots, above the %d cap"
                % (surface.total_slots, MAX_SURFACE_SLOTS))
        surface.load(image, warnings)
        lap("load_surface")

        relocations = parse_base_relocations(image, headers, surface, warnings)
        lap("relocations")
        if use_relocation_filter and not relocations["summary"]["usable"]:
            use_relocation_filter = False
            warnings.append(
                "the relocation filter was requested but this image gives it "
                "nothing to work with; it is switched off and every code-"
                "addressing slot is kept. Candidate precision is lower than the "
                "documented figures, which were measured with the filter on")

        runtime = parse_runtime_functions(headers, warnings)
        functions = FunctionIndex(runtime["starts"], runtime["ends"])
        lap("runtime_functions")

        code_sections = [s for s in headers.sections
                         if s["rsize"] > 0
                         and s["characteristics"] & (IMAGE_SCN_MEM_EXECUTE
                                                     | IMAGE_SCN_CNT_CODE)]
        if use_code_references and not code_sections:
            use_code_references = False
            warnings.append("no executable section has raw bytes on disk, so no "
                            "code reference can be found and every candidate "
                            "falls in the unreferenced tier")
        if use_code_references:
            references = scan_code_references(image, headers, address, surface,
                                             code_sections, warnings)
        else:
            references = {"summary": {"skipped": True},
                          "lea": surface.new_byte_bitmaps(),
                          "store": surface.new_byte_bitmaps()}
        lap("code_references")

        runs = scan_runs(surface, address, relocations["bitmaps"],
                         use_relocation_filter, warnings)
        lap("runs")

        candidates, segmentation = segment_runs(
            surface, runs["runs"], runs["targets"], references["lea"],
            references["store"], use_code_references, warnings)
        lap("segmentation")

        tables = known_pointer_tables(headers, warnings)
        table_lookup = build_table_lookup(tables)

        locator_count = 0
        for candidate in candidates:
            candidate.update(classify_prior_slot(surface, address,
                                                 relocations["bitmaps"], candidate))
            if candidate["rtti_locator_rva"] is not None:
                locator_count += 1
            candidate["overlaps_declared_table"] = table_lookup(
                candidate["vtable_rva"], candidate["slot_count"],
                headers.pointer_size)
            candidate["slot_targets_at_function_starts"] = sum(
                1 for target in candidate["slot_target_rvas"]
                if functions.is_start(target))
            candidate["distinct_slot_targets"] = len(set(candidate["slot_target_rvas"]))
            found = surface.locate(candidate["vtable_rva"])
            candidate["section"] = found[0]["name"] if found else None
            candidate["file_offset"] = (found[0]["raw_pointer"] + found[1]
                                        if found else None)
        lap("prior_slots")

        literals = find_source_path_literals(image, surface, warnings) \
            if want_source_paths else []
        lap("source_path_literals")

        statistics = build_statistics(candidates, surface, functions, literals,
                                      headers.pointer_size)
        literal_rvas = [row["rva"] for row in literals]
        for candidate in candidates:
            candidate.update(nearest_literal(literal_rvas, literals,
                                             candidate["vtable_rva"]))

        if want_source_paths and use_code_references and literals:
            wanted = {row["rva"] for row in literals}
            wanted |= {c["vtable_rva"] for c in candidates
                       if c["tier"] in (TIER_STORED, TIER_REFERENCED)}
            sites = collect_reference_sites(image, address, code_sections, wanted,
                                            warnings)
            statistics["source_path_same_function_join"] = \
                source_path_same_function_join(candidates, literals, sites,
                                               functions, sample_rows)
            for candidate in candidates:
                candidate["reference_site_rvas"] = list(
                    sites.get(candidate["vtable_rva"], ()))
        else:
            statistics["source_path_same_function_join"] = {
                "skipped": True,
                "reason": ("the join needs both the source-path literals and the "
                           "code-reference pass"),
            }
            for candidate in candidates:
                candidate["reference_site_rvas"] = []
        lap("source_path_join")

        probes = build_refutation_probes(surface, address, relocations["bitmaps"],
                                        candidates, runs["summary"], tables,
                                        table_lookup, statistics)
        cross_check = None
        if rtti_json:
            cross_check = cross_check_rtti(rtti_json, candidates, runs["summary"],
                                           locator_count, warnings)
            for probe in probes:
                if probe["probe"] == "positional premise":
                    adjacency = (cross_check or {}).get("owner_adjacency") or {}
                    probe["decisive_test_available"] = bool(adjacency)
                    probe["observed_same_owner_rate"] = adjacency.get("observed_rate")
                    probe["chance_same_owner_rate"] = \
                        adjacency.get("chance_rate_from_owner_frequencies")
                    observed = adjacency.get("observed_rate")
                    chance = adjacency.get("chance_rate_from_owner_frequencies")
                    if observed is not None and chance is not None:
                        probe["result"] = (
                            "REFUTATION FAILED (the premise holds): adjacent "
                            "vtables share an owner at %.3f against a chance rate "
                            "of %.3f" % (observed, chance)) if observed > chance \
                            else ("REFUTATION SUCCEEDED: adjacency carries no more "
                                  "information than chance, so nothing positional "
                                  "in this output may be read as evidence")
        lap("probes")

        # -- class-P layer -------------------------------------------------- #
        target = locus_target(path, install_root)
        sampled = _spread([c for c in candidates if c["tier"] == TIER_STORED]
                          or candidates, literal_samples)
        literal_reads = []
        for candidate in sampled:
            if candidate["file_offset"] is None:
                continue
            length = min(candidate["slot_count"], 4) * headers.pointer_size
            raw = image.read_at(candidate["file_offset"], length,
                                "candidate literal read")
            literal_reads.append(literal_read(
                target, "candidate@%d" % candidate["vtable_rva"],
                candidate["file_offset"], raw,
                note=("one range inside the surface named in tested_surface; the "
                      "interpretive half is the candidate row with the same RVA")))
        reproduced = confirm_literal_reads(path, literal_reads, target, warnings)
        lap("literal_reads")

        digest = None
        if want_file_digest:
            digest = _sha256(image)
        lap("digest")

    second_method = None
    if cross_check and cross_check.get("readable"):
        known = cross_check.get("known_vtables") or {}
        if known.get("in_the_rtti_artifact"):
            second_method = (
                "the MSVC RTTI graph, walked by tools/static/rtti_scan.py from the "
                "decorated-name side, reaches %d vtables in this image; %d of them "
                "are recovered here from the pointer-run side with %d slot-count "
                "disagreements. The two methods share no code and no starting "
                "point -- one starts at '.?A' name strings, the other at "
                "relocation fixups -- so the agreement is a genuine second method "
                "and not a re-read"
                % (known["in_the_rtti_artifact"], known["recovered_as_a_candidate"],
                   known["slot_count_disagreements"]))

    document = {
        "task": "S-09",
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
        "generated_at": now_iso_utc(),
        "d04_oracle_only": _is_d04_oracle(path),
        "file": {
            "path": os.path.abspath(path),
            "name": os.path.basename(path),
            "install_relative": target,
            "size": os.path.getsize(path),
            "sha256": digest,
            "pe_format": headers.pe_format,
            "machine": headers.machine,
            "image_base": headers.image_base,
            "size_of_image": headers.size_of_image,
            "pointer_size": headers.pointer_size,
        },
        "tested_surface": {
            "sections_scanned": describe_sections(chosen),
            "sections_not_scanned": excluded,
            "executable_sections": [s["name"] for s in code_sections],
            "slot_alignment": headers.pointer_size,
            "slots_in_surface": surface.total_slots,
            "bytes_in_surface": sum(s["rsize"] for s in chosen),
            "not_tested": [
                "a section with no raw bytes holds nothing on disk and cannot be "
                "searched",
                "the virtual tail of a section (vsize beyond rsize) is zero-filled "
                "by the loader and is not on disk",
                "code generated or unpacked at run time is out of scope: only the "
                "on-disk image is read",
                "a vtable whose slots the loader patches by a mechanism other than "
                "a base relocation would be missed by the relocation filter",
            ],
        },
        "relocations": relocations["summary"],
        "runtime_functions": runtime["summary"],
        "code_references": references["summary"],
        "slot_scan": runs["summary"],
        "segmentation": segmentation,
        "declared_pointer_tables": tables,
        "source_path_literals": {
            "scanned": want_source_paths,
            "pattern": SOURCE_PATH_RE.pattern.decode("ascii", "replace"),
            "count": len(literals),
            "rva_span": ([literals[0]["rva"], literals[-1]["rva"]]
                         if literals else None),
            "sections": dict(sorted(Counter(r["section"] for r in literals).items())),
            "sample": _spread([{"rva": r["rva"], "path": r["path"]}
                               for r in literals], sample_rows),
        },
        "statistics": statistics,
        "candidate_sample": [_public_candidate(c)
                             for c in _spread(candidates, sample_rows)],
        "refutation_probes": probes,
        "cross_check": cross_check,
        "literal_reads": literal_reads,
        "interpreted_annotation": interpreted_annotation(target, second_method),
        "summary": _summary(candidates, locator_count, runs["summary"],
                            segmentation, statistics, cross_check, reproduced),
        "timings_seconds": timings,
        "warnings": warnings,
    }
    document["candidates_total"] = len(candidates)
    document["_candidates"] = candidates          # for jsonl_lines; not serialised
    return document


def _sha256(image) -> str:
    """Whole-file digest, streamed.

    ``pe_info.PEImage.iter_chunks`` yields ``(chunk_offset, memoryview)`` pairs
    (tools/fingerprint/pe_info.py:589), not bare buffers. Unpacking the pair is
    not a style choice: feeding the tuple to ``digest.update`` raises TypeError,
    which is exactly how this was found -- the first execution of this tool.
    """
    digest = hashlib.sha256()
    for _position, chunk in image.iter_chunks(0, image.size):
        digest.update(chunk)
    return digest.hexdigest()


def _is_d04_oracle(path: str) -> bool:
    """True for the second, 282 MB MISERY.exe -- decision D-04's read-only oracle."""
    normalised = os.path.abspath(path).replace("\\", "/").lower()
    return normalised.endswith("/binaries/win64/misery.exe")


def _public_candidate(candidate: dict) -> dict:
    """One candidate row with the bulk field dropped and the counts kept.

    ``slot_target_rvas`` is the largest thing in the run -- 4 428 entries for the
    RTTI-bearing vtables alone -- and every question the document asks of it is
    already answered by a count next to it. The full target list stays in the
    JSONL rows, where a joiner can use it.
    """
    row = {k: v for k, v in candidate.items() if k != "slot_target_rvas"}
    row["slot_target_rvas_first"] = (candidate["slot_target_rvas"][0]
                                     if candidate["slot_target_rvas"] else None)
    return row


def _summary(candidates: list[dict], locator_count: int, run_stats: dict,
             segmentation: dict, statistics: dict, cross_check: dict | None,
             reproduced: bool) -> dict:
    by_tier = Counter(c["tier"] for c in candidates)
    stored = [c for c in candidates if c["tier"] == TIER_STORED]
    referenced = [c for c in candidates if c["tier"] == TIER_REFERENCED]
    out = {
        "candidates_total": len(candidates),
        "candidates_by_tier": {tier: by_tier.get(tier, 0) for tier in TIER_ORDER},
        "candidates_code_stored": len(stored),
        "candidates_code_stored_with_2_or_more_slots":
            sum(1 for c in stored if c["slot_count"] >= 2),
        "candidates_code_referenced_or_stored": len(stored) + len(referenced),
        "raw_runs": run_stats["runs"],
        "interior_cut_points": segmentation["interior_cut_points"],
        "slots_addressing_executable_sections":
            run_stats["slots_addressing_executable_sections"],
        "slots_addressing_executable_and_relocated":
            run_stats["slots_addressing_executable_and_relocated"],
        "census_without_relocation_filter":
            run_stats["census_without_relocation_filter"]["runs_by_minimum_length"],
        "candidates_with_an_rtti_complete_object_locator": locator_count,
        "candidates_without_an_rtti_complete_object_locator":
            len(candidates) - locator_count,
        "code_stored_without_an_rtti_locator":
            sum(1 for c in stored if c["rtti_locator_rva"] is None),
        "literal_reads_reproduced": reproduced,
        "primary_estimate": (
            "the defensible vtable population of this image is the %d candidates "
            "in the code-stored tier: a relocated run of code addresses whose first "
            "address a constructor-shaped instruction pair writes into an object. "
            "Recall for that tier, measured against the RTTI-reachable vtables, is "
            "reported in cross_check; precision is not measurable on this file and "
            "is measured on a control binary instead (research/evidence/S-09/)."
            % len(stored)),
    }
    if cross_check and cross_check.get("readable"):
        known = cross_check.get("known_vtables") or {}
        out["cross_check_recall"] = known.get("recall")
        out["cross_check_recall_code_stored"] = known.get("recall_code_stored")
        out["cross_check_slot_count_disagreements"] = \
            known.get("slot_count_disagreements")
        out["cross_check_census_agrees"] = (cross_check.get("census") or {}).get(
            "runs_agree")
    return out


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def jsonl_lines(document: dict, tiers: tuple[str, ...], min_slots: int) -> list[str]:
    """The ``vtables.jsonl`` artifact of plan.md S-09: one JSON object per candidate.

    Flat and joinable: this is what the rest of section 7 will join against, so
    it carries the facts and not the evidence apparatus. The grading lives once,
    in the full document. What it does carry is the tier and the flags, because a
    consumer that cannot see which candidates are weak will treat them all as
    strong.
    """
    lines = []
    name = document["file"]["install_relative"]
    for candidate in document["_candidates"]:
        if candidate["tier"] not in tiers or candidate["slot_count"] < min_slots:
            continue
        lines.append(json.dumps({
            "build_target": name,
            "vtable_rva": candidate["vtable_rva"],
            "file_offset": candidate["file_offset"],
            "section": candidate["section"],
            "slot_count": candidate["slot_count"],
            "tier": candidate["tier"],
            "is_run_start": candidate["is_run_start"],
            "run_rva": candidate["run_rva"],
            "run_slot_count": candidate["run_slot_count"],
            "distinct_slot_targets": candidate["distinct_slot_targets"],
            "slot_targets_at_function_starts":
                candidate["slot_targets_at_function_starts"],
            "slot_target_rvas": list(candidate["slot_target_rvas"]),
            "prior_slot_kind": candidate["prior_slot_kind"],
            "rtti_locator_rva": candidate["rtti_locator_rva"],
            "overlaps_declared_table": candidate["overlaps_declared_table"],
            "reference_site_rvas": candidate["reference_site_rvas"],
            "nearest_source_path": candidate["nearest_source_path"],
            "nearest_source_path_distance": candidate["nearest_source_path_distance"],
        }, sort_keys=True, ensure_ascii=False))
    return lines


def public_document(document: dict) -> dict:
    """The document minus the internal join field, ready to serialise."""
    return {k: v for k, v in document.items() if not k.startswith("_")}


def format_summary(document: dict) -> str:
    out: list[str] = []
    add = out.append
    summary = document["summary"]
    file_info = document["file"]

    add("%s (%s %s)" % (file_info["path"], GENERATOR_NAME, GENERATOR_VERSION))
    add("  %s, image base 0x%x, %d bytes on disk"
        % (file_info["pe_format"], file_info["image_base"], file_info["size"]))
    if document["d04_oracle_only"]:
        add("  D-04: this file is the read-only ORACLE. Any conclusion drawn here "
            "must be re-verified on MISERY-Win64-Shipping.exe before it counts.")
    add("")
    add("Tested surface")
    for section in document["tested_surface"]["sections_scanned"]:
        add("  %-10s file [%d, %d)  %d bytes"
            % (section["name"], section["file_offset"],
               section["file_offset"] + section["raw_size"], section["raw_size"]))
    add("  not scanned: %s"
        % (", ".join(document["tested_surface"]["sections_not_scanned"]) or "none"))
    add("  %d slots at alignment %d"
        % (document["tested_surface"]["slots_in_surface"],
           document["tested_surface"]["slot_alignment"]))
    add("")
    add("Slots and runs")
    scan = document["slot_scan"]
    add("  slots examined                       : %d" % scan["slots_examined"])
    add("  addressing executable sections       : %d"
        % scan["slots_addressing_executable_sections"])
    add("  ... and carrying a relocation fixup  : %d"
        % scan["slots_addressing_executable_and_relocated"])
    add("  ... and NOT relocated (not pointers) : %d"
        % scan["slots_addressing_executable_not_relocated"])
    add("  raw runs                             : %d" % scan["runs"])
    add("  interior cut points (runs split)     : %d"
        % document["segmentation"]["interior_cut_points"])
    census = scan["census_without_relocation_filter"]["runs_by_minimum_length"]
    add("  census without the fixup filter      : >=4 %s, >=8 %s, >=16 %s"
        % (census.get("4"), census.get("8"), census.get("16")))
    add("")
    add("Candidates")
    for tier in TIER_ORDER:
        tier_stats = document["statistics"]["by_tier"][tier]
        add("  %-16s %6d  (>=2 slots %6d)  slots %8d  median %s  max %s"
            % (tier, tier_stats["candidates"],
               tier_stats["candidates_with_at_least_2_slots"],
               tier_stats["slot_total"],
               tier_stats["slot_count_percentiles"]["50"],
               tier_stats["slot_count_max"]))
    add("  with an RTTI complete-object-locator : %d"
        % summary["candidates_with_an_rtti_complete_object_locator"])
    add("  without one                          : %d"
        % summary["candidates_without_an_rtti_complete_object_locator"])
    add("  code-stored without one              : %d"
        % summary["code_stored_without_an_rtti_locator"])
    shared = document["statistics"]["shared_slot_targets"]
    add("")
    add("Population")
    add("  distinct slot targets                : %d" % shared["distinct_slot_targets"])
    add("  targets used by >1 candidate         : %d (%s)"
        % (shared["targets_used_by_more_than_one_candidate"],
           shared["share_of_targets_that_are_shared"]))
    starts = document["statistics"]["slot_targets_at_function_starts"]
    add("  slot targets at a function start     : %d of %d (%s)"
        % (starts["at_a_runtime_function_start"], starts["slots"], starts["share"]))
    clusters = document["statistics"]["clusters"][TIER_STORED]
    add("  code-stored clusters (back to back)  : %d for %d candidates, largest %s"
        % (clusters["clusters"], clusters["candidates"], clusters["largest_cluster"]))
    relation = document["statistics"]["source_path_relation"]
    add("  UE source-path literals              : %d, median distance %s bytes"
        % (relation["literals"], relation["distance_percentiles"]["50"]))
    join = document["statistics"].get("source_path_same_function_join") or {}
    if join.get("skipped"):
        add("  same-function join                   : skipped")
    else:
        add("  same-function join                   : %d of %d candidates"
            % (join["candidates_joined_to_a_source_path"],
               join["candidates_considered"]))
    split = document["statistics"].get("rtti_split")
    if split:
        add("")
        add("The population WITHOUT an RTTI locator, against the one with")
        add("  %-36s %12s %12s" % ("", "with RTTI", "no RTTI"))
        rows = (
            ("candidates", "candidates"),
            ("slots, median", None),
            ("slots, 90th percentile", None),
            ("slots, max", "slot_count_max"),
            ("distinct slot targets", "distinct_slot_targets"),
            ("share of targets shared", "share_of_targets_that_are_shared"),
            ("share of slots at a function start", "share_of_slots_at_a_function_start"),
            ("contiguous runs [confounded, see below]", "contiguous_runs"),
            ("largest contiguous run [confounded]", "largest_contiguous_run"),
        )
        left = split["with_an_rtti_locator"]
        right = split["without_an_rtti_locator"]
        for label, key in rows:
            if key is None:
                point = "50" if "median" in label else "90"
                a = left["slot_count_percentiles"][point]
                b = right["slot_count_percentiles"][point]
            else:
                a, b = left[key], right[key]
            add("  %-36s %12s %12s" % (label, a, b))
        stored = split["by_tier"][TIER_STORED]
        add("  code-stored tier only                %12d %12d"
            % (stored["with_an_rtti_locator"]["candidates"],
               stored["without_an_rtti_locator"]["candidates"]))
        add("  [confounded] an RTTI vtable always carries its locator pointer in "
            "the slot before it,")
        add("               so two of them can never be adjacent under this "
            "definition. The")
        add("               contiguity gap across the split is an artefact and "
            "means nothing.")
        link = split["cross_link"]
        add("  no-locator candidates sharing a slot target with a named vtable: "
            "%d (%s), over %d distinct targets"
            % (link["candidates_without_a_locator_sharing_a_slot_target_with_a_named_vtable"],
               link["share_of_the_no_locator_population"],
               link["distinct_shared_targets"]))

    if document["cross_check"] and document["cross_check"].get("readable"):
        check = document["cross_check"]
        known = check["known_vtables"]
        add("")
        add("Cross-check against %s" % check["artifact"])
        add("  census slots agree                   : %s"
            % check["census"]["slots_agree"])
        add("  census runs agree (4/8/16)           : %s"
            % check["census"]["runs_agree"])
        add("  known vtables recovered              : %d of %d (recall %s)"
            % (known["recovered_as_a_candidate"], known["in_the_rtti_artifact"],
               known["recall"]))
        add("  slot-count disagreements             : %d"
            % known["slot_count_disagreements"])
        add("  recall, code-stored tier only        : %s"
            % known["recall_code_stored"])
        locator = check["independent_rtti_locator_count"]
        add("  RTTI locators, vtable side vs names  : %s vs %s (agree %s)"
            % (locator["found_from_the_vtable_side"],
               locator["found_by_rtti_scan_from_the_name_side"], locator["agree"]))
        adjacency = check["owner_adjacency"]
        add("  adjacent vtables share an owner      : %s (chance %s)"
            % (adjacency["observed_rate"],
               adjacency["chance_rate_from_owner_frequencies"]))
    add("")
    add("Refutation probes")
    for probe in document["refutation_probes"]:
        add("  %s" % probe["probe"])
        if probe.get("result"):
            add("    %s" % probe["result"])
    add("")
    add("Literal reads (class P): %d ranges, all re-read through a second handle: %s"
        % (len(document["literal_reads"]),
           "reproduced" if all(r.get("reproduced") for r in document["literal_reads"])
           else "AT LEAST ONE DID NOT REPRODUCE"))
    add("Timings (s): %s" % json.dumps(document["timings_seconds"], sort_keys=True))
    if document["warnings"]:
        add("")
        add("Warnings")
        for line in document["warnings"]:
            add("  %s" % line)
    return "\n".join(out)


def write_text(text: str, out_path: str, install_root: str, what: str) -> str:
    """Write *text* to *out_path*, refusing any path inside an installation.

    The guard runs before the file is opened, so a refused path leaves nothing
    behind -- not even a truncated file.
    """
    target = pathguard.check_output_path(out_path, install_root, what=what)
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return target


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vtable_scan.py",
        description=(
            "Read-only vtable census for a PE image (plan.md task S-09). Prints a "
            "human summary by default; --json prints the machine-readable "
            "document. Refuses any output path that resolves inside a game "
            "installation (D-01)."),
    )
    parser.add_argument("path", help="the PE image to read (opened read-only)")
    parser.add_argument("--json", action="store_true",
                        help="print the JSON document instead of the summary")
    parser.add_argument("--jsonl", action="store_true",
                        help="print the per-candidate JSONL artifact to stdout")
    parser.add_argument("--out", default=None,
                        help=("write the JSON document here; refused (exit 2) if it "
                              "resolves inside a game installation, before "
                              "anything is opened"))
    parser.add_argument("--jsonl-out", default=None,
                        help="write the per-candidate vtables.jsonl artifact here")
    parser.add_argument("--install-dir", default=None,
                        help=("installation root the output guard checks against "
                              "(default: auto-detected from the input path)"))
    parser.add_argument("--sections", default=None, metavar="A,B",
                        help=("comma-separated section names to scan (default: "
                              "every section with raw data that is not executable "
                              "and not %s)" % "/".join(DEFAULT_SKIP_SECTIONS)))
    parser.add_argument("--tiers", default=TIER_STORED, metavar="T,T",
                        help=("which tiers the JSONL artifact carries (default: "
                              "%s; 'all' for every tier)" % TIER_STORED))
    parser.add_argument("--min-slots", type=int, default=1, metavar="N",
                        help="drop JSONL rows with fewer than N slots (default: 1)")
    parser.add_argument("--rtti-json", default=None, metavar="FILE",
                        help=("an rtti_scan.py document for the same image; enables "
                              "the mechanical cross-check and the owner-adjacency "
                              "premise test"))
    parser.add_argument("--no-relocation-filter", action="store_true",
                        help=("keep code-addressing slots that carry no relocation "
                              "fixup; this reproduces the run definition "
                              "rtti_scan.py's internal census uses"))
    parser.add_argument("--no-code-references", action="store_true",
                        help=("skip the instruction scan; every candidate is then a "
                              "whole run in the unreferenced tier"))
    parser.add_argument("--no-source-paths", action="store_true",
                        help="skip the Unreal source-path literal scan and the join")
    parser.add_argument("--literal-samples", type=int,
                        default=DEFAULT_LITERAL_SAMPLES, metavar="N",
                        help=("how many evenly spaced candidates to record as "
                              "class-P literal reads (default: %d)"
                              % DEFAULT_LITERAL_SAMPLES))
    parser.add_argument("--sample-rows", type=int, default=DEFAULT_SAMPLE_ROWS,
                        metavar="N",
                        help="how many rows each in-document sample carries")
    parser.add_argument("--no-digest", action="store_true",
                        help="skip the whole-file sha256")
    return parser


def _split_sections(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _split_tiers(value: str) -> tuple[str, ...]:
    if value.strip().lower() == "all":
        return TIER_ORDER
    wanted = tuple(part.strip() for part in value.split(",") if part.strip())
    return tuple(t for t in TIER_ORDER if t in wanted)


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not os.path.isfile(args.path):
        print("error: not a file: %s" % args.path, file=sys.stderr)
        return 2
    if args.literal_samples < 0 or args.sample_rows < 0 or args.min_slots < 0:
        print("error: --literal-samples, --sample-rows and --min-slots must not "
              "be negative", file=sys.stderr)
        return 2
    tiers = _split_tiers(args.tiers)
    if not tiers:
        print("error: --tiers selected no known tier; known tiers are %s"
              % ", ".join(TIER_ORDER), file=sys.stderr)
        return 2

    install_root = args.install_dir or pe_info.detect_install_root(args.path)

    # Layer 1 (plan.md 1.5 / D-01) is checked before any parsing, so a refused
    # path costs nothing and leaves nothing behind. write_text checks again.
    checked: dict[str, str] = {}
    for flag, value in (("--out", args.out), ("--jsonl-out", args.jsonl_out)):
        if not value:
            continue
        try:
            checked[flag] = pathguard.check_output_path(value, install_root,
                                                       what=flag)
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2

    try:
        document = analyze(
            args.path,
            sections=_split_sections(args.sections),
            use_relocation_filter=not args.no_relocation_filter,
            use_code_references=not args.no_code_references,
            want_source_paths=not args.no_source_paths,
            rtti_json=args.rtti_json,
            literal_samples=args.literal_samples,
            sample_rows=args.sample_rows,
            want_file_digest=not args.no_digest,
            # Only an EXPLICIT root is passed on: the fallback inside
            # detect_install_root is "the configured root", which would make a
            # file outside any installation look relative to one it is not in.
            install_root=args.install_dir,
        )
    except PEFormatError as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2
    except OSError as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2

    written: list[str] = []
    try:
        if "--out" in checked:
            written.append(write_text(dump_json(public_document(document)),
                                      checked["--out"], install_root, "--out"))
        if "--jsonl-out" in checked:
            body = "".join(line + "\n" for line
                           in jsonl_lines(document, tiers, args.min_slots))
            written.append(write_text(body, checked["--jsonl-out"], install_root,
                                      "--jsonl-out"))
    except pathguard.OutputPathRefused as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except OSError as error:
        print("error: cannot write: %s" % error, file=sys.stderr)
        return 2

    if args.json:
        sys.stdout.write(dump_json(public_document(document)))
    elif args.jsonl:
        for line in jsonl_lines(document, tiers, args.min_slots):
            sys.stdout.write(line + "\n")
    else:
        print(format_summary(document))
        for path in written:
            print("\nwritten: %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
