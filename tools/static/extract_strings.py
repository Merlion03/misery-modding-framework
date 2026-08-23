#!/usr/bin/env python3
"""Read-only ASCII / UTF-16LE string index for a PE image (plan.md task S-01).

The question this tool exists to answer
---------------------------------------
plan.md 7.3 row S-01 asks for "extraction of ASCII/UTF-16 strings with offsets
and RVA" producing ``strings.jsonl``. That understates what the artifact is for.
Every later task in section 7 -- the xref hunt, the signature work, the
candidate search for ``GUObjectArray`` / ``FName pool`` / ``ProcessEvent`` /
``GEngine`` -- starts by finding a *string* and following the references to it.
An index that silently drops a token, or that reports an offset a reader cannot
act on, does not slow those tasks down: it makes them look up an answer that is
not there and conclude the answer does not exist.

So this tool is written for RECALL and for HONEST ADDRESSES, in that order, and
speed comes third. Concretely:

* nothing is dropped for being short. Short runs are emitted with a flag that
  says which noise band they fall in, and the size of that band is MEASURED
  rather than asserted -- see the noise control below.
* a byte offset that has no run-time address says so. It never gets a
  plausible-looking wrong RVA.
* the whole file is covered. Not "the sections we thought were interesting":
  every byte of the file belongs to exactly one region, the regions tile
  ``[0, file_size)`` with no gap and no overlap, and the tiling is checked as a
  refutation probe on every run. A null result over a named surface is a
  finding; a null result over an unknown surface is nothing at all.

The three decisions that change what later research can find
------------------------------------------------------------
1. MINIMUM LENGTH. Default 4 characters, not the conventional 8.

   ``strings(1)`` defaults to 4 and ``strings -n 8`` is the habit; both are
   guesses. The tokens this project needs sit on both sides of that line:
   ``/Script/`` is exactly 8 characters, ``Link``, ``Core``, ``Tick``, ``r.``
   prefixed console variables and the four-character chunk tags UE writes into
   its own containers are 4 or fewer. Setting the floor at 8 would lose them
   silently, and "silently" is the problem -- a later xref hunt for ``Link``
   would come back empty and read as evidence.

   The price of 4 is noise, and the price is large: on the 134 MB Shipping image
   roughly three quarters of all ASCII hits are exactly 4 characters long and
   almost all of those are incidental byte runs inside ``.text``. The answer is
   NOT to raise the floor. It is to emit the short runs with ``noise_band:
   true`` and to publish, per length, how many hits a same-size buffer of
   uniform pseudo-random bytes produces (``--noise-control``, on by default).
   That turns "length 4 is noisy" from an opinion into a ratio a reader can
   check, and it lets a consumer of ``strings.jsonl`` choose its own floor
   without rescanning 134 MB.

   ``NOISE_BAND_CEILING_ASCII`` is 10 rather than 8 because that is where the
   measurement puts the crossover, not where tradition puts it: at length 8 the
   uniform-random expectation for this image is the same order of magnitude as
   the observed count, at length 9 it is a third of it, and by length 12 it is a
   thirtieth. A flag drawn at 8 would have called a noise-dominated band clean.

2. UTF-16LE WITHOUT FABRICATION. Three rules, and each one has a stated cost.

   The shape of a UTF-16LE string whose characters are all ASCII is a run of
   ``(printable, 0x00)`` pairs. So is an array of ``uint16`` whose values all
   happen to fall in ``0x20..0x7E``, and no amount of cleverness distinguishes
   those two from the bytes alone -- they are the same bytes. What can be done
   is to state a rule, publish what the rule rejects, and publish enough per
   record that a consumer can tighten the rule without rescanning:

   (a) MINIMUM 4 CODE UNITS. Unlike the ASCII case this floor costs almost
       nothing, and the noise control is what says so: the per-2-byte
       probability of a ``(printable, 0x00)`` pair in uniform random data is
       about 0.0015, so a run of four is expected roughly 3e-4 times in a 134 MB
       buffer. UTF-16 runs are therefore never uniform-random noise. Every false
       positive here is STRUCTURED data, which is a different risk and needs a
       different control -- see (c).

   (b) EVEN ALIGNMENT ONLY. A candidate is accepted only when its start is at an
       even image offset (equivalently an even RVA: section RVAs are
       section-alignment multiples, so parity inside a section is the same in
       both views). A ``wchar_t`` array in a C++ image is 2-byte aligned by the
       language, so an odd-aligned printable-wide run is the misread tail of some
       other structure -- for instance ``00 41 00 42 00 43 00 00`` read from one
       byte in gives "ABC", while the aligned reading of the same bytes is three
       CJK code points. THE COST: a genuinely odd-aligned UTF-16 string is
       missed. Nothing a C++ compiler emits for a string literal is odd-aligned,
       but a string inside a packed binary blob could be, and this tool would not
       see it. The number of runs rejected for parity is counted and printed, so
       the size of what the rule threw away is on the record rather than being
       taken on trust.

   (c) NO CONTENT FILTER -- MEASUREMENTS INSTEAD. The tool does not decide that a
       run "looks like a table". It publishes, per record, the count of
       alphabetic, digit and other characters, the number of distinct
       characters, whether the run is NUL-terminated, and whether the two bytes
       adjacent to it look like a wide character with a non-zero high byte (which
       is what a UTF-16 string containing a non-ASCII character looks like from
       the outside, and the one systematic way this scanner splits a real string
       into pieces). A single derived flag, ``low_information``, is set when a run
       has no alphabetic character at all or fewer than three distinct
       characters -- the shape a small-integer table has. It is a FLAG, not a
       filter: the record is still emitted with its text.

3. AN OFFSET A LATER READER CAN ACT ON. Every record carries the file offset,
   and carries an RVA only when one exists:

   * inside a section: ``rva = section.rva + (offset - raw_pointer)``, and
     ``beyond_virtual_size`` is set when the byte lies in the section's raw tail
     past ``VirtualSize``, where whether the loader maps it depends on alignment
     rounding rather than on anything in the section header;
   * inside the headers: the RVA equals the file offset, because the PE loader
     maps ``SizeOfHeaders`` bytes at the image base identically. This is a real
     mapping, not a convenience, and version-resource and section-name strings
     live there;
   * in inter-section padding, or in the overlay past the last section's raw
     data: ``rva`` is ``null`` and ``rva_absent_reason`` says which of the two it
     is. An overlay is where a self-extractor, an installer payload or a signed
     blob lives, so it is exactly the region a naive scanner mislabels.

   The translation is not re-derived here. Section geometry belongs to F-01's
   parser (``tools/fingerprint/pe_info.py``); giving this tool a second,
   differently-buggy opinion about where ``.rdata`` is would defeat the purpose of
   having one. Refutation probe P4 feeds a sample of the reported RVAs back
   through ``pe_info.PEHeaders.rva_to_offset`` and requires the original offset
   back. The sample is two populations, not one: the first and last record of
   every region, because a translation bug shows at a boundary first, and a
   decimated sample spread over the whole index, because a bug in the middle of
   one large section would touch no boundary at all. Absent RVAs are checked in
   the other direction, against the raw section table, so that declaring a byte
   unaddressable cannot hide a bug either.

Two output layers, never merged (plan.md 10.3)
----------------------------------------------
``literal_reads``
    Class **P**. A bounded, evenly spread sample of ranges, each stated as
    offset + length + raw bytes and nothing more, each re-read through a second
    independently opened handle before the record is allowed to say it
    reproduced. The ``target`` is the INSTALL-RELATIVE path, never the bare
    basename: this installation holds two different files called ``MISERY.exe``,
    so a basename names an ambiguity class rather than a place.

``findings`` / ``classification`` / ``summary``
    Class **I**. These say what the bytes MEAN -- that a run is a package path,
    that a path names an engine module, that a name belongs to the game rather
    than to the engine. Every one of those is an interpretation and is graded as
    one, separately, with its own oracle list and its own method count.

The three questions M2s actually needs, and how each is graded
--------------------------------------------------------------
``findings.script_paths``
    Which ``/Script/<Name>`` package paths occur. Two byte-level passes see this
    population independently -- the ASCII pass and the UTF-16 pass -- at
    different offsets with different predicates, so a name found by BOTH has two
    independent acts of measurement behind it and a name found by only one has
    one. The document reports the two sets separately and grades them
    separately, because averaging them would hide exactly the distinction that
    makes one of them stronger.

    What this canNOT show, and the document says so in the record: a
    ``/Script/<Module>`` literal proves the name is MENTIONED in the image. It
    does not prove the module is linked in. UE emits these strings from
    generated reflection registration, from core-redirect tables and from
    packaged config defaults, and a redirect entry for a module that no longer
    exists is exactly the kind of thing that shows up here.

``findings.engine_source_paths``
    Which build-machine source paths occur, and which engine modules AND FILES
    they name. Both granularities are published: the module list says which
    engine modules left a mark in the image, the file list says which individual
    translation units did. ``--file-query <name>`` answers a named lookup
    outright -- present or absent, with counts, module and the bound on what an
    absent answer means -- so that "is this file in the image?" is a field in the
    document rather than a grep over a two-thousand-name list.
    The module is NOT the fourth path segment -- ``Engine\\Source\\Runtime\\
    Experimental\\Chaos\\...`` and ``Engine\\Source\\Runtime\\Online\\HTTP\\...``
    would give "Experimental" and "Online", which are grouping directories. The
    module is the segment immediately before the first ``Private``, ``Public``,
    ``Classes`` or ``Internal`` component, which is the layout UnrealBuildTool
    requires. With ``--ue-source-root`` each extracted name is checked against a
    module index built from ``<Module>.build.cs`` files in the local UE tree
    (matched case-insensitively -- the engine ships both ``MRMesh.build.cs`` and
    ``Core.Build.cs``, and a case-sensitive index quietly loses the first).

``findings.origin``
    Which strings look like they belong to the game rather than to the engine or
    to a third-party library. S-10 found zero game classes in RTTI, so this may
    be the only cheap surface that names game code at all -- which is a reason to
    look, not a reason to believe the answer. Sorting strings by origin is a
    naming-convention heuristic: class I, one method, graded low and printed with
    its rule table so a reviewer can disagree with a specific rule instead of
    with a verdict. One narrow sub-claim does get a second method: a name that
    also appears as a plugin or project name in V-07's container index
    (``--v07-plugins``) or as a directory under the installation's own
    ``Plugins`` tree has been reached twice, by two different oracles.

Safety properties (plan.md 1.5, decisions D-01, D-04 and C-13)
--------------------------------------------------------------
* The target is opened ``"rb"`` and only ever read. Nothing inside a game
  installation is created, modified, moved or deleted.
* Every output path goes through ``tools/inventory/pathguard.check_output_path``
  BEFORE any file is opened, so a refused path leaves nothing behind. The guard
  is imported, never reimplemented.
* D-04: ``MISERY\\Binaries\\Win64\\MISERY.exe`` is a read-only oracle. This tool
  scans it and stamps ``"d04_oracle_only": true`` on the document, because a
  conclusion reached there must be re-verified on the Shipping binary.
* C-13: ``strings.jsonl`` for a game binary carries the binary's string table
  verbatim and MUST NOT be committed to this public repository. The tool makes
  that hard to get wrong: the JSONL is a separate ``--jsonl-out`` file, the
  summary document carries only counts, digests, the classified path/module names
  the findings actually argue from, and a bounded sample of class-P byte ranges.
  ``--jsonl-out`` prints a reminder naming the .gitignore rule.

Memory (plan.md F-04)
---------------------
Nothing is read whole and no per-record dictionary survives its window. Records
are streamed to the JSONL as they are found; what stays in memory is a set of
counters, two ``array('q')`` extent lists used for the cross-encoding overlap
count (8 bytes per hit, not a dict), and a capped table of the classified
records the findings argue from. Peak additional memory on the 134 MB target
measured well under 200 MB.

Determinism
-----------
Sorted keys, indent 2, LF, UTF-8 without BOM, trailing newline. Records are
emitted in ascending file-offset order, and where a byte range is claimed by
both encodings the ASCII record precedes the UTF-16 one. Two runs over an
unchanged file differ only in ``generated_at`` and in ``timings_seconds``.

Standard library only.

CLI
---
    python tools/static/extract_strings.py <image.exe>
    python tools/static/extract_strings.py <image.exe> --json
    python tools/static/extract_strings.py <image.exe> \\
        --out workspace/strings/x-summary.json \\
        --jsonl-out workspace/strings/x-strings.jsonl \\
        --ue-source-root "D:/Program Files/UE_5.4/Engine" \\
        --v07-plugins research/evidence/V-07/staged-plugins.json \\
        --file-query UnversionedPropertySerialization.cpp

Exit codes: 0 the scan completed (whatever it found), 2 usage / I/O error /
unparseable input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from array import array
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

# The PE layer is F-01's. Section geometry and RVA translation come from there
# so that this tool cannot hold a second opinion about where a section is.
import pe_info  # noqa: E402

GENERATOR_NAME = "tools/static/extract_strings.py"
GENERATOR_VERSION = "1.0.0"

PEFormatError = pe_info.PEFormatError


# --------------------------------------------------------------------------- #
# hard limits and tuning constants. Every one of these bounds a number that
# either comes FROM THE FILE or bounds an allocation, and none may be raised
# without thinking about what a hostile file could do with it.
# --------------------------------------------------------------------------- #

MAX_STRING_BYTES = 4096          # longest run recorded; longer runs are clipped
LOOKAHEAD = MAX_STRING_BYTES + 8  # so a run starting just before the commit
#                                   boundary is seen at its full capped extent
# Committed bytes per window. The window and its lookahead are fetched in ONE
# pe_info.Image.read_at, and that call refuses anything over MAX_SINGLE_READ, so
# the commit size is derived from the limit rather than written next to it: a
# hard-coded 8 MiB commit asks for 8 MiB + LOOKAHEAD and is refused on the first
# region large enough to need a second window. That is exactly how this was
# found -- the tool had never been run on a file over 8 MiB.
SCAN_WINDOW = pe_info.MAX_SINGLE_READ - LOOKAHEAD
DEFAULT_MIN_LENGTH = 4           # characters, not bytes -- see decision 1 above
MIN_ALLOWED_MIN_LENGTH = 1
MAX_ALLOWED_MIN_LENGTH = 256

# See decision 1. The ASCII ceiling is where the measured uniform-random
# expectation for a 134 MB image stops being the same order as the observed
# count. The UTF-16 ceiling equals the minimum length, i.e. no UTF-16 run is
# ever flagged as noise-band, because the random expectation there is ~3e-4 per
# 134 MB and the residual risk is structured data instead (flagged separately as
# low_information).
NOISE_BAND_CEILING_ASCII = 10
NOISE_BAND_CEILING_UTF16 = 0

# low_information: the shape a small-integer table has. A flag, never a filter.
LOW_INFORMATION_DISTINCT_CHARS = 3

ENCODING_ASCII = "ascii"
ENCODING_UTF16 = "utf-16le"
ENCODING_ORDER = {ENCODING_ASCII: 0, ENCODING_UTF16: 1}

# The noise control (refutation probe P1). Deterministic pseudo-random bytes
# from SHA-256 in counter mode: same bytes on every machine and every run, no
# dependence on the `random` module's seeding, standard library only.
DEFAULT_NOISE_CONTROL_BYTES = 16 << 20
MAX_NOISE_CONTROL_BYTES = 64 << 20
NOISE_CONTROL_SEED = b"S-01/extract_strings.py/noise-control/v1"
NOISE_HISTOGRAM_MAX_LENGTH = 24   # lengths above this are pooled into one bucket

DEFAULT_LITERAL_SAMPLES = 8
DEFAULT_CLASSIFIED_CAP = 20000    # per category, before the table is truncated
DEFAULT_RVA_PROBE_SAMPLE = 4096

UE_MODULE_MARKER = ".build.cs"    # matched case-insensitively, see below
UE_MODULE_INDEX_MAX_FILES = 1 << 20
UE_MODULE_LAYOUT_DIRS = ("private", "public", "classes", "internal")

# Confidence ceiling is 0.99 (plan.md 10.2); 1.00 is forbidden anywhere.
CONFIDENCE_LITERAL = 0.99
CONFIDENCE_TWO_METHODS = 0.85
CONFIDENCE_ONE_METHOD = 0.79
CONFIDENCE_HEURISTIC = 0.65

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

# The per-source "oracle" key of kb-record.schema.json#/$defs/source is
# deliberately NOT set on any source object below: it is legal in the schema but
# it makes tools/kb/validate.py read every source object as a whole knowledge-base
# record. container_info.py and rtti_scan.py hit the same wall. The oracle is
# stated inside the note instead, and the record-level "oracle" list is
# unaffected.


# --------------------------------------------------------------------------- #
# region model: a complete, non-overlapping tiling of the file
# --------------------------------------------------------------------------- #

REGION_HEADERS = "headers"
REGION_SECTION = "section"
REGION_GAP = "gap"
REGION_OVERLAY = "overlay"

RVA_ABSENT_GAP = (
    "the offset lies in inter-section file padding: no section's raw range covers "
    "it, so it has no image-relative address")
RVA_ABSENT_OVERLAY = (
    "the offset lies past the last section's raw data (the overlay): the loader "
    "never maps it, so it has no image-relative address")
RVA_ABSENT_HEADER_TAIL = (
    "the offset lies past SizeOfHeaders but before the first section's raw data, "
    "so it is neither header nor section content and has no image-relative address")


class RegionMap:
    """Every byte of the file assigned to exactly one region, in file order.

    Built rather than assumed, for two reasons that both bit earlier tools:

    * a *null* result only means something over a NAMED surface, and the surface
      has to be printable to be named. ``regions`` is that surface, and probe P3
      re-checks on every run that the regions tile ``[0, size)`` exactly;
    * an offset outside every section has no RVA, and there are three different
      ways for that to happen (header tail, inter-section padding, overlay). They
      are different findings about the file and are kept apart.

    The sweep tolerates a hostile section table -- unsorted, overlapping or
    out-of-file raw ranges -- by clamping and warning, never by trusting. A
    section whose raw range is entirely swallowed by an earlier one is reported
    and contributes no region, because the bytes are already covered and covering
    them twice would double-count every string in them.
    """

    def __init__(self, headers, warnings: list[str]) -> None:
        self.headers = headers
        self.size = headers.image.size
        self.regions: list[dict] = []
        self._build(warnings)

    def _build(self, warnings: list[str]) -> None:
        size = self.size
        header_end = min(max(0, self.headers.size_of_headers), size)

        # Candidate extents: the headers, then every section with raw data.
        # Sorted by (start, end) so the sweep is deterministic whatever order
        # the section table is in.
        candidates: list[tuple[int, int, dict | None]] = []
        if header_end > 0:
            candidates.append((0, header_end, None))
        for section in self.headers.sections:
            start = section["raw_pointer"]
            length = section["rsize"]
            if length <= 0:
                continue
            if start >= size:
                warnings.append(
                    "section %d (%s): raw range starts at %d, past the end of the "
                    "%d-byte file; no bytes of it were scanned"
                    % (section["index"], section["name"] or "<unnamed>", start, size))
                continue
            end = min(start + length, size)
            if end < start + length:
                warnings.append(
                    "section %d (%s): raw range [%d, %d) is clipped to the end of "
                    "the %d-byte file" % (section["index"],
                                          section["name"] or "<unnamed>",
                                          start, start + length, size))
            candidates.append((start, end, section))
        candidates.sort(key=lambda item: (item[0], item[1]))

        cursor = 0
        for start, end, section in candidates:
            if end <= cursor:
                if section is not None:
                    warnings.append(
                        "section %d (%s): raw range [%d, %d) is entirely covered by "
                        "an earlier region; its bytes are scanned once, under that "
                        "region" % (section["index"], section["name"] or "<unnamed>",
                                    start, end))
                continue
            if start > cursor:
                self._add(REGION_GAP, cursor, start, None, warnings)
            elif start < cursor and section is not None:
                warnings.append(
                    "section %d (%s): raw range [%d, %d) overlaps the preceding "
                    "region; the overlapping prefix is scanned once, under that "
                    "region" % (section["index"], section["name"] or "<unnamed>",
                                start, end))
            kind = REGION_SECTION if section is not None else REGION_HEADERS
            self._add(kind, max(start, cursor), end, section, warnings)
            cursor = end
        if cursor < size:
            kind = REGION_OVERLAY if self.regions else REGION_GAP
            self._add(kind, cursor, size, None, warnings)

    def _add(self, kind: str, start: int, end: int, section: dict | None,
             warnings: list[str]) -> None:
        if end <= start:
            return
        # A gap that follows the headers but precedes any section is padding
        # between the two; a gap after the last section is the overlay. The
        # distinction is made here, once, so a record never has to guess.
        if kind == REGION_GAP and not any(r["kind"] == REGION_SECTION
                                          for r in self.regions):
            name = "header-padding"
        elif kind == REGION_GAP:
            name = "inter-section-padding"
        elif kind == REGION_OVERLAY:
            name = "overlay"
        elif kind == REGION_HEADERS:
            name = "headers"
        else:
            name = section["name"] or "<unnamed>"
        self.regions.append({
            "index": len(self.regions),
            "kind": kind,
            "name": name,
            "start": start,
            "end": end,
            "length": end - start,
            "section_index": section["index"] if section is not None else None,
            "section_name": section["name"] if section is not None else None,
            "section_rva": section["rva"] if section is not None else None,
            "section_raw_pointer": section["raw_pointer"] if section is not None else None,
            "section_virtual_size": section["vsize"] if section is not None else None,
            "section_characteristics": ("0x%08x" % section["characteristics"]
                                        if section is not None else None),
            "rva_available": kind in (REGION_HEADERS, REGION_SECTION),
        })

    # -- address translation ------------------------------------------------ #

    def address(self, region: dict, offset: int) -> tuple[int | None, str | None, bool]:
        """``(rva, rva_absent_reason, beyond_virtual_size)`` for *offset*.

        The headers case is a real mapping and not a convenience: the loader maps
        ``SizeOfHeaders`` bytes at the image base identically, so a string in the
        version resource directory or in the section table itself does have an
        RVA, and it equals its file offset.
        """
        if region["kind"] == REGION_HEADERS:
            if offset < min(self.headers.size_of_headers, self.size):
                return offset, None, False
            return None, RVA_ABSENT_HEADER_TAIL, False
        if region["kind"] == REGION_SECTION:
            delta = offset - region["section_raw_pointer"]
            rva = region["section_rva"] + delta
            beyond = delta >= (region["section_virtual_size"] or 0)
            return rva, None, beyond
        if region["kind"] == REGION_OVERLAY:
            return None, RVA_ABSENT_OVERLAY, False
        if region["name"] == "header-padding":
            return None, RVA_ABSENT_HEADER_TAIL, False
        return None, RVA_ABSENT_GAP, False

    def describe(self) -> list[dict]:
        return [{
            "index": region["index"],
            "kind": region["kind"],
            "name": region["name"],
            "start": region["start"],
            "end": region["end"],
            "length": region["length"],
            "section_index": region["section_index"],
            "section_rva": region["section_rva"],
            "section_virtual_size": region["section_virtual_size"],
            "section_characteristics": region["section_characteristics"],
            "rva_available": region["rva_available"],
        } for region in self.regions]


# --------------------------------------------------------------------------- #
# the two run patterns
# --------------------------------------------------------------------------- #

def build_patterns(min_length: int) -> tuple[re.Pattern, re.Pattern]:
    """The ASCII and UTF-16LE run patterns for *min_length* characters.

    The printable class is ``0x20..0x7E`` exactly: no tab, no CR, no LF. Adding
    the line separators would merge what are logically separate lines of an
    embedded text blob into one record, which changes the offset of every part
    a later xref hunt wants to point at. A consumer who wants the blob can
    reassemble adjacent records; a consumer who wants the line cannot split one
    back out of a merged record without re-reading the file.

    Neither pattern requires a terminator. C string literals are
    NUL-terminated, but a string packed inside a larger table is not, and
    recall comes first here -- so termination is RECORDED per record
    (``nul_terminated``) instead of being required.
    """
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    return ascii_re, utf16_re


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hex_bytes(raw: bytes) -> str:
    return raw.hex()


def dump_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _character_profile(text: str) -> dict:
    """Per-record character-class counts -- the numbers that replace a filter.

    Published rather than reduced to a verdict so that a consumer of
    ``strings.jsonl`` can impose a stricter rule than this tool's without
    re-reading the image.
    """
    alpha = digit = other = 0
    for character in text:
        if character.isalpha():
            alpha += 1
        elif character.isdigit():
            digit += 1
        else:
            other += 1
    distinct = len(set(text))
    return {
        "alpha_count": alpha,
        "digit_count": digit,
        "other_count": other,
        "distinct_chars": distinct,
        "low_information": bool(alpha == 0
                                or distinct < LOW_INFORMATION_DISTINCT_CHARS),
    }


def _spread(items: list, count: int) -> list:
    """A deterministic, evenly spaced sample -- never just the first N.

    The first N strings of an image all come from the same part of the same
    section, so a sample taken from the front is a sample of one region.
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


# --------------------------------------------------------------------------- #
# classification (class I -- naming conventions, one method unless stated)
# --------------------------------------------------------------------------- #

# Ordered, first match wins. Printed with the results so a reviewer can
# disagree with one rule instead of with a verdict. Each entry is
# (category, compiled pattern, what the rule is claiming).
#
# These rules classify a string by its SHAPE. A shape is evidence about what
# kind of thing a string is; it is not evidence about who wrote it. The origin
# question is answered separately, from the module index and the container
# index, and graded lower.
CLASSIFICATION_RULES: tuple[tuple[str, re.Pattern, str], ...] = (
    ("unreal-script-path", re.compile(r"^/Script/[A-Za-z0-9_]+"),
     "the UE package path for a native module's reflection namespace"),
    ("unreal-content-path", re.compile(r"^/(Game|Engine|Temp|Memory|Paper2D|Niagara)"
                                       r"/[A-Za-z0-9_./]*$"),
     "a UE content mount point followed by a package path"),
    ("build-source-path", re.compile(r"^[A-Za-z]:[\\/](?:[^\\/]+[\\/]){2,}[^\\/]+"
                                     r"\.(?:cpp|h|hpp|inl|c|cc|usf|ush|cs)$",
                                     re.IGNORECASE),
     "an absolute path to a source file, i.e. a build-machine path baked into "
     "the image (__FILE__, a check() macro, or an assert)"),
    ("source-file-name", re.compile(r"^[A-Za-z0-9_.+-]+\.(?:cpp|h|hpp|inl|c|cc|usf|ush)$"),
     "a bare source file name with no directory part"),
    ("unreal-log-category", re.compile(r"^Log[A-Z][A-Za-z0-9_]{2,}$"),
     "the UE log-category naming convention"),
    ("unreal-console-variable", re.compile(r"^[a-z]{1,6}\.[A-Za-z0-9_]"
                                           r"[A-Za-z0-9_.]{2,}$"),
     "the UE console-variable naming convention (a short lowercase group, a "
     "dot, then a CamelCase name)"),
    ("unreal-type-name", re.compile(r"^(?:U|A|F|T|I|E)[A-Z][A-Za-z0-9_]{2,}$"),
     "the UE Hungarian type-prefix convention"),
    ("dll-name", re.compile(r"^[A-Za-z0-9_.+-]+\.(?:dll|exe|sys)$", re.IGNORECASE),
     "a Windows module file name"),
    ("ini-or-config-path", re.compile(r"^[A-Za-z0-9_./\\-]+\.(?:ini|json|cfg|xml|uplugin"
                                      r"|uproject)$", re.IGNORECASE),
     "a configuration or descriptor file path"),
)

# The categories whose CONTENT the findings argue from, and which are therefore
# retained in memory and published in the summary document. Everything else is
# counted only. This is a C-13 decision as much as a memory one: the categories
# below hold module names, engine source paths and descriptor names -- facts
# about the build -- whereas an arbitrary string from the image is content.
PUBLISHABLE_CATEGORIES = frozenset({
    "unreal-script-path",
    "unreal-content-path",
    "build-source-path",
    "ini-or-config-path",
})


def classify_string(text: str) -> tuple[str, str]:
    """``(category, rule)`` for *text*. First matching rule wins."""
    for category, pattern, rule in CLASSIFICATION_RULES:
        if pattern.match(text):
            return category, rule
    return "unclassified", "no rule in CLASSIFICATION_RULES matched"


# --------------------------------------------------------------------------- #
# module-name extraction from a source path
# --------------------------------------------------------------------------- #

def split_path_components(text: str) -> list[str]:
    """Path components of *text*, either separator, empties dropped."""
    return [part for part in text.replace("\\", "/").split("/") if part]


def extract_engine_module(text: str) -> dict | None:
    """The engine module a build-machine source path names, or None.

    The module is the component immediately before the first ``Private``,
    ``Public``, ``Classes`` or ``Internal`` component. That is the layout
    UnrealBuildTool requires of a module directory, and it is the only rule that
    gets the grouped modules right:

        Engine\\Source\\Runtime\\Core\\Private\\Async\\TaskGraph.cpp     -> Core
        Engine\\Source\\Runtime\\Experimental\\Chaos\\Private\\...        -> Chaos
        Engine\\Source\\Runtime\\Online\\HTTP\\Private\\...               -> HTTP
        Engine\\Plugins\\Animation\\ACLPlugin\\Source\\ACLPlugin\\Private -> ACLPlugin

    Taking the fourth component instead -- the obvious rule -- returns
    "Experimental" and "Online", which are grouping directories and not modules
    at all. Getting this wrong does not fail loudly: it produces a plausible
    module list with a dozen names in it that no ``.build.cs`` ever declared.

    Returns the module name plus where in the path it was found, so a consumer
    can see the evidence for the extraction rather than only its result.
    """
    parts = split_path_components(text)
    lowered = [part.lower() for part in parts]
    for index, part in enumerate(lowered):
        if part in UE_MODULE_LAYOUT_DIRS and index >= 1:
            return {
                "module": parts[index - 1],
                "layout_dir": parts[index],
                "layout_dir_index": index,
                "components": len(parts),
            }
    return None


def build_ue_module_index(root: str, warnings: list[str]) -> dict:
    """Module names declared by ``<Module>.build.cs`` under *root*.

    The second, independent method for "this name is an Unreal Engine module":
    a different oracle (``filesystem`` for the file's existence, ``external-doc``
    for what a ``.build.cs`` means) reached by a different act of measurement.

    Two details that are easy to get wrong and that silently shrink the index:

    * the suffix is matched CASE-INSENSITIVELY. UE 5.4.4 ships both
      ``Core.Build.cs`` and ``MRMesh.build.cs``; a case-sensitive test on
      ``.Build.cs`` loses every module spelled the second way, and the loss shows
      up as those modules looking absent from the engine -- which is exactly the
      conclusion this pass exists to avoid drawing by accident.
    * ``Intermediate`` directories are skipped. They hold generated headers for
      modules that were built on THIS machine for some other project, so
      counting them would make the index a statement about the local build state
      rather than about the engine.
    """
    started = time.monotonic()
    index: dict[str, str] = {}
    files = 0
    if not os.path.isdir(root):
        warnings.append("--ue-source-root %r is not a directory; the module "
                        "corroboration pass did not run" % root)
        return {"root": root, "available": False, "modules": {}, "files_scanned": 0,
                "elapsed_seconds": 0.0, "truncated": False}
    truncated = False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames
                             if name.lower() not in ("intermediate", "binaries"))
        for name in sorted(filenames):
            files += 1
            if files > UE_MODULE_INDEX_MAX_FILES:
                truncated = True
                break
            if not name.lower().endswith(UE_MODULE_MARKER):
                continue
            module = name[:-len(UE_MODULE_MARKER)]
            if module and module.lower() not in index:
                index[module.lower()] = os.path.relpath(
                    os.path.join(dirpath, name), root).replace("\\", "/")
        if truncated:
            break
    if truncated:
        warnings.append(
            "the Unreal module index hit the %d-file walk limit; the module list "
            "below is a floor" % UE_MODULE_INDEX_MAX_FILES)
    return {
        "root": root,
        "available": True,
        "modules": index,
        "files_scanned": files,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "truncated": truncated,
    }


def load_v07_plugin_names(path: str, warnings: list[str]) -> dict:
    """Plugin and project names from a V-07 ``staged-plugins.json`` artifact.

    A DIFFERENT ORACLE (``container-metadata``: the pak directory index) reached
    by a different act of measurement, which is what makes it usable as a second
    method. What it proves is narrow and the record says so: a ``.uplugin`` entry
    in the container index means the descriptor was STAGED into the package. It
    does not mean the plugin's modules are compiled into the executable, and a
    ``.uplugin`` name is a PLUGIN name while a ``/Script/`` path carries a MODULE
    name -- one plugin routinely declares several modules under different names,
    so the two sets are not the same kind of thing and set arithmetic between
    them has to be read with that in mind.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as error:
        warnings.append("--v07-plugins %r could not be read: %s; the container "
                        "cross-check did not run" % (path, error))
        return {"path": path, "available": False}
    entries = ((document.get("reading") or {}).get("plugin_and_project_files")
               or [])
    plugins: dict[str, str] = {}
    projects: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, str):
            continue
        base = entry.replace("\\", "/").rsplit("/", 1)[-1]
        stem, _, suffix = base.rpartition(".")
        if suffix.lower() == "uplugin" and stem:
            plugins.setdefault(stem, entry)
        elif suffix.lower() == "uproject" and stem:
            projects.setdefault(stem, entry)
    return {
        "path": path,
        "available": True,
        "build_key": document.get("build_key"),
        "entry_count": len(entries),
        "plugin_names": plugins,
        "project_names": projects,
        "engine_plugin_names": sorted(
            name for name, entry in plugins.items()
            if entry.replace("\\", "/").startswith("Engine/")),
        "non_engine_plugin_names": sorted(
            name for name, entry in plugins.items()
            if not entry.replace("\\", "/").startswith("Engine/")),
    }


def install_plugin_directories(install_root: str | None) -> dict:
    """Plugin directory names present in the installation's own Plugins tree.

    A third reading, on the ``filesystem`` oracle, of the same question the
    container index answers: which plugins are this project's rather than the
    engine's. Read-only, one directory listing deep, and it names no file inside
    the installation -- only the directory names, which is what the claim needs.
    """
    if not install_root:
        return {"root": None, "available": False, "names": []}
    names: list[str] = []
    roots_examined: list[str] = []
    for candidate in ("MISERY/Plugins", "Plugins"):
        path = os.path.join(install_root, candidate.replace("/", os.sep))
        if not os.path.isdir(path):
            continue
        roots_examined.append(candidate)
        try:
            for entry in sorted(os.listdir(path)):
                if os.path.isdir(os.path.join(path, entry)):
                    names.append(entry)
        except OSError:
            continue
    return {
        "root": install_root,
        "available": bool(roots_examined),
        "directories_examined": roots_examined,
        "names": sorted(set(names)),
    }


# --------------------------------------------------------------------------- #
# the scan
# --------------------------------------------------------------------------- #

class StringSink:
    """Where records go, and what survives them.

    Records are streamed out; only counters, two extent arrays and a capped
    table of classified records stay in memory (plan.md F-04). The extent arrays
    are ``array('q')`` -- eight bytes per hit rather than a dictionary -- which
    is what makes the cross-encoding overlap count affordable on an image with
    1.6 million ASCII hits.
    """

    def __init__(self, handle, classified_cap: int,
                 rva_sample_cap: int = DEFAULT_RVA_PROBE_SAMPLE) -> None:
        self.handle = handle
        self.classified_cap = classified_cap
        self.total = 0
        self.by_encoding = Counter()
        # Probe P2 needs the low-information share of the UTF-16 population
        # ALONE; sink.flags mixes the encodings, so the split is counted here as
        # the records go past. Counting it anywhere later is impossible: no
        # record survives its window (plan.md F-04).
        self.low_information_by_encoding = Counter()
        # A decimated sample of lightweight per-record slots, kept for probe P4.
        self.rva_sample_cap = max(0, rva_sample_cap)
        self.rva_sample: list[dict] = []
        self._rva_stride = 1
        self._rva_seen = 0
        self.by_region_kind = Counter()
        self.by_region_name = Counter()
        self.by_category = Counter()
        self.length_histogram: dict[str, Counter] = {
            ENCODING_ASCII: Counter(), ENCODING_UTF16: Counter()}
        self.region_length_histogram: dict[str, Counter] = {}
        self.flags = Counter()
        self.classified: dict[str, list[dict]] = {}
        self.classified_truncated: Counter = Counter()
        self.starts = array("q")
        self.ends = array("q")
        self.encodings = array("b")
        self.first_last_by_region: dict[int, list[dict]] = {}
        self.bytes_emitted = 0

    def add(self, record: dict) -> None:
        self.total += 1
        encoding = record["encoding"]
        self.by_encoding[encoding] += 1
        self.by_region_kind[record["region_kind"]] += 1
        self.by_region_name[record["region"]] += 1
        self.by_category[record["category"]] += 1
        bucket = min(record["char_count"], NOISE_HISTOGRAM_MAX_LENGTH)
        self.length_histogram[encoding][bucket] += 1
        key = "%s/%s" % (record["region"], encoding)
        self.region_length_histogram.setdefault(key, Counter())[bucket] += 1
        for flag in ("noise_band", "low_information", "nul_terminated", "clipped",
                     "beyond_virtual_size", "abuts_wide_non_ascii"):
            if record.get(flag):
                self.flags[flag] += 1
        if record.get("low_information"):
            self.low_information_by_encoding[encoding] += 1
        if record["rva"] is None:
            self.flags["rva_absent"] += 1
        self.starts.append(record["offset"])
        self.ends.append(record["offset"] + record["length"])
        self.encodings.append(ENCODING_ORDER[encoding])

        # The boundary records of every region: probe P4 checks these
        # explicitly, because a translation bug shows up at a boundary first.
        slot = self.first_last_by_region.setdefault(record["region_index"], [])
        if len(slot) < 2:
            slot.append(record)
        else:
            slot[1] = record

        # A sample spread over the WHOLE index, for probe P4, held as four small
        # fields per entry rather than as the record. Deterministic and
        # single-pass: every stride-th record is kept, and when the table fills
        # the stride doubles and every other entry is dropped, so the sample
        # stays evenly spread over however many records turn up without the
        # total having to be known in advance.
        if self.rva_sample_cap:
            if self._rva_seen % self._rva_stride == 0:
                self.rva_sample.append({
                    "offset": record["offset"],
                    "rva": record["rva"],
                    "encoding": encoding,
                    "region": record["region"],
                })
                if len(self.rva_sample) > self.rva_sample_cap:
                    self.rva_sample = self.rva_sample[::2]
                    self._rva_stride *= 2
            self._rva_seen += 1

        category = record["category"]
        if category in PUBLISHABLE_CATEGORIES:
            table = self.classified.setdefault(category, [])
            if len(table) < self.classified_cap:
                table.append(record)
            else:
                self.classified_truncated[category] += 1

        if self.handle is not None:
            line = json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
            self.handle.write(line)
            self.bytes_emitted += len(line.encode("utf-8"))


def iter_windows(image, region: dict, window: int, lookahead: int):
    """Yield ``(origin, buffer, commit_length)`` covering one region's bytes.

    ``commit_length`` is how much of *buffer* owns its starts: a match beginning
    at or after it belongs to the next window and is skipped here, so no run is
    reported twice and none is reported at a truncated length merely because a
    window ended inside it. The lookahead is ``MAX_STRING_BYTES + 8``, i.e. more
    than the longest run this tool will record, so a match that starts inside the
    committed part is always visible at its full capped extent.
    """
    start = region["start"]
    total = region["length"]
    position = 0
    while position < total:
        commit = min(window, total - position)
        want = min(commit + lookahead, total - position)
        block = image.read_at(start + position, want, "region scan")
        yield start + position, block, commit
        position += commit


def scan_region(image, region: RegionMap, entry: dict, patterns, min_length: int,
                sink: StringSink, stats: Counter) -> None:
    """Find every run in one region and hand each to *sink*, in offset order.

    Both encodings are matched in the same window so that the emitted stream is
    in ascending offset order without a second sorting pass over the whole file,
    and so the cross-encoding overlap for the window can be counted while both
    hit lists are still in hand.
    """
    ascii_re, utf16_re = patterns
    carried: list[tuple[int, int, int]] = []   # (start, end, encoding_code)
    for origin, buffer, commit in iter_windows(image, entry, SCAN_WINDOW, LOOKAHEAD):
        limit = len(buffer)
        hits: list[tuple[int, int, str, bytes]] = []

        for match in ascii_re.finditer(buffer):
            begin = match.start()
            if begin >= commit:
                break
            end = min(match.end(), begin + MAX_STRING_BYTES)
            hits.append((begin, end, ENCODING_ASCII, buffer[begin:end]))

        for match in utf16_re.finditer(buffer):
            begin = match.start()
            if begin >= commit:
                break
            if (origin + begin) % 2:
                # Rule (b) of decision 2: only even image offsets start a
                # UTF-16 candidate. Counted, not silently dropped -- the size of
                # what the alignment rule threw away is part of the finding.
                stats["utf16_rejected_odd_alignment"] += 1
                continue
            end = min(match.end(), begin + MAX_STRING_BYTES)
            if (end - begin) % 2:
                end -= 1
            if (end - begin) // 2 < min_length:
                stats["utf16_rejected_short_after_cap"] += 1
                continue
            hits.append((begin, end, ENCODING_UTF16, buffer[begin:end]))

        hits.sort(key=lambda item: (item[0], ENCODING_ORDER[item[2]]))

        # Cross-encoding overlap, counted while both lists are in hand. The
        # carry list holds the previous window's hits that reach past its commit
        # boundary, so a pair straddling the boundary is still seen.
        extents = carried + [(begin, end, ENCODING_ORDER[encoding])
                             for begin, end, encoding, _ in hits]
        extents.sort()
        for index in range(len(extents) - 1):
            begin, end, code = extents[index]
            for other in extents[index + 1:]:
                if other[0] >= end:
                    break
                if other[2] != code:
                    stats["ranges_claimed_by_both_encodings"] += 1
        # Rebase into the NEXT window's frame. The next buffer starts `commit`
        # bytes further into the file, so an extent carried across the boundary
        # has to be shifted by that much: comparing an old-frame extent against
        # a new-frame one compares two different coordinate systems and both
        # invents overlaps and misses real ones.
        carried = [(begin - commit, end - commit, code)
                   for begin, end, code in extents if end > commit]

        for begin, end, encoding, raw in hits:
            offset = origin + begin
            _emit(image, region, entry, offset, end - begin, encoding, raw,
                  buffer, begin, end, limit, entry["end"], sink, stats)


def _emit(image, region: RegionMap, entry: dict, offset: int, length: int,
          encoding: str, raw: bytes, buffer: bytes, begin: int, end: int,
          buffer_limit: int, region_end: int, sink: StringSink,
          stats: Counter) -> None:
    """Build one record and hand it to *sink*."""
    if encoding == ENCODING_ASCII:
        text = raw.decode("ascii")
        char_count = len(text)
        ceiling = NOISE_BAND_CEILING_ASCII
    else:
        text = raw.decode("utf-16-le")
        char_count = len(text)
        ceiling = NOISE_BAND_CEILING_UTF16

    # Termination and neighbourhood, read from the window we already hold: the
    # bytes just past the run. When the run ends at the window's end we cannot
    # see them, and the record says "unknown" rather than guessing -- which only
    # happens for a run clipped by the length cap or by the region end.
    unit = 1 if encoding == ENCODING_ASCII else 2
    nul_terminated: bool | None = None
    abuts_wide_non_ascii = False
    if end + unit <= buffer_limit:
        following = buffer[end:end + unit]
        nul_terminated = following == b"\x00" * unit
        if encoding == ENCODING_UTF16 and following[1:2] not in (b"", b"\x00"):
            abuts_wide_non_ascii = True
    elif offset + length + unit > region_end:
        nul_terminated = False       # the region ends here; nothing follows
    if encoding == ENCODING_UTF16 and begin >= unit:
        preceding = buffer[begin - unit:begin]
        if preceding[1:2] not in (b"", b"\x00"):
            abuts_wide_non_ascii = True

    clipped = bool(length >= MAX_STRING_BYTES or offset + length >= region_end)
    if length >= MAX_STRING_BYTES:
        stats["runs_clipped_by_length_cap"] += 1
    if offset + length >= region_end:
        stats["runs_touching_region_end"] += 1

    rva, absent_reason, beyond_virtual_size = region.address(entry, offset)
    category, rule = classify_string(text)
    profile = _character_profile(text)

    record = {
        "offset": offset,
        "length": length,
        "char_count": char_count,
        "encoding": encoding,
        "rva": rva,
        "rva_absent_reason": absent_reason,
        "beyond_virtual_size": beyond_virtual_size,
        "region": entry["name"],
        "region_kind": entry["kind"],
        "region_index": entry["index"],
        "section": entry["section_name"],
        "noise_band": bool(char_count < ceiling),
        "nul_terminated": nul_terminated,
        "clipped": clipped,
        "abuts_wide_non_ascii": abuts_wide_non_ascii,
        "category": category,
        "category_rule": rule,
        "text": text,
    }
    record.update(profile)
    sink.add(record)


# --------------------------------------------------------------------------- #
# the noise control (refutation probe P1)
# --------------------------------------------------------------------------- #

def noise_control(min_length: int, want_bytes: int, target_bytes: int) -> dict:
    """Run both patterns over deterministic pseudo-random bytes.

    WHAT THIS MEASURES. How many hits of each length a buffer with no strings in
    it produces, so that "length 4 is mostly noise" becomes a ratio instead of a
    claim. The bytes come from SHA-256 in counter mode over a fixed seed, so the
    control is identical on every machine and every run and adds nothing
    non-deterministic to the document.

    WHAT IT DOES NOT MEASURE, stated because it bounds every use of the result.
    Uniform random bytes are a LOWER BOUND on the incidental-hit rate of real
    machine code, not an estimate of it: x86-64 instruction streams are dense in
    the ``0x20..0x7E`` range (REX prefixes, common ModRM bytes, small
    displacements) and produce MORE short printable runs than uniform random
    does. So when the observed count at some length is close to the control, the
    honest reading is "at this length the population is noise-dominated", and
    the conclusion is conservative in the right direction. It cannot be used the
    other way round to argue that a length is clean because it beats the control
    by a small factor.

    ``expected_at_target_size`` is an explicit linear extrapolation from the
    control size to the target size and is labelled as one. The raw control
    counts and the two sizes are published beside it so the extrapolation can be
    redone or rejected.
    """
    started = time.monotonic()
    want_bytes = max(0, min(want_bytes, MAX_NOISE_CONTROL_BYTES))
    if want_bytes < 64:
        return {"ran": False, "reason": "control size below 64 bytes"}
    ascii_re, utf16_re = build_patterns(min_length)
    histogram = {ENCODING_ASCII: Counter(), ENCODING_UTF16: Counter()}
    produced = 0
    counter = 0
    chunk_target = 1 << 20
    while produced < want_bytes:
        pieces = []
        made = 0
        while made < chunk_target and produced + made < want_bytes:
            pieces.append(hashlib.sha256(
                NOISE_CONTROL_SEED + counter.to_bytes(8, "little")).digest())
            counter += 1
            made += 32
        block = b"".join(pieces)[:max(0, want_bytes - produced)]
        for match in ascii_re.finditer(block):
            histogram[ENCODING_ASCII][
                min(len(match.group()), NOISE_HISTOGRAM_MAX_LENGTH)] += 1
        for match in utf16_re.finditer(block):
            histogram[ENCODING_UTF16][
                min(len(match.group()) // 2, NOISE_HISTOGRAM_MAX_LENGTH)] += 1
        produced += len(block)
        if not block:
            break
    scale = (target_bytes / produced) if produced else 0.0
    return {
        "ran": True,
        "seed": NOISE_CONTROL_SEED.decode("ascii"),
        "byte_source": "sha256(seed || little-endian uint64 counter), concatenated",
        "control_bytes": produced,
        "target_bytes": target_bytes,
        "scale_to_target": round(scale, 6),
        "min_length": min_length,
        "histogram": {encoding: {str(length): count
                                 for length, count in sorted(counter_.items())}
                      for encoding, counter_ in histogram.items()},
        "expected_at_target_size": {
            encoding: {str(length): round(count * scale, 1)
                       for length, count in sorted(counter_.items())}
            for encoding, counter_ in histogram.items()},
        "extrapolation_is_linear_and_is_a_lower_bound": True,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


# --------------------------------------------------------------------------- #
# evidence layer 1 (class P): literal reads
# --------------------------------------------------------------------------- #

def locus_target(path: str, install_root: str | None = None) -> str:
    """The spelling a class-P read locus uses for *path*: install-relative, '/'.

    A bare basename is not a determinate location, and in this installation that
    is not hypothetical: it holds two different files called ``MISERY.exe`` -- the
    422 kB bootstrap shim at the root and the 282 MB D-04 oracle under
    ``MISERY/Binaries/Win64`` -- so ``MISERY.exe@126984040+16`` names an
    ambiguity class rather than a range of bytes. Same rule, same reason, as
    ``rtti_scan.locus_target``; kept here rather than imported because importing
    a sibling scanner to borrow one helper would couple two tools that otherwise
    share only the PE parser and the path guard.
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
    except ValueError:          # different drives on Windows
        return os.path.basename(absolute)
    relative = relative.replace("\\", "/")
    if relative.startswith("../") or relative in ("..", ".") or ":" in relative:
        return os.path.basename(absolute)
    return relative


def literal_read(target: str, join_key: str, offset: int, raw: bytes,
                 note: str | None = None) -> dict:
    """One class-P record: a literal read at a determinate place, and no more.

    ``claim`` states the offset AND the length -- which plan.md 10.3 v2.4 makes
    mandatory for ``binary-analysis`` to be class P at all -- and stops short of
    naming what the bytes are. ``join_key`` is a pointer into the interpretive
    layer, deliberately outside the graded object: naming a structure inside the
    graded note is exactly what would disqualify it.
    """
    length = len(raw)
    plural = "byte" if length == 1 else "bytes"
    claim = "%d %s at offset %d of %s are %s" % (
        length, plural, offset, target, hex_bytes(raw))
    return {
        "join_key": join_key,
        "interpretation_lives_in": (
            "the record with the same offset in strings.jsonl, and the counts in "
            "summary{} -- plan.md 10.3, the A-07 / A-07i split"),
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
                "method": "S-01",
                "artifact": None,
                "locator": "%s@%d+%d" % (target, offset, length),
                # Filled in by confirm_literal_reads once the second read has
                # actually happened. Never pre-filled: an attestation written
                # before the check is a claim about the author's intention.
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
            # The note IS the claim, on purpose: tools/kb/validate.py derives the
            # claim class of a reduced annotation from this string alone, and
            # plan.md 10.3 v2.4 admits binary-analysis into class P only when the
            # claim states a determinate address AND an extent and does not name
            # what the bytes are.
            "note": ("%s. This record gives the position and the extent, and "
                     "nothing else." % claim),
        },
    }


def confirm_literal_reads(path: str, literals: list[dict], target: str,
                          warnings: list[str]) -> bool:
    """Perform every literal read a SECOND time and stamp the result on each record.

    plan.md 10.3 class-P criterion 2 executed rather than asserted. The second
    pass uses a freshly opened handle and seeks independently. On any
    disagreement nothing is adjusted: the failure is recorded and the reading
    stands as unreproduced.
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
            "oracle binary-analysis. Read by %s, read-only. %s"
            % (GENERATOR_NAME, attestation))
        read["evidence"]["note"] = "%s %s" % (read["evidence"]["note"], attestation)
    return reproduced


# --------------------------------------------------------------------------- #
# evidence layer 2 (class I): the graded annotations
# --------------------------------------------------------------------------- #

def interpretive_annotation(target: str, confidence: float, note: str,
                            methods: list[dict], oracles: list[str],
                            level: str = "INFERRED") -> dict:
    """A class-I annotation with an explicit method list.

    plan.md 10.3 wants TWO INDEPENDENT METHODS from 0.80 up, and is explicit
    that an extra oracle is not a method, an artifact path is not a method and a
    clause of reasoning is not a method. So *methods* is a list of acts of
    measurement, the second and later ones carry ``independent_of``, and the
    caller that cannot name two does not get to ask for 0.85 -- the assertion
    below makes that a programming error rather than a judgement call.
    """
    if confidence >= 0.80 and len(methods) < 2:
        raise ValueError(
            "confidence %.2f needs two independent methods, %d given -- plan.md "
            "10.3 rule 1" % (confidence, len(methods)))
    sources = []
    for index, method in enumerate(methods):
        source = {
            "method": "S-01",
            "artifact": method.get("artifact"),
            "locator": method.get("locator") or target,
            "note": "oracle %s. %s" % (method["oracle"], method["note"]),
        }
        if index:
            source["independent_of"] = ["S-01/%s" % methods[0]["id"]]
        sources.append(source)
    return {
        "evidence_level": level,
        "claim_class": "I",
        "confidence": confidence,
        "oracle": sorted(set(oracles)),
        "sources": sources,
        "read_locus": None,
        "note": note,
    }


# --------------------------------------------------------------------------- #
# findings: the three questions M2s needs answered
# --------------------------------------------------------------------------- #

SCRIPT_PATH_RE = re.compile(r"^/Script/([A-Za-z0-9_]+)")


def build_script_path_finding(sink: StringSink, target: str,
                              module_index: dict | None,
                              v07: dict | None, install_plugins: dict | None) -> dict:
    """Question 1: which ``/Script/<Name>`` package paths occur, and whose are they?

    The two encodings are two independent acts of measurement over the same
    file: different byte patterns, different offsets, different alignment rules.
    A name seen by BOTH therefore has two methods behind it and a name seen by
    only one has one, and the two sets are reported and graded separately rather
    than averaged -- averaging them would erase the only distinction that makes
    one half stronger than the other.
    """
    by_encoding: dict[str, Counter] = {ENCODING_ASCII: Counter(),
                                       ENCODING_UTF16: Counter()}
    first_offset: dict[str, dict] = {}
    for record in sink.classified.get("unreal-script-path", ()):
        match = SCRIPT_PATH_RE.match(record["text"])
        if not match:
            continue
        name = match.group(1)
        by_encoding[record["encoding"]][name] += 1
        slot = first_offset.setdefault(name, {})
        slot.setdefault(record["encoding"], {
            "offset": record["offset"], "rva": record["rva"],
            "region": record["region"], "text": record["text"]})

    ascii_names = set(by_encoding[ENCODING_ASCII])
    utf16_names = set(by_encoding[ENCODING_UTF16])
    both = ascii_names & utf16_names
    union = ascii_names | utf16_names

    declared = {}
    undeclared = []
    if module_index and module_index.get("available"):
        for name in sorted(union):
            hit = module_index["modules"].get(name.lower())
            if hit:
                declared[name] = hit
            else:
                undeclared.append(name)

    # Which of the undeclared names a second oracle also calls non-engine.
    container_names = set((v07 or {}).get("plugin_names") or {})
    container_projects = set((v07 or {}).get("project_names") or {})
    installed_dirs = set((install_plugins or {}).get("names") or [])
    corroborated = {}
    for name in undeclared:
        reached_by = []
        if name in container_names:
            reached_by.append("container-metadata: a %s.uplugin entry in the "
                              "V-07 pak directory index" % name)
        if name in container_projects:
            reached_by.append("container-metadata: a %s.uproject entry in the "
                              "V-07 pak directory index" % name)
        if name in installed_dirs:
            reached_by.append("filesystem: a directory named %s in the "
                              "installation's own Plugins tree" % name)
        if reached_by:
            corroborated[name] = reached_by

    annotation_both = interpretive_annotation(
        target, CONFIDENCE_TWO_METHODS,
        note=(
            "%d distinct names occur after the byte sequence '/Script/' in BOTH "
            "encodings, at different offsets. Interpretive because it reads the "
            "bytes as a UE package path and the trailing component as a module "
            "name. WHAT WOULD REFUTE IT: a name in this set whose two occurrences "
            "turn out to be the same bytes counted twice (they cannot be -- an "
            "8-bit run and a 16-bit run cannot occupy the same range and both "
            "match), or the population turning out to sit entirely in one region "
            "of the file, which the per-region counts would show. WHAT IT DOES "
            "NOT SHOW: that the module is LINKED INTO this image. A '/Script/X' "
            "literal proves the name is mentioned; UE emits such literals from "
            "generated reflection registration, from core-redirect tables and "
            "from packaged config defaults, so a redirect entry for a module that "
            "no longer exists appears here too." % len(both)),
        methods=[
            {"id": "ascii-run-scan", "oracle": "binary-analysis",
             "note": "an 8-bit printable-run scan of every region of the image, "
                     "reporting the file offset of each hit"},
            {"id": "utf16-run-scan", "oracle": "binary-analysis",
             "note": "an independent 16-bit even-aligned printable-pair scan of "
                     "the same regions, which finds these names at different "
                     "offsets in different byte ranges"},
        ],
        oracles=["binary-analysis"])

    annotation_union = interpretive_annotation(
        target, CONFIDENCE_ONE_METHOD,
        note=(
            "%d distinct names in total, of which %d were seen in one encoding "
            "only and therefore rest on a single act of measurement. Graded below "
            "0.80 for exactly that reason (plan.md 10.3 rule 1). WHAT WOULD "
            "REFUTE IT: a single-encoding name whose only occurrence is a "
            "noise-band hit or a clipped run -- the per-record 'noise_band' and "
            "'clipped' flags in strings.jsonl are what a reviewer would check."
            % (len(union), len(union - both))),
        methods=[{"id": "ascii-run-scan", "oracle": "binary-analysis",
                  "note": "one printable-run scan; the second encoding did not "
                          "see these names"}],
        oracles=["binary-analysis"])

    finding = {
        "question": ("Does the string table contain /Script/ package paths, and "
                     "which ones?"),
        "distinct_names": len(union),
        "names": sorted(union),
        "names_in_both_encodings": sorted(both),
        "names_ascii_only": sorted(ascii_names - utf16_names),
        "names_utf16_only": sorted(utf16_names - ascii_names),
        "occurrences_ascii": sum(by_encoding[ENCODING_ASCII].values()),
        "occurrences_utf16": sum(by_encoding[ENCODING_UTF16].values()),
        "occurrences_by_name": {
            name: {"ascii": by_encoding[ENCODING_ASCII].get(name, 0),
                   "utf16": by_encoding[ENCODING_UTF16].get(name, 0)}
            for name in sorted(union)},
        "first_occurrence": {name: first_offset.get(name, {})
                             for name in sorted(union)},
        "declared_as_ue_module": dict(sorted(declared.items())),
        "not_declared_as_ue_module": sorted(undeclared),
        "not_declared_but_corroborated_non_engine": dict(sorted(corroborated.items())),
        "module_index_available": bool(module_index
                                       and module_index.get("available")),
        "evidence_both_encodings": annotation_both,
        "evidence_union": annotation_union,
    }
    return finding


def build_source_path_finding(sink: StringSink, target: str,
                              module_index: dict | None,
                              file_queries: list[str] | None = None) -> dict:
    """Question 2: are there UE source-path literals, and what do they name?

    The build root is read off the paths rather than assumed, and the module is
    extracted by the layout rule documented on ``extract_engine_module`` -- the
    obvious "fourth component" rule silently invents a dozen modules that no
    ``.build.cs`` declares.

    Two granularities are reported, because they answer different questions.
    The MODULE list says which engine modules left a mark; the FILE list says
    which individual translation units did, and that is the one another task
    needs to look one name up in. ``file_queries`` answers a named lookup
    explicitly -- present or absent, with the count and the module -- so that
    "is <file> in the image?" is a field in the document and not an exercise
    left to the reader of a 2000-name list. An absent answer is bounded by the
    same limitation as everything else here: a file with no surviving __FILE__
    literal is invisible on this surface, so ABSENCE IS NOT EVIDENCE OF ABSENCE
    of the code, only of a path literal naming it.
    """
    roots = Counter()
    trees = Counter()
    modules_by_encoding: dict[str, Counter] = {ENCODING_ASCII: Counter(),
                                               ENCODING_UTF16: Counter()}
    module_examples: dict[str, dict] = {}
    files_by_encoding: dict[str, Counter] = {ENCODING_ASCII: Counter(),
                                             ENCODING_UTF16: Counter()}
    file_examples: dict[str, dict] = {}
    file_to_modules: dict[str, set] = {}
    unextracted = Counter()
    separators = Counter()
    total = 0
    for record in sink.classified.get("build-source-path", ()):
        text = record["text"]
        total += 1
        parts = split_path_components(text)
        separators["backslash" if "\\" in text else "forward-slash"] += 1
        # The build root is everything up to the first component that names an
        # engine tree, so a root of any depth is read rather than assumed.
        lowered = [part.lower() for part in parts]
        cut = None
        for index, part in enumerate(lowered):
            if part == "engine" and index + 1 < len(lowered) \
                    and lowered[index + 1] in ("source", "plugins", "intermediate"):
                cut = index
                break
        if cut is None:
            roots["<no Engine/{Source,Plugins,Intermediate} component>"] += 1
            trees["<none>"] += 1
        else:
            roots["/".join(parts[:cut])] += 1
            trees["/".join(parts[cut:cut + 2])] += 1
        # The FILE is the last component of the path, and it is recorded whether
        # or not a module could be extracted from the same path: a path that
        # does not fit the module layout still names a translation unit, and
        # dropping it here would make the file list a subset of the module list
        # for no reason a reader could see.
        basename = parts[-1] if parts else ""
        found = extract_engine_module(text)
        if basename:
            files_by_encoding[record["encoding"]][basename] += 1
            file_examples.setdefault(basename, {
                "offset": record["offset"], "rva": record["rva"],
                "region": record["region"],
                "module": found["module"] if found else None,
                "text": text})
            if found:
                file_to_modules.setdefault(basename, set()).add(found["module"])
        if found is None:
            unextracted[("/".join(parts[:4]) if parts else "<empty>")] += 1
            continue
        name = found["module"]
        modules_by_encoding[record["encoding"]][name] += 1
        module_examples.setdefault(name, {
            "offset": record["offset"], "rva": record["rva"],
            "region": record["region"], "layout_dir": found["layout_dir"],
            "text": text})

    ascii_modules = set(modules_by_encoding[ENCODING_ASCII])
    utf16_modules = set(modules_by_encoding[ENCODING_UTF16])
    union = ascii_modules | utf16_modules
    both = ascii_modules & utf16_modules

    ascii_files = set(files_by_encoding[ENCODING_ASCII])
    utf16_files = set(files_by_encoding[ENCODING_UTF16])
    file_union = ascii_files | utf16_files
    file_both = ascii_files & utf16_files

    # The named lookups. Matched case-insensitively on the basename, because a
    # build-machine path can be spelled with either case and a case-sensitive
    # miss would read as an absence.
    lowered_files = {}
    for name in file_union:
        lowered_files.setdefault(name.lower(), []).append(name)
    queries: dict[str, dict] = {}
    for wanted in (file_queries or []):
        hits = sorted(lowered_files.get(wanted.lower(), []))
        queries[wanted] = {
            "present": bool(hits),
            "matched_spellings": hits,
            "occurrences": {
                name: {"ascii": files_by_encoding[ENCODING_ASCII].get(name, 0),
                       "utf16": files_by_encoding[ENCODING_UTF16].get(name, 0)}
                for name in hits},
            "modules": sorted({module for name in hits
                               for module in file_to_modules.get(name, ())}),
            "first_occurrence": {name: file_examples[name] for name in hits},
            "what_an_absent_answer_means": (
                "no absolute source path ending in this file name was matched on "
                "the tested surface. That is a statement about surviving __FILE__ "
                "literals, not about compiled code: a translation unit whose "
                "assertion text the linker dropped, or which never had one, is "
                "invisible here and its absence is not evidence that it was not "
                "compiled in."),
        }

    declared: dict[str, str] = {}
    undeclared: list[str] = []
    if module_index and module_index.get("available"):
        for name in sorted(union):
            hit = module_index["modules"].get(name.lower())
            if hit:
                declared[name] = hit
            else:
                undeclared.append(name)

    corroborated = bool(declared)
    annotation = interpretive_annotation(
        target,
        CONFIDENCE_TWO_METHODS if corroborated else CONFIDENCE_ONE_METHOD,
        note=(
            "%d absolute source-file paths occur in the image, naming %d distinct "
            "file names; the module names extracted from them number %d distinct, "
            "of which %d are declared by "
            "a <Module>.build.cs in the local UE 5.4.4 tree. Interpretive: it "
            "reads a byte run as a path, applies a layout rule to pick the module "
            "component out of it, and treats the result as naming a compilation "
            "unit that went into this image. WHAT WOULD REFUTE IT: a module name "
            "in the list that the engine tree does not declare AND that is not a "
            "plausible module (the 'not_declared_as_ue_module' list is published "
            "for exactly that inspection); or the extraction rule picking a "
            "grouping directory -- which is why the rule keys on the "
            "Private/Public/Classes/Internal component rather than on a fixed "
            "depth. WHAT IT DOES NOT SHOW: completeness. These paths come from "
            "__FILE__ expansions surviving in check() and assert() text, so the "
            "module list is the set of modules that have a surviving assertion "
            "string, which is a SUBSET of the modules compiled in -- a module "
            "with no such string is invisible here and its absence is not "
            "evidence. The same bound applies file by file, which is why every "
            "answer in 'file_queries' carries it."
            % (total, len(file_union), len(union), len(declared))),
        methods=([
            {"id": "path-literal-scan", "oracle": "binary-analysis",
             "note": "a printable-run scan of the image, then a path-shape rule "
                     "and the module-layout extraction rule applied to each hit"},
            {"id": "ue-module-index", "oracle": "filesystem",
             "artifact": (module_index or {}).get("root"),
             "note": "an independent walk of the local UE 5.4.4 source tree "
                     "collecting <Module>.build.cs declarations; a different "
                     "oracle and a different act of measurement, which is what "
                     "turns 'this looks like a module name' into 'the engine "
                     "declares a module of this name'"},
        ] if corroborated else [
            {"id": "path-literal-scan", "oracle": "binary-analysis",
             "note": "a printable-run scan and the module-layout extraction rule; "
                     "no engine tree was supplied, so nothing corroborated it"},
        ]),
        oracles=(["binary-analysis", "external-doc", "filesystem"] if corroborated
                 else ["binary-analysis"]))

    return {
        "question": ("Are there UE source-path literals, and do they name a "
                     "build-machine root?"),
        "path_literal_count": total,
        "build_roots": dict(sorted(roots.items(),
                                   key=lambda item: (-item[1], item[0]))),
        "engine_trees": dict(sorted(trees.items(),
                                    key=lambda item: (-item[1], item[0]))),
        "path_separators": dict(sorted(separators.items())),
        "distinct_modules": len(union),
        "modules": sorted(union),
        "modules_in_both_encodings": sorted(both),
        "occurrences_by_module": {
            name: {"ascii": modules_by_encoding[ENCODING_ASCII].get(name, 0),
                   "utf16": modules_by_encoding[ENCODING_UTF16].get(name, 0)}
            for name in sorted(union)},
        "module_examples": {name: module_examples[name]
                            for name in sorted(module_examples)},
        "distinct_files": len(file_union),
        "files": sorted(file_union),
        "files_in_both_encodings": sorted(file_both),
        "occurrences_by_file": {
            name: {"ascii": files_by_encoding[ENCODING_ASCII].get(name, 0),
                   "utf16": files_by_encoding[ENCODING_UTF16].get(name, 0),
                   "modules": sorted(file_to_modules.get(name, ()))}
            for name in sorted(file_union)},
        "files_by_module": {
            module: sorted(name for name in file_union
                           if module in file_to_modules.get(name, ()))
            for module in sorted(union)},
        "file_examples": {name: file_examples[name]
                          for name in sorted(file_examples)},
        "file_queries": queries,
        "paths_with_no_extractable_module": dict(sorted(
            unextracted.items(), key=lambda item: (-item[1], item[0]))),
        "declared_as_ue_module": dict(sorted(declared.items())),
        "not_declared_as_ue_module": sorted(undeclared),
        "module_index_available": bool(module_index
                                       and module_index.get("available")),
        "evidence": annotation,
    }


def build_origin_finding(sink: StringSink, target: str, script: dict,
                         v07: dict | None, install_plugins: dict | None) -> dict:
    """Question 3: which strings look like the GAME rather than engine or library?

    Graded low on purpose. Sorting strings by origin is a naming-convention
    heuristic on one oracle, and S-10's result -- zero game classes in RTTI --
    is a reason to look here, not a reason to believe what is found. Two tiers
    are reported separately because they are not the same claim:

    ``corroborated_game_names``
        names that the string scan finds AND that a second oracle independently
        calls non-engine: a ``.uplugin``/``.uproject`` entry in V-07's container
        index, or a directory in the installation's own ``Plugins`` tree. Two
        methods, two oracles, so this tier can carry 0.85 -- but only for the
        narrow claim "this name belongs to a non-engine plugin or project of this
        build", not for anything about what code it names.

    ``heuristic_game_candidates``
        names that merely fail to appear in the engine module index. One method.
        0.65, and the rule table is printed so a reviewer can reject one rule
        rather than the whole tier.
    """
    container_plugins = set((v07 or {}).get("plugin_names") or {})
    container_projects = set((v07 or {}).get("project_names") or {})
    engine_plugins = set((v07 or {}).get("engine_plugin_names") or [])
    non_engine_plugins = set((v07 or {}).get("non_engine_plugin_names") or [])
    installed = set((install_plugins or {}).get("names") or [])

    undeclared = set(script.get("not_declared_as_ue_module") or [])
    corroborated = dict(script.get("not_declared_but_corroborated_non_engine") or {})
    heuristic = sorted(undeclared - set(corroborated))

    # Where the two name populations agree and disagree. They are DIFFERENT
    # KINDS of name -- a .uplugin is a plugin, a /Script/ path carries a module
    # -- so the set arithmetic is reported with that stated rather than implied.
    script_names = set(script.get("names") or [])
    agreement = {
        "plugin_names_also_seen_as_script_modules": sorted(
            container_plugins & script_names),
        "plugin_names_never_seen_as_a_script_module": sorted(
            container_plugins - script_names),
        "script_modules_that_are_not_a_plugin_name": sorted(
            script_names - container_plugins - container_projects),
        "non_engine_plugin_names_seen_as_script_modules": sorted(
            non_engine_plugins & script_names),
        "non_engine_plugin_names_not_seen": sorted(
            non_engine_plugins - script_names),
        "engine_plugin_names_seen_as_script_modules": sorted(
            engine_plugins & script_names),
        "installation_plugin_directories": sorted(installed),
        "why_the_two_sets_differ_by_construction": (
            "a .uplugin entry is a PLUGIN descriptor staged into the container; a "
            "/Script/<Name> literal carries a MODULE name. One plugin commonly "
            "declares several modules under names unlike its own (a runtime "
            "module, an editor module, a shared module), and an engine plugin can "
            "be staged as content while none of its modules is linked into this "
            "executable. So a plugin name absent from the /Script/ set is not "
            "evidence that the plugin is absent, and a /Script/ name absent from "
            "the plugin set is not evidence that it is not a plugin's module."),
    }

    corroborated_annotation = interpretive_annotation(
        target, CONFIDENCE_TWO_METHODS,
        note=(
            "%d names are reached by two independent oracles: a printable-run "
            "scan of the executable, and a name in the packaged container index "
            "or a directory in the installation's own Plugins tree. The claim "
            "graded here is narrow and deliberately so: these names belong to "
            "non-engine plugins or to the project of this build. WHAT WOULD "
            "REFUTE IT: finding any of these names declared by a <Module>.build.cs "
            "in the engine tree after all -- which is checked, and is why they are "
            "in this tier rather than the engine one. WHAT IT DOES NOT SHOW: that "
            "any game CODE is identifiable. A module name is a name; S-10 found "
            "zero game classes in RTTI and this finding does not change that."
            % len(corroborated)),
        methods=[
            {"id": "script-path-scan", "oracle": "binary-analysis",
             "note": "the /Script/ literals found by the run scan of this image"},
            {"id": "container-and-install-index", "oracle": "container-metadata",
             "artifact": (v07 or {}).get("path"),
             "note": "the plugin and project descriptor names in V-07's reading "
                     "of the pak directory index, plus the plugin directory names "
                     "present in the installation; neither reads the executable, "
                     "so neither can inherit a mistake made by the run scan"},
        ],
        oracles=["binary-analysis", "container-metadata", "filesystem"])

    heuristic_annotation = interpretive_annotation(
        target, CONFIDENCE_HEURISTIC,
        note=(
            "%d further names match the shape of a UE module but are not declared "
            "by any <Module>.build.cs in the local UE 5.4.4 tree, and no second "
            "oracle names them. HYPOTHESIS, one method, 0.65: 'absent from the "
            "engine tree' has at least three explanations besides 'belongs to the "
            "game' -- a legacy module name kept alive by a core-redirect table, a "
            "module from a marketplace plugin not staged into this container, and "
            "a module whose .build.cs the index missed. The list is published "
            "name by name so each can be settled separately instead of being "
            "believed collectively. WHAT WOULD REFUTE IT: any one of these names "
            "turning out to be an engine module under a spelling the index does "
            "not cover." % len(heuristic)),
        methods=[{"id": "module-index-absence", "oracle": "filesystem",
                  "note": "absence from the <Module>.build.cs index built from "
                          "the local engine tree -- one act of measurement, and "
                          "an absence rather than an observation"}],
        oracles=["binary-analysis", "filesystem"],
        level="HYPOTHESIS")

    return {
        "question": ("Which strings look like they belong to the game rather "
                     "than the engine or a third-party library?"),
        "corroborated_game_names": dict(sorted(corroborated.items())),
        "heuristic_game_candidates": heuristic,
        "plugin_name_agreement": agreement,
        "category_counts": dict(sorted(sink.by_category.items(),
                                       key=lambda item: (-item[1], item[0]))),
        "classification_rules": [
            {"category": category, "pattern": pattern.pattern, "claims": claims}
            for category, pattern, claims in CLASSIFICATION_RULES],
        "publishable_categories": sorted(PUBLISHABLE_CATEGORIES),
        "what_this_surface_cannot_do": (
            "a string is not a symbol. This surface can name a module, a log "
            "category, a console variable or an asset path; it cannot name a "
            "class, a function or a field, and nothing here narrows S-10's result "
            "that no game class carries RTTI in this build."),
        "evidence_corroborated": corroborated_annotation,
        "evidence_heuristic": heuristic_annotation,
    }


# --------------------------------------------------------------------------- #
# refutation probes
# --------------------------------------------------------------------------- #

def build_refutation_probes(document_parts: dict) -> list[dict]:
    """Five checks whose PURPOSE is to break the headline numbers.

    A scan that only produces supporting counts cannot tell a real finding from
    a broken scanner, so each probe states what result would refute the reading
    and reports whether that happened.
    """
    sink: StringSink = document_parts["sink"]
    stats: Counter = document_parts["stats"]
    regions: list[dict] = document_parts["regions"]
    control: dict = document_parts["noise_control"]
    rva_probe: dict = document_parts["rva_probe"]
    size: int = document_parts["file_size"]
    probes: list[dict] = []

    # P1: is the population at the low lengths distinguishable from noise?
    observed = sink.length_histogram[ENCODING_ASCII]
    expected = {}
    ratios = {}
    noise_dominated = []
    if control.get("ran"):
        expected = control["expected_at_target_size"][ENCODING_ASCII]
        for length in sorted(observed):
            got = observed[length]
            want = expected.get(str(length))
            if want is None:
                continue
            ratio = (got / want) if want else None
            ratios[str(length)] = None if ratio is None else round(ratio, 3)
            if ratio is not None and ratio < 2.0 and length < NOISE_HISTOGRAM_MAX_LENGTH:
                noise_dominated.append(length)
    probes.append({
        "id": "P1-low-length-noise-floor",
        "question": ("At the minimum length this scan uses, is the ASCII "
                     "population distinguishable from incidental byte runs?"),
        "refuting_result": (
            "observed counts at the shortest lengths within a factor of two of "
            "what a same-size buffer of pseudo-random bytes produces -- those "
            "lengths would then carry no information on their own, and any "
            "conclusion drawn from a bare count of 'strings' would be a "
            "conclusion about noise"),
        "observed": {
            "min_length": document_parts["min_length"],
            "noise_band_ceiling_ascii": NOISE_BAND_CEILING_ASCII,
            "control_ran": bool(control.get("ran")),
            "observed_by_length": {str(k): v for k, v in sorted(observed.items())},
            "expected_by_length_from_random_control": expected,
            "observed_over_expected": ratios,
            "lengths_noise_dominated": noise_dominated,
            "records_flagged_noise_band": sink.flags.get("noise_band", 0),
        },
        # This probe is EXPECTED to refute at the low lengths, and that is the
        # point: it is why nothing is dropped and everything short is flagged.
        # Reporting it as "did not refute" would be the dishonest outcome.
        "refuted_the_conclusion": bool(noise_dominated),
        "what_the_refutation_means_here": (
            "it does NOT invalidate the index. It says that a count of records is "
            "not a count of strings at these lengths, which is why every record "
            "carries char_count and noise_band and why no consumer should filter "
            "by record count alone."),
    })

    # P2: is the UTF-16 layer fabricating strings out of integer tables?
    accepted = sink.by_encoding.get(ENCODING_UTF16, 0)
    low_info = document_parts["utf16_low_information"]
    rejected = stats.get("utf16_rejected_odd_alignment", 0)
    share = (low_info / accepted) if accepted else None
    probes.append({
        "id": "P2-utf16-is-not-an-integer-table",
        "question": ("Are the UTF-16LE runs strings, or arrays of small integers "
                     "read as text?"),
        "refuting_result": (
            "a large share of accepted runs with no alphabetic character or fewer "
            "than three distinct characters -- the shape of an index table -- or "
            "an odd-aligned rejected population large enough that the alignment "
            "rule is deciding the answer rather than filtering an artefact"),
        "observed": {
            "accepted": accepted,
            "rejected_odd_alignment": rejected,
            "rejected_short_after_length_cap": stats.get(
                "utf16_rejected_short_after_cap", 0),
            "low_information_accepted": low_info,
            "low_information_share": None if share is None else round(share, 4),
            "runs_abutting_a_wide_non_ascii_character":
                sink.flags.get("abuts_wide_non_ascii", 0),
            "random_control_expectation_at_target_size":
                (control.get("expected_at_target_size", {}) or {}).get(
                    ENCODING_UTF16, {}),
        },
        "refuted_the_conclusion": bool(share is not None and share > 0.25),
    })

    # P3: does every byte of the file belong to exactly one region?
    covered = sum(region["length"] for region in regions)
    ordered = all(regions[i]["end"] == regions[i + 1]["start"]
                  for i in range(len(regions) - 1))
    starts_at_zero = (not regions) or regions[0]["start"] == 0
    ends_at_eof = (not regions) or regions[-1]["end"] == size
    probes.append({
        "id": "P3-region-cover-is-complete",
        "question": ("Do the scanned regions tile the whole file, with no byte "
                     "uncovered and none covered twice?"),
        "refuting_result": (
            "a covered total unequal to the file size, a discontinuity between "
            "consecutive regions, or a first/last region not touching the file "
            "boundaries -- any of which means some offsets could never be "
            "reported, so a null result at those offsets would be an artefact of "
            "the scanner rather than a fact about the file"),
        "observed": {
            "file_size": size,
            "regions": len(regions),
            "bytes_covered": covered,
            "contiguous": ordered,
            "starts_at_zero": starts_at_zero,
            "ends_at_eof": ends_at_eof,
            "by_kind": dict(sorted(Counter(
                region["kind"] for region in regions).items())),
        },
        "refuted_the_conclusion": not (covered == size and ordered
                                       and starts_at_zero and ends_at_eof),
    })

    # P4: is every reported RVA one a later reader can act on?
    probes.append({
        "id": "P4-rva-round-trips-through-the-pe-parser",
        "question": ("Does every RVA this index reports translate back to the "
                     "file offset it came from?"),
        "refuting_result": (
            "any sampled record whose RVA, fed through "
            "pe_info.PEHeaders.rva_to_offset -- a different implementation, "
            "written for F-01 and not by this tool -- comes back as a different "
            "offset or as None. Every xref built on this index would then point "
            "somewhere else, and the failure would be invisible in the counts; or "
            "any sampled record reported WITHOUT an rva whose offset the raw "
            "section table does in fact cover, which would mean a real address "
            "was turned into a null and a later xref hunt over those bytes would "
            "come back empty for a reason that is not about the file"),
        "observed": rva_probe,
        "refuted_the_conclusion": bool(rva_probe.get("mismatches")
                                       or rva_probe.get("absent_rva_but_mappable")),
    })

    # P5: how much do the two encodings double-count?
    overlaps = stats.get("ranges_claimed_by_both_encodings", 0)
    probes.append({
        "id": "P5-cross-encoding-double-count",
        "question": ("How many byte ranges are claimed by both the ASCII and the "
                     "UTF-16 pass, so that one region of the file is counted "
                     "twice?"),
        "refuting_result": (
            "an overlap large relative to the UTF-16 population, which would mean "
            "the two layers are largely describing the same bytes and the total "
            "record count is not a count of distinct string data"),
        "observed": {
            "overlapping_pairs": overlaps,
            "utf16_records": accepted,
            "ascii_records": sink.by_encoding.get(ENCODING_ASCII, 0),
            "overlap_over_utf16": (round(overlaps / accepted, 4)
                                   if accepted else None),
        },
        "refuted_the_conclusion": bool(accepted and overlaps > accepted * 0.5),
    })
    return probes


def _raw_range_owner(headers, offset: int) -> str | None:
    """The headers, or the section, whose RAW range covers *offset*; else None.

    Re-derived from the section table here rather than asked of ``RegionMap``, on
    purpose. RegionMap is what decided the offset has no RVA; asking it whether
    the offset is mappable would only ask it to repeat itself, and the point of
    the check is to give a second opinion. This reading clamps nothing and
    merges nothing -- it is the raw table.
    """
    if offset < min(headers.size_of_headers, headers.image.size):
        return "headers"
    for section in headers.sections:
        start = section["raw_pointer"]
        length = section["rsize"]
        if length and start <= offset < start + length:
            return section["name"] or "<unnamed>"
    return None


def probe_rva_round_trip(headers, sink: StringSink, sample: int) -> dict:
    """Feed reported RVAs back through the PE parser and report disagreements.

    Two populations are checked, for two different reasons: the FIRST AND LAST
    record of every region, because a translation bug shows itself at a boundary
    before it shows itself in the middle; and a decimated sample spread over the
    whole index, because a bug confined to the middle of one big section would
    never touch a boundary.

    Both directions are checked. A reported RVA must translate back to its own
    file offset. An ABSENT RVA must be absent for a reason: no section's raw
    range and not the header span may cover that offset, or this tool declared
    unaddressable a byte the loader does in fact map -- which would turn a real
    address into a null and make a later xref hunt come back empty.
    """
    boundary = []
    for records in sink.first_last_by_region.values():
        boundary.extend(records)
    population = list(boundary) + list(sink.rva_sample)
    checked = 0
    boundary_checked = 0
    absent_checked = 0
    mismatches = []
    absent_but_mappable = []
    seen = set()
    for index, record in enumerate(population):
        key = (record["offset"], record["encoding"])
        if key in seen:
            continue
        seen.add(key)
        checked += 1
        if index < len(boundary):
            boundary_checked += 1
        if record["rva"] is None:
            absent_checked += 1
            owner = _raw_range_owner(headers, record["offset"])
            if owner is not None:
                absent_but_mappable.append({"offset": record["offset"],
                                            "region": record["region"],
                                            "raw_range_owner": owner})
            continue
        back = headers.rva_to_offset(record["rva"])
        if back != record["offset"]:
            mismatches.append({"offset": record["offset"], "rva": record["rva"],
                               "parser_offset": back, "region": record["region"]})
    return {
        "records_checked": checked,
        "boundary_records_checked": boundary_checked,
        "boundary_records_available": len(boundary),
        "spread_sample_records": len(sink.rva_sample),
        "records_with_absent_rva_checked": absent_checked,
        "sample_cap": sample,
        "mismatches": mismatches,
        "mismatch_count": len(mismatches),
        "absent_rva_but_mappable": absent_but_mappable,
        "absent_rva_but_mappable_count": len(absent_but_mappable),
        "method": ("each reported rva fed to pe_info.PEHeaders.rva_to_offset and "
                   "required to return the record's own file offset; each absent "
                   "rva checked against the raw section table for an owner that "
                   "would have made it addressable"),
    }


# --------------------------------------------------------------------------- #
# top-level analysis
# --------------------------------------------------------------------------- #

def _is_d04_oracle(path: str) -> bool:
    """True for the 282 MB MISERY.exe -- decision D-04's read-only oracle.

    Stamped on the document rather than refused: reading it is allowed and
    useful. What is not allowed is letting a conclusion reached there stand
    without re-verification on the Shipping binary.
    """
    normalised = os.path.abspath(path).replace("\\", "/").lower()
    return normalised.endswith("/binaries/win64/misery.exe")


def analyze(path: str, *, min_length: int = DEFAULT_MIN_LENGTH,
            jsonl_handle=None,
            literal_samples: int = DEFAULT_LITERAL_SAMPLES,
            classified_cap: int = DEFAULT_CLASSIFIED_CAP,
            noise_control_bytes: int = DEFAULT_NOISE_CONTROL_BYTES,
            want_noise_control: bool = True,
            want_file_digest: bool = True,
            ue_source_root: str | None = None,
            v07_plugins: str | None = None,
            install_root: str | None = None,
            file_queries: list[str] | None = None,
            rva_probe_sample: int = DEFAULT_RVA_PROBE_SAMPLE) -> dict:
    """Scan *path* and return the whole document. Read-only, bounded, streaming."""
    warnings: list[str] = []
    timings: dict[str, float] = {}
    started_total = time.monotonic()

    if not MIN_ALLOWED_MIN_LENGTH <= min_length <= MAX_ALLOWED_MIN_LENGTH:
        raise ValueError("--min-length must be between %d and %d"
                         % (MIN_ALLOWED_MIN_LENGTH, MAX_ALLOWED_MIN_LENGTH))

    patterns = build_patterns(min_length)

    with pe_info.Image.open(path) as image:
        headers = pe_info.PEHeaders(image)
        warnings.extend(headers.warnings)
        region_map = RegionMap(headers, warnings)

        sink = StringSink(jsonl_handle, classified_cap,
                          rva_sample_cap=rva_probe_sample)
        stats: Counter = Counter()

        started = time.monotonic()
        for entry in region_map.regions:
            scan_region(image, region_map, entry, patterns, min_length, sink, stats)
        timings["string_scan"] = round(time.monotonic() - started, 3)

        # The UTF-16 low-information count has to be taken from the records, and
        # the records are gone by now, so the sink counts it as it goes. It is
        # separated out here because probe P2 needs the UTF-16 share alone and
        # sink.flags mixes both encodings.
        utf16_low_information = sink.low_information_by_encoding.get(
            ENCODING_UTF16, 0)

        started = time.monotonic()
        control = (noise_control(min_length, noise_control_bytes, image.size)
                   if want_noise_control else {"ran": False,
                                               "reason": "--no-noise-control"})
        timings["noise_control"] = round(time.monotonic() - started, 3)

        started = time.monotonic()
        module_index = (build_ue_module_index(ue_source_root, warnings)
                        if ue_source_root else None)
        timings["ue_module_index"] = round(time.monotonic() - started, 3)

        v07 = load_v07_plugin_names(v07_plugins, warnings) if v07_plugins else None
        detected_root = install_root or pe_info.detect_install_root(path)
        installed = install_plugin_directories(
            detected_root if pathguard.looks_like_install_root(detected_root or "")
            else None)

        target = locus_target(path, install_root)

        started = time.monotonic()
        script_finding = build_script_path_finding(sink, target, module_index,
                                                   v07, installed)
        source_finding = build_source_path_finding(sink, target, module_index,
                                                   file_queries)
        origin_finding = build_origin_finding(sink, target, script_finding, v07,
                                              installed)
        timings["findings"] = round(time.monotonic() - started, 3)

        rva_probe = probe_rva_round_trip(headers, sink, rva_probe_sample)

        # ---- class-P literal layer ------------------------------------------ #
        started = time.monotonic()
        literals: list[dict] = []
        sample_pool = []
        for records in sink.first_last_by_region.values():
            sample_pool.extend(records)
        for category in sorted(PUBLISHABLE_CATEGORIES):
            sample_pool.extend(sink.classified.get(category, ()))
        sample_pool.sort(key=lambda record: (record["offset"],
                                             ENCODING_ORDER[record["encoding"]]))
        for record in _spread(sample_pool, literal_samples):
            raw = image.read_at(record["offset"], record["length"], "string bytes")
            literals.append(literal_read(
                target, "strings.jsonl@offset=%d" % record["offset"],
                record["offset"], raw,
                note=("a range of bytes selected by an evenly spaced sample over "
                      "the regions this run covered")))
        confirm_literal_reads(path, literals, target, warnings)
        timings["literal_reads"] = round(time.monotonic() - started, 3)

        file_sha256 = None
        if want_file_digest:
            started = time.monotonic()
            digest = hashlib.sha256()
            for _position, chunk in image.iter_chunks(0, image.size):
                digest.update(chunk)
            file_sha256 = digest.hexdigest()
            timings["file_digest"] = round(time.monotonic() - started, 3)

        summary = {
            "min_length": min_length,
            "records_total": sink.total,
            "records_ascii": sink.by_encoding.get(ENCODING_ASCII, 0),
            "records_utf16": sink.by_encoding.get(ENCODING_UTF16, 0),
            "records_in_noise_band": sink.flags.get("noise_band", 0),
            "records_low_information": sink.flags.get("low_information", 0),
            "records_nul_terminated": sink.flags.get("nul_terminated", 0),
            "records_clipped": sink.flags.get("clipped", 0),
            "records_without_rva": sink.flags.get("rva_absent", 0),
            "records_beyond_virtual_size": sink.flags.get("beyond_virtual_size", 0),
            "records_abutting_wide_non_ascii":
                sink.flags.get("abuts_wide_non_ascii", 0),
            "utf16_rejected_odd_alignment":
                stats.get("utf16_rejected_odd_alignment", 0),
            "utf16_rejected_short_after_length_cap":
                stats.get("utf16_rejected_short_after_cap", 0),
            "runs_clipped_by_length_cap": stats.get("runs_clipped_by_length_cap", 0),
            "runs_touching_region_end": stats.get("runs_touching_region_end", 0),
            "ranges_claimed_by_both_encodings":
                stats.get("ranges_claimed_by_both_encodings", 0),
            "by_region_kind": dict(sorted(sink.by_region_kind.items())),
            "by_region": dict(sorted(sink.by_region_name.items(),
                                     key=lambda item: (-item[1], item[0]))),
            "by_category": dict(sorted(sink.by_category.items(),
                                       key=lambda item: (-item[1], item[0]))),
            "length_histogram": {
                encoding: {str(length): count
                           for length, count in sorted(counter.items())}
                for encoding, counter in sink.length_histogram.items()},
            "length_histogram_pooled_above": NOISE_HISTOGRAM_MAX_LENGTH,
            "classified_retained": {category: len(records) for category, records
                                    in sorted(sink.classified.items())},
            "classified_truncated": dict(sorted(sink.classified_truncated.items())),
            "jsonl_bytes_written": sink.bytes_emitted,
        }

        document_parts = {
            "sink": sink,
            "stats": stats,
            "regions": region_map.describe(),
            "noise_control": control,
            "rva_probe": rva_probe,
            "file_size": image.size,
            "min_length": min_length,
            "utf16_low_information": utf16_low_information,
        }
        probes = build_refutation_probes(document_parts)

        timings["total"] = round(time.monotonic() - started_total, 3)

        document = {
            "file": {
                "path": os.path.abspath(path),
                # "name" is the basename and stays the basename; the determinate
                # spelling a class-P locus needs is "install_relative".
                "name": os.path.basename(path),
                "install_relative": target,
                "size": image.size,
                "sha256": file_sha256,
                "pe_format": headers.pe_format,
                "machine": headers.machine,
                "image_base": headers.image_base,
                "size_of_image": headers.size_of_image,
                "size_of_headers": headers.size_of_headers,
            },
            "generated_at": now_iso_utc(),
            "generator": GENERATOR_NAME,
            "generator_version": GENERATOR_VERSION,
            "task": "S-01",
            "d04_oracle_only": _is_d04_oracle(path),
            "tested_surface": {
                "regions": region_map.describe(),
                "encodings": [ENCODING_ASCII, ENCODING_UTF16],
                "min_length_characters": min_length,
                "ascii_pattern": patterns[0].pattern.decode("latin-1"),
                "utf16_pattern": patterns[1].pattern.decode("latin-1"),
                "utf16_alignment_rule": ("a candidate must start at an even image "
                                         "offset; odd-aligned runs are counted and "
                                         "rejected"),
                "max_recorded_run_bytes": MAX_STRING_BYTES,
                "terminator_required": False,
                "printable_class": "0x20..0x7e; no tab, no CR, no LF",
                "not_tested": [
                    "a string built at run time, or held compressed or encrypted "
                    "on disk, is not on this surface: only the bytes of the image "
                    "as stored are read",
                    "the virtual tail of a section (VirtualSize beyond raw size) "
                    "holds no bytes on disk and cannot be searched",
                    "any encoding other than 8-bit printable-ASCII runs and "
                    "even-aligned UTF-16LE runs of printable-ASCII characters: "
                    "UTF-8 multibyte sequences, UTF-16BE, and UTF-16LE runs whose "
                    "characters are outside 0x20..0x7e are not matched, and a "
                    "UTF-16 string containing one non-ASCII character is reported "
                    "as the two runs either side of it (counted as "
                    "records_abutting_wide_non_ascii)",
                ],
            },
            "noise_control": control,
            "ue_module_index": (None if module_index is None else {
                "root": module_index["root"],
                "available": module_index["available"],
                "modules_declared": len(module_index["modules"]),
                "files_scanned": module_index["files_scanned"],
                "elapsed_seconds": module_index["elapsed_seconds"],
                "truncated": module_index["truncated"],
                "marker": ("a file whose name ends, case-insensitively, in "
                           "'.build.cs'; the stem is the module name"),
            }),
            "container_index": (None if v07 is None else {
                "path": v07.get("path"),
                "available": v07.get("available"),
                "build_key": v07.get("build_key"),
                "entry_count": v07.get("entry_count"),
                "plugin_names": sorted(v07.get("plugin_names") or {}),
                "project_names": sorted(v07.get("project_names") or {}),
                "engine_plugin_names": v07.get("engine_plugin_names"),
                "non_engine_plugin_names": v07.get("non_engine_plugin_names"),
            }),
            "install_plugin_directories": installed,
            "findings": {
                "script_paths": script_finding,
                "engine_source_paths": source_finding,
                "origin": origin_finding,
            },
            "summary": summary,
            "refutation_probes": probes,
            "literal_reads": literals,
            "timings_seconds": timings,
            "warnings": sorted(set(warnings)),
        }
        return document


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def format_summary(document: dict, name_limit: int = 40) -> str:
    out: list[str] = []
    add = out.append
    summary = document["summary"]
    file_info = document["file"]

    add("%s (%s %s)" % (file_info["path"], GENERATOR_NAME, GENERATOR_VERSION))
    add("  %s, image base 0x%x, %d bytes on disk, SizeOfHeaders %d"
        % (file_info["pe_format"], file_info["image_base"], file_info["size"],
           file_info["size_of_headers"]))
    if document["d04_oracle_only"]:
        add("  D-04: this file is the read-only ORACLE. Any conclusion drawn here "
            "must be re-verified on MISERY-Win64-Shipping.exe before it counts.")
    add("")
    add("Tested surface: %d regions tiling [0, %d), min length %d characters"
        % (len(document["tested_surface"]["regions"]), file_info["size"],
           summary["min_length"]))
    for region in document["tested_surface"]["regions"]:
        add("  %-10s %-22s [%d, %d)  %d bytes  rva=%s"
            % (region["kind"], region["name"], region["start"], region["end"],
               region["length"], "yes" if region["rva_available"] else "NO"))
    add("")
    add("Records")
    add("  total                          : %d" % summary["records_total"])
    add("  ascii                          : %d" % summary["records_ascii"])
    add("  utf-16le                       : %d" % summary["records_utf16"])
    add("  in the ascii noise band (<%d)   : %d"
        % (NOISE_BAND_CEILING_ASCII, summary["records_in_noise_band"]))
    add("  low information                 : %d" % summary["records_low_information"])
    add("  NUL-terminated                  : %d" % summary["records_nul_terminated"])
    add("  clipped (length cap / region end): %d" % summary["records_clipped"])
    add("  WITHOUT an RVA                  : %d" % summary["records_without_rva"])
    add("  in a section's raw tail         : %d"
        % summary["records_beyond_virtual_size"])
    add("  abutting a wide non-ASCII char  : %d"
        % summary["records_abutting_wide_non_ascii"])
    add("  utf-16 rejected, odd alignment  : %d"
        % summary["utf16_rejected_odd_alignment"])
    add("  ranges claimed by both encodings: %d"
        % summary["ranges_claimed_by_both_encodings"])
    add("")
    add("By region")
    for name, count in sorted(summary["by_region"].items(),
                              key=lambda item: (-item[1], item[0])):
        add("  %-10d %s" % (count, name))
    add("")
    add("By category")
    for name, count in sorted(summary["by_category"].items(),
                              key=lambda item: (-item[1], item[0])):
        add("  %-10d %s" % (count, name))
    add("")
    add("ASCII length histogram (observed / random control expectation / ratio)")
    probe = next((p for p in document["refutation_probes"]
                  if p["id"] == "P1-low-length-noise-floor"), None)
    if probe:
        observed = probe["observed"]["observed_by_length"]
        expected = probe["observed"]["expected_by_length_from_random_control"]
        ratios = probe["observed"]["observed_over_expected"]
        for length in sorted(observed, key=int):
            add("  %-4s %-12d %-14s %s"
                % (length, observed[length], expected.get(length, "-"),
                   ratios.get(length, "-")))
        add("  lengths noise-dominated (ratio < 2): %s"
            % (probe["observed"]["lengths_noise_dominated"] or "none"))

    add("")
    script = document["findings"]["script_paths"]
    add("Q1  /Script/ package paths: %d distinct (%d in both encodings, %d ascii "
        "only, %d utf-16 only)"
        % (script["distinct_names"], len(script["names_in_both_encodings"]),
           len(script["names_ascii_only"]), len(script["names_utf16_only"])))
    add("    occurrences: ascii %d, utf-16 %d"
        % (script["occurrences_ascii"], script["occurrences_utf16"]))
    if script["module_index_available"]:
        add("    declared as a UE module by the local engine tree: %d"
            % len(script["declared_as_ue_module"]))
        add("    NOT declared there (%d): %s"
            % (len(script["not_declared_as_ue_module"]),
               ", ".join(script["not_declared_as_ue_module"]) or "none"))
        for name, reasons in sorted(
                script["not_declared_but_corroborated_non_engine"].items()):
            add("      %-28s corroborated by %d other reading(s)"
                % (name, len(reasons)))
    for name in script["names"][:name_limit]:
        counts = script["occurrences_by_name"][name]
        add("      %-34s ascii %-4d utf16 %-4d"
            % (name, counts["ascii"], counts["utf16"]))
    if len(script["names"]) > name_limit:
        add("      ... %d more" % (len(script["names"]) - name_limit))

    add("")
    source = document["findings"]["engine_source_paths"]
    add("Q2  absolute source-path literals: %d" % source["path_literal_count"])
    for root, count in list(source["build_roots"].items())[:6]:
        add("      %-8d root %s" % (count, root))
    for tree, count in list(source["engine_trees"].items())[:6]:
        add("      %-8d tree %s" % (count, tree))
    add("    separators: %s" % json.dumps(source["path_separators"], sort_keys=True))
    add("    distinct modules named: %d (%d in both encodings)"
        % (source["distinct_modules"], len(source["modules_in_both_encodings"])))
    if source["module_index_available"]:
        add("      declared by the local engine tree: %d"
            % len(source["declared_as_ue_module"]))
        add("      NOT declared there: %s"
            % (", ".join(source["not_declared_as_ue_module"]) or "none"))
    add("    modules: %s" % ", ".join(source["modules"][:name_limit]))
    if len(source["modules"]) > name_limit:
        add("      ... %d more" % (len(source["modules"]) - name_limit))
    add("    distinct FILE names: %d (%d in both encodings)"
        % (source["distinct_files"], len(source["files_in_both_encodings"])))
    for name, answer in sorted(source["file_queries"].items()):
        if answer["present"]:
            counts = answer["occurrences"][answer["matched_spellings"][0]]
            add("    query %-44s PRESENT (ascii %d, utf16 %d, module %s)"
                % (name, counts["ascii"], counts["utf16"],
                   ", ".join(answer["modules"]) or "-"))
        else:
            add("    query %-44s NOT FOUND on the tested surface (absence of a "
                "path literal, not of the code)" % name)
    if source["paths_with_no_extractable_module"]:
        add("    paths with no extractable module: %s"
            % json.dumps(source["paths_with_no_extractable_module"],
                         sort_keys=True)[:400])

    add("")
    origin = document["findings"]["origin"]
    add("Q3  game-origin candidates")
    add("    corroborated by a second oracle (%d):"
        % len(origin["corroborated_game_names"]))
    for name, reasons in sorted(origin["corroborated_game_names"].items()):
        add("      %-28s %s" % (name, "; ".join(reasons)))
    add("    heuristic only, one method, 0.65 (%d): %s"
        % (len(origin["heuristic_game_candidates"]),
           ", ".join(origin["heuristic_game_candidates"]) or "none"))
    agreement = origin["plugin_name_agreement"]
    add("    V-07 plugin names also seen as /Script/ modules: %d"
        % len(agreement["plugin_names_also_seen_as_script_modules"]))
    add("    V-07 plugin names never seen as a /Script/ module: %d"
        % len(agreement["plugin_names_never_seen_as_a_script_module"]))
    add("    /Script/ modules that are not any plugin name: %d"
        % len(agreement["script_modules_that_are_not_a_plugin_name"]))
    add("    non-engine plugin names seen as /Script/ modules: %s"
        % (", ".join(agreement["non_engine_plugin_names_seen_as_script_modules"])
           or "none"))

    add("")
    add("Refutation probes")
    for probe in document["refutation_probes"]:
        add("  %-42s %s" % (probe["id"],
                            "REFUTED THE CONCLUSION" if probe["refuted_the_conclusion"]
                            else "did not refute"))
        add("      %s" % probe["question"])
        if probe["id"] != "P1-low-length-noise-floor":
            add("      observed: %s" % json.dumps(probe["observed"],
                                                  sort_keys=True)[:600])
        if probe.get("what_the_refutation_means_here"):
            add("      note: %s" % probe["what_the_refutation_means_here"])

    module_index = document["ue_module_index"]
    if module_index is not None:
        add("")
        add("UE module index (%s)" % module_index["root"])
        if not module_index["available"]:
            add("  the tree was not available; the corroboration pass did not run")
        else:
            add("  %d modules declared, %d files walked, %s s"
                % (module_index["modules_declared"], module_index["files_scanned"],
                   module_index["elapsed_seconds"]))
    container = document["container_index"]
    if container is not None:
        add("")
        add("Container index (%s)" % container["path"])
        add("  %s plugin names, %s of them outside Engine/"
            % (len(container["plugin_names"] or []),
               len(container["non_engine_plugin_names"] or [])))

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


def write_text(text: str, out_path: str, install_root: str | None,
               what: str) -> str:
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
        prog="extract_strings.py",
        description=(
            "Read-only ASCII / UTF-16LE string index for a PE image (plan.md task "
            "S-01). Prints a human summary by default; --json prints the "
            "machine-readable document. Refuses any output path that resolves "
            "inside a game installation (D-01)."),
    )
    parser.add_argument("path", help="the PE image to read (opened read-only)")
    parser.add_argument("--json", action="store_true",
                        help="print the JSON summary document instead of the text summary")
    parser.add_argument("--out", default=None,
                        help=("write the JSON summary document here; refused (exit 2) "
                              "if it resolves inside a game installation, before "
                              "anything is opened"))
    parser.add_argument("--jsonl-out", default=None,
                        help=("write strings.jsonl here -- one record per string. For "
                              "a game binary this file carries the image's string "
                              "table verbatim: keep it in workspace/, never in git "
                              "(C-13)"))
    parser.add_argument("--install-dir", default=None,
                        help=("installation root the output guard checks against "
                              "(default: auto-detected from the input path)"))
    parser.add_argument("--min-length", type=int, default=DEFAULT_MIN_LENGTH,
                        metavar="N",
                        help=("minimum run length in CHARACTERS (default %d). Lower "
                              "than the conventional 8 on purpose: '/Script/' is 8 "
                              "and 'Link' is 4. Short runs are flagged, not dropped."
                              % DEFAULT_MIN_LENGTH))
    parser.add_argument("--literal-samples", type=int,
                        default=DEFAULT_LITERAL_SAMPLES, metavar="N",
                        help=("how many evenly spaced ranges to record as class-P "
                              "literal reads (default %d)" % DEFAULT_LITERAL_SAMPLES))
    parser.add_argument("--classified-cap", type=int,
                        default=DEFAULT_CLASSIFIED_CAP, metavar="N",
                        help=("how many records per publishable category to retain "
                              "for the findings (default %d)" % DEFAULT_CLASSIFIED_CAP))
    parser.add_argument("--noise-control-bytes", type=int,
                        default=DEFAULT_NOISE_CONTROL_BYTES, metavar="N",
                        help=("size of the pseudo-random control buffer (default %d)"
                              % DEFAULT_NOISE_CONTROL_BYTES))
    parser.add_argument("--no-noise-control", action="store_true",
                        help=("skip the random-byte control. The per-length "
                              "signal-to-noise ratios and refutation probe P1 are "
                              "then unavailable, and the minimum-length choice "
                              "becomes an assertion instead of a measurement"))
    parser.add_argument("--ue-source-root", default=None, metavar="DIR",
                        help=("an Unreal Engine source tree (e.g. "
                              "'D:/Program Files/UE_5.4/Engine'); enables the "
                              "second, independent method for every claim that a "
                              "name is an engine module"))
    parser.add_argument("--v07-plugins", default=None, metavar="FILE",
                        help=("a V-07 staged-plugins.json; enables the container "
                              "cross-check for the plugin/module comparison"))
    parser.add_argument("--file-query", action="append", default=None,
                        metavar="NAME",
                        help=("ask explicitly whether a source FILE NAME appears "
                              "in any absolute source-path literal (repeatable, "
                              "matched case-insensitively on the basename). The "
                              "answer lands in "
                              "findings.engine_source_paths.file_queries with its "
                              "occurrence counts, its module and the bound on what "
                              "an absent answer means"))
    parser.add_argument("--names", type=int, default=40, metavar="N",
                        help="how many names to print per finding")
    parser.add_argument("--no-digest", action="store_true",
                        help="skip the whole-file sha256")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not os.path.isfile(args.path):
        print("error: not a file: %s" % args.path, file=sys.stderr)
        return 2
    if args.literal_samples < 0:
        print("error: --literal-samples must not be negative", file=sys.stderr)
        return 2
    if not MIN_ALLOWED_MIN_LENGTH <= args.min_length <= MAX_ALLOWED_MIN_LENGTH:
        print("error: --min-length must be between %d and %d"
              % (MIN_ALLOWED_MIN_LENGTH, MAX_ALLOWED_MIN_LENGTH), file=sys.stderr)
        return 2
    if args.classified_cap < 0:
        print("error: --classified-cap must not be negative", file=sys.stderr)
        return 2

    install_root = args.install_dir or pe_info.detect_install_root(args.path)

    # Layer 1 (plan.md 1.5 / D-01) is checked before any parsing, so a refused
    # path costs nothing and leaves nothing behind. write_text checks again, and
    # the JSONL handle below is opened only after its path has passed.
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

    jsonl_handle = None
    jsonl_path = checked.get("--jsonl-out")
    try:
        if jsonl_path:
            parent = os.path.dirname(jsonl_path)
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
            jsonl_handle = open(jsonl_path, "w", encoding="utf-8", newline="\n")
        document = analyze(
            args.path,
            min_length=args.min_length,
            jsonl_handle=jsonl_handle,
            literal_samples=args.literal_samples,
            classified_cap=args.classified_cap,
            noise_control_bytes=args.noise_control_bytes,
            want_noise_control=not args.no_noise_control,
            want_file_digest=not args.no_digest,
            ue_source_root=args.ue_source_root,
            v07_plugins=args.v07_plugins,
            file_queries=args.file_query,
            # Only an EXPLICIT root is passed on: the fallback inside
            # detect_install_root is "the configured root", which would make a
            # file outside any installation look relative to one it is not in.
            install_root=args.install_dir,
        )
    except (PEFormatError, ValueError) as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2
    except OSError as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2
    finally:
        if jsonl_handle is not None:
            jsonl_handle.close()

    written: list[str] = []
    try:
        if "--out" in checked:
            written.append(write_text(dump_json(document), checked["--out"],
                                      install_root, "--out"))
    except pathguard.OutputPathRefused as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except OSError as error:
        print("error: cannot write: %s" % error, file=sys.stderr)
        return 2

    if args.json:
        sys.stdout.write(dump_json(document))
    else:
        print(format_summary(document, name_limit=args.names))
        for path in written:
            print("\nwritten: %s" % path)
        if jsonl_path:
            print("written: %s (%d records, %d bytes)"
                  % (jsonl_path, document["summary"]["records_total"],
                     document["summary"]["jsonl_bytes_written"]))
            print("  C-13: this file carries the image's string table verbatim. "
                  "It belongs in workspace/ (gitignored), not in git. Publish the "
                  "summary, the counts and this file's sha256 instead.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
