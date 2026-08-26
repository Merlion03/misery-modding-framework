#!/usr/bin/env python3
"""Read-only byte-pattern signature scanner (plan.md task S-07).

The question this tool exists to answer
---------------------------------------
plan.md 7.3 row S-07 asks for a verdict -- ``unique`` / ``ambiguous`` /
``absent`` -- for a byte-pattern signature in a binary, and names the reason the
verdict is wanted: *"повторная проверка на новой сборке"*. Every finding this
project records against a code address is worth exactly as much as the ability
to find that address again in the build that ships next month, and this tool is
the half of that mechanism that does the finding. ``tools/static/sigmake.py``
is the half that produces the signature; it imports this module for its own
uniqueness check, so there is one matcher in the repository and not two.

Why the verdict has three values and not two
--------------------------------------------
The failure modes are asymmetric and they must not be collapsed:

``unique``
    exactly one occurrence on the searched surface. This is the only verdict
    that licenses "the function is here".

``ambiguous``
    two or more occurrences. This is the dangerous one, and it is dangerous
    precisely because a tool that returned the *first* hit would look like it
    worked. A signature that matches twice does not identify anything; the
    honest output is the count and the list of places, and the caller must not
    be able to obtain an address from this tool without also learning that the
    address was one of several.

``absent``
    zero occurrences. On a *new* build this is the expected outcome for any
    signature that happens to span a build-varying immediate, and it means
    "re-locate this function", never "the function was removed". The
    distinction is not decoration: ``sigmake`` masks only what the base
    relocation table proves is relocated (see that module's ``mask policy``
    section), so a rebuilt image moves RIP-relative displacements and rel32
    call targets that this repository cannot detect without a disassembler.
    Absence is therefore the *designed* failure direction -- it is the safe one,
    because it produces a re-search instead of a wrong address.

A fourth state exists and is reported separately rather than folded into
``ambiguous``: ``count_truncated``, meaning the occurrence counter hit its cap
(``--count-cap``). A pattern that matches 200 000 times is not "ambiguous with
200 000 places", it is a pattern that is not a signature at all, and the output
says so with ``truncated: true`` so that a reader cannot mistake the printed
count for the real one.

The pattern grammar, and what it deliberately refuses
-----------------------------------------------------
One byte per token, whitespace separated, case-insensitive::

    48 89 5C 24 ?? 57 48 83 EC 20

``??`` (or a single ``?``) is a wildcard byte: the position is not compared.
Two hex digits are a literal byte: the position must compare equal.

Nibble wildcards (``4?``, ``?8``) are **refused**, with the reason stated in the
error. They are a real notation in other tools, and they are refused here for a
specific reason rather than out of minimalism: this repository has no
disassembler in Phase 1, so it has no way to justify *which* nibble of a byte is
the unstable one. A nibble mask that nobody can derive is a mask that gets
guessed, and a guessed mask is the failure this pair of tools exists to prevent.
If a later milestone brings instruction decoding, the notation can be added with
a derivation behind it.

The searched surface is part of the verdict
-------------------------------------------
"Unique" is meaningless without "unique in what". Three surfaces are offered and
the chosen one is recorded on the document:

``exec``     (default) every section whose characteristics carry
             ``IMAGE_SCN_MEM_EXECUTE`` or ``IMAGE_SCN_CNT_CODE``. Functions live
             here, and searching only here is what makes a code signature's
             uniqueness a statement about code rather than about the image.
``initialized``
             every section with raw data on disk. Catches the case where the
             same byte sequence also sits in ``.rdata`` as data -- which matters,
             because a future tool that searches the whole file would then find
             two hits where this tool found one.
``all``      the whole file as a flat byte range, headers and overlay included.
             Also the only surface available for a non-PE target.

A section restriction (``--sections``) narrows any of them, and the resulting
byte ranges are published in ``surface.ranges`` so a null result is a statement
about a named extent instead of about the file as a whole.

**Uniqueness is a property of a pattern AND a surface, never of a pattern.**
That is easy to nod at and easy to forget, so it is worth one measured example.
Of the 1 530 signatures that ``sigmake`` accepted as unique in
``MISERY-Win64-Shipping.exe``, scanning the same 1 530 against the larger
``MISERY.exe`` of the same installation returned 655 unique, 113 **ambiguous**
and 762 absent. 113 patterns that identify exactly one location in the image
they were cut from identify two or more in another image -- one of them 81
places. A caller that treated ``unique`` as an attribute of the signature,
cached once and reused, would be wrong 113 times.

Two output layers, never merged (plan.md 10.3)
----------------------------------------------
As in ``tools/fingerprint/container_info.py`` and ``tools/static/rtti_scan.py``:

``literal_reads``
    Class **P**. For each recorded hit, the bytes at that file offset read back
    through a second, independently opened handle, with a claim that states the
    offset and the length and names nothing about what the bytes are. The word
    "signature" cannot appear in such a claim -- plan.md 10.3 v2.4 lists a
    signature among the things a class-P claim must not name -- so the claim is
    the bare reading and the join key lives outside the graded object.

``signatures`` / ``summary`` / ``cross_image``
    Class **I**. These say that a hit *is* the function the signature was made
    for, which leans on the signature's provenance and on the assumption that
    the code has not been duplicated; and they say what a hit or a miss in a
    foreign image means, which is an inference about two different builds.

One consequence of the class-P rule is worth stating so it is not rediscovered
as a bug. A class-P claim has to name its target, because this installation
holds two files called ``MISERY.exe`` and a bare basename would locate nothing
-- so the install-relative path goes into the claim text. But
``tools/kb/validate.py`` derives class I for any claim containing a CamelCase
identifier, on the ground that such a token names a layout, and it cannot tell
a struct name from a directory name. A target under
``Engine/Binaries/ThirdParty/...`` therefore trips the rule on the word
``ThirdParty`` alone, and its ``literal_reads`` are refused as class P.

That is the validator being conservative in the direction it is supposed to be
conservative in: the cost is one artifact's primitive layer, and the alternative
would be admitting an interpretation as a measurement. The remedy is
``--literal-samples 0`` for such a target, which drops the class-P layer and
keeps the class-I verdicts -- and the reason belongs in the evidence README, not
in a silenced rule.

Safety properties (plan.md 1.5, decisions D-01 and D-04)
--------------------------------------------------------
* Targets are opened ``"rb"`` and only ever read; nothing inside a game
  installation is created, modified, moved or deleted.
* ``--out`` goes through ``tools/inventory/pathguard.check_output_path`` before
  any file is opened. The guard is imported, never reimplemented.
* D-04: scanning ``MISERY\\Binaries\\Win64\\MISERY.exe`` stamps
  ``d04_oracle_only`` on the document. A cross-build conclusion reached there is
  HYPOTHESIS-grade, because the build relationship between that image and the
  Shipping image is itself unproven (decision D-04).

Memory (plan.md F-04)
---------------------
Nothing is read whole. Every surface range is streamed through one reused buffer
with an overlap of ``max pattern length - 1`` bytes, which is what makes a match
straddling a buffer boundary findable; the de-duplication rule that goes with
that overlap is stated at :func:`scan_surface` and pinned by a test.

Determinism
-----------
Sorted keys, indent 2, LF, UTF-8 without BOM, trailing newline. Hits are
emitted in ascending file-offset order. Two runs over unchanged inputs differ
only in ``generated_at`` and in ``timings_seconds``.

Standard library only.

CLI
---
    python tools/static/sigscan.py <image> --library signatures.json
    python tools/static/sigscan.py <image> --pattern "48 89 5C 24 ?? 57" --json
    python tools/static/sigscan.py <image> --library sig.json --out out.json

Exit codes: 0 the scan completed (whatever the verdicts), 1 only with
``--require-unique`` when some signature did not come out unique, 2 usage /
I/O error / unparseable input / unparseable pattern.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
for _extra in (os.path.join(_TOOLS, "inventory"), os.path.join(_TOOLS, "fingerprint")):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never
# reimplemented: pathguard is the single place where "is this path inside the
# game installation" is decided.
import pathguard  # noqa: E402  (sys.path is prepared just above)

# The PE layer is F-01's. Re-deriving section tables and RVA translation here
# would give this tool a second, differently-buggy opinion about where .text is.
import pe_info  # noqa: E402

GENERATOR_NAME = "tools/static/sigscan.py"
GENERATOR_VERSION = "1.0.0"

PEFormatError = pe_info.PEFormatError


# --------------------------------------------------------------------------- #
# hard limits. Every one of these bounds a number that comes from a file or
# from a caller and must therefore never be believed.
# --------------------------------------------------------------------------- #

SCAN_CHUNK = 8 << 20             # streaming window for every surface range
MAX_PATTERN_BYTES = 4096         # longest pattern this tool will accept
MAX_PATTERNS = 4096              # most patterns in one invocation
DEFAULT_HIT_LIMIT = 64           # hits RECORDED per pattern
DEFAULT_COUNT_CAP = 4096         # hits COUNTED per pattern before truncation
DEFAULT_LITERAL_SAMPLES = 6      # class-P literal reads kept
MAX_SURFACE_RANGES = 4096

# Confidence ceiling is 0.99 (plan.md 10.2); 1.00 is forbidden anywhere.
CONFIDENCE_LITERAL = 0.99
CONFIDENCE_INTERPRETED_CORROBORATED = 0.85
CONFIDENCE_INTERPRETED_SINGLE_METHOD = 0.79

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_CNT_CODE = 0x00000020

VERDICT_UNIQUE = "unique"
VERDICT_AMBIGUOUS = "ambiguous"
VERDICT_ABSENT = "absent"
VERDICTS = (VERDICT_UNIQUE, VERDICT_AMBIGUOUS, VERDICT_ABSENT)

SURFACE_EXEC = "exec"
SURFACE_INITIALIZED = "initialized"
SURFACE_ALL = "all"
SURFACE_KINDS = (SURFACE_EXEC, SURFACE_INITIALIZED, SURFACE_ALL)

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

_TOKEN_RE = re.compile(r"^(?:[0-9a-fA-F]{2}|\?\?|\?)$")


# --------------------------------------------------------------------------- #
# the pattern grammar
# --------------------------------------------------------------------------- #

class PatternError(ValueError):
    """A pattern that cannot be parsed, with the reason stated."""


class Pattern:
    """One parsed byte pattern: the values, the mask, and the facts about it.

    ``mask[i]`` is 1 when position *i* must compare equal and 0 when it is a
    wildcard. ``values[i]`` at a wildcard position is normalised to 0 so that
    two patterns that differ only in the byte hidden under a wildcard have
    identical ``values`` -- otherwise "the same signature" would hash two ways.

    The derived numbers are computed once, here, because every one of them is a
    number some caller will want to justify a decision with:

    ``masked_bytes`` / ``masked_fraction``
        the size of the hole. ``sigmake`` refuses a signature whose fraction is
        too high, and this is where that number comes from.
    ``literal_bytes``
        how much of the pattern is actually being compared. A 64-byte pattern
        with 60 wildcards is a 4-byte pattern wearing a costume.
    ``anchor_offset`` / ``anchor_length``
        the longest run of consecutive literal bytes. It is what the matcher
        searches for with ``bytes.find`` (the only fast primitive available in
        pure Python), and it is also a quality measure in its own right: a
        pattern whose literal bytes are scattered as singletons has no run long
        enough to discriminate anything.
    ``distinct_literal_values``
        how many different byte values the literal positions take. A run of 32
        ``CC`` bytes is 32 literal bytes and still not a fingerprint of
        anything, and this is the number that catches it.
    """

    __slots__ = ("values", "mask", "text", "length", "masked_bytes",
                 "literal_bytes", "masked_fraction", "anchor_offset",
                 "anchor_length", "distinct_literal_values", "label")

    def __init__(self, values: bytes, mask: bytes, label: str | None = None) -> None:
        if len(values) != len(mask):
            raise PatternError("values and mask differ in length (%d vs %d)"
                               % (len(values), len(mask)))
        if not values:
            raise PatternError("an empty pattern matches nothing and everything; "
                               "refused")
        if len(values) > MAX_PATTERN_BYTES:
            raise PatternError("pattern is %d bytes, over the %d-byte limit"
                               % (len(values), MAX_PATTERN_BYTES))
        # Normalise the bytes under wildcards away (see the class docstring).
        self.values = bytes(v if m else 0 for v, m in zip(values, mask))
        self.mask = bytes(1 if m else 0 for m in mask)
        self.label = label
        self.length = len(self.values)
        self.literal_bytes = sum(self.mask)
        self.masked_bytes = self.length - self.literal_bytes
        self.masked_fraction = round(self.masked_bytes / self.length, 6)
        self.text = format_pattern(self.values, self.mask)
        offset, run = _longest_literal_run(self.mask)
        self.anchor_offset = offset
        self.anchor_length = run
        self.distinct_literal_values = len({
            self.values[i] for i in range(self.length) if self.mask[i]})

    @property
    def anchor(self) -> bytes:
        return self.values[self.anchor_offset:self.anchor_offset + self.anchor_length]

    def matches(self, buf, position: int) -> bool:
        """True when *buf* at *position* satisfies every literal position.

        Kept explicit rather than clever: this is the predicate the whole tool's
        correctness rests on, and a reader has to be able to see that a
        wildcard position is skipped and nothing else is.
        """
        values = self.values
        mask = self.mask
        for index in range(self.length):
            if mask[index] and buf[position + index] != values[index]:
                return False
        return True

    def facts(self) -> dict:
        """The pattern's own numbers, for the artifact."""
        return {
            "pattern": self.text,
            "length": self.length,
            "literal_bytes": self.literal_bytes,
            "masked_bytes": self.masked_bytes,
            "masked_fraction": self.masked_fraction,
            "anchor_offset": self.anchor_offset,
            "anchor_length": self.anchor_length,
            "anchor_hex": self.anchor.hex(),
            "distinct_literal_values": self.distinct_literal_values,
            "sha256_of_pattern_text": hashlib.sha256(
                self.text.encode("ascii")).hexdigest(),
        }


def _longest_literal_run(mask: bytes) -> tuple[int, int]:
    """(offset, length) of the longest run of 1s in *mask*; ties go to the left.

    Ties go left deliberately: it makes the anchor a deterministic function of
    the pattern, which is what lets two runs of either tool produce byte
    identical output.
    """
    best_offset = 0
    best_length = 0
    run_start = None
    for index, bit in enumerate(mask):
        if bit:
            if run_start is None:
                run_start = index
            length = index - run_start + 1
            if length > best_length:
                best_length = length
                best_offset = run_start
        else:
            run_start = None
    return best_offset, best_length


def parse_pattern(text: str, label: str | None = None) -> Pattern:
    """Parse the IDA-style textual form into a :class:`Pattern`.

    Every refusal names what was wrong and why, because this function is the
    only place a human-authored pattern enters the system and a silent
    misparse here is a wrong answer everywhere downstream.
    """
    if not isinstance(text, str):
        raise PatternError("pattern must be a string, got %s" % type(text).__name__)
        # (a bytes object would parse as its repr and match nothing)
    tokens = text.replace(",", " ").split()
    if not tokens:
        raise PatternError("pattern is empty")
    values = bytearray()
    mask = bytearray()
    for position, token in enumerate(tokens):
        if not _TOKEN_RE.match(token):
            if len(token) == 2 and "?" in token:
                raise PatternError(
                    "token %d is %r: a NIBBLE wildcard. This tool masks whole "
                    "bytes only. A nibble mask has to say which half of the byte "
                    "is unstable, and in Phase 1 there is no instruction decoder "
                    "to derive that from, so the notation is refused rather than "
                    "guessed at (see the module docstring)" % (position, token))
            raise PatternError(
                "token %d is %r: expected two hex digits, '??' or '?'"
                % (position, token))
        if token.startswith("?"):
            values.append(0)
            mask.append(0)
        else:
            values.append(int(token, 16))
            mask.append(1)
        if len(values) > MAX_PATTERN_BYTES:
            raise PatternError("pattern is longer than the %d-byte limit"
                               % MAX_PATTERN_BYTES)
    return Pattern(bytes(values), bytes(mask), label=label)


def format_pattern(values: bytes, mask: bytes) -> str:
    """The canonical textual form: space separated, upper case, ``??`` for holes."""
    parts = []
    for value, bit in zip(values, mask):
        parts.append("%02X" % value if bit else "??")
    return " ".join(parts)


# --------------------------------------------------------------------------- #
# the searched surface
# --------------------------------------------------------------------------- #

def _section_is_executable(section: dict) -> bool:
    return bool(section["characteristics"] & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))


def build_surface(headers, kind: str, only_sections: tuple[str, ...] | None,
                  file_size: int, warnings: list[str]) -> dict:
    """The byte ranges that will be searched, named and published.

    A range is ``{name, file_offset, length, rva}``. ``rva`` is the RVA of the
    range's first byte where one exists, so a hit can be reported in both
    address spaces; it is None for the flat surface, where a file offset is the
    only address there is.

    The ranges are clamped to what is really on disk. A section header claiming
    more raw bytes than the file holds is a thing that happens, and a surface
    that trusted it would report "absent" for a region it never read.
    """
    ranges: list[dict] = []
    if headers is None or kind == SURFACE_ALL:
        ranges.append({"name": "<whole file>", "file_offset": 0,
                       "length": file_size, "rva": None})
        chosen = SURFACE_ALL
    else:
        chosen = kind
        for section in headers.sections:
            if section["rsize"] <= 0:
                continue
            if kind == SURFACE_EXEC and not _section_is_executable(section):
                continue
            if only_sections is not None and section["name"] not in only_sections:
                continue
            start = section["raw_pointer"]
            if start >= file_size:
                warnings.append(
                    "section %s starts at file offset %d but the file is %d bytes; "
                    "it is not part of the searched surface"
                    % (section["name"] or "<unnamed>", start, file_size))
                continue
            length = min(section["rsize"], file_size - start)
            if length <= 0:
                continue
            if length < section["rsize"]:
                warnings.append(
                    "section %s declares %d raw bytes but only %d are on disk; the "
                    "searched surface is the readable part"
                    % (section["name"] or "<unnamed>", section["rsize"], length))
            ranges.append({"name": section["name"] or "<unnamed>",
                           "file_offset": start, "length": length,
                           "rva": section["rva"]})
        if only_sections is not None:
            missing = sorted(set(only_sections)
                             - {r["name"] for r in ranges})
            for name in missing:
                warnings.append(
                    "--sections named %r but no section with raw data and the "
                    "requested characteristics carries that name" % name)
    ranges.sort(key=lambda item: (item["file_offset"], item["name"]))
    if len(ranges) > MAX_SURFACE_RANGES:
        warnings.append("surface has %d ranges, truncated to %d"
                        % (len(ranges), MAX_SURFACE_RANGES))
        ranges = ranges[:MAX_SURFACE_RANGES]
    return {
        "kind": chosen,
        "kind_requested": kind,
        "sections_restricted_to": (sorted(only_sections)
                                   if only_sections is not None else None),
        "ranges": ranges,
        "range_count": len(ranges),
        "bytes_searched": sum(r["length"] for r in ranges),
        "definition": {
            SURFACE_EXEC: ("every section with raw data whose characteristics carry "
                           "IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_CNT_CODE"),
            SURFACE_INITIALIZED: "every section with raw data on disk",
            SURFACE_ALL: "the whole file as one flat byte range",
        }[chosen],
        "not_searched": {
            SURFACE_EXEC: ("read-only and writable data, resources, the headers and "
                           "any overlay -- a byte sequence present there is NOT "
                           "counted by this run"),
            SURFACE_INITIALIZED: ("the PE headers, the gaps between sections and any "
                                  "overlay past the last section"),
            SURFACE_ALL: "nothing in the file; nothing outside it",
        }[chosen],
    }


# --------------------------------------------------------------------------- #
# the matcher
# --------------------------------------------------------------------------- #

class HitCollector:
    """Per-pattern occurrence bookkeeping, with both caps made visible.

    Two different caps, on purpose, because they answer different questions:

    ``hit_limit``  bounds how many occurrences are RECORDED with their
                   addresses. Six thousand addresses in a JSON document is a
                   log, not evidence.
    ``count_cap``  bounds how many are COUNTED at all. Past it the pattern stops
                   being matched and ``truncated`` is set, so the printed count
                   can never be mistaken for the real one.
    """

    __slots__ = ("pattern", "count", "offsets", "hit_limit", "count_cap", "truncated")

    def __init__(self, pattern: Pattern, hit_limit: int, count_cap: int) -> None:
        self.pattern = pattern
        self.count = 0
        self.offsets: list[int] = []
        self.hit_limit = hit_limit
        self.count_cap = count_cap
        self.truncated = False

    @property
    def exhausted(self) -> bool:
        return self.truncated

    def add(self, offset: int) -> None:
        self.count += 1
        if len(self.offsets) < self.hit_limit:
            self.offsets.append(offset)
        if self.count >= self.count_cap:
            self.truncated = True


def scan_surface(path: str, surface: dict, patterns: list[Pattern], *,
                 hit_limit: int = DEFAULT_HIT_LIMIT,
                 count_cap: int = DEFAULT_COUNT_CAP,
                 chunk_size: int = SCAN_CHUNK) -> list[HitCollector]:
    """Count occurrences of every pattern on *surface*, streaming.

    The de-duplication rule, stated because it is the part that a careless
    rewrite breaks silently. Buffer *i* covers absolute file offsets
    ``[A_i, A_i + L_i)`` and buffer *i+1* starts at ``A_i + L_i - overlap``
    where ``overlap = max pattern length - 1``. A match beginning at ``s`` is
    accepted from buffer *i* only when ``s < A_i + L_i - overlap``, except in the
    final buffer of a range where every match is accepted. Any match rejected
    by that rule begins inside the overlap and is therefore wholly contained in
    buffer *i+1*, where it is found exactly once. Without the rule every match
    that starts in the overlap is reported twice, which turns a unique signature
    into an ambiguous one -- a false alarm rather than a missed one, but a wrong
    verdict either way.

    The anchor (the longest run of literal bytes) is searched with
    ``bytes.find``, which is the only string-search primitive in the standard
    library that runs at C speed. Everything else about a candidate is verified
    byte by byte by :meth:`Pattern.matches`. Overlapping occurrences are found:
    the search resumes at ``found + 1``, not at ``found + len(anchor)``.
    """
    collectors = [HitCollector(pattern, hit_limit, count_cap) for pattern in patterns]
    if not patterns:
        return collectors
    max_length = max(pattern.length for pattern in patterns)
    overlap = max_length - 1
    step = max(chunk_size, max_length)

    with open(path, "rb", buffering=0) as handle:
        for entry in surface["ranges"]:
            range_start = entry["file_offset"]
            range_end = range_start + entry["length"]
            position = range_start
            while position < range_end:
                want = min(step, range_end - position)
                handle.seek(position)
                buf = handle.read(want)
                if not buf:
                    break
                buffer_end = position + len(buf)
                final = buffer_end >= range_end
                # Matches at or past this absolute offset belong to the next
                # buffer (see the docstring). In the final buffer nothing is
                # deferred, because there is no next buffer to defer to.
                accept_below = buffer_end if final else buffer_end - overlap
                for collector in collectors:
                    if collector.exhausted:
                        continue
                    pattern = collector.pattern
                    if pattern.length > len(buf):
                        continue
                    anchor = pattern.anchor
                    limit = len(buf) - pattern.length
                    if anchor:
                        cursor = 0
                        while True:
                            found = buf.find(anchor, cursor)
                            if found < 0:
                                break
                            cursor = found + 1
                            start = found - pattern.anchor_offset
                            if start < 0 or start > limit:
                                continue
                            absolute = position + start
                            if absolute >= accept_below:
                                continue
                            if pattern.matches(buf, start):
                                collector.add(absolute)
                                if collector.exhausted:
                                    break
                    else:
                        # An all-wildcard pattern has no anchor and matches at
                        # every position. It is not a signature and sigmake
                        # refuses to emit one, but the refutation probes need it
                        # to prove the matcher is not silently selective, so the
                        # case is handled rather than excluded.
                        for start in range(0, limit + 1):
                            absolute = position + start
                            if absolute >= accept_below:
                                break
                            collector.add(absolute)
                            if collector.exhausted:
                                break
                if buffer_end >= range_end:
                    break
                position = buffer_end - overlap
    return collectors


def verdict_of(collector: HitCollector) -> str:
    """``unique`` / ``ambiguous`` / ``absent`` from an occurrence count.

    A truncated count is ``ambiguous``: whatever the true number is, it is at
    least the cap, and "at least 4096" is emphatically not one.
    """
    if collector.truncated:
        return VERDICT_AMBIGUOUS
    if collector.count == 0:
        return VERDICT_ABSENT
    if collector.count == 1:
        return VERDICT_UNIQUE
    return VERDICT_AMBIGUOUS


# --------------------------------------------------------------------------- #
# signature library input
# --------------------------------------------------------------------------- #

def load_library(path: str, include_rejected: bool) -> tuple[list[dict], dict, list[str]]:
    """Read a ``sigmake`` document (or a bare list) and return its signatures.

    Accepts both the full ``sigmake`` document and a bare JSON list of
    ``{"label": ..., "pattern": ...}`` objects, because the second is what a
    human writes by hand and refusing it would push people towards editing the
    generated document instead.

    By default only ``accepted`` signatures are returned. ``sigmake`` records
    the ones it refused *together with the reasons*, and scanning them is
    occasionally exactly what a reviewer wants -- to check that a signature
    marked ``not_unique`` really does match more than once -- so the filter is a
    flag rather than a deletion.
    """
    notes: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    if isinstance(document, list):
        rows = document
        provenance = {"format": "bare list", "source_image": None,
                      "generator": None, "generator_version": None,
                      "mask_policy": None}
    elif isinstance(document, dict) and isinstance(document.get("signatures"), list):
        rows = document["signatures"]
        provenance = {
            "format": "sigmake document",
            "source_image": document.get("source_image"),
            "generator": document.get("generator"),
            "generator_version": document.get("generator_version"),
            "mask_policy": document.get("mask_policy"),
        }
    else:
        raise ValueError("%s is neither a sigmake document (an object with a "
                         "'signatures' list) nor a bare list of signatures" % path)

    signatures: list[dict] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            notes.append("signatures[%d] is not an object; skipped" % index)
            continue
        text = row.get("pattern")
        if not isinstance(text, str):
            notes.append("signatures[%d] has no 'pattern' string; skipped" % index)
            continue
        accepted = row.get("accepted")
        if accepted is False and not include_rejected:
            continue
        label = row.get("label") or "signature[%d]" % index
        signatures.append({
            "label": str(label),
            "pattern": text,
            "accepted_in_library": accepted,
            "source_rva": row.get("source_rva"),
            "source_file_offset": row.get("source_file_offset"),
            "rejections": row.get("rejections") or [],
        })
        if len(signatures) >= MAX_PATTERNS:
            notes.append("library holds more than %d signatures; the rest were "
                         "not read" % MAX_PATTERNS)
            break
    return signatures, provenance, notes


# --------------------------------------------------------------------------- #
# evidence layer 1 (class P): literal reads
# --------------------------------------------------------------------------- #

def hex_bytes(raw: bytes) -> str:
    return raw.hex()


def dump_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def locus_target(path: str, install_root: str | None = None) -> str:
    """The spelling a class-P read locus uses for *path*: install-relative, '/'.

    Same rule and same reason as ``rtti_scan.locus_target``: this installation
    holds two different files called ``MISERY.exe``, so a bare basename names an
    ambiguity class rather than a range of bytes, and plan.md 10.3 v2.4 admits
    binary-analysis into class P only for a claim at a determinate address.
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
    """One class-P record: a literal read at a determinate place, and nothing more.

    ``claim`` states the offset AND the length -- mandatory for the
    ``binary-analysis`` oracle to be class P at all (plan.md 10.3 v2.4) -- and
    stops there. It must NOT say "signature", "pattern", "function" or "match":
    10.3 v2.4 lists a signature among the things naming which pushes a claim
    into class I, and this claim's whole value is that it is the un-interpreted
    half. The join key into the interpretive layer lives outside ``evidence``.
    """
    length = len(raw)
    plural = "byte" if length == 1 else "bytes"
    claim = "%d %s at offset %d of %s are %s" % (
        length, plural, offset, target, hex_bytes(raw))
    return {
        "join_key": join_key,
        "interpretation_lives_in": (
            "the matching entry of signatures[] in the same document -- plan.md "
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
            "oracle": ["binary-analysis"],
            "sources": [{
                "method": "S-07",
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
            # claim class of a reduced annotation from this string alone. See the
            # long comment on the same field in tools/static/rtti_scan.py.
            "note": ("%s. This record gives the position and the extent, and "
                     "nothing else." % claim),
        },
    }


def confirm_literal_reads(path: str, literals: list[dict], target: str,
                          warnings: list[str]) -> bool:
    """Perform every literal read a SECOND time and stamp the result on each record.

    plan.md 10.3 class-P criterion 2 executed rather than asserted. On any
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


def scan_annotation(target: str, same_image: bool) -> dict:
    """The class-I annotation for the interpretive layer.

    Two independent methods are available for "this hit is that function" only
    when the scanned image is the image the signature was cut from, where the
    signature's own source address is an independent statement about where the
    match should be and the scan either confirms it or does not. On a foreign
    image there is no second method -- the identity of a hit rests on the
    signature alone -- so the confidence is capped lower. plan.md 10.3 wants two
    independent methods from 0.80 up, and a second scan of the same bytes is not
    a second method.
    """
    sources = [{
        "method": "S-07",
        "artifact": None,
        "locator": target,
        "note": ("oracle binary-analysis. Exhaustive byte-pattern count over the "
                 "published surface ranges, wildcard positions excluded from the "
                 "comparison."),
    }]
    oracles = ["binary-analysis"]
    if same_image:
        sources.append({
            "method": "S-06",
            "artifact": None,
            "locator": target,
            "independent_of": ["S-07/pattern-count"],
            "note": ("oracle binary-analysis. Second, independent method: the "
                     "boundary oracle of the source image (the PE exception "
                     "directory) states independently where the covered range "
                     "begins, and the single occurrence found by the count either "
                     "coincides with that address or refutes the reading."),
        })
    return {
        "evidence_level": "INFERRED",
        "claim_class": "I",
        "confidence": (CONFIDENCE_INTERPRETED_CORROBORATED if same_image
                       else CONFIDENCE_INTERPRETED_SINGLE_METHOD),
        "oracle": sorted(oracles),
        "sources": sources,
        "read_locus": None,
        "note": (
            "Interpretive: this layer says that an occurrence IS the function the "
            "pattern was cut from, and that a miss means the function moved rather "
            "than that it is gone. Both lean on the pattern's provenance and on the "
            "assumption that the compiler did not emit the same bytes elsewhere. "
            "The primitive half -- the bytes found at the offsets -- is in "
            "literal_reads[]."
        ),
    }


# --------------------------------------------------------------------------- #
# refutation probes
# --------------------------------------------------------------------------- #

def build_refutation_probes(path: str, surface: dict, patterns: list[Pattern],
                            results: list[dict], *, chunk_size: int,
                            probe_window: int) -> list[dict]:
    """Checks whose PURPOSE is to break the headline verdicts.

    A scanner that only ever produces supporting numbers cannot tell a real
    ``unique`` from a matcher that returns 1 for everything, so each probe below
    states what result would refute the verdicts and reports whether that
    happened.
    """
    probes: list[dict] = []
    unique_labels = [r["label"] for r in results
                     if r["verdict"] == VERDICT_UNIQUE]

    # Probe 1: the matcher must not be selective. An all-wildcard pattern of the
    # same length has to match at essentially every position of a bounded
    # window. If it comes back with one hit, or none, the matcher is broken and
    # every "unique" in this document is worthless.
    window = _bounded_window(surface, probe_window)
    probe = {
        "id": "all-wildcard-control",
        "question": ("does the matcher find a pattern that constrains nothing, at "
                     "every position of a bounded window?"),
        "would_refute": ("an all-wildcard pattern matching once, or not at all, "
                         "would mean the matcher is selective for reasons other "
                         "than the pattern, and every verdict in this document "
                         "would be void"),
        "window": window,
        "refuted": None,
    }
    if window["ranges"] and patterns:
        length = min(16, max(1, min(p.length for p in patterns)))
        blank = Pattern(bytes(length), bytes(length), label="all-wildcard-control")
        got = scan_surface(path, window, [blank], hit_limit=1,
                           count_cap=window["bytes_searched"] + 1,
                           chunk_size=chunk_size)[0]
        expected = max(0, window["bytes_searched"] - (length - 1))
        probe["pattern_length"] = length
        probe["occurrences"] = got.count
        probe["occurrences_expected"] = expected
        probe["refuted"] = got.count < 2
        probe["note"] = (
            "%d occurrences of a %d-byte all-wildcard pattern in a %d-byte window; "
            "%d expected (one per position that can hold the pattern)"
            % (got.count, length, window["bytes_searched"], expected))
    else:
        probe["note"] = "no window or no patterns to size the control against"
    probes.append(probe)

    # Probe 2: the strongest available check that a signature discriminates.
    # Flip one literal byte and the pattern must become absent. If a
    # one-byte-different pattern still matches, the pattern is not identifying
    # the bytes it claims to identify.
    flipped: list[Pattern] = []
    flipped_labels: list[str] = []
    for pattern in patterns:
        index = next((i for i in range(pattern.length) if pattern.mask[i]), None)
        if index is None:
            continue
        values = bytearray(pattern.values)
        values[index] ^= 0xFF
        flipped.append(Pattern(bytes(values), pattern.mask,
                               label="flip:%s" % (pattern.label or "?")))
        flipped_labels.append(pattern.label or "?")
    probe = {
        "id": "one-byte-flip-control",
        "question": ("with a single literal byte inverted, does each pattern become "
                     "absent?"),
        "would_refute": ("a flipped pattern that still matches somewhere would mean "
                         "the surviving literal bytes, not the pattern as written, "
                         "are doing the work"),
        "patterns_flipped": len(flipped),
        "refuted": None,
    }
    if flipped:
        got = scan_surface(path, surface, flipped, hit_limit=4,
                           count_cap=16, chunk_size=chunk_size)
        survivors = [{"label": flipped_labels[i], "occurrences": c.count}
                     for i, c in enumerate(got) if c.count]
        probe["survivors"] = survivors
        probe["refuted"] = bool(survivors)
        probe["note"] = (
            "%d of %d flipped patterns still matched somewhere on the surface"
            % (len(survivors), len(flipped)))
    else:
        probe["note"] = "no pattern had a literal byte to flip"
    probes.append(probe)

    # Probe 3: a four-byte prefix must be ambiguous on a real code surface. If a
    # 4-byte pattern comes out unique in tens of megabytes of x86-64, the
    # scanner is not scanning what it says it is.
    prefixes: list[Pattern] = []
    prefix_labels: list[str] = []
    for pattern in patterns:
        if pattern.length < 4 or not all(pattern.mask[:4]):
            continue
        prefixes.append(Pattern(pattern.values[:4], pattern.mask[:4],
                                label="prefix4:%s" % (pattern.label or "?")))
        prefix_labels.append(pattern.label or "?")
    probe = {
        "id": "short-prefix-control",
        "question": ("is a four-byte prefix of each signature ambiguous, as a byte "
                     "sequence that short must be on a large code surface?"),
        "would_refute": ("a four-byte prefix coming out unique would mean the "
                         "surface being searched is far smaller than "
                         "surface.bytes_searched claims"),
        "patterns_tested": len(prefixes),
        "refuted": None,
    }
    if prefixes:
        got = scan_surface(path, surface, prefixes, hit_limit=1, count_cap=64,
                           chunk_size=chunk_size)
        singletons = [{"label": prefix_labels[i], "occurrences": c.count}
                      for i, c in enumerate(got) if c.count < 2]
        probe["not_ambiguous"] = singletons
        probe["refuted"] = bool(singletons)
        probe["note"] = ("%d of %d four-byte prefixes came out with fewer than two "
                         "occurrences" % (len(singletons), len(prefixes)))
    else:
        probe["note"] = "no signature had four leading literal bytes"
    probes.append(probe)

    # Probe 4: the de-duplication rule of scan_surface, exercised against the
    # smallest buffer the matcher is allowed to use. A verdict that changes when
    # the buffer size changes is a bookkeeping bug, and it is the one bug in this
    # tool that would silently turn unique into ambiguous.
    probe = {
        "id": "buffer-size-invariance",
        "question": ("does every verdict survive re-scanning with a buffer barely "
                     "larger than the longest pattern?"),
        "would_refute": ("any count that changes with the buffer size would mean the "
                         "overlap or the de-duplication rule is wrong, and no "
                         "verdict in this document could be trusted"),
        "refuted": None,
    }
    if patterns:
        small = max(p.length for p in patterns) + 1
        got = scan_surface(path, surface, patterns, hit_limit=1,
                           count_cap=DEFAULT_COUNT_CAP, chunk_size=small)
        # Joined on the LABEL, never on the list index: ``results`` is sorted by
        # label before it reaches this function while ``got`` is in pattern
        # order, so an index join compares one signature's count against
        # another's and manufactures disagreements that are an artefact of the
        # sort rather than of the buffer size.
        by_label: dict[str, dict] = {}
        for record in results:
            by_label.setdefault(record["label"], record)
        disagreements = []
        for collector in got:
            label = collector.pattern.label
            record = by_label.get(label)
            if record is None:
                disagreements.append({"label": label, "default_buffer": None,
                                      "small_buffer": collector.count,
                                      "note": ("no result carries this label, so "
                                               "the two passes cannot be joined")})
                continue
            if collector.count != record["occurrences"]:
                disagreements.append({"label": label,
                                      "default_buffer": record["occurrences"],
                                      "small_buffer": collector.count})
        probe["buffer_bytes"] = small
        probe["disagreements"] = disagreements
        probe["refuted"] = bool(disagreements)
        probe["note"] = ("%d of %d counts changed when the buffer was reduced to %d "
                         "bytes" % (len(disagreements), len(patterns), small))
    else:
        probe["note"] = "no patterns to re-scan"
    probes.append(probe)

    probe = {
        "id": "unique-verdict-population",
        "question": "how many signatures actually came out unique?",
        "would_refute": ("nothing on its own; this probe exists so the headline "
                         "count cannot be quoted without its denominator"),
        "unique": len(unique_labels),
        "total": len(results),
        "refuted": False,
        "note": "%d of %d signatures are unique on this surface"
                % (len(unique_labels), len(results)),
    }
    probes.append(probe)
    return probes


def _bounded_window(surface: dict, size: int) -> dict:
    """A small sub-surface, taken from the first range, for the control probes.

    Bounded because the all-wildcard control matches once per byte and running
    it over 98 MB would produce a hundred million counted hits for no extra
    information.
    """
    ranges = []
    if surface["ranges"]:
        first = surface["ranges"][0]
        length = min(size, first["length"])
        if length > 0:
            ranges.append({"name": first["name"], "file_offset": first["file_offset"],
                           "length": length, "rva": first["rva"]})
    return {"kind": "window", "ranges": ranges,
            "bytes_searched": sum(r["length"] for r in ranges),
            "note": "the first %d bytes of the first surface range" % size}


# --------------------------------------------------------------------------- #
# the scan
# --------------------------------------------------------------------------- #

def _is_d04_oracle(path: str) -> bool:
    """True for the second, 282 MB MISERY.exe -- decision D-04's read-only oracle."""
    normalised = os.path.abspath(path).replace("\\", "/").lower()
    return normalised.endswith("/binaries/win64/misery.exe")


def _file_digest(path: str, size: int) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(SCAN_CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _offset_to_rva(surface: dict, offset: int) -> int | None:
    for entry in surface["ranges"]:
        if entry["rva"] is None:
            continue
        if entry["file_offset"] <= offset < entry["file_offset"] + entry["length"]:
            return entry["rva"] + (offset - entry["file_offset"])
    return None


def _range_name(surface: dict, offset: int) -> str | None:
    for entry in surface["ranges"]:
        if entry["file_offset"] <= offset < entry["file_offset"] + entry["length"]:
            return entry["name"]
    return None


def analyze(path: str, signatures: list[dict], *,
            surface_kind: str = SURFACE_EXEC,
            only_sections: tuple[str, ...] | None = None,
            hit_limit: int = DEFAULT_HIT_LIMIT,
            count_cap: int = DEFAULT_COUNT_CAP,
            literal_samples: int = DEFAULT_LITERAL_SAMPLES,
            library_provenance: dict | None = None,
            library_notes: list[str] | None = None,
            want_file_digest: bool = True,
            want_probes: bool = True,
            probe_window: int = 1 << 20,
            chunk_size: int = SCAN_CHUNK,
            install_root: str | None = None) -> dict:
    """Scan *path* for every signature and assemble the document."""
    started = time.monotonic()
    warnings: list[str] = list(library_notes or [])
    timings: dict[str, float] = {}

    size = os.path.getsize(path)
    headers = None
    pe_note = None
    try:
        image = pe_info.Image.open(path)
    except OSError as error:
        raise
    try:
        try:
            headers = pe_info.PEHeaders(image)
        except PEFormatError as error:
            pe_note = ("not parseable as a PE image (%s); the flat 'all' surface is "
                       "the only one available" % error)
            warnings.append(pe_note)
        surface = build_surface(headers, surface_kind, only_sections, size, warnings)

        patterns: list[Pattern] = []
        parse_failures: list[dict] = []
        for row in signatures:
            try:
                patterns.append(parse_pattern(row["pattern"], label=row["label"]))
            except PatternError as error:
                parse_failures.append({"label": row["label"], "reason": str(error)})
        if parse_failures:
            warnings.append("%d signature(s) could not be parsed and were not "
                            "scanned" % len(parse_failures))

        mark = time.monotonic()
        collectors = scan_surface(path, surface, patterns, hit_limit=hit_limit,
                                  count_cap=count_cap, chunk_size=chunk_size)
        timings["scan"] = round(time.monotonic() - mark, 3)

        source_image = (library_provenance or {}).get("source_image") or {}
        source_sha = source_image.get("sha256")
        digest = _file_digest(path, size) if want_file_digest else None
        # "Same image" is decided on the content digest, not on the path: a copy
        # of the Shipping exe in a Ghidra workspace is the same image, and a
        # different build sitting at the same path is not.
        same_image = bool(digest and source_sha and digest == source_sha)
        if source_sha and digest and not same_image:
            warnings.append(
                "this target is NOT the image the signatures were cut from "
                "(sha256 %s vs %s); every 'absent' below is therefore consistent "
                "with the function existing at a different address"
                % (digest[:16], str(source_sha)[:16]))

        results: list[dict] = []
        for index, collector in enumerate(collectors):
            pattern = collector.pattern
            row = next((s for s in signatures if s["label"] == pattern.label), {})
            verdict = verdict_of(collector)
            hits = []
            for offset in collector.offsets:
                hits.append({
                    "file_offset": offset,
                    "rva": _offset_to_rva(surface, offset),
                    "range": _range_name(surface, offset),
                })
            expected_rva = row.get("source_rva") if same_image else None
            at_expected = None
            if expected_rva is not None:
                at_expected = any(h["rva"] == expected_rva for h in hits)
            record = {
                "label": pattern.label,
                "verdict": verdict,
                "occurrences": collector.count,
                "occurrences_truncated": collector.truncated,
                "hits": hits,
                "hits_recorded": len(hits),
                "hit_limit": hit_limit,
                "count_cap": count_cap,
                "accepted_in_library": row.get("accepted_in_library"),
                "library_rejections": row.get("rejections") or [],
                "source_rva": row.get("source_rva"),
                "source_file_offset": row.get("source_file_offset"),
                "found_at_source_rva": at_expected,
                "meaning": _meaning(verdict, same_image, at_expected,
                                    collector.truncated),
            }
            record.update(pattern.facts())
            results.append(record)
        results.sort(key=lambda item: item["label"])

        probes: list[dict] = []
        if want_probes:
            mark = time.monotonic()
            probes = build_refutation_probes(path, surface, patterns, results,
                                             chunk_size=chunk_size,
                                             probe_window=probe_window)
            timings["refutation_probes"] = round(time.monotonic() - mark, 3)

        target = locus_target(path, install_root)
        literals: list[dict] = []
        sampled = _spread([r for r in results if r["hits"]], literal_samples)
        for record in sampled:
            hit = record["hits"][0]
            raw = image.read_clamped(hit["file_offset"], record["length"])
            if len(raw) != record["length"]:
                warnings.append("the recorded hit for %s at offset %d could not be "
                                "read back in full" % (record["label"],
                                                       hit["file_offset"]))
                continue
            literals.append(literal_read(target, record["label"],
                                         hit["file_offset"], raw))
        literals.sort(key=lambda item: (item["offset"], item["length"]))
        if literals:
            confirm_literal_reads(path, literals, target, warnings)

        counts = {name: 0 for name in VERDICTS}
        for record in results:
            counts[record["verdict"]] += 1
        summary = {
            "signatures_scanned": len(results),
            "signatures_unparseable": len(parse_failures),
            "unique": counts[VERDICT_UNIQUE],
            "ambiguous": counts[VERDICT_AMBIGUOUS],
            "absent": counts[VERDICT_ABSENT],
            "truncated_counts": sum(1 for r in results
                                    if r["occurrences_truncated"]),
            "found_at_source_rva": sum(1 for r in results
                                       if r["found_at_source_rva"] is True),
            "not_found_at_source_rva": sum(1 for r in results
                                           if r["found_at_source_rva"] is False),
            "bytes_searched": surface["bytes_searched"],
            "same_image_as_signature_source": same_image,
            "masked_fraction_min": (min(r["masked_fraction"] for r in results)
                                    if results else None),
            "masked_fraction_max": (max(r["masked_fraction"] for r in results)
                                    if results else None),
            "masked_fraction_mean": (round(sum(r["masked_fraction"] for r in results)
                                           / len(results), 6) if results else None),
        }
        timings["total"] = round(time.monotonic() - started, 3)

        return {
            "task": "S-07",
            "generator": GENERATOR_NAME,
            "generator_version": GENERATOR_VERSION,
            "generated_at": pe_info.now_iso_utc(),
            "d04_oracle_only": _is_d04_oracle(path),
            "target": {
                "name": os.path.basename(os.path.abspath(path)),
                "path": os.path.abspath(path),
                "install_relative": target,
                "size": size,
                "sha256": digest,
                "pe_format": None if headers is None else headers.pe_format,
                "machine": None if headers is None else headers.machine,
                "image_base": None if headers is None else headers.image_base,
                "size_of_image": None if headers is None else headers.size_of_image,
                "timestamp": None if headers is None else headers.timestamp,
                "pe_note": pe_note,
            },
            "library": library_provenance or {"format": "inline --pattern"},
            "surface": surface,
            "verdict_definitions": {
                VERDICT_UNIQUE: "exactly one occurrence on the searched surface",
                VERDICT_AMBIGUOUS: ("two or more occurrences, or the occurrence "
                                    "counter reached its cap"),
                VERDICT_ABSENT: "zero occurrences on the searched surface",
            },
            "signatures": results,
            "unparseable": sorted(parse_failures, key=lambda item: item["label"]),
            "summary": summary,
            "refutation_probes": probes,
            "literal_reads": literals,
            "interpreted_annotation": scan_annotation(target, same_image),
            "timings_seconds": timings,
            "warnings": sorted(set(warnings)),
        }
    finally:
        image.close()


def _meaning(verdict: str, same_image: bool, at_expected, truncated: bool) -> str:
    """What this verdict licenses, spelled out on every record.

    On the record rather than in the documentation because the M1 review found
    four defects that were all "a document asserting something its own artifact
    refutes". A reader who quotes ``verdict: absent`` out of a foreign image
    should be quoting the sentence that says what that does not mean.
    """
    if truncated:
        return ("the occurrence counter reached its cap, so the count below is a "
                "lower bound and this pattern is not a signature of anything")
    if verdict == VERDICT_UNIQUE:
        if same_image and at_expected is True:
            return ("one occurrence, at the address the signature was cut from: the "
                    "pattern identifies that location in this image")
        if same_image and at_expected is False:
            return ("one occurrence, but NOT at the address the signature records as "
                    "its source. Either the signature or the source address is "
                    "wrong; do not use this signature until that is explained")
        return ("one occurrence in an image other than the one the signature was cut "
                "from. That the occurrence is the same function is an inference from "
                "the pattern alone -- no second method corroborates it here")
    if verdict == VERDICT_AMBIGUOUS:
        return ("more than one occurrence: this pattern does not identify a location. "
                "An address taken from the first hit would be a coin toss")
    if same_image:
        return ("no occurrence in the image the signature was cut from. That is a "
                "defect in this tool pair or in the recorded pattern, not a fact "
                "about the image, and it must be explained before anything else here "
                "is used")
    return ("no occurrence. On a different build this is the DESIGNED failure "
            "direction: the pattern masks only what the base relocation table proves "
            "is relocated, so a rebuilt image moves the RIP-relative displacements "
            "and rel32 targets that Phase 1 cannot detect. It means 're-locate this "
            "function', not 'the function is gone'")


def _spread(items: list, count: int) -> list:
    """A deterministic, evenly spaced sample -- never just the first N."""
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
    """One flat JSON object per signature -- the joinable artifact of S-07."""
    lines = []
    for record in document["signatures"]:
        lines.append(json.dumps({
            "target": document["target"]["install_relative"],
            "target_sha256": document["target"]["sha256"],
            "label": record["label"],
            "verdict": record["verdict"],
            "occurrences": record["occurrences"],
            "occurrences_truncated": record["occurrences_truncated"],
            "first_hit_rva": record["hits"][0]["rva"] if record["hits"] else None,
            "first_hit_file_offset": (record["hits"][0]["file_offset"]
                                      if record["hits"] else None),
            "source_rva": record["source_rva"],
            "found_at_source_rva": record["found_at_source_rva"],
            "length": record["length"],
            "masked_bytes": record["masked_bytes"],
            "masked_fraction": record["masked_fraction"],
            "surface_kind": document["surface"]["kind"],
            "surface_bytes": document["surface"]["bytes_searched"],
        }, sort_keys=True, ensure_ascii=False))
    return lines


def write_text(text: str, out_path: str, install_root: str, what: str) -> str:
    """Write *text* to *out_path*, refusing any path inside an installation."""
    target = pathguard.check_output_path(out_path, install_root, what=what)
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return target


def _fmt_int(value) -> str:
    if value is None:
        return "-"
    return "{:,}".format(value).replace(",", " ")


def format_summary(document: dict, limit: int = 40) -> str:
    """The human summary. Every number printed here is a field of the document."""
    lines: list[str] = []
    target = document["target"]
    surface = document["surface"]
    summary = document["summary"]
    lines.append("sigscan %s (%s)" % (GENERATOR_VERSION, document["task"]))
    lines.append("target:   %s" % target["install_relative"])
    lines.append("          %s bytes, sha256 %s"
                 % (_fmt_int(target["size"]),
                    (target["sha256"] or "not computed")[:32]))
    if document["d04_oracle_only"]:
        lines.append("          D-04 read-only oracle: a conclusion reached here "
                     "must be re-verified on the Shipping image")
    if target["pe_note"]:
        lines.append("          %s" % target["pe_note"])
    library = document["library"]
    lines.append("library:  %s" % (library.get("format") or "?"))
    source = library.get("source_image") or {}
    if source:
        lines.append("          cut from %s (sha256 %s)"
                     % (source.get("install_relative") or source.get("name"),
                        str(source.get("sha256"))[:32]))
    lines.append("          same image as the signature source: %s"
                 % ("yes" if summary["same_image_as_signature_source"] else "no"))
    lines.append("surface:  %s -- %s" % (surface["kind"], surface["definition"]))
    lines.append("          %s bytes over %d range(s): %s"
                 % (_fmt_int(surface["bytes_searched"]), surface["range_count"],
                    ", ".join("%s[%s+%s]" % (r["name"], r["file_offset"], r["length"])
                              for r in surface["ranges"][:6])
                    or "none"))
    lines.append("          NOT searched: %s" % surface["not_searched"])
    lines.append("")
    lines.append("verdicts: unique %d   ambiguous %d   absent %d   (of %d scanned)"
                 % (summary["unique"], summary["ambiguous"], summary["absent"],
                    summary["signatures_scanned"]))
    if summary["signatures_unparseable"]:
        lines.append("          %d signature(s) could not be parsed"
                     % summary["signatures_unparseable"])
    if summary["same_image_as_signature_source"]:
        lines.append("          at the recorded source address: %d   elsewhere: %d"
                     % (summary["found_at_source_rva"],
                        summary["not_found_at_source_rva"]))
    if summary["masked_fraction_mean"] is not None:
        lines.append("          masked-byte fraction: min %.3f  mean %.3f  max %.3f"
                     % (summary["masked_fraction_min"],
                        summary["masked_fraction_mean"],
                        summary["masked_fraction_max"]))
    lines.append("")
    lines.append("%-11s %-9s %6s %5s %5s %-11s %s"
                 % ("verdict", "occur.", "len", "mask", "anch", "first rva", "label"))
    for record in document["signatures"][:limit]:
        first = record["hits"][0]["rva"] if record["hits"] else None
        lines.append("%-11s %-9s %6d %5d %5d %-11s %s"
                     % (record["verdict"],
                        ("%d+" if record["occurrences_truncated"] else "%d")
                        % record["occurrences"],
                        record["length"], record["masked_bytes"],
                        record["anchor_length"],
                        ("0x%x" % first) if first is not None else "-",
                        _shorten(record["label"], 64)))
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
        prog="sigscan.py",
        description=(
            "Count occurrences of byte-pattern signatures in a binary and return "
            "unique / ambiguous / absent (plan.md task S-07). Read-only. Refuses "
            "any output path that resolves inside a game installation (D-01)."),
    )
    parser.add_argument("path", help="the file to search (opened read-only)")
    parser.add_argument("--library", default=None, metavar="JSON",
                        help=("a sigmake document, or a bare JSON list of "
                              "{label, pattern} objects"))
    parser.add_argument("--pattern", action="append", default=None, metavar="P",
                        help=("a pattern to search for, e.g. \"48 89 5C 24 ?? 57\"; "
                              "repeatable"))
    parser.add_argument("--label", action="append", default=None, metavar="NAME",
                        help="label for the matching --pattern, in the same order")
    parser.add_argument("--include-rejected", action="store_true",
                        help=("also scan signatures the library marked accepted:false "
                              "-- useful for checking that a rejection was right"))
    parser.add_argument("--surface", choices=SURFACE_KINDS, default=SURFACE_EXEC,
                        help="which byte ranges to search (default: exec)")
    parser.add_argument("--sections", default=None, metavar="A,B",
                        help="restrict the surface to these section names")
    parser.add_argument("--hit-limit", type=int, default=DEFAULT_HIT_LIMIT,
                        metavar="N", help="occurrences recorded per signature")
    parser.add_argument("--count-cap", type=int, default=DEFAULT_COUNT_CAP,
                        metavar="N", help="occurrences counted before truncating")
    parser.add_argument("--literal-samples", type=int,
                        default=DEFAULT_LITERAL_SAMPLES, metavar="N",
                        help="how many hits to record as class-P literal reads")
    parser.add_argument("--no-probes", action="store_true",
                        help="skip the refutation probes (they re-scan the surface)")
    parser.add_argument("--no-digest", action="store_true",
                        help=("skip the whole-file sha256; the 'is this the image the "
                              "signatures came from' test needs it"))
    parser.add_argument("--require-unique", action="store_true",
                        help="exit 1 if any signature is not unique")
    parser.add_argument("--json", action="store_true",
                        help="print the JSON document instead of the summary")
    parser.add_argument("--jsonl", action="store_true",
                        help="print the per-signature JSONL artifact to stdout")
    parser.add_argument("--out", default=None,
                        help="write the JSON document here")
    parser.add_argument("--jsonl-out", default=None,
                        help="write the per-signature JSONL artifact here")
    parser.add_argument("--install-dir", default=None,
                        help="installation root the output guard checks against")
    parser.add_argument("--limit", type=int, default=40, metavar="N",
                        help="signatures printed in the human summary")
    return parser


def _split_sections(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    return tuple(part.strip() for part in value.split(",") if part.strip())


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not os.path.isfile(args.path):
        print("error: not a file: %s" % args.path, file=sys.stderr)
        return 2
    if not args.library and not args.pattern:
        print("error: nothing to search for: pass --library or at least one "
              "--pattern", file=sys.stderr)
        return 2
    for name, value in (("--hit-limit", args.hit_limit),
                        ("--count-cap", args.count_cap),
                        ("--literal-samples", args.literal_samples)):
        if value < 0:
            print("error: %s must not be negative" % name, file=sys.stderr)
            return 2
    if args.count_cap == 0:
        print("error: --count-cap 0 would count nothing and report every signature "
              "as absent", file=sys.stderr)
        return 2

    signatures: list[dict] = []
    provenance: dict = {"format": "inline --pattern"}
    notes: list[str] = []
    if args.library:
        try:
            signatures, provenance, notes = load_library(args.library,
                                                         args.include_rejected)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print("error: --library %s: %s" % (args.library, error), file=sys.stderr)
            return 2
    if args.pattern:
        labels = args.label or []
        for index, text in enumerate(args.pattern):
            label = labels[index] if index < len(labels) else "--pattern[%d]" % index
            signatures.append({"label": label, "pattern": text,
                               "accepted_in_library": None, "source_rva": None,
                               "source_file_offset": None, "rejections": []})
        if args.library:
            provenance = dict(provenance)
            provenance["format"] = "%s + inline --pattern" % provenance.get("format")
    if not signatures:
        print("error: no signatures to scan (the library was empty, or every entry "
              "was rejected -- try --include-rejected)", file=sys.stderr)
        return 2
    # Duplicate labels would make the per-signature join ambiguous, and the join
    # is what ties a verdict to the address it is about.
    seen: dict[str, int] = {}
    for row in signatures:
        seen[row["label"]] = seen.get(row["label"], 0) + 1
    duplicates = sorted(name for name, count in seen.items() if count > 1)
    if duplicates:
        print("error: duplicate signature label(s): %s. A label is the join key "
              "between a verdict and an address; it has to be unique"
              % ", ".join(duplicates[:8]), file=sys.stderr)
        return 2

    install_root = args.install_dir or pe_info.detect_install_root(args.path)

    checked: dict[str, str] = {}
    for flag, value in (("--out", args.out), ("--jsonl-out", args.jsonl_out)):
        if not value:
            continue
        try:
            checked[flag] = pathguard.check_output_path(value, install_root, what=flag)
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2

    try:
        document = analyze(
            args.path, signatures,
            surface_kind=args.surface,
            only_sections=_split_sections(args.sections),
            hit_limit=args.hit_limit,
            count_cap=args.count_cap,
            literal_samples=args.literal_samples,
            library_provenance=provenance,
            library_notes=notes,
            want_file_digest=not args.no_digest,
            want_probes=not args.no_probes,
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
            written.append(write_text(dump_json(document), checked["--out"],
                                      install_root, "--out"))
        if "--jsonl-out" in checked:
            body = "".join(line + "\n" for line in jsonl_lines(document))
            written.append(write_text(body, checked["--jsonl-out"], install_root,
                                      "--jsonl-out"))
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
        for path in written:
            print("\nwritten: %s" % path)

    if args.require_unique and document["summary"]["unique"] != len(
            document["signatures"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
