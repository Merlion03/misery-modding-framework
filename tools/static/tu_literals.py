#!/usr/bin/env python3
"""Read-only census of compiled-in source-path literals in a PE image (CK-01).

The question this tool exists to answer
---------------------------------------
``research/unknowns.md`` CK-01 asks whether the shipped build uses unversioned
property serialization in cooked packages. The route that would MEASURE that --
read ``PKG_UnversionedProperties`` out of a shipped package summary -- is closed:
every one of the 4424 payloads in ``MISERY-Windows.pak`` is encrypted, that
container holds no cooked asset of any kind, the IoStore directory index is
encrypted, and decision D-02 forbids decryption (see
``research/evidence/CK-01/pak-index.json`` and ``research/modkit/ck-01.md``).

What is left on the binary side is a much weaker question, and it is worth being
precise about how weak: *is the unversioned-serialization translation unit
compiled into the image at all?* An absence would be decisive -- a runtime that
cannot execute ``SerializeUnversionedProperties`` cannot load an unversioned
package. A presence licenses almost nothing, because
``UnversionedPropertySerialization.h:13`` declares
``SerializeUnversionedProperties`` with no ``#if`` guard, so CoreUObject compiles
it in every configuration whether the project's content uses it or not.

A cheap way to ask "was translation unit X compiled in" is to look for X's own
path as a string literal: MSVC emits ``__FILE__`` for the assertion and logging
macros, so a TU that uses one of them leaves its own source path in ``.rdata``.
This tool performs that census -- AND measures how much power the test has,
because a test whose power is not measured produces absences that read like
evidence and are not.

Why the power measurement is the point, not a decoration
--------------------------------------------------------
``UnversionedPropertySerialization.cpp`` contains no ``UE_LOG`` at all: its only
diagnostics are ``check``/``checkf`` (lines 126, 193, 438, 608, 614, 707, 733,
783, 884, 917 of the UE 5.4.4 source) and one editor-only ``ensureMsgf`` (1001).
``Engine/Source/Runtime/Core/Public/Misc/Build.h:312-313`` (inside the
``#elif UE_BUILD_SHIPPING`` branch opened at ``:308``) defines ``DO_CHECK`` as
``USE_CHECKS_IN_SHIPPING`` in a Shipping configuration -- corrected 2026-08-23,
was wrongly cited as ``:290-291``, which is the ``#elif UE_BUILD_TEST`` branch
opened at ``:286`` and happens to define the same macro the same way, so the
number below was never wrong, only the pointer to where it comes from -- and
``Build.h:195-196`` defines ``USE_CHECKS_IN_SHIPPING`` as ``0``. So in a Shipping
image every one of those macros -- and with them every ``__FILE__`` they would
have emitted -- is compiled out, and the TU can be fully linked while leaving no
path literal whatever.

That means the absence of this file's path from a Shipping image is EXPECTED and
carries no information. Asserting that would be an opinion. This tool measures
it instead, in two ways that need no assumption about which macro emits what:

1. Over a named corpus of translation units that are certainly linked into the
   image (``Runtime/Core/Private`` and ``Runtime/CoreUObject/Private`` -- a UE5
   game cannot run without either module), it reports what fraction leave a path
   literal at all. If that fraction is small, no single absence means anything.

2. It cross-tabulates "leaves a literal" against "uses the ``check`` family",
   and it does so for TWO images of the same game: the Shipping binary and the
   282 MB ``MISERY.exe`` that D-04 keeps as a read-only oracle. If the check
   family is the emitter and Shipping compiles it out, the correlation must be
   strong in one image and near-absent in the other. That is a prediction this
   tool can fail, and it is checked rather than assumed.

Neither measurement says anything about the cook. Nothing in an executable can:
the flag CK-01 asks about is a property of the CONTENT, written into each
package's summary at save time (``LinkerSave.cpp:528-550``) and read back per
package at load time (``LinkerLoad.cpp:1421-1423``,
``AsyncLoading2.cpp:6205``). This tool bounds what the image can be doing. It
does not answer CK-01, and ``research/modkit/ck-01.md`` says so explicitly.

Where the layout comes from
---------------------------
The PE layer is not re-derived here. ``tools/fingerprint/pe_info.py`` owns the
DOS/COFF/optional headers, the section table and RVA translation (task F-01),
and this module imports it so that there is exactly one opinion in the project
about where ``.rdata`` is.

The string-shape rules are the ones ``tools/static/extract_strings.py`` argued
for and are restated because they decide what this census can see:

* ASCII runs are expanded from a marker to the nearest non-printable byte in
  each direction, which is how a NUL-terminated literal ends.
* UTF-16LE candidates must start at an EVEN file offset. A ``wchar_t`` array in
  a C++ image is 2-byte aligned by the language, so an odd-aligned printable
  wide run is the misread tail of some other structure. The cost -- a genuinely
  odd-aligned wide string is missed -- is stated rather than hidden, and the
  number of parity rejections is reported.
* Nothing is dropped silently. A run that matches the marker but does not end in
  a source-file extension is counted in ``unclassified_runs`` rather than
  discarded, so "the census found N paths" can be checked against "the scan
  found N+M runs".

The build-root prefix is DISCOVERED, not assumed. The scan anchors on
``<sep>Source<sep>`` and walks left to the start of the printable run, so
whatever precedes ``Engine`` is measured. That makes "is there exactly one build
root in this image?" a real probe: two roots would mean mixed provenance and
would change what the whole census means.

Refutation probes (plan.md 10.3, class-I criterion: try to break the headline)
-----------------------------------------------------------------------------
``decoy_query``
    A query for a path that cannot exist in any UE tree must come back ABSENT.
    If the matcher answered "found" for a fabricated name, every other absence
    in this document would be worthless. Run on every invocation.

``roundtrip_query``
    A path taken FROM the census is queried back through the same matcher and
    must come back present with the same offsets. A matcher that normalises
    separators or case can easily fail to find what it just recorded.

``prefix_census``
    Every distinct build-root prefix with its count. One root is the expected
    result; more than one is reported loudly rather than averaged away.

``corpus_partition``
    Every ``.cpp`` in the corpus lands in exactly one bucket (platform-excluded,
    test-excluded, candidate) and the buckets sum to the file count. A silent
    drop here would inflate or deflate the measured power directly.

``second_read``
    Every literal read reported in the class-P layer is performed again through a
    freshly opened handle and the result is stamped onto the record. Nothing is
    adjusted on disagreement: the reading stands as unreproduced.

What this tool does NOT prove
-----------------------------
* Not that the TU is absent when its path is absent. See the power measurement.
* Not that the TU is present when its path is present in ANOTHER image. The
  282 MB ``MISERY.exe`` is a different binary from the Shipping one; D-04 keeps
  it as an oracle and leaves "Development build" at HYPOTHESIS 0.65.
* Not anything about the cook. See above.

Safety
------
Read-only with respect to the game: the images are opened ``"rb"`` and nothing
is ever written next to them. Every output path is checked by
``tools/inventory/pathguard.check_output_path`` BEFORE any file is opened, so a
path that resolves inside an installation leaves nothing behind (D-01).

Exit codes: 0 the census completed (whatever the verdict), 2 usage / I/O error /
unparseable input. An absent query is a successful run, not a failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
for _extra in (os.path.join(_TOOLS, "inventory"), os.path.join(_TOOLS, "fingerprint")):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never
# reimplemented.
import pathguard  # noqa: E402  (sys.path is prepared just above)

# The PE layer is F-01's. Re-deriving section tables here would give this tool a
# second, differently-buggy opinion about where .rdata is.
import pe_info  # noqa: E402

GENERATOR_NAME = "tools/static/tu_literals.py"
GENERATOR_VERSION = "1.0.0"

PEFormatError = pe_info.PEFormatError

# Confidence for a bare positioned read of bytes. Matches the value the other
# static tools use for the same kind of claim.
CONFIDENCE_LITERAL = 0.99

# Read the scan surface in slices this large. The surface is the WHOLE file on
# purpose: a null result over "the sections we thought were interesting" is not
# a finding, and the tiling below is checked.
SLICE_BYTES = 32 << 20
# Overlap between slices, so a literal straddling a slice boundary is still
# found exactly once. Comfortably larger than the longest run accepted.
SLICE_OVERLAP = 4096

# A source path literal is at most this long. MSVC emits __FILE__ as the path
# the compiler was given, which for UE is the absolute path under the build
# root; 400 bytes is roughly twice the longest such path in the 5.4 tree.
MAX_RUN_BYTES = 400
# ... and at least this long, so that a two-character run cannot become a "path".
MIN_RUN_BYTES = 12

# Accepted source-file extensions, lowercase, with the dot.
SOURCE_EXTENSIONS = (".cpp", ".h", ".inl", ".c", ".hpp", ".cc", ".cxx", ".ipp")

# Path components that mark a translation unit as belonging to a platform this
# image was not built for. Excluded from the power corpus and counted.
NON_WINDOWS_COMPONENTS = frozenset((
    "unix", "mac", "apple", "ios", "tvos", "visionos", "android",
    "hololens", "linux", "switch", "ps4", "ps5", "xboxone", "xsx",
    "nintendo", "sony", "microsoft",
))

# Basename/component markers for automation-test translation units. In a
# Shipping build WITH_DEV_AUTOMATION_TESTS is 0, so these are not linked;
# excluded from the corpus and counted.
TEST_BASENAME_SUFFIXES = ("test.cpp", "tests.cpp", "testing.cpp")
TEST_COMPONENTS = frozenset(("tests", "test"))

# The check family. Not "the emitter" -- a hypothesis about the emitter, which
# the cross-image contingency table is there to confirm or refute.
CHECK_FAMILY = re.compile(
    r"\b(?:check|checkf|checkSlow|checkfSlow|verify|verifyf|checkCode|"
    r"checkNoEntry|checkNoReentry|checkNoRecursion|ensure|ensureMsgf|"
    r"ensureAlways|ensureAlwaysMsgf)\b")
LOG_FAMILY = re.compile(r"\b(?:UE_LOG|UE_CLOG|UE_LOGFMT|UE_CLOGFMT)\b")
# The subset of the logging family that a Shipping build cannot drop, because a
# fatal log is the error path itself rather than a diagnostic. Named separately
# so the contingency table can say which of the three candidate emitters the
# measurement actually points at, instead of asserting one.
FATAL_FAMILY = re.compile(
    r"\bLowLevelFatalError\b|\bUE_LOG\s*\(\s*\w+\s*,\s*Fatal\b|"
    r"\bUE_CLOG\s*\([^;]{0,200}?,\s*Fatal\b")

PRINTABLE = bytes(range(0x20, 0x7F))
_PRINTABLE_SET = frozenset(PRINTABLE)


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hex_bytes(raw: bytes) -> str:
    return " ".join("%02x" % byte for byte in raw)


def normalise_path(text: str) -> str:
    """Separators to ``/``. Case is preserved; comparisons fold it separately."""
    return text.replace("\\", "/")


def file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb", buffering=0) as handle:
        while True:
            block = handle.read(1 << 20)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _is_printable(byte: int) -> bool:
    return byte in _PRINTABLE_SET


def install_relative_name(path: str) -> str:
    """The install-relative spelling of *path*, or its basename.

    A class-P read locus has to be determinate, and this installation has two
    files called ``MISERY.exe``, so a bare basename is not enough for an image
    that lives inside it. For an image that does NOT -- a synthetic one under a
    temporary directory, possibly on another drive -- there is no
    install-relative spelling to give, and inventing one would be worse than
    the basename. ``os.path.relpath`` raises across drives on Windows; that is
    a normal outcome here, not an error.
    """
    absolute = os.path.abspath(path)
    root = pe_info.detect_install_root(path)
    if not root:
        return os.path.basename(absolute)
    try:
        if not pathguard.is_inside(absolute, root):
            return os.path.basename(absolute)
        return os.path.relpath(absolute, root).replace(os.sep, "/")
    except (ValueError, OSError):
        return os.path.basename(absolute)


# --------------------------------------------------------------------------- #
# the scan
# --------------------------------------------------------------------------- #

class Run:
    """One printable run that contained the marker, with its encoding."""

    __slots__ = ("offset", "length", "encoding", "text")

    def __init__(self, offset: int, length: int, encoding: str, text: str) -> None:
        self.offset = offset
        self.length = length
        self.encoding = encoding
        self.text = text


def _expand_ascii(blob: bytes, base: int, hit: int) -> Run | None:
    """Expand an ASCII hit to the printable run around it.

    ``base`` is the file offset of ``blob[0]``; ``hit`` is an index into
    ``blob``. Returns None when the run hits a slice edge, in which case the
    overlap of the next slice will catch it.
    """
    start = hit
    limit = max(0, hit - MAX_RUN_BYTES)
    while start > limit and _is_printable(blob[start - 1]):
        start -= 1
    end = hit
    ceiling = min(len(blob), hit + MAX_RUN_BYTES)
    while end < ceiling and _is_printable(blob[end]):
        end += 1
    if start == 0 and base != 0:
        return None
    if end == len(blob) and base + len(blob) != _SCAN_TOTAL[0]:
        return None
    length = end - start
    if length < MIN_RUN_BYTES:
        return None
    return Run(base + start, length, "ascii",
               blob[start:end].decode("ascii", "replace"))


def _expand_utf16(blob: bytes, base: int, hit: int,
                  parity_rejected: list[int]) -> Run | None:
    """Expand a UTF-16LE hit to the aligned (printable, 0x00) run around it."""
    if (base + hit) % 2 != 0:
        parity_rejected[0] += 1
        return None
    start = hit
    limit = max(0, hit - 2 * MAX_RUN_BYTES)
    while (start - 2 >= limit
           and _is_printable(blob[start - 2]) and blob[start - 1] == 0):
        start -= 2
    end = hit
    ceiling = min(len(blob) - 1, hit + 2 * MAX_RUN_BYTES)
    while end + 1 < ceiling and _is_printable(blob[end]) and blob[end + 1] == 0:
        end += 2
    if start == 0 and base != 0:
        return None
    if end >= len(blob) - 2 and base + len(blob) != _SCAN_TOTAL[0]:
        return None
    length = end - start
    if length < 2 * MIN_RUN_BYTES:
        return None
    text = blob[start:end:2].decode("ascii", "replace")
    return Run(base + start, length, "utf-16le", text)


# The whole-file size, set once per scan. Module-level because the expanders
# need to know whether a run that reaches a slice edge also reaches the file
# edge, and threading that through every call adds noise for no gain.
_SCAN_TOTAL = [0]


def scan_runs(path: str, size: int) -> tuple[list[Run], dict]:
    """Every printable run in the whole file that contains ``<sep>Source<sep>``.

    The surface is the entire file. Slices overlap by ``SLICE_OVERLAP`` and a run
    that touches a slice edge is dropped by the expander and picked up from the
    neighbouring slice, so each run is reported exactly once -- checked by the
    duplicate count in the returned statistics.
    """
    _SCAN_TOTAL[0] = size
    markers_ascii = (b"\\Source\\", b"/Source/")
    markers_utf16 = tuple(m.decode("ascii").encode("utf-16-le")
                          for m in markers_ascii)
    seen: dict[tuple[int, str], Run] = {}
    stats = {
        "slices": 0,
        "bytes_read": 0,
        "marker_hits_ascii": 0,
        "marker_hits_utf16": 0,
        "runs_dropped_at_slice_edge": 0,
        "runs_dropped_too_short": 0,
        "utf16_parity_rejected": 0,
        "duplicate_runs_suppressed": 0,
    }
    parity = [0]
    with open(path, "rb", buffering=0) as handle:
        base = 0
        while base < size:
            handle.seek(base)
            blob = handle.read(SLICE_BYTES + SLICE_OVERLAP)
            if not blob:
                break
            stats["slices"] += 1
            stats["bytes_read"] += len(blob)
            for marker in markers_ascii:
                cursor = 0
                while True:
                    hit = blob.find(marker, cursor)
                    if hit < 0:
                        break
                    cursor = hit + 1
                    stats["marker_hits_ascii"] += 1
                    run = _expand_ascii(blob, base, hit)
                    if run is None:
                        stats["runs_dropped_at_slice_edge"] += 1
                        continue
                    key = (run.offset, run.encoding)
                    if key in seen:
                        stats["duplicate_runs_suppressed"] += 1
                    else:
                        seen[key] = run
            for marker in markers_utf16:
                cursor = 0
                while True:
                    hit = blob.find(marker, cursor)
                    if hit < 0:
                        break
                    cursor = hit + 1
                    stats["marker_hits_utf16"] += 1
                    run = _expand_utf16(blob, base, hit, parity)
                    if run is None:
                        stats["runs_dropped_at_slice_edge"] += 1
                        continue
                    key = (run.offset, run.encoding)
                    if key in seen:
                        stats["duplicate_runs_suppressed"] += 1
                    else:
                        seen[key] = run
            if len(blob) < SLICE_BYTES + SLICE_OVERLAP:
                break
            base += SLICE_BYTES
    stats["utf16_parity_rejected"] = parity[0]
    return list(seen.values()), stats


def classify_runs(runs: list[Run]) -> tuple[dict, dict, list[Run]]:
    """Split runs into source paths (prefix + relative path) and the rest.

    Returns ``(paths, prefixes, unclassified)`` where ``paths`` maps the
    normalised relative path -- everything from the component before
    ``/Source/`` onward -- to a record with the occurrence list.
    """
    paths: dict[str, dict] = {}
    prefixes: Counter = Counter()
    unclassified: list[Run] = []
    for run in runs:
        text = normalise_path(run.text)
        lowered = text.lower()
        if not lowered.endswith(SOURCE_EXTENSIONS):
            unclassified.append(run)
            continue
        marker = lowered.rfind("/source/")
        if marker < 0:
            unclassified.append(run)
            continue
        # The module root is the component immediately before /Source/ --
        # "Engine" for the engine tree, the project or plugin name otherwise.
        root_start = text.rfind("/", 0, marker)
        if root_start < 0:
            unclassified.append(run)
            continue
        prefix = text[:root_start + 1]
        relative = text[root_start + 1:]
        prefixes[prefix] += 1
        record = paths.setdefault(relative, {
            "relative_path": relative,
            "occurrences": [],
        })
        record["occurrences"].append({
            "offset": run.offset,
            "length": run.length,
            "encoding": run.encoding,
            "prefix": prefix,
        })
    for record in paths.values():
        record["occurrences"].sort(key=lambda item: item["offset"])
        record["occurrence_count"] = len(record["occurrences"])
        record["encodings"] = sorted({o["encoding"] for o in record["occurrences"]})
        record["first_offset"] = record["occurrences"][0]["offset"]
    return paths, dict(prefixes), unclassified


def drive_roots(prefixes: dict) -> dict:
    """Prefixes folded to drive plus first component, with their counts.

    The raw prefix census is deliberately literal, and that makes it noisy for
    two reasons that are both facts about the image rather than bugs: (a) the
    anchor is the LAST ``/Source/`` in a run, which for a plugin tree correctly
    puts the plugin name before it and therefore pushes the prefix deeper than
    the build root; (b) the left expansion stops at the first non-printable
    byte, so when two literals sit adjacent with no NUL between them the run
    absorbs a few bytes of its neighbour and the prefix acquires a garbage head.
    Folding to drive + first component collapses both effects and makes the
    real question -- how many machines built the code in this image -- legible.
    """
    folded: Counter = Counter()
    for prefix, count in prefixes.items():
        parts = [part for part in prefix.split("/") if part]
        head = "/".join(parts[:2]) + "/" if len(parts) >= 2 else prefix
        folded[head] += count
    return dict(folded)


def attribute_sections(headers, offsets: list[int]) -> dict:
    """Which PE section each offset falls in, by raw range. Counts only."""
    table = []
    for section in headers.sections:
        start = section["raw_pointer"]
        end = start + section["rsize"]
        table.append((start, end, section["name"]))
    counts: Counter = Counter()
    for offset in offsets:
        placed = None
        for start, end, name in table:
            if start <= offset < end:
                placed = name
                break
        counts[placed or "<outside every raw section range>"] += 1
    return dict(counts)


# --------------------------------------------------------------------------- #
# queries
# --------------------------------------------------------------------------- #

def query_paths(paths: dict, wanted: str) -> dict:
    """Suffix match of a relative path against the census, case-folded."""
    needle = normalise_path(wanted).lower().lstrip("/")
    matches = []
    for relative, record in paths.items():
        if relative.lower().endswith(needle):
            matches.append(record)
    matches.sort(key=lambda record: record["first_offset"])
    return {
        "query": normalise_path(wanted),
        "found": bool(matches),
        "match_count": len(matches),
        "matches": [{
            "relative_path": record["relative_path"],
            "occurrence_count": record["occurrence_count"],
            "first_offset": record["first_offset"],
            "encodings": record["encodings"],
        } for record in matches],
    }


# --------------------------------------------------------------------------- #
# the power measurement
# --------------------------------------------------------------------------- #

def corpus_files(source_root: str, corpus_relatives: list[str],
                 warnings: list[str]) -> tuple[list[str], dict]:
    """Every ``.cpp`` under each corpus directory, as a path relative to root.

    ``source_root`` is the directory that contains ``Runtime`` -- that is,
    ``<UE>/Engine/Source``. The returned relative paths are spelled the way the
    census spells them, ``Engine/Source/...``, so the two can be compared.
    """
    found: list[str] = []
    counts = {"roots_missing": 0, "cpp_total": 0}
    for relative in corpus_relatives:
        root = os.path.join(source_root, relative.replace("/", os.sep))
        if not os.path.isdir(root):
            counts["roots_missing"] += 1
            warnings.append(
                "corpus root %r is not a directory under the given source root; "
                "the power measurement is missing that corpus" % relative)
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                if not name.lower().endswith(".cpp"):
                    continue
                absolute = os.path.join(dirpath, name)
                rel = os.path.relpath(absolute, source_root)
                found.append("Engine/Source/" + normalise_path(rel))
                counts["cpp_total"] += 1
    found.sort()
    return found, counts


def bucket_corpus(files: list[str]) -> dict:
    """Partition the corpus. Every file lands in exactly one bucket."""
    buckets = {"platform_excluded": [], "test_excluded": [], "candidate": []}
    for relative in files:
        components = [c.lower() for c in relative.split("/")]
        basename = components[-1]
        if any(c in NON_WINDOWS_COMPONENTS for c in components[:-1]):
            buckets["platform_excluded"].append(relative)
        elif (basename.endswith(TEST_BASENAME_SUFFIXES)
              or any(c in TEST_COMPONENTS for c in components[:-1])):
            buckets["test_excluded"].append(relative)
        else:
            buckets["candidate"].append(relative)
    return buckets


def read_text_best_effort(path: str) -> str | None:
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        return None
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def measure_power(paths: dict, source_root: str, corpus_relatives: list[str],
                 warnings: list[str]) -> dict:
    """How often does a certainly-linked translation unit leave its path behind?

    The headline is ``p_present_overall``: over translation units that a UE5 game
    cannot run without, the fraction whose source path appears in this image.
    When that number is small, no single absence carries information, and the
    "is this TU compiled in?" test has no power for a TU that leaves no literal.
    """
    files, counts = corpus_files(source_root, corpus_relatives, warnings)
    buckets = bucket_corpus(files)
    present_index = {relative.lower() for relative in paths}

    def is_present(relative: str) -> bool:
        needle = relative.lower()
        if needle in present_index:
            return True
        return any(candidate.endswith(needle) for candidate in present_index)

    table = {"check_present": 0, "check_absent": 0,
             "nocheck_present": 0, "nocheck_absent": 0,
             "unreadable": 0}
    log_table = {"log_present": 0, "log_absent": 0,
                 "nolog_present": 0, "nolog_absent": 0}
    fatal_table = {"fatal_present": 0, "fatal_absent": 0,
                   "nofatal_present": 0, "nofatal_absent": 0}
    present_total = 0
    for relative in buckets["candidate"]:
        absolute = os.path.join(source_root,
                                relative[len("Engine/Source/"):].replace("/", os.sep))
        text = read_text_best_effort(absolute)
        present = is_present(relative)
        if present:
            present_total += 1
        if text is None:
            table["unreadable"] += 1
            continue
        has_check = bool(CHECK_FAMILY.search(text))
        has_log = bool(LOG_FAMILY.search(text))
        has_fatal = bool(FATAL_FAMILY.search(text))
        if has_check:
            table["check_present" if present else "check_absent"] += 1
        else:
            table["nocheck_present" if present else "nocheck_absent"] += 1
        if has_log:
            log_table["log_present" if present else "log_absent"] += 1
        else:
            log_table["nolog_present" if present else "nolog_absent"] += 1
        if has_fatal:
            fatal_table["fatal_present" if present else "fatal_absent"] += 1
        else:
            fatal_table["nofatal_present" if present else "nofatal_absent"] += 1

    candidates = len(buckets["candidate"])

    def ratio(numerator: int, denominator: int):
        if denominator == 0:
            return None
        return round(numerator / denominator, 4)

    partition_ok = (len(buckets["platform_excluded"]) + len(buckets["test_excluded"])
                    + candidates) == counts["cpp_total"]
    return {
        "corpus_roots": corpus_relatives,
        "cpp_total": counts["cpp_total"],
        "roots_missing": counts["roots_missing"],
        "platform_excluded": len(buckets["platform_excluded"]),
        "test_excluded": len(buckets["test_excluded"]),
        "candidates": candidates,
        "candidates_with_literal": present_total,
        "p_present_overall": ratio(present_total, candidates),
        "contingency_check_family": table,
        "p_present_given_check": ratio(
            table["check_present"], table["check_present"] + table["check_absent"]),
        "p_present_given_no_check": ratio(
            table["nocheck_present"],
            table["nocheck_present"] + table["nocheck_absent"]),
        "contingency_log_family": log_table,
        "p_present_given_log": ratio(
            log_table["log_present"], log_table["log_present"] + log_table["log_absent"]),
        "p_present_given_no_log": ratio(
            log_table["nolog_present"],
            log_table["nolog_present"] + log_table["nolog_absent"]),
        "contingency_fatal_family": fatal_table,
        "p_present_given_fatal": ratio(
            fatal_table["fatal_present"],
            fatal_table["fatal_present"] + fatal_table["fatal_absent"]),
        "p_present_given_no_fatal": ratio(
            fatal_table["nofatal_present"],
            fatal_table["nofatal_present"] + fatal_table["nofatal_absent"]),
        "probe_corpus_partition": {
            "buckets_sum_to_file_count": partition_ok,
            "note": ("every .cpp under the corpus roots lands in exactly one "
                     "bucket; a mismatch here would move the measured power "
                     "directly"),
        },
    }


# --------------------------------------------------------------------------- #
# class-P literal reads
# --------------------------------------------------------------------------- #

def literal_read(target: str, offset: int, raw: bytes, join_key: str) -> dict:
    """A positioned read that names nothing about what the bytes are.

    plan.md 10.3: for the binary-analysis oracle a class-P claim must state the
    offset AND the length and must not name a field, a layout, a type or a
    signature. ``join_key`` is a join into the interpretive layer, outside the
    graded object, because naming a structure inside the claim string is exactly
    what would derive class I.
    """
    length = len(raw)
    plural = "byte" if length == 1 else "bytes"
    claim = "%d %s at offset %d of %s are %s" % (
        length, plural, offset, target, hex_bytes(raw))
    return {
        "join_key": join_key,
        "interpretation_lives_in": (
            "the matching entry of source_path_literals[] / queries[] in the same "
            "document -- plan.md 10.3, the class-P / class-I split"),
        "target": target,
        "offset": offset,
        "length": length,
        "bytes_hex": hex_bytes(raw),
        "claim": claim,
        "reproduced": None,
        "evidence": {
            "evidence_level": "OBSERVED",
            "claim_class": "P",
            "confidence": CONFIDENCE_LITERAL,
            "oracle": ["binary-analysis"],
            "sources": [{
                "method": "CK-01",
                "artifact": None,
                "locator": "%s@%d+%d" % (target, offset, length),
                "note": ("oracle binary-analysis. Read by %s, read-only. "
                         "Reproduction: PENDING." % GENERATOR_NAME),
            }],
            "read_locus": {
                "target": target,
                "address_kind": "file-offset",
                "offset": offset,
                "length": length,
                "bytes_hex": hex_bytes(raw),
            },
            "note": ("%s. This record gives the position and the extent, and "
                     "nothing else." % claim),
        },
    }


def confirm_literal_reads(path: str, reads: list[dict], target: str,
                          warnings: list[str]) -> bool:
    """Perform every literal read a SECOND time through a fresh handle."""
    reproduced = True
    try:
        with open(path, "rb", buffering=0) as handle:
            for read in reads:
                handle.seek(read["offset"])
                again = handle.read(read["length"])
                if hex_bytes(again) != read["bytes_hex"]:
                    reproduced = False
                    read["reproduced"] = False
                    warnings.append(
                        "%s: the second read of %d bytes at offset %d gave %s but "
                        "the first gave %s -- the reading did NOT reproduce"
                        % (target, read["length"], read["offset"],
                           hex_bytes(again), read["bytes_hex"]))
                else:
                    read["reproduced"] = True
    except OSError as error:
        reproduced = False
        warnings.append("%s: second read pass failed: %s" % (target, error))
    for read in reads:
        note = read["evidence"]["sources"][0]["note"]
        read["evidence"]["sources"][0]["note"] = note.replace(
            "Reproduction: PENDING.",
            "Reproduction: the same range was read again through a freshly opened "
            "handle and %s." % ("gave the same bytes" if read.get("reproduced")
                                else "DID NOT give the same bytes"))
    return reproduced


# --------------------------------------------------------------------------- #
# analysis
# --------------------------------------------------------------------------- #

DEFAULT_QUERIES = (
    # The CK-01 target.
    "Runtime/CoreUObject/Private/Serialization/UnversionedPropertySerialization.cpp",
    # Its neighbours on the same code path, for contrast.
    "Runtime/CoreUObject/Private/UObject/Class.cpp",
    "Runtime/CoreUObject/Private/UObject/LinkerLoad.cpp",
    "Runtime/CoreUObject/Private/UObject/LinkerSave.cpp",
    "Runtime/CoreUObject/Private/UObject/PropertyTag.cpp",
    "Runtime/CoreUObject/Private/UObject/SavePackage2.cpp",
    "Runtime/CoreUObject/Private/Serialization/AsyncLoading2.cpp",
    "Runtime/CoreUObject/Private/UObject/PackageFileSummary.cpp",
    # A path that cannot exist anywhere: the matcher must say ABSENT.
    "Runtime/CoreUObject/Private/Serialization/NoSuchFileForCK01Decoy.cpp",
)

DEFAULT_CORPUS = (
    "Runtime/Core/Private",
    "Runtime/CoreUObject/Private",
)


def analyze(path: str, *, source_root: str | None = None,
            queries: list[str] | None = None,
            corpus: list[str] | None = None) -> dict:
    warnings: list[str] = []
    timings: dict[str, float] = {}
    started = time.perf_counter()

    size = os.path.getsize(path)
    digest = file_sha256(path)
    timings["digest"] = round(time.perf_counter() - started, 3)

    mark = time.perf_counter()
    with pe_info.Image.open(path) as image:
        headers = pe_info.PEHeaders(image)
        pe_facts = {
            "pe_format": headers.pe_format,
            "machine": headers.machine,
            "image_base": headers.image_base,
            "size_of_image": headers.size_of_image,
            "section_count": len(headers.sections),
        }
        section_names = [section["name"] for section in headers.sections]
        warnings.extend(headers.warnings)
    timings["pe_headers"] = round(time.perf_counter() - mark, 3)

    mark = time.perf_counter()
    runs, scan_stats = scan_runs(path, size)
    timings["scan"] = round(time.perf_counter() - mark, 3)

    mark = time.perf_counter()
    paths, prefixes, unclassified = classify_runs(runs)
    all_offsets = [occurrence["offset"]
                   for record in paths.values()
                   for occurrence in record["occurrences"]]
    with pe_info.Image.open(path) as image:
        headers = pe_info.PEHeaders(image)
        sections_hit = attribute_sections(headers, all_offsets)
    timings["classify"] = round(time.perf_counter() - mark, 3)

    wanted = list(queries) if queries else list(DEFAULT_QUERIES)
    query_results = [query_paths(paths, item) for item in wanted]

    # Probes ----------------------------------------------------------------
    decoy = query_paths(paths, DEFAULT_QUERIES[-1])
    roundtrip = None
    if paths:
        sample = sorted(paths.values(), key=lambda record: record["first_offset"])[0]
        roundtrip = query_paths(paths, sample["relative_path"])
        roundtrip_ok = (roundtrip["found"]
                        and roundtrip["matches"][0]["first_offset"]
                        == sample["first_offset"])
    else:
        roundtrip_ok = False
    probes = {
        "decoy_query": {
            "query": decoy["query"],
            "found": decoy["found"],
            "passed": not decoy["found"],
            "note": ("a fabricated path must come back absent; if it did not, "
                     "every absence in this document would be worthless"),
        },
        "roundtrip_query": {
            "passed": bool(roundtrip_ok),
            "query": roundtrip["query"] if roundtrip else None,
            "note": ("a path taken from the census is queried back through the "
                     "same matcher and must return with the same first offset"),
        },
        "prefix_census": {
            "distinct_prefixes": len(prefixes),
            "prefixes": prefixes,
            "distinct_drive_roots": len(drive_roots(prefixes)),
            "drive_roots": drive_roots(prefixes),
            "passed": len(drive_roots(prefixes)) <= 1,
            "note": ("one build root is the expected result; more than one means "
                     "the code in this image was compiled on more than one "
                     "machine, which changes what the census means. Not a "
                     "failure of the scan -- a fact about the image. Read "
                     "drive_roots, not prefixes: see drive_roots() for the two "
                     "reasons the raw prefix is deeper or dirtier than the "
                     "build root"),
        },
        "run_accounting": {
            "runs_found": len(runs),
            "classified_as_source_paths": sum(
                record["occurrence_count"] for record in paths.values()),
            "unclassified_runs": len(unclassified),
            "passed": (sum(record["occurrence_count"] for record in paths.values())
                       + len(unclassified)) == len(runs),
            "note": ("nothing is dropped silently: classified plus unclassified "
                     "must equal the runs the scan found"),
        },
    }

    # Power -----------------------------------------------------------------
    mark = time.perf_counter()
    if source_root:
        power = measure_power(paths, source_root,
                              list(corpus) if corpus else list(DEFAULT_CORPUS),
                              warnings)
    else:
        power = None
        warnings.append(
            "--ue-source-root was not given, so the power of the presence test "
            "was NOT measured. Without it an absence in queries[] cannot be "
            "read as evidence of anything.")
    timings["power"] = round(time.perf_counter() - mark, 3)

    # class-P literal reads --------------------------------------------------
    install_relative = install_relative_name(path)
    reads: list[dict] = []
    chosen = []
    for result in query_results:
        if result["found"]:
            chosen.append(result)
        if len(chosen) >= 2:
            break
    with open(path, "rb", buffering=0) as handle:
        for result in chosen:
            offset = result["matches"][0]["first_offset"]
            record = None
            for candidate in paths.values():
                if candidate["first_offset"] == offset:
                    record = candidate
                    break
            length = record["occurrences"][0]["length"] if record else 32
            handle.seek(offset)
            raw = handle.read(min(length, 64))
            reads.append(literal_read(install_relative, offset, raw,
                                      result["query"]))
    confirm_literal_reads(path, reads, install_relative, warnings)

    timings["total"] = round(time.perf_counter() - started, 3)

    return {
        "$comment": (
            "Census of compiled-in source-path literals in one PE image. The "
            "class-P layer is literal_reads[]; everything that says what a byte "
            "MEANS is class I and lives in source_path_literals[], queries[] and "
            "power[]. This document does NOT answer CK-01: the cook-time flag it "
            "asks about is a property of the content, not of the executable."),
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
        "generated_at": now_iso_utc(),
        "task": "CK-01",
        "file": {
            "install_relative": install_relative,
            "name": os.path.basename(path),
            "size": size,
            "sha256": digest,
            **pe_facts,
        },
        "scan_surface": {
            "bytes_in_file": size,
            "slice_bytes": SLICE_BYTES,
            "slice_overlap": SLICE_OVERLAP,
            "sections_in_image": section_names,
            "note": ("the surface is the whole file, not a chosen section: a "
                     "null result over an unnamed surface is nothing at all"),
            **scan_stats,
        },
        "source_path_literals": {
            "distinct_relative_paths": len(paths),
            "total_occurrences": sum(record["occurrence_count"]
                                     for record in paths.values()),
            "sections_hit": sections_hit,
            "prefixes": prefixes,
            "drive_roots": drive_roots(prefixes),
        },
        "queries": query_results,
        "power": power,
        "probes": probes,
        "literal_reads": reads,
        "unclassified_run_samples": [
            {"offset": run.offset, "length": run.length, "encoding": run.encoding}
            for run in sorted(unclassified, key=lambda r: r.offset)[:20]
        ],
        "timings_seconds": timings,
        "warnings": warnings,
        "_paths": {relative: record for relative, record in sorted(paths.items())},
    }


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def format_summary(document: dict) -> str:
    out: list[str] = []
    add = out.append
    handle = document["file"]
    add("%s %s" % (GENERATOR_NAME, GENERATOR_VERSION))
    add("Image: %s  size=%d  sha256=%s"
        % (handle["install_relative"], handle["size"], handle["sha256"]))
    surface = document["scan_surface"]
    add("Surface: whole file, %d bytes in %d slices; marker hits ascii=%d utf16=%d"
        % (surface["bytes_in_file"], surface["slices"],
           surface["marker_hits_ascii"], surface["marker_hits_utf16"]))
    literals = document["source_path_literals"]
    add("Source-path literals: %d distinct relative paths, %d occurrences"
        % (literals["distinct_relative_paths"], literals["total_occurrences"]))
    add("  build roots (drive + first component): %s"
        % json.dumps(literals["drive_roots"]))
    add("  sections hit: %s" % json.dumps(literals["sections_hit"]))
    add("")
    add("Queries")
    for result in document["queries"]:
        add("  %-6s %s%s" % ("FOUND" if result["found"] else "ABSENT",
                             result["query"],
                             ("  occurrences=%d first_offset=%d"
                              % (result["matches"][0]["occurrence_count"],
                                 result["matches"][0]["first_offset"]))
                             if result["found"] else ""))
    power = document["power"]
    add("")
    if power is None:
        add("Power of the presence test: NOT MEASURED (--ue-source-root absent). "
            "An absence above therefore licenses nothing.")
    else:
        add("Power of the presence test, over translation units a UE5 game "
            "cannot run without")
        add("  corpus %s" % ", ".join(power["corpus_roots"]))
        add("  .cpp files %d = platform-excluded %d + test-excluded %d + "
            "candidates %d"
            % (power["cpp_total"], power["platform_excluded"],
               power["test_excluded"], power["candidates"]))
        add("  candidates whose path literal is in this image: %d of %d "
            "(P=%s)"
            % (power["candidates_with_literal"], power["candidates"],
               power["p_present_overall"]))
        add("  P(literal | uses check family)    = %s"
            % power["p_present_given_check"])
        add("  P(literal | no check family)      = %s"
            % power["p_present_given_no_check"])
        add("  P(literal | uses UE_LOG family)   = %s"
            % power["p_present_given_log"])
        add("  P(literal | no UE_LOG family)     = %s"
            % power["p_present_given_no_log"])
        add("  P(literal | uses fatal family)    = %s"
            % power["p_present_given_fatal"])
        add("  P(literal | no fatal family)      = %s"
            % power["p_present_given_no_fatal"])
    add("")
    add("Probes")
    for name, probe in document["probes"].items():
        add("  %-18s %s" % (name, "PASS" if probe.get("passed") else "SEE NOTE"))
    add("")
    add("Literal reads (class P): %d ranges, re-read through a second handle: %s"
        % (len(document["literal_reads"]),
           "reproduced" if document["literal_reads"]
           and all(read.get("reproduced") for read in document["literal_reads"])
           else ("none taken" if not document["literal_reads"]
                 else "AT LEAST ONE DID NOT REPRODUCE")))
    add("Timings (s): %s" % json.dumps(document["timings_seconds"], sort_keys=True))
    if document["warnings"]:
        add("")
        add("Warnings")
        for line in document["warnings"]:
            add("  %s" % line)
    return "\n".join(out)


def dump_json(document: dict) -> str:
    public = {key: value for key, value in document.items() if key != "_paths"}
    return json.dumps(public, indent=2, sort_keys=False, ensure_ascii=False)


def format_paths(document: dict) -> str:
    lines = [
        "# %s %s -- source-path literals in %s"
        % (GENERATOR_NAME, GENERATOR_VERSION,
           document["file"]["install_relative"]),
        "# Columns: occurrences, first file offset, encodings, relative path.",
        "# The build-root prefix is reported once in source_path_literals.prefixes.",
    ]
    for relative, record in sorted(document["_paths"].items()):
        lines.append("%6d %12d %-18s %s"
                     % (record["occurrence_count"], record["first_offset"],
                        ",".join(record["encodings"]), relative))
    return "\n".join(lines) + "\n"


def write_text(text: str, out_path: str, install_root: str, what: str) -> str:
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
        prog="tu_literals.py",
        description=(
            "Read-only census of compiled-in source-path literals in a PE image "
            "(CK-01). Prints a human summary by default; --json prints the "
            "machine-readable document. Refuses any output path that resolves "
            "inside a game installation (D-01)."),
    )
    parser.add_argument("path", help="the PE image to read (opened read-only)")
    parser.add_argument("--json", action="store_true",
                        help="print the JSON document instead of the summary")
    parser.add_argument("--out", default=None, metavar="FILE",
                        help="also write the JSON document here")
    parser.add_argument("--paths-out", default=None, metavar="FILE",
                        help="also write the full relative-path list here")
    parser.add_argument("--ue-source-root", default=None, metavar="DIR",
                        help=("the directory containing Runtime/, i.e. "
                              "<UE>/Engine/Source. Without it the power of the "
                              "presence test is not measured and an absence "
                              "licenses nothing"))
    parser.add_argument("--query", action="append", default=None, metavar="REL",
                        help=("relative source path to look for; repeatable. "
                              "Replaces the default query set"))
    parser.add_argument("--corpus", action="append", default=None, metavar="REL",
                        help=("corpus directory for the power measurement, "
                              "relative to --ue-source-root; repeatable"))
    parser.add_argument("--install-dir", default=None, metavar="DIR",
                        help="installation root to protect (default: detected)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    install_root = args.install_dir or pe_info.detect_install_root(args.path)

    checked: dict[str, str] = {}
    for flag, value in (("--out", args.out), ("--paths-out", args.paths_out)):
        if value:
            try:
                checked[flag] = pathguard.check_output_path(
                    value, install_root, what=flag)
            except pathguard.OutputPathRefused as error:
                sys.stderr.write("%s: %s\n" % (flag, error))
                return 2

    if args.ue_source_root and not os.path.isdir(args.ue_source_root):
        sys.stderr.write("--ue-source-root %r is not a directory\n"
                         % args.ue_source_root)
        return 2

    try:
        document = analyze(args.path,
                           source_root=args.ue_source_root,
                           queries=args.query,
                           corpus=args.corpus)
    except (PEFormatError, OSError) as error:
        sys.stderr.write("%s\n" % error)
        return 2

    if args.json:
        sys.stdout.write(dump_json(document) + "\n")
    else:
        sys.stdout.write(format_summary(document) + "\n")

    if "--out" in checked:
        written = write_text(dump_json(document) + "\n", checked["--out"],
                             install_root, what="--out")
        sys.stdout.write("wrote %s\n" % written)
    if "--paths-out" in checked:
        written = write_text(format_paths(document), checked["--paths-out"],
                             install_root, what="--paths-out")
        sys.stdout.write("wrote %s\n" % written)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
