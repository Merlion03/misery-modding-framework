#!/usr/bin/env python3
"""Read-only probe: is the UStruct::Link property-offset path in a shipped PE? (CK-04)

The question this tool exists to answer
---------------------------------------
plan.md 14A.4 marks CK-04 the *decisive* question of the mod-kit track: are the
property offsets of a child Blueprint class BAKED at cook time, or recomputed at
load time by ``UStruct::Link``? plan.md 14A.3 danger 2 gives the stake -- child
properties are laid out after the parent, so if offsets are baked, a Blueprint
cooked against a RECONSTRUCTED parent carries offsets computed from OUR idea of
the parent's size, and the moment the real parent is a different size every
child property reads the wrong memory.

That question is answered by READING THE FIRST-PARTY SOURCE at the changelist
this build was made from. This tool does not answer it. This tool answers the
*second*, different question that the source cannot answer:

    does the shipped image actually CONTAIN the code path the source reading
    concluded governs this build?

Those are two acts of measurement of two different objects. The UE 5.4.4 tree
says what the engine does. The image says what was linked into THIS executable.
Only the pair says anything about the game, and this project has previously
fallen into exactly the trap of proving something about UE 5.4.4 in general and
then stating it as a fact about this build.

Why diagnostic strings, and why that is weaker than it looks
-----------------------------------------------------------
The functions at issue -- ``UStruct::Link``, ``FProperty::SetupOffset`` -- have
no exported symbol, no RTTI name (S-10: game classes 0, and these are engine
functions anyway) and no import to key off. What they DO have is unique
diagnostic string literals, and a string literal is the one artefact a compiler
cannot dissolve: it must be in ``.rdata``, byte for byte, or the call that
formats it has nothing to format.

But the honest limits have to be stated, because a string is not a function:

* a string in ``.rdata`` proves the STRING is in the image. It does not by
  itself prove any code reaches it. That is why this tool does not stop at
  ``bytes.find`` and performs an x86-64 RIP-relative reference pass
  (:func:`scan_riprel_references`) over the executable sections. A literal with
  zero references is reported as zero references and is worth much less.
* a string proves the ENCLOSING statement was compiled in. It does not prove the
  statement executes, and it does not prove the branch it sits in is the branch
  that runs at load time. That inference belongs to the source reading, is graded
  there, and is not laundered upward here.
* absence proves nothing about the function, only about the string. ``check``,
  ``checkf`` and ``ensureMsgf`` message text is compiled OUT when ``DO_CHECK`` /
  ``DO_ENSURE`` are 0, which is the normal Shipping configuration. So an absent
  ``checkf`` string is the EXPECTED reading for a Shipping image and says nothing
  about whether the surrounding function is present.

That last point is turned from an excuse into a test. The needles are tagged
with the macro that guards them (``UE_LOG_FATAL``, ``UE_LOG_ERROR``, ``CHECKF``,
``ENSUREMSGF``), the probe predicts which classes survive a Shipping link and
which do not, and :func:`build_refutation_probes` FAILS if the observed
presence pattern contradicts the prediction. A ``checkf`` string found in an
image where no ``UE_LOG(Fatal)`` string was found would mean the model of
compile-time gating is wrong, and then every "absent" reading in this document
would have to be re-read.

Nothing here is hard-coded except where to look
-----------------------------------------------
Every needle is READ OUT OF THE UE SOURCE TREE at run time, following the
pattern established by ``tools/static/find_constants.py``. ``NEEDLE_LOCI`` names
a file, a line-anchored regular expression and the guarding macro -- never the
literal text. If the tree at hand is a different changelist and a message was
reworded, this tool reports the wording it actually found, and the citation it
prints is the file and line it actually read. A hard-coded needle list would be
a list of guesses about the engine wearing the costume of a measurement.

Two output layers, and why they are separated
---------------------------------------------
plan.md 10.3 v2.4 forbids mixing a literal read with an interpretation under one
grade, so the document has two:

``literal_reads`` (class P, OBSERVED)
    "N bytes at offset X of <target> are <hex>". Offset AND length are stated in
    the claim itself because the binary-analysis oracle requires it for class P,
    and the claim names NOTHING about what the bytes are -- no module, no
    function, no field. Every one is re-read from a fresh handle before the
    document is emitted (class-P criterion 2).

``findings`` (class I, INFERRED)
    "this byte range is the message literal of <file>:<line>, and it is
    referenced from N places in an executable section". This names what the
    bytes are and leans on the source tree, so it carries two oracles
    (``binary-analysis`` + ``external-doc``) and a lower ceiling.

Oracles: ``binary-analysis`` for the image, ``external-doc`` for the UE source
tree, plus ``filesystem`` for the bare fact that a source file exists with the
text quoted. Per plan.md 10.5 reading the engine tree is external-doc: it proves
what the ENGINE does, never what this build does.

Refutation, stated in advance
-----------------------------
What we would see if the conclusion were wrong:

* the ``UE_LOG(Fatal)`` needle from inside the ``bRelinkExistingProperties``
  branch of ``UStruct::Link`` absent from the image -- the relink branch was not
  linked in, and the whole source argument would be about code this build does
  not carry;
* the ``FProperty::SetupOffset`` needle absent -- the function that assigns
  ``Offset_Internal`` from the owner's running size is not in the image;
* either needle present but with ZERO references from an executable section --
  the literal survived as dead data and no code formats it;
* a needle occurring MORE than once -- attribution to one source line is then
  ambiguous and is reported as ambiguous rather than as a hit;
* a ``CHECKF``-guarded needle present while no ``UE_LOG_FATAL`` needle is --
  the compile-gating model is inverted and every absence in this run is
  uninterpretable.

Each of those is a probe with a boolean outcome in ``probes``, and the headline
verdict is withheld unless the probes that can break it pass.

Verdicts (``verdict`` in the document)
--------------------------------------
``PATH_PRESENT_AND_REFERENCED``
    every required needle found exactly once and referenced at least once from
    an executable section.
``PATH_PRESENT_UNREFERENCED``
    found, but at least one required needle has no reference. Weaker.
``PATH_NOT_FOUND_WITHIN_TESTED_SURFACE``
    a required needle was not found. Phrased about the tested surface, never
    about the file, and the surface is listed byte range by byte range.
``INCONCLUSIVE``
    the probes contradict each other; no verdict is issued.

Read-only, always. The image is opened ``rb`` and nothing is written anywhere
near the installation; the output path is checked by ``pathguard`` (D-01).

Exit codes: 0 the probe ran (whatever the verdict), 2 usage / I/O error /
unparseable input. A negative verdict is a successful run, not a failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
for _extra in (os.path.join(_TOOLS, "inventory"), os.path.join(_TOOLS, "fingerprint")):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never
# reimplemented.
import pathguard  # noqa: E402

# The PE layer is F-01's. Section tables and RVA translation are not re-derived
# here: a second opinion about where .text is would be a second thing to keep
# correct.
import pe_info  # noqa: E402

GENERATOR_NAME = "tools/static/link_path_probe.py"
GENERATOR_VERSION = "1.0.0"

PEFormatError = pe_info.PEFormatError

CONFIDENCE_LITERAL = 0.99
CONFIDENCE_DECODED = 0.85

RERUN_CONFIRMED = "Method rerun and result reproduced."
RERUN_NOT_CONFIRMED = "Method rerun and the result did NOT reproduce."

# Hard limits. Each bounds a number that comes from a file and must not be
# believed.
MAX_SOURCE_FILE = 8 << 20        # a UE .cpp we will read whole
MAX_NEEDLE_CHARS = 512           # longest literal we will chase
MIN_NEEDLE_CHARS = 24            # shorter than this is not a distinctive needle
MAX_HITS_PER_NEEDLE = 64         # stop counting occurrences after this
MAX_REFS_PER_NEEDLE = 4096       # stop counting references after this
SCAN_CHUNK = 8 << 20
IMAGE_CHARACTERISTICS_EXECUTE = 0x20000000

UE_TREE_DEFAULT_ENV = "UE_SOURCE_ROOT"


# --------------------------------------------------------------------------- #
# The needles. A locus names a FILE, a REGEX and the guarding macro.
# It never names the literal text: that is read out of the tree at run time.
# --------------------------------------------------------------------------- #

# ``guard`` is the compile-time gate on the message text:
#   UE_LOG_FATAL  -- Fatal verbosity is never compiled out, Shipping included.
#   UE_LOG_ERROR  -- compiled out only by NO_LOGGING.
#   CHECKF        -- text gone when DO_CHECK == 0 (normal Shipping).
#   ENSUREMSGF    -- text gone when DO_ENSURE == 0 (normal Shipping).
#
# ``role`` says what the needle is FOR:
#   required   -- the verdict depends on it. Only UE_LOG_FATAL needles qualify,
#                 because only they are predicted to survive any configuration.
#   corroborating -- strengthens the reading where present, absence expected in
#                 Shipping and carries no weight either way.
#   control    -- exists to test the tool or the gating model, not the claim.

NEEDLE_LOCI = [
    {
        "id": "link_relink_branch",
        "role": "required",
        "guard": "UE_LOG_FATAL",
        "source": "Engine/Source/Runtime/CoreUObject/Private/UObject/Class.cpp",
        # UE_LOG(LogClass, Fatal, TEXT("'Struct recursion via arrays ...")) sits
        # INSIDE `if (bRelinkExistingProperties)`, in the UScriptStruct sub-block.
        "pattern": r'UE_LOG\(LogClass,\s*Fatal,\s*TEXT\("(\'Struct recursion via arrays[^"]*)"\)',
        "encloses": "UStruct::Link, inside the bRelinkExistingProperties branch",
        "why": ("its presence shows the branch that RECOMPUTES offsets was "
                "compiled into the image; UStruct::Link's other branch calls "
                "LinkWithoutChangingOffset instead and contains no Fatal log"),
    },
    {
        "id": "setup_offset",
        "role": "required",
        "guard": "UE_LOG_FATAL",
        "source": "Engine/Source/Runtime/CoreUObject/Private/UObject/Property.cpp",
        # UE::CoreUObject::Private::OnInvalidPropertySize -- one caller in the
        # whole tree, and that caller is FProperty::SetupOffset.
        "pattern": r'UE_LOG\(LogProperty,\s*Fatal,\s*TEXT\("(Invalid property size[^"]*)"\)',
        "encloses": ("UE::CoreUObject::Private::OnInvalidPropertySize, whose only "
                     "caller in the tree is FProperty::SetupOffset"),
        "why": ("SetupOffset is the function that assigns Offset_Internal from "
                "the owner struct's running PropertiesSize; the overflow guard "
                "that formats this message is inside it"),
    },
    {
        "id": "struct_property_link",
        "role": "corroborating",
        "guard": "UE_LOG_ERROR",
        "source": "Engine/Source/Runtime/CoreUObject/Private/UObject/PropertyStruct.cpp",
        "pattern": r'UE_LOG\(LogProperty,\s*Error,\s*TEXT\("(Struct type unknown for property[^"]*)"\)',
        "encloses": "FStructProperty::LinkInternal",
        "why": ("LinkInternal is where a struct property's ElementSize is "
                "recomputed from the resolved struct at load time"),
    },
    {
        "id": "link_owner_ensure",
        "role": "corroborating",
        "guard": "ENSUREMSGF",
        "source": "Engine/Source/Runtime/CoreUObject/Private/UObject/Class.cpp",
        "pattern": r'ensureMsgf\(Property->GetOwner<UObject>\(\) == this,\s*TEXT\("([^"]*)"\)',
        "encloses": "UStruct::Link, inside the bRelinkExistingProperties branch",
        "why": "sits two statements above the Property->Link(Ar) call itself",
    },
    {
        "id": "native_never_loaded",
        "role": "corroborating",
        "guard": "CHECKF",
        "source": "Engine/Source/Runtime/CoreUObject/Private/UObject/Class.cpp",
        "pattern": r'checkf\(!HasAnyClassFlags\(CLASS_Native\),\s*TEXT\("([^"]*)"\)',
        "encloses": "UClass::Serialize, immediately above its Link(Ar, true) call",
        "why": ("states in first-party words that a native class is never loaded "
                "from a package, which is the whole of question 1"),
    },
    {
        "id": "cpp_size_mismatch",
        "role": "corroborating",
        "guard": "CHECKF",
        "source": "Engine/Source/Runtime/CoreUObject/Private/UObject/Class.cpp",
        "pattern": r'checkf\(Stride == ClearedSize && PropertiesSize == ClearedSize,\s*TEXT\("([^"]*)"\)',
        "encloses": "UScriptStruct::DestroyStruct",
        "why": ("the only size cross-check in this area, and it compares C++ "
                "sizeof against the reflected size of a NATIVE struct -- not a "
                "cook-time size against a load-time size"),
    },
]

# A needle that must NOT be found: the tool has to be able to return zero.
# The text is derived from a real needle by mutation at run time, so it cannot
# drift into being a real string.
CONTROL_ABSENT_ID = "link_relink_branch"


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


def hex_bytes(raw: bytes) -> str:
    return " ".join("%02x" % byte for byte in raw)


def sha256_file(path: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb", buffering=0) as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def unescape_cpp(text: str) -> str:
    """Turn a C++ string-literal body into the bytes the compiler emits.

    Only the escapes UE actually uses in these messages are handled, and an
    unknown escape is left alone rather than guessed at -- a wrong guess here
    would silently search for a string that no compiler ever produced.
    """
    out = []
    index = 0
    simple = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'",
              "0": "\0"}
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            nxt = text[index + 1]
            if nxt in simple:
                out.append(simple[nxt])
                index += 2
                continue
        out.append(char)
        index += 1
    return "".join(out)


# --------------------------------------------------------------------------- #
# source layer -- read the needles out of the UE tree
# --------------------------------------------------------------------------- #

def locate_ue_tree(explicit: str | None, warnings: list[str]) -> str | None:
    """Find the UE source root. Explicit argument wins, then the environment.

    No search of the filesystem: a tool that goes looking for "some" engine tree
    can silently measure the wrong changelist, and the changelist is the entire
    reason the tree is admissible evidence at all.
    """
    for candidate in (explicit, os.environ.get(UE_TREE_DEFAULT_ENV)):
        if not candidate:
            continue
        root = os.path.abspath(candidate)
        if os.path.isdir(os.path.join(root, "Engine", "Source")):
            return root
        warnings.append("UE tree candidate %r has no Engine/Source -- ignored" % candidate)
    return None


def read_build_version(root: str, warnings: list[str]) -> dict | None:
    """Engine/Build/Build.version, verbatim. The changelist is the citation."""
    path = os.path.join(root, "Engine", "Build", "Build.version")
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as error:
        warnings.append("Build.version unreadable (%s): the tree cannot be cited "
                        "by changelist" % error)
        return None
    keep = ("MajorVersion", "MinorVersion", "PatchVersion", "Changelist",
            "BranchName", "IsPromotedBuild")
    return {key: data.get(key) for key in keep if key in data}


def harvest_needles(root: str, warnings: list[str]) -> list[dict]:
    """Extract each needle's literal text from the tree, with file and line.

    A locus that matches nothing is reported with ``found_in_source: false`` and
    dropped from the image pass. A locus that matches more than once is reported
    ambiguous and also dropped: attributing a hit to one source line is the
    whole point, and two candidate lines would make the citation a guess.
    """
    needles = []
    cache: dict[str, list[str]] = {}
    for locus in NEEDLE_LOCI:
        record = {
            "id": locus["id"],
            "role": locus["role"],
            "guard": locus["guard"],
            "source_file": locus["source"],
            "pattern": locus["pattern"],
            "encloses": locus["encloses"],
            "why": locus["why"],
            "found_in_source": False,
            "source_line": None,
            "text": None,
            "text_chars": None,
            "matches_in_file": 0,
        }
        path = os.path.join(root, *locus["source"].split("/"))
        if path not in cache:
            try:
                if os.path.getsize(path) > MAX_SOURCE_FILE:
                    warnings.append("%s exceeds %d bytes -- not read"
                                    % (locus["source"], MAX_SOURCE_FILE))
                    cache[path] = []
                else:
                    with open(path, "r", encoding="utf-8", errors="replace") as handle:
                        cache[path] = handle.read().splitlines()
            except OSError as error:
                warnings.append("%s unreadable: %s" % (locus["source"], error))
                cache[path] = []
        lines = cache[path]
        regex = re.compile(locus["pattern"])
        hits = []
        for number, line in enumerate(lines, start=1):
            match = regex.search(line)
            if match:
                hits.append((number, unescape_cpp(match.group(1))))
        record["matches_in_file"] = len(hits)
        if not hits:
            warnings.append("needle %s: pattern matched nothing in %s -- the "
                            "message may have been reworded at this changelist"
                            % (locus["id"], locus["source"]))
            needles.append(record)
            continue
        if len(hits) > 1:
            warnings.append("needle %s: pattern matched %d lines in %s -- "
                            "ambiguous, not used"
                            % (locus["id"], len(hits), locus["source"]))
            needles.append(record)
            continue
        number, text = hits[0]
        if not (MIN_NEEDLE_CHARS <= len(text) <= MAX_NEEDLE_CHARS):
            warnings.append("needle %s: literal of %d chars is outside "
                            "[%d, %d] -- not distinctive enough to chase"
                            % (locus["id"], len(text), MIN_NEEDLE_CHARS,
                               MAX_NEEDLE_CHARS))
            needles.append(record)
            continue
        record.update({
            "found_in_source": True,
            "source_line": number,
            "text": text,
            "text_chars": len(text),
            "citation": "%s:%d" % (locus["source"], number),
        })
        needles.append(record)
    return needles


# --------------------------------------------------------------------------- #
# source layer -- the refutation probe that reads the serializers
# --------------------------------------------------------------------------- #

# The question "is an offset written into a cooked package?" has an exact
# mechanical form: does the serializer for the object stream the member that
# holds the offset? So instead of asserting that it does not, extract the set of
# members each serializer streams and look. If a future changelist starts
# streaming the offset, this probe changes its answer on its own.
SERIALIZER_PROBES = [
    {
        "id": "fproperty_serialize",
        "source": "Engine/Source/Runtime/CoreUObject/Private/UObject/Property.cpp",
        "signature": "void FProperty::Serialize( FArchive& Ar )",
        "must_not_stream": ["Offset_Internal"],
        "why": ("Offset_Internal is the member that holds a property's offset "
                "from the container base. If a cooked package carried the "
                "offset, this is the one place it could be written."),
    },
    {
        "id": "ustruct_serialize",
        "source": "Engine/Source/Runtime/CoreUObject/Private/UObject/Class.cpp",
        "signature": "void UStruct::Serialize(FArchive& Ar)",
        "must_not_stream": ["PropertiesSize", "MinAlignment"],
        "why": ("PropertiesSize is the parent size that every child offset is "
                "measured from. If the cook-time parent size were recorded "
                "anywhere, this is where."),
    },
    {
        "id": "uclass_serialize",
        "source": "Engine/Source/Runtime/CoreUObject/Private/UObject/Class.cpp",
        "signature": "void UClass::Serialize( FArchive& Ar )",
        "must_not_stream": ["PropertiesSize", "MinAlignment", "Offset_Internal"],
        "why": "the class-level serializer, for the same two members",
    },
]

# ``Ar << X;`` and ``Ar << (T&)X;`` and ``Ar << X.GetAccessTrackedObjectPtr();``
_STREAM_RE = re.compile(r"Ar\s*<<\s*(?:\(\s*[A-Za-z_][\w:<>\* ]*\s*&\s*\)\s*)?"
                        r"([A-Za-z_][\w]*)")


def extract_function_body(lines: list[str], signature: str) -> tuple[int, int] | None:
    """Line span of a function whose signature line matches exactly.

    Brace counting from the opening ``{`` on or after the signature line to the
    matching close. Crude, and adequate for these three functions: none of them
    contains a brace inside a string literal or a comment before its body ends,
    and if that ever changed the probe would report a span that fails its own
    sanity check rather than a wrong answer, because the reported span is in the
    document for a reader to check.
    """
    start = None
    for number, line in enumerate(lines):
        if line.strip() == signature.strip():
            start = number
            break
    if start is None:
        return None
    depth = 0
    opened = False
    for number in range(start, len(lines)):
        for char in lines[number]:
            if char == "{":
                depth += 1
                opened = True
            elif char == "}":
                depth -= 1
        if opened and depth <= 0:
            return (start + 1, number + 1)
    return None


def run_serializer_probes(root: str, warnings: list[str]) -> list[dict]:
    """For each serializer, the members it streams -- read, not asserted.

    This is the refutation attempt plan.md 10.3 class-I criterion 6 demands,
    executed mechanically: "what would we see if offsets were baked into the
    package?" We would see the offset member in one of these lists.
    """
    results = []
    cache: dict[str, list[str]] = {}
    for probe in SERIALIZER_PROBES:
        record = {
            "id": probe["id"],
            "source_file": probe["source"],
            "signature": probe["signature"],
            "why": probe["why"],
            "found": False,
            "line_span": None,
            "streams": [],
            "must_not_stream": probe["must_not_stream"],
            "violations": [],
            "passed": False,
        }
        path = os.path.join(root, *probe["source"].split("/"))
        if path not in cache:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    cache[path] = handle.read().splitlines()
            except OSError as error:
                warnings.append("%s unreadable: %s" % (probe["source"], error))
                cache[path] = []
        lines = cache[path]
        span = extract_function_body(lines, probe["signature"])
        if span is None:
            warnings.append("serializer probe %s: signature %r not found in %s"
                            % (probe["id"], probe["signature"], probe["source"]))
            results.append(record)
            continue
        record["found"] = True
        record["line_span"] = list(span)
        streamed: list[str] = []
        for number in range(span[0] - 1, span[1]):
            for name in _STREAM_RE.findall(lines[number]):
                if name not in streamed:
                    streamed.append(name)
        record["streams"] = streamed
        record["violations"] = [name for name in probe["must_not_stream"]
                                if name in streamed]
        record["passed"] = not record["violations"]
        results.append(record)
    return results


# --------------------------------------------------------------------------- #
# image layer -- surface, search, references
# --------------------------------------------------------------------------- #

def describe_surface(headers) -> dict:
    """Every section, its on-disk byte range, and whether it is executable.

    A null result has to be a statement about a NAMED surface, so the surface is
    reported range by range and the tiling is stated rather than assumed.
    """
    sections = []
    searched = 0
    executable = 0
    for section in headers.sections:
        start = section["raw_pointer"]
        length = min(section["rsize"], max(0, headers.image.size - start))
        is_exec = bool(section["characteristics"] & IMAGE_CHARACTERISTICS_EXECUTE)
        sections.append({
            "name": section["name"],
            "rva": section["rva"],
            "file_offset": start,
            "raw_bytes_on_disk": length,
            "virtual_size": section["vsize"],
            "executable": is_exec,
        })
        searched += length
        if is_exec:
            executable += length
    return {
        "image_base": headers.image_base,
        "file_size": headers.image.size,
        "sections": sections,
        "bytes_with_on_disk_data": searched,
        "bytes_in_executable_sections": executable,
        "literal_search_surface": "the whole file, byte 0 to file_size",
        "reference_search_surface": ("only sections whose characteristics carry "
                                     "IMAGE_SCN_MEM_EXECUTE (0x20000000)"),
    }


def offset_to_rva(headers, offset: int) -> int | None:
    """File offset -> RVA, using the SAME section table pe_info parsed.

    Answers None rather than a plausible-looking wrong number when the offset
    falls outside every section's on-disk data -- headers, padding, overlay.
    """
    for section in headers.sections:
        start = section["raw_pointer"]
        length = section["rsize"]
        if length and start <= offset < start + length:
            return section["rva"] + (offset - start)
    return None


def section_at_offset(headers, offset: int) -> str | None:
    for section in headers.sections:
        start = section["raw_pointer"]
        length = section["rsize"]
        if length and start <= offset < start + length:
            return section["name"]
    return None


def find_all(blob: bytes, pattern: bytes, limit: int) -> list[int]:
    hits = []
    index = blob.find(pattern)
    while index != -1 and len(hits) < limit:
        hits.append(index)
        index = blob.find(pattern, index + 1)
    return hits


def scan_riprel_references(blob: bytes, headers, targets: dict[int, str],
                           surface: dict) -> dict[str, list[int]]:
    """Count x86-64 RIP-relative LEA references to each target RVA.

    A string literal on x64 is not addressed by an absolute constant: the
    compiler emits ``lea reg, [rip + disp32]``. So the reference pass decodes
    that one form -- any REX prefix with W set (0x48..0x4f; in RIP-relative
    addressing there is no base or index register, so REX.X and REX.B are
    ignored by the CPU and the assembler may emit either value), opcode 0x8d,
    ModRM with mod == 00 and rm == 101 -- and computes
    ``rip_after_instruction + disp32``. Seven bytes, no ambiguity, no
    disassembler.

    This deliberately UNDERCOUNTS. It does not decode a 32-bit LEA without REX,
    a MOV of an absolute address, a pointer sitting in a data table, or a
    reference formed by arithmetic. An undercount is the safe direction: it can
    only make the evidence look weaker than it is, never stronger. What it must
    never do is count a reference that is not there, and the arithmetic is exact
    so a hit is a hit.

    The scan runs over executable sections only, in windows with a 6-byte
    overlap so an instruction straddling a window boundary is still seen.
    """
    found: dict[str, list[int]] = {name: [] for name in targets.values()}
    if not targets:
        return found
    wanted = set(targets)
    for section in surface["sections"]:
        if not section["executable"]:
            continue
        base_offset = section["file_offset"]
        base_rva = section["rva"]
        length = section["raw_bytes_on_disk"]
        position = 0
        while position < length:
            window = min(SCAN_CHUNK, length - position)
            # +6 so a 7-byte instruction starting in this window is complete.
            chunk = blob[base_offset + position:base_offset + position + window + 6]
            local = 0
            while True:
                local = chunk.find(b"\x8d", local)
                if local == -1 or local - 1 >= window:
                    break
                rex = chunk[local - 1] if local >= 1 else 0
                if not 0x48 <= rex <= 0x4F:
                    local += 1
                    continue
                if local + 5 >= len(chunk):
                    break
                modrm = chunk[local + 1]
                if (modrm & 0xC7) != 0x05:
                    local += 1
                    continue
                disp = int.from_bytes(chunk[local + 2:local + 6], "little",
                                      signed=True)
                instr_rva = base_rva + position + (local - 1)
                target = instr_rva + 7 + disp
                if target in wanted:
                    name = targets[target]
                    if len(found[name]) < MAX_REFS_PER_NEEDLE:
                        found[name].append(base_offset + position + (local - 1))
                local += 1
            position += window
    return found


def find_absolute_pointers(blob: bytes, headers, rva: int,
                           limit: int = 16) -> list[dict]:
    """Every 8-byte little-endian occurrence of this RVA's virtual address.

    Why this form has to be decoded as well as the LEA form: UE 5.4's logging
    macros do not always hand the format string to the call site directly. The
    modern path emits a STATIC RECORD in ``.rdata`` whose first field is a
    pointer to the format string, and the call site addresses the record. So a
    literal with zero LEA references can still be perfectly live -- reached
    through one indirection -- and a probe that only decoded the LEA form would
    report a false absence and call it evidence.

    Measured on this installation: the two UE_LOG(Fatal) needles are addressed
    by a LEA in one image of the pair and by a static record in the other. Two
    forms, same statement. Both are counted, and they are counted SEPARATELY so
    a reader can see which one was found.
    """
    hits = []
    pattern = (headers.image_base + rva).to_bytes(8, "little")
    index = blob.find(pattern)
    while index != -1 and len(hits) < limit:
        # A pointer has to be 8-byte aligned to be a pointer.
        if index % 8 == 0:
            pointer_rva = offset_to_rva(headers, index)
            hits.append({
                "file_offset": index,
                "rva": pointer_rva,
                "section": section_at_offset(headers, index),
            })
        index = blob.find(pattern, index + 1)
    return hits


def probe_image(path: str, needles: list[dict], warnings: list[str]) -> dict:
    """Locate every harvested needle in the image and count its references."""
    with pe_info.Image.open(path) as image:
        headers = pe_info.PEHeaders(image)
        surface = describe_surface(headers)
        # Read the file whole with our OWN handle rather than through
        # Image.read_at: that method's length cap exists to distrust a length
        # field taken from the file, and this length is not one -- it is the size
        # the filesystem reports. The cap is right to be there and wrong to
        # apply here.
        with open(path, "rb") as raw_handle:
            blob = raw_handle.read()
        if len(blob) != image.size:
            warnings.append(
                "the image is %d bytes by the section-table pass and %d by the "
                "whole-file read -- the file changed under us" % (image.size,
                                                                 len(blob)))

    hits: list[dict] = []
    ref_targets: dict[int, str] = {}
    for needle in needles:
        record = {
            "id": needle["id"],
            "role": needle["role"],
            "guard": needle["guard"],
            "citation": needle.get("citation"),
            "encloses": needle["encloses"],
            "why": needle["why"],
            "searched": False,
            "encoding": None,
            "occurrences": 0,
            "offsets": [],
            "byte_length": None,
            "rva": None,
            "va": None,
            "section": None,
            "references": 0,
            "reference_offsets": [],
            "static_record_pointers": [],
            "references_to_static_record": 0,
            "reference_form": None,
            "reachable_from_code": False,
        }
        if not needle["found_in_source"]:
            hits.append(record)
            continue
        record["searched"] = True
        text = needle["text"]
        # TEXT() on Windows is wchar_t, so UTF-16LE is the expected form. UTF-8
        # is tried as well: a null result must not be an artefact of guessing
        # the encoding wrong.
        for encoding, raw in (("utf-16le", text.encode("utf-16-le")),
                              ("utf-8", text.encode("utf-8"))):
            offsets = find_all(blob, raw, MAX_HITS_PER_NEEDLE)
            if offsets:
                record["encoding"] = encoding
                record["occurrences"] = len(offsets)
                record["offsets"] = offsets
                record["byte_length"] = len(raw)
                break
        if record["occurrences"] == 1:
            offset = record["offsets"][0]
            record["rva"] = offset_to_rva(headers, offset)
            record["section"] = section_at_offset(headers, offset)
            if record["rva"] is not None:
                record["va"] = headers.image_base + record["rva"]
                ref_targets[record["rva"]] = needle["id"]
                record["static_record_pointers"] = find_absolute_pointers(
                    blob, headers, record["rva"])
            else:
                warnings.append(
                    "needle %s sits at offset %d, which maps to no section's "
                    "on-disk data -- no RVA, so no reference pass"
                    % (needle["id"], offset))
        elif record["occurrences"] > 1:
            warnings.append("needle %s occurs %d times -- attribution to one "
                            "source line is ambiguous"
                            % (needle["id"], record["occurrences"]))
        hits.append(record)

    # One LEA pass over the executable sections, for BOTH kinds of target: the
    # literals themselves and the static log records that point at them. The
    # pass is the expensive part of this tool, so it runs once.
    by_id = {record["id"]: record for record in hits}
    record_targets: dict[int, str] = {}
    for record in hits:
        for pointer in record["static_record_pointers"]:
            if pointer["rva"] is not None:
                record_targets[pointer["rva"]] = record["id"]
    combined = dict(ref_targets)
    combined.update({rva: "record:" + name for rva, name in record_targets.items()})
    references = scan_riprel_references(blob, headers, combined, surface)
    for name, offsets in references.items():
        if name.startswith("record:"):
            target_record = by_id[name[len("record:"):]]
            target_record["references_to_static_record"] += len(offsets)
        else:
            by_id[name]["references"] = len(offsets)
            by_id[name]["reference_offsets"] = offsets[:16]

    for record in hits:
        direct = record["references"] > 0
        indirect = (bool(record["static_record_pointers"])
                    and record["references_to_static_record"] > 0)
        record["reachable_from_code"] = direct or indirect
        record["reference_form"] = (
            "riprel-lea+static-record" if direct and indirect
            else "riprel-lea" if direct
            else "static-record" if indirect
            else "static-record-unreferenced" if record["static_record_pointers"]
            else None)

    # The control: a needle that must NOT be found. Built by mutating a real
    # one so it cannot accidentally be a real string.
    control = None
    seed = by_id.get(CONTROL_ABSENT_ID)
    source_text = next((n["text"] for n in needles
                        if n["id"] == CONTROL_ABSENT_ID and n["found_in_source"]),
                       None)
    if source_text:
        mutated = source_text[:-1] + "§§ABSENT§§"
        found = find_all(blob, mutated.encode("utf-16-le"), 2)
        control = {
            "kind": "negative control",
            "derived_from": CONTROL_ABSENT_ID,
            "occurrences": len(found),
            "passed": len(found) == 0,
            "note": ("a real needle with its tail replaced. A tool that cannot "
                     "return zero cannot report an absence."),
        }
    if seed is None:
        warnings.append("the negative control could not be built: needle %s was "
                        "not harvested" % CONTROL_ABSENT_ID)

    return {
        "surface": surface,
        "hits": hits,
        "control": control,
        "blob_len": len(blob),
    }


# --------------------------------------------------------------------------- #
# class-P literal layer
# --------------------------------------------------------------------------- #

def literal_read(target: str, offset: int, raw: bytes, join_key: str) -> dict:
    """One class-P record: a literal read at a determinate place, and nothing more.

    ``claim`` states the offset AND the length -- mandatory for the
    binary-analysis oracle to be class P at all (plan.md 10.3 v2.4) -- and names
    nothing about what the bytes are: no module, no function, no encoding, no
    field. ``join_key`` is the join into the class-I layer and sits OUTSIDE the
    graded object, because naming a structure inside the graded note is exactly
    what would disqualify class P.

    Shape follows tools/content/pak_index.py deliberately: one consumer reads
    both documents, and a second shape for the same idea would be a second thing
    to keep correct.
    """
    length = len(raw)
    plural = "byte" if length == 1 else "bytes"
    claim = "%d %s at offset %d of %s are %s" % (
        length, plural, offset, target, hex_bytes(raw))
    return {
        "join_key": join_key,
        "interpretation_lives_in": (
            "the matching entry of findings[] in the same document -- plan.md "
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
                # The per-source "oracle" key of kb-record.schema.json is
                # deliberately NOT set: it is legal in the schema but makes
                # tools/kb/validate.py read every source object as a whole
                # record. The oracle is stated in the note instead.
                "method": "CK-04 image needle read",
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


def confirm_literal_reads(path: str, literals: list[dict], target: str,
                          warnings: list[str]) -> bool:
    """Perform every literal read a SECOND time and stamp the result on each record.

    plan.md 10.3 class-P criterion 2 executed rather than asserted. A fresh
    handle, an independent seek. On disagreement nothing is adjusted: the failure
    is recorded and the reading stands as unreproduced.
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


def build_literal_reads(path: str, target: str, hits: list[dict],
                        warnings: list[str]) -> list[dict]:
    literals = []
    with open(path, "rb", buffering=0) as handle:
        for record in hits:
            if record["occurrences"] != 1 or record["byte_length"] is None:
                continue
            offset = record["offsets"][0]
            handle.seek(offset)
            raw = handle.read(record["byte_length"])
            literals.append(literal_read(target, offset, raw, record["id"]))
    confirm_literal_reads(path, literals, target, warnings)
    return literals


# --------------------------------------------------------------------------- #
# class-I layer and probes
# --------------------------------------------------------------------------- #

def decoded_annotation(build_version: dict | None) -> dict:
    """The class-I annotation. Two independent methods, named.

    This is the REDUCED annotation shape of kb-record.schema.json#/$defs/
    annotation, which is additionalProperties:false over seven keys -- so the two
    methods are named inside ``sources`` rather than given a key of their own.
    """
    changelist = (build_version or {}).get("Changelist")
    return {
        "evidence_level": "INFERRED",
        "claim_class": "I",
        "confidence": CONFIDENCE_DECODED,
        "oracle": ["binary-analysis", "external-doc"],
        "sources": [
            {
                "method": "CK-04 first-party source read at the build's changelist",
                "artifact": None,
                "locator": "UStruct::Link / FProperty::SetupOffset / FProperty::Serialize",
                "note": ("oracle external-doc: every needle's text, file and line "
                         "were read out of the UE source tree at run time"
                         + (" (Changelist %s)" % changelist if changelist else "")
                         + ". This proves what the ENGINE does, never what this "
                         "build does."),
            },
            {
                "method": "CK-04 image needle location and RIP-relative reference pass",
                "artifact": None,
                "locator": "probe.hits[].offsets / probe.hits[].reference_offsets",
                "independent_of": [
                    "CK-04 first-party source read at the build's changelist"],
                "note": ("oracle binary-analysis: a different data source -- the "
                         "shipped PE, not the source tree. Answers whether the "
                         "code path is IN this image, which the tree cannot."),
            },
        ],
        "note": ("Two independent methods over two different objects. Neither "
                 "alone supports a claim about this build: the tree says what "
                 "UE 5.4.4 does, the image says what was linked in."),
    }


def build_refutation_probes(hits: list[dict], control: dict | None,
                            serializers: list[dict]) -> list[dict]:
    """Probes that can BREAK the conclusion, each with a boolean outcome."""
    probes = []
    by_id = {record["id"]: record for record in hits}
    required = [record for record in hits if record["role"] == "required"]

    # 1. every required needle found exactly once.
    missing = [r["id"] for r in required if r["occurrences"] == 0]
    ambiguous = [r["id"] for r in required if r["occurrences"] > 1]
    probes.append({
        "id": "required_needles_unique",
        "question": ("is every needle the verdict depends on present exactly "
                     "once on the searched surface?"),
        "breaks_conclusion_if": ("a required needle is absent -- the code path "
                                 "was not linked into this image; or occurs more "
                                 "than once -- attribution is ambiguous"),
        "missing": missing,
        "ambiguous": ambiguous,
        "passed": not missing and not ambiguous,
    })

    # 2. every required needle actually reachable from executable code, by
    #    either of the two forms the engine's logging macros produce.
    unreferenced = [r["id"] for r in required
                    if r["occurrences"] == 1 and not r["reachable_from_code"]]
    probes.append({
        "id": "required_needles_referenced",
        "question": ("does code in an executable section reach each required "
                     "needle -- directly by a RIP-relative LEA, or through a "
                     "static log record in .rdata that points at it?"),
        "breaks_conclusion_if": ("a needle is reached by neither form -- the "
                                 "literal survived as dead data and no code "
                                 "formats it, so its presence says nothing about "
                                 "the function"),
        "unreferenced": unreferenced,
        "forms": {r["id"]: r["reference_form"] for r in required},
        "passed": not unreferenced,
        "note": ("the LEA decoder handles one instruction form and the pointer "
                 "decoder one data form, so the count UNDERCOUNTS; only zero "
                 "carries weight here, and an undercount can make the evidence "
                 "look weaker than it is, never stronger"),
    })

    # 3. the compile-time gating model. This is the probe that can invalidate
    #    every ABSENCE in the run.
    fatal_present = [r["id"] for r in hits
                     if r["guard"] == "UE_LOG_FATAL" and r["occurrences"] >= 1]
    check_present = [r["id"] for r in hits
                     if r["guard"] in ("CHECKF", "ENSUREMSGF")
                     and r["occurrences"] >= 1]
    check_searched = [r["id"] for r in hits
                      if r["guard"] in ("CHECKF", "ENSUREMSGF") and r["searched"]]
    inverted = bool(check_present) and not fatal_present
    probes.append({
        "id": "compile_gating_consistent",
        "question": ("is the observed presence pattern consistent with the "
                     "model 'Fatal log text always survives, check/ensure text "
                     "does not survive a Shipping link'?"),
        "breaks_conclusion_if": ("check/ensure text is present while no Fatal "
                                 "text is -- the model of compile-time gating is "
                                 "inverted, and then every absence in this "
                                 "document is uninterpretable"),
        "fatal_text_present": fatal_present,
        "check_text_present": check_present,
        "check_text_searched": check_searched,
        "configuration_reading": (
            "checks retained" if check_present and fatal_present
            else "checks compiled out" if fatal_present
            else "no Fatal text found at all"),
        "passed": not inverted,
    })

    # 4. the tool can return zero.
    probes.append({
        "id": "negative_control",
        "question": "does a deliberately mutated needle return zero occurrences?",
        "breaks_conclusion_if": ("the mutated string is 'found' -- the matcher "
                                 "reports hits that are not there and every "
                                 "positive in this document is worthless"),
        "detail": control,
        "passed": bool(control and control["passed"]),
    })

    # 5. the two required needles are in different translation units, so a
    #    single stray blob of unreferenced .rdata cannot explain both.
    sections = sorted({r["section"] for r in required if r["section"]})
    probes.append({
        "id": "required_needles_distinct_origin",
        "question": ("do the required needles come from different source files, "
                     "so that one accidental data blob cannot explain both?"),
        "breaks_conclusion_if": ("both needles trace to the same line or file, "
                                 "in which case they are one observation wearing "
                                 "two names"),
        "citations": [r["citation"] for r in required],
        "sections_found_in": sections,
        "passed": len({(r["citation"] or "").split(":")[0]
                       for r in required}) == len(required),
    })

    # 6. the source-side refutation: does any serializer stream the offset?
    checked = [probe for probe in serializers if probe["found"]]
    violated = [probe["id"] for probe in checked if probe["violations"]]
    probes.append({
        "id": "no_serializer_streams_the_offset",
        "question": ("do FProperty::Serialize / UStruct::Serialize / "
                     "UClass::Serialize stream Offset_Internal, PropertiesSize "
                     "or MinAlignment?"),
        "breaks_conclusion_if": ("any of them does -- then an offset or a "
                                 "cook-time parent size IS written into the "
                                 "package and could be read back, and the whole "
                                 "recompute reading is wrong"),
        "serializers_checked": [probe["id"] for probe in checked],
        "serializers_not_found": [probe["id"] for probe in serializers
                                  if not probe["found"]],
        "violations": violated,
        "passed": bool(checked) and not violated,
        "note": ("the member lists are EXTRACTED from the tree, not asserted "
                 "here; see source_probes[].streams for what each one does "
                 "stream"),
    })
    return probes


def build_findings(hits: list[dict], build_version: dict | None) -> list[dict]:
    """The class-I layer: what each located byte range IS, and how strongly."""
    annotation = decoded_annotation(build_version)
    findings = []
    for record in hits:
        if not record["searched"]:
            continue
        if record["occurrences"] == 1:
            claim = ("the %d bytes at offset %d are the message literal of %s, "
                     "which sits in %s; it is reached from executable code by "
                     "the %s form (%d direct RIP-relative reference(s), %d "
                     "static log record(s) pointing at it, %d reference(s) to "
                     "those records)"
                     % (record["byte_length"], record["offsets"][0],
                        record["citation"], record["encloses"],
                        record["reference_form"] or "no decoded",
                        record["references"],
                        len(record["static_record_pointers"]),
                        record["references_to_static_record"]))
            state = "PRESENT" if record["reachable_from_code"] else "PRESENT_UNREFERENCED"
        elif record["occurrences"] == 0:
            claim = ("no byte sequence on the searched surface matches the "
                     "message literal of %s; for a %s-guarded message that is "
                     "the expected reading of an image built with that macro "
                     "compiled out, and it says nothing about whether %s is "
                     "present" % (record["citation"], record["guard"],
                                  record["encloses"]))
            state = "NOT_FOUND_WITHIN_TESTED_SURFACE"
        else:
            claim = ("the message literal of %s occurs %d times; attribution of "
                     "any one occurrence to that line is ambiguous"
                     % (record["citation"], record["occurrences"]))
            state = "AMBIGUOUS"
        findings.append({
            "id": record["id"],
            "role": record["role"],
            "state": state,
            "claim": claim,
            "why_this_needle": record["why"],
            "evidence": dict(annotation),
        })
    return findings


def decide_verdict(probes: list[dict], hits: list[dict]) -> tuple[str, str]:
    by_id = {probe["id"]: probe for probe in probes}
    if not by_id["negative_control"]["passed"]:
        return ("INCONCLUSIVE",
                "the matcher failed its own negative control; no positive in "
                "this run can be believed")
    if not by_id["compile_gating_consistent"]["passed"]:
        return ("INCONCLUSIVE",
                "the presence pattern contradicts the compile-gating model, so "
                "the absences cannot be read")
    if not by_id["required_needles_unique"]["passed"]:
        return ("PATH_NOT_FOUND_WITHIN_TESTED_SURFACE",
                "a needle the verdict depends on was absent or ambiguous on the "
                "searched surface")
    if not by_id["required_needles_referenced"]["passed"]:
        return ("PATH_PRESENT_UNREFERENCED",
                "every required needle is present, but at least one has no "
                "reference from an executable section")
    return ("PATH_PRESENT_AND_REFERENCED",
            "every required needle is present exactly once and is addressed by "
            "code in an executable section")


# --------------------------------------------------------------------------- #
# document
# --------------------------------------------------------------------------- #

def build_document(image_path: str, ue_root: str | None, install_dir: str | None,
                   warnings: list[str]) -> dict:
    digest, size = sha256_file(image_path)
    target = os.path.basename(image_path)
    if install_dir:
        try:
            relative = os.path.relpath(image_path, install_dir)
            if not relative.startswith(".."):
                target = relative.replace(os.sep, "/")
        except ValueError:
            pass

    build_version = None
    needles: list[dict] = []
    if ue_root:
        build_version = read_build_version(ue_root, warnings)
        needles = harvest_needles(ue_root, warnings)
    else:
        warnings.append(
            "no UE source tree given (--ue-root or %s): the needles cannot be "
            "read out of the tree, so nothing was searched for. This is a "
            "refusal, not a null result." % UE_TREE_DEFAULT_ENV)

    serializers = run_serializer_probes(ue_root, warnings) if ue_root else []

    probe = None
    literals: list[dict] = []
    findings: list[dict] = []
    probes: list[dict] = []
    verdict, verdict_why = ("INCONCLUSIVE", "no needle was harvested")
    if any(needle["found_in_source"] for needle in needles):
        probe = probe_image(image_path, needles, warnings)
        literals = build_literal_reads(image_path, target, probe["hits"], warnings)
        probes = build_refutation_probes(probe["hits"], probe["control"],
                                        serializers)
        findings = build_findings(probe["hits"], build_version)
        verdict, verdict_why = decide_verdict(probes, probe["hits"])

    return {
        "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
        "generated_at": now_iso_utc(),
        "question": "CK-04 -- plan.md 14A.4",
        "question_text": ("does the shipped image contain the UStruct::Link / "
                          "FProperty::SetupOffset code path that the first-party "
                          "source says recomputes property offsets at load time?"),
        "what_this_does_not_answer": (
            "whether offsets are recomputed. That is answered by reading the "
            "source, is graded in research/packages/sp1-static-proxy.md, and is "
            "NOT strengthened by this document. This document answers only "
            "whether the code path is in this image."),
        "target": {
            "path_in_install": target,
            "sha256": digest,
            "size": size,
            "read_only": True,
        },
        "ue_source_tree": {
            "given": bool(ue_root),
            "build_version": build_version,
            "note": ("oracle external-doc per plan.md 10.5: this tree proves what "
                     "UE 5.4.4 does at this changelist, and nothing about this "
                     "build."),
        },
        "needles": needles,
        "source_probes": serializers,
        "surface": probe["surface"] if probe else None,
        "hits": probe["hits"] if probe else [],
        "negative_control": probe["control"] if probe else None,
        "probes": probes,
        "verdict": verdict,
        "verdict_why": verdict_why,
        "literal_reads": literals,
        "findings": findings,
        "warnings": warnings,
    }


def render_summary(document: dict) -> str:
    lines = []
    target = document["target"]
    lines.append("%s %s" % (GENERATOR_NAME, GENERATOR_VERSION))
    lines.append("target      %s  (%d bytes)" % (target["path_in_install"],
                                                 target["size"]))
    lines.append("sha256      %s" % target["sha256"])
    tree = document["ue_source_tree"]
    version = tree.get("build_version") or {}
    if version:
        lines.append("ue tree     %s.%s.%s CL %s  %s"
                     % (version.get("MajorVersion"), version.get("MinorVersion"),
                        version.get("PatchVersion"), version.get("Changelist"),
                        version.get("BranchName")))
    surface = document.get("surface")
    if surface:
        lines.append("surface     %d bytes of on-disk section data, %d of it "
                     "executable, in %d sections"
                     % (surface["bytes_with_on_disk_data"],
                        surface["bytes_in_executable_sections"],
                        len(surface["sections"])))
    lines.append("")
    lines.append("%-24s %-13s %-6s %-6s %-5s %-5s %-6s %-26s"
                 % ("needle", "guard", "role", "occurs", "lea", "recs",
                    "rec>", "form"))
    for record in document["hits"]:
        lines.append("%-24s %-13s %-6s %-6s %-5s %-5s %-6s %-26s"
                     % (record["id"], record["guard"], record["role"][:6],
                        record["occurrences"] if record["searched"] else "-",
                        record["references"],
                        len(record["static_record_pointers"]),
                        record["references_to_static_record"],
                        record["reference_form"] or "-"))
    lines.append("")
    for record in document["hits"]:
        lines.append("  %-24s %s" % (record["id"], record["citation"] or "-"))
    lines.append("")
    for probe in document.get("source_probes") or []:
        lines.append("serializer %-22s lines %-13s streams %d member(s)%s"
                     % (probe["id"],
                        "%d-%d" % tuple(probe["line_span"]) if probe["line_span"]
                        else "-",
                        len(probe["streams"]),
                        "" if probe["passed"]
                        else "  <-- STREAMS %s" % ", ".join(probe["violations"])))
    lines.append("")
    for probe in document["probes"]:
        lines.append("probe %-34s %s" % (probe["id"],
                                         "PASS" if probe["passed"] else "FAIL"))
    lines.append("")
    lines.append("VERDICT     %s" % document["verdict"])
    lines.append("            %s" % document["verdict_why"])
    if document["warnings"]:
        lines.append("")
        lines.append("warnings (%d):" % len(document["warnings"]))
        for warning in document["warnings"]:
            lines.append("  - %s" % warning)
    return "\n".join(lines)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description=("CK-04: does a shipped PE contain the UStruct::Link / "
                     "FProperty::SetupOffset property-offset code path?"))
    parser.add_argument("path", help="the PE image to read (read-only)")
    parser.add_argument("--ue-root", help="root of the UE source tree; every "
                        "needle is read out of it at run time. Falls back to $%s"
                        % UE_TREE_DEFAULT_ENV)
    parser.add_argument("--install-dir", help="installation root, so the read "
                        "locus is install-relative rather than a bare basename")
    parser.add_argument("--json", action="store_true", help="print the whole document")
    parser.add_argument("--out", help="write the JSON document here")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    warnings: list[str] = []
    ue_root = locate_ue_tree(args.ue_root, warnings)
    try:
        document = build_document(args.path, ue_root, args.install_dir, warnings)
    except (OSError, PEFormatError) as error:
        sys.stderr.write("%s: %s\n" % (GENERATOR_NAME, error))
        return 2

    if args.out:
        # The guard needs the installation the INPUT belongs to, not the output
        # path's own tree: a caller that does not know which tree it is reading
        # is a bug, not a licence to skip the check (pathguard docstring).
        install_root = args.install_dir or pe_info.detect_install_root(args.path)
        try:
            resolved_out = pathguard.check_output_path(
                args.out, install_root, what="--out")
        except (pathguard.OutputPathRefused, ValueError) as error:
            sys.stderr.write("%s: refusing to write: %s\n" % (GENERATOR_NAME, error))
            return 2
        directory = os.path.dirname(os.path.abspath(resolved_out))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(resolved_out, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, indent=2, ensure_ascii=False,
                      sort_keys=True)
            handle.write("\n")

    if args.json:
        sys.stdout.write(json.dumps(document, indent=2, ensure_ascii=False,
                                    sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_summary(document) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
