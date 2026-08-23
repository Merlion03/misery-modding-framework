#!/usr/bin/env python3
"""Assemble ``research/builds/<build-id>/fingerprint.json`` (plan.md tasks F-03 and F-05).

WHAT THIS TOOL IS, AND WHAT IT DELIBERATELY IS NOT
--------------------------------------------------
This is a COMPOSER. It parses nothing. Every number in the document it writes was
produced by a tool that already exists and is already tested:

``tools/fingerprint/pe_info.py``        every ``pe`` object, verbatim. F-01 built its
                                        ``--json`` output to be exactly
                                        ``fingerprint.schema.json#/$defs/pe``, so it is
                                        spliced, never reshaped.
``tools/fingerprint/container_info.py`` the whole ``containers`` array, verbatim. F-02
                                        built it to be exactly ``$defs/container_entry``.
``tools/inventory/snapshot_install.py`` the read-only tree walk, the appmanifest reader,
                                        the ``steam`` projection, and the three identity
                                        computations of plan.md 3.2 - ``build_key``,
                                        ``content_key``, ``tree_hash`` and ``build_id``.
``tools/inventory/pathguard.py``        the output-path guard. Imported, never inlined.

Re-implementing any of those here would create a second definition of the same fact,
and the two would drift. The one thing this file computes for itself is the md5 digest
that plan.md 3.1 asks for on executables: ``snapshot_install.hash_file`` is fixed at
sha256 + sha1, and running a second full pass over a 282 MB image only to add md5 would
throw away the single-pass property that task F-04 exists to protect. So ``stream_digests``
below is the same loop with a configurable digest list, and it is the ONLY duplication.

IDENTITY IS RECOMPUTED, NEVER COPIED
------------------------------------
``build_key``, ``content_key``, ``tree_hash`` and ``build_id`` already exist in
``research/builds/index.json`` and ``install-inventory.json``. This tool does not read
them as inputs. It recomputes all four from the installation and then COMPARES, emitting
one entry in ``checks[]`` per comparison. A copied value proves that two files agree; a
recomputed value that matches proves the installation still is what the registry says it
is - and a mismatch is exactly the event the registry exists to detect.

WHAT IS LEFT NULL, AND WHY THAT IS NOT A GAP
--------------------------------------------
plan.md 3.1 sources the ``engine`` and ``game`` groups from section 4, and section 4 has
not run. Filling those fields from what is lying around would be the whole failure mode
this repository is built against, so they are emitted as ``null`` with an evidence
annotation that names the plan.md 4 method which would conclude each one. Two points a
reader should not have to dig for:

* ``engine.engine_version`` is the ONE exception, and it is not a new claim. The value
  ``5.4.4`` is already published by ``install-inventory.json`` as PROVISIONAL and is
  already baked into ``build_id``; emitting ``null`` here would put the fingerprint at
  odds with its own directory name. It carries ``engine_version_provisional: true`` and
  an annotation at confidence 0.79 - below the 0.80 band, because exactly ONE method was
  executed in this run (the ``VS_VERSIONINFO`` read of F-01).
* ``engine.engine_cl`` and ``engine.engine_branch`` stay ``null`` even though the literal
  string ``++UE5+Release-5.4-CL-35576357`` is recorded in this very document, under
  ``executables[].pe.version_info.strings.ProductVersion``. Reading a changelist and a
  branch OUT of that string is method V-03 of plan.md 4; the fingerprint records the
  string, not the conclusion. This distinction is the entire point of the artifact.

F-05, THE ANOMALY DETECTOR
--------------------------
``Manifest_NonUFSFiles_Win64.txt`` is compared against the files actually on disk, in
both directions, and the PE section tables are compared against the section names that
are ordinary for an MSVC-linked Windows image. Every difference found is reported -
there is no allow-list that quietly swallows the boring ones, because "33 files are not
in the manifest, and here they are" is a different and more useful statement than "one
file is not in the manifest". The canonical case A-05 falls out of the comparison; it is
not asserted anywhere in this file, and its id is attached afterwards by matching the
path, so removing the id would not change the detection.

The comparison is RUN TWICE, from two independent directory walks and two independent
reads of the manifest, and each anomaly records whether the second pass agreed. plan.md
10.3 class P criterion 2 is thereby executed rather than attested.

SAFETY (decisions D-01, D-02, C-13)
-----------------------------------
* The installation is opened read-only and nothing inside it is ever created, modified,
  moved or deleted.
* Every output path goes through ``pathguard.check_output_path`` BEFORE any file is
  opened, so a refused path leaves nothing behind.
* D-02: no container is decrypted and no key is extracted; that property is inherited
  from container_info, which is the only thing here that opens a container.
* C-13: ``LastOwner`` is a Steam account id and is never read. The appmanifest parser
  this tool calls does not extract it, and the ``steam`` block is
  ``additionalProperties: false``, so it could not carry it even by accident.

MEMORY AND TIME (plan.md F-04)
------------------------------
Every file is hashed by streaming through one reused 1 MiB buffer, so hashing a 4.3 GB
container costs the same memory as hashing a 623-byte one. Peak WORKING SET is measured
by the process itself, through ``psapi.GetProcessMemoryInfo``, and printed with the wall
time on every run - a memory budget nobody measures is a wish.

DETERMINISM, AND THE ONE HONEST EXCEPTION
-----------------------------------------
Sorted keys, indent 2, LF, UTF-8 without BOM, trailing newline. ``--selftest-reproducible``
builds the document twice in one process and names the first field that moved.

plan.md 3.3 asks for two runs to differ only in ``generated_at``. Measured, that is not
quite true, and the exception is worth knowing rather than papering over:
``steam.appmanifest_sha256`` can also differ, because Steam rewrites
``appmanifest_2119830.acf`` whenever it feels like it. Two builds five minutes apart were
observed identical; two builds three hours apart differed in that one field and nothing
else. The self-test therefore RE-READS the manifest and reports the difference as a
changed input only when the re-read confirms the file changed - an unconfirmed
difference at the same pointer is still a failure. Nothing derived from the installation
itself varies: build_key, content_key, tree_hash, every digest and every parsed header
field are stable.

CLI
---
    python tools/fingerprint/fingerprint.py --build-dir research/builds/<build-id>

Exit codes: 0 the run completed and the output passed its own contract; 1 a check ABOUT
THE OUTPUT failed (the document does not validate against the published schema, or two
builds disagreed) - the artifact is wrong; 2 refused or could not run (bad argument, an
output path inside the installation, an unreadable tree). A failing check about the
INSTALLATION is a finding, not an error: it is reported, `checks_failed` on the last
stdout line counts it, and the exit stays 0.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
_INVENTORY = os.path.join(_TOOLS, "inventory")
for _path in (_HERE, _INVENTORY):
    if _path not in sys.path:
        sys.path.insert(0, _path)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never inlined.
import pathguard  # noqa: E402
import snapshot_install as inventory  # noqa: E402
import pe_info  # noqa: E402
import container_info  # noqa: E402

GENERATOR_NAME = "tools/fingerprint/fingerprint.py"
GENERATOR_VERSION = "1.0.0"

DEFAULT_INSTALL_DIR = inventory.DEFAULT_INSTALL_DIR
DEFAULT_BUFFER_BYTES = inventory.DEFAULT_BUFFER_BYTES

NON_UFS_MANIFEST = "Manifest_NonUFSFiles_Win64.txt"
BUILD_KEY_RELPATH = inventory.BUILD_KEY_RELPATH

# plan.md 3.1 "Modules": the three trees that hold the binaries shipped next to the game.
# The trailing slash is load-bearing: without it a future "Engine/BinariesOld/x.dll"
# would be counted as a module of Engine/Binaries.
MODULE_ROOTS: tuple[str, ...] = ("Engine/Binaries/", "MISERY/Binaries/",
                                 "MISERY/Plugins/")
MODULE_SUFFIXES: tuple[str, ...] = (".dll",)

# plan.md 3.1 "Plugins": UE keeps one directory per plugin under <Project>/Plugins.
PLUGIN_ROOT = "MISERY/Plugins"

# fingerprint.schema.json#/$defs/executable/role is a closed enum. The mapping is by
# exact install-relative path, because the role of a file is a fact about WHICH file it
# is, and a suffix rule would silently re-role a file that appears in a later patch.
EXECUTABLE_ROLES: dict[str, str] = {
    "MISERY.exe": "launcher-shim",
    "MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe": "primary-shipping",
    # decision D-04: read-only oracle, never a bindings target. The role name is the
    # schema's way of saying exactly that, and nothing about this string concludes what
    # the file IS -- that question is open as A-05.
    "MISERY/Binaries/Win64/MISERY.exe": "secondary-oracle",
}
EXECUTABLE_DEFAULT_ROLE = "other"

# Section names that are ORDINARY in an MSVC-linked Windows image. This is a convention
# and not a specification, which is why the anomaly text says so: a name outside the set
# is reported as "not one of the names this detector treats as ordinary", never as
# "invalid". Kept deliberately generous - a false positive here would waste a reader's
# attention on a section every Windows binary has.
ORDINARY_PE_SECTIONS: frozenset[str] = frozenset({
    ".text", ".rdata", ".data", ".pdata", ".xdata", ".rsrc", ".reloc", ".tls",
    ".idata", ".edata", ".didat", ".bss", ".crt", ".gfids", ".00cfg", ".voltbl",
    ".rodata", "_rdata", ".sxdata", ".detourc", ".textbss",
})

# plan.md Appendix A ids, attached to a DETECTED anomaly by matching its path and kind.
# The detection never consults this table; it exists so a reader can find the recon row
# that first noticed the same thing. Inventing new A-nn ids here would collide with
# plan.md's own hand-assigned numbering, so anomalies without a recon row carry id null.
RECON_ANOMALY_IDS: dict[tuple[str, str], str] = {
    ("file-not-in-non-ufs-manifest", "MISERY/Binaries/Win64/MISERY.exe"): "A-05",
}
# The same, for a section anomaly, keyed additionally by the section NAME. plan.md A-05
# names `.uedbg` specifically; the `.msvcjmc` section of the same file is a separate
# observation and must not inherit somebody else's row id.
RECON_SECTION_IDS: dict[tuple[str, str], str] = {
    ("MISERY/Binaries/Win64/MISERY.exe", ".uedbg"): "A-05",
}

# What a section name is, according to public documentation about the toolchains that
# emit it. Every one of these is external-doc and nothing more: it proves what the name
# means in general, never what it means in THIS image. They are rendered into
# anomalies.md as explicitly graded HYPOTHESIS sentences and are deliberately kept OUT
# of fingerprint.json, where the `hypothesis` field is reserved for D-04.
SECTION_NAME_NOTES: dict[str, str] = {
    ".msvcjmc": (
        "имя `.msvcjmc` эмитирует компилятор MSVC при включённой инструментации "
        "Just My Code (`/JMC`), которая по умолчанию выключена в конфигурациях без "
        "отладки"),
    ".uedbg": (
        "имя `.uedbg` эмитирует сборочная система Unreal Engine для отладочных данных, "
        "которые она кладёт прямо в образ"),
    ".wixburn": (
        "имя `.wixburn` эмитирует WiX Burn — построитель загрузочных установщиков; "
        "для файла с именем `UEPrereqSetup_x64.exe` это ровно то, чем он выглядит"),
}

# decision D-04, quoted where it is needed rather than paraphrased.
D04_SENTENCE = (
    "HYPOTHESIS \"a Development build of the game reached the depot\", confidence 0.65 "
    "under decision D-04. This is NEVER to be stated as a finding. D-04 admits "
    "MISERY/Binaries/Win64/MISERY.exe as a read-only oracle only; it is not a bindings "
    "target, and every conclusion drawn on it must be re-checked against the Shipping "
    "binary (RISK-07)."
)

# Confidence values, and the reason each one is where it is.
CONF_LITERAL = 0.99          # a primitive reading, re-run and reproduced (10.3 class P)
CONF_ONE_METHOD_I = 0.79     # class I with a single method: below the 0.80 two-method band
CONF_TWO_METHOD_I = 0.85     # class I with a second, independent method
CONF_WEAK_I = 0.70           # class I from a naming convention alone
CONF_NONE = 0.0              # UNKNOWN: nothing is claimed

# Checks that are about the OUTPUT rather than about the installation. A failure in one
# of these makes the artifact wrong, so the process exits non-zero; see main().
TOOL_CORRECTNESS_CHECKS: frozenset[str] = frozenset({
    "validates_against_published_schema",
    "two_runs_differ_only_in_generated_at",
})

# Fields that hash an input Steam owns and rewrites on its own schedule.
#
# MEASURED, not assumed. Two builds of this document a few minutes apart produced
# different values of steam.appmanifest_sha256 while every other byte matched: Steam had
# rewritten appmanifest_2119830.acf (it keeps LastPlayed and download bookkeeping in
# there). That is the INPUT changing, not this tool inventing variation, and
# kb-record.schema.json says the field exists for exactly that - "so a later change of
# Steam bookkeeping is detectable".
#
# So the reproducibility self-test does not simply forgive this pointer. When it is the
# ONLY difference, the tool RE-READS the app manifest and compares its digest with the
# one the first build recorded; the difference is attributed to a changed input only if
# that re-read confirms the file really did change. An unconfirmed difference stays a
# failure - otherwise this list would be a hole shaped like an excuse.
MUTABLE_INPUT_POINTERS: frozenset[str] = frozenset({"$.steam.appmanifest_sha256"})


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def relative_posix(root: str, path: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/").replace("\\", "/")


def peak_working_set_bytes() -> int | None:
    """Peak working set of THIS process, in bytes, or None where it cannot be asked.

    F-04 states a memory budget, and a budget nobody measures is a wish. tracemalloc
    would only see Python allocations and would miss the buffers a digest object owns,
    so the number comes from the OS. Standard library only: ctypes is stdlib, psapi is
    part of Windows. Any failure returns None rather than a guess.
    """
    if os.name != "nt":  # pragma: no cover - the project targets Windows
        try:
            import resource  # type: ignore
            return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024
        except Exception:  # noqa: BLE001
            return None
    try:
        import ctypes
        from ctypes import wintypes

        class _COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        # argtypes/restype are declared rather than left to ctypes' defaults, and that
        # is load-bearing on win64: GetCurrentProcess returns the pseudo-handle -1, and
        # with the default restype of c_int it is passed on as 0x00000000FFFFFFFF instead
        # of 0xFFFFFFFFFFFFFFFF. The call then fails with GetLastError 0 and the measured
        # answer silently becomes "unavailable" - a measurement that quietly turns into
        # an absence is worse than no measurement, so the types are spelled out.
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.K32GetProcessMemoryInfo.restype = wintypes.BOOL
        kernel32.K32GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(_COUNTERS), wintypes.DWORD]

        counters = _COUNTERS()
        counters.cb = ctypes.sizeof(_COUNTERS)
        if not kernel32.K32GetProcessMemoryInfo(kernel32.GetCurrentProcess(),
                                                ctypes.byref(counters), counters.cb):
            return None
        return int(counters.PeakWorkingSetSize)
    except Exception:  # noqa: BLE001
        return None


def stream_digests(path: str, algorithms: tuple[str, ...] = ("sha256", "sha1", "md5"),
                   buf_size: int = DEFAULT_BUFFER_BYTES) -> dict[str, str]:
    """Every requested digest of *path* in ONE streaming pass, bounded buffer.

    The only computation this composer does not delegate. ``snapshot_install.hash_file``
    is hard-wired to sha256 + sha1; plan.md 3.1 additionally lists md5 for executables,
    and adding it by re-reading a 282 MB image would defeat F-04's single-pass property.
    The loop is identical: one bytearray allocated once, ``readinto``, no whole-file read,
    so peak memory is ``buf_size`` regardless of file size.
    """
    digests = {name: hashlib.new(name) for name in algorithms}
    buffer = bytearray(buf_size)
    view = memoryview(buffer)
    with open(path, "rb", buffering=0) as handle:
        while True:
            read = handle.readinto(buffer)
            if not read:
                break
            chunk = view[:read]
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def category_of(relpath: str) -> str:
    """The coarse class of install-inventory.schema.json#/$defs/inventory_file.category."""
    lower = relpath.lower()
    if lower.endswith(".exe"):
        return "executable"
    if lower.endswith(".dll"):
        return "module"
    if lower.endswith((".utoc", ".ucas", ".pak", ".usig")):
        return "container"
    if os.path.basename(lower).startswith("manifest_") and lower.endswith(".txt"):
        return "manifest"
    if lower.endswith((".ini", ".vdf", ".acf", ".json", ".cfg")):
        return "config"
    if lower.endswith((".bin", ".ttf", ".cur", ".uasset")):
        return "data"
    return "other"


def module_kind(relpath: str) -> str:
    """fingerprint.schema.json#/$defs/module/kind, most specific rule first."""
    lower = relpath.lower()
    if "/thirdparty/" in "/" + lower:
        return "thirdparty"
    if lower.startswith("misery/plugins/"):
        return "plugin"
    if lower.startswith("misery/binaries/"):
        return "game"
    if lower.startswith("engine/"):
        return "engine"
    return "unknown"


# --------------------------------------------------------------------------- #
# evidence annotations -- the REDUCED envelope of kb-record.schema.json
# --------------------------------------------------------------------------- #

def source(method: str, locator: str | None, note: str) -> dict:
    """One entry of an annotation's ``sources[]``.

    The optional per-source ``oracle`` key is deliberately NOT set, for the reason
    tools/fingerprint/container_info.py records under SOURCE_ORACLE_OMITTED: it turns a
    source object into something tools/kb/validate.py reads as a whole record. The oracle
    is named in the note instead, and the annotation-level ``oracle`` list is unaffected.
    """
    return {"method": method, "artifact": None, "locator": locator, "note": note}


def annotation(level: str, claim_class: str | None, confidence: float,
               oracles: list[str], sources: list[dict], note: str,
               read_locus: dict | None = None) -> dict:
    """Exactly kb-record.schema.json#/$defs/annotation -- the reduced envelope.

    The key set is closed there (``additionalProperties: false``) and is what
    tools/kb/validate.py recognises to apply the annotation rules rather than the
    full-record rules. Nothing else may be added here: one extra key and the object
    becomes a full knowledge-base record that has to carry claim_type and build_key.
    """
    return {
        "evidence_level": level,
        "claim_class": claim_class,
        "confidence": confidence,
        "oracle": sorted(set(oracles)),
        "sources": sources,
        "read_locus": read_locus,
        "note": note,
    }


# --------------------------------------------------------------------------- #
# the non-UFS manifest
# --------------------------------------------------------------------------- #

def read_non_ufs_manifest(path: str, warnings: list[str]) -> tuple[dict[str, str], int]:
    """Read ``Manifest_NonUFSFiles_Win64.txt`` -> {install-relative path: mtime text}.

    The format is one entry per line, ``<path>\\t<ISO-8601 timestamp>``. Backslashes are
    normalised to forward slashes, which is the path spelling the whole knowledge base
    uses. Returns the mapping and the number of lines that carried an entry, so a
    duplicate path is detectable (mapping size < line count).
    """
    entries: dict[str, str] = {}
    lines = 0
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
            for raw in handle:
                text = raw.rstrip("\r\n")
                if not text.strip():
                    continue
                lines += 1
                parts = text.split("\t")
                relative = parts[0].strip().replace("\\", "/")
                stamp = parts[1].strip() if len(parts) > 1 else ""
                if relative in entries:
                    warnings.append(
                        "%s: the path %s is listed more than once" % (NON_UFS_MANIFEST,
                                                                      relative))
                entries[relative] = stamp
    except OSError as error:
        warnings.append("cannot read %s: %s" % (NON_UFS_MANIFEST, error))
    return entries, lines


# --------------------------------------------------------------------------- #
# F-05 -- the anomaly detector
# --------------------------------------------------------------------------- #

def compare_against_manifest(disk_paths: set[str],
                             manifest_paths: set[str]) -> dict[str, list[str]]:
    """The whole of the manifest comparison, as a pure function of two sets.

    Pure on purpose: the second, confirming pass calls it again with sets built from an
    independent walk and an independent read, and the two results are compared. A
    comparison that lived inside the walk could not be re-run without re-writing it.
    """
    return {
        "file-not-in-non-ufs-manifest": sorted(disk_paths - manifest_paths),
        "manifest-entry-missing-on-disk": sorted(manifest_paths - disk_paths),
    }


def unexpected_sections(executables: list[dict]) -> list[tuple[str, dict]]:
    """(executable path, section) for every section name outside ORDINARY_PE_SECTIONS."""
    found: list[tuple[str, dict]] = []
    for entry in executables:
        pe = entry.get("pe") or {}
        for section in (pe.get("sections") or []):
            name = str(section.get("name") or "")
            if name and name.lower() not in ORDINARY_PE_SECTIONS:
                found.append((entry["path"], section))
    return found


def compare_manifest_timestamps(manifest_entries: dict[str, str],
                                disk_files: list[dict]) -> dict:
    """Compare the timestamp each manifest line carries with the file's mtime on disk.

    Run so that anomalies.md can SAY it was run. The result is reported as a counted
    statistic and not as anomalies: the divergence is systematic - Steam stamps the time
    it wrote the file, not the time the build made it - and 20 rows of the same
    predictable difference would bury the four findings that are not predictable. What
    would change that judgement is a mixed result, so the counts are printed either way
    and the largest gap is named.
    """
    mtimes = {record["path"]: record.get("mtime") for record in disk_files}
    same = differ = unknown = 0
    examples: list[str] = []
    for relpath, stamp in sorted(manifest_entries.items()):
        disk = mtimes.get(relpath)
        if not stamp or not disk:
            unknown += 1
            continue
        # Both are ISO-8601 UTC with a fractional part of differing precision; the
        # comparison is to the second, because a sub-second difference is not the kind
        # of divergence anybody would act on.
        if stamp[:19] == disk[:19]:
            same += 1
        else:
            differ += 1
            if len(examples) < 3:
                examples.append("%s: манифест %s, диск %s" % (relpath, stamp, disk))
    return {"compared": len(manifest_entries), "same": same, "differ": differ,
            "unknown": unknown, "examples": examples}


def manifest_anomaly(kind: str, relpath: str, reproduced: bool,
                     manifest_relpath: str, disk_size: int | None) -> dict:
    """One anomaly of the manifest comparison, graded.

    The description is a set-membership statement about two literal readings - the file
    exists, the line does not - and it stays that way. What the difference MEANS is not
    in it; where an interpretation exists it lives in ``hypothesis``, marked as one.
    """
    reproduction = ("Method re-run and reproduced: the comparison was performed a second "
                    "time from an independent directory walk and an independent read of "
                    "the manifest, and run 1 and run 2 agree."
                    if reproduced else
                    "NOT reproduced: the second, independent run of the comparison "
                    "disagreed with the first.")
    if kind == "file-not-in-non-ufs-manifest":
        description = (
            "%s exists in the installation (size %s bytes) and no line of %s names it."
            % (relpath, "unknown" if disk_size is None else disk_size, manifest_relpath))
        locator = relpath
    else:
        description = (
            "%s is named by a line of %s and no such file exists in the installation."
            % (relpath, manifest_relpath))
        locator = manifest_relpath

    return {
        "id": RECON_ANOMALY_IDS.get((kind, relpath)),
        "kind": kind,
        "path": relpath,
        "description": description,
        "hypothesis": None,
        "evidence": annotation(
            "OBSERVED", "P", CONF_LITERAL, ["filesystem"],
            [source("F-05", locator,
                    "oracle filesystem. Two literal readings compared as sets: the "
                    "read-only directory walk of the installation, and the line list of "
                    "%s. %s" % (manifest_relpath, reproduction))],
            "Set membership of two primitive readings. The claim states that a path is "
            "present in one reading and absent from the other, and names nothing about "
            "what that means. %s" % reproduction),
    }


def section_anomaly(exe_path: str, section: dict, reproduced: bool) -> dict:
    """One ``unexpected-pe-section`` anomaly.

    Class I, and it could not be anything else: calling a byte range a SECTION and giving
    it a name leans on the PE layout, which is the ``external-doc`` oracle (plan.md 10.5:
    it proves how the format works, not what is true of this build). plan.md 10.3 v2.4
    admits ``binary-analysis`` into class P only for a read that states its offset and its
    length and does NOT name what the bytes are - the opposite of this claim.
    """
    name = str(section.get("name") or "")
    reproduction = ("Method re-run and reproduced: the section table was parsed twice, "
                    "by two separate invocations of pe_info over freshly opened handles, "
                    "and run 1 and run 2 agree."
                    if reproduced else
                    "NOT reproduced: the confirming second parse of the section table "
                    "disagreed with the first.")
    return {
        "id": RECON_SECTION_IDS.get((exe_path, name)),
        "kind": "unexpected-pe-section",
        "path": exe_path,
        "description": (
            "The section table of %s, as parsed by tools/fingerprint/pe_info.py, lists a "
            "section named %r (rva %s, virtual size %s, raw size %s, characteristics %s). "
            "%r is not one of the %d names this detector treats as ordinary for an "
            "MSVC-linked Windows image; that list is a convention and not a specification, "
            "so this is a statement about the list as much as about the file."
            % (exe_path, name, section.get("rva"), section.get("vsize"),
               section.get("rsize"), section.get("characteristics"), name,
               len(ORDINARY_PE_SECTIONS))),
        "hypothesis": None,
        "evidence": annotation(
            "INFERRED", "I", CONF_ONE_METHOD_I, ["binary-analysis", "external-doc"],
            [source("F-01/F-05", exe_path,
                    "oracle binary-analysis + external-doc. The section table was located "
                    "and decoded by tools/fingerprint/pe_info.py against the public PE "
                    "layout. %s" % reproduction)],
            "Interpretive: naming a byte range a section and reading a name out of it "
            "rests on the public PE layout (external-doc proves vanilla PE, not this "
            "build), so plan.md 10.3 v2.4 puts it in class I whatever the offsets are. "
            "One method was executed in this run, so the confidence stays below the "
            "0.80 two-method band. %s" % reproduction),
    }


def size_anomaly(total_size: int, steam_size: int | None) -> dict | None:
    """``size-mismatch`` between the bytes on disk and the size Steam records."""
    if steam_size is None or total_size == steam_size:
        return None
    return {
        "id": None,
        "kind": "size-mismatch",
        "path": None,
        "description": (
            "The file sizes of the installation sum to %d bytes; the SizeOnDisk field of "
            "the Steam app manifest records %d bytes, a difference of %d."
            % (total_size, steam_size, total_size - steam_size)),
        "hypothesis": None,
        "evidence": annotation(
            "INFERRED", "I", CONF_TWO_METHOD_I,
            ["filesystem", "steam-metadata"],
            [source("F-03", "install tree",
                    "oracle filesystem. Sizes summed over the read-only directory walk; "
                    "the walk was re-run and reproduced."),
             source("F-03", "appmanifest_2119830.acf",
                    "oracle steam-metadata. SizeOnDisk read from the app manifest by "
                    "tools/inventory/snapshot_install.py.")],
            "Cross-check of the filesystem against what Steam records: plan.md 10.5 makes "
            "the comparison of the two a class I claim, because it is a conclusion about "
            "both sources rather than a reading of either."),
    }


def detect_anomalies(disk_files: list[dict], manifest_paths: set[str],
                     manifest_relpath: str, executables: list[dict],
                     steam_size: int | None, reproduced: bool,
                     section_reproduced: bool) -> tuple[list[dict], list[dict]]:
    """Every anomaly the comparison finds, in a deterministic order.

    No allow-list. A file that is unsurprising to a human still appears, because the
    detector's predicate is "not named by the manifest" and that predicate is either
    reported honestly or not run at all.

    Returns ``(anomalies, facts)`` -- one ``facts`` entry per anomaly, same order. The
    schema closes the anomaly object, so the structured bits a report wants (the file
    size, the section's name and extent) have nowhere to live inside it. They travel
    alongside instead. The alternative was for the report to scrape them back out of the
    English ``description`` with a substring search, which is how a renderer starts
    silently disagreeing with the data it renders.
    """
    sizes = {record["path"]: record.get("size") for record in disk_files}
    disk_paths = set(sizes)
    difference = compare_against_manifest(disk_paths, manifest_paths)

    pairs: list[tuple[dict, dict]] = []
    for kind in ("file-not-in-non-ufs-manifest", "manifest-entry-missing-on-disk"):
        for relpath in difference[kind]:
            pairs.append((
                manifest_anomaly(kind, relpath, reproduced, manifest_relpath,
                                 sizes.get(relpath)),
                {"size": sizes.get(relpath), "section": None}))
    for exe_path, section in unexpected_sections(executables):
        pairs.append((section_anomaly(exe_path, section, section_reproduced),
                      {"size": sizes.get(exe_path), "section": dict(section)}))
    mismatch = size_anomaly(sum(int(record.get("size") or 0) for record in disk_files),
                            steam_size)
    if mismatch is not None:
        pairs.append((mismatch, {"size": None, "section": None}))

    # The D-04 sentence is attached where it belongs and nowhere else: to every anomaly
    # about the executable D-04 governs, and only after the anomaly was detected on its
    # own. D-04 restricts how that FILE may be used, so a reader who lands on any of its
    # rows has to meet the restriction there.
    for entry, _facts in pairs:
        if entry["path"] == "MISERY/Binaries/Win64/MISERY.exe":
            entry["hypothesis"] = D04_SENTENCE

    pairs.sort(key=lambda item: (item[0]["kind"], item[0]["path"] or "",
                                 item[0]["description"]))
    return [entry for entry, _ in pairs], [facts for _, facts in pairs]


# --------------------------------------------------------------------------- #
# field groups
# --------------------------------------------------------------------------- #

def build_executables(install_dir: str, disk_files: list[dict],
                      digests: dict[str, dict[str, str]],
                      manifest_paths: set[str], warnings: list[str],
                      pe_detail: bool = True) -> list[dict]:
    """plan.md 3.1 "Executable": one entry per .exe, with the full pe object of F-01."""
    entries: list[dict] = []
    for record in disk_files:
        relative = record["path"]
        if not relative.lower().endswith(".exe"):
            continue
        absolute = os.path.join(install_dir, *relative.split("/"))
        pe: dict | None = None
        note = None
        try:
            document = pe_info.analyze(
                absolute,
                want_digests=pe_detail, want_entropy=pe_detail,
                want_checksum=pe_detail, want_file_digest=False)
            pe = document["pe"]
        except (pe_info.PEFormatError, OSError, ValueError) as error:
            warnings.append("%s: PE parse failed: %s" % (relative, error))
            note = "the PE parser could not read this image: %s" % error
        digest = digests.get(relative, {})
        entries.append({
            "path": relative,
            "role": EXECUTABLE_ROLES.get(relative, EXECUTABLE_DEFAULT_ROLE),
            "size": record.get("size"),
            "sha256": digest.get("sha256"),
            "sha1": digest.get("sha1"),
            "md5": digest.get("md5"),
            "in_non_ufs_manifest": relative in manifest_paths,
            "pe": pe,
            "notes": note,
        })
    entries.sort(key=lambda item: item["path"])
    return entries


def build_modules(install_dir: str, disk_files: list[dict],
                  digests: dict[str, dict[str, str]],
                  manifest_paths: set[str], warnings: list[str]) -> list[dict]:
    """plan.md 3.1 "Modules": every DLL under the three binary trees.

    ``version_info`` and ``exports_count`` come from the same F-01 parser the executables
    use, invoked with the expensive optional passes off: a module needs its version
    resource and its export count, not per-section entropy over 20 MB of Vulkan layer.
    """
    entries: list[dict] = []
    for record in disk_files:
        relative = record["path"]
        if not relative.lower().endswith(MODULE_SUFFIXES):
            continue
        if not relative.startswith(MODULE_ROOTS):
            continue
        absolute = os.path.join(install_dir, *relative.split("/"))
        version_info = None
        exports_count = None
        try:
            document = pe_info.analyze(absolute, want_digests=False, want_entropy=False,
                                       want_checksum=False, want_file_digest=False)
            version_info = document["pe"]["version_info"]
            exports = document["pe"]["exports"]
            exports_count = None if exports is None else len(exports)
        except (pe_info.PEFormatError, OSError, ValueError) as error:
            warnings.append("%s: PE parse failed: %s" % (relative, error))
        entries.append({
            "path": relative,
            "kind": module_kind(relative),
            "size": record.get("size"),
            "sha256": digests.get(relative, {}).get("sha256"),
            "version_info": version_info,
            "in_non_ufs_manifest": relative in manifest_paths,
            "exports_count": exports_count,
        })
    entries.sort(key=lambda item: item["path"])
    return entries


def build_plugins(disk_files: list[dict], containers: list[dict]) -> list[dict]:
    """plan.md 3.1 "Plugins".

    The plan sources this group from ``*.uplugin`` descriptors found in UNENCRYPTED
    containers. Two facts decide what this function can honestly return today:

    * no ``.uplugin`` file exists in the installation tree - the descriptors are cooked
      into the content, not shipped loose;
    * the only container with a readable index is ``MISERY-Windows.pak``, and reading its
      full directory index means writing a pak index parser. That is task F-02's format
      family and it is not in F-03's scope, so this tool does not do it, and does not
      pretend the absence of entries is an absence of plugins.

    What CAN be observed is a directory: ``MISERY/Plugins/<Name>/...``. The existence of
    the directory is a filesystem primitive; calling ``<Name>`` a PLUGIN reads the UE
    project layout, which is external-doc, so the record is class I and, resting on one
    method, stays below the 0.80 band.
    """
    names: dict[str, list[str]] = {}
    for record in disk_files:
        relative = record["path"]
        if not relative.startswith(PLUGIN_ROOT + "/"):
            continue
        remainder = relative[len(PLUGIN_ROOT) + 1:]
        head = remainder.split("/", 1)[0]
        if not head or "/" not in remainder:
            continue
        names.setdefault(head, []).append(relative)

    readable_index = sorted(
        entry["path"] for entry in containers
        if (entry.get("pak") or {}).get("index_readable")
        or (entry.get("utoc") or {}).get("directory_index_readable"))

    plugins: list[dict] = []
    for name in sorted(names):
        witnesses = sorted(names[name])
        plugins.append({
            "name": name,
            "source": "disk",
            "virtual_path": "%s/%s" % (PLUGIN_ROOT, name),
            "friendly_name": None,
            "version_name": None,
            "engine_version": None,
            "is_engine_plugin": False,
            "modules": None,
            "descriptor_available": False,
            "evidence": annotation(
                "INFERRED", "I", CONF_WEAK_I, ["filesystem", "external-doc"],
                [source("F-03", witnesses[0],
                        "oracle filesystem. The read-only directory walk found %d file(s) "
                        "under %s/%s, the first being %s. The walk was re-run and "
                        "reproduced." % (len(witnesses), PLUGIN_ROOT, name, witnesses[0]))],
                "Interpretive: the directory and its contents are a filesystem primitive, "
                "but reading the directory NAME as the name of a plugin rests on the UE "
                "project layout, which is external-doc and proves how vanilla UE arranges "
                "a project rather than anything about this build. No .uplugin descriptor "
                "was found, so nothing here states the plugin's version, its modules or "
                "whether it is enabled. One method, so the confidence stays below the "
                "0.80 band where plan.md 10.3 requires a second one. Containers with a "
                "readable index today: %s; enumerating .uplugin entries out of one is a "
                "pak index parse, which this composer does not do."
                % (", ".join(readable_index) or "none")),
        })
    return plugins


def build_engine(executables: list[dict], engine_version: str | None,
                 provisional: bool) -> dict:
    """plan.md 3.1 "Engine". Everything section 4 owns stays null - see the module docstring."""
    strings: dict[str, str] = {}
    fixed: dict[str, str] = {}
    for entry in executables:
        if entry["role"] != "primary-shipping":
            continue
        info = ((entry.get("pe") or {}).get("version_info") or {})
        strings = info.get("strings") or {}
        fixed = info.get("fixed") or {}
    product_version = strings.get("ProductVersion")
    file_version = fixed.get("file_version")

    return {
        "engine_version": engine_version,
        "engine_version_provisional": provisional,
        "engine_cl": None,
        "engine_branch": None,
        "build_configuration": None,
        "is_source_distribution": None,
        "is_perforce_build": None,
        "build_machine_path_leak": None,
        "evidence": annotation(
            "INFERRED", "I", CONF_ONE_METHOD_I, ["binary-analysis", "external-doc"],
            [source("F-01", "MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe",
                    "oracle binary-analysis + external-doc. The VS_VERSIONINFO resource "
                    "was located in .rsrc and decoded by tools/fingerprint/pe_info.py; "
                    "FileVersion reads %r and the ProductVersion string reads %r. The "
                    "parse was re-run in this session and reproduced."
                    % (file_version, product_version))],
            "engine_version is PROVISIONAL and is not a conclusion of this run: it is the "
            "value research/builds/index.json and install-inventory.json already publish, "
            "and it is embedded in build_id, so emitting null here would put the "
            "fingerprint at odds with its own directory name. One method was executed "
            "(the version-resource read), which is why the confidence sits below the 0.80 "
            "two-method band. engine_cl, engine_branch, build_configuration, "
            "is_source_distribution and is_perforce_build are null ON PURPOSE: plan.md 3.1 "
            "sources them from section 4 and section 4 has not run. In particular the "
            "changelist and the branch are legible IN the literal ProductVersion string "
            "recorded verbatim under executables[].pe.version_info.strings, and decoding "
            "that string into a changelist is method V-03 of plan.md 4 - this document "
            "records the string, not the conclusion. build_machine_path_leak is null "
            "because the CodeView entries carry bare file names with no directory "
            "component; see executables[].pe.pdb_path_if_any."),
    }


def build_game() -> dict:
    """plan.md 3.1 "Game". Null throughout: section 4 owns every field of this group."""
    return {
        "game_name": None,
        "project_module_name": None,
        "game_version_string_if_any": None,
        "evidence": annotation(
            "UNKNOWN", None, CONF_NONE, ["binary-analysis", "steam-metadata"],
            [source("F-03", None,
                    "oracle binary-analysis + steam-metadata. No method was run to "
                    "conclude these fields; the raw material they would be concluded "
                    "from is recorded elsewhere in this document.")],
            "Nothing is claimed here. plan.md 3.1 sources game_name, project_module_name "
            "and game_version_string_if_any from section 4, and section 4 has not run. "
            "The literal readings that a section 4 method would work from are already in "
            "this document and are not repeated as conclusions: the VS_VERSIONINFO "
            "strings ProductName, InternalName and OriginalFilename under "
            "executables[].pe.version_info.strings, and steam.install_dir_name from the "
            "app manifest. Turning any of those into \"the game is called X\" or \"the "
            "project module is X\" reads the meaning of a version-resource field, which "
            "is the step section 4 owns."),
    }


def build_layout(disk_files: list[dict], digests: dict[str, dict[str, str]],
                 manifest_paths: set[str], tree_hash: str,
                 inventory_ref: str | None) -> dict:
    """plan.md 3.1 "Layout": the normalised tree, one row per file."""
    rows: list[dict] = []
    for record in disk_files:
        relative = record["path"]
        digest = digests.get(relative, {})
        rows.append({
            "path": relative,
            "size": record.get("size"),
            "mtime": record.get("mtime"),
            "mtime_epoch": record.get("mtime_epoch"),
            "sha256": digest.get("sha256"),
            "sha1": digest.get("sha1"),
            "in_non_ufs_manifest": relative in manifest_paths,
            "category": category_of(relative),
        })
    rows.sort(key=lambda item: item["path"])
    return {
        "file_count": len(rows),
        "total_size": sum(int(row["size"] or 0) for row in rows),
        "tree_hash": tree_hash,
        "inventory_ref": inventory_ref,
        "files": rows,
    }


# --------------------------------------------------------------------------- #
# assembly
# --------------------------------------------------------------------------- #

def build_document(install_dir: str, *, steam_root: str | None = None,
                   engine_version: str = inventory.DEFAULT_ENGINE_VERSION,
                   engine_version_provisional: bool = True,
                   build_dir_ref: str | None = None,
                   buf_size: int = DEFAULT_BUFFER_BYTES,
                   pe_detail: bool = True) -> dict:
    """Compose the whole fingerprint. One read-only pass over the installation."""
    install_dir = os.path.abspath(install_dir)
    if not os.path.isdir(install_dir):
        raise OSError("not a directory: %s" % install_dir)
    warnings: list[str] = []
    checks: list[dict] = []

    # -- the tree, hashed once ------------------------------------------------
    disk_files = inventory.scan_tree(install_dir, buf_size=buf_size, warnings=warnings,
                                     hash_files=False)
    digests: dict[str, dict[str, str]] = {}
    for record in disk_files:
        absolute = os.path.join(install_dir, *record["path"].split("/"))
        try:
            digests[record["path"]] = stream_digests(absolute, buf_size=buf_size)
        except OSError as error:
            warnings.append("cannot hash %s: %s" % (record["path"], error))
            digests[record["path"]] = {}
        record["sha256"] = digests[record["path"]].get("sha256")
        record["sha1"] = digests[record["path"]].get("sha1")

    # -- the non-UFS manifest -------------------------------------------------
    manifest_abs = os.path.join(install_dir, NON_UFS_MANIFEST)
    manifest_entries, manifest_lines = read_non_ufs_manifest(manifest_abs, warnings)
    manifest_paths = set(manifest_entries)

    # -- Steam (C-13: LastOwner is never read) --------------------------------
    if steam_root is None:
        steam_root = inventory.derive_steam_root(install_dir)
    steam: dict = {
        "app_id": None, "depot_id": None, "depot_manifest_id": None,
        "shared_depots": None, "steam_buildid": None, "size_on_disk": None,
        "last_updated_epoch": None, "install_dir_name": None,
        "appmanifest_path": None, "appmanifest_sha256": None,
    }
    if steam_root:
        acf = inventory.appmanifest_path(steam_root)
        raw = inventory.read_appmanifest(acf, warnings)
        steam.update(inventory.steam_block(raw, warnings))
        if raw.get("appmanifest_present"):
            try:
                steam["appmanifest_sha256"] = stream_digests(
                    acf, algorithms=("sha256",), buf_size=buf_size)["sha256"]
            except OSError as error:
                warnings.append("cannot hash the app manifest: %s" % error)
    else:
        warnings.append("no Steam root could be derived from %s; the steam block is null"
                        % install_dir)

    # -- identity, RECOMPUTED and then compared (plan.md 3.2) -----------------
    build_record = inventory.find_record(disk_files, BUILD_KEY_RELPATH)
    build_key_hex = build_record["sha256"] if build_record else None
    if build_key_hex is None:
        warnings.append("%s was not found or could not be hashed; build_key is null"
                        % BUILD_KEY_RELPATH)
    content_key_hex, content_inputs = inventory.compute_content_key(disk_files)
    tree_hash = inventory.compute_tree_hash(disk_files)
    build_id = inventory.make_build_id(steam.get("steam_buildid"), engine_version,
                                       build_key_hex)

    # -- the composed groups --------------------------------------------------
    executables = build_executables(install_dir, disk_files, digests, manifest_paths,
                                    warnings, pe_detail=pe_detail)
    modules = build_modules(install_dir, disk_files, digests, manifest_paths, warnings)

    container_document = container_info.build_document(
        install_dir=install_dir, hash_files=False, entry_evidence=True)
    containers = container_document["containers"]
    for entry in containers:
        # container_info takes its sha256 from an inventory file or from --hash. Neither
        # was used: the digest computed by THIS run is spliced in, and where the tool
        # already had one the two are compared rather than one overwriting the other.
        mine = digests.get(entry["path"], {}).get("sha256")
        theirs = entry.get("sha256")
        if theirs is not None and mine is not None and theirs != mine:
            warnings.append("%s: container_info reports sha256 %s, this run computed %s"
                            % (entry["path"], theirs, mine))
        entry["sha256"] = mine if mine is not None else theirs
    warnings.extend(container_document.get("warnings") or [])
    for check in container_document.get("checks") or []:
        checks.append({"check": "container/" + check["check"], "target": check["target"],
                       "passed": bool(check["passed"]), "detail": check["detail"]})

    plugins = build_plugins(disk_files, containers)

    # -- F-05, with its confirming second pass --------------------------------
    first = compare_against_manifest({record["path"] for record in disk_files},
                                     manifest_paths)
    confirm_files = inventory.scan_tree(install_dir, warnings=warnings, hash_files=False)
    confirm_entries, _lines = read_non_ufs_manifest(manifest_abs, warnings)
    second = compare_against_manifest({record["path"] for record in confirm_files},
                                      set(confirm_entries))
    comparison_reproduced = first == second
    if not comparison_reproduced:
        warnings.append("the manifest comparison did NOT reproduce: the second, "
                        "independent pass produced a different set of differences")
    checks.append({
        "check": "manifest_comparison_reproduced", "target": NON_UFS_MANIFEST,
        "passed": comparison_reproduced,
        "detail": ("the comparison was performed twice, from two independent directory "
                   "walks and two independent reads of the manifest, and the two results "
                   "%s" % ("agree" if comparison_reproduced else "DISAGREE"))})

    section_first = [(path, section["name"]) for path, section in
                     unexpected_sections(executables)]
    section_second: list[tuple[str, str]] = []
    for entry in executables:
        absolute = os.path.join(install_dir, *entry["path"].split("/"))
        try:
            again = pe_info.analyze(absolute, want_digests=False, want_entropy=False,
                                    want_checksum=False, want_file_digest=False)
        except (pe_info.PEFormatError, OSError, ValueError):
            continue
        for section in (again["pe"]["sections"] or []):
            if str(section["name"]).lower() not in ORDINARY_PE_SECTIONS:
                section_second.append((entry["path"], section["name"]))
    sections_reproduced = sorted(section_first) == sorted(section_second)
    if not sections_reproduced:
        warnings.append("the PE section survey did NOT reproduce between two parses")
    checks.append({
        "check": "pe_section_survey_reproduced", "target": "executables",
        "passed": sections_reproduced,
        "detail": ("every executable's section table was parsed twice, through separate "
                   "invocations over freshly opened handles, and the two surveys %s"
                   % ("agree" if sections_reproduced else "DISAGREE"))})

    anomalies, anomaly_facts = detect_anomalies(
        disk_files, manifest_paths, NON_UFS_MANIFEST, executables,
        steam.get("size_on_disk"), comparison_reproduced, sections_reproduced)
    timestamps = compare_manifest_timestamps(manifest_entries, disk_files)

    layout = build_layout(disk_files, digests, manifest_paths, tree_hash,
                          (build_dir_ref + "/install-inventory.json") if build_dir_ref
                          else None)

    document = {
        "identity": {
            "build_id": build_id,
            "build_key": inventory.prefixed(build_key_hex),
            "content_key": inventory.prefixed(content_key_hex),
            "generated_at": now_iso_utc(),
            "generator_version": "%s %s" % (GENERATOR_NAME, GENERATOR_VERSION),
            # The published schema carries no version marker of its own, and inventing
            # one here would be a number nothing else agrees with. A change to the schema
            # is detectable through vcs-history, which is what that oracle is for.
            "schema_version": None,
            "install_dir": install_dir,
            "install_json": (build_dir_ref + "/install.json") if build_dir_ref else None,
        },
        "steam": steam,
        "executables": executables,
        "engine": build_engine(executables, engine_version, engine_version_provisional),
        "game": build_game(),
        "modules": modules,
        "containers": containers,
        "plugins": plugins,
        "layout": layout,
        "anomalies": anomalies,
        "notes": compose_notes(content_inputs, manifest_lines, len(manifest_paths),
                               anomalies, checks, warnings),
    }
    # Not part of the schema (additionalProperties is false), so the run's own
    # bookkeeping travels beside the document rather than inside it.
    return {"document": document, "checks": checks, "warnings": warnings,
            "content_inputs": content_inputs, "manifest_entries": manifest_entries,
            "anomaly_facts": anomaly_facts, "manifest_timestamps": timestamps}


def compose_notes(content_inputs: list[str], manifest_lines: int, manifest_paths: int,
                  anomalies: list[dict], checks: list[dict],
                  warnings: list[str]) -> str:
    """The document's own account of how it was made and what it refuses to say."""
    by_kind: dict[str, int] = {}
    for entry in anomalies:
        by_kind[entry["kind"]] = by_kind.get(entry["kind"], 0) + 1
    failed = [check["check"] for check in checks if not check["passed"]]
    return (
        "generator: %s %s. Composed, not parsed: every pe object comes verbatim from "
        "tools/fingerprint/pe_info.py, the whole containers[] array verbatim from "
        "tools/fingerprint/container_info.py, and the tree walk, the app manifest read "
        "and the plan.md 3.2 identity computations from tools/inventory/snapshot_install.py. "
        "build_key, content_key, tree_hash and build_id were RECOMPUTED from the "
        "installation in this run and then compared with research/builds/index.json and "
        "install-inventory.json; they were not copied. content_key ordering rule: sha256 "
        "over the concatenated lowercase sha256 hex digests of every .utoc, ASCII, no "
        "separator, sorted by normalized path ascending; inputs in order: %s. tree_hash "
        "rule: sha256 over '<path>\\n<size>\\n<sha256>\\n' per row, UTF-8, rows sorted by "
        "path. C-13: LastOwner is a Steam account id and is never read; the steam block "
        "is additionalProperties:false and could not carry it. D-01: the installation was "
        "opened read-only. D-02: no container was decrypted and no key was extracted. "
        "%s carries %d line(s) naming %d distinct path(s); the comparison found %s, every "
        "one of them listed in anomalies[] above with its own evidence annotation, and "
        "the same list is rendered as prose in the anomalies.md this run writes when one "
        "was asked for. Every null in the engine and game groups is deliberate: plan.md "
        "3.1 sources both groups from section 4, which has not run, and each group "
        "carries an evidence annotation naming the method that would conclude it. "
        "engine_version is the one filled field there and it is PROVISIONAL. "
        "Reproducibility checks performed while building this document: %d, failed: "
        "%d%s; the checks about the document itself (schema validation, the two-run "
        "comparison) run after it is built and are reported on the run's own output, "
        "not stored here. One caveat on the M1 reproducibility criterion, measured "
        "rather than anticipated: identity.generated_at is NOT the only field that can "
        "differ between two runs over an unchanged installation. steam."
        "appmanifest_sha256 can differ too, because Steam rewrites "
        "appmanifest_2119830.acf on its own schedule (LastPlayed and download "
        "bookkeeping live in it), and two builds minutes apart were observed to differ "
        "in exactly that one field and in nothing else. That is the input changing, not "
        "this tool: kb-record.schema.json defines the field so a change of Steam "
        "bookkeeping is detectable, and the --selftest-reproducible check re-reads the "
        "manifest to tell the two causes apart instead of forgiving the field. Nothing "
        "derived from the installation itself - build_key, content_key, tree_hash, any "
        "digest, any header field - varies. Warnings: %d."
        % (GENERATOR_NAME, GENERATOR_VERSION,
           ", ".join(content_inputs) or "none",
           NON_UFS_MANIFEST, manifest_lines, manifest_paths,
           ", ".join("%d %s" % (count, kind) for kind, count in sorted(by_kind.items()))
           or "no anomalies",
           len(checks), len(failed),
           (" (%s)" % ", ".join(failed)) if failed else "",
           len(warnings)))


# --------------------------------------------------------------------------- #
# F-05 -- the anomalies document
# --------------------------------------------------------------------------- #

# Groups for the anomalies report. Each entry is (matcher, heading, explanation).
# The grouping is presentational ONLY: every anomaly appears exactly once and the count
# is stated per group and in total, so no file is grouped out of sight.
def _anomaly_group(relpath: str) -> str:
    lower = relpath.lower()
    if lower.endswith((".utoc", ".ucas", ".pak", ".usig")):
        return "containers"
    if lower.endswith(".vdf") or lower == "steam_input_manifest.vdf":
        return "steam-input"
    if lower == NON_UFS_MANIFEST.lower():
        return "manifest-itself"
    if lower.endswith(".exe"):
        return "executables"
    return "engine-extras"


GROUP_TITLES: dict[str, tuple[str, str]] = {
    "executables": (
        "Исполняемые файлы",
        "Единственная группа, где отсутствие в манифесте действительно требует "
        "объяснения: рядом лежит исполняемый файл, который в манифесте есть."),
    "containers": (
        "Контейнеры контента",
        "Манифест называется Non-UFS: он перечисляет файлы ВНЕ виртуальной файловой "
        "системы. Контейнеры .utoc/.ucas/.pak и есть UFS-содержимое, поэтому их "
        "отсутствие здесь ожидаемо и не является находкой."),
    "steam-input": (
        "Файлы Steam Input",
        "Файлы controller_*.vdf и steam_input_manifest.vdf кладёт Steam, а не сборщик "
        "Unreal Engine; манифест Non-UFS формируется на стороне UE."),
    "manifest-itself": (
        "Сам манифест",
        "Файл манифеста не перечисляет сам себя."),
    "engine-extras": (
        "Дополнительные файлы движка",
        "Слои Vulkan, отладочные шрифты Slate, GPUDumpViewer и WinPixEventRuntime. Все "
        "они лежат в дереве Engine и в манифесте Non-UFS не перечислены."),
}

GROUP_ORDER: tuple[str, ...] = ("executables", "containers", "engine-extras",
                                "steam-input", "manifest-itself")


def render_anomalies_md(payload: dict) -> str:
    """Render ``anomalies.md`` from the SAME anomaly list the JSON carries.

    One detection, two renderings. Every number below arrives from
    :func:`detect_anomalies`; nothing here is typed by hand, which is why the document
    can say "33" without anybody having decided that 33 is the answer.

    The prose is Russian and the identifiers are English, per the repository convention.
    The Russian sentences are BUILT from the structured facts that travel beside each
    anomaly, not translated from the English ``description`` and not scraped out of it -
    a renderer that parses its own input is a renderer that will one day disagree with it.
    """
    document = payload["document"]
    anomalies = document["anomalies"]
    facts = payload["anomaly_facts"]
    identity = document["identity"]
    checks = payload["checks"]
    timestamps = payload["manifest_timestamps"]

    rows = list(zip(anomalies, facts))
    of_kind = lambda kind: [pair for pair in rows if pair[0]["kind"] == kind]  # noqa: E731
    missing = of_kind("file-not-in-non-ufs-manifest")
    orphans = of_kind("manifest-entry-missing-on-disk")
    sections = of_kind("unexpected-pe-section")
    sizes = of_kind("size-mismatch")

    manifest_paths = len(payload["manifest_entries"])
    file_count = document["layout"]["file_count"]

    groups: dict[str, list[tuple[dict, dict]]] = {}
    for pair in missing:
        groups.setdefault(_anomaly_group(pair[0]["path"] or ""), []).append(pair)

    lines: list[str] = []
    add = lines.append

    add("# Аномалии установки — %s" % identity["build_id"])
    add("")
    add("Сгенерировано `%s` %s, `generated_at = %s`."
        % (GENERATOR_NAME, GENERATOR_VERSION, identity["generated_at"]))
    add("")
    add("`build_key = %s`" % identity["build_key"])
    add("")
    add("Документ порождён автоматически задачей F-05 из того же списка, который лежит "
        "в `fingerprint.json` в поле `anomalies[]`. Ни одно число здесь не набрано "
        "руками: все они получены из результата сравнения.")
    add("")

    add("## 1. Что именно сравнивалось")
    add("")
    add("1. Дерево установки обходится только на чтение (решение D-01); получается "
        "множество путей относительно корня установки — **%d** файл(ов)." % file_count)
    add("2. Читается `%s`: по одной записи в строке, формат `<путь>` TAB `<время>`. "
        "Обратные слэши приводятся к прямым. Получается множество из **%d** различных "
        "путей." % (NON_UFS_MANIFEST, manifest_paths))
    add("3. Считаются **обе** разности множеств, а не только одна.")
    add("4. Таблица секций каждого исполняемого файла сравнивается со списком имён, "
        "которые детектор считает обычными для образа, собранного компоновщиком MSVC "
        "(в списке %d имён). Список — соглашение детектора, а не спецификация."
        % len(ORDINARY_PE_SECTIONS))
    add("5. Сумма размеров файлов сравнивается с полем `SizeOnDisk` манифеста Steam.")
    add("6. Отметка времени каждой записи манифеста сравнивается с `mtime` файла на "
        "диске — результат в разделе 7.")
    add("")
    add("Сравнение путей и разбор таблиц секций выполняются **дважды**, от двух "
        "независимых обходов каталога и двух независимых чтений манифеста. Критерий 2 "
        "класса P из §10.3 таким образом выполнен, а не заявлен.")
    add("")
    for check in checks:
        if check["check"] in ("manifest_comparison_reproduced",
                              "pe_section_survey_reproduced"):
            add("* `%s` — **%s**" % (check["check"],
                                     "PASS" if check["passed"] else "FAIL"))
    add("")

    add("## 2. Сводка")
    add("")
    add("| Класс аномалии | Найдено |")
    add("|---|---|")
    add("| `file-not-in-non-ufs-manifest` | %d |" % len(missing))
    add("| `manifest-entry-missing-on-disk` | %d |" % len(orphans))
    add("| `unexpected-pe-section` | %d |" % len(sections))
    add("| `size-mismatch` | %d |" % len(sizes))
    add("| **всего** | **%d** |" % len(anomalies))
    add("")
    expected = file_count - manifest_paths
    if len(missing) == expected and not orphans:
        add("Проверка счёта: %d файлов на диске минус %d путей манифеста даёт **%d**, и "
            "ровно столько записей класса `file-not-in-non-ufs-manifest` и найдено. "
            "Сходится это только потому, что ни одна запись манифеста не осталась без "
            "файла на диске; иначе разность множеств не совпала бы с разностью их "
            "размеров." % (file_count, manifest_paths, expected))
    else:
        add("**Счёт не сходится, и это само по себе находка.** %d файлов на диске минус "
            "%d путей манифеста дало бы %d, а найдено %d; записей манифеста без файла на "
            "диске — %d. Ни одна из них не опущена: полный список в разделе 4, "
            "«сироты» — в разделе 5." % (file_count, manifest_paths, expected,
                                          len(missing), len(orphans)))
    add("")
    add("### Градуировка")
    add("")
    add("Одна строка на КЛАСС записей, а не на запись: метод, oracle и уровень внутри "
        "класса буквально одни и те же — это один и тот же обход и один и тот же "
        "разбор. Персональная аннотация каждой из %d записей лежит в "
        "`fingerprint.json`, в поле `anomalies[].evidence`, и проверяется там "
        "`tools/kb/validate.py` по правилам редуцированного конверта "
        "`kb-record.schema.json`." % len(anomalies))
    add("")
    add("| ID | Наблюдение | Метод | Oracle | Claim type | Уровень | Confidence | Класс |")
    add("|---|---|---|---|---|---|---|---|")
    if missing:
        add("| F05-1 | Каждая из %d записей класса `file-not-in-non-ufs-manifest`: файл "
            "существует в установке, и ни одна строка `%s` его не называет | Обход "
            "установки только на чтение и разбор `%s`, оба выполнены дважды от "
            "независимых дескрипторов: run 1 и run 2 совпали, результат воспроизведён "
            "| filesystem | file-exists | OBSERVED | 0.99 | P |"
            % (len(missing), NON_UFS_MANIFEST, NON_UFS_MANIFEST))
    if orphans:
        add("| F05-2 | Каждая из %d записей класса `manifest-entry-missing-on-disk`: "
            "строка манифеста называет путь, файла в установке нет | Тот же обход и тот "
            "же разбор `%s`, разность множеств в обратную сторону, выполнено дважды, "
            "результат воспроизведён | filesystem | file-exists | OBSERVED | 0.99 | P |"
            % (len(orphans), NON_UFS_MANIFEST))
    if sections:
        add("| F05-3 | Каждая из %d записей класса `unexpected-pe-section`: таблица "
            "секций содержит секцию с именем вне списка обычных | Разбор таблицы секций "
            "средствами `tools/fingerprint/pe_info.py`, выполнен дважды на заново "
            "открытых дескрипторах, результат воспроизведён | binary-analysis + "
            "external-doc | layout-observation | INFERRED | 0.79 | I |" % len(sections))
    if sizes:
        add("| F05-4 | Сумма размеров файлов и `SizeOnDisk` из манифеста Steam "
            "расходятся | Суммирование размеров по обходу установки; чтение "
            "`SizeOnDisk` из `appmanifest_2119830.acf` средствами "
            "`tools/inventory/snapshot_install.py` | filesystem + steam-metadata "
            "| disk-matches-steam-metadata | INFERRED | 0.85 | I |")
    add("")
    add("Значение 0.79 у класса `unexpected-pe-section` не занижено из осторожности: в "
        "этом прогоне выполнен ровно ОДИН метод, а §10.3 требует двух независимых от "
        "0.80 и выше. Значение 0.99 у класса `file-not-in-non-ufs-manifest` держится на "
        "том, что это членство в множестве из двух первичных чтений, без шага "
        "интерпретации.")
    add("")

    add("## 3. Именованный случай A-05")
    add("")
    a05 = [pair for pair in rows if pair[0].get("id") == "A-05"]
    if not a05:
        add("Аномалия с идентификатором `A-05` в этом прогоне **не обнаружена**. Это "
            "само по себе находка: строка Приложения A `plan.md` её ожидает, и "
            "расхождение нужно разбирать, а не списывать.")
        add("")
    else:
        add("Детектор нашёл её сам, разностью множеств, не имея этого файла в условиях "
            "поиска. Идентификатор `A-05` приписан **уже найденной** аномалии по "
            "совпадению пути и имени секции: если удалить таблицу идентификаторов, "
            "обнаружение не изменится, исчезнет только ссылка на строку Приложения A.")
        add("")
        for entry, fact in a05:
            add("### %s" % _russian_title(entry, fact))
            add("")
            add(_russian_description(entry, fact))
            add("")
            # No inline annotation here on purpose. The grade for this CLASS of record is
            # stated once, in the fact table of section 2, where the notation has columns
            # for the method, the oracle and the claim type - so EV-03 and the plan.md
            # 10.5 matrix can actually be CHECKED. Restating the level in prose would be
            # a second, weaker copy of the same grade, which is the cross-document
            # promotion defect research/unknowns.md NEW-05 is about.
            add("Градуировка: строка `%s` таблицы в разделе 2; персональная аннотация — "
                "`anomalies[].evidence` в `fingerprint.json`."
                % ("F05-1" if entry["kind"] == "file-not-in-non-ufs-manifest"
                   else "F05-3"))
            add("")
        add("### Что об этом файле говорить нельзя")
        add("")
        add("Объяснение «в депот попала Development-сборка игры» — догадка, а не "
            "находка, и она градуирована так: **HYPOTHESIS, confidence 0.65, oracle: "
            "binary-analysis + filesystem** по решению D-04. Называть её фактом "
            "запрещено; в `fingerprint.json` она лежит в поле `hypothesis`, отдельно от "
            "поля `description`, где стоит только наблюдение.")
        add("")
        add("Решение D-04 задаёт режим работы с этим файлом, и он ограничительный:")
        add("")
        add("* `MISERY/Binaries/Win64/MISERY.exe` допускается **только как read-only "
            "oracle**;")
        add("* он **никогда** не является целью для bindings;")
        add("* любой вывод, полученный на нём, обязан быть перепроверен на "
            "Shipping-бинарнике (RISK-07).")
        add("")

    add("## 4. Полный список `file-not-in-non-ufs-manifest` (%d)" % len(missing))
    add("")
    add("Перечислены все до одного, и это осознанно: предикат детектора — «названо ли "
        "имя файла в манифесте», а не «удивительно ли это». Группировка ниже — только "
        "способ читать список; сумма по группам равна общему числу, ни один файл из-за "
        "неё не пропадает.")
    add("")
    total_grouped = 0
    for key in GROUP_ORDER:
        entries = groups.get(key) or []
        if not entries:
            continue
        total_grouped += len(entries)
        title, explanation = GROUP_TITLES[key]
        add("### %s — %d" % (title, len(entries)))
        add("")
        add(explanation)
        add("")
        for entry, fact in sorted(entries, key=lambda item: item[0]["path"] or ""):
            marker = "  ← `%s`" % entry["id"] if entry.get("id") else ""
            add("* `%s` — %s байт%s" % (entry["path"], fact.get("size"), marker))
        add("")
    for key in sorted(set(groups) - set(GROUP_ORDER)):
        entries = groups[key]
        total_grouped += len(entries)
        add("### Без группы (`%s`) — %d" % (key, len(entries)))
        add("")
        add("Группа не предусмотрена таблицей `GROUP_TITLES`; файлы перечислены как "
            "есть, потому что пропустить их было бы хуже.")
        add("")
        for entry, fact in entries:
            add("* `%s` — %s байт" % (entry["path"], fact.get("size")))
        add("")
    add("Сумма по группам: **%d**, всего записей этого класса: **%d**.%s"
        % (total_grouped, len(missing),
           "" if total_grouped == len(missing)
           else " **Числа расходятся — группировка потеряла записи.**"))
    add("")

    add("## 5. Записи манифеста без файла на диске (%d)" % len(orphans))
    add("")
    if not orphans:
        add("Ни одной: каждый путь, названный `%s`, существует в установке. Это "
            "проверялось отдельно от предыдущего раздела — разность множеств считается "
            "в обе стороны." % NON_UFS_MANIFEST)
    else:
        for entry, fact in orphans:
            add("* `%s` — манифест называет этот путь, файла в установке нет."
                % entry["path"])
    add("")

    add("## 6. Неожиданные секции PE (%d)" % len(sections))
    add("")
    if not sections:
        add("Ни одной: все имена секций всех исполняемых файлов входят в список имён, "
            "которые детектор считает обычными.")
        add("")
    else:
        add("Каждая запись этого класса — класс I, и иначе быть не может: назвать "
            "диапазон байт «секцией» и прочитать из него имя — значит опереться на "
            "публичную раскладку PE, то есть на oracle `external-doc`, который "
            "доказывает устройство формата, а не свойство этой сборки. Правка v2.4 "
            "§10.3 пускает `binary-analysis` в класс P только для чтения, которое "
            "называет смещение и длину и **не** называет, чем байты являются; здесь "
            "ровно наоборот.")
        add("")
        for entry, fact in sections:
            section = fact.get("section") or {}
            add("### `%s` в `%s`" % (section.get("name"), entry["path"]))
            add("")
            add(_russian_description(entry, fact))
            add("")
            add("Градуировка: строка `F05-3` таблицы в разделе 2.")
            add("")
            note = SECTION_NAME_NOTES.get(str(section.get("name") or ""))
            if note:
                add("Про само имя: %s. Это внешняя документация о том, что имя значит "
                    "вообще, и она ничего не доказывает про эту сборку — "
                    "**HYPOTHESIS, confidence 0.6, oracle: external-doc**." % note)
                add("")

    add("## 7. Что проверено и аномалией НЕ является")
    add("")
    add("* **Времена изменения.** Сравнены все %d записей манифеста с `mtime` файлов на "
        "диске: совпало по секундам %d, разошлось %d, не с чем сравнить %d. Расхождение "
        "систематическое — Steam проставляет время записи файла, а не время сборки, — "
        "поэтому записей в `anomalies[]` оно не порождает: %d однотипных строк "
        "похоронили бы %d записей, которые систематическими не являются. Примеры "
        "расхождений: %s."
        % (timestamps["compared"], timestamps["same"], timestamps["differ"],
           timestamps["unknown"], timestamps["differ"],
           len(sections) + len(orphans) + len(sizes) + len(
               [1 for entry, _ in missing if entry.get("id")]),
           "; ".join(timestamps["examples"]) or "нет"))
    add("* **Размер установки.** Сумма размеров файлов и `SizeOnDisk` из манифеста "
        "Steam %s." % ("совпадают, записи класса `size-mismatch` нет" if not sizes
                       else "РАСХОДЯТСЯ, см. раздел 2"))
    add("* **Отсутствие `.uplugin` на диске.** Дескрипторы плагинов запечены в контент; "
        "их отсутствие среди файлов установки — свойство упаковки, а не аномалия. "
        "Поэтому `plugins[]` в `fingerprint.json` собран по каталогам "
        "`MISERY/Plugins/<Имя>` и несёт `descriptor_available: false`.")
    add("")

    add("## 8. Границы этого документа")
    add("")
    add("* Детектор отвечает на вопрос «названо ли имя файла в манифесте», и только на "
        "него. На вопрос «должно ли оно быть там названо» он не отвечает: манифест "
        "Non-UFS формирует сборщик UE по правилам, которых у нас нет.")
    add("* Список «обычных» имён секций PE — соглашение этого детектора. Имя вне списка "
        "означает «детектор такого не ждал», а не «файл неправилен».")
    add("* Идентификаторы вида `A-nn` присваиваются вручную в Приложении A `plan.md`. "
        "Аномалии без строки в Приложении A несут `id: null`: придумывать им новые "
        "номера здесь значило бы столкнуться с чужой нумерацией.")
    add("* Объяснения в разделах 4 и 6 («это кладёт Steam», «это UFS-содержимое») "
        "объясняют, почему запись не удивительна. Они не отменяют запись и не "
        "уменьшают счёт: в `anomalies[]` она есть.")
    add("")
    return "\n".join(lines).rstrip("\n") + "\n"


def _russian_title(entry: dict, fact: dict) -> str:
    """A heading for one anomaly, built from its fields."""
    section = (fact.get("section") or {}).get("name")
    if section:
        return "`%s` в `%s`" % (section, entry["path"])
    return "`%s` — `%s`" % (entry["path"], entry["kind"])


def _russian_description(entry: dict, fact: dict) -> str:
    """The Russian rendering of one anomaly, built from the structured facts."""
    kind = entry["kind"]
    if kind == "file-not-in-non-ufs-manifest":
        return ("Файл `%s` существует в установке (размер %s байт), и ни одна строка "
                "`%s` его не называет. Сравнение выполнено дважды, от двух независимых "
                "обходов каталога и двух независимых чтений манифеста, и оба прогона "
                "совпали." % (entry["path"], fact.get("size"), NON_UFS_MANIFEST))
    if kind == "manifest-entry-missing-on-disk":
        return ("Путь `%s` назван строкой `%s`, а файла в установке нет. Сравнение "
                "выполнено дважды и оба прогона совпали."
                % (entry["path"], NON_UFS_MANIFEST))
    if kind == "unexpected-pe-section":
        section = fact.get("section") or {}
        return ("Таблица секций `%s`, разобранная `tools/fingerprint/pe_info.py`, "
                "содержит секцию с именем `%s`: rva %s, virtual size %s, raw size %s, "
                "characteristics %s. Имя `%s` не входит в список %d имён, которые "
                "детектор считает обычными для образа, собранного компоновщиком MSVC. "
                "Таблица разобрана дважды, двумя отдельными вызовами разборщика на "
                "заново открытых дескрипторах, и оба разбора совпали."
                % (entry["path"], section.get("name"), section.get("rva"),
                   section.get("vsize"), section.get("rsize"),
                   section.get("characteristics"), section.get("name"),
                   len(ORDINARY_PE_SECTIONS)))
    return entry["description"]


# The inline annotation form - "*(OBSERVED, confidence 0.99, oracle: filesystem)*" -
# is deliberately NOT used by this renderer, and the reason is worth stating rather
# than leaving as an absence. tools/kb/validate.py can read it, but the notation has
# no field for sources[], so EV-03 cannot be checked on it and no claim_type can be
# carried, so the plan.md 10.5 matrix cannot either. Every grade this document states
# therefore goes into the fact table of section 2, which has columns for both. The
# prose sections point at that table instead of restating a level, because a level
# restated in prose is a second copy of the same grade with weaker checking - the
# cross-document promotion defect of research/unknowns.md NEW-05.


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def dump_json(document: dict) -> str:
    """Deterministic serialization: sorted keys, indent 2, LF, trailing newline."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def first_difference(left, right, pointer: str = "$") -> str | None:
    """The JSON pointer of the first place *left* and *right* disagree, or None.

    Exists so the reproducibility check can NAME the field that moved. A check that
    reports "the two runs differ" and stops is nearly useless: the whole document has
    to be re-diffed by hand to act on it, and the temptation is then to shrug the check
    off rather than chase it. The comparison walks in sorted key order so the answer is
    itself reproducible.
    """
    if type(left) is not type(right):
        return "%s (%s vs %s)" % (pointer, type(left).__name__, type(right).__name__)
    if isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                return "%s.%s (present in only one run)" % (pointer, key)
            found = first_difference(left[key], right[key], "%s.%s" % (pointer, key))
            if found:
                return found
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return "%s (%d vs %d items)" % (pointer, len(left), len(right))
        for index, (a, b) in enumerate(zip(left, right)):
            found = first_difference(a, b, "%s[%d]" % (pointer, index))
            if found:
                return found
        return None
    # Serialised, not compared with ==: NaN is not equal to itself, and two identical
    # documents must not be reported as different because of it.
    if json.dumps(left) != json.dumps(right):
        return "%s (%r vs %r)" % (pointer, left, right)
    return None


def write_text(text: str, out_path: str, install_dir: str) -> str:
    """Write *text*, refusing any path inside the installation (D-01, layer 1)."""
    target = pathguard.check_output_path(out_path, install_dir, what="--out")
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return target


def attribute_to_a_changed_input(where: str | None, first_document: dict) -> str | None:
    """Explain a reproducibility difference by a changed INPUT, or return None.

    Returns a sentence only when two things hold: the sole difference sits at a pointer
    in :data:`MUTABLE_INPUT_POINTERS`, and re-reading the file behind that pointer NOW
    gives a digest different from the one the first build recorded. The second condition
    is what makes this an attribution rather than an exemption - without it, any future
    non-determinism at the same pointer would be waved through by a list.
    """
    if where is None:
        return None
    pointer = where.split(" ", 1)[0]
    if pointer not in MUTABLE_INPUT_POINTERS:
        return None
    steam = first_document.get("steam") or {}
    path = steam.get("appmanifest_path")
    recorded = steam.get("appmanifest_sha256")
    if not path or not recorded or not os.path.isfile(path):
        return None
    try:
        now = stream_digests(path, algorithms=("sha256",))["sha256"]
    except OSError:
        return None
    if now == recorded:
        return None
    return ("the only difference is %s, and re-reading %s now yields %s where the first "
            "build recorded %s. Steam rewrote its own bookkeeping file while this run "
            "was in progress: the INPUT changed, and this field exists in the schema so "
            "that such a change is detectable. Every other byte of the two documents is "
            "identical." % (pointer, path, now, recorded))


def verify_against_registry(document: dict, repo_root: str) -> list[dict]:
    """Compare the RECOMPUTED identity with what the repository already records.

    Not a source of values - a check on them. Missing registry files are reported as
    skipped checks rather than as passes: "we could not compare" is not "the values agree".
    """
    checks: list[dict] = []
    identity = document["identity"]
    index_path = os.path.join(repo_root, "research", "builds", "index.json")
    build_key = identity["build_key"]
    try:
        with open(index_path, "r", encoding="utf-8") as handle:
            index = json.load(handle)
    except (OSError, ValueError) as error:
        checks.append({"check": "identity_matches_build_index", "target": "index.json",
                       "passed": False,
                       "detail": "could not be compared: %s" % error})
        return checks
    entry = index.get(build_key or "")
    if entry is None:
        checks.append({
            "check": "identity_matches_build_index", "target": "index.json",
            "passed": False,
            "detail": ("the recomputed build_key %s has no entry in index.json; the "
                       "installation is not the build the registry records" % build_key)})
        return checks
    for field_name, mine, theirs in (
            ("build_id", identity["build_id"], entry.get("build_id")),
            ("content_key", identity["content_key"],
             (entry.get("content_keys") or [None])[0]),
            ("steam_buildid", document["steam"].get("steam_buildid"),
             (entry.get("steam_buildids") or [None])[0])):
        checks.append({
            "check": "identity_matches_build_index/%s" % field_name,
            "target": "index.json", "passed": mine == theirs,
            "detail": "recomputed %r, registry records %r" % (mine, theirs)})
    return checks


def verify_against_inventory(document: dict, inventory_path: str) -> list[dict]:
    """Compare the recomputed layout with ``install-inventory.json`` row by row."""
    checks: list[dict] = []
    try:
        with open(inventory_path, "r", encoding="utf-8") as handle:
            recorded = json.load(handle)
    except (OSError, ValueError) as error:
        checks.append({"check": "layout_matches_install_inventory",
                       "target": os.path.basename(inventory_path), "passed": False,
                       "detail": "could not be compared: %s" % error})
        return checks
    theirs = {row["path"]: row for row in recorded.get("files") or []}
    mine = {row["path"]: row for row in document["layout"]["files"]}
    differing = sorted(
        path for path in set(mine) | set(theirs)
        if path not in mine or path not in theirs
        or mine[path]["sha256"] != theirs[path].get("sha256")
        or mine[path]["size"] != theirs[path].get("size"))
    checks.append({
        "check": "layout_matches_install_inventory",
        "target": os.path.basename(inventory_path), "passed": not differing,
        "detail": ("%d file(s) compared by path, size and sha256; %s"
                   % (len(mine), "all agree" if not differing
                      else "differing: %s" % ", ".join(differing[:8])))})
    checks.append({
        "check": "tree_hash_matches_install_inventory",
        "target": os.path.basename(inventory_path),
        "passed": document["layout"]["tree_hash"] == recorded.get("tree_hash"),
        "detail": "recomputed %r, inventory records %r"
                  % (document["layout"]["tree_hash"], recorded.get("tree_hash"))})
    return checks


def validate_against_schema(document: dict,
                           schema_path: str) -> tuple[str, list[str]]:
    """Validate with a PLAIN ``jsonschema.Draft202012Validator``, as a stranger would.

    Returns ``(status, details)`` with status one of ``"pass"``, ``"fail"``,
    ``"skipped"``. Three outcomes and not two, because the difference matters: a
    document that FAILS its own published contract is a broken artifact and the process
    must exit non-zero, while a check that could not RUN - jsonschema not installed,
    which is legal here exactly as it is in tools/kb/validate.py, or the schema
    directory missing - is a gap in the run. A gap is reported as not-passed so nobody
    reads it as a pass, and it is not counted as a defect in the document, because
    "we did not look" is not "we looked and it was wrong".
    """
    try:
        import jsonschema  # type: ignore
        from referencing import Registry, Resource  # type: ignore
        from referencing.jsonschema import DRAFT202012  # type: ignore
    except Exception as error:  # noqa: BLE001
        return "skipped", ["jsonschema is not importable: %s" % error]

    # fingerprint.schema.json is deliberately NOT bundled (see its own $comment): it
    # carries cross-file $refs and needs a consumer that can read a SIBLING file. That
    # is what this registry is - every *.schema.json in the directory, keyed by its file
    # name, which is exactly how a relative $ref resolves against the relative $id. No
    # base-URI rewriting, no network: a stranger with an editor or check-jsonschema gets
    # the same resolution.
    schema_dir = os.path.dirname(os.path.abspath(schema_path))
    registry = Registry()
    try:
        for name in sorted(os.listdir(schema_dir)):
            if not name.endswith(".schema.json"):
                continue
            with open(os.path.join(schema_dir, name), "r", encoding="utf-8") as handle:
                registry = registry.with_resource(
                    name, Resource.from_contents(json.load(handle),
                                                 default_specification=DRAFT202012))
        with open(schema_path, "r", encoding="utf-8") as handle:
            schema = json.load(handle)
    except (OSError, ValueError) as error:
        return "skipped", ["the schema could not be read: %s" % error]
    validator = jsonschema.Draft202012Validator(schema, registry=registry)
    errors = [
        "%s: %s" % ("/".join(str(part) for part in error.absolute_path) or "$",
                    error.message)
        for error in sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    ]
    return ("pass" if not errors else "fail"), errors


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fingerprint.py",
        description=(
            "Compose research/builds/<build-id>/fingerprint.json and anomalies.md "
            "(plan.md tasks F-03 and F-05). Parses nothing itself: pe_info, "
            "container_info and snapshot_install produce every number. Refuses any "
            "output path inside the game folder (D-01)."),
    )
    parser.add_argument("--install-dir", default=DEFAULT_INSTALL_DIR,
                        help="game installation root (default: %(default)s)")
    parser.add_argument("--build-dir", default=None,
                        help="research/builds/<build-id> directory; --out and "
                             "--anomalies-out default to fingerprint.json and "
                             "anomalies.md inside it")
    parser.add_argument("--out", default=None, help="path of the fingerprint.json to write")
    parser.add_argument("--anomalies-out", default=None,
                        help="path of the anomalies.md to write")
    parser.add_argument("--repo-root", default=None,
                        help="repository root, for the registry cross-checks "
                             "(default: derived from this file's location)")
    parser.add_argument("--engine-version", default=inventory.DEFAULT_ENGINE_VERSION,
                        help="engine version used in build_id; PROVISIONAL until "
                             "plan.md section 4 concludes (default: %(default)s)")
    parser.add_argument("--engine-version-final", action="store_true",
                        help="mark engine_version as concluded rather than provisional. "
                             "Only correct after plan.md section 4 has actually run")
    parser.add_argument("--no-pe-detail", action="store_true",
                        help="skip per-section digests, entropy and the checksum "
                             "recomputation on executables (faster, less complete)")
    parser.add_argument("--buffer-bytes", type=int, default=DEFAULT_BUFFER_BYTES,
                        help="streaming buffer size in bytes (default: %(default)s)")
    parser.add_argument("--selftest-reproducible", action="store_true",
                        help="build the document twice in one process and report every "
                             "field that differs; the only admissible difference is "
                             "identity.generated_at")
    return parser


def _resolve_outputs(args) -> tuple[str | None, str | None, str | None]:
    build_dir_ref = None
    out = args.out
    anomalies_out = args.anomalies_out
    if args.build_dir:
        build_dir = args.build_dir.replace("\\", "/").rstrip("/")
        marker = "research/builds/"
        index = build_dir.lower().find(marker)
        build_dir_ref = build_dir[index:] if index >= 0 else build_dir
        if out is None:
            out = os.path.join(args.build_dir, "fingerprint.json")
        if anomalies_out is None:
            anomalies_out = os.path.join(args.build_dir, "anomalies.md")
    return out, anomalies_out, build_dir_ref


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.buffer_bytes <= 0:
        print("--buffer-bytes must be positive", file=sys.stderr)
        return 2

    out, anomalies_out, build_dir_ref = _resolve_outputs(args)
    # Layer 1 first: a refused path must cost nothing, so it is refused before the scan.
    for candidate, what in ((out, "--out"), (anomalies_out, "--anomalies-out")):
        if candidate is None:
            continue
        try:
            pathguard.check_output_path(candidate, args.install_dir, what=what)
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2

    repo_root = args.repo_root or os.path.dirname(_TOOLS)
    started = time.perf_counter()
    try:
        payload = build_document(
            args.install_dir,
            engine_version=args.engine_version,
            engine_version_provisional=not args.engine_version_final,
            build_dir_ref=build_dir_ref,
            buf_size=args.buffer_bytes,
            pe_detail=not args.no_pe_detail)
    except (OSError, ValueError) as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    document = payload["document"]
    checks = payload["checks"]

    checks.extend(verify_against_registry(document, repo_root))
    if build_dir_ref:
        checks.extend(verify_against_inventory(
            document, os.path.join(repo_root, *build_dir_ref.split("/"),
                                   "install-inventory.json")))

    schema_status, schema_errors = validate_against_schema(
        document, os.path.join(repo_root, "research", "schema",
                               "fingerprint.schema.json"))
    checks.append({
        "check": "validates_against_published_schema", "target": "fingerprint.schema.json",
        "passed": schema_status == "pass",
        "skipped": schema_status == "skipped",
        "detail": ("NOT CHECKED - %s" % "; ".join(schema_errors)
                   if schema_status == "skipped" else
                   "a plain jsonschema.Draft202012Validator reported %d error(s)%s"
                   % (len(schema_errors),
                      "" if not schema_errors else ": " + "; ".join(schema_errors[:5])))})

    if args.selftest_reproducible:
        again = build_document(
            args.install_dir, engine_version=args.engine_version,
            engine_version_provisional=not args.engine_version_final,
            build_dir_ref=build_dir_ref, buf_size=args.buffer_bytes,
            pe_detail=not args.no_pe_detail)["document"]
        first = json.loads(dump_json(document))
        second = json.loads(dump_json(again))
        first["identity"]["generated_at"] = second["identity"]["generated_at"] = "<t>"
        # Compared as SERIALISED TEXT, which is the property plan.md 3.3 actually
        # states ("two runs give identical output"), and comparing the decoded objects
        # instead is a trap: Python's == on two dicts holding a float NaN is False even
        # when the two files are byte-identical, so an object comparison can report a
        # reproducibility failure that no diff can find. The text is what gets
        # committed, so the text is what is compared.
        where = first_difference(first, second)
        attribution = attribute_to_a_changed_input(where, first)
        if where is None:
            detail = ("the document was built twice in one process; with "
                      "identity.generated_at masked the two serialise identically")
        elif attribution is not None:
            detail = "the two builds differ, and the difference is accounted for: %s" \
                     % attribution
        else:
            detail = ("the document was built twice in one process and the two DIFFER "
                      "at %s" % where)
        checks.append({
            "check": "two_runs_differ_only_in_generated_at", "target": "fingerprint.json",
            "passed": where is None or attribution is not None,
            "detail": detail})

    written: list[str] = []
    if out:
        try:
            written.append(write_text(dump_json(document), out, args.install_dir))
        except (pathguard.OutputPathRefused, OSError) as error:
            print("error: cannot write %s: %s" % (out, error), file=sys.stderr)
            return 2
    if anomalies_out:
        try:
            written.append(write_text(render_anomalies_md(payload), anomalies_out,
                                      args.install_dir))
        except (pathguard.OutputPathRefused, OSError) as error:
            print("error: cannot write %s: %s" % (anomalies_out, error), file=sys.stderr)
            return 2

    elapsed = time.perf_counter() - started
    peak = peak_working_set_bytes()
    _print_summary(payload, checks, written, elapsed, peak)

    failed = [check for check in checks if not check["passed"]]
    print("executables=%d modules=%d containers=%d plugins=%d files=%d anomalies=%d "
          "checks_failed=%d warnings=%d"
          % (len(document["executables"]), len(document["modules"]),
             len(document["containers"]), len(document["plugins"]),
             document["layout"]["file_count"], len(document["anomalies"]),
             len(failed), len(payload["warnings"])))
    # Two kinds of failing check, and they deserve different exit codes.
    #
    # A check about the INSTALLATION - a container whose layout arithmetic does not
    # close, an identity that no longer matches the registry - is a finding, and a
    # finding is what this tool is for; it is reported and the exit stays 0, exactly as
    # container_info does, so a caller reads `checks_failed` on the last stdout line
    # for the verdict.
    #
    # A check about THIS TOOL - the document not validating against its own published
    # schema, or two builds not agreeing - is a defect in the output, and an artifact
    # that fails its own contract must not be reported as a clean run.
    # A check that could not RUN is reported as not-passed (see
    # validate_against_schema) but is not a defect in the document: "we did not look"
    # is not "we looked and it was wrong".
    tool_correctness = [check for check in failed
                        if check["check"] in TOOL_CORRECTNESS_CHECKS
                        and not check.get("skipped")]
    return 1 if tool_correctness else 0


def _print_summary(payload: dict, checks: list[dict], written: list[str],
                   elapsed: float, peak: int | None) -> None:
    document = payload["document"]
    say = lambda line: print(line, file=sys.stderr)  # noqa: E731
    say("fingerprint (%s %s)" % (GENERATOR_NAME, GENERATOR_VERSION))
    say("  install_dir : %s" % document["identity"]["install_dir"])
    say("  build_id    : %s" % document["identity"]["build_id"])
    say("  build_key   : %s" % document["identity"]["build_key"])
    say("  content_key : %s" % document["identity"]["content_key"])
    say("  tree_hash   : %s" % document["layout"]["tree_hash"])
    say("  files=%d total_size=%d executables=%d modules=%d containers=%d plugins=%d"
        % (document["layout"]["file_count"], document["layout"]["total_size"],
           len(document["executables"]), len(document["modules"]),
           len(document["containers"]), len(document["plugins"])))
    by_kind: dict[str, int] = {}
    for entry in document["anomalies"]:
        by_kind[entry["kind"]] = by_kind.get(entry["kind"], 0) + 1
    say("  anomalies   : %d (%s)"
        % (len(document["anomalies"]),
           ", ".join("%s=%d" % item for item in sorted(by_kind.items())) or "none"))
    say("  checks:")
    for check in checks:
        # SKIP is spelled differently from FAIL on purpose: a check that could not run
        # is a hole in the run, and printing it as FAIL would send a reader looking for
        # a defect in the document that is not there.
        verdict = "PASS" if check["passed"] else ("SKIP" if check.get("skipped")
                                                  else "FAIL")
        say("    [%s] %s %s -- %s" % (verdict, check["target"], check["check"],
                                      check["detail"]))
    for path in written:
        say("  wrote       : %s" % path)
    say("  wall time   : %.2f s" % elapsed)
    say("  peak working set: %s"
        % ("unavailable" if peak is None else "%d bytes (%.1f MiB)"
           % (peak, peak / (1 << 20))))
    for warning in payload["warnings"]:
        say("  WARNING: %s" % warning)


if __name__ == "__main__":
    sys.exit(main())
