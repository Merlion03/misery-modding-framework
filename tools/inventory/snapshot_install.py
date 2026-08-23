#!/usr/bin/env python3
"""Read-only baseline inventory of the MISERY game installation (plan.md R-05, 1.5 layer 3).

What this tool does
-------------------
* Walks the game installation tree **read-only** and records, for every file:
  path relative to the installation root (always with forward slashes so the JSON is
  stable across shells), size in bytes, mtime as an ISO-8601 UTC timestamp,
  sha256 and sha1.
* Reads the Steam application manifest (``appmanifest_<app_id>.acf``) with a small
  tolerant VDF parser and records appid / name / installdir / buildid / SizeOnDisk /
  LastUpdated / InstalledDepots / SharedDepots.
* Derives the build identity described in plan.md section 3.2:
  ``build_key`` (sha256 of the Shipping executable), ``content_key``
  (sha256 over the concatenated sha256 hex digests of all ``.utoc`` files, in sorted
  path order) and ``build_id``.

Safety properties (plan.md section 1.5, decision D-01)
-----------------------------------------------------
* The installation directory is only ever *read*. Files are opened with mode ``"rb"``
  and unbuffered ``buffering=0``; nothing is created, renamed, moved or deleted, and
  no file handle is ever opened for writing.
* The only path this tool writes to is the ``--out`` file, and layer 1 of the safety
  model is *enforced*, not merely requested of the caller: ``--out`` is passed through
  ``pathguard.check_output_path`` against the installation root before the tree is even
  walked. If it resolves to a location inside the installation -- including via a
  relative path, a different letter case, a trailing separator, an 8.3 short name, a
  junction, or the root itself -- the tool prints the offending path with a reference to
  D-01 and exits 2 without creating any file. The check is repeated inside
  ``write_json`` so the guard cannot be bypassed by calling that function directly.
* Hashing is streaming with a bounded 1 MiB buffer reused across reads, because one of
  the container files is ~4.3 GB. No file is ever read into memory as a whole; peak RSS
  stays far below the 64 MB budget of task F-04.
* Reading a file can still update the volume's *last access* time if the OS is
  configured to track it (Windows disables that by default). That is a property of the
  filesystem, not a write performed by this tool, and it does not affect content,
  size or mtime.

Scope: files only. Directories are not recorded as entries (symlinks are not
followed while walking), so ``file_count`` counts files, exactly like the recon
figure of 53.

Determinism
-----------
Output is JSON with sorted keys, indent 2, LF line endings, UTF-8 without BOM.
Two runs over an unchanged tree produce **byte-identical** output except for the
``generated_at`` field. That is the reproducibility requirement of M1.

Output protocol
---------------
* stderr: a human-readable summary (and loud warnings).
* stdout: exactly one line, the last one, ``build_id=<value>`` and nothing else,
  so a caller can capture the identity with a single read.

Exit codes: 0 success (a file-count mismatch only warns), 2 usage or I/O error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Never inline these
# checks: pathguard is the single place where "is this path inside the game
# installation" is decided, for this tool and for the discovery/content tools.
import pathguard  # noqa: E402  (sys.path is prepared just above)

GENERATOR_NAME = "tools/inventory/snapshot_install.py"
GENERATOR_VERSION = "1.0.0"
SCHEMA_ID = "misery.install-inventory/1"

DEFAULT_INSTALL_DIR = r"D:\Games\Steam\steamapps\common\MISERY"
DEFAULT_STEAM_ROOT = r"D:\Games\Steam"
DEFAULT_APP_ID = "2119830"

# plan.md ground truth: the pristine install contains exactly 53 files.
EXPECTED_FILE_COUNT = 53

# plan.md section 4 -- provisional until milestone M1 confirms it from two
# independent oracles. Overridable with --engine-version.
DEFAULT_ENGINE_VERSION = "5.4.4"

# Canonical identity source, plan.md section 3.2.
BUILD_KEY_RELPATH = "MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe"

# Bounded streaming buffer. 1 MiB keeps peak RSS tiny even for the 4.3 GB .ucas.
DEFAULT_BUFFER_BYTES = 1 << 20

UNKNOWN_BUILD_KEY_SEGMENT = "UNKNOWN_SHA12"
UNKNOWN_STEAM_BUILDID_SEGMENT = "UNKNOWNBUILD"


# --------------------------------------------------------------------------- #
# time helpers
# --------------------------------------------------------------------------- #

def iso_utc_from_ns(mtime_ns: int) -> str:
    """Format a nanosecond POSIX timestamp as ISO-8601 UTC with microseconds.

    Computed from integers only, so the formatting is bit-for-bit reproducible
    (no float rounding in the path).
    """
    seconds, remainder_ns = divmod(int(mtime_ns), 1_000_000_000)
    moment = datetime.fromtimestamp(seconds, timezone.utc)
    return "%s.%06dZ" % (moment.strftime("%Y-%m-%dT%H:%M:%S"), remainder_ns // 1000)


def iso_utc_from_epoch(epoch_seconds: int) -> str:
    """Format an integer POSIX epoch as ISO-8601 UTC, second precision."""
    moment = datetime.fromtimestamp(int(epoch_seconds), timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# streaming hashing
# --------------------------------------------------------------------------- #

def hash_file(path: str, buf_size: int = DEFAULT_BUFFER_BYTES) -> tuple[str, str]:
    """Return (sha256_hex, sha1_hex) for *path*, streaming with one bounded buffer.

    Both digests are computed in a single pass so a 4.3 GB file is read once.
    The buffer is allocated once and reused via readinto(), so peak additional
    memory is ``buf_size`` regardless of file size.
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    buffer = bytearray(buf_size)
    view = memoryview(buffer)
    with open(path, "rb", buffering=0) as handle:
        while True:
            read = handle.readinto(buffer)
            if not read:
                break
            chunk = view[:read]
            sha256.update(chunk)
            sha1.update(chunk)
    return sha256.hexdigest(), sha1.hexdigest()


# --------------------------------------------------------------------------- #
# tree scan
# --------------------------------------------------------------------------- #

def relative_posix(root: str, path: str) -> str:
    """Path of *path* relative to *root*, with forward slashes."""
    return os.path.relpath(path, root).replace(os.sep, "/").replace("\\", "/")


def scan_tree(
    install_dir: str,
    buf_size: int = DEFAULT_BUFFER_BYTES,
    warnings: list[str] | None = None,
    hash_files: bool = True,
) -> list[dict]:
    """Walk *install_dir* read-only and return the sorted list of file records.

    Each record has exactly the keys: path, size, mtime, mtime_epoch, sha256, sha1
    -- the row shape of install-inventory.schema.json#/$defs/inventory_file, which
    fingerprint.schema.json also references through ``layout.files``, so the shape
    is defined once and must not be renamed here.
    If a file cannot be read, sha256/sha1 are ``None`` and a warning is appended.
    Symlinks are not followed when walking directories.
    """
    if warnings is None:
        warnings = []
    records: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(install_dir, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            absolute = os.path.join(dirpath, name)
            relative = relative_posix(install_dir, absolute)
            try:
                stat = os.stat(absolute, follow_symlinks=False)
            except OSError as error:
                warnings.append("cannot stat %s: %s" % (relative, error))
                continue
            sha256_hex = None
            sha1_hex = None
            if hash_files:
                try:
                    sha256_hex, sha1_hex = hash_file(absolute, buf_size=buf_size)
                except OSError as error:
                    warnings.append("cannot read %s: %s" % (relative, error))
            records.append(
                {
                    "path": relative,
                    "size": int(stat.st_size),
                    "mtime": iso_utc_from_ns(stat.st_mtime_ns),
                    "mtime_epoch": int(stat.st_mtime_ns) // 1_000_000_000,
                    "sha256": sha256_hex,
                    "sha1": sha1_hex,
                }
            )
    records.sort(key=lambda record: record["path"])
    return records


# --------------------------------------------------------------------------- #
# tolerant VDF / ACF parser
# --------------------------------------------------------------------------- #

_VDF_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"'}
_VDF_MAX_DEPTH = 64


def _vdf_tokens(text: str) -> list[tuple[str, str]]:
    """Tokenize VDF/ACF text into ('brace', '{'|'}') and ('str', value) tokens.

    Tolerant by design: unterminated quotes, bare (unquoted) tokens and ``//``
    comments are all accepted instead of raising.
    """
    tokens: list[tuple[str, str]] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char in " \t\r\n":
            index += 1
            continue
        if char == "/" and index + 1 < length and text[index + 1] == "/":
            newline = text.find("\n", index)
            index = length if newline < 0 else newline + 1
            continue
        if char in "{}":
            tokens.append(("brace", char))
            index += 1
            continue
        if char == '"':
            index += 1
            parts: list[str] = []
            while index < length and text[index] != '"':
                if text[index] == "\\" and index + 1 < length:
                    nxt = text[index + 1]
                    parts.append(_VDF_ESCAPES.get(nxt, nxt))
                    index += 2
                    continue
                parts.append(text[index])
                index += 1
            index += 1  # closing quote, or one past the end when unterminated
            tokens.append(("str", "".join(parts)))
            continue
        end = index
        while end < length and text[end] not in ' \t\r\n{}"':
            end += 1
        tokens.append(("str", text[index:end]))
        index = end
    return tokens


def parse_vdf(text: str) -> dict:
    """Parse VDF/ACF text (nested braces with quoted key/value pairs) into a dict.

    Tolerant: stray braces, missing values and duplicate keys never raise. A
    duplicate key keeps the last occurrence. Nesting deeper than 64 levels is
    ignored rather than recursed into.
    """
    tokens = _vdf_tokens(text)

    def parse_block(position: int, depth: int) -> tuple[dict, int]:
        block: dict = {}
        while position < len(tokens):
            kind, value = tokens[position]
            if kind == "brace":
                position += 1
                if value == "}":
                    return block, position
                continue  # stray '{' -- skip it
            key = value
            position += 1
            if position >= len(tokens):
                block[key] = ""
                break
            next_kind, next_value = tokens[position]
            if next_kind == "brace" and next_value == "{":
                if depth + 1 > _VDF_MAX_DEPTH:
                    block[key] = {}
                    position += 1
                    continue
                child, position = parse_block(position + 1, depth + 1)
                block[key] = child
            elif next_kind == "brace" and next_value == "}":
                block[key] = ""
            else:
                block[key] = next_value
                position += 1
        return block, position

    root, _ = parse_block(0, 0)
    return root


def vdf_get(mapping, *keys, default=None):
    """Case-insensitive nested lookup in a parsed VDF dict."""
    current = mapping
    for key in keys:
        if not isinstance(current, dict):
            return default
        found = None
        lowered = key.lower()
        for candidate in current:
            if candidate.lower() == lowered:
                found = candidate
                break
        if found is None:
            return default
        current = current[found]
    return current


def _as_int(value):
    """Best-effort int() of a VDF string value; None when not an integer."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def appmanifest_path(steam_root: str, app_id: str = DEFAULT_APP_ID) -> str:
    return os.path.join(steam_root, "steamapps", "appmanifest_%s.acf" % app_id)


def parse_appmanifest_text(text: str) -> dict:
    """Extract the Steam fields required by plan.md sections 2.2 and 3.1.

    Returns a dict with keys: app_id, name, installdir, buildid, size_on_disk,
    last_updated_epoch, last_updated_utc, installed_depots, shared_depots.
    Every field is None / empty when absent, never a guessed value.
    """
    root = parse_vdf(text)
    state = vdf_get(root, "AppState")
    if not isinstance(state, dict):
        # Tolerate a manifest whose outer block name differs.
        state = root if isinstance(root, dict) else {}

    installed_depots: dict[str, dict] = {}
    depots_block = vdf_get(state, "InstalledDepots")
    if isinstance(depots_block, dict):
        for depot_id, depot_value in depots_block.items():
            if isinstance(depot_value, dict):
                installed_depots[str(depot_id)] = {
                    "manifest": vdf_get(depot_value, "manifest"),
                    "size": _as_int(vdf_get(depot_value, "size")),
                }
            else:
                installed_depots[str(depot_id)] = {
                    "manifest": None,
                    "size": None,
                    "value": depot_value,
                }

    shared_depots: dict[str, str] = {}
    shared_block = vdf_get(state, "SharedDepots")
    if isinstance(shared_block, dict):
        for depot_id, parent_app in shared_block.items():
            shared_depots[str(depot_id)] = (
                parent_app if isinstance(parent_app, str) else None
            )

    last_updated = _as_int(vdf_get(state, "LastUpdated"))
    return {
        "app_id": vdf_get(state, "appid"),
        "name": vdf_get(state, "name"),
        "installdir": vdf_get(state, "installdir"),
        "buildid": vdf_get(state, "buildid"),
        "size_on_disk": _as_int(vdf_get(state, "SizeOnDisk")),
        "last_updated_epoch": last_updated,
        "last_updated_utc": (
            iso_utc_from_epoch(last_updated) if last_updated is not None else None
        ),
        "installed_depots": installed_depots,
        "shared_depots": shared_depots,
    }


def read_appmanifest(path: str, warnings: list[str] | None = None) -> dict:
    """Read and parse an appmanifest .acf. Missing file is not an error."""
    if warnings is None:
        warnings = []
    record = {
        "appmanifest_path": os.path.normpath(path),
        "appmanifest_present": False,
        "app_id": None,
        "name": None,
        "installdir": None,
        "buildid": None,
        "size_on_disk": None,
        "last_updated_epoch": None,
        "last_updated_utc": None,
        "installed_depots": {},
        "shared_depots": {},
    }
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except FileNotFoundError:
        warnings.append("appmanifest not found: %s" % os.path.normpath(path))
        return record
    except OSError as error:
        warnings.append("cannot read appmanifest %s: %s" % (os.path.normpath(path), error))
        return record
    record.update(parse_appmanifest_text(text))
    record["appmanifest_present"] = True
    return record


# --------------------------------------------------------------------------- #
# build identity (plan.md section 3.2)
# --------------------------------------------------------------------------- #

def find_record(records: list[dict], relpath: str) -> dict | None:
    """Locate a file record by relative path, case-insensitively (Windows paths)."""
    lowered = relpath.lower()
    for record in records:
        if record["path"].lower() == lowered:
            return record
    return None


def compute_content_key(records: list[dict]) -> tuple[str | None, list[str]]:
    """content_key = sha256(concat(sha256 hex of every .utoc, sorted by path)).

    The concatenation uses the lowercase hex digests with no separator, encoded
    as ASCII. Returns (content_key or None, list of contributing paths).
    """
    utocs = sorted(
        (record for record in records if record["path"].lower().endswith(".utoc")),
        key=lambda record: record["path"],
    )
    inputs = [record["path"] for record in utocs]
    if not utocs or any(record["sha256"] is None for record in utocs):
        return None, inputs
    digest = hashlib.sha256()
    for record in utocs:
        digest.update(record["sha256"].lower().encode("ascii"))
    return digest.hexdigest(), inputs


def compute_tree_hash(records: list[dict]) -> str:
    """tree_hash per install-inventory.schema.json: sha256 over the canonical rows.

    For each row, sorted by path, the UTF-8 bytes ``'<path>\\n<size>\\n<sha256>\\n'``.
    Must equal fingerprint.json ``layout.tree_hash`` for the same installation, so
    the serialization is fixed here and may not be varied. An unreadable file
    contributes the literal ``UNKNOWN`` in place of its digest, so a tree with a
    read error can never collide with a fully hashed one.
    """
    digest = hashlib.sha256()
    for record in sorted(records, key=lambda item: item["path"]):
        sha256_hex = record["sha256"] or "UNKNOWN"
        line = "%s\n%d\n%s\n" % (record["path"], record["size"], sha256_hex)
        digest.update(line.encode("utf-8"))
    return digest.hexdigest()


def prefixed(digest_hex: str | None) -> str | None:
    """Render a digest as ``sha256:<hex>``, the KB-wide form of plan.md 3.2.

    kb-record.schema.json#/$defs/build_key and #/$defs/content_key both require
    the prefix, build-index.schema.json uses it as its property name, and
    plan.md itself writes ``"build_key": "sha256:..."``. build_id keeps slicing
    the BARE hex, because plan.md 3.2 ``build_key[0:12]`` means the digest.
    """
    return None if digest_hex is None else "sha256:%s" % digest_hex


def make_build_id(steam_buildid, engine_version: str, build_key: str | None) -> str:
    """build_id = "misery-" + steam_buildid + "-ue" + engine_version + "-" + build_key[:12].

    *build_key* is the BARE hex digest, never the ``sha256:``-prefixed form.
    """
    buildid_segment = (
        str(steam_buildid).strip()
        if steam_buildid not in (None, "")
        else UNKNOWN_STEAM_BUILDID_SEGMENT
    )
    key_segment = build_key[:12] if build_key else UNKNOWN_BUILD_KEY_SEGMENT
    return "misery-%s-ue%s-%s" % (buildid_segment, engine_version, key_segment)


# --------------------------------------------------------------------------- #
# inventory assembly
# --------------------------------------------------------------------------- #

def derive_steam_root(install_dir: str) -> str | None:
    """Derive the Steam root from a ``...\\steamapps\\common\\<installdir>`` path."""
    normalized = os.path.normpath(os.path.abspath(install_dir))
    parent = os.path.dirname(normalized)
    grandparent = os.path.dirname(parent)
    if (
        os.path.basename(parent).lower() == "common"
        and os.path.basename(grandparent).lower() == "steamapps"
    ):
        return os.path.dirname(grandparent)
    return None


def pick_primary_depot(installed_depots: dict) -> str | None:
    """Choose the primary content depot deterministically.

    The observed install has exactly one installed depot (2119831), so the rule
    only matters for robustness: largest ``size`` first, ties broken by the
    smallest numeric depot id. Never random, never dict-order dependent.
    """
    if not installed_depots:
        return None
    def sort_key(item):
        depot_id, info = item
        size = info.get("size")
        return (-(size if isinstance(size, int) else -1), int(depot_id))
    return sorted(installed_depots.items(), key=sort_key)[0][0]


def steam_block(raw: dict, warnings: list[str] | None = None) -> dict:
    """Project the rich appmanifest parse onto fingerprint.schema.json#/$defs/steam.

    The parser keeps a richer internal shape (every installed depot with its own
    manifest and size, and the parent app of every shared depot). The published
    ``steam`` block is the shape shared with fingerprint.json, so the extra
    detail that does not fit is surfaced through the document's ``notes`` instead
    of being invented into the schema.
    """
    installed = raw.get("installed_depots") or {}
    primary = pick_primary_depot(installed)
    primary_info = installed.get(primary, {}) if primary else {}
    if warnings is not None and len(installed) > 1:
        warnings.append(
            "appmanifest lists %d installed depots; depot_id/depot_manifest_id "
            "report the primary one (%s) -- see notes" % (len(installed), primary)
        )
    shared = raw.get("shared_depots") or {}
    return {
        "app_id": _as_int(raw.get("app_id")),
        "depot_id": _as_int(primary),
        "depot_manifest_id": primary_info.get("manifest"),
        "shared_depots": sorted(shared, key=lambda value: (len(value), value)),
        "steam_buildid": _as_int(raw.get("buildid")),
        "size_on_disk": _as_int(raw.get("size_on_disk")),
        "last_updated_epoch": _as_int(raw.get("last_updated_epoch")),
        "install_dir_name": raw.get("installdir"),
        "appmanifest_path": raw.get("appmanifest_path"),
    }


def build_inventory(
    install_dir: str,
    steam_root: str | None = None,
    engine_version: str = DEFAULT_ENGINE_VERSION,
    engine_version_source: str = "default",
    app_id: str = DEFAULT_APP_ID,
    expected_file_count: int | None = EXPECTED_FILE_COUNT,
    buf_size: int = DEFAULT_BUFFER_BYTES,
    hash_files: bool = True,
    diagnostics: dict | None = None,
) -> dict:
    """Produce the full install-inventory document for *install_dir*.

    Everything except ``generated_at`` is a pure function of the tree on disk and
    the arguments, which is what makes two consecutive runs byte-identical.

    The returned document conforms to install-inventory.schema.json, whose
    top-level object is closed. Per-run diagnostics therefore do not appear as
    document fields; when *diagnostics* is given it is filled with
    ``warnings`` (list) and ``file_count_matches_expected`` (bool or None) so the
    CLI can still shout about them on stderr.
    """
    install_dir = os.path.normpath(os.path.abspath(install_dir))
    if not os.path.isdir(install_dir):
        raise NotADirectoryError(install_dir)

    warnings: list[str] = []
    records = scan_tree(
        install_dir, buf_size=buf_size, warnings=warnings, hash_files=hash_files
    )

    if steam_root is None:
        steam_root = derive_steam_root(install_dir)
    steam: dict
    if steam_root is None:
        warnings.append(
            "steam root could not be derived from install dir and was not given; "
            "Steam metadata is UNKNOWN"
        )
        steam = {
            "appmanifest_path": None,
            "appmanifest_present": False,
            "app_id": None,
            "name": None,
            "installdir": None,
            "buildid": None,
            "size_on_disk": None,
            "last_updated_epoch": None,
            "last_updated_utc": None,
            "installed_depots": {},
            "shared_depots": {},
        }
    else:
        steam_root = os.path.normpath(os.path.abspath(steam_root))
        steam = read_appmanifest(appmanifest_path(steam_root, app_id), warnings)

    steam_raw = steam
    steam = steam_block(steam_raw, warnings)

    shipping = find_record(records, BUILD_KEY_RELPATH)
    build_key = shipping["sha256"] if shipping else None
    if shipping is None:
        warnings.append(
            "build_key source missing: %s -- build_id carries %s"
            % (BUILD_KEY_RELPATH, UNKNOWN_BUILD_KEY_SEGMENT)
        )
    elif build_key is None:
        warnings.append("build_key source unreadable: %s" % BUILD_KEY_RELPATH)

    content_key, content_inputs = compute_content_key(records)
    if content_key is None:
        warnings.append("content_key is UNKNOWN: no readable .utoc file found")

    file_count = len(records)
    count_matches = None
    if expected_file_count is not None:
        count_matches = file_count == expected_file_count
        if not count_matches:
            warnings.append(
                "file count %d differs from expected %d -- the installation is NOT "
                "the recon baseline; investigate before trusting any build identity"
                % (file_count, expected_file_count)
            )

    build_id = make_build_id(steam.get("steam_buildid"), engine_version, build_key)

    notes = _compose_notes(
        steam_raw=steam_raw,
        steam_root=steam_root,
        content_inputs=content_inputs,
        engine_version_source=engine_version_source,
        expected_file_count=expected_file_count,
        count_matches=count_matches,
        buf_size=buf_size,
        hash_files=hash_files,
        warnings=warnings,
    )

    if diagnostics is not None:
        diagnostics["warnings"] = warnings
        diagnostics["file_count_matches_expected"] = count_matches

    return {
        "generated_at": now_iso_utc(),
        "generator_version": GENERATOR_VERSION,
        "install_dir": install_dir,
        "build_id": build_id,
        "build_key": prefixed(build_key),
        "content_key": prefixed(content_key),
        "file_count": file_count,
        "total_size": sum(record["size"] for record in records),
        "tree_hash": compute_tree_hash(records),
        "steam": steam,
        # Only 'value' and 'provisional' are asserted: this tool reads the version
        # from its argument, not from the binary, so claiming cl / branch /
        # build_configuration / methods here would state an unverified provenance
        # as fact. Those fields are established in M1 (plan.md 4.2) and stay
        # absent, i.e. UNKNOWN, until then.
        #
        # 'provisional' is NOT hard-coded. It was, and that made this file disagree
        # with research/unreal/engine-version.json once M1.5 concluded -- the same
        # fact carrying two grades in two artifacts, which plan.md 18.3 item 6 makes
        # a blocker for closing a milestone. The flag now follows the authority, so
        # the two cannot drift again. Absent authority means still provisional: a
        # fresh clone has no conclusion to read and must not pretend otherwise.
        "engine_version": {
            "value": engine_version,
            "provisional": engine_version_is_provisional(),
        },
        "files": records,
        "notes": notes,
    }


# --- engine version authority (plan.md 4.2, section 18.3 item 6) -------------
#
# research/unreal/engine-version.json is the ONE place the engine claim is
# concluded. This tool records the version as a convenience duplicate, so it must
# follow that conclusion rather than carry an opinion of its own. plan.md 4.2 sets
# the bar for a settled claim at confidence 0.90 with at least one text and one
# data-format source; below it the value stays provisional.
ENGINE_AUTHORITY_RELPATH = os.path.join("research", "unreal", "engine-version.json")
ENGINE_SETTLED_AT = 0.90


def _engine_authority_confidence():
    """Confidence the authority assigns to engine_version, or None.

    None means "no conclusion to read" -- an absent, unreadable or malformed
    authority, or one that has not concluded. Every one of those keeps the value
    provisional, because a fresh clone has nothing to read and must not pretend.
    """
    # tools/inventory/snapshot_install.py -> tools/inventory -> tools -> repo root.
    # Three levels, not two: two lands in tools/ and the read silently fails open
    # to "provisional", which looks like a conclusion rather than a missing file.
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    path = os.path.join(root, ENGINE_AUTHORITY_RELPATH)
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return None
    # Shape as published: $.claim.engine_version.evidence.confidence. The claim
    # container is named "claim", singular; "claims" is accepted only so a rename
    # does not silently turn a settled version back into a provisional one -- a
    # missing key here fails OPEN to provisional, which is the safe direction but
    # also the direction that hides a typo.
    claims = document.get("claim")
    if not isinstance(claims, dict):
        claims = document.get("claims")
    if not isinstance(claims, dict):
        return None
    node = claims.get("engine_version")
    if not isinstance(node, dict):
        return None
    evidence = node.get("evidence")
    source = evidence if isinstance(evidence, dict) else node
    value = source.get("confidence")
    return value if isinstance(value, (int, float)) else None


def engine_version_is_provisional() -> bool:
    confidence = _engine_authority_confidence()
    return confidence is None or confidence < ENGINE_SETTLED_AT


def _engine_provisional_note() -> str:
    confidence = _engine_authority_confidence()
    if confidence is None:
        return ("provisional: research/unreal/engine-version.json was not readable "
                "from here, so no conclusion could be followed.")
    if confidence < ENGINE_SETTLED_AT:
        return ("provisional: the authority concludes at confidence %.2f, below the "
                "plan.md 4.2 bar of %.2f." % (confidence, ENGINE_SETTLED_AT))
    return ("settled: research/unreal/engine-version.json concludes at confidence "
            "%.2f, at or above the plan.md 4.2 bar of %.2f." % (confidence, ENGINE_SETTLED_AT))


def _compose_notes(
    steam_raw: dict,
    steam_root: str | None,
    content_inputs: list[str],
    engine_version_source: str,
    expected_file_count: int | None,
    count_matches: bool | None,
    buf_size: int,
    hash_files: bool,
    warnings: list[str],
) -> str:
    """Build the 'notes' string.

    install-inventory.schema.json closes the top-level object
    (``additionalProperties: false``) and documents 'notes' as the place for the
    content_key ordering rule, skipped files, mtime handling and I/O errors. So
    the per-run diagnostics that have no typed home are recorded here rather
    than invented as extra top-level keys.
    """
    lines = [
        "generator: %s %s." % (GENERATOR_NAME, GENERATOR_VERSION),
        "content_key ordering rule: sha256 over the concatenated lowercase sha256 "
        "hex digests of every .utoc, ASCII, no separator, sorted by normalized "
        "path ascending; inputs in order: %s."
        % (", ".join(content_inputs) if content_inputs else "none"),
        "tree_hash rule: sha256 over '<path>\\n<size>\\n<sha256>\\n' per row, "
        "UTF-8, rows sorted by path ascending.",
        "mtime handling: every mtime is UTC with microsecond precision, derived "
        "from st_mtime_ns by integer arithmetic, so no float rounding enters the "
        "document; mtime_epoch is the same instant truncated to whole seconds.",
        "hashing: %s, sha256 and sha1 in a single streaming pass with a %d byte "
        "buffer." % ("enabled" if hash_files else "DISABLED (digests are null)", buf_size),
        "engine_version source: %s; %s cl, branch and build_configuration "
        "are UNKNOWN to this tool and deliberately omitted."
        % (engine_version_source, _engine_provisional_note()),
        "steam_root: %s." % (steam_root if steam_root else "UNKNOWN"),
        "file_count check: expected %s, %s."
        % (
            expected_file_count if expected_file_count is not None else "not checked",
            "matches" if count_matches else ("MISMATCH" if count_matches is False else "n/a"),
        ),
    ]
    shared = steam_raw.get("shared_depots") or {}
    if shared:
        lines.append(
            "shared_depots parent apps (the schema stores depot ids only): %s."
            % ", ".join("%s from app %s" % (depot, shared[depot]) for depot in sorted(shared))
        )
    installed = steam_raw.get("installed_depots") or {}
    if len(installed) > 1:
        lines.append(
            "installed depots beyond the primary one: %s."
            % ", ".join(sorted(installed))
        )
    if not steam_raw.get("appmanifest_present", False):
        lines.append("appmanifest was NOT present; every steam value is UNKNOWN.")
    lines.append(
        "warnings: %s" % ("; ".join(warnings) if warnings else "none.")
    )
    return " ".join(lines)


def dump_json(document: dict) -> str:
    """Serialize deterministically: sorted keys, indent 2, LF, trailing newline."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_json(document: dict, out_path: str, install_dir: str | None = None) -> str:
    """Write *document* to *out_path*, refusing any path inside the installation.

    The guard (plan.md 1.5 layer 1, D-01) runs before the file is opened, so a
    refused path leaves nothing behind -- not even a truncated file. *install_dir*
    defaults to the ``install_dir`` recorded in *document*, which is the root the
    document describes, so the check is always made against the right tree even
    when this function is called directly rather than through the CLI.

    Returns the resolved path that was actually written.
    """
    root = install_dir or document.get("install_dir") or DEFAULT_INSTALL_DIR
    target = pathguard.check_output_path(out_path, root, what="--out")
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dump_json(document))
    return target


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _print_summary(document: dict, out_path: str | None,
                   diagnostics: dict | None = None) -> None:
    diagnostics = diagnostics or {}
    say = lambda line: print(line, file=sys.stderr)
    steam = document["steam"]
    say("install-inventory snapshot (%s %s)" % (GENERATOR_NAME, GENERATOR_VERSION))
    say("  install_dir      : %s" % document["install_dir"])
    say("  appmanifest      : %s%s" % (
        steam["appmanifest_path"],
        "" if steam["appmanifest_path"] else "  (ABSENT)",
    ))
    say("  steam buildid    : %s" % steam["steam_buildid"])
    say("  steam depot      : %s manifest %s" % (
        steam["depot_id"], steam["depot_manifest_id"]))
    say("  files            : %d" % document["file_count"])
    say("  total size       : %d bytes" % document["total_size"])
    say("  tree_hash        : %s" % document["tree_hash"])
    say("  build_key        : %s" % document["build_key"])
    say("  content_key      : %s" % document["content_key"])
    say("  engine_version   : %s (provisional)" % document["engine_version"]["value"])
    say("  build_id         : %s" % document["build_id"])
    say("  output           : %s" % (out_path if out_path else "<not written>"))
    if diagnostics.get("warnings"):
        say("")
        for warning in diagnostics["warnings"]:
            say("  WARNING: %s" % warning)
        if diagnostics.get("file_count_matches_expected") is False:
            say("  " + "!" * 72)
            say("  !!! FILE COUNT MISMATCH -- see the warning above. Snapshot written")
            say("  !!! anyway so the deviation itself is recorded, but do not treat")
            say("  !!! this tree as the pristine baseline without an explanation.")
            say("  " + "!" * 72)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="snapshot_install.py",
        description=(
            "Read-only baseline inventory of the MISERY installation. Refuses any "
            "--out path that resolves inside the game folder (plan.md D-01, "
            "safety model 1.5 layer 1)."
        ),
    )
    parser.add_argument(
        "--install-dir",
        default=DEFAULT_INSTALL_DIR,
        help="game installation root (default: %(default)s)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help=(
            "path of the JSON file to write; when omitted nothing is written. "
            "A path inside --install-dir is refused (exit 2) before any work is "
            "done -- see plan.md 1.5 layer 1 / D-01"
        ),
    )
    parser.add_argument(
        "--engine-version",
        default=None,
        help=(
            "Unreal Engine version string used in build_id "
            "(default: %s, provisional until M1)" % DEFAULT_ENGINE_VERSION
        ),
    )
    parser.add_argument(
        "--steam-root",
        default=None,
        help="Steam root holding steamapps/appmanifest_<app-id>.acf (default: derived)",
    )
    parser.add_argument(
        "--app-id",
        default=DEFAULT_APP_ID,
        help="Steam AppID of the manifest to read (default: %(default)s)",
    )
    parser.add_argument(
        "--expected-file-count",
        type=int,
        default=EXPECTED_FILE_COUNT,
        help="expected number of files; a mismatch warns loudly (default: %(default)s)",
    )
    parser.add_argument(
        "--buffer-bytes",
        type=int,
        default=DEFAULT_BUFFER_BYTES,
        help="streaming hash buffer size in bytes (default: %(default)s)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.buffer_bytes <= 0:
        print("--buffer-bytes must be positive", file=sys.stderr)
        return 2

    # Layer 1 (plan.md 1.5) is checked here, before the tree is walked: a full
    # snapshot takes minutes, and refusing afterwards would waste them. write_json
    # checks again at the moment of writing, so the guard holds for direct callers
    # of that function too.
    out_path = None
    if args.out:
        try:
            out_path = pathguard.check_output_path(
                args.out, args.install_dir, what="--out"
            )
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2

    engine_version = args.engine_version or DEFAULT_ENGINE_VERSION
    engine_source = "cli" if args.engine_version else "default"

    diagnostics: dict = {}
    try:
        document = build_inventory(
            install_dir=args.install_dir,
            steam_root=args.steam_root,
            engine_version=engine_version,
            engine_version_source=engine_source,
            app_id=args.app_id,
            expected_file_count=args.expected_file_count,
            buf_size=args.buffer_bytes,
            diagnostics=diagnostics,
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

    _print_summary(document, out_path, diagnostics)
    # stdout carries exactly one line, and it is the last thing printed.
    print("build_id=%s" % document["build_id"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
