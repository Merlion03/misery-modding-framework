#!/usr/bin/env python3
"""Deterministic, read-only discovery of the MISERY game installation (plan.md 2).

Implements the seven-step algorithm of plan.md 2.1 in exactly that order and emits the
document described by plan.md 2.2, validated by research/schema/install.schema.json:

    1. explicit override      : MISERY_GAME_DIR, or research/config/local.json
    2. Steam registry         : HKCU\\Software\\Valve\\Steam -> SteamPath
                                HKLM\\SOFTWARE\\WOW6432Node\\Valve\\Steam -> InstallPath
    3. library enumeration    : <SteamPath>\\steamapps\\libraryfolders.vdf -> every "path"
    4. app manifest           : <library>\\steamapps\\appmanifest_2119830.acf
    5. install dir            : <library>\\steamapps\\common\\<installdir>
    6. validation             : MISERY\\Binaries\\Win64\\MISERY-Win64-Shipping.exe
                                MISERY\\Content\\Paks\\global.utoc
    7. fallback               : Uninstall registry keys; full-disk search only with --deep

Standard library only (constraint of the M0 toolchain: this script must run on a bare
CPython with no site-packages, because it is the first thing a fresh clone runs).

Safety properties
-----------------
* Decision D-01: the installation directory is a read-only research target. This tool
  opens nothing inside it for writing and creates nothing there. It only calls
  ``os.path.exists`` / ``os.scandir`` / ``os.stat``. The single path it writes to is
  ``--out``, and it refuses to write inside the installation.
* Nothing is hashed and no container body is read: discovery answers "where is it and is
  it really it", not "what is in it". File hashes are the job of
  ``tools/inventory/snapshot_install.py`` and of the fingerprint stage (plan.md 3.2).

Privacy (constraint C-13, public repository)
-------------------------------------------
* ``LastOwner`` from the Steam app manifest is a Steam account id (a SteamID64,
  i.e. personal data identifying the machine's owner). It is never copied into the
  output. The manifest reader whitelists the fields it extracts instead of copying the
  parsed manifest, so the field cannot leak by accident, and ``check_privacy`` refuses
  to emit a document that contains the value anyway. plan.md 10.5 states the same rule
  for the knowledge base: "LastOwner и подобные поля - персональные данные, в knowledge
  base не переносятся (C-13)".
* Any emitted path that points inside the current user's profile is rewritten to the
  ``%LOCALAPPDATA%`` / ``%APPDATA%`` / ``%USERPROFILE%`` form, never expanded.

Evidence
--------
``discovery_trace`` records, per step of plan.md 2.1, what was inspected, what was found
and why a step was skipped, together with the oracle (plan.md 10.5) that the step's
result belongs to: ``filesystem`` for existence and sizes, ``steam-metadata`` for
anything Steam wrote about the app. The trace is the evidence for the ``method`` field:
without it, "discovery found the installation" is an unverifiable assertion.

Output protocol
---------------
* stderr: human readable summary, warnings, validation failures.
* stdout: with ``--out <file>`` a single line ``install_dir=<path>``; without ``--out``
  (or with ``--out -``) the JSON document itself.
* Exit code 0 only when an installation was found AND validation step 6 passed;
  1 otherwise; 2 on usage/I-O error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import string
import sys
from datetime import datetime, timezone

# tools/ is not a Python package (these scripts are run directly, not as -m modules),
# so the sibling directory holding the shared guard is put on sys.path explicitly.
# pathguard is the SINGLE implementation of "is this path inside the installation"
# (plan.md 1.5 layer 1, decision D-01); it is imported, never copy-pasted. The inline
# copy that used to live in write_document() below was built on os.path.abspath, which
# does not resolve symlinks or NTFS junctions, so an --out path through a junction
# aimed at the installation was accepted and the file was written inside the tree.
_PATHGUARD_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "inventory")
if _PATHGUARD_DIR not in sys.path:
    sys.path.insert(0, _PATHGUARD_DIR)

import pathguard  # noqa: E402  (sys.path is prepared just above)

GENERATOR_NAME = "tools/discovery/find_misery.py"
GENERATOR_VERSION = "1.0.0"

# plan.md 2.1: the Steam AppID of MISERY.
DEFAULT_APP_ID = 2119830

# plan.md 2.1 step 6 -- the two files whose presence defines "this really is MISERY".
# Native Windows form with backslashes, because install.schema.json keeps paths in the
# plan.md 2.2 form. Container paths use forward slashes (see enumerate_containers).
SHIPPING_EXE_REL = "MISERY\\Binaries\\Win64\\MISERY-Win64-Shipping.exe"
GLOBAL_UTOC_REL = "MISERY\\Content\\Paks\\global.utoc"
PAKS_DIR_REL = "MISERY\\Content\\Paks"

# Decision D-04: the root MISERY.exe is the UE BootstrapPackagedGame shim, the Shipping
# image is the primary analysis target, and MISERY\Binaries\Win64\MISERY.exe (282 MB,
# 10 PE sections including .uedbg, anomaly A-05) is a read-only oracle only -- it must
# never be reported as the primary executable.
LAUNCHER_SHIM_REL = "MISERY.exe"
SECONDARY_EXE_RELS = ("MISERY\\Binaries\\Win64\\MISERY.exe",)

# plan.md 2.2 -- per-user directories. Deliberately kept in %VAR% form (C-13).
USER_CONFIG_DIR = "%LOCALAPPDATA%\\MISERY\\Saved\\Config\\Windows"
USER_SAVE_DIR = "%LOCALAPPDATA%\\MISERY\\Saved\\SaveGames"
CRASH_DIR = "%LOCALAPPDATA%\\MISERY\\Saved\\Crashes"
LOG_DIR = "%LOCALAPPDATA%\\MISERY\\Saved\\Logs"

# research/config/local.json is honoured if it exists but is NEVER created by this tool.
LOCAL_CONFIG_RELPATH = os.path.join("research", "config", "local.json")

ENV_OVERRIDE = "MISERY_GAME_DIR"

CONTAINER_KINDS = {
    ".utoc": "utoc",
    ".ucas": "ucas",
    ".pak": "pak",
    ".sig": "usig",
    ".usig": "usig",
}

# Guard rails for the untrusted-input parsers and for --deep.
MAX_VDF_DEPTH = 32
MAX_VDF_BYTES = 8 << 20
DEEP_MAX_DEPTH = 6

# Directories a full-disk search must not descend into: huge, never a Steam library,
# and walking them turns --deep from slow into useless.
DEEP_SKIP_DIRS = {
    "$recycle.bin",
    "system volume information",
    "windows",
    "winsxs",
    "$windows.~bt",
    "$windows.~ws",
    "node_modules",
    ".git",
}


class DiscoveryError(Exception):
    """Unrecoverable I/O or usage problem (exit code 2)."""


class VdfError(Exception):
    """Malformed Valve KeyValues text."""


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def now_iso_utc() -> str:
    """Current time, ISO-8601 UTC with a trailing Z and whole seconds."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_path(path: str) -> str:
    r"""Native Windows form: backslashes, no trailing separator, upper-case drive letter.

    The registry hands out ``d:/games/steam`` and libraryfolders.vdf hands out
    ``D:\\Games\\Steam``; both must collapse to one spelling so the output is stable.
    """
    if not path:
        return path
    text = path.strip().strip('"')
    text = text.replace("/", "\\")
    while "\\\\" in text[2:]:
        text = text[:2] + text[2:].replace("\\\\", "\\")
    if len(text) > 3 and text.endswith("\\"):
        text = text.rstrip("\\")
    if len(text) >= 2 and text[1] == ":":
        text = text[0].upper() + text[1:]
    return text


def canonical_case(path: str) -> str:
    r"""Fix only the CASE of an existing path, component by component.

    HKCU\\Software\\Valve\\Steam\\SteamPath holds ``d:/games/steam`` on the research
    machine while libraryfolders.vdf holds ``D:\Games\Steam``. Both name one directory,
    and emitting both spellings in one document would make a reader wonder whether they
    are two. NTFS is case-insensitive, so the filesystem is the authority on the answer.

    Deliberately not ``pathlib.Path.resolve()``: that also follows junctions, symlinks and
    substituted drives, so a Steam library reached through ``subst`` would be silently
    rewritten into a path the user never typed. Only the case is touched here.
    """
    normalized = normalize_path(path)
    if normalized.startswith("\\\\"):
        return normalized  # UNC share: not worth walking, and the parent may not list
    if not normalized or not os.path.exists(normalized):
        return normalized
    parts = [part for part in normalized.split("\\") if part != ""]
    if not parts:
        return normalized
    resolved = [parts[0].upper()]
    current = resolved[0] + "\\"
    for part in parts[1:]:
        chosen = part
        try:
            for entry in os.listdir(current):
                if entry.lower() == part.lower():
                    chosen = entry
                    break
        except OSError:
            pass
        resolved.append(chosen)
        current = current + chosen + "\\"
    return "\\".join(resolved)


def join_native(*parts: str) -> str:
    """Join path components in the native Windows form, independent of os.sep."""
    cleaned = [normalize_path(parts[0])]
    for part in parts[1:]:
        cleaned.append(part.replace("/", "\\").strip("\\"))
    return "\\".join([piece for piece in cleaned if piece != ""])


def profile_prefixes() -> list[tuple[str, str]]:
    """(expanded, placeholder) pairs, longest expansion first.

    LOCALAPPDATA is a child of USERPROFILE, so ordering by descending length is what
    makes ``%LOCALAPPDATA%`` win over ``%USERPROFILE%\\AppData\\Local``.
    """
    pairs = []
    seen = set()
    for name in ("LOCALAPPDATA", "APPDATA", "USERPROFILE"):
        value = os.environ.get(name)
        if not value:
            continue
        # Both forms of the same directory. Windows may hand the variable out in 8.3
        # short form (C:\Users\RUNNER~1\AppData\Local) while a path we are privatising
        # arrived resolved to its long form (C:\Users\runneradmin\...), or the reverse.
        # Comparing only the raw value then finds no prefix, the literal profile path
        # survives into the document, and the C-13 guard refuses to emit anything --
        # so the tool becomes unusable on that host rather than merely imprecise.
        # A GitHub Windows runner is exactly such a host; that is where this surfaced.
        for form in (value, _resolved_or_none(value)):
            if not form:
                continue
            expanded = normalize_path(form)
            key = expanded.lower()
            if key in seen:
                continue
            seen.add(key)
            pairs.append((expanded, "%" + name + "%"))
    pairs.sort(key=lambda item: len(item[0]), reverse=True)
    return pairs


def _resolved_or_none(path: str) -> str | None:
    """realpath(path), or None when it cannot be resolved.

    Resolution touches the filesystem, so it can fail on a stale or unmounted
    directory. A failure here must not take down privatisation: returning None
    just means this form contributes no prefix.
    """
    try:
        return os.path.realpath(path)
    except OSError:
        return None


def privatize_path(path: str | None) -> str | None:
    r"""Rewrite a path that points into the user profile into %VAR% form (C-13).

    ``C:\Users\<name>\AppData\Local\MISERY`` becomes ``%LOCALAPPDATA%\MISERY``. Paths
    outside the profile are returned unchanged: the repository is public, so a literal
    profile path is a leak, while ``D:\Games\Steam`` is not.
    """
    if not path:
        return path
    text = normalize_path(path)
    lowered = text.lower()
    for expanded, placeholder in profile_prefixes():
        if not expanded:
            continue
        low = expanded.lower()
        if lowered == low:
            return placeholder
        if lowered.startswith(low + "\\"):
            return placeholder + text[len(expanded):]
    return text


def forbidden_strings(extra: list[str] | None = None) -> list[str]:
    """Values that must never appear in the emitted document (C-13).

    Profile directories and the account name are machine-identifying; ``extra`` carries
    the Steam ``LastOwner`` value when the app manifest contained one.
    """
    values = []
    seen = set()
    for name in ("LOCALAPPDATA", "APPDATA", "USERPROFILE"):
        value = os.environ.get(name)
        if not value:
            continue
        # Both the raw and the resolved form, for the reason given in profile_prefixes.
        # Here the asymmetry is the more dangerous half: if the variable is long-form
        # and a short-form profile path reaches the document, a guard that knows only
        # the long form MISSES the leak. An over-eager guard costs a refusal; a guard
        # that misses publishes a user's directory layout to a public repository.
        for form in (value, _resolved_or_none(value)):
            if not form:
                continue
            expanded = normalize_path(form)
            if expanded.lower() in seen:
                continue
            seen.add(expanded.lower())
            values.append(expanded)
    username = os.environ.get("USERNAME") or ""
    # A user name that happens to be a common word (e.g. "Steam") would make this a
    # false positive; that is the safe direction to fail in for a public repository.
    if len(username) >= 3:
        values.append(username)
    for value in extra or []:
        if value:
            values.append(value)
    return values


def locate_in_document(node, needle: str, path: str = "$") -> list[str]:
    """JSON key paths whose value contains ``needle`` (case-insensitive).

    Used only to make a C-13 refusal actionable: the offending VALUE is never printed,
    but the field carrying it has to be nameable or the guard cannot be acted on. Keys
    are reported, not values, so nothing sensitive reaches the log.
    """
    hits = []
    low = needle.lower()
    if isinstance(node, dict):
        for key, value in node.items():
            hits.extend(locate_in_document(value, needle, "%s.%s" % (path, key)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            hits.extend(locate_in_document(value, needle, "%s[%d]" % (path, index)))
    elif isinstance(node, str):
        for spelling in {needle, needle.replace("\\", "/")}:
            if spelling.lower() in node.lower():
                hits.append(path)
                break
    return hits


def check_privacy(text: str, extra: list[str] | None = None) -> list[str]:
    r"""Return every forbidden value that occurs in ``text`` (case-insensitive).

    ``text`` is JSON, where ``C:\Users\x`` is spelled ``C:\\Users\\x``, so a needle
    containing a single backslash would never match the haystack. Every candidate is
    therefore tested in three spellings: literal, JSON-escaped, and forward-slashed.

    The final pattern is a backstop that does not depend on knowing the field name: a
    SteamID64 is 17 digits beginning with 7656119, so any such token in the output is an
    account id regardless of which Steam field a future client put it in.
    """
    lowered = text.lower()
    hits = []
    for value in forbidden_strings(extra):
        spellings = {value, value.replace("\\", "\\\\"), value.replace("\\", "/")}
        for spelling in spellings:
            if spelling.lower() in lowered:
                hits.append(value)
                break
    match = re.search(r"(?<!\d)7656119\d{10}(?!\d)", text)
    if match:
        hits.append(match.group(0))
    return sorted(set(hits))


# ---------------------------------------------------------------------------
# Valve KeyValues (VDF / ACF) parsing -- plan.md 2.1 steps 3 and 4
# ---------------------------------------------------------------------------


def _vdf_tokens(text: str) -> list[tuple[str, str]]:
    """Tokenize KeyValues text into ('string'|'open'|'close', value) pairs."""
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
        if char == "{":
            tokens.append(("open", "{"))
            index += 1
            continue
        if char == "}":
            tokens.append(("close", "}"))
            index += 1
            continue
        if char == '"':
            index += 1
            buffer: list[str] = []
            closed = False
            while index < length:
                current = text[index]
                if current == "\\" and index + 1 < length:
                    following = text[index + 1]
                    buffer.append(
                        {"n": "\n", "t": "\t", "\\": "\\", '"': '"'}.get(
                            following, following
                        )
                    )
                    index += 2
                    continue
                if current == '"':
                    index += 1
                    closed = True
                    break
                buffer.append(current)
                index += 1
            if not closed:
                raise VdfError("unterminated quoted string")
            tokens.append(("string", "".join(buffer)))
            continue
        end = index
        while end < length and text[end] not in ' \t\r\n"{}':
            end += 1
        tokens.append(("string", text[index:end]))
        index = end
    return tokens


def parse_vdf(text: str) -> dict:
    """Parse KeyValues text into nested dicts. Leaf values stay strings.

    Tolerant on purpose: libraryfolders.vdf and appmanifest_*.acf are written by Steam,
    not by us, and their exact shape has changed between Steam versions. A duplicate key
    keeps the last occurrence, which is what Steam's own loader does.
    """
    if len(text) > MAX_VDF_BYTES:
        raise VdfError("KeyValues document larger than %d bytes" % MAX_VDF_BYTES)
    tokens = _vdf_tokens(text)

    def parse_block(position: int, depth: int) -> tuple[dict, int]:
        if depth > MAX_VDF_DEPTH:
            raise VdfError("KeyValues nesting deeper than %d" % MAX_VDF_DEPTH)
        result: dict = {}
        while position < len(tokens):
            kind, value = tokens[position]
            if kind == "close":
                return result, position + 1
            if kind == "open":
                raise VdfError("unexpected '{' where a key was expected")
            key = value
            position += 1
            if position >= len(tokens):
                result[key] = ""
                return result, position
            next_kind, next_value = tokens[position]
            if next_kind == "open":
                child, position = parse_block(position + 1, depth + 1)
                result[key] = child
            elif next_kind == "close":
                result[key] = ""
                return result, position + 1
            else:
                result[key] = next_value
                position += 1
        return result, position

    document, _ = parse_block(0, 0)
    return document


def vdf_get(mapping, *keys, default=None):
    """Case-insensitive nested lookup: Steam's key casing is not contractual."""
    current = mapping
    for key in keys:
        if not isinstance(current, dict):
            return default
        found = None
        wanted = key.lower()
        for candidate in current:
            if candidate.lower() == wanted:
                found = candidate
                break
        if found is None:
            return default
        current = current[found]
    return current


def read_text_file(path: str) -> str:
    """Read a Steam metadata file. UTF-8 with a lenient fallback: ACF files are ASCII in
    practice but a game name can carry anything."""
    with open(path, "rb") as handle:
        raw = handle.read(MAX_VDF_BYTES + 1)
    if len(raw) > MAX_VDF_BYTES:
        raise VdfError("%s larger than %d bytes" % (path, MAX_VDF_BYTES))
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.decode("utf-8", errors="replace")


def _as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# step 1 -- explicit override
# ---------------------------------------------------------------------------


def read_local_config(repo_root: str) -> tuple[str | None, dict | None, str | None]:
    """Read research/config/local.json if it exists. Never creates it.

    Returns (path, parsed, error). The file is developer-local (it is git-ignored) and is
    the documented way to point the toolchain at an installation on a machine where Steam
    is absent or where a second copy of the build is being compared.
    """
    path = os.path.join(repo_root, LOCAL_CONFIG_RELPATH)
    if not os.path.isfile(path):
        return path, None, None
    try:
        with open(path, "rb") as handle:
            parsed = json.loads(handle.read().decode("utf-8-sig"))
    except (OSError, ValueError) as exc:
        return path, None, str(exc)
    if not isinstance(parsed, dict):
        return path, None, "top level value is not an object"
    return path, parsed, None


# ---------------------------------------------------------------------------
# step 2 -- Steam registry
# ---------------------------------------------------------------------------

REGISTRY_STEAM_KEYS = (
    ("HKCU", "Software\\Valve\\Steam", "SteamPath"),
    ("HKLM", "SOFTWARE\\WOW6432Node\\Valve\\Steam", "InstallPath"),
    ("HKLM", "SOFTWARE\\Valve\\Steam", "InstallPath"),
)


def _winreg():
    """Return the winreg module, or None when it is unavailable.

    Absence must be handled and not crash: the tests run without touching the real
    registry, and the tool is expected to degrade to steps 1/3 with an explicit
    --steam-root on a machine without Steam.
    """
    try:
        import winreg  # noqa: PLC0415 -- optional, Windows only
    except ImportError:
        return None
    return winreg


def registry_steam_roots() -> tuple[list[tuple[str, str]], list[str]]:
    """plan.md 2.1 step 2. Returns ([(source, path)], notes)."""
    winreg = _winreg()
    if winreg is None:
        return [], ["winreg unavailable (not a Windows CPython): registry step skipped"]
    hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    found: list[tuple[str, str]] = []
    notes: list[str] = []
    for hive_name, subkey, value_name in REGISTRY_STEAM_KEYS:
        source = "%s\\%s\\%s" % (hive_name, subkey, value_name)
        try:
            with winreg.OpenKey(hives[hive_name], subkey) as handle:
                raw, _kind = winreg.QueryValueEx(handle, value_name)
        except FileNotFoundError:
            notes.append("%s: absent" % source)
            continue
        except OSError as exc:
            notes.append("%s: unreadable (%s)" % (source, exc))
            continue
        path = canonical_case(str(raw))
        if not path:
            notes.append("%s: empty value" % source)
            continue
        exists = os.path.isdir(path)
        notes.append(
            "%s = %s (%s)"
            % (source, privatize_path(path), "directory exists" if exists else "MISSING")
        )
        if exists:
            found.append((source, path))
    return found, notes


def uninstall_registry_candidates() -> tuple[list[tuple[str, str]], list[str]]:
    """plan.md 2.1 step 7, first half: Windows Uninstall keys.

    Steam registers ``Steam App <appid>`` for installed games, and a non-Steam build
    would register its own DisplayName. Both are covered by matching the app id in the
    subkey name or 'misery' in the DisplayName.
    """
    winreg = _winreg()
    if winreg is None:
        return [], ["winreg unavailable: Uninstall-key fallback skipped"]
    roots = (
        ("HKLM", winreg.HKEY_LOCAL_MACHINE,
         "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE,
         "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
        ("HKCU", winreg.HKEY_CURRENT_USER,
         "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
    )
    found: list[tuple[str, str]] = []
    notes: list[str] = []
    for hive_name, hive, subkey in roots:
        try:
            parent = winreg.OpenKey(hive, subkey)
        except OSError as exc:
            notes.append("%s\\%s: unreadable (%s)" % (hive_name, subkey, exc))
            continue
        with parent:
            index = 0
            scanned = 0
            while True:
                try:
                    name = winreg.EnumKey(parent, index)
                except OSError:
                    break
                index += 1
                scanned += 1
                interesting = str(DEFAULT_APP_ID) in name or "misery" in name.lower()
                display = None
                location = None
                if not interesting:
                    continue
                try:
                    with winreg.OpenKey(parent, name) as child:
                        try:
                            display = str(winreg.QueryValueEx(child, "DisplayName")[0])
                        except OSError:
                            display = None
                        try:
                            location = str(
                                winreg.QueryValueEx(child, "InstallLocation")[0]
                            )
                        except OSError:
                            location = None
                except OSError:
                    continue
                label = "%s\\%s\\%s" % (hive_name, subkey, name)
                if location:
                    path = canonical_case(location)
                    notes.append(
                        "%s: DisplayName=%r InstallLocation=%s"
                        % (label, display, privatize_path(path))
                    )
                    if os.path.isdir(path):
                        found.append((label, path))
                else:
                    notes.append(
                        "%s: DisplayName=%r, no InstallLocation" % (label, display)
                    )
            notes.append("%s\\%s: %d subkeys scanned" % (hive_name, subkey, scanned))
    return found, notes


# ---------------------------------------------------------------------------
# step 3 -- library enumeration
# ---------------------------------------------------------------------------


def parse_libraryfolders(text: str) -> list[dict]:
    r"""Parse libraryfolders.vdf into [{'key', 'path', 'apps': {appid: size}}].

    Two historical shapes are accepted, because a machine that has not run a recent
    Steam client still has the old one:
      * current: "libraryfolders" { "0" { "path" "D:\\Games\\Steam"  "apps" { ... } } }
      * legacy : "LibraryFolders" { "1" "E:\\SteamLibrary" ... }
    Non-numeric bookkeeping keys ("TimeNextStatsReport", "ContentStatsID") are ignored.
    """
    document = parse_vdf(text)
    root = vdf_get(document, "libraryfolders")
    if not isinstance(root, dict):
        # Some writers omit the wrapper entirely.
        root = document if isinstance(document, dict) else {}
    libraries: list[dict] = []
    for key in sorted(root, key=lambda item: (not item.isdigit(), item)):
        if not key.isdigit():
            continue
        value = root[key]
        if isinstance(value, str):
            path = normalize_path(value)
            apps: dict[str, int | None] = {}
        elif isinstance(value, dict):
            path = normalize_path(str(vdf_get(value, "path", default="") or ""))
            apps_block = vdf_get(value, "apps")
            apps = {}
            if isinstance(apps_block, dict):
                for app_id, size in apps_block.items():
                    apps[str(app_id)] = _as_int(size)
        else:
            continue
        if not path:
            continue
        libraries.append({"key": key, "path": path, "apps": apps})
    return libraries


def steamapps_dir(library_path: str) -> str:
    return join_native(library_path, "steamapps")


def appmanifest_path_for(library_path: str, app_id: int) -> str:
    return join_native(steamapps_dir(library_path), "appmanifest_%d.acf" % app_id)


# ---------------------------------------------------------------------------
# step 4 -- app manifest
# ---------------------------------------------------------------------------


def extract_appmanifest(raw: dict) -> dict:
    """Whitelist the fields plan.md 2.2 asks for. Nothing else is carried over.

    This is a whitelist rather than a copy-and-delete for one specific reason: the
    manifest contains ``LastOwner``, a SteamID64 of the account that installed the game.
    That is personal data about the machine's owner, the repository is public, and
    constraint C-13 forbids account ids in it (plan.md 10.5 repeats the rule for the
    knowledge base). A whitelist cannot leak a field that a future Steam client adds;
    a blacklist can. ``last_owner_present`` records only the boolean fact that the field
    existed, which is what the trace needs, and ``_last_owner_value`` is returned solely
    so check_privacy can assert the value is absent from the output -- it is stripped
    before the document is built.
    """
    installed: dict[str, dict] = {}
    depots_block = vdf_get(raw, "AppState", "InstalledDepots")
    if isinstance(depots_block, dict):
        for depot_id, body in depots_block.items():
            if not str(depot_id).isdigit():
                continue
            entry: dict = {"manifest": None, "size": None}
            if isinstance(body, dict):
                manifest = vdf_get(body, "manifest")
                # Depot manifest ids exceed the exact-integer range of a JSON double,
                # so they stay decimal strings (install.schema.json says the same).
                if isinstance(manifest, str) and manifest.isdigit():
                    entry["manifest"] = manifest
                entry["size"] = _as_int(vdf_get(body, "size"))
            elif isinstance(body, str) and body.isdigit():
                entry["manifest"] = body
            installed[str(depot_id)] = entry

    shared: list[str] = []
    shared_block = vdf_get(raw, "AppState", "SharedDepots")
    if isinstance(shared_block, dict):
        shared = sorted(
            (str(key) for key in shared_block if str(key).isdigit()),
            key=lambda item: int(item),
        )

    last_owner = vdf_get(raw, "AppState", "LastOwner")
    return {
        "app_id": _as_int(vdf_get(raw, "AppState", "appid")),
        "name": vdf_get(raw, "AppState", "name"),
        "installdir": vdf_get(raw, "AppState", "installdir"),
        "buildid": _as_int(vdf_get(raw, "AppState", "buildid")),
        "size_on_disk": _as_int(vdf_get(raw, "AppState", "SizeOnDisk")),
        "state_flags": _as_int(vdf_get(raw, "AppState", "StateFlags")),
        "depots": installed,
        "shared_depots": shared,
        "last_owner_present": isinstance(last_owner, str) and last_owner != "",
        "_last_owner_value": last_owner if isinstance(last_owner, str) else None,
    }


def read_appmanifest(path: str) -> dict:
    return extract_appmanifest(parse_vdf(read_text_file(path)))


# ---------------------------------------------------------------------------
# step 6 -- validation
# ---------------------------------------------------------------------------


def validate_install(install_dir: str) -> dict:
    """plan.md 2.1 step 6. Reports WHICH check failed, not just that one did."""
    errors: list[str] = []
    if not os.path.isdir(install_dir):
        return {
            "shipping_exe_present": False,
            "global_utoc_present": False,
            "file_count": None,
            "read_only_respected": True,
            "errors": ["install_dir is not a directory: %s" % privatize_path(install_dir)],
        }
    shipping = join_native(install_dir, SHIPPING_EXE_REL)
    utoc = join_native(install_dir, GLOBAL_UTOC_REL)
    shipping_ok = os.path.isfile(shipping)
    utoc_ok = os.path.isfile(utoc)
    if not shipping_ok:
        errors.append("check 1 failed: %s is missing" % SHIPPING_EXE_REL)
    if not utoc_ok:
        errors.append("check 2 failed: %s is missing" % GLOBAL_UTOC_REL)
    file_count = count_files(install_dir)
    return {
        "shipping_exe_present": shipping_ok,
        "global_utoc_present": utoc_ok,
        "file_count": file_count,
        # This tool contains no code path that opens anything under install_dir for
        # writing; the assertion is therefore a property of the implementation, and the
        # only writable path is --out, which write_document refuses to place inside.
        "read_only_respected": True,
        "errors": errors,
    }


def count_files(root: str) -> int | None:
    """Count files in the installation tree (stat only, symlinks not followed)."""
    total = 0
    try:
        for _dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            total += len(filenames)
    except OSError:
        return None
    return total


def enumerate_containers(install_dir: str) -> list[dict]:
    """Every file in MISERY\\Content\\Paks with name, kind and size (plan.md 2.2/3).

    Paths use forward slashes relative to the installation root, matching
    fingerprint.schema.json container entries. sha256 and the parsed .utoc/.pak headers
    are deliberately absent: hashing here would re-read 4.4 GB for no new fact, and
    decoding a FIoStoreTocHeader is task F-02 in M1. plan.md Appendix A A-07 grades the
    header BYTES as OBSERVED 0.99 but the DECODED FIELD VALUES and the encryption verdict
    only as INFERRED 0.85 (hand-decoded against the public layout, so external-doc
    contributes); a discovery tool must not manufacture those weaker-grade values as if
    they were direct measurements.
    """
    paks = join_native(install_dir, PAKS_DIR_REL)
    if not os.path.isdir(paks):
        return []
    entries: list[dict] = []
    names: list[str] = []
    try:
        with os.scandir(paks) as iterator:
            for entry in iterator:
                if entry.is_file(follow_symlinks=False):
                    names.append(entry.name)
    except OSError:
        return []
    present = set(names)
    for name in sorted(names):
        extension = os.path.splitext(name)[1].lower()
        kind = CONTAINER_KINDS.get(extension, "other")
        try:
            size = os.stat(join_native(paks, name)).st_size
        except OSError:
            size = None
        sibling = None
        stem = os.path.splitext(name)[0]
        if kind == "utoc" and stem + ".ucas" in present:
            sibling = PAKS_DIR_REL.replace("\\", "/") + "/" + stem + ".ucas"
        elif kind == "ucas" and stem + ".utoc" in present:
            sibling = PAKS_DIR_REL.replace("\\", "/") + "/" + stem + ".utoc"
        entries.append(
            {
                "path": PAKS_DIR_REL.replace("\\", "/") + "/" + name,
                "kind": kind,
                "size": size,
                "sha256": None,
                "sibling_path": sibling,
                "notes": "size and existence only (oracle: filesystem); sha256 and the "
                         "parsed container header belong to the fingerprint stage "
                         "(plan.md 3.2, task F-02)",
            }
        )
    return entries


def relative_executables(install_dir: str) -> tuple[str | None, str | None, list[str]]:
    """(primary, launcher_shim, secondary) as paths relative to install_dir.

    Decision D-04: the primary is always the Shipping image. The 282 MB
    MISERY\\Binaries\\Win64\\MISERY.exe is reported in secondary_executables and never
    as primary, no matter that it is the larger file.
    """
    primary = None
    if os.path.isfile(join_native(install_dir, SHIPPING_EXE_REL)):
        primary = SHIPPING_EXE_REL
    shim = None
    if os.path.isfile(join_native(install_dir, LAUNCHER_SHIM_REL)):
        shim = LAUNCHER_SHIM_REL
    secondary = [
        relpath
        for relpath in SECONDARY_EXE_RELS
        if os.path.isfile(join_native(install_dir, relpath))
    ]
    return primary, shim, secondary


# ---------------------------------------------------------------------------
# step 7 -- full-disk search
# ---------------------------------------------------------------------------


def deep_scan(limit_drives: list[str] | None = None) -> tuple[list[str], list[str]]:
    """plan.md 2.1 step 7, second half. Runs ONLY when --deep was passed.

    Looks for any directory that satisfies validation check 1, which is a far cheaper
    predicate than "is named MISERY" and cannot produce a false positive on a mod folder.
    """
    notes: list[str] = []
    found: list[str] = []
    drives = limit_drives
    if drives is None:
        drives = [
            "%s:\\" % letter
            for letter in string.ascii_uppercase
            if os.path.isdir("%s:\\" % letter)
        ]
    notes.append("drives searched: %s" % (", ".join(drives) if drives else "none"))
    for drive in drives:
        base_depth = drive.rstrip("\\").count("\\")
        for dirpath, dirnames, _filenames in os.walk(drive, followlinks=False):
            depth = dirpath.count("\\") - base_depth
            if depth >= DEEP_MAX_DEPTH:
                dirnames[:] = []
            else:
                dirnames[:] = sorted(
                    name for name in dirnames if name.lower() not in DEEP_SKIP_DIRS
                )
            if os.path.isfile(join_native(dirpath, SHIPPING_EXE_REL)):
                found.append(canonical_case(dirpath))
                dirnames[:] = []
    notes.append("candidates found: %d" % len(found))
    return found, notes


# ---------------------------------------------------------------------------
# discovery driver
# ---------------------------------------------------------------------------


class Trace:
    """Ordered evidence log. Each entry names the plan.md 2.1 step it belongs to."""

    def __init__(self) -> None:
        self.entries: list[dict] = []

    def add(self, step, name, status, detail, oracle=None, source=None):
        # The keys are "oracle_class" and "inspected", NOT "oracle" and "source", and
        # that is deliberate. tools/kb/validate.py treats any JSON object carrying
        # "oracle" (or "evidence_level" / "claim_type" / "confidence") as a knowledge-base
        # record and then demands evidence_level, confidence, claim_type, build_key and a
        # sources[] ARRAY of method ids on it. A trace line is a tool log, not a graded
        # record: "MISERY_GAME_DIR is not set in the environment" has no confidence and no
        # build_key, and install.json is a raw measurement artifact exactly like
        # install-inventory.json. The oracle attribution is still recorded, under a name
        # that does not claim knowledge-base semantics; the graded records that CITE this
        # file live in the markdown documents.
        self.entries.append(
            {
                "step": step,
                "name": name,
                "status": status,
                "oracle_class": oracle,
                "inspected": privatize_path(source) if source else None,
                "detail": detail,
            }
        )

    def as_list(self) -> list[dict]:
        return list(self.entries)


class Found:
    """A resolved installation together with the Steam facts backing it."""

    def __init__(self, install_dir, method, steam_path=None, library_path=None,
                 appmanifest=None, appmanifest_file=None):
        # canonical_case, not normalize_path: every path in the document must use the one
        # spelling the filesystem reports, whatever spelling the registry or Steam used.
        self.install_dir = canonical_case(install_dir)
        self.method = method
        self.steam_path = canonical_case(steam_path) if steam_path else None
        self.library_path = canonical_case(library_path) if library_path else None
        self.appmanifest = appmanifest
        self.appmanifest_file = canonical_case(appmanifest_file) if appmanifest_file else None


def attach_steam_metadata(found: Found, app_id: int, trace: Trace) -> None:
    """For an installation resolved by override or fallback, try to recover the Steam
    facts anyway: <install>\\..\\..  is the steamapps dir of its library when the layout
    is the standard one. Without this, an override run would report null buildid and null
    depots even on a perfectly normal Steam install."""
    if found.appmanifest is not None:
        return
    library = os.path.dirname(os.path.dirname(found.install_dir))  # drop common\<dir>
    candidate = appmanifest_path_for(os.path.dirname(library), app_id)
    if os.path.basename(library).lower() != "steamapps":
        trace.add(
            4, "app-manifest", "skipped",
            "installation was not resolved through Steam and its parent chain is not "
            "<library>\\steamapps\\common\\<installdir> (parent: %s), so no app manifest "
            "was looked for" % privatize_path(library),
            oracle="filesystem",
        )
        return
    if not os.path.isfile(candidate):
        trace.add(
            4, "app-manifest", "not-found",
            "derived the library from the installation path but %s does not exist"
            % os.path.basename(candidate),
            oracle="filesystem", source=candidate,
        )
        return
    try:
        manifest = read_appmanifest(candidate)
    except (OSError, VdfError) as exc:
        trace.add(4, "app-manifest", "error",
                  "unreadable: %s" % exc, oracle="steam-metadata", source=candidate)
        return
    found.appmanifest = manifest
    found.appmanifest_file = candidate
    found.library_path = canonical_case(os.path.dirname(library))
    trace.add(
        4, "app-manifest", "found",
        describe_manifest(manifest),
        oracle="steam-metadata", source=candidate,
    )


def describe_manifest(manifest: dict) -> str:
    depots = ", ".join(
        "%s@%s" % (depot, (body.get("manifest") or "?"))
        for depot, body in sorted(manifest["depots"].items())
    )
    return (
        "appid=%s installdir=%r buildid=%s SizeOnDisk=%s StateFlags=%s; "
        "InstalledDepots: %s; SharedDepots: %s; LastOwner %s -- excluded from the output "
        "as a Steam account id (C-13)"
        % (
            manifest.get("app_id"),
            manifest.get("installdir"),
            manifest.get("buildid"),
            manifest.get("size_on_disk"),
            manifest.get("state_flags"),
            depots or "none",
            ", ".join(manifest["shared_depots"]) or "none",
            "present" if manifest.get("last_owner_present") else "absent",
        )
    )


def discover(args, repo_root: str, trace: Trace) -> Found | None:
    app_id = args.app_id

    # ---- step 1: explicit override -------------------------------------------------
    if args.install_dir:
        path = canonical_case(args.install_dir)
        trace.add(1, "explicit-override", "found",
                  "--install-dir given on the command line; steps 2-5 skipped",
                  oracle="filesystem", source=path)
        found = Found(path, "explicit-path")
        attach_steam_metadata(found, app_id, trace)
        return found

    env_value = os.environ.get(ENV_OVERRIDE)
    if env_value:
        path = canonical_case(env_value)
        if os.path.isdir(path):
            trace.add(1, "explicit-override", "found",
                      "%s is set and points at an existing directory; steps 2-5 skipped"
                      % ENV_OVERRIDE, oracle="filesystem", source=path)
            found = Found(path, "env-override")
            attach_steam_metadata(found, app_id, trace)
            return found
        trace.add(1, "explicit-override", "not-found",
                  "%s is set to %s but that is not a directory; continuing with step 2"
                  % (ENV_OVERRIDE, privatize_path(path)), oracle="filesystem")
    else:
        trace.add(1, "explicit-override", "skipped",
                  "%s is not set in the environment" % ENV_OVERRIDE, oracle="filesystem")

    config_path, config, config_error = read_local_config(repo_root)
    if config_error:
        trace.add(1, "local-config", "error",
                  "%s exists but could not be parsed: %s" % (LOCAL_CONFIG_RELPATH,
                                                             config_error),
                  oracle="filesystem", source=config_path)
    elif config is None:
        trace.add(1, "local-config", "skipped",
                  "%s does not exist (honoured when present, never created by this tool)"
                  % LOCAL_CONFIG_RELPATH, oracle="filesystem", source=config_path)
    else:
        candidate = config.get("install_dir") or config.get("misery_game_dir")
        if candidate and os.path.isdir(normalize_path(str(candidate))):
            path = canonical_case(str(candidate))
            trace.add(1, "local-config", "found",
                      "install_dir from %s; steps 2-5 skipped" % LOCAL_CONFIG_RELPATH,
                      oracle="filesystem", source=path)
            found = Found(path, "local-config")
            attach_steam_metadata(found, app_id, trace)
            return found
        trace.add(1, "local-config", "not-found",
                  "%s exists but has no usable install_dir (keys: %s)"
                  % (LOCAL_CONFIG_RELPATH, ", ".join(sorted(config)) or "none"),
                  oracle="filesystem", source=config_path)
        if config.get("steam_root") and not args.steam_root:
            args.steam_root = str(config["steam_root"])

    # ---- step 2: Steam registry ----------------------------------------------------
    steam_roots: list[tuple[str, str]] = []
    if args.steam_root:
        path = canonical_case(args.steam_root)
        trace.add(2, "steam-registry", "skipped",
                  "--steam-root (or local.json steam_root) supplied, registry not read",
                  oracle="filesystem", source=path)
        if os.path.isdir(path):
            steam_roots.append(("--steam-root", path))
        else:
            trace.add(2, "steam-registry", "not-found",
                      "supplied Steam root %s is not a directory" % privatize_path(path),
                      oracle="filesystem")
    else:
        registry_found, registry_notes = registry_steam_roots()
        steam_roots.extend(registry_found)
        trace.add(2, "steam-registry",
                  "found" if registry_found else "not-found",
                  "; ".join(registry_notes) or "no registry values inspected",
                  oracle="filesystem")

    # ---- steps 3-5: libraries, manifest, install dir -------------------------------
    seen_libraries: list[str] = []
    for source, steam_root in steam_roots:
        vdf_path = join_native(steamapps_dir(steam_root), "libraryfolders.vdf")
        if not os.path.isfile(vdf_path):
            trace.add(3, "library-enumeration", "not-found",
                      "libraryfolders.vdf missing under Steam root from %s; falling back "
                      "to the Steam root itself as a single library" % source,
                      oracle="filesystem", source=vdf_path)
            libraries = [{"key": "-", "path": steam_root, "apps": {}}]
        else:
            try:
                libraries = parse_libraryfolders(read_text_file(vdf_path))
            except (OSError, VdfError) as exc:
                trace.add(3, "library-enumeration", "error",
                          "libraryfolders.vdf unreadable: %s" % exc,
                          oracle="steam-metadata", source=vdf_path)
                continue
            listing = "; ".join(
                "[%s] %s (%d apps%s)"
                % (
                    entry["key"],
                    privatize_path(entry["path"]),
                    len(entry["apps"]),
                    ", app %d listed with size %s" % (app_id, entry["apps"][str(app_id)])
                    if str(app_id) in entry["apps"] else "",
                )
                for entry in libraries
            )
            trace.add(3, "library-enumeration",
                      "found" if libraries else "not-found",
                      "%d library folder(s) from libraryfolders.vdf via %s: %s"
                      % (len(libraries), source, listing or "none"),
                      oracle="steam-metadata", source=vdf_path)

        # A library that lists the app in its "apps" block is tried first; that block is
        # Steam's own index, so trusting it for ORDERING only (never for existence) makes
        # the common case one stat call instead of one per library.
        ordered = sorted(
            libraries, key=lambda entry: (str(app_id) not in entry["apps"], entry["key"])
        )
        for entry in ordered:
            library = entry["path"]
            if library in seen_libraries:
                continue
            seen_libraries.append(library)
            manifest_file = appmanifest_path_for(library, app_id)
            if not os.path.isfile(manifest_file):
                trace.add(4, "app-manifest", "not-found",
                          "no appmanifest_%d.acf in library %s"
                          % (app_id, privatize_path(library)),
                          oracle="filesystem", source=manifest_file)
                continue
            try:
                manifest = read_appmanifest(manifest_file)
            except (OSError, VdfError) as exc:
                trace.add(4, "app-manifest", "error",
                          "appmanifest_%d.acf unreadable: %s" % (app_id, exc),
                          oracle="steam-metadata", source=manifest_file)
                continue
            trace.add(4, "app-manifest", "found", describe_manifest(manifest),
                      oracle="steam-metadata", source=manifest_file)
            installdir = manifest.get("installdir")
            if not installdir:
                trace.add(5, "install-dir", "not-found",
                          "app manifest carries no installdir, cannot build "
                          "<library>\\steamapps\\common\\<installdir> (question Q-2.5)",
                          oracle="steam-metadata", source=manifest_file)
                continue
            install_dir = join_native(steamapps_dir(library), "common", str(installdir))
            if not os.path.isdir(install_dir):
                trace.add(5, "install-dir", "not-found",
                          "Steam promises installdir %r but %s is not a directory -- "
                          "steam-metadata and filesystem disagree, which is itself a "
                          "finding (plan.md 10.5)"
                          % (installdir, privatize_path(install_dir)),
                          oracle="filesystem", source=install_dir)
                continue
            trace.add(5, "install-dir", "found",
                      "<library>\\steamapps\\common\\%s resolved and exists" % installdir,
                      oracle="filesystem", source=install_dir)
            return Found(install_dir, "steam-libraryfolders", steam_path=steam_root,
                         library_path=library, appmanifest=manifest,
                         appmanifest_file=manifest_file)

    if not steam_roots:
        trace.add(3, "library-enumeration", "skipped",
                  "no usable Steam root from step 2, so there is nothing to enumerate",
                  oracle="filesystem")

    # ---- step 7: fallbacks ---------------------------------------------------------
    uninstall_found, uninstall_notes = uninstall_registry_candidates()
    trace.add(7, "uninstall-registry",
              "found" if uninstall_found else "not-found",
              "; ".join(uninstall_notes) or "no Uninstall keys inspected",
              oracle="filesystem")
    for label, path in uninstall_found:
        probe = validate_install(path)
        if probe["shipping_exe_present"]:
            trace.add(7, "uninstall-registry", "found",
                      "InstallLocation from %s satisfies validation check 1" % label,
                      oracle="filesystem", source=path)
            found = Found(path, "uninstall-registry")
            attach_steam_metadata(found, app_id, trace)
            return found

    if not args.deep:
        trace.add(7, "disk-scan", "skipped",
                  "a full-disk search is destructive of time, not of data, and runs only "
                  "with the explicit --deep flag (plan.md 2.1 step 7)",
                  oracle="filesystem")
        return None

    deep_found, deep_notes = deep_scan(args.deep_drives)
    trace.add(7, "disk-scan", "found" if deep_found else "not-found",
              "; ".join(deep_notes), oracle="filesystem")
    if deep_found:
        found = Found(deep_found[0], "disk-scan")
        attach_steam_metadata(found, app_id, trace)
        return found
    return None


# ---------------------------------------------------------------------------
# document assembly
# ---------------------------------------------------------------------------


def build_document(found: Found, validation: dict, trace: Trace, app_id: int) -> dict:
    manifest = found.appmanifest or {}
    depots = manifest.get("depots")
    primary, shim, secondary = relative_executables(found.install_dir)
    containers = enumerate_containers(found.install_dir)
    paks_present = os.path.isdir(join_native(found.install_dir, PAKS_DIR_REL))

    notes_parts = [
        "generator: %s %s." % (GENERATOR_NAME, GENERATOR_VERSION),
        "method=%s; the per-step evidence is in discovery_trace, which is the only thing "
        "that makes this field auditable." % found.method,
        "oracles (plan.md 10.5): existence, paths and sizes are filesystem; app_id, "
        "depots, shared_depots and steam_buildid are steam-metadata and describe what "
        "Steam RECORDED, not what is on disk -- validation is the filesystem half of "
        "that pair.",
        "LastOwner from the app manifest is NOT copied here: it is a Steam account id "
        "and constraint C-13 forbids account ids in this public repository. The manifest "
        "reader whitelists fields, so the value never reaches the document.",
        "containers[].sha256 is null and no .utoc/.pak header is parsed: discovery "
        "measures existence and size only. Hashes come from "
        "tools/inventory/snapshot_install.py, header decoding is task F-02 in M1 "
        "(plan.md 3). Per plan.md Appendix A A-07 the header BYTES are OBSERVED 0.99 "
        "while DECODED field values and the encryption verdict are only INFERRED 0.85, "
        "so this tool does not produce them.",
        "user_config_dir / user_save_dir / crash_dir / log_dir are emitted in %VAR% form "
        "and are NOT verified to exist by this tool; they are the documented UE layout "
        "for this build (plan.md 2.2), not a measurement made here.",
        "read_only_respected=true is a property of the implementation: no code path here "
        "opens anything under install_dir for writing (decision D-01).",
    ]
    if not manifest:
        notes_parts.append(
            "app_id, depots, shared_depots and steam_buildid are null because no Steam "
            "app manifest was read on this run; see discovery_trace step 4."
        )
    if not paks_present:
        notes_parts.append(
            "containers is an empty array because %s does not exist." % PAKS_DIR_REL
        )

    document = {
        "discovered_at": now_iso_utc(),
        "method": found.method,
        "steam_path": privatize_path(found.steam_path),
        "library_path": privatize_path(found.library_path),
        "app_id": manifest.get("app_id") if manifest else None,
        "appmanifest_path": privatize_path(found.appmanifest_file),
        "depots": depots if manifest else None,
        "shared_depots": manifest.get("shared_depots") if manifest else None,
        "steam_buildid": manifest.get("buildid") if manifest else None,
        "install_dir": privatize_path(found.install_dir),
        "primary_executable": primary,
        "launcher_shim": shim,
        "secondary_executables": secondary,
        "paks_dir": PAKS_DIR_REL if paks_present else None,
        "containers": containers,
        "user_config_dir": USER_CONFIG_DIR,
        "user_save_dir": USER_SAVE_DIR,
        "crash_dir": CRASH_DIR,
        "log_dir": LOG_DIR,
        "validation": validation,
        "discovery_trace": trace.as_list(),
        "generator_version": GENERATOR_VERSION,
        "notes": " ".join(notes_parts),
    }
    if document["app_id"] is None and manifest:
        document["app_id"] = app_id
    return document


def dump_json(document: dict) -> str:
    """Sorted keys, indent 2, LF, trailing newline. UTF-8 without BOM on write."""
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def write_document(document: dict, out_path: str, install_dir: str) -> None:
    """Write install.json to *out_path*, refusing any path inside an installation.

    The guard is ``pathguard.check_output_path`` -- the shared implementation of
    plan.md 1.5 layer 1 / D-01 -- not a local copy of it. It resolves symlinks and
    junctions, folds case and 8.3 spellings, and protects every installation it can
    identify, not only *install_dir*: a mistyped --install-dir no longer switches the
    check off. ``OutputPathRefused`` is raised before the file is opened, so a refused
    path leaves nothing behind; main() turns it into the documented exit code 2.
    """
    resolved_out = pathguard.check_output_path(out_path, install_dir, what="--out")
    parent = os.path.dirname(resolved_out)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(resolved_out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dump_json(document))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="find_misery.py",
        description="Find the MISERY installation read-only and emit install.json "
                    "(plan.md 2).",
    )
    parser.add_argument(
        "--out", metavar="FILE",
        help="write install.json here. '-' or omitted: print the JSON on stdout. "
             "Refuses any path inside the installation (decision D-01).",
    )
    parser.add_argument(
        "--install-dir", metavar="DIR",
        help="skip steps 1-5 and use this installation root (method=explicit-path).",
    )
    parser.add_argument(
        "--steam-root", metavar="DIR",
        help="use this Steam root instead of reading it from the registry (step 2).",
    )
    parser.add_argument(
        "--deep", action="store_true",
        help="allow the full-disk search of step 7. Off by default: it is slow and "
             "plan.md 2.1 permits it only on an explicit request.",
    )
    parser.add_argument(
        "--deep-drives", metavar="DIR", nargs="+", default=None,
        help="limit --deep to these roots instead of every fixed drive.",
    )
    parser.add_argument(
        "--app-id", type=int, default=DEFAULT_APP_ID, metavar="N",
        help="Steam AppID to look for (default %d)." % DEFAULT_APP_ID,
    )
    parser.add_argument(
        "--repo-root", metavar="DIR", default=None,
        help="repository root used to locate %s (default: two levels above this file)."
             % LOCAL_CONFIG_RELPATH,
    )
    return parser


def default_repo_root() -> str:
    """Repository root: this file lives in <repo>/tools/discovery/, so three levels up."""
    return os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    repo_root = args.repo_root or default_repo_root()
    trace = Trace()

    try:
        found = discover(args, repo_root, trace)
    except DiscoveryError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    if found is None:
        sys.stderr.write("MISERY installation NOT found. Steps taken:\n")
        for entry in trace.as_list():
            sys.stderr.write(
                "  step %s %-20s %-10s %s\n"
                % (entry["step"], entry["name"], entry["status"], entry["detail"])
            )
        sys.stderr.write(
            "hint: set %s, pass --install-dir, or re-run with --deep.\n" % ENV_OVERRIDE
        )
        return 1

    validation = validate_install(found.install_dir)
    trace.add(
        6, "validation", "ok" if not validation["errors"] else "failed",
        "check 1 %s exists: %s; check 2 %s exists: %s; files in tree: %s%s"
        % (
            SHIPPING_EXE_REL, validation["shipping_exe_present"],
            GLOBAL_UTOC_REL, validation["global_utoc_present"],
            validation["file_count"],
            "" if not validation["errors"] else "; " + "; ".join(validation["errors"]),
        ),
        oracle="filesystem", source=found.install_dir,
    )

    last_owner = None
    if found.appmanifest:
        last_owner = found.appmanifest.pop("_last_owner_value", None)
    document = build_document(found, validation, trace, args.app_id)
    text = dump_json(document)

    leaks = check_privacy(text, [last_owner] if last_owner else None)
    if leaks:
        # Report WHERE, not just how many. The value itself stays redacted -- printing it
        # into a public CI log would be the leak this guard exists to prevent -- but the
        # JSON key path carrying it is not sensitive and is the only thing that makes the
        # refusal actionable. Without it the message says "3 values forbidden" and leaves
        # the reader to guess which field failed to go through privatize_path().
        print(
            "error: refusing to emit install.json, it contains %d value(s) forbidden by "
            "C-13 (account id or literal user-profile path): %s"
            % (len(leaks), ", ".join("<%d chars>" % len(item) for item in leaks)),
            file=sys.stderr,
        )
        for value in leaks:
            where = locate_in_document(document, value)
            print(
                "  <%d chars> appears at: %s"
                % (len(value), ", ".join(where) if where else
                   "(not at any single key -- check the serialised form)"),
                file=sys.stderr,
            )
        return 1

    if args.out and args.out != "-":
        try:
            # found.install_dir, not document["install_dir"]: the document field is in
            # the privatized %VAR% form (C-13) and the guard should be handed the real
            # path. It is only the first protected root anyway -- pathguard also refuses
            # any other installation it can identify above the output path.
            write_document(document, args.out, found.install_dir)
        except (pathguard.OutputPathRefused, DiscoveryError, ValueError) as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
        except OSError as exc:
            print("error: cannot write %s: %s" % (args.out, exc), file=sys.stderr)
            return 2
        sys.stderr.write("wrote %s\n" % args.out)
        sys.stdout.write("install_dir=%s\n" % document["install_dir"])
    else:
        sys.stdout.write(text)

    sys.stderr.write(
        "method=%s\ninstall_dir=%s\nsteam_buildid=%s\ncontainers=%d\nvalidation=%s\n"
        % (
            document["method"], document["install_dir"], document["steam_buildid"],
            len(document["containers"] or []),
            "PASSED" if not validation["errors"] else "FAILED",
        )
    )
    for error in validation["errors"]:
        sys.stderr.write("validation: %s\n" % error)
    return 0 if not validation["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
