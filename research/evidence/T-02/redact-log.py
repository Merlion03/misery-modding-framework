#!/usr/bin/env python3
"""Deterministic C-13 redactor for captured tool console logs (T-02 evidence).

WHY THIS EXISTS
---------------
plan.md C-13 forbids literal user-profile paths, account ids and user-directory
listings anywhere in this public repository. Ghidra's `analyzeHeadless` console
output violates all three: it prints its own log/preferences paths under the
roaming profile, it prints the whole machine PATH as the library search path,
and it stamps the account name on every file it creates inside the project.

A raw log therefore cannot be committed as-is. Deleting the offending lines
would make the artifact unverifiable, so instead the transformation is
mechanical, lossless in structure, and reproducible: run the smoke test, run
this script, and the committed file comes out byte-identical (modulo the timing
lines, which genuinely differ between runs).

This script itself carries no account id -- the values to redact are read from
the environment at run time, never hardcoded.

USAGE
-----
    python redact-log.py <raw-log-in> <redacted-log-out>

Output is written UTF-8 without BOM and with LF line endings, matching the
repository's text convention.
"""

from __future__ import annotations

import os
import re
import sys

# Substitutions are applied in this order. Longest / most specific paths must
# come first, otherwise the USERPROFILE rule would swallow the AppData ones and
# the result would lose information for no privacy gain.
_ENV_KEYS: tuple[tuple[str, str], ...] = (
    ("LOCALAPPDATA", "%LOCALAPPDATA%"),
    ("APPDATA", "%APPDATA%"),
    ("USERPROFILE", "%USERPROFILE%"),
)

# `Using Library Search Path: [ ... ]` is a verbatim dump of the machine PATH.
# It is a user-directory listing under C-13 and it carries no evidential value
# for the smoke test, so the bracket contents are replaced by a marker that
# preserves the one fact that matters: how many entries were searched.
_SEARCH_PATH_RE = re.compile(
    r"(Using Library Search Path: )\[(?P<body>.*?)\]", re.DOTALL
)


def _redact_paths(text: str) -> str:
    """Replace literal profile paths with their %VAR% form (C-13)."""
    for key, placeholder in _ENV_KEYS:
        raw = os.environ.get(key)
        if not raw:
            continue
        raw = raw.rstrip("\\/")
        # Ghidra emits both native (backslash) and file-URL (forward slash)
        # spellings of the same directory, and the drive letter case is not
        # stable, so both separators are handled and matching is
        # case-insensitive.
        for variant in {raw, raw.replace("\\", "/")}:
            text = re.sub(re.escape(variant), placeholder, text, flags=re.IGNORECASE)
    return text


def _redact_search_path(text: str) -> str:
    """Collapse the machine PATH dump to an entry count (C-13)."""

    def _sub(match: "re.Match[str]") -> str:
        entries = [part.strip() for part in match.group("body").split(",")]
        entries = [part for part in entries if part]
        return (
            f"{match.group(1)}[REDACTED per C-13: verbatim machine PATH dump, "
            f"{len(entries)} entries]"
        )

    return _SEARCH_PATH_RE.sub(_sub, text)


def _redact_username(text: str) -> str:
    """Replace the bare account name with %USERNAME% (C-13)."""
    user = os.environ.get("USERNAME") or os.environ.get("USER")
    if not user:
        return text
    return re.sub(rf"\b{re.escape(user)}\b", "%USERNAME%", text)


def redact(text: str) -> str:
    """Apply every C-13 transformation, in the documented order."""
    text = _redact_search_path(text)
    text = _redact_paths(text)
    text = _redact_username(text)
    return text


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {os.path.basename(argv[0])} <in> <out>", file=sys.stderr)
        return 2

    with open(argv[1], "r", encoding="utf-8", errors="replace", newline="") as handle:
        raw = handle.read()

    redacted = redact(raw).replace("\r\n", "\n").replace("\r", "\n")

    with open(argv[2], "w", encoding="utf-8", newline="\n") as handle:
        handle.write(redacted)

    # A non-zero residual count means a form of the profile path this script
    # does not know about survived. That must fail loudly rather than quietly
    # ship a C-13 violation.
    residual = len(re.findall(r"[A-Za-z]:[\\/]Users[\\/]", redacted))
    if residual:
        print(f"C-13 CHECK FAILED: {residual} literal Users path(s) remain", file=sys.stderr)
        return 1

    print(f"wrote {argv[2]} ({len(redacted.encode('utf-8'))} bytes), C-13 check clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
