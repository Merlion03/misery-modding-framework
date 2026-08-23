#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pre-commit knowledge-base gate: run validate.py and judge the staged files.

Called by tools/kb/githooks/pre-commit (see that file for the one-line
install). Can also be run by hand:

    D:\\Tools\\venv-research\\Scripts\\python.exe tools\\kb\\pre_commit_check.py

WHAT IT CHECKS, AND WHAT THE VERDICT IS SCOPED TO -- READ THIS
--------------------------------------------------------------
The SCAN is always full. tools/kb/validate.py takes about one second over the
whole repository (measured 2026-08-22: 0.9-1.1 s, 24 files, 228 records), so
there is no speed argument for checking less, and a partial scan that gets
mistaken for a full one is the failure mode this file exists to avoid.

The VERDICT is scoped to the files you are committing. That is a different
thing from a partial check, and the distinction is the whole design:

  * the hook blocks the commit when a file you STAGED carries a violation;
  * it reports violations in files you did not touch as PRE-EXISTING DEBT,
    loudly, with the exact count -- and lets the commit through.

Why that is safe rather than lenient: a violation is always produced by the
text of a record, so a NEW violation is necessarily in a file that changed.
Scoping the verdict to staged files therefore cannot let a new violation in;
it only refuses to hold your commit hostage to someone else's. The one gap is
a cross-file rule whose result can change without the file changing (the
vcs-history reachability check depends on git history, not on the citing file
alone), and that gap is exactly why layer 3 -- .github/workflows/ci.yml --
runs the same validator unscoped and demands zero violations overall.

Set MISERY_HOOK_ALL=1 to make the hook use the strict, CI-shaped verdict (any
violation anywhere blocks the commit). Once the tree reaches zero violations,
the two verdicts coincide and stay that way.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Extensions the validator can find graded facts in. Staging nothing that
# matches means there is nothing for the validator to say, so it is not run.
FACT_SUFFIXES = (".md", ".json", ".jsonl")

# Directories whose CODE decides what the validator finds. A change here can
# alter the result for every document without any document changing, so a
# staged file under one of these always triggers a run.
TOOL_PREFIXES = ("tools/kb/", "research/schema/")


def make_output_safe() -> None:
    """UTF-8 output, line-buffered, on both streams.

    Two concrete Windows failures this prevents:
      * the findings quote plan.md, which is in Russian. On a console whose
        code page cannot encode Cyrillic, printing a finding raises
        UnicodeEncodeError -- and a hook that dies with a traceback tells you
        nothing about your commit. errors="replace" keeps the diagnosis
        readable even when the console cannot render every character.
      * stdout is block-buffered when git captures it, so without line
        buffering the summary line arrives AFTER the errors it introduces.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
            except (ValueError, OSError):  # pragma: no cover -- redirected stream
                pass


def repo_relative(path: str) -> str:
    """Normalise a git path to forward slashes, lower-cased for comparison."""
    return path.replace("\\", "/").strip()


def staged_files(repo_root: Path) -> list[str] | None:
    """Paths added/copied/modified/renamed in the index, repo-relative.

    Returns None when the index could not be READ at all, which is a different
    situation from an index that is legitimately empty (running this script by
    hand outside a commit). Both fall back to a whole-tree verdict, but they
    are reported differently, because "I could not look" must never be printed
    as "there was nothing there".

    -z plus a NUL split, because a research path may contain a space and
    git's default output would quote it.
    """
    completed = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        # No index, or not a work tree. Say so; do not pretend to have checked.
        print(
            "pre-commit: could not read the git index (%s). Falling back to a "
            "whole-tree verdict." % completed.stderr.strip(),
            file=sys.stderr,
        )
        return None
    return [repo_relative(part) for part in completed.stdout.split("\0") if part.strip()]


def is_relevant(paths: list[str]) -> bool:
    """True when the validator has anything to say about this commit."""
    for path in paths:
        lowered = path.lower()
        if lowered.endswith(FACT_SUFFIXES):
            return True
        if any(lowered.startswith(prefix) for prefix in TOOL_PREFIXES):
            return True
    return False


def record_floor(repo_root: Path) -> int | None:
    """Read MIN_TOTAL_RECORDS from the live gate test -- one source of truth.

    The floor is defined and justified in tests/test_validator_live.py. The
    hook imports it rather than restating it, because two copies of a
    threshold is how thresholds drift apart (see the requirements.txt history
    note for the same mistake made with an install order).
    """
    module_path = repo_root / "tests" / "test_validator_live.py"
    if not module_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "_misery_live_gate_floors", module_path
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return int(module.MIN_TOTAL_RECORDS)
    except Exception:  # pragma: no cover -- a broken import must not block a commit
        return None


def run_validator(repo_root: Path) -> tuple[int, dict, str, float]:
    """Full validation run. Returns (rc, json document, stderr, seconds)."""
    validator = repo_root / "tools" / "kb" / "validate.py"
    started = time.monotonic()
    completed = subprocess.run(
        [sys.executable, str(validator), "--json", "--repo-root", str(repo_root)],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    elapsed = time.monotonic() - started
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return completed.returncode, {}, completed.stderr, elapsed
    return completed.returncode, document, completed.stderr, elapsed


def main(argv: list[str] | None = None) -> int:
    make_output_safe()
    parser = argparse.ArgumentParser(
        description="pre-commit knowledge-base gate (plan.md 9.4/K-03)"
    )
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[2]),
        help="repository root (default: two levels above this script)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="block on ANY violation in the tree, not only in staged files "
        "(same verdict as CI; also enabled by MISERY_HOOK_ALL=1)",
    )
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    strict = args.all or os.environ.get("MISERY_HOOK_ALL", "") not in ("", "0")

    validator = repo_root / "tools" / "kb" / "validate.py"
    if not validator.is_file():
        print(
            "pre-commit: tools/kb/validate.py not found at %s -- the "
            "knowledge base was NOT checked." % validator,
            file=sys.stderr,
        )
        return 1

    staged = staged_files(repo_root)
    if staged and not is_relevant(staged):
        print(
            "pre-commit: %d staged file(s), none of them a document, JSON "
            "artifact, schema or knowledge-base tool -- validator not run."
            % len(staged)
        )
        return 0

    returncode, document, stderr, elapsed = run_validator(repo_root)
    if not document:
        print(
            "pre-commit: validate.py produced no readable JSON (exit %s), so "
            "NOTHING WAS CHECKED. Do not read this as a pass.\n%s"
            % (returncode, stderr.strip()[:2000]),
            file=sys.stderr,
        )
        return 1

    summary = document.get("summary", {})
    total_violations = int(summary.get("violations") or 0)
    records = int(summary.get("records") or 0)
    files = int(summary.get("files") or 0)

    print(
        "pre-commit: FULL knowledge-base validation (%s file(s), %s record(s), "
        "%.1f s)." % (files, records, elapsed)
    )

    # -- the count-of-records trap, checked here too -------------------------
    # A validator that finds nothing reports no violations and exits 0. The
    # hook must not accept that as a clean tree either.
    floor = record_floor(repo_root)
    if floor is not None and records < floor:
        print(
            "pre-commit: BLOCKED -- only %s record(s) found, floor %s.\n"
            "            A collapsed record count is a failure, not a pass: "
            "the validator reports violations only for records it actually "
            "read, so finding nothing looks exactly like finding nothing "
            "wrong. See tests/test_validator_live.py."
            % (records, floor),
            file=sys.stderr,
        )
        return 1

    if document.get("schema_backend") != "jsonschema" or document.get(
        "schema_backend_degraded"
    ):
        # Warned, not blocked: this says something about the interpreter you
        # committed from, not about your commit. CI enforces the real backend.
        print(
            "pre-commit: WARNING -- schema backend is %r%s, so JSON artifacts "
            "were checked more weakly than their schemas ask for ('format' "
            "and 'propertyNames' are ignored). Commit permitted; CI will fail "
            "on this. Install the pinned jsonschema (requirements.txt step 5) "
            "or point MISERY_PYTHON at the canonical interpreter."
            % (
                document.get("schema_backend"),
                " [degraded]" if document.get("schema_backend_degraded") else "",
            ),
            file=sys.stderr,
        )

    # -- map violations to files -------------------------------------------
    errors_by_file: dict[str, int] = {}
    findings_by_file: dict[str, list[dict]] = {}
    for entry in document.get("files", []):
        count = int(entry.get("errors") or 0)
        if count:
            path = repo_relative(str(entry.get("path", "?")))
            errors_by_file[path] = count
            findings_by_file[path] = [
                finding
                for finding in (entry.get("findings") or [])
                if str(finding.get("severity", "")).upper() == "ERROR"
            ]

    if not errors_by_file and total_violations == 0:
        print("pre-commit: 0 violations. Knowledge base is clean (plan.md 9.4/K-03).")
        return 0

    staged_set = {path.lower() for path in (staged or [])}
    blocking = {
        path: count
        for path, count in errors_by_file.items()
        if strict or not staged_set or path.lower() in staged_set
    }
    elsewhere = {
        path: count for path, count in errors_by_file.items() if path not in blocking
    }

    if elsewhere:
        print(
            "pre-commit: PRE-EXISTING DEBT in %d file(s) you did not stage, "
            "%d violation(s) total -- not blocking this commit, but the CI "
            "gate is RED until they reach zero:"
            % (len(elsewhere), sum(elsewhere.values())),
            file=sys.stderr,
        )
        for path, count in sorted(elsewhere.items(), key=lambda kv: -kv[1]):
            print("            %-4d %s" % (count, path), file=sys.stderr)

    if not blocking:
        print(
            "pre-commit: no violation in the file(s) you staged. Commit "
            "allowed. Run with MISERY_HOOK_ALL=1 for the CI verdict."
        )
        return 0

    # Name the scope the verdict was taken over, so the message can never be
    # read as "these are the files you staged" when it is not.
    if strict:
        scope = "whole-tree verdict (MISERY_HOOK_ALL / --all)"
    elif staged is None:
        scope = "whole-tree verdict (the git index could not be read)"
    elif not staged_set:
        scope = "whole-tree verdict (nothing staged)"
    else:
        scope = "staged file(s)"
    print("", file=sys.stderr)
    print(
        "pre-commit: BLOCKED -- %d violation(s) in %d file(s), %s:"
        % (sum(blocking.values()), len(blocking), scope),
        file=sys.stderr,
    )
    for path, count in sorted(blocking.items(), key=lambda kv: -kv[1]):
        print("            %-4d %s" % (count, path), file=sys.stderr)
        for finding in findings_by_file.get(path, [])[:5]:
            message = str(finding.get("message", "")).splitlines()[0]
            print(
                "                 [%s] %s: %s"
                % (
                    finding.get("rule", "?"),
                    finding.get("pointer", "?"),
                    message[:160],
                ),
                file=sys.stderr,
            )
        remaining = len(findings_by_file.get(path, [])) - 5
        if remaining > 0:
            print("                 ... and %d more" % remaining, file=sys.stderr)
    print("", file=sys.stderr)
    print(
        "pre-commit: full report:\n"
        "            %s tools\\kb\\validate.py" % sys.executable,
        file=sys.stderr,
    )
    print(
        "pre-commit: fix the records, do not re-label them. Bypass with "
        "--no-verify only if you accept that CI will fail.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
