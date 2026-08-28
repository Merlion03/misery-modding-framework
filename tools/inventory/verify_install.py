#!/usr/bin/env python3
"""Verify the live MISERY installation against a recorded install-inventory JSON.

This is layer 3 of the safety model in plan.md section 1.5: it does not prevent a
change to the game folder, it *detects* one -- ours, Steam's, or a third party's.
Run it after every milestone (plan.md section 18.3), before and after any session
with the game running, and before and after the first use of the Probe.

Two modes and the tradeoff between them
---------------------------------------
``--fast``  compares size and mtime only. It reads directory metadata, not file
            content, so it finishes in well under a second on the ~4.9 GB tree.
            What it buys in speed it loses in certainty: a same-size, same-mtime
            edit is invisible to it, and a changed mtime cannot be shown to be
            harmless (there is no hash to compare against), so every mtime change
            is reported as ``mtime_changed_unverified`` and counts as serious.
            Use it for the frequent pre/post-session checks.

default     re-hashes every file (sha256, streaming, bounded buffer) and compares
            digests. This is the authoritative answer: it reads ~4.9 GB, so expect
            minutes, not seconds, dominated by disk throughput. Only this mode can
            report ``mtime_changed_hash_same`` -- a touched but byte-identical file,
            which is benign. Use it for milestone gates and any time the fast mode
            flagged something.

Both modes open files read-only; nothing inside the installation is ever written
(decision D-01).

The one path this tool writes is ``--json``, and layer 1 of the same safety model
is enforced on it rather than left to the caller: it is passed through
``pathguard.check_output_path`` against the installation root (the ``--install-dir``
argument, or the ``install_dir`` recorded in the inventory) before the comparison
starts. A path that resolves inside the installation -- by any spelling: relative,
different case, trailing separator, 8.3 short name, junction, or the root itself --
is refused with exit code 2 and no file is created. Writing the report into the
installation would be self-defeating: it would alter the very tree being verified
and make the next run of this tool report an ``added`` finding for the report.

Findings
--------
Serious: ``missing``, ``added``, ``size_changed``, ``hash_changed``,
``unreadable``, ``mtime_changed_unverified`` (fast mode only).
Benign:  ``mtime_changed_hash_same``, ``baseline_hash_missing``.

The distinction matters: a changed mtime with an identical hash means the content
of the installation is intact, so research findings keyed on ``build_key`` remain
valid. A changed hash means they may not.

Known limitation: the inventory records files, not directories, so an added *empty*
directory produces no finding. Any file inside it does.

Exit codes
----------
0  the installation matches (no serious findings; benign findings may be printed)
1  the installation does not match (at least one serious finding)
2  usage or I/O error (missing inventory, unreadable inventory, missing install dir)

``--strict`` promotes benign findings to serious, so any deviation at all yields 1.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import snapshot_install as snap  # noqa: E402  (sys.path is prepared just above)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. One implementation for
# every tool that writes a file; do not inline a commonpath check here.
import pathguard  # noqa: E402

SERIOUS_KINDS = frozenset(
    {
        "missing",
        "added",
        "size_changed",
        "hash_changed",
        "unreadable",
        "mtime_changed_unverified",
    }
)
BENIGN_KINDS = frozenset({"mtime_changed_hash_same", "baseline_hash_missing"})

_KIND_ORDER = {
    "hash_changed": 0,
    "size_changed": 1,
    "missing": 2,
    "added": 3,
    "unreadable": 4,
    "mtime_changed_unverified": 5,
    "mtime_changed_hash_same": 6,
    "baseline_hash_missing": 7,
}


def _finding(kind: str, path: str, **detail) -> dict:
    record = {
        "kind": kind,
        "path": path,
        "severity": "serious" if kind in SERIOUS_KINDS else "benign",
    }
    record.update(detail)
    return record


def load_inventory(path: str) -> dict:
    """Load an install-inventory JSON document. Raises OSError/ValueError."""
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict) or not isinstance(document.get("files"), list):
        raise ValueError("%s is not an install-inventory document" % path)
    return document


def verify(
    inventory: dict,
    install_dir: str | None = None,
    fast: bool = False,
    buf_size: int = snap.DEFAULT_BUFFER_BYTES,
) -> list[dict]:
    """Compare the tree at *install_dir* against *inventory*; return findings.

    *install_dir* defaults to the ``install_dir`` recorded in the inventory.
    The returned list is sorted deterministically (by severity class, then kind,
    then path), so two identical runs print identical reports.
    """
    root = os.path.normpath(os.path.abspath(install_dir or inventory["install_dir"]))
    if not os.path.isdir(root):
        raise NotADirectoryError(root)

    findings: list[dict] = []
    baseline = {record["path"]: record for record in inventory["files"]}

    # Present on disk now, keyed the same way the snapshot keys them.
    live: dict[str, os.stat_result] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # `.claude/` is Claude Code's own session infrastructure (e.g.
        # scheduled_tasks.lock), never part of the MISERY install. It can appear
        # under the install root when the research is driven from here; it is
        # definitionally not a game file, so pruning it removes a false-positive
        # `added` finding without weakening verification of any actual game file.
        # (This is the fix anticipated in research/decisions.md, ESC-01 side-note.)
        dirnames[:] = [d for d in dirnames if d != ".claude"]
        dirnames.sort()
        for name in sorted(filenames):
            absolute = os.path.join(dirpath, name)
            relative = snap.relative_posix(root, absolute)
            try:
                live[relative] = os.stat(absolute, follow_symlinks=False)
            except OSError as error:
                findings.append(_finding("unreadable", relative, error=str(error)))

    for relative in sorted(baseline):
        expected = baseline[relative]
        stat = live.get(relative)
        if stat is None:
            findings.append(
                _finding(
                    "missing",
                    relative,
                    expected_size=expected.get("size"),
                    expected_sha256=expected.get("sha256"),
                )
            )
            continue

        actual_size = int(stat.st_size)
        actual_mtime = snap.iso_utc_from_ns(stat.st_mtime_ns)
        size_changed = actual_size != expected.get("size")
        mtime_changed = actual_mtime != expected.get("mtime")

        if size_changed:
            findings.append(
                _finding(
                    "size_changed",
                    relative,
                    expected_size=expected.get("size"),
                    actual_size=actual_size,
                )
            )

        if fast:
            if mtime_changed:
                findings.append(
                    _finding(
                        "mtime_changed_unverified",
                        relative,
                        expected_mtime_utc=expected.get("mtime"),
                        actual_mtime_utc=actual_mtime,
                        note="fast mode did not hash; content state UNKNOWN",
                    )
                )
            continue

        expected_sha256 = expected.get("sha256")
        if expected_sha256 is None:
            findings.append(
                _finding(
                    "baseline_hash_missing",
                    relative,
                    note="inventory carries no sha256 for this file; cannot compare content",
                )
            )
            if mtime_changed:
                findings.append(
                    _finding(
                        "mtime_changed_unverified",
                        relative,
                        expected_mtime_utc=expected.get("mtime"),
                        actual_mtime_utc=actual_mtime,
                        note="no baseline hash to compare against",
                    )
                )
            continue

        try:
            actual_sha256, _ = snap.hash_file(
                os.path.join(root, relative.replace("/", os.sep)), buf_size=buf_size
            )
        except OSError as error:
            findings.append(_finding("unreadable", relative, error=str(error)))
            continue

        if actual_sha256 != expected_sha256:
            findings.append(
                _finding(
                    "hash_changed",
                    relative,
                    expected_sha256=expected_sha256,
                    actual_sha256=actual_sha256,
                    expected_size=expected.get("size"),
                    actual_size=actual_size,
                )
            )
        elif mtime_changed:
            findings.append(
                _finding(
                    "mtime_changed_hash_same",
                    relative,
                    expected_mtime_utc=expected.get("mtime"),
                    actual_mtime_utc=actual_mtime,
                    sha256=actual_sha256,
                    note="content identical; only the timestamp moved",
                )
            )

    for relative in sorted(set(live) - set(baseline)):
        findings.append(
            _finding("added", relative, actual_size=int(live[relative].st_size))
        )

    findings.sort(
        key=lambda item: (
            0 if item["severity"] == "serious" else 1,
            _KIND_ORDER.get(item["kind"], 99),
            item["path"],
        )
    )
    return findings


def format_report(
    findings: list[dict],
    inventory: dict,
    root: str,
    fast: bool,
    strict: bool,
) -> str:
    lines: list[str] = []
    lines.append("verify_install: %s" % root)
    lines.append("  baseline     : %s files, build_id=%s" % (
        len(inventory["files"]), inventory.get("build_id")))
    lines.append("  mode         : %s" % ("fast (size+mtime only)" if fast else "full (re-hash)"))
    if strict:
        lines.append("  strict       : benign findings count as failures")

    serious = [item for item in findings if item["severity"] == "serious"]
    benign = [item for item in findings if item["severity"] == "benign"]

    counts: dict[str, int] = {}
    for item in findings:
        counts[item["kind"]] = counts.get(item["kind"], 0) + 1
    if counts:
        lines.append("  findings     : %s" % ", ".join(
            "%s=%d" % (kind, counts[kind]) for kind in sorted(counts)))
    else:
        lines.append("  findings     : none")

    if serious:
        lines.append("")
        lines.append("SERIOUS (%d):" % len(serious))
        for item in serious:
            lines.append("  [%s] %s" % (item["kind"], item["path"]))
            for key in sorted(item):
                if key in ("kind", "path", "severity"):
                    continue
                lines.append("      %s: %s" % (key, item[key]))
    if benign:
        lines.append("")
        lines.append("BENIGN (%d):" % len(benign))
        for item in benign:
            lines.append("  [%s] %s" % (item["kind"], item["path"]))
            for key in sorted(item):
                if key in ("kind", "path", "severity"):
                    continue
                lines.append("      %s: %s" % (key, item[key]))

    lines.append("")
    if not serious and not benign:
        lines.append("RESULT: MATCH -- installation is identical to the baseline")
    elif serious:
        lines.append("RESULT: MISMATCH -- %d serious finding(s)" % len(serious))
    elif strict:
        lines.append("RESULT: MISMATCH (strict) -- %d benign finding(s)" % len(benign))
    else:
        lines.append(
            "RESULT: MATCH with %d benign finding(s) -- content intact" % len(benign)
        )
    return "\n".join(lines)


def exit_code_for(findings: list[dict], strict: bool = False) -> int:
    if any(item["severity"] == "serious" for item in findings):
        return 1
    if strict and findings:
        return 1
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify_install.py",
        description=(
            "Compare the live installation against an install-inventory JSON. "
            "Read-only; a --json report path inside the game folder is refused "
            "(plan.md D-01, safety model 1.5 layer 1)."
        ),
    )
    parser.add_argument("inventory", help="path to a previously written inventory JSON")
    parser.add_argument(
        "--install-dir",
        default=None,
        help="installation root to check (default: the one recorded in the inventory)",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="compare size+mtime only; fast but cannot prove content is intact",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat benign findings (mtime-only changes) as failures too",
    )
    parser.add_argument(
        "--json",
        default=None,
        help=(
            "also write the findings as JSON to this path; a path resolving inside "
            "the installation is refused (exit 2) before verification starts -- see "
            "plan.md 1.5 layer 1 / D-01"
        ),
    )
    parser.add_argument(
        "--buffer-bytes",
        type=int,
        default=snap.DEFAULT_BUFFER_BYTES,
        help="streaming hash buffer size in bytes (default: %(default)s)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.buffer_bytes <= 0:
        print("--buffer-bytes must be positive", file=sys.stderr)
        return 2

    try:
        # json.JSONDecodeError is a ValueError, so malformed JSON lands here too.
        inventory = load_inventory(args.inventory)
    except (OSError, ValueError) as error:
        print("error: cannot use inventory %s: %s" % (args.inventory, error), file=sys.stderr)
        return 2

    root = os.path.normpath(
        os.path.abspath(args.install_dir or inventory.get("install_dir") or ".")
    )

    # Layer 1 (plan.md 1.5) before layer 3: refuse a report path inside the tree
    # we are about to verify, and refuse it now rather than after a multi-minute
    # full-hash pass.
    report_path = None
    if args.json:
        try:
            report_path = pathguard.check_output_path(args.json, root, what="--json")
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2

    try:
        findings = verify(
            inventory,
            install_dir=root,
            fast=args.fast,
            buf_size=args.buffer_bytes,
        )
    except OSError as error:
        print("error: %s" % error, file=sys.stderr)
        return 2

    print(format_report(findings, inventory, root, args.fast, args.strict))

    if report_path:
        payload = {
            "checked_at": snap.now_iso_utc(),
            "inventory": os.path.normpath(os.path.abspath(args.inventory)),
            "install_dir": root,
            "mode": "fast" if args.fast else "full",
            "strict": bool(args.strict),
            "baseline_build_id": inventory.get("build_id"),
            "baseline_build_key": inventory.get("build_key"),
            "findings": findings,
            "serious_count": sum(1 for i in findings if i["severity"] == "serious"),
            "benign_count": sum(1 for i in findings if i["severity"] == "benign"),
        }
        try:
            # Re-checked at the moment of writing, not only at argument-parse
            # time: the guard must hold even if the code above is reordered.
            target = pathguard.check_output_path(report_path, root, what="--json")
            with open(target, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(
                    json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
                    + "\n"
                )
        except pathguard.OutputPathRefused as error:
            print("error: %s" % error, file=sys.stderr)
            return 2
        except OSError as error:
            print("error: cannot write %s: %s" % (report_path, error), file=sys.stderr)
            return 2

    return exit_code_for(findings, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
