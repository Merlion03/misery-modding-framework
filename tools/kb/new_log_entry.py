#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Append one entry to research/RESEARCH_LOG.md.

Implements plan.md task K-05 (section 9.4) using the exact entry template of
plan.md section 9.3.  The point of this tool is stated in the plan itself:
"уменьшает шанс, что вывод не будет записан".

Guarantees:
  * append-only: existing bytes are never rewritten, reordered or reformatted;
  * LOG-NNNN ids are auto-incremented by scanning the ID lines already present;
  * a missing optional field renders as an explicit TODO marker, never as a
    silently empty line;
  * safe when research/RESEARCH_LOG.md does not exist yet - the file is created
    with a header.  (The seed file itself is owned elsewhere; this tool only
    has to survive both cases.)
  * UTF-8 without BOM, LF line endings.

Examples:
    python tools/kb/new_log_entry.py --question "Какой exe стартует Steam?"
    python tools/kb/new_log_entry.py --question "..." --method RF-05 \\
        --evidence research/evidence/RF-05/xrefs-uobjectarray.json \\
        --finding "..." --level INFERRED --confidence 0.65 \\
        --build sha256:<64hex> --supersedes LOG-0031 --next "..."
    python tools/kb/new_log_entry.py --question "..." --dry-run

Exit codes:
    0  entry appended (or rendered, with --dry-run)
    2  invalid arguments / unwritable log
"""

from __future__ import annotations

import argparse
import datetime as _dt
import io
import re
import sys
from pathlib import Path
from typing import Sequence

GENERATOR_VERSION = "1.0.0"

# Keep in sync with tools/kb/validate.py (plan.md 10.1 / 10.2 / 3.2).
EVIDENCE_LEVELS: tuple[str, ...] = (
    "OBSERVED",
    "INFERRED",
    "HYPOTHESIS",
    "UNKNOWN",
    "REFUTED",
)
BUILD_KEY_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# plan.md 9.3: "- **ID:** LOG-0042"
ID_LINE_RE = re.compile(r"^-\s+\*\*ID:\*\*\s+LOG-(\d+)\s*$", re.MULTILINE)
ID_WIDTH = 4

EM_DASH = "—"
TITLE_MAX_LEN = 90

FILE_HEADER = """# RESEARCH_LOG

Append-only журнал исследования MISERY Modding Framework.

Формат записи зафиксирован в `plan.md` §9.3. Записи только **добавляются в
конец**: существующие записи никогда не переписываются и не переупорядочиваются.
Изменение вывода — это новая запись со ссылкой `Supersedes:` на предыдущую
(`plan.md` §9.1).

Записи создаются генератором `tools/kb/new_log_entry.py` (`plan.md` §9.4, K-05).
"""

# One TODO text per optional field, so a half-filled entry is visibly unfinished.
TODO_MARKERS: dict[str, str] = {
    "method": "TODO: указать метод (id из plan.md, например RF-05)",
    "evidence": "TODO: указать путь к сырому артефакту в research/evidence/<method-id>/",
    "finding": "TODO: сформулировать вывод",
    "level": "TODO: " + " | ".join(EVIDENCE_LEVELS) + " (plan.md §10.1)",
    "confidence": "TODO: 0.00-0.99 (plan.md §10.2, значение 1.00 не используется)",
    "build": "TODO: build_key=sha256:<64 hex> (plan.md §3.2)",
    "supersedes": "TODO: LOG-NNNN или none",
    "next": "TODO: сформулировать следующий вопрос",
}


# ---------------------------------------------------------------------------
# id handling
# ---------------------------------------------------------------------------

def scan_ids(text: str) -> list[int]:
    """Return every numeric LOG id found on an ID line, in file order."""
    return [int(m.group(1)) for m in ID_LINE_RE.finditer(text)]


def next_log_id(text: str) -> str:
    """Next LOG-NNNN id for a log whose current content is `text`."""
    ids = scan_ids(text)
    number = (max(ids) + 1) if ids else 1
    width = ID_WIDTH
    for match in ID_LINE_RE.finditer(text):
        width = max(width, len(match.group(1)))
    return f"LOG-{number:0{width}d}"


def read_log(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8-sig")


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def _value_or_todo(value: str | None, key: str) -> str:
    if value is None:
        return TODO_MARKERS[key]
    value = value.strip()
    if not value:
        return TODO_MARKERS[key]
    return value


def make_title(question: str, title: str | None) -> str:
    if title and title.strip():
        return title.strip()
    text = " ".join(question.split())
    if len(text) <= TITLE_MAX_LEN:
        return text
    cut = text[:TITLE_MAX_LEN].rsplit(" ", 1)[0]
    return (cut or text[:TITLE_MAX_LEN]) + "..."


def format_confidence(value: str | None) -> str:
    if value is None or not str(value).strip():
        return TODO_MARKERS["confidence"]
    return f"{float(value):.2f}"


def format_build(value: str | None) -> str:
    if value is None or not value.strip():
        return TODO_MARKERS["build"]
    value = value.strip()
    if "=" in value:
        return value
    return f"build_key={value}"


def render_entry(
    log_id: str,
    date: str,
    question: str,
    title: str | None = None,
    method: str | None = None,
    evidence: str | None = None,
    finding: str | None = None,
    level: str | None = None,
    confidence: str | None = None,
    build: str | None = None,
    supersedes: str | None = None,
    next_question: str | None = None,
) -> str:
    """Render one entry in the exact field order of plan.md 9.3."""
    lines = [
        f"## {date} {EM_DASH} {make_title(question, title)}",
        f"- **ID:** {log_id}",
        f"- **Question:** {' '.join(question.split())}",
        f"- **Method:** {_value_or_todo(method, 'method')}",
        f"- **Evidence:** {_value_or_todo(evidence, 'evidence')}",
        f"- **Finding:** {_value_or_todo(finding, 'finding')}",
        f"- **Evidence level:** {_value_or_todo(level, 'level')}",
        f"- **Confidence:** {format_confidence(confidence)}",
        f"- **Build:** {format_build(build)}",
        f"- **Supersedes:** {_value_or_todo(supersedes, 'supersedes')}",
        f"- **Next question:** {_value_or_todo(next_question, 'next')}",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# append-only write
# ---------------------------------------------------------------------------

def append_entry(path: Path, entry: str, create_header: bool = True) -> None:
    """Append `entry` to `path`, never touching what is already there."""
    existing = read_log(path) if path.exists() else None

    if existing is None:
        prefix = (FILE_HEADER + "\n") if create_header else ""
        with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(prefix + entry)
        return

    # Decide the separator without rewriting a single existing byte.
    if existing == "":
        separator = ""
    elif existing.endswith("\n\n"):
        separator = ""
    elif existing.endswith("\n"):
        separator = "\n"
    else:
        separator = "\n\n"

    with io.open(path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(separator + entry)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def default_log_path() -> Path:
    # tools/kb/new_log_entry.py -> <repo root>/research/RESEARCH_LOG.md
    return Path(__file__).resolve().parents[2] / "research" / "RESEARCH_LOG.md"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Append a plan.md 9.3 formatted entry to research/RESEARCH_LOG.md "
                    "(plan.md 9.4, K-05).",
    )
    parser.add_argument("--question", required=True,
                        help="the research question this entry answers (required)")
    parser.add_argument("--title", default=None,
                        help="short heading text; default: a truncation of --question")
    parser.add_argument("--method", default=None,
                        help="method id, e.g. 'RF-05 (Ghidra xrefs)'")
    parser.add_argument("--evidence", default=None,
                        help="path to the saved raw artifact under research/evidence/")
    parser.add_argument("--finding", default=None, help="the conclusion")
    parser.add_argument("--level", default=None, choices=list(EVIDENCE_LEVELS),
                        help="evidence level (plan.md 10.1)")
    parser.add_argument("--confidence", default=None,
                        help="0.00-0.99; 1.00 is forbidden by plan.md 10.2")
    parser.add_argument("--build", default=None,
                        help="build_key, e.g. sha256:<64 hex>, or the literal UNKNOWN")
    parser.add_argument("--supersedes", default=None,
                        help="LOG-NNNN this entry replaces; pass 'none' when it "
                             "replaces nothing")
    parser.add_argument("--next", default=None, dest="next_question",
                        help="the next question this finding opens")
    parser.add_argument("--date", default=None,
                        help="entry date, YYYY-MM-DD (default: today, UTC)")
    parser.add_argument("--log", default=None,
                        help="path to RESEARCH_LOG.md (default: <repo>/research/"
                             "RESEARCH_LOG.md)")
    parser.add_argument("--no-header", action="store_true",
                        help="when creating the file, do not write the file header")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the entry instead of appending it")
    return parser


def validate_args(args: argparse.Namespace) -> list[str]:
    problems: list[str] = []

    if not args.question.strip():
        problems.append("--question must not be empty")

    if args.confidence is not None and args.confidence.strip():
        try:
            value = float(args.confidence)
        except ValueError:
            problems.append(f"--confidence {args.confidence!r} is not a number")
        else:
            if value < 0.0 or value > 1.0:
                problems.append(f"--confidence {value} is outside [0.00, 1.00]")
            elif value >= 1.0:
                problems.append("--confidence 1.00 is forbidden (plan.md 10.2: "
                                "\"не используется\")")

    if args.date is not None and args.date.strip():
        try:
            _dt.date.fromisoformat(args.date.strip())
        except ValueError:
            problems.append(f"--date {args.date!r} is not ISO YYYY-MM-DD")

    if args.supersedes is not None and args.supersedes.strip():
        text = args.supersedes.strip()
        if text.lower() not in ("none", "-") and not re.fullmatch(r"LOG-\d{4,}", text):
            problems.append(f"--supersedes {text!r} must be 'LOG-NNNN' or 'none'")

    return problems


def warnings_for(args: argparse.Namespace) -> list[str]:
    notes: list[str] = []
    if args.confidence is not None and args.confidence.strip():
        try:
            value = float(args.confidence)
        except ValueError:
            value = None
        if value is not None and value >= 0.8:
            notes.append("confidence >= 0.80: plan.md 10.4/EV-03 requires at least two "
                         "independent sources, and 10.3 requires a saved raw artifact "
                         "plus an explicit build_key - make sure the machine-readable "
                         "record carries them")
    if args.build is not None and args.build.strip():
        value = args.build.strip()
        bare = value.split("=", 1)[1] if "=" in value else value
        if bare != "UNKNOWN" and not BUILD_KEY_RE.match(bare):
            notes.append(f"build value {bare!r} is not 'sha256:<64 lowercase hex>' nor "
                         "'UNKNOWN' (plan.md 3.2)")
    if args.level in ("OBSERVED", "INFERRED") and not (args.evidence or "").strip():
        notes.append("evidence level OBSERVED/INFERRED without --evidence: plan.md 10.3 "
                     "rule 3 requires a saved raw artifact")
    return notes


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    problems = validate_args(args)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2

    log_path = Path(args.log).resolve() if args.log else default_log_path()
    date = (args.date or "").strip() or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")

    existing = read_log(log_path)
    log_id = next_log_id(existing)

    entry = render_entry(
        log_id=log_id,
        date=date,
        question=args.question,
        title=args.title,
        method=args.method,
        evidence=args.evidence,
        finding=args.finding,
        level=args.level,
        confidence=args.confidence,
        build=args.build,
        supersedes=args.supersedes,
        next_question=args.next_question,
    )

    for note in warnings_for(args):
        print(f"warning: {note}", file=sys.stderr)

    if args.dry_run:
        sys.stdout.write(entry)
        print(f"# dry run: nothing written; would append {log_id} to {log_path}",
              file=sys.stderr)
        return 0

    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        created = not log_path.exists()
        append_entry(log_path, entry, create_header=not args.no_header)
    except OSError as exc:
        print(f"error: cannot write {log_path}: {exc}", file=sys.stderr)
        return 2

    action = "created and wrote" if created else "appended"
    print(f"{log_id} {action} -> {log_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
