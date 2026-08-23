#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# kb_status.py -- generator for the ONE place in this repository that is
# allowed to carry typed knowledge-base / test-suite numbers.
#
# WHY THIS FILE EXISTS
# --------------------
# The snapshot in docs/toolchain.md section 15.1 went stale twice in two days,
# and the same numbers were ALSO typed into the header comment of
# .github/workflows/ci.yml. Two hand-typed copies of one volatile reading is
# not a diligence problem, it is a mechanism problem: nothing fails when a
# comment stops being true, and nobody can tell by looking whether a number
# was measured five minutes or five days ago.
#
# So the numbers now have exactly one home, and it is generated:
#
#     docs/toolchain.md, between
#         <!-- BEGIN GENERATED kb-status ... -->
#         <!-- END GENERATED kb-status -->
#
# Everything else -- README.md, the ci.yml header, section 16 -- points at
# that region or at a LIVE indicator (the CI badge, the CI job summary) and
# states no numbers of its own. If a number appears in a second file, that is
# the defect returning.
#
# THE TWO COMMANDS
# ----------------
#     python .github\scripts\kb_status.py --write     refresh the region
#     python .github\scripts\kb_status.py --check     is the region current?
#
# --check re-measures, re-renders the region with the RECORDED timestamp and
# commit, and diffs it against what is on disk. Same payload => the block is
# still true and only its date is old. Different payload => stale, and the
# diff says in which number.
#
# WHY --check IS NOT WIRED INTO THE GATE
# -------------------------------------
# Deliberately. docs/toolchain.md section 15.1 already argues it: a test that
# demands the documented numbers equal a fresh run would go red on every
# closed violation -- it would punish progress, and would be muted within a
# week. The volatile numbers are therefore defended by a DATE plus a one-step
# refresh, not by a red build. What CI does check is the live thing: the gate
# itself, plus the generated job summary that cannot be stale because it does
# not exist before the run that prints it.
#
# The interpreter that runs THIS script is the interpreter used for the
# measurement, and it is recorded in the block. Run it with the canonical
# interpreter (docs/toolchain.md section 3.1) or the block will honestly say
# you did not.
# ---------------------------------------------------------------------------
"""Regenerate (or verify) the generated knowledge-base status block."""

from __future__ import annotations

import argparse
import difflib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

GENERATOR_VERSION = "1.0.0"

BEGIN_RE = re.compile(
    r"<!--\s*BEGIN GENERATED kb-status\b[^>]*-->", re.IGNORECASE)
END_MARKER = "<!-- END GENERATED kb-status -->"

# The meta line carries the three facts that legitimately differ between two
# runs of --check over an unchanged repository: when it was taken, at which
# commit, and by which interpreter. --check re-uses them verbatim so that a
# difference in the diff always means a difference in a MEASUREMENT.
META_RE = re.compile(
    r"^>\s*\*\*Снято:\*\*\s*(?P<taken>[^|]+?)\s*\|\s*HEAD\s*`(?P<head>[^`]*)`"
    r"\s*\|\s*интерпретатор\s*`(?P<python>[^`]*)`",
    re.MULTILINE)

# Files that host the generated region. Exactly one, on purpose (see header).
HOST = Path("docs/toolchain.md")


def repo_root() -> Path:
    # .github/scripts/kb_status.py -> repo root is two levels up
    return Path(__file__).resolve().parents[2]


def run(root: Path, args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        args, cwd=str(root), capture_output=True, text=True,
        encoding="utf-8", errors="replace")
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def git_head(root: Path) -> str:
    """Short HEAD hash, or 'не определён'. Read-only: rev-parse only."""
    code, out = run(root, ["git", "rev-parse", "--short", "HEAD"])
    if code != 0:
        return "не определён"
    return out.strip().splitlines()[0] if out.strip() else "не определён"


def measure_validator(root: Path) -> dict:
    """Run tools/kb/validate.py --json and reduce it to what the block prints."""
    code, out = run(
        root, [sys.executable, str(Path("tools") / "kb" / "validate.py"),
               "--json"])
    start = out.find("{")
    if start < 0:
        raise SystemExit(
            "validate.py --json produced no JSON object; output was:\n" + out)
    doc = json.loads(out[start:])
    summary = doc["summary"]

    by_file: list[tuple[str, int, int, int]] = []
    for entry in doc.get("files", []):
        errors = int(entry.get("errors", 0))
        warnings = int(entry.get("warnings", 0))
        unparseable = int(entry.get("unparseable_count", 0))
        if errors or unparseable:
            by_file.append((entry["path"], errors, unparseable, warnings))
    by_file.sort(key=lambda row: (-row[1], -row[2], row[0]))

    rules = {}
    for rule, counts in (summary.get("by_rule") or {}).items():
        if isinstance(counts, dict):
            # rule_histogram() names the error bucket "errors"; the summary
            # names the same total "violations". Accept either spelling so a
            # rename in the validator degrades to a zero, not to a crash.
            rules[rule] = (int(counts.get("errors",
                                          counts.get("violations", 0))),
                           int(counts.get("warnings", 0)))
        else:  # tolerate a flat {rule: violations} shape
            rules[rule] = (int(counts), 0)

    return {
        "schema_backend": doc.get("schema_backend"),
        "files": summary.get("files"),
        "records": summary.get("records"),
        "records_by_notation": dict(summary.get("records_by_notation") or {}),
        "unparseable": summary.get("unparseable_records"),
        "violations": summary.get("violations"),
        "warnings": summary.get("warnings"),
        "by_rule": rules,
        "by_file": by_file,
        "exit_code": code,
    }


def interpreter_label() -> str:
    """The interpreter path, with any user-profile prefix redacted (C-13).

    The block is committed to a PUBLIC repository. A run under a per-user
    interpreter must not write a literal profile path into it, so the profile
    part is replaced by a placeholder and the fact that it was redacted stays
    visible.
    """
    raw = sys.executable
    home = str(Path.home())
    if home and raw.lower().startswith(home.lower()):
        return "<user-profile>" + raw[len(home):] + " (путь профиля скрыт, C-13)"
    return raw


def measure_pytest(root: Path) -> dict:
    """Run the suite and keep the summary line plus the failing node ids.

    -rf is added so the failing node ids are printed as node ids rather than
    read out of a traceback. It changes no count: the documented human command
    stays `python -m pytest -q`.
    """
    code, out = run(root, [sys.executable, "-m", "pytest", "-q", "-rf"])
    lines = [line.rstrip() for line in out.splitlines()]

    summary = ""
    for line in reversed(lines):
        stripped = line.strip().strip("=").strip()
        if not stripped:
            continue
        if re.search(r"\b\d+\s+(passed|failed|error|skipped)", stripped):
            # Drop the wall-clock duration. It differs on every run over an
            # unchanged repository, and leaving it in would make --check
            # report STALE always -- which would train everyone to ignore
            # --check, the exact failure mode this whole mechanism exists to
            # avoid. The duration is not a fact about the repository.
            summary = re.sub(r"\s+in\s+[\d.,]+\s*s$", "", stripped)
            break

    failed = []
    for line in lines:
        match = re.match(r"^FAILED\s+(?P<node>\S+)", line.strip())
        if match:
            node = match.group("node").replace("\\", "/")
            if node not in failed:
                failed.append(node)
    return {"summary": summary, "failed": failed, "exit_code": code}


def payload(root: Path) -> dict:
    return {"validator": measure_validator(root), "pytest": measure_pytest(root)}


def _notations(counts: dict) -> str:
    order = ["inline-annotation", "log-entry", "table-row", "json"]
    keys = [k for k in order if k in counts] + \
           [k for k in sorted(counts) if k not in order]
    return ", ".join(f"{k}={counts[k]}" for k in keys) or "—"


def render(data: dict, taken_at: str, head: str, python: str) -> str:
    val = data["validator"]
    pyt = data["pytest"]
    out: list[str] = []
    add = out.append

    add(f"<!-- BEGIN GENERATED kb-status v{GENERATOR_VERSION} "
        f"-- правится генератором, не руками -->")
    add("")
    add("> **Этот блок сгенерирован.** Руками его не правят: правка будет "
        "затёрта следующим запуском генератора, и — что хуже — станет "
        "неотличима от измерения.")
    add(">")
    add(f"> **Снято:** {taken_at} | HEAD `{head}` | интерпретатор `{python}`")
    add(">")
    add("> Обновить (один шаг): "
        "`python .github\\scripts\\kb_status.py --write`")
    add(">")
    add("> Спросить, не устарел ли блок, ничего не правя: "
        "`python .github\\scripts\\kb_status.py --check` — он перемеряет, "
        "пересобирает блок с ЭТОЙ датой и этим HEAD и печатает diff. Пустой "
        "diff = числа всё ещё верны, устарела только дата. Непустой diff "
        "называет, какое именно число разошлось. Выход 1 = блок устарел.")
    add(">")
    add("> Почему `--check` не встроен в гейт — см. врезку после блока и шапку "
        "генератора: тест, требующий совпадения документа со свежим прогоном, "
        "краснел бы на каждом закрытом нарушении, то есть наказывал бы за "
        "прогресс.")
    add("")

    add("**Валидатор базы знаний — "
        f"`tools\\kb\\validate.py` (exit {val['exit_code']}).**")
    add("")
    add("| показатель | значение |")
    add("|---|---|")
    add(f"| schema backend | `{val['schema_backend']}` |")
    add(f"| файлов просмотрено | {val['files']} |")
    add(f"| размеченных записей | {val['records']} |")
    add(f"| записей по нотациям | {_notations(val['records_by_notation'])} |")
    add(f"| нечитаемых кандидатов в записи | **{val['unparseable']}** |")
    add(f"| нарушений (ERROR) | **{val['violations']}** |")
    add(f"| предупреждений (WARN) | {val['warnings']} |")
    add(f"| exit code | {val['exit_code']} |")
    add("")
    # The validator is run WITHOUT --require-jsonschema on purpose: a
    # degraded backend has to be reported, not turned into a crash that
    # produces no block at all. But a degraded run must never be mistaken for
    # a measurement, so say it here in words (docs/toolchain.md 3.1,
    # finding MAJOR-6).
    if (val["schema_backend"] or "").lower() != "jsonschema":
        add(f"> **Результат этого прогона НЕДЕЙСТВИТЕЛЕН: schema backend — "
            f"`{val['schema_backend']}`, а не `jsonschema`.** Валидатор "
            f"деградировал до встроенного минимального чекера, который "
            f"игнорирует `format` и `propertyNames` и всё равно выходит с "
            f"кодом 0 (находка MAJOR-6). Числа ниже читать как «проверка не "
            f"проводилась», а не как «нарушений нет». См. §3.1 и §15 п.9.")
        add("")

    if val["by_rule"]:
        add("Нарушения и предупреждения по правилам:")
        add("")
        add("| правило | нарушений | предупреждений |")
        add("|---|---|---|")
        for rule in sorted(val["by_rule"],
                           key=lambda r: (-val["by_rule"][r][0], r)):
            errors, warnings = val["by_rule"][rule]
            add(f"| `{rule}` | {errors} | {warnings} |")
        add("")

    if val["by_file"]:
        add("Файлы-носители нарушений (файл без нарушений в таблицу не "
            "попадает):")
        add("")
        add("| файл | нарушений | нечитаемых | предупреждений |")
        add("|---|---|---|---|")
        for path, errors, unparseable, warnings in val["by_file"]:
            add(f"| `{path}` | {errors} | {unparseable} | {warnings} |")
        add("")
    else:
        add("Ни один файл не несёт нарушений и нечитаемых кандидатов.")
        add("")

    add(f"**Набор тестов — `python -m pytest -q` (exit {pyt['exit_code']}).**")
    add("")
    add("```")
    add(pyt["summary"] or "(суммарная строка не распознана — см. полный вывод)")
    add("```")
    add("")
    if pyt["failed"]:
        add("Провалившиеся тесты, по идентификаторам узлов:")
        add("")
        for node in pyt["failed"]:
            add(f"* `{node}`")
        add("")
    else:
        add("Провалившихся тестов нет.")
        add("")

    add(END_MARKER)
    return "\n".join(out)


def split_host(text: str) -> tuple[str, str, str]:
    """Return (prefix, region, suffix) around the generated region."""
    begin = BEGIN_RE.search(text)
    if not begin:
        raise SystemExit(
            f"{HOST}: no '<!-- BEGIN GENERATED kb-status ... -->' marker found")
    end = text.find(END_MARKER, begin.end())
    if end < 0:
        raise SystemExit(f"{HOST}: '{END_MARKER}' not found after the BEGIN marker")
    return (text[:begin.start()],
            text[begin.start():end + len(END_MARKER)],
            text[end + len(END_MARKER):])


def read_host(root: Path) -> str:
    return (root / HOST).read_text(encoding="utf-8")


def write_host(root: Path, text: str) -> None:
    (root / HOST).write_text(text, encoding="utf-8", newline="\n")


def cmd_write(root: Path) -> int:
    data = payload(root)
    taken = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    block = render(data, taken, git_head(root), interpreter_label())
    prefix, _old, suffix = split_host(read_host(root))
    write_host(root, prefix + block + suffix)
    val = data["validator"]
    print(f"{HOST}: generated region refreshed ({taken})")
    print(f"  records={val['records']} violations={val['violations']} "
          f"unparseable={val['unparseable']} exit={val['exit_code']}")
    print(f"  pytest: {data['pytest']['summary']}")
    return 0


def cmd_check(root: Path) -> int:
    _prefix, old, _suffix = split_host(read_host(root))
    meta = META_RE.search(old)
    if not meta:
        print(f"{HOST}: the generated region has no recognisable meta line; "
              f"regenerate it with --write")
        return 1
    fresh = render(payload(root), meta.group("taken").strip(),
                   meta.group("head"), meta.group("python"))
    if fresh.strip() == old.strip():
        print(f"{HOST}: generated region is CURRENT "
              f"(taken {meta.group('taken').strip()}); only its date is older "
              f"than this run.")
        return 0
    print(f"{HOST}: generated region is STALE "
          f"(taken {meta.group('taken').strip()}). Difference, "
          f"on disk (-) vs fresh measurement (+):")
    for line in difflib.unified_diff(
            old.strip().splitlines(), fresh.strip().splitlines(),
            fromfile="on disk", tofile="fresh", lineterm=""):
        print("  " + line)
    print(f"  Refresh with: python .github\\scripts\\kb_status.py --write")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kb_status.py",
        description=("Regenerate or verify the single generated status block "
                     "in docs/toolchain.md section 15.1."),
        epilog=("The block is the only place in the repository allowed to "
                "carry typed validator / suite numbers. README.md and the "
                "ci.yml header carry live indicators and pointers instead."))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true",
                       help="measure and rewrite the generated region")
    group.add_argument("--check", action="store_true",
                       help=("measure and diff against the region on disk; "
                             "exit 1 if a number moved"))
    parser.add_argument("--repo-root", default=None,
                        help="override the repository root (default: inferred)")
    args = parser.parse_args(argv)

    root = Path(args.repo_root).resolve() if args.repo_root else repo_root()
    return cmd_write(root) if args.write else cmd_check(root)


if __name__ == "__main__":
    raise SystemExit(main())
