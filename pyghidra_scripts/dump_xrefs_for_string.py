#!/usr/bin/env python3
"""S-03 -- xrefs to a given string (plan.md §7.3 S-03 / §6.2 RF-04).

RF-04's method, mechanised
---------------------------
plan.md §6.2 names RF-04 as "поиск известных строк-якорей (\"UObjectBase\",
\"None\", \"ProcessEvent\", \"CoreUObject\", \"/Script/CoreUObject\", ...) и их
xrefs" -> "кандидатные функции инициализации reflection". This script IS that
search, made repeatable: given one or more needle strings, it walks every
DEFINED string/data item in the program's listing, keeps the ones containing
a needle, and for each kept occurrence lists every cross-reference TO that
address -- the referencing (instruction) address, the function containing
that instruction if any, and the reference type Ghidra assigned. It finds
CANDIDATES; it does not decide what a candidate function does (that is S-04)
or draw the graph around it (that is S-05).

Why "defined data", and what that surface does and does not cover
---------------------------------------------------------------------
"Occurrence" here means a Ghidra-DEFINED string Data item whose value
contains the needle -- the same surface RF-04 describes ("строк-якорей"),
produced by Ghidra's own "ASCII Strings" analyzer during the T-05
default-analysis run this script reuses. A raw byte scan of the whole image
(S-01's method) would find MORE candidate locations, including ones Ghidra's
analyzer did not turn into a Data item (e.g. inside an already-disassembled
instruction, or a run the analyzer's length/charset heuristics rejected) --
that surface is exactly what S-01 already covers, and duplicating it here
would blur which tool is answering which question. A needle that exists in
the image but never became defined string data will report zero occurrences
from this tool; that is not evidence the string is absent, only that it
was not surfaced by Ghidra's own string analyzer (see S-01 for a whole-image
answer to that separate question).

Matching is substring-by-default, case-sensitive by default: a needle used to
mean "does this data item MENTION the anchor" (e.g. needle "CoreUObject"
matching a defined string "/Script/CoreUObject" as well as a standalone
"CoreUObject"), which is what a source-path or a full-path FName literal
would produce. ``--whole-string`` restricts to exact equality;
``--ignore-case`` folds case for both the needle and the haystack.

Output
------
One JSONL record per xref (``--jsonl-out``), plus a JSON summary
(``--out``) with per-occurrence detail and the counts the task asks for:
occurrence count, total xref count, distinct containing-function count.

Class of the claims this run's evidence supports
--------------------------------------------------
The address, length and literal value of an occurrence, and the address/type
of a single xref, are class-P-shaped (a determinate location, a length, no
naming of what the reference MEANS) -- see this tool's own
``research/evidence/S-03/README.md`` for the actual graded claims from a real
run; nothing here asserts a function's PURPOSE (that step, e.g. "this looks
like an initialization routine", is HYPOTHESIS and belongs to RF-04's own
finding write-up in a later wave, not to this tool).

Run only with ``D:\\Tools\\venv-research\\Scripts\\python.exe``.

CLI
---
    python pyghidra_scripts/dump_xrefs_for_string.py --needle CoreUObject \\
        --needle /Script/CoreUObject \\
        --out research/evidence/S-03/xrefs-summary.json \\
        --jsonl-out workspace/xrefs/coreuobject.jsonl
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Iterable

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import _pyghidra_runner as runner  # noqa: E402

GENERATOR_NAME = "pyghidra_scripts/dump_xrefs_for_string.py"
GENERATOR_VERSION = "1.0.0"

QUESTION = (
    "plan.md RF-04: which defined strings/data in this build contain a given "
    "anchor literal, and what cross-references does each occurrence have "
    "(referencing address, containing function, reference type)?"
)

DEFAULT_MAX_STRING_LENGTH = 2000


# --------------------------------------------------------------------------- #
# core logic -- narrow interfaces, so tests can fake them without a real JVM
# --------------------------------------------------------------------------- #

def string_matches(value: str, needle: str, *, whole_string: bool,
                   ignore_case: bool) -> bool:
    v = value.lower() if ignore_case else value
    n = needle.lower() if ignore_case else needle
    return (v == n) if whole_string else (n in v)


def find_string_occurrences(
    listing: Any,
    needles: list[str],
    *,
    whole_string: bool = False,
    ignore_case: bool = False,
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH,
) -> list[dict]:
    """Walk ``listing.getDefinedData(True)``; keep every Data item that
    ``hasStringValue()`` and whose value matches at least one needle.

    *listing* needs exactly one method: ``getDefinedData(True) ->
    Iterable[data]``, where each *data* needs ``hasStringValue() -> bool``,
    ``getValue() -> str-convertible``, ``getAddress() -> address-like``
    (``str()``-able) and ``getLength() -> int``. Ghidra's real
    ``ghidra.program.model.listing.Listing``/``Data`` satisfy this; the tests
    use plain Python stand-ins.

    A Data item matching MULTIPLE needles yields one occurrence record per
    matching needle (so the summary's per-needle counts add up), all sharing
    the same address/value/length.
    """
    occurrences: list[dict] = []
    for data in listing.getDefinedData(True):
        if not data.hasStringValue():
            continue
        raw = data.getValue()
        if raw is None:
            continue
        value = str(raw)
        if len(value) > max_string_length:
            value = value[:max_string_length]
        for needle in needles:
            if string_matches(value, needle, whole_string=whole_string,
                             ignore_case=ignore_case):
                occurrences.append({
                    "needle": needle,
                    "address": str(data.getAddress()),
                    "length": int(data.getLength()),
                    "value": value,
                    "value_truncated": len(str(raw)) > max_string_length,
                })
    return occurrences


def find_xrefs_to_address(reference_manager: Any, function_manager: Any,
                          address: Any) -> list[dict]:
    """Every xref TO *address*: referencing address, containing function
    (or None), reference type. *reference_manager* needs
    ``getReferencesTo(address) -> Iterable[ref]`` with ``ref.getFromAddress()``,
    ``ref.getReferenceType()`` and ``ref.isPrimary()``; *function_manager*
    needs ``getFunctionContaining(address) -> function-or-None``.
    """
    records = []
    for ref in reference_manager.getReferencesTo(address):
        from_addr = ref.getFromAddress()
        containing = function_manager.getFunctionContaining(from_addr)
        records.append({
            "referencing_address": str(from_addr),
            "containing_function": runner.describe_function_brief(containing),
            "reference_type": runner.classify_ref_type(ref.getReferenceType()),
            "is_primary": bool(ref.isPrimary()),
        })
    return records


def build_records_and_summary(
    program: Any,
    needles: list[str],
    *,
    whole_string: bool,
    ignore_case: bool,
    max_string_length: int,
) -> tuple[list[dict], dict]:
    """Drive the two functions above against a real (or faked) ``program``
    and assemble the JSONL records plus the counts the summary needs.
    """
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    func_mgr = program.getFunctionManager()

    occurrences = find_string_occurrences(
        listing, needles, whole_string=whole_string, ignore_case=ignore_case,
        max_string_length=max_string_length)

    address_factory = program.getAddressFactory()
    records: list[dict] = []
    containing_function_entries: set[str] = set()
    per_needle_xrefs: dict[str, int] = {n: 0 for n in needles}
    ref_type_histogram: dict[str, int] = {}

    for occ in occurrences:
        addr = address_factory.getAddress(occ["address"])
        xrefs = find_xrefs_to_address(ref_mgr, func_mgr, addr)
        for xref in xrefs:
            record = {
                "needle": occ["needle"],
                "string_address": occ["address"],
                "string_length": occ["length"],
                "string_value": occ["value"],
                "referencing_address": xref["referencing_address"],
                "containing_function": xref["containing_function"],
                "reference_type": xref["reference_type"],
                "is_primary": xref["is_primary"],
            }
            records.append(record)
            per_needle_xrefs[occ["needle"]] = per_needle_xrefs.get(occ["needle"], 0) + 1
            if xref["containing_function"] is not None:
                containing_function_entries.add(xref["containing_function"]["entry"])
            bucket = xref["reference_type"]["bucket"]
            ref_type_histogram[bucket] = ref_type_histogram.get(bucket, 0) + 1

    occurrences_without_xrefs = sum(
        1 for occ in occurrences
        if not any(r["string_address"] == occ["address"] and r["needle"] == occ["needle"]
                  for r in records)
    )

    summary_counts = {
        "occurrence_count": len(occurrences),
        "occurrences_with_no_xrefs": occurrences_without_xrefs,
        "xref_count": len(records),
        "distinct_containing_functions": len(containing_function_entries),
        "xrefs_per_needle": per_needle_xrefs,
        "reference_type_histogram": ref_type_histogram,
        "occurrences": occurrences,
    }
    return records, summary_counts


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dump_xrefs_for_string.py",
        description=(
            "S-03: find every defined string/data occurrence of one or more "
            "needle strings and list every xref to each occurrence "
            "(plan.md RF-04)."),
    )
    parser.add_argument("--needle", action="append", required=True, metavar="TEXT",
                        help="string to search for; repeatable")
    parser.add_argument("--whole-string", action="store_true",
                        help="require the defined data value to EQUAL the needle "
                             "(default: substring match)")
    parser.add_argument("--ignore-case", action="store_true",
                        help="case-insensitive matching")
    parser.add_argument("--max-string-length", type=int,
                        default=DEFAULT_MAX_STRING_LENGTH,
                        help="truncate an over-long defined string value in the "
                             "output (does not affect matching against the "
                             "untruncated value)")
    parser.add_argument("--out", required=True, help="JSON summary output path")
    parser.add_argument("--jsonl-out", required=True,
                        help="JSONL xref-records output path")
    runner.add_common_arguments(parser)
    return parser


@runner.handle_prerequisite_errors
def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    # Layer 1 first: a refused output path costs nothing (checked before the
    # JVM starts, matching ghidra_import.py's own ordering).
    for flag, value in (("--out", args.out), ("--jsonl-out", args.jsonl_out)):
        pathguard_target = value
        runner.pathguard.check_output_path(
            pathguard_target, args.install_dir or runner.pathguard.CONFIGURED_INSTALL_ROOTS[0],
            what=flag)

    copy_record = None
    if not args.skip_copy_verification:
        copy_record = runner.verify_target_copy(args.target_copy, args.expect_sha256)

    generated_at = runner.recorded_at(args)

    with runner.open_program_from_args(args) as (project, program):
        records, counts = build_records_and_summary(
            program, args.needle, whole_string=args.whole_string,
            ignore_case=args.ignore_case, max_string_length=args.max_string_length)
        program_name = program.getName()

    jsonl_path = runner.write_jsonl_guarded(records, args.jsonl_out, args.install_dir,
                                            "--jsonl-out")
    jsonl_text = runner.dump_jsonl(records)

    document = {
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
        "generated_at": generated_at,
        "question": QUESTION,
        "task": "plan.md §7.3 S-03 / §6.2 RF-04",
        "build_key": runner.DEFAULT_BUILD_KEY if args.expect_sha256 == runner.DEFAULT_EXPECT_SHA256
                    else ("sha256:" + args.expect_sha256 if args.expect_sha256 else None),
        "target_copy": copy_record,
        "project": {"root": args.project_root, "name": args.project_name,
                   "program": args.program, "program_name": program_name},
        "needles": args.needle,
        "whole_string": args.whole_string,
        "ignore_case": args.ignore_case,
        "max_string_length": args.max_string_length,
        "occurrence_count": counts["occurrence_count"],
        "occurrences_with_no_xrefs": counts["occurrences_with_no_xrefs"],
        "xref_count": counts["xref_count"],
        "distinct_containing_functions": counts["distinct_containing_functions"],
        "xrefs_per_needle": counts["xrefs_per_needle"],
        "reference_type_histogram": counts["reference_type_histogram"],
        "occurrences": counts["occurrences"],
        "jsonl_path": jsonl_path,
        "jsonl_records": len(records),
        "jsonl_bytes": len(jsonl_text.encode("utf-8")),
        "jsonl_sha256": runner.sha256_text(jsonl_text),
    }

    out_path = runner.write_json_guarded(document, args.out, args.install_dir, "--out")
    print("occurrences=%d xrefs=%d distinct_functions=%d"
         % (counts["occurrence_count"], counts["xref_count"],
            counts["distinct_containing_functions"]), file=sys.stderr)
    print("written: %s" % out_path, file=sys.stderr)
    print("written: %s" % jsonl_path, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
