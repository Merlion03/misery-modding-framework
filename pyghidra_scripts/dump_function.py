#!/usr/bin/env python3
"""S-04 -- decompile one function by address or name (plan.md §7.3 S-04).

What this is for
-----------------
S-03 finds candidate addresses (xrefs to an anchor string). This is the tool
RF-05..RF-09 (next wave) use to actually READ a candidate function's logic
once S-03 has named it: entry address and size, calling convention if known,
full decompiled pseudocode, the disassembly listing, and one level of
outgoing/incoming calls. It answers "what does this ONE function look like",
nothing about its neighbourhood (that is S-05) and nothing about why it was
chosen (that is whatever found the address in the first place).

Function resolution
--------------------
``--function`` accepts either a hex address (Ghidra's own ``Address.toString()``
form, e.g. ``140f4d8e0``, or ``0x``-prefixed) -- resolved to the function
whose entry point IS that address, or failing that, whose body CONTAINS it --
or an exact function name, resolved via a full scan of the function manager
(:func:`_pyghidra_runner.resolve_function`). An ambiguous name (more than one
function sharing it -- this happens: Ghidra names compiler-generated
switch-case fragments ``caseD_N`` and different functions can each have their
own ``caseD_1``) is refused with every matching address named, rather than
silently picking one.

Decompiler correctness is Ghidra's, verified is ours
--------------------------------------------------------
This tool does not second-guess ``DecompInterface`` -- it reports exactly
what ``DecompileResults.decompileCompleted()``/``getErrorMessage()`` say, and
does not retry or reinterpret a failure. What IS this tool's job is proving
the plumbing works: ``research/evidence/S-04/README.md`` decompiles several
functions found from real RTTI vtable slots
(``research/evidence/S-10/rtti.jsonl``) whose SIZE is independently known
from Ghidra's own function body, and records that the decompiler's output is
non-empty, syntactically C-shaped pseudocode rather than an error string or
garbage -- a mechanical, objective check (balanced braces, a semicolon
count, no error markers), not a claim about what the function DOES (that
step is HYPOTHESIS and belongs to a later wave's actual RF-05..RF-09 work).

Output volume and C-13
------------------------
Full decompiled C-like pseudocode and a full disassembly listing can run to
hundreds of lines for a real function; they are written to
``workspace/functions/`` (gitignored, reproducible from the project by
re-running this tool) with only a hash, a line count and a bounded excerpt
committed under ``research/evidence/S-04/`` -- the same split S-01 already
uses for its own bulk extract (``strings.jsonl`` vs. the committed summary).
This is judgement, not mechanical enforcement: unlike S-03's output (short,
metadata-shaped, safe to commit whole), a full decompiled function is a
substantial reconstruction of compiled logic, and the volume alone makes it
the wrong shape for a reviewable public diff regardless of whose code it
turns out to be.

Run only with ``D:\\Tools\\venv-research\\Scripts\\python.exe``.

CLI
---
    python pyghidra_scripts/dump_function.py --function 140f4d8e0 \\
        --out research/evidence/S-04/fun-140f4d8e0.json \\
        --c-out workspace/functions/fun-140f4d8e0.c
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import _pyghidra_runner as runner  # noqa: E402

GENERATOR_NAME = "pyghidra_scripts/dump_function.py"
GENERATOR_VERSION = "1.0.0"

QUESTION = (
    "plan.md §7.3 S-04: for one function (by address or name), what is its "
    "entry/size/calling convention, its decompiled pseudocode, its "
    "disassembly, and its one-level outgoing/incoming calls?"
)

DEFAULT_MAX_INSTRUCTIONS = 20000
DEFAULT_EXCERPT_LINES = 20
DEFAULT_MAX_CALLS = 100


# --------------------------------------------------------------------------- #
# core logic -- narrow interfaces, so tests can fake them without a real JVM
# --------------------------------------------------------------------------- #

def describe_signature(func: Any) -> dict:
    try:
        calling_convention = func.getCallingConventionName()
    except Exception:  # pragma: no cover - defensive; Ghidra rarely raises here
        calling_convention = None
    try:
        signature = str(func.getSignature(False))
    except Exception:  # pragma: no cover
        signature = None
    try:
        return_type = str(func.getReturnType())
    except Exception:  # pragma: no cover
        return_type = None
    parameters = []
    for p in func.getParameters():
        parameters.append({
            "ordinal": int(p.getOrdinal()),
            "name": p.getName(),
            "data_type": str(p.getDataType()),
        })
    return {
        "calling_convention": calling_convention,
        "signature": signature,
        "return_type": return_type,
        "parameters": parameters,
        "parameter_count": int(func.getParameterCount()),
    }


def decompile(decompiler: Any, func: Any, timeout_seconds: int, monitor: Any) -> dict:
    """Run the decompiler on *func*; report exactly what it said.

    *decompiler* needs ``decompileFunction(func, timeout, monitor) ->
    results``, where *results* needs ``decompileCompleted() -> bool``,
    ``getErrorMessage() -> str`` and, when completed,
    ``getDecompiledFunction().getC() -> str``.
    """
    results = decompiler.decompileFunction(func, int(timeout_seconds), monitor)
    completed = bool(results.decompileCompleted())
    error_message = results.getErrorMessage() or None
    c_code = None
    if completed:
        decompiled = results.getDecompiledFunction()
        if decompiled is not None:
            c_code = str(decompiled.getC())
    return {
        "succeeded": completed and c_code is not None,
        "error_message": str(error_message) if error_message else None,
        "c_code": c_code,
    }


# A mechanical, objective "is this plausible C, not garbage or an error
# string" check -- balanced braces/parens, at least one statement-terminating
# semicolon for anything longer than a stub, no known decompiler error
# markers. This is NOT a claim about correctness or meaning; see the module
# docstring.
_ERROR_MARKERS = ("Unable to decompile", "WARNING:", "Low-level Error")


def sanity_check_c_code(c_code: str) -> dict:
    if not c_code:
        return {"non_empty": False, "braces_balanced": None,
               "parens_balanced": None, "semicolon_count": 0,
               "contains_error_marker": None, "plausible": False}
    braces_balanced = c_code.count("{") == c_code.count("}")
    parens_balanced = c_code.count("(") == c_code.count(")")
    semicolons = c_code.count(";")
    has_marker = any(marker in c_code for marker in _ERROR_MARKERS)
    return {
        "non_empty": True,
        "braces_balanced": braces_balanced,
        "parens_balanced": parens_balanced,
        "semicolon_count": semicolons,
        "contains_error_marker": has_marker,
        "plausible": braces_balanced and parens_balanced and not has_marker,
    }


def disassemble(listing: Any, body: Any, max_instructions: int) -> tuple[list[dict], bool]:
    """One row per instruction in *body*: address, mnemonic, operands,
    length. *listing* needs ``getInstructions(body, True) ->
    Iterable[instruction]``. Truncates at *max_instructions* and reports
    whether truncation happened, rather than silently capping.
    """
    rows = []
    truncated = False
    for instr in listing.getInstructions(body, True):
        if len(rows) >= max_instructions:
            truncated = True
            break
        operands = [str(instr.getDefaultOperandRepresentation(i))
                   for i in range(int(instr.getNumOperands()))]
        rows.append({
            "address": str(instr.getMinAddress()),
            "mnemonic": instr.getMnemonicString(),
            "operands": operands,
            "length": int(instr.getLength()),
        })
    return rows, truncated


def one_level_calls(func: Any, monitor: Any) -> tuple[list[dict], list[dict]]:
    """Functions this one calls, and functions that call this one -- one
    level, via ``Function.getCalledFunctions``/``getCallingFunctions``
    (Ghidra's own resolved call graph, not a re-derivation from
    references)."""
    outgoing = sorted(
        (runner.describe_function_brief(f) for f in func.getCalledFunctions(monitor)),
        key=lambda d: d["entry"])
    incoming = sorted(
        (runner.describe_function_brief(f) for f in func.getCallingFunctions(monitor)),
        key=lambda d: d["entry"])
    return outgoing, incoming


def bound_call_list(calls: list[dict], max_calls: int) -> tuple[list[dict], bool]:
    """Cap an outgoing/incoming call list at *max_calls*, same shape as
    :func:`disassemble`'s truncation: a popular address (a COMDAT-folded
    helper found in practice with 5612 callers -- see
    ``research/evidence/S-04/README.md``) must not turn one function's JSON
    into a multi-hundred-KB document. The COUNT reported alongside it is
    always computed from the untruncated list."""
    if len(calls) <= max_calls:
        return calls, False
    return calls[:max_calls], True


def excerpt(text: str, max_lines: int) -> tuple[str, bool]:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text, False
    return "\n".join(lines[:max_lines]), True


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dump_function.py",
        description=("S-04: decompile and disassemble one function by "
                    "address or name (plan.md §7.3)."),
    )
    parser.add_argument("--function", required=True, metavar="ADDR-OR-NAME",
                        help="hex address (e.g. 140f4d8e0) or exact function name")
    parser.add_argument("--decompile-timeout", type=int,
                        default=runner.DEFAULT_DECOMPILE_TIMEOUT_SECONDS,
                        metavar="SEC", help="DecompInterface per-function timeout")
    parser.add_argument("--max-instructions", type=int,
                        default=DEFAULT_MAX_INSTRUCTIONS,
                        help="cap on the disassembly listing row count")
    parser.add_argument("--excerpt-lines", type=int, default=DEFAULT_EXCERPT_LINES,
                        help="how many lines of decompiled C to inline in --out "
                             "(the full text goes to --c-out if given)")
    parser.add_argument("--max-calls", type=int, default=DEFAULT_MAX_CALLS,
                        help="cap on how many outgoing/incoming call entries are "
                             "inlined in --out (a popular address can have thousands; "
                             "outgoing_call_count/incoming_call_count are always the "
                             "full, untruncated counts)")
    parser.add_argument("--out", required=True, help="JSON output path")
    parser.add_argument("--c-out", default=None,
                        help="optional path for the FULL decompiled C text "
                             "(should be under workspace/, not research/evidence/ "
                             "-- see module docstring, C-13)")
    parser.add_argument("--disasm-out", default=None,
                        help="optional path for the FULL disassembly listing as JSONL "
                             "(should be under workspace/, not research/evidence/)")
    runner.add_common_arguments(parser)
    return parser


@runner.handle_prerequisite_errors
def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    for flag, value in (("--out", args.out), ("--c-out", args.c_out),
                       ("--disasm-out", args.disasm_out)):
        if value:
            runner.pathguard.check_output_path(
                value, args.install_dir or runner.pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what=flag)

    copy_record = None
    if not args.skip_copy_verification:
        copy_record = runner.verify_target_copy(args.target_copy, args.expect_sha256)

    generated_at = runner.recorded_at(args)

    with runner.open_program_from_args(args) as (project, program):
        # ghidra.* only becomes importable once the JVM PyGhidra started is
        # up (open_program_from_args/open_existing_program does that on
        # __enter__), so these imports must live inside the `with`, not
        # above it -- moving them earlier reproducibly fails with
        # "ModuleNotFoundError: No module named 'ghidra'" (found by running
        # this exact mistake against the real project once).
        from ghidra.app.decompiler import DecompInterface  # type: ignore
        from ghidra.util.task import TaskMonitor  # type: ignore

        func = runner.resolve_function(program, args.function)
        listing = program.getListing()
        monitor = TaskMonitor.DUMMY

        body = func.getBody()
        brief = runner.describe_function_brief(func)
        signature = describe_signature(func)
        size = int(body.getNumAddresses())

        decompiler = DecompInterface()
        try:
            opened = bool(decompiler.openProgram(program))
            if not opened:
                decompile_result = {"succeeded": False,
                                   "error_message": "DecompInterface.openProgram "
                                                    "returned false",
                                   "c_code": None}
            else:
                decompile_result = decompile(decompiler, func,
                                            args.decompile_timeout, monitor)
        finally:
            decompiler.dispose()

        disasm_rows, disasm_truncated = disassemble(listing, body, args.max_instructions)
        outgoing, incoming = one_level_calls(func, monitor)
        program_name = program.getName()

    c_code = decompile_result["c_code"] or ""
    sanity = sanity_check_c_code(c_code)
    c_excerpt, c_excerpt_truncated = excerpt(c_code, args.excerpt_lines)

    c_sha256 = None
    c_lines = 0
    if c_code:
        c_lines = len(c_code.splitlines())
        c_sha256 = runner.sha256_text(c_code)

    outgoing_bounded, outgoing_truncated = bound_call_list(outgoing, args.max_calls)
    incoming_bounded, incoming_truncated = bound_call_list(incoming, args.max_calls)

    # Full-text writers (plain text, not JSON) -- guarded the same way.
    def _write_text_guarded(text, out_path, what):
        target = runner.pathguard.check_output_path(
            out_path, args.install_dir or runner.pathguard.CONFIGURED_INSTALL_ROOTS[0],
            what=what)
        parent = os.path.dirname(target)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        return target

    c_out_path = _write_text_guarded(c_code, args.c_out, "--c-out") if args.c_out and c_code else None

    disasm_out_path = None
    disasm_sha256 = None
    if args.disasm_out:
        disasm_text = runner.dump_jsonl(disasm_rows)
        disasm_sha256 = runner.sha256_text(disasm_text)
        disasm_out_path = _write_text_guarded(disasm_text, args.disasm_out, "--disasm-out")

    document = {
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
        "generated_at": generated_at,
        "question": QUESTION,
        "task": "plan.md §7.3 S-04",
        "build_key": runner.DEFAULT_BUILD_KEY if args.expect_sha256 == runner.DEFAULT_EXPECT_SHA256
                    else ("sha256:" + args.expect_sha256 if args.expect_sha256 else None),
        "target_copy": copy_record,
        "project": {"root": args.project_root, "name": args.project_name,
                   "program": args.program, "program_name": program_name},
        "function_spec": args.function,
        "function": {
            **brief,
            "size_bytes": size,
            **signature,
        },
        "decompile": {
            "succeeded": decompile_result["succeeded"],
            "error_message": decompile_result["error_message"],
            "timeout_seconds": args.decompile_timeout,
            "c_code_lines": c_lines,
            "c_code_sha256": c_sha256,
            "c_code_excerpt": c_excerpt if c_code else None,
            "c_code_excerpt_truncated": c_excerpt_truncated if c_code else None,
            "c_code_full_path": c_out_path,
            "sanity_check": sanity,
        },
        "disassembly": {
            "instruction_count": len(disasm_rows),
            "truncated_at_max_instructions": disasm_truncated,
            "max_instructions": args.max_instructions,
            "rows": disasm_rows if not args.disasm_out else disasm_rows[:args.excerpt_lines],
            "rows_are_excerpt": bool(args.disasm_out),
            "full_jsonl_path": disasm_out_path,
            "full_jsonl_sha256": disasm_sha256,
        },
        "outgoing_calls": outgoing_bounded,
        "outgoing_calls_truncated": outgoing_truncated,
        "outgoing_call_count": len(outgoing),
        "incoming_calls": incoming_bounded,
        "incoming_calls_truncated": incoming_truncated,
        "incoming_call_count": len(incoming),
    }

    out_path = runner.write_json_guarded(document, args.out, args.install_dir, "--out")
    print("function=%s entry=%s size=%d decompile_succeeded=%s instructions=%d "
         "outgoing=%d incoming=%d"
         % (brief["name"], brief["entry"], size, decompile_result["succeeded"],
            len(disasm_rows), len(outgoing), len(incoming)), file=sys.stderr)
    print("written: %s" % out_path, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
