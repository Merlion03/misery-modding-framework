#!/usr/bin/env python3
"""Phase 2 (per the user's own explicit directive): reconstructs the calling
ABI for ``UObject::ProcessEvent`` and classifies already-collected UFunction/
FProperty records (I-05/I-06's own committed JSONL, plan.md 6.3 schema) by
PARAMETER-BUFFER MARSHALING SAFETY -- which parameters can be written into a
Parms buffer as a plain value, and which cannot without real C++ construction/
destruction this tool does not attempt to perform.

STRICTLY OFFLINE / READ-ONLY. This module touches no live process, opens no
handle, calls no function. It reads only already-committed
``research/reflection/<build_key>/functions.jsonl``/``properties.jsonl`` files
(I-05/I-06's own schema-graded output) and reasons about them in memory. It
constructs no parameter buffer, invokes nothing. Capability PE-02
(``research/instruments/eri/eri.py``) is the live-process half of Phase 1;
this tool is the offline half of Phase 2. Any actual ``ProcessEvent`` call is
Phase 3 -- an entirely separate, not-yet-started IPP capability (``P-02``,
``plan.md`` 8.3), gated by ``plan.md`` 8.4's own escalation criteria and an
explicit decision from the project owner. Nothing here brings that call
closer to happening; it only prepares the ABI knowledge Phase 3 would need.

THE ABI CONTRACT ITSELF, established this session by decompiling the live-
confirmed ``UObject::ProcessEvent`` address (PE-02, ``research/RESEARCH_LOG.md``
LOG-0056) and reading ``Engine/Source/Runtime/CoreUObject/Private/UObject/
ScriptCore.cpp:1971-2165`` directly (UE 5.4.4 CL 35576357):

    ProcessEvent(UObject* Obj, UFunction* Function, void* Parms)

``Parms`` must point to a caller-owned buffer of EXACTLY ``Function.parms_size``
bytes (I-05's own ``parms_size`` field), NOT ``PropertiesSize`` (the function's
FULL local-variable frame, always >= ``parms_size`` -- see I-05's own
``local_variable_count`` field for how many extra ChildProperties entries are
locals, not parameters). ``ProcessEvent`` allocates and zero-initializes its
OWN internal frame of the full ``PropertiesSize``, then does
``FMemory::Memcpy(Frame, Parms, Function.parms_size)`` (``ScriptCore.cpp:2083``)
to copy the caller's buffer in -- the caller never needs to know or allocate
anything beyond ``parms_size``. Each TRUE parameter (``CPF_Parm``, ``0x80`` --
already the exact filter I-05 applies to its own ``parameters[]`` field, see
``eri.py``'s own ``CPF_PARM`` docstring) belongs at its own
``parameters[i].offset`` byte offset within that buffer (I-06's own
``Offset_Internal``, unchanged). A parameter carrying ``CPF_ReturnParm``
(``0x400``) is the function's return value -- read back from that SAME offset
in the caller's own buffer after the call returns (``Function.return_value_
offset``, I-05's own ``return_value_offset`` field, is this SAME offset,
confirmed identical by direct decompiled-code correlation this session: the
disassembly compares ``Function+0xb8`` against ``0xffff`` (``MAX_uint16``) and,
when set, treats ``Parms + ReturnValueOffset`` as the address to write the
return value into -- ``ScriptCore.cpp:2140-2141``). A parameter carrying
``CPF_OutParm`` (``0x100``) is written back into the CALLER's buffer at its own
offset too, by ``ProcessEvent`` itself (via the ``FOutParmRec`` linked list
built at ``ScriptCore.cpp:2094-2129`` -- decompiled and confirmed this session,
PE-02) -- the caller does not need to do anything special to receive an out
value beyond reading the right offset after the call.

WHY THIS TOOL CANNOT JUST "PUT VALUES IN A ROW" (the user's own explicit
warning): ``FProperty`` construction/destruction is VIRTUAL
(``InitializeValueInternal``/``DestroyValueInternal``, ``UnrealType.h:905-974``)
-- different concrete property types need genuinely different C++ logic (e.g.
``FArrayProperty::InitializeValueInternal`` placement-``new``s a real
``FScriptArray`` in place, ``UnrealType.h:3652-3670`` -- not a memzero). This
tool does not reimplement that logic for every property type. Instead it uses
the SAME signal the ENGINE ITSELF already computes, per property, for exactly
this question:

    CPF_ZeroConstructor  (0x200,        ObjectMacros.h:408) -- "memset is fine
                                          for construction"
    CPF_IsPlainOldData   (0x40000000,   ObjectMacros.h:429) -- "the property
                                          can be memcopied instead of
                                          CopyCompleteValue/CopySingleValue"
    CPF_NoDestructor     (0x1000000000, ObjectMacros.h:435) -- "No destructor"

All three are members of ``CPF_ComputedFlags`` (``ObjectMacros.h:480``) --
computed by the engine's OWN reflection system from the real C++ type, never
hand-set by a modder, and therefore authoritative. This was independently
cross-checked against every ALREADY-COLLECTED live property in
``research/reflection/misery-24953925-ue5.4.4-bace50f7185d/properties.jsonl``
(234 rows, I-06): every numeric leaf (``FByteProperty``/``FDoubleProperty``/
``FEnumProperty``/``FFloatProperty``/``FIntProperty``/``FNameProperty``/
``FWeakObjectProperty``) has all three flags set consistently; ``FBoolProperty``
is genuinely MIXED (a native full-byte ``bool`` has all three set, a
BITFIELD-packed ``bool`` does not -- matching I-06's own already-decoded
``is_bitfield`` field exactly, since writing a packed bitfield byte would
clobber sibling bits without a read-modify-write this tool does not attempt);
``FObjectProperty``/``FClassProperty``/``FWeakObjectProperty`` have
``CPF_ZeroConstructor``+``CPF_NoDestructor`` set but NOT ``CPF_IsPlainOldData``
(a ``TObjectPtr`` assignment has GC-tracking side effects
``CopySingleValue``/the assignment operator would trigger, which this tool's
own direct-byte-write approach never goes through -- but for a PARAMETER
BUFFER specifically, that is exactly what ``ProcessEvent``'s own bulk
``FMemory::Memcpy`` already does too, so a raw pointer write is safe for THIS
purpose, tracked here as its own distinct, explicitly caveated tier, never
silently folded into "trivial"); ``FArrayProperty``/``FStrProperty``/both
delegate property classes are consistently missing ``CPF_NoDestructor`` (real
cleanup required); ``FStructProperty`` is genuinely mixed across ALL three
flags depending on the SPECIFIC struct's own members -- exactly why this tool
checks the flags on each INDIVIDUAL property, never by ``property_class``
alone, and needs no per-struct special-casing to get this right.

Every parameter this tool cannot place in the ``trivial`` or
``object_reference`` tier is reported as ``unsupported`` and EXCLUDED from
""safe call eligible"" -- never guessed, never silently attempted.
"""

from __future__ import annotations

import argparse
import json
import sys

# ObjectMacros.h:395-480 (EPropertyFlags), the exact bits this tool's own
# safety classification depends on -- see the module docstring above for the
# full citation and cross-check against real collected data.
CPF_ZERO_CONSTRUCTOR = 0x0000000000000200
CPF_IS_PLAIN_OLD_DATA = 0x0000000040000000
CPF_NO_DESTRUCTOR = 0x0000001000000000

# The three FProperty subclasses this tool treats as "object_reference" --
# a raw TObjectPtr-shaped pointer value, safe to write into a Parms buffer
# for a ProcessEvent call specifically (see the module docstring's own
# reasoning), never safe as a general-purpose "copy this value" operation.
OBJECT_REFERENCE_PROPERTY_CLASSES = frozenset(
    {"FObjectProperty", "FClassProperty", "FWeakObjectProperty"})

TIER_TRIVIAL = "trivial"
TIER_OBJECT_REFERENCE = "object_reference"
TIER_UNSUPPORTED = "unsupported"

# A DELIBERATELY CONSERVATIVE, NAME-ONLY heuristic (never a substitute for
# reading a function's own real behavior) for "sounds like it mutates state"
# -- used only to steer candidate SELECTION for a first positive control
# towards the most boring option available, per the user's own explicit
# instruction not to start with SpawnActor/GiveItem/damage/inventory
# mutation/networking/world mutation. A function is never excluded from
# "safe_call_eligible" for matching this list -- eligibility is decided
# ENTIRELY by parameter marshaling safety above; this list only affects
# ranking/ordering of eligible candidates, and is reported per-candidate so
# a human can see and override it.
MUTATION_NAME_KEYWORDS = (
    "set", "add", "remove", "delete", "destroy", "damage", "give", "spawn",
    "kill", "apply", "modify", "save", "load", "create", "attach", "detach",
    "equip", "unequip", "drop", "pickup", "heal", "consume", "craft", "build",
    "open", "close", "toggle", "enable", "disable", "reset", "clear", "init",
    "start", "stop", "fire", "shoot", "hit", "push", "pull", "move",
    "teleport", "possess", "activate", "deactivate", "commit", "exit",
    "enter", "execute",
)
GETTER_NAME_PREFIXES = ("get", "is", "has", "can", "should", "was", "does")


def _flags_int(flags_raw: str | None) -> int:
    """'0x...' hex text (I-05/I-06's own property_flags_raw/flags_raw
    convention) -> int. None/empty -> 0 (no flags known), never guessed
    otherwise -- a missing flags_raw is honest absence, not zero evidence.
    """
    if not flags_raw:
        return 0
    return int(flags_raw, 16)


def classify_parameter_marshaling(parameter: dict) -> str:
    """One TRUE parameter (I-05's own function_record.parameters[i] shape,
    or I-06's own property_record -- both carry 'flags_raw'/
    'property_flags_raw' and 'property_class') -> one of TIER_TRIVIAL/
    TIER_OBJECT_REFERENCE/TIER_UNSUPPORTED. See the module docstring's own
    "WHY THIS TOOL CANNOT JUST PUT VALUES IN A ROW" section for the exact
    reasoning and citations behind this rule -- never re-derive it ad hoc
    elsewhere in this file.
    """
    flags_raw = parameter.get("flags_raw", parameter.get("property_flags_raw"))
    flags = _flags_int(flags_raw)
    zero_constructor = bool(flags & CPF_ZERO_CONSTRUCTOR)
    no_destructor = bool(flags & CPF_NO_DESTRUCTOR)
    is_plain_old_data = bool(flags & CPF_IS_PLAIN_OLD_DATA)

    if is_plain_old_data and zero_constructor and no_destructor:
        return TIER_TRIVIAL
    if (parameter.get("property_class") in OBJECT_REFERENCE_PROPERTY_CLASSES
            and zero_constructor and no_destructor):
        return TIER_OBJECT_REFERENCE
    return TIER_UNSUPPORTED


def classify_function_eligibility(function_record: dict) -> dict:
    """One I-05 function_record (already-committed functions.jsonl row) ->
    a plain classification dict, never mutating the input, never reading
    anything beyond it (no live process, no second file).

    'strict_eligible': every TRUE parameter (function_record['parameters'],
    already CPF_Parm-filtered by I-05 itself -- see eri.py's own
    build_i05_function_record()) classifies TIER_TRIVIAL. This is the
    SAFEST tier: every byte written or read is a plain value with no
    engine-side-effect risk this tool is aware of.

    'eligible_with_object_refs': every TRUE parameter classifies
    TIER_TRIVIAL or TIER_OBJECT_REFERENCE. Broader, still explicitly
    caveated (see the module docstring) -- a candidate in this tier but not
    'strict_eligible' should be PREFERRED LESS than a strict_eligible one
    for a first positive control, never treated as equally safe.

    Neither flag alone decides whether a human should actually pick this
    function for Phase 3 -- see rank_candidates() below for that.
    """
    parameters = function_record.get("parameters") or []
    tiers = [classify_parameter_marshaling(p) for p in parameters]
    strict_eligible = all(t == TIER_TRIVIAL for t in tiers)
    eligible_with_object_refs = all(
        t in (TIER_TRIVIAL, TIER_OBJECT_REFERENCE) for t in tiers)

    name_lower = function_record["raw_name"].lower()
    looks_like_mutation = any(kw in name_lower for kw in MUTATION_NAME_KEYWORDS)
    looks_like_getter = any(name_lower.startswith(p) for p in GETTER_NAME_PREFIXES)

    return {
        "raw_name": function_record["raw_name"],
        "owner": function_record["owner"],
        "num_true_parameters": len(parameters),
        "parameter_tiers": tiers,
        "strict_eligible": strict_eligible,
        "eligible_with_object_refs": eligible_with_object_refs,
        "is_native": function_record.get("is_native"),
        "is_static": function_record.get("is_static"),
        "is_event": function_record.get("is_event"),
        "is_net": function_record.get("is_net"),
        "parms_size": function_record.get("parms_size"),
        "local_variable_count": function_record.get("local_variable_count"),
        "looks_like_mutation": looks_like_mutation,
        "looks_like_getter": looks_like_getter,
    }


def _candidate_sort_key(entry: dict) -> tuple:
    """Ranks 'most boring, most likely safe' FIRST. Every field here is a
    DELIBERATE, individually-justified preference (see the module docstring
    and classify_function_eligibility()'s own docstring) -- never a single
    opaque score. A human reading candidate_tally output can see exactly
    WHY one candidate outranks another, and override it.
    """
    return (
        0 if entry["strict_eligible"] else 1,            # trivial-only first.
        1 if entry["looks_like_mutation"] else 0,         # avoid mutation-sounding names.
        0 if entry["is_native"] else 1,                   # prefer native (no BP graph).
        0 if entry["is_static"] else 1,                   # prefer static (CDO-callable,
                                                            # no live-instance search needed).
        1 if entry["is_net"] else 0,                      # avoid anything network-flagged.
        entry["num_true_parameters"],                     # fewer true parameters first.
        0 if entry["looks_like_getter"] else 1,            # bonus: reads as a query.
        entry["owner"], entry["raw_name"],                 # deterministic tiebreak.
    )


def rank_candidates(function_records: list) -> dict:
    """The whole point of this tool's own CLI: given an ALREADY-COLLECTED
    functions.jsonl (I-05's own committed output for a real live session --
    never re-derived, never re-walked), classify every function and rank
    the eligible ones for a human to pick a first Phase 3 positive control
    from. Never picks one itself -- that decision, and the safety
    justification for it, belongs to a human, exactly as the user's own
    Phase 3 instructions require ("отдельно объясни в evidence, почему
    именно эта функция выбрана").

    Returns {'total_functions', 'strict_eligible_count',
    'eligible_with_object_refs_count', 'unsupported_count',
    'strict_eligible_ranked' (list, best candidate first),
    'eligible_with_object_refs_ranked' (list, excludes anything already in
    strict_eligible_ranked)}.
    """
    classified = [classify_function_eligibility(f) for f in function_records]
    strict = [c for c in classified if c["strict_eligible"]]
    with_refs = [c for c in classified
                 if c["eligible_with_object_refs"] and not c["strict_eligible"]]
    unsupported = [c for c in classified if not c["eligible_with_object_refs"]]

    strict.sort(key=_candidate_sort_key)
    with_refs.sort(key=_candidate_sort_key)

    return {
        "total_functions": len(function_records),
        "strict_eligible_count": len(strict),
        "eligible_with_object_refs_count": len(with_refs),
        "unsupported_count": len(unsupported),
        "strict_eligible_ranked": strict,
        "eligible_with_object_refs_ranked": with_refs,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Phase 2: offline ProcessEvent parameter-marshaling-safety "
            "classification over an already-committed functions.jsonl "
            "(I-05's own output). Reads no live process, calls nothing."))
    parser.add_argument(
        "functions_jsonl", help="path to a committed functions.jsonl (I-05 schema)")
    parser.add_argument(
        "--out", help="write the full ranked JSON document here (default: stdout)")
    parser.add_argument(
        "--top", type=int, default=10,
        help="print this many top-ranked candidates per tier to stderr (default: 10)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    with open(args.functions_jsonl, encoding="utf-8") as handle:
        function_records = [json.loads(line) for line in handle if line.strip()]

    result = rank_candidates(function_records)

    print(
        "PE-ABI: total=%d strict_eligible=%d eligible_with_object_refs=%d "
        "unsupported=%d" % (
            result["total_functions"], result["strict_eligible_count"],
            result["eligible_with_object_refs_count"], result["unsupported_count"]),
        file=sys.stderr)
    for tier_name, key in (
            ("strict_eligible", "strict_eligible_ranked"),
            ("eligible_with_object_refs", "eligible_with_object_refs_ranked")):
        print("-- top %d %s --" % (args.top, tier_name), file=sys.stderr)
        for entry in result[key][:args.top]:
            print(
                "  %s::%s  params=%d native=%s static=%s net=%s "
                "mutation_name=%s getter_name=%s" % (
                    entry["owner"], entry["raw_name"], entry["num_true_parameters"],
                    entry["is_native"], entry["is_static"], entry["is_net"],
                    entry["looks_like_mutation"], entry["looks_like_getter"]),
                file=sys.stderr)

    text = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.write("\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
