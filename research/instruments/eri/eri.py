#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ERI -- External Read-Only Inspector, capabilities I-01 and I-02 (plan.md 8.2).

RESEARCH ONLY -- NOT PRODUCTION. This file lives in research/instruments/,
never in src/, and nothing in Phase 2 may be a refactor of it (plan.md 8.1:
"ни ERI, ни IPP не наследуются продуктом"). Disposability, "no API stability
whatsoever" and "fail loudly and immediately" are the NORM for this file, not
defects to be fixed -- see research/instruments/eri/README.md's own
"RESEARCH ONLY" section and its "Чему из этого кода нельзя подражать в
Phase 2" once filled in.

WHAT I-01 IS
------------
plan.md 8.2, capability I-01: "Найти процесс, получить базовый адрес и
размер образа Shipping-модуля" -- find the MISERY-Win64-Shipping.exe process,
and read the base load address and image size of its own module, as the
OS's module loader currently has it mapped. Every later ERI capability
(I-02..I-15) needs this as its foundation, because every one of them reads
memory relative to that base address.

WHAT I-02 IS
------------
plan.md 8.2, capability I-02: "Перечислить объекты через кандидатный
GUObjectArray" -- enumerate objects via the candidate GUObjectArray. This is
the first capability in this tool's life that actually reads target-process
MEMORY (I-01 only reads the OS's own module table via Toolhelp32), and the
first consumer of RF-05's static candidate (research/evidence/RF-05/README.md,
grade HYPOTHESIS, confidence 0.65). I-02 does not merely re-read the candidate
and assume it still holds because a static signature still matches
byte-for-byte (it does -- see research/builds/misery-24953925-ue5.4.4-bace50f7185d/
sigscan/RF-05-sigscan.json); it VERIFIES the candidate against LIVE structural
behaviour, because plan.md 564-566 places an absolute ceiling on any
static-analysis offset regardless of how well the pattern matches: a
runtime read is a categorically different, stronger kind of evidence, never
interchangeable with "the bytes on disk still look right". The exact three
checks implemented here are the three RF-05/README.md itself names in its own
"What a runtime observation would need to show to move this above HYPOTHESIS"
section -- see run_i02() below for the implementation of each, and
research/evidence/RF-05/README.md for the struct layout and chunk-addressing
arithmetic this is built from. A refuted candidate is a valid, REPORTABLE
research outcome, not a tool malfunction -- see the "STRUCTURAL REFUTATION IS
A RESULT, NOT AN ERROR" section below.

WHAT I-03 IS
------------
plan.md 8.2, capability I-03: "Разрешить FName в строку (обход FNamePool)"
-- resolve an FName (an FNameEntryId, a plain uint32) to its string text by
reading FNamePool's own internal block table directly, bypassing the
in-process C++ API entirely (this tool never calls a single game function --
see the "no game function is ever called" guarantee below, which I-03 does
not weaken in any way). This is the second consumer of a HYPOTHESIS-grade
static candidate (research/evidence/RF-06/README.md, confidence 0.60) and
the second capability that reads target-process memory, reusing I-02's own
ReadProcessMemory call site and rva_to_live_va() helper rather than adding
either a second one.

RF-06/README.md's own "What a runtime observation would need to show to move
this above HYPOTHESIS" section names three steps; I-03 implements the first
two (bNamePoolInitialized is nonzero; decoding FNameEntryId 0 produces the
literal text "None", the one case with a KNOWN expected answer, since
EName::None is guaranteed to be the first hardcoded name ever registered --
UnrealNames.cpp's own REGISTER_NAME loop, cited in RF-06/README.md). Failing
that decode is a real, reportable STRUCTURAL REFUTATION of the FNamePool
candidate, the bit-layout assumption, or both -- see "STRUCTURAL REFUTATION
IS A RESULT, NOT AN ERROR" below, which applies to I-03 exactly as it does
to I-02. RF-06's third step -- cross-checking against a live UObject found
via I-02 -- is implemented here as the "/Script/MISERY live reflection"
probe (sample_object_names()): a BOUNDED, honestly-reported (never claimed
exhaustive) search for the literal leaf FName "MISERY" among a sample of
live UObjects located via I-02's own chunk-walk arithmetic (factored into
_locate_object_pointer() for exactly this reuse).

The FNameEntryHeader bit layout (bIsWide:1 + LowercaseProbeHash:5 + Len:10,
packed LSB-first into one uint16) was read from Engine/Source/Runtime/Core/
Public/UObject/NameTypes.h for this exact build (WITH_CASE_PRESERVING_NAME=0,
confirmed independently by RF-06's own disassembly of the 256-shard
constructor loop), not merely assumed -- decode_fname_entry_id()'s own
docstring has the full citation. The UObjectBase field layout
DEFAULT_NAME_PRIVATE_OFFSET is built from was derived the same way, from
Engine/Source/Runtime/CoreUObject/Public/UObject/UObjectBase.h's own member
declaration order, and cross-checked against RF-05's own independently-found
disassembly offset for InternalIndex (+0xc) -- see
DEFAULT_NAME_PRIVATE_OFFSET's own comment for the full derivation and why
that cross-check landing exactly on +0xc is meaningful, not coincidental.

WHAT I-04 IS
------------
plan.md 8.2, capability I-04: "Дамп UClass с иерархией наследования" -- the
first real UObject/UClass TRAVERSAL, not merely a bounded sample. Where I-03's
own "/Script/MISERY live reflection" probe (sample_object_names()) only ever
read one field (NamePrivate) of a bounded sample of objects, I-04 walks EVERY
object I-02's own GUObjectArray chunk-walk locates (bounded only by
--i04-max-scan-indices, a safety cap, never a statistical sample size) and
reads three UObjectBase fields per object -- ClassPrivate (+0x10),
NamePrivate (+0x18, I-03's own DEFAULT_NAME_PRIVATE_OFFSET, reused verbatim)
and OuterPrivate (+0x20, the ONE genuinely new offset this capability
introduces) -- to answer two questions per object: what is its canonical
object_path (built by walking the Outer chain, bounded and cycle-protected),
and IS this object itself a UClass instance.

The second question is answered without ever reading a single UClass/UStruct/
UField-specific field (ClassFlags, SuperStruct, ChildProperties, ...) --
deliberately out of scope for this pass, see this section's own "scope"
paragraph below. Instead it uses a genuine architectural fixed point of real
UE reflection: UClass::StaticClass()->ClassPrivate == itself (every UClass
"type descriptor" object's own Class is the native UClass type, literally
named "Class" in the FNamePool), so the ONE self-referential object in the
whole live UObject universe (ClassPrivate address == its own address) is
"Class", found and cross-checked against its own decoded name/object_path
(never merely trusted because it happens to be self-referential -- see
find_uclass_self_reference()'s own docstring) before anything is built on
top of it. From that single seed, class_address_universe grows from a SET
of principled ROOTS -- NEVER a general "anything whose ClassPrivate is
already a member of the growing universe joins" closure, which is a subtly
different and WRONG rule this capability deliberately does not implement
(see compute_class_identity()'s own docstring for exactly why: real UE
semantics mean an ORDINARY GAMEPLAY INSTANCE of any native class also has
its own ClassPrivate equal to that class's address, so a truly general
transitive closure would, after enough passes, also sweep in thousands of
plain object instances as "is a UClass" -- not a hypothetical, but what the
literal general rule would produce against a real ~26 000-object live
GUObjectArray). Round 1: every object whose ClassPrivate == the seed
("Class") -- this catches every native type descriptor, "ScriptStruct",
"Function", "Enum", "BlueprintGeneratedClass" itself, and every ordinary
native UClass (MiseryFocusSubsystem, MiseryBlueprintFunctionLibrary, ...),
because UClass, UScriptStruct, UFunction, UEnum and UBlueprintGeneratedClass
are ALL native C++ types whose own metaclass is UClass. Every round-1 member
whose OWN name ends with "GeneratedClass" (find_meta_type_roots(), a GENERAL
name-suffix test -- CORRECTED 2026-08-27 after a targeted review found the
original design's single hardcoded "BlueprintGeneratedClass"-only check
missed real native siblings like UWidgetBlueprintGeneratedClass and
UAnimBlueprintGeneratedClass) is promoted to an additional root; the plain
"BlueprintGeneratedClass" name is ALSO still separately found and
path-cross-checked (find_blueprint_generated_class_address()) as one
specific, reported data point. Round 2+ (bounded by
--i04-max-fixed-point-passes, converged/logged either way): every object
whose ClassPrivate is EXACTLY one of this FIXED root set -- never the whole
growing universe -- joins. This catches real Blueprint class ASSETS of
EVERY discovered meta-type (their own metaclass is one of the roots), while
correctly excluding an ordinary instance of, say, MiseryFocusSubsystem (its
own ClassPrivate is MiseryFocusSubsystem's address, which is never promoted
to a root, since "MiseryFocusSubsystem" does not end in "GeneratedClass")
and an ordinary UScriptStruct/UFunction/UEnum instance (e.g. the
struct-descriptor object for FVector; its own ClassPrivate is "ScriptStruct",
likewise never promoted). See compute_class_identity()'s own docstring for
the full worked trace this reasoning is pinned against, including the
FIRST, ALSO-WRONG attempted fix (a rootless "every distinct ClassPrivate
value" rule) that this project's own test suite caught before it was
trusted.

object_path is built for every classified UClass instance by walking the
Outer chain (bounded depth, cycle-protected -- see resolve_object_path()'s
own docstring), using this session's own confirmed fact (LOG-0051,
i03-fnamepool.json's misery_reflection.decoded_names) that a UPackage's own
NamePrivate already holds its FULL "/Script/<Module>" or "/Game/<...>" path,
never a bare leaf name.

SCOPE, DELIBERATELY (per the task this capability was specified from --
"не угадывай UObject layout" applies with full force to anything past
OuterPrivate): I-04 reads ONLY the three UObjectBase fields named above. It
never reads a byte of UObjectBaseUtility, UObject, UField, UStruct or UClass
storage -- no ClassFlags, no SuperStruct, no ChildProperties, no size, no
alignment. Every such field in the committed classes.jsonl rows this
capability writes is explicitly null, not guessed and not half-implemented
(build_i04_class_record()'s own docstring lists every one). I-04 also never
invokes ProcessEvent or any UFunction, sets no hook, and writes nothing to
the target process -- identical read-only guarantee to I-01/I-02/I-03, using
the SAME single ReadProcessMemory call site and the SAME single OpenProcess
call site; no new Win32 API, no new access right.

classes.jsonl (research/schema/reflection-record.schema.json's class_record
branch) is the committed artifact this capability produces: every classified
UClass instance under /Script/MISERY (the literal exit-criterion target),
plus a small BOUNDED sample of /Game/* Blueprint-generated classes (never an
exhaustive dump -- see build_i04_document()'s own docstring for the sample
cap and the honest full-count reporting alongside it), and explicitly NOT
the hundreds of native /Script/Engine, /Script/CoreUObject etc. classes this
same walk inevitably also finds (their total count is reported, never
persisted -- the "огромный полный semantic dump" the task this capability
was specified from explicitly says not to produce yet).

WHAT I-06 IS
------------
plan.md 8.2, capability I-06: "Декодер FProperty" -- the first FIELD-level
(as opposed to OBJECT-level) reflection reader. Where I-04 reads exactly
three fields of every live UObject and never touches a single
UObjectBaseUtility/UObject/UField/UStruct/UClass-specific byte, I-06 walks
ONE new UStruct field I-04 deliberately never reads -- ChildProperties
(UStruct's own +0x50 -- UObjectBase's own 0x28 total size + UField's own
Next at +0x28 (UField total 0x30) + a PRIVATE, conditionally-compiled
FStructBaseChain base subobject (+0x30..+0x3F, 0x10 bytes, present in every
non-editor/Shipping build -- see USTRUCT_CHILD_PROPERTIES_OFFSET's own
docstring below for the full derivation, including how a prior session
phase's own +0x40 figure missed this base class and was corrected LIVE this
pass) + UStruct's own SuperStruct(+0x40)/Children(+0x48)/
ChildProperties(+0x50)) -- and, from there, an entirely
different C++ type hierarchy: FField/FFieldClass/FProperty (Engine/Source/
Runtime/CoreUObject/Public/UObject/Field.h and UnrealType.h, UE 5.4.4
CL 35576357), which is NOT UObject-derived, NOT a member of GUObjectArray,
and whose own "type object" (FFieldClass) has no vtable at all (a
non-virtual destructor -- Field.h:62-92) -- see decode_property_type()'s own
docstring for why this makes an FFieldClass pointer validated differently
from a UObject's own ClassPrivate (I-04's vtable-in-module-range check
simply does not apply; there is no vtable to check).

THE DISPATCH RULE, DELIBERATELY NOT EClassCastFlags: every FField's own
concrete leaf type is identified by decoding its FFieldClass::Name (Field.h:
67, an FName, via I-03's own decode_fname_entry_id() -- reused, never a
second FName decoder) and, for structural validation, walking
FFieldClass::SuperClass (Field.h:75, a SIMPLE single-parent pointer, unlike
UClass's own fixed-point-identity problem I-04 had to solve) up to and
including "FProperty" itself, bounded and cycle-protected exactly like
resolve_object_path()'s own Outer-chain walk (see _walk_fieldclass_super_
chain()'s own docstring). This is the ONLY dispatch mechanism this
capability uses -- no EClassCastFlags/CASTCLASS_* bit is ever read, per this
session's own confirmed rule (name-string + SuperClass-chain-walk is the
proven, non-guessing approach; a second, CastFlags-based dispatch mechanism
would only invite the two silently drifting apart).

REUSE, EXPLICITLY: decode_property_type() below is written to decode ONE
FField-derived object given only its own address -- nothing about "is this
on a UStruct's ChildProperties chain" is baked into it -- specifically so
walk_property_chain() (this capability's own ChildProperties/Next-chain
walker) and every container-nesting case (FArrayProperty's own Inner,
FSetProperty's own ElementProp, FMapProperty's own KeyProp/ValueProp,
FEnumProperty's own UnderlyingProp -- all four are themselves nested FField/
FProperty objects elsewhere in memory, decoded via the SAME function,
recursively, bounded by --i06-max-container-depth) both call it identically,
and so a FUTURE capability (I-05, UFunction/parameter-list decoding -- out
of scope for this pass, see below) can reuse it for a UFunction's own
parameter list without this function ever needing to know that caller
exists.

SCOPE, DELIBERATELY (mirrors I-04's own "SCOPE, DELIBERATELY" section
above): no ProcessEvent, no UFunction, no EFunctionFlags, no parameter-list
traversal (that is I-05, a separate future capability). No individual
EPropertyFlags bit decoding (CPF_BlueprintVisible/CPF_Edit/CPF_Transient/
CPF_Config/CPF_Net/...) -- only the raw uint64 PropertyFlags word, as
property_flags_raw hex text; is_blueprint_visible/is_editable/is_transient/
is_config are explicitly null on every record this pass writes, never
guessed from the raw bits. No UScriptStruct-owned property traversal -- only
class-owned (owner_kind="class") TOP-LEVEL properties from the proof set
below; an FStructProperty's own struct_name is recorded, but this pass never
recurses into decoding THAT struct's own ChildProperties. No CDO
instantiation, no default-value reading, no interface/replication semantics
beyond the two direct, cheap FProperty fields RepIndex/RepNotifyFunc.

PROOF-SET-FIRST, NOT A FULL DUMP (matches I-04's own bounded-sample
precedent, and this session's own explicit instruction): I-06 never re-walks
GUObjectArray -- it reuses I-04's OWN already-classified, already-validated
class list from THIS SAME run (--run-i04 is a hard requirement, checked by
_validate_i06_requirements() before any handle is opened) as a deterministic,
documented, in-memory filter (select_i06_proof_set() below): every
/Script/MISERY class, I-04's own already-bounded /Game sample, and up to
--i06-engine-class-cap well-known engine classes found by name preference
(I06_ENGINE_CLASS_NAME_PREFERENCE) over I-04's own FULL walked class
universe (not merely the subset build_i04_document() ever writes to
classes.jsonl). A small (roughly 20-class) proof set is the deliberate exit
criterion for this pass; scaling to every class this walk finds is a future
pass's job, not this one's.

CONFIDENCE HAS NO POSSIBLE CEILING ABOVE 0.79 FOR THIS CAPABILITY, EVER, AND
THAT IS A FACT ABOUT THE FORMAT, NOT A GRADING CHOICE: research/reflection/
misery-24826585-ue5.4.4-0eef3715244b/README.md's own "Почему properties.jsonl
пуст -- и всегда будет пуст" section proves properties.jsonl is empty by
design and stays empty FOREVER for RF-01's own offline global.ucas method,
because FProperty is not a UObject and cannot appear in the ScriptObjects
chunk that container is built from (PackageStoreOptimizer.cpp:952-957 walks
GetObjectsWithOuter, which only ever visits UObject-derived entries). This
means every property_record this capability writes has NO possible offline
cross-check, ever, for any build -- single-source, oracle=["runtime-
reflection"] only, always. Every record therefore carries confidence 0.75
(the same "one strong method, runtime-validated, no independent
corroboration" reasoning build_i04_class_record() already applies to a
single-source /Game class record, class I per kb-record.schema.json's own
claim_type matrix row 9 "class-property" -> runtime-reflection), never
higher -- this is not a conservative choice that could be revisited with
more effort; it is the CEILING the format itself imposes.

CANONICAL object_path NORMALIZATION (this session's own explicit request,
ahead of a future semantic diff -- see canonicalize_object_path() below,
placed near resolve_object_path()): resolve_object_path() already documents
a KNOWN, DELIBERATE convention mismatch between this tool's own "."-joined
runtime object_path and RF-01's already-committed "/"-joined offline
classes.jsonl. canonicalize_object_path() is the pure function that makes
the two comparable at diff time WITHOUT ever rewriting the committed offline
artifact -- see its own docstring for the exact algorithm and the two
worked example strings this session specified.

THE "ALL OR NOTHING" WRITE GUARANTEE, AND WHY I-06 HAS NO FOUNDATIONAL
SINGLE-POINT READ OF ITS OWN: I-02's/I-03's own single foundational reads
(GUObjectArray's own Objects/NumElements/MaxElements; FNamePool's own
bNamePoolInitialized) are each read exactly ONCE per run, are NEVER wrapped
in a try/except that would convert a hard failure into a rejection, and so a
ReadProcessMemoryFailedError there propagates all the way to main()'s own
outer exception handler -- which writes NOTHING, because every output-file
write in main() happens strictly AFTER every run_iNN() call completes (see
main()'s own structure). I-04's OWN per-object reads (ClassPrivate/
NamePrivate/OuterPrivate of an object walk_object_universe() already
LOCATED) are the opposite case -- _classify_object() catches
ReadProcessMemoryFailedError there and converts it to a counted
'read_failure' rejection, never propagated, because that object was already
found to exist; a torn read on it is a scanning concern, not evidence the
whole capability cannot proceed (see the module docstring's "STRUCTURAL
REFUTATION IS A RESULT, NOT AN ERROR" section, and _classify_object()'s own
docstring, for the full reasoning this mirrors). I-06 has NO read that
matches the FIRST case at all: every single read this capability makes is
either (a) a field of a class object I-04's OWN walk, in THIS SAME run,
already found and validated to exist (walk_object_universe()'s own
'valid'==True), or (b) a field of an FField/FFieldClass object reached FROM
there via a pointer this SAME capability already read. There is no
GUObjectArray-shaped "read this exactly once, with no fallback, or the
whole capability cannot proceed" operation anywhere in I-06's own logic --
so EVERY read failure in decode_property_type()/walk_property_chain()/
run_i06() mirrors I-04's OWN per-object precedent (case b: an
already-located candidate's own field failed to read -- a torn read,
counted and documented, never propagated), and none of them mirrors I-02's/
I-03's foundational-single-read case. The "nothing is written on a genuine
tool malfunction" guarantee therefore still holds, but it holds via the SAME
mechanism as every other capability in this file: run_i06() itself never
raises, so main()'s own ordering (compute everything, write only after
everything computed) is what makes an actually-unexpected exception
(a real bug, not a modeled failure mode) still result in nothing written,
exactly as for I-01 through I-04.

WHAT I-05 IS
------------
plan.md 8.2, capability I-05: "Декодер UFunction" -- decode a UFunction's
own EFunctionFlags, its own parameter list (including which parameter, if
any, is the return value), and their declaration order, into a full semantic
signature. UFunction : public UStruct (Class.h:1789, a single, unconditional
inheritance -- unlike UStruct's own conditional FStructBaseChain base), so a
UFunction's own parameters -- including its own return value -- are ITS OWN
"child properties" in UE's reflection system: literally the SAME
UStruct::ChildProperties/FField::Next linked list I-06 already walks for a
class's own member variables, at the SAME USTRUCT_CHILD_PROPERTIES_OFFSET
(+0x50). I-05 therefore REUSES decode_property_type()/walk_property_chain()
(I-06, immediately above) COMPLETELY UNCHANGED for the parameter list --
exactly the reuse I-06's own module docstring already predicted for it ("a
FUTURE capability, I-05 ... can reuse it for a UFunction's own parameter
list without this function ever needing to know that caller exists").

DISCOVERING WHICH OF A CLASS'S CHILDREN ARE UFUNCTION INSTANCES: a UClass's
own Children field (TObjectPtr<UField>, +0x48, "Pointer to start of linked
list of child fields") is a DIFFERENT linked list from ChildProperties --
it holds UField-DERIVED UObject children (in UE5, primarily UFunction,
since properties moved to the separate FField tree), walked via UField::Next
(this capability's own new DEFAULT_UFIELD_NEXT_OFFSET, +0x28 -- I-04's own
already-live-validated UObjectBase.h field layout continued one member
further, not re-derived) -- NEVER FField::Next, which is a different offset
on a different, non-UObject type entirely. walk_children_chain() below
mirrors walk_property_chain()'s own bounded/cycle-protected/all-rejections-
counted shape, but classifies each node via I-04's OWN
ClassPrivate/NamePrivate/OuterPrivate offsets (reused unchanged, never
re-derived) rather than decode_property_type()'s FField-specific ones. A
node "is a UFunction" iff its own ClassPrivate EXACTLY EQUALS the live
address of the UClass literally named "Function" (/Script/CoreUObject.Function),
found ONCE per run by an exact raw_name lookup over I-04's OWN already-
computed full class list (find_function_class_address()) -- a single
exact-address equality check, deliberately simpler than I-04's own
class-identity fixed point, because I-05 already knows exactly what it is
looking for by name. A node whose ClassPrivate does not match is simply not
a function -- skipped, counted, never treated as an error (the SAME
"structurally implausible but successfully read = data, never raised"
philosophy the module docstring's "STRUCTURAL REFUTATION IS A RESULT, NOT
AN ERROR" section already establishes, applied here to "this UField is not
what I was looking for" rather than to a corrupted structure).

TWO REAL OFFSET BUGS WERE ALREADY FOUND IN I-06 BY LIVE TESTING, NOT BY
SOURCE READING -- AND I-05 INHERITS THAT LESSON DIRECTLY, NOT MERELY IN
SPIRIT: USTRUCT_CHILD_PROPERTIES_OFFSET's own comment above documents how a
careful, twice-reviewed +0x40 derivation for ChildProperties was still
wrong (the real offset is +0x50) until a live read caught it, because a
private, conditionally-compiled FStructBaseChain base subobject is invisible
to anyone who does not independently re-read Class.h:382-385's own
`#if USTRUCT_FAST_ISCHILDOF_IMPL == USTRUCT_ISCHILDOF_STRUCTARRAY` line.
I-05 introduced exactly one offset with the SAME kind of derivation risk:
USTRUCT_TOTAL_SIZE_SHIPPING (+0xB0, the total size of UStruct's own layout
in this Shipping build, i.e. where UFunction's own FunctionFlags/NumParms/
ParmsSize/ReturnValueOffset begin) was derived the same careful way
ChildProperties was the first time -- by reading UStruct's own remaining
member declarations one at a time. See that constant's own comment for the
full field-by-field derivation AND its own live-confirmation result: unlike
the +0x40 ChildProperties figure, USTRUCT_TOTAL_SIZE_SHIPPING's own
MANDATORY EMPIRICAL SELF-CHECK (below) came back 247/247 matched, zero
mismatches, against the real live process -- it survived exactly the test
that caught ChildProperties' own error.

MANDATORY EMPIRICAL SELF-CHECK, BUILT INTO run_i05() ITSELF: because
USTRUCT_TOTAL_SIZE_SHIPPING has no independent structural proof from source
alone (unlike a class's own PropertiesSize/MinAlignment, whose plausibility
decode_property_type() indirectly exercises via every property it
successfully decodes), run_i05() cross-checks every decoded UFunction's own
NumParms (read directly from that offset) against the number of entries
walk_property_chain() actually ACCEPTS, and CPF_Parm-flags, on that SAME
function's own ChildProperties chain (read via I-06's OWN already-live-
verified USTRUCT_CHILD_PROPERTIES_OFFSET; the CPF_Parm filter is itself
a live finding, see run_i05()'s own docstring) -- two INDEPENDENT readings
of "how many TRUE parameters does this function have" that agree if, and
only if, the UStruct-total-size assumption is correct. A mismatch is counted
(run_i05()'s own 'num_parms_cross_check' aggregate) and documented on the
affected function_record's own 'notes' field, NEVER silently accepted --
this is a genuine, own-data cross-check requiring no assumption beyond "the
two supposedly-related numbers should actually agree." Against the real
live process this pass, they did: 247/247, exactly the kind of self-check
that would have caught the ChildProperties bug faster than source re-reading
alone did, this time confirming rather than refuting the offset it checks.
This check is reported PROMINENTLY in run_i05()'s own returned summary and
in build_i05_document().

SCOPE, DELIBERATELY (mirrors I-04's/I-06's own "SCOPE, DELIBERATELY"
sections): no ProcessEvent, no function invocation, no hooks, no writes, no
CDO/default-value reading, no bytecode disassembly. RPCId/RPCResponseId
(+0xBA/+0xBC) and everything after -- every `#if UE_BLUEPRINT_EVENTGRAPH_
FASTCALLS`/`#if WITH_LIVE_CODING` conditionally-compiled field, and the
native Func pointer -- are DELIBERATELY never read: real, unresolved
conditional-compilation uncertainty this pass does not attempt to resolve,
exactly like I-06's own scope boundary excludes individual EPropertyFlags
bit decoding. native_func_address/bytecode_size are therefore explicitly
null on every function_record this capability writes, never guessed "for
completeness" -- that is exactly the kind of unverified confidence that
caused the two I-06 bugs. Only four EFunctionFlags-derived booleans/one hex
word are decoded (is_native/is_static/is_event/is_net/net_flags_raw) and
three EPropertyFlags-derived booleans per parameter
(is_return/is_out/is_reference) -- parsed from property_flags_raw, a value
decode_property_type() ALREADY read for I-06, at no new memory cost. No
offline RF-01 cross-check is attempted this pass (research/reflection/
misery-24826585-ue5.4.4-0eef3715244b/functions.jsonl's own 18
HYPOTHESIS-graded named functions are a DIFFERENT build's DIFFERENT method,
name-only, no structural detail) -- a legitimate future enhancement,
explicitly out of scope here.

PROOF SET, REUSED VERBATIM, NOT A SECOND SELECTOR: I-05 reuses
select_i06_proof_set()'s own output EXACTLY (every /Script/MISERY class,
I-04's own bounded /Game sample, up to --i06-engine-class-cap well-known
engine classes) -- it never re-walks GUObjectArray and never builds a
second, different proof-set selection function. --run-i05 requires
--run-i04 in the SAME invocation (mirrors _validate_i06_requirements()'s own
shape), but DELIBERATELY does NOT require --run-i06: walk_children_chain()
only ever needs I-04's own class list (both as the proof set and to find
the "Function" meta-class address by name) -- nothing run_i06() itself
computes is a genuine data dependency of I-05, exactly like I-06 itself
requires --run-i04 but not --run-i02/--run-i03 directly (those are I-04's
OWN already-separately-guaranteed transitive requirements).

WHAT PE-02 IS
-------------
NOT a plan.md 8.2 capability -- deliberately spelled "PE-02", never
"I-07".."I-15" (plan.md 8.2's own table, section 8.2, already reserves
those ten ids for UWorld/UGameInstance/ULocalPlayer/property-value/Role-
NetMode/snapshot-diff/container/AssetRegistry/export capabilities, none of
them related to this). PE-02 is the second entry in the PE-01 EVIDENCE
TRACK (research/evidence/PE-01/README.md), a continuation of that static
analysis, not a new numbered ERI capability -- see CAPABILITY_ID_PE02's own
comment for why it therefore NEVER appears in manifest.json's own
capabilities_enabled array: instrument-run-manifest.schema.json's own
eri_capability_id enum is CLOSED to "I-01".."I-16", so writing "PE-02"
there would be a schema violation, not a style choice. main() records this
capability's own output path in the manifest's 'artifacts' list (a
free-text array, unconstrained) and nowhere else.

PE-01's own static, line-by-line vtable-slot count concluded
UObject::ProcessEvent (Object.h:1417, ScriptCore.cpp:1971, UE 5.4.4 CL
35576357) sits at C++ vtable slot 77 (byte offset 77*8 = 0x268), HYPOTHESIS,
confidence 0.60, class I -- ONE method (manual counting through
UObjectBase.h/UObjectBaseUtility.h/Object.h) with ONE successful cross-check
on a DIFFERENT class (UEngine::Init, independently measured by disassembly
at the SAME predicted slot). PE-01/README.md's own "What's needed to move
past HYPOTHESIS" section names the next step: runtime confirmation that a
real live UObject-derived instance's own vtable actually holds a plausible
function pointer at this exact slot. PE-02 gathers exactly that LIVE
evidence -- and only that; see "NON-GOALS" below for what it deliberately
does not do.

REUSES I-04's OWN objects_by_address, NEVER RE-WALKS GUObjectArray:
run_pe02_vtable_scan() (and every function below it) takes I-04's OWN
already-walked, already-validated objects_by_address dict (walk_object_
universe()'s own return value, now ALSO threaded out through run_i04()'s
own return dict as an ADDITIVE key -- see run_i04()'s own docstring update
-- never a second walk of the array, never a change to what run_i04()
already computed for I-04 itself). --run-pe02-vtable-scan therefore requires
--run-i04 in THIS SAME invocation (_validate_pe02_requirements(), the
identical shape _validate_i06_requirements()/_validate_i05_requirements()
already establish), and reuses every valid ('valid': True, i.e. structurally
validated by I-04's OWN _classify_object() checks 1-3) object I-04's walk
located as its sampling population -- a bounded sample of it
(DEFAULT_PE02_VTABLE_SAMPLE_SIZE=500, --pe02-vtable-sample-size), never all
~26 000 objects a real walk finds, since the evidentiary value here comes
from CLASS DIVERSITY across a few hundred samples, not exhaustive coverage.

TWO DIFFERENT VTABLE READS IN THIS FILE, READ CAREFULLY, DO NOT CONFUSE
THEM: I-04's own _classify_object() check 3 reads the vtable pointer at
CLASS_PTR's own address -- the vtable of the UClass "type descriptor"
object *object_ptr* is an instance of, used ONLY to sanity-check that
ClassPrivate looks like a real UObject-derived pointer. PE-02 needs a
DIFFERENT read entirely: *object_ptr*'s OWN personal instance vtable, at
object_ptr + 0x00, because ProcessEvent dispatches virtually through the
CALLING instance's own vtable, never through its class descriptor's vtable
(the class descriptor is itself a separate UObject, with its own vtable,
appropriate to UClass -- not to whatever concrete class object_ptr is an
instance of). Nothing in I-04's own walk ever reads THIS address for THIS
purpose -- _classify_processevent_vtable_candidate() below performs a
FRESH read of object_ptr + 0x00 for exactly this reason, and says so again
in its own docstring, so a future reader who has not read this section
first still cannot make this mistake silently.

ALGORITHM, per sampled valid object O (_classify_processevent_vtable_
candidate()): (1) read O's own vtable pointer at O+0x00; validate it is
plausible (_pointer_is_plausible(), reused) AND resolves into the module's
own image range (_vtable_pointer_in_module_range(), reused -- the IDENTICAL
function I-04's own check 3 already uses, never a second copy). (2) read
the pointer stored at vtable_ptr + vtable_slot_offset (default slot 77,
byte offset 0x268 -- DEFAULT_PROCESSEVENT_VTABLE_SLOT, overridable via
--processevent-vtable-slot, because the WHOLE POINT of this capability is
to gather evidence FOR OR AGAINST slot 77, so it must never be hardcoded
un-overridably). This is the CANDIDATE function pointer. (3) validate it is
plausible AND convert it to an RVA (candidate_va - base_address) AND check
that RVA falls in [0, image_size_bytes) -- I-01's own image_size_bytes, the
SAME bound every other module-range check in this file already uses, never
a second image-size source. A read failure or a failed check at any step is
a per-object REJECTION (counted, torn-read precedent, never raised -- see
_classify_processevent_vtable_candidate()'s own docstring); it never aborts
the sample.

THE MODULE-RANGE CHECK ON THE CANDIDATE IS WEAK EVIDENCE, STATED EXPLICITLY,
NEVER OVERSOLD: practically every function pointer belonging to a 138MB
Shipping image passes it -- it is a NECESSARY, NOT SUFFICIENT structural
check, kept as a gate only because an address outside the image cannot be
expressed as an RVA any static tool (pyghidra_scripts/dump_function.py)
could look up at all. The REAL evidence this capability produces is the
DISTRIBUTION of accepted candidate RVAs across the whole sample
(aggregate_processevent_vtable_candidates()): the same RVA recurring under
MANY DIFFERENT object classes is strong, class-independent evidence
(ProcessEvent is inherited from UObject, so a class-independent slot value
is exactly what the HYPOTHESIS predicts), while the same RVA recurring only
under ONE class, or several DIFFERENT RVAs each tied to one class, is
either evidence of genuine per-class ProcessEvent overrides or evidence the
slot/method is wrong -- this capability reports BOTH possibilities as raw
data (top_candidate, minority_candidates, each with its own distinct-class
count) and draws NO conclusion between them; a human (this session's own
operator) runs static disassembly correlation on the surfaced RVA(s)
separately, by hand, using the EXISTING pyghidra_scripts/dump_function.py
tool, and writes the graded verdict to RESEARCH_LOG.md.

OUTPUT, RAW, NOT A SCHEMA-GRADED RECORD: pe02-vtable-scan.json (build_pe02_
document()) is "raw single-run data, no evidence envelope" in the IDENTICAL
sense build_i04_document()'s own docstring already establishes -- no
evidence_level/claim_type/oracle/confidence field anywhere in it (none of
tools/kb/validate.py's MARKER_KEYS), so it is never mistaken for a graded
knowledge-base record by the validator. Unlike i04-classes.json, it carries
the FULL per-object sample list (bounded to a few hundred rows, small
enough to persist completely, unlike I-04's own ~26 000-object census).

NON-GOALS, DELIBERATELY OUT OF SCOPE: no disassembly, no decompilation, no
pyghidra_scripts invocation from this Python capability -- that correlation
step belongs to the human operator, separately, by hand, never wrapped or
called from eri.py. No ProcessEvent invocation, no function call of any
kind, no hooks, no writes -- strictly read-only ERI level 1, identical
guarantee to every other capability in this file (see "THE ARCHITECTURAL
GUARANTEE" section immediately below, unaffected: PE-02 adds new CALLERS of
the SAME single Win32Api.read_process_memory call site, via the SAME
_read_u64() helper I-02/I-03/I-04/I-06/I-05 already use, never a second
read primitive). No confidence grading, no schema envelope, no RESEARCH_LOG
entry -- the operator writes that, once, after personally reviewing this
capability's own raw output and running disassembly correlation.

THE ARCHITECTURAL GUARANTEE THIS FILE EXISTS TO PROVE (plan.md 8.2)
---------------------------------------------------------------------
    "Ничего не пишет, ничего не инжектит, не ставит хуков, не вызывает
    функций игры" -- writes nothing, injects nothing, hooks nothing, calls
    no game function.

This is not a configuration choice this tool happens to make; it is the one
property that makes this tool legitimate read-only research tooling instead
of a cheat-engine-shaped hack. It has to be provable by a reviewer who does
NOT trust this file's comments, so it is provable from two small, greppable
facts rather than from prose:

  1. Every Win32 call this tool ever makes is one of exactly EIGHT functions,
     all read-only observation primitives: CreateToolhelp32Snapshot,
     Process32FirstW, Process32NextW, Module32FirstW, Module32NextW,
     OpenProcess, ReadProcessMemory and CloseHandle. None of them writes to,
     allocates in, protects, or executes anything in the target process. In
     particular: no WriteProcessMemory, no VirtualAllocEx/VirtualProtectEx,
     no CreateRemoteThread/NtCreateThreadEx, no SetWindowsHookEx -- grep this
     file for "kernel32\\." and that is the complete list, forever, for this
     pass. ReadProcessMemory (added for I-02, REUSED verbatim by I-03 -- see
     point 2) reads only; it neither needs nor is ever given any access
     right beyond the PROCESS_VM_READ the handle already carries.
  2. There is exactly ONE call site for OpenProcess in the whole tool (see
     ``Win32Api.open_process`` below), and the access-rights argument it
     passes is the single module-level constant ``PROCESS_ACCESS_RIGHTS``,
     defined once, a few lines below this docstring, as
     ``PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`` and nothing else -- no
     ``PROCESS_ALL_ACCESS``, no ``PROCESS_VM_WRITE``, no
     ``PROCESS_VM_OPERATION``, no ``PROCESS_CREATE_THREAD``, no
     ``PROCESS_DUP_HANDLE``. This constant is UNCHANGED by I-02's or I-03's
     addition: ReadProcessMemory only ever needs PROCESS_VM_READ, which the
     handle already has, so neither capability opens a new kind of handle or
     requests a new right. There is likewise exactly ONE call site for
     ReadProcessMemory (``Win32Api.read_process_memory`` below), the single
     place this tool ever reads target-process memory -- I-03's own
     decode_fname_entry_id()/sample_object_names() call it through the same
     method, never a second wrapper. A reviewer who does not trust this
     docstring needs to read exactly two lines (one per call site) to audit
     both claims, and ``tests/test_eri_i01.py`` pins the "exactly one
     OpenProcess call site" fact and ``tests/test_eri_i02.py`` pins the
     equivalent "exactly one ReadProcessMemory call site" fact (still true
     with I-03 added -- ``tests/test_eri_i03.py`` does not re-pin it,
     because there is still only one file-wide count to pin and I-02's test
     already owns that assertion), so a future edit cannot silently add a
     second one of either.

CORRECTNESS/SAFETY RULE: EXACT MATCH, NEVER SUBSTRING (plan.md 8.5 "только
полностью контролируемых сессий")
---------------------------------------------------------------------------
Process and module name matching in this file is EXACT, case-insensitive
filename equality -- never ``in``, never ``startswith``, never a regex that
could match more than the literal name. This is not merely a correctness
nicety: a substring match (for example matching any process whose name
CONTAINS "MISERY-Win64-Shipping.exe") could silently attach this tool's
read-only handle to an unrelated process that merely has a similar or
longer name, which is both a wrong-result bug and a safety violation of the
"fully controlled session only" rule -- the tool would then be observing (or
a careless future edit could have it act on) a process nobody chose. See
``_names_equal`` below, the single place this comparison happens, and
``find_process_by_name``/``find_module_in_process``, its only two callers.

WHY ctypes, NOT A COMPILED LANGUAGE (plan.md 8.6 Q-8.1)
----------------------------------------------------------
plan.md 8.6 Q-8.1's own stated criterion: "минимальная стоимость до первого
дампа" (minimum cost to first dump). Python + ctypes calling the
Toolhelp32/OpenProcess Win32 API directly needs no new runtime dependency
(ctypes is standard library), is the same language as the rest of this
project's research tooling, and gets to a first working read-only dump
fastest. See the README's "Технология и почему выбрана" section for the
full answer; this paragraph exists so the choice is visible from the code
that embodies it too.

TESTABILITY WITHOUT A LIVE GAME PROCESS
-------------------------------------------
No MISERY process runs in CI or on a dev box without the game launched, so
every Win32 call in this file is reached through the ``Win32Api`` interface
below rather than called directly from the higher-level logic functions.
``tests/test_eri_i01.py`` substitutes a ``FakeWin32Api`` that returns
scripted process/module lists without touching the real Windows API -- the
same "duck-typed narrow interface, faked in tests" idiom
``pyghidra_scripts/dump_xrefs_for_string.py`` uses for the Ghidra API it
cannot start a JVM to exercise. The real ``Win32Api`` is what
``main()`` uses, and it is a thin, mechanical passthrough with no logic of
its own -- everything worth unit-testing lives in the plain-Python functions
below it, which take a Win32Api-shaped object as their first argument.

FAIL LOUDLY, NOT GRACEFULLY (plan.md 8.1)
---------------------------------------------
plan.md 8.1's own comparison table states the OPPOSITE error-handling rule
for ERI/IPP than for production code: "Обработка ошибок: падать громко и
сразу" for both instrument levels, versus "деградировать безопасно" for the
eventual MiseryRuntime product. Every failure mode here -- process not
found, module not found, OpenProcess refused, snapshot creation refused,
ReadProcessMemory refused or partial -- raises a specific exception with an
actionable message and propagates it; nothing here returns None-and-hope,
nothing retries silently, nothing falls back to a default. Do not "fix" this
into graceful degradation; that would be correct for product code and wrong
for this file.

STRUCTURAL REFUTATION IS A RESULT, NOT AN ERROR (I-02, I-03)
-------------------------------------------------------------
The rule above is about the TOOL malfunctioning -- a handle refused, a read
that could not be completed at all. It is deliberately NOT the rule for what
I-02 exists to determine: whether the RF-05 candidate's live structural
behaviour actually looks like a GUObjectArray. That question has an honest
"no" as one of its two possible answers, and "no" is exactly as valid and
exactly as worth recording as "yes" -- refuting a HYPOTHESIS is the whole
point of running this check, not a failure of the tool that ran it. So
run_i02() never raises for an implausible NumElements/MaxElements pair, a low
vtable-plausibility fraction, or a decreasing NumElements between polls; it
returns a plain dict with a boolean "pass" per check plus reasoning text, and
main() writes that dict to i02-guobjectarray.json exactly as it is, whichever
way the checks came out. What DOES raise (ReadProcessMemoryFailedError) is
the tool being unable to even attempt the read -- a hard Win32 failure or a
partial read from ReadProcessMemory itself -- because that is a genuine
malfunction, not a research finding, and conflating the two would make a
tool bug indistinguishable from a real refutation of RF-05's candidate.

The identical split applies to I-03: decode_fname_entry_id() decoding
FNameEntryId 0 to something other than "None" is a real, reportable
STRUCTURAL REFUTATION of the RF-06 candidate/bit-layout assumption -- it is
returned as data (decoded_as_expected: False, plus the raw bytes/length/
wide-flag actually observed, for a human to diagnose), never raised. The
"/Script/MISERY live reflection" probe's own not-found result
(misery_found: False) is likewise never treated as a refutation of
anything -- see sample_object_names()'s own docstring for why a miss in a
BOUNDED, non-exhaustive sample of the live UObject universe carries no such
implication. What DOES raise for I-03, identically to I-02, is
ReadProcessMemory itself failing on a foundational read this capability
cannot proceed without (bNamePoolInitialized, or any read inside the
decode arithmetic that is not itself the character-data decode).

Usage
-----
    python research/instruments/eri/eri.py \\
        --run-dir research/instrument-runs/2026-08-27T120000Z

See "Как запускать" in research/instruments/eri/README.md for the full
option reference.

IDENTITY IS SELF-ESTABLISHED, NEVER MERELY ASSERTED (LOG-0048/LOG-0049)
-------------------------------------------------------------------------
On 2026-08-27, an operator ran this tool with a --build-key copied from
earlier static-analysis work, without rechecking it, at the exact moment
Steam had silently updated MISERY as a side effect of launching it
(steam_buildid 24826585 -> 24953925). The supplied --build-key was WRONG for
the process actually being read, and this was only discovered afterward, by
hand, comparing a manually computed sha256 against appmanifest_2119830.acf's
buildid -- a real research-integrity mistake, found late, that had to be
corrected in already-written JSON artifacts.

The fix is structural, not a reminder to "be more careful": every run of
this tool computes the sha256 of MISERY-Win64-Shipping.exe ITSELF, streamed
from module.exe_path -- the exact file the OS loader mapped for the process
this run actually attached to -- and uses that as the authoritative
build_key (see establish_build_identity() below). --build-key is now an
OPTIONAL CROSS-CHECK, never the source of truth: if given, it is compared
against the self-computed hash and a mismatch raises BuildKeyMismatchError
loudly, before any output file is written, instead of silently producing a
document whose build_key lies about which build was actually read.
"""

from __future__ import annotations

import argparse
import collections
import ctypes
import hashlib
import json
import os
import re
import struct
import sys
import time
from ctypes import wintypes
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# import the shared output-path guard (plan.md decision D-01 / safety model
# 1.5 layer 1: no tool ever accepts a path inside the game installation as an
# output path). Imported, never reimplemented -- pathguard's own docstring is
# written about exactly the drift that copy-pasting this check invites.
# research/instruments/ is not itself a package (mirrors tools/), so this file
# bootstraps sys.path the same way pyghidra_scripts/_pyghidra_runner.py does
# to reach a sibling directory's module.
# --------------------------------------------------------------------------- #
_HERE = os.path.dirname(os.path.abspath(__file__))                 # research/instruments/eri
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))  # repo root
_TOOLS_INVENTORY = os.path.join(_REPO_ROOT, "tools", "inventory")
if _TOOLS_INVENTORY not in sys.path:
    sys.path.insert(0, _TOOLS_INVENTORY)

import pathguard  # noqa: E402

GENERATOR_NAME = "research/instruments/eri/eri.py"
GENERATOR_VERSION = "0.1.0"

CAPABILITY_ID = "I-01"
CAPABILITY_ID_I02 = "I-02"
CAPABILITY_ID_I03 = "I-03"
CAPABILITY_ID_I04 = "I-04"
CAPABILITY_ID_I05 = "I-05"
CAPABILITY_ID_I06 = "I-06"

# PE-02 (research/evidence/PE-01/README.md's own evidence track, continued)
# -- deliberately NOT an "I-0N" id: it is not one of plan.md 8.2's sixteen
# numbered capabilities (I-07..I-15 are reserved for UWorld/UGameInstance/
# etc., unrelated to this), so it must NEVER be appended to manifest.json's
# own capabilities_enabled array -- instrument-run-manifest.schema.json's
# eri_capability_id enum is closed to "I-01".."I-16" and would reject it.
# Used only as this capability's own raw document's 'capability' field
# (informational text, not schema-checked) -- see the module docstring's
# "WHAT PE-02 IS" section.
CAPABILITY_ID_PE02 = "PE-02"


# --------------------------------------------------------------------------- #
# small helpers (deliberately duplicated rather than imported across the
# research/instruments <-> tools/static boundary -- tools/static/protection_scan.py
# does the same for these two trivial functions rather than reaching into
# pyghidra_scripts, and this file is meant to be read and thrown away on its
# own, per the RESEARCH ONLY rule above)
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dump_json(document: dict) -> str:
    """Deterministic serialization: sorted keys, indent 2, LF, trailing newline."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _repo_relative(path: str) -> str:
    """*path* relative to the repository root, '/'-separated.

    Used only for the manifest's own 'artifacts' list, which
    research/schema/instrument-run-manifest.schema.json documents as
    repository-relative paths -- never an absolute path, which would carry
    this machine's user profile (C-13). Normal usage (plan.md 8.5: "все
    дампы пишутся в research/ этого репозитория") always has the output
    under the repository, so the relative form is what gets written in
    practice.

    Falls back to the absolute, '/'-separated path if *path* is not
    reachable from the repository root via a relative path at all -- on
    Windows, os.path.relpath() RAISES ValueError for two paths on different
    drive letters (e.g. output on C: while the repository is on D:), rather
    than returning something usable. That case is not a policy violation
    this function's job to enforce (pathguard's own job above is narrower:
    it only refuses a path INSIDE the game installation, never enforces
    "must be under research/"), so this must degrade to a still-valid
    artifact path instead of raising and losing the manifest entirely --
    the I-01 document itself may already be written to disk by the time
    this runs (see main()'s ordering), so crashing here would leave an
    orphaned dump with no manifest to explain it.
    """
    resolved = os.path.abspath(path)
    try:
        relative = os.path.relpath(resolved, _REPO_ROOT)
    except ValueError:
        return resolved.replace(os.sep, "/")
    return relative.replace(os.sep, "/")


# --------------------------------------------------------------------------- #
# Win32 constants -- READ THIS BLOCK to audit the safety guarantee.
# --------------------------------------------------------------------------- #

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008

MAX_PATH = 260
MAX_MODULE_NAME32 = 255

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# THE single access-rights constant this tool ever passes to OpenProcess
# (Win32Api.open_process below is the ONE call site). Read-only query and
# read-only memory-read rights, nothing else: no PROCESS_VM_WRITE, no
# PROCESS_VM_OPERATION (required before a VirtualProtectEx/WriteProcessMemory
# would even be attempted), no PROCESS_CREATE_THREAD, no PROCESS_DUP_HANDLE,
# no PROCESS_ALL_ACCESS. This literal value (0x0410) is the auditable proof
# of plan.md 8.2's "ничего не пишет, ничего не инжектит" for the handle this
# tool holds on the game process.
PROCESS_ACCESS_RIGHTS = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ


# --------------------------------------------------------------------------- #
# ctypes structures -- the WIDE (W) Toolhelp32 layouts only. Mixing the ANSI
# and wide structs/functions is the classic bug this tool must not have: an
# ANSI PROCESSENTRY32 read through the wide Process32FirstW (or vice versa)
# has a different total size and different field widths, which either
# corrupts adjacent memory or silently reads garbage into szExeFile/szModule.
# Every struct, every function below is the W variant, with no ANSI sibling
# anywhere in this file.
# --------------------------------------------------------------------------- #

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),   # ULONG_PTR; value unused
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),         # BYTE*; the base address itself
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", wintypes.WCHAR * MAX_PATH),
    ]


# --------------------------------------------------------------------------- #
# plain-Python records the logic layer actually works with -- decoupled from
# ctypes so FakeWin32Api in the test suite never has to touch a real struct.
# --------------------------------------------------------------------------- #

ProcessEntry = collections.namedtuple("ProcessEntry", ["pid", "exe_file"])
ModuleEntry = collections.namedtuple(
    "ModuleEntry", ["module_name", "exe_path", "base_address", "size"])


# --------------------------------------------------------------------------- #
# exceptions -- every failure mode this tool recognizes raises one of these,
# with an actionable message, and none of them is ever swallowed (plan.md 8.1
# "падать громко и сразу").
# --------------------------------------------------------------------------- #

class EriError(Exception):
    """Base class for every error this tool raises on purpose."""


class SnapshotFailedError(EriError):
    """CreateToolhelp32Snapshot itself failed (not: the snapshot was empty)."""


class ProcessNotFoundError(EriError):
    """No running process has EXACTLY the requested executable filename."""


class TargetModuleNotFoundError(EriError):
    """The target process exists, but its module list has no exact match."""


class OpenProcessFailedError(EriError):
    """OpenProcess (with PROCESS_ACCESS_RIGHTS only) was refused by the OS."""


class ReadProcessMemoryFailedError(EriError):
    """ReadProcessMemory (I-02 onward) could not complete the requested read.

    Covers BOTH distinct failure modes ReadProcessMemory can produce, never
    conflating them: a hard Win32 failure (the BOOL return itself is false --
    typically the address is unmapped, or the process has since exited), and
    a PARTIAL read (the call succeeds, but *lpNumberOfBytesRead is less than
    the size requested -- for example because the requested range straddles
    an unmapped page). A partial read is not "close enough" data; treating
    fewer bytes than requested as if the full read had succeeded would silently
    feed truncated/garbage bytes into struct unpacking downstream, which is
    strictly worse than failing loudly here.

    This is a TOOL malfunction, not a research finding -- see the module
    docstring's "STRUCTURAL REFUTATION IS A RESULT, NOT AN ERROR" section for
    why this must never be confused with run_i02()'s own structural-invariant
    checks failing (an implausible NumElements, a low vtable-plausibility
    fraction, a decreasing NumElements): those are honest "no" answers to a
    research question and are returned as data, never raised as this
    exception.
    """


class BuildKeyMismatchError(EriError):
    """--build-key was given, but does not match the self-computed sha256 of
    module.exe_path -- the file the OS loader actually mapped for THIS live
    process.

    This is exactly the class of mistake LOG-0048/LOG-0049 recorded on
    2026-08-27: an operator supplied a --build-key copied from earlier
    static-analysis work, without rechecking it, at the exact moment Steam
    had silently updated the game as a side effect of launching it
    (steam_buildid 24826585 -> 24953925). The recorded build_key was wrong
    for the process actually being read, and the mistake was only caught
    afterward, by hand, and had to be corrected in already-written JSON
    artifacts. That is precisely the failure this exception exists to make
    impossible to miss: a cached/supplied build_key is never the source of
    truth (see establish_build_identity() and the module docstring's
    "IDENTITY IS SELF-ESTABLISHED" section), so a mismatch between what was
    supplied and what this run actually observed must fail loudly, before a
    single output file is written, rather than silently producing a document
    that misattributes this run's data to the wrong build. Do not "simplify"
    this check away or make it a warning -- a warning is exactly what got
    missed in LOG-0048.
    """


def _last_error_suffix(api: "Win32Api | object") -> str:
    """' (GetLastError=N)' when *api* can report one, else ''.

    Best-effort only: FakeWin32Api in tests need not implement
    get_last_error at all, and a real failure is fully actionable from the
    exception type and message alone even without the raw code.
    """
    getter = getattr(api, "get_last_error", None)
    if getter is None:
        return ""
    try:
        code = getter()
    except Exception:  # noqa: BLE001 - diagnostics must never mask the real error
        return ""
    return "" if not code else " (GetLastError=%d)" % code


# --------------------------------------------------------------------------- #
# Win32Api -- the ONLY place any kernel32 function is ever called from. Every
# method here is a mechanical 1:1 wrapper around exactly one Win32 call; no
# branching logic of consequence lives in this class, which is what makes
# "audit the OpenProcess call site" a one-line exercise instead of a
# whole-class one.
# --------------------------------------------------------------------------- #

_kernel32 = None  # lazily bound so importing this module never touches ctypes


def _kernel32_dll():
    """The bound kernel32 DLL with prototypes set, created on first use.

    Deferred past import time so that ``import eri`` (for --help, or for a
    test that only exercises the plain-Python logic functions against
    FakeWin32Api) never requires a Windows kernel32.dll to be loadable --
    useful on the rare occasion this module is merely imported for its
    constants/schema-shape from a non-Windows checker.
    """
    global _kernel32
    if _kernel32 is not None:
        return _kernel32

    dll = ctypes.WinDLL("kernel32", use_last_error=True)

    dll.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    dll.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

    dll.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    dll.Process32FirstW.restype = wintypes.BOOL
    dll.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    dll.Process32NextW.restype = wintypes.BOOL

    dll.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    dll.Module32FirstW.restype = wintypes.BOOL
    dll.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    dll.Module32NextW.restype = wintypes.BOOL

    # THE one function whose access-rights argument matters for the whole
    # tool's safety story. argtypes pinned so ctypes never silently truncates
    # dwDesiredAccess on a 64-bit build.
    dll.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    dll.OpenProcess.restype = wintypes.HANDLE

    # THE one function this tool uses to read target-process memory (I-02
    # onward). BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress,
    # LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead). SIZE_T is
    # POINTER-WIDTH (8 bytes on x64), never a 32-bit int -- ctypes.c_size_t is
    # used for both the size argument and the out-parameter it points to,
    # specifically so this never silently truncates on a 64-bit build the way
    # a wrongly-picked c_uint32 would.
    dll.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    dll.ReadProcessMemory.restype = wintypes.BOOL

    dll.CloseHandle.argtypes = [wintypes.HANDLE]
    dll.CloseHandle.restype = wintypes.BOOL

    _kernel32 = dll
    return dll


def _is_invalid_handle(value) -> bool:
    """True for every ctypes marshalling of INVALID_HANDLE_VALUE / NULL.

    A failed CreateToolhelp32Snapshot returns (HANDLE)-1
    (INVALID_HANDLE_VALUE); a failed OpenProcess returns NULL. ctypes'
    marshalling of a HANDLE return value can come back as ``None`` (NULL),
    as Python ``-1``, or -- depending on ctypes/platform internals -- as the
    unsigned 64-bit spelling of -1; all three are checked so the failure
    path never depends on which one this ctypes build happens to produce.
    """
    return value in (None, 0, -1, 0xFFFFFFFFFFFFFFFF)


class Win32Api:
    """Real Windows API access. See the module docstring for why every
    logic function below takes an object shaped like this one as a
    parameter instead of calling kernel32 directly: it is the seam
    ``tests/test_eri_i01.py`` substitutes to exercise this tool with no
    MISERY process running anywhere.
    """

    def create_toolhelp32_snapshot(self, flags: int, pid: int) -> int:
        return _kernel32_dll().CreateToolhelp32Snapshot(flags, pid)

    def process32_first(self, snapshot: int) -> ProcessEntry | None:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not _kernel32_dll().Process32FirstW(snapshot, ctypes.byref(entry)):
            return None
        return ProcessEntry(pid=int(entry.th32ProcessID), exe_file=str(entry.szExeFile))

    def process32_next(self, snapshot: int) -> ProcessEntry | None:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not _kernel32_dll().Process32NextW(snapshot, ctypes.byref(entry)):
            return None
        return ProcessEntry(pid=int(entry.th32ProcessID), exe_file=str(entry.szExeFile))

    def module32_first(self, snapshot: int) -> ModuleEntry | None:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if not _kernel32_dll().Module32FirstW(snapshot, ctypes.byref(entry)):
            return None
        return ModuleEntry(
            module_name=str(entry.szModule), exe_path=str(entry.szExePath),
            base_address=int(entry.modBaseAddr or 0), size=int(entry.modBaseSize))

    def module32_next(self, snapshot: int) -> ModuleEntry | None:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if not _kernel32_dll().Module32NextW(snapshot, ctypes.byref(entry)):
            return None
        return ModuleEntry(
            module_name=str(entry.szModule), exe_path=str(entry.szExePath),
            base_address=int(entry.modBaseAddr or 0), size=int(entry.modBaseSize))

    def open_process(self, pid: int) -> int:
        """THE ONLY OpenProcess call site in this entire tool.

        The access mask is the module-level constant PROCESS_ACCESS_RIGHTS
        (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) and nothing else --
        never a parameter, never computed, never widened by a caller. A
        reviewer auditing plan.md 8.2's "read-only, no write/inject" claim
        needs to read this one method and nowhere else in the file.
        """
        return _kernel32_dll().OpenProcess(PROCESS_ACCESS_RIGHTS, False, pid)

    def read_process_memory(self, handle: int, address: int, size: int) -> bytes:
        """THE ONLY ReadProcessMemory call site in this entire tool (I-02
        onward) -- the one place this tool ever reads target-process memory.
        Uses the SAME already-open, already-audited handle
        open_process_read_only() establishes via the one OpenProcess call
        site above; PROCESS_ACCESS_RIGHTS is unchanged by this method's
        existence, because ReadProcessMemory only ever needs the
        PROCESS_VM_READ bit that handle already carries -- no
        PROCESS_VM_WRITE, no PROCESS_VM_OPERATION, no widened mask of any
        kind is requested anywhere for this call to work.

        Raises ReadProcessMemoryFailedError, distinguishing the two failure
        modes the real Win32 call can produce, both handled explicitly:

        * a hard failure -- the BOOL return itself is false (address
          unmapped, process exited, access denied);
        * a PARTIAL read -- the call returns true, but
          *lpNumberOfBytesRead is less than *size* (for example, the
          requested range straddles the end of a mapped page). This is
          checked explicitly and separately from the BOOL return: a partial
          read must never be treated as if the full read had succeeded,
          because the caller would otherwise silently struct-unpack
          truncated or uninitialised bytes as if they were real data.

        Returns exactly *size* bytes on success, never fewer, never a
        larger buffer's unsliced backing memory.
        """
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        ok = _kernel32_dll().ReadProcessMemory(
            handle, ctypes.c_void_p(address), buffer, ctypes.c_size_t(size),
            ctypes.byref(bytes_read))
        if not ok:
            raise ReadProcessMemoryFailedError(
                "ReadProcessMemory(address=0x%x, size=%d) failed%s" %
                (address, size, _last_error_suffix(self)))
        if bytes_read.value != size:
            raise ReadProcessMemoryFailedError(
                "ReadProcessMemory(address=0x%x, size=%d) returned a PARTIAL "
                "read: only %d of %d requested bytes were actually read%s -- "
                "a distinct failure mode from a hard Win32 failure, and never "
                "silently treated as if the full read had succeeded." %
                (address, size, bytes_read.value, size, _last_error_suffix(self)))
        return buffer.raw[:size]

    def close_handle(self, handle: int) -> bool:
        return bool(_kernel32_dll().CloseHandle(handle))

    def get_last_error(self) -> int:
        return ctypes.get_last_error()


# --------------------------------------------------------------------------- #
# core logic -- takes an api object (Win32Api or a FakeWin32Api in tests),
# never touches kernel32/ctypes directly. Handles are closed on every path,
# including every error path, via try/finally.
# --------------------------------------------------------------------------- #

def _names_equal(a: str, b: str) -> bool:
    """EXACT, case-insensitive filename equality. NEVER substring.

    The one comparison predicate used by both find_process_by_name and
    find_module_in_process. A process or module named
    'NotMISERY-Win64-Shipping.exe' or 'MISERY-Win64-Shipping.exe.bak' must
    NOT match a request for 'MISERY-Win64-Shipping.exe' -- see the module
    docstring's "CORRECTNESS/SAFETY RULE" section for why a substring match
    here would be a safety bug, not merely an inconvenience.
    """
    return a.casefold() == b.casefold()


def find_process_by_name(api, process_name: str) -> ProcessEntry:
    """The one running process whose executable filename EXACTLY (case-
    insensitively) equals *process_name*. Raises ProcessNotFoundError if
    none does; raises SnapshotFailedError if the snapshot itself could not
    be created. The snapshot handle is always closed, on every path.
    """
    snapshot = api.create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0)
    if _is_invalid_handle(snapshot):
        raise SnapshotFailedError(
            "CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) failed%s -- cannot "
            "enumerate running processes at all." % _last_error_suffix(api))
    try:
        entry = api.process32_first(snapshot)
        while entry is not None:
            if _names_equal(entry.exe_file, process_name):
                return entry
            entry = api.process32_next(snapshot)
    finally:
        api.close_handle(snapshot)
    raise ProcessNotFoundError(
        "no running process has the exact executable filename %r (matching is "
        "exact and case-insensitive, never substring -- see the module "
        "docstring). Is the game actually running, and is --process-name "
        "spelled exactly as Windows reports it?" % process_name)


def find_module_in_process(api, pid: int, module_name: str) -> ModuleEntry:
    """The one module of process *pid* whose szModule (or szExePath's own
    basename) EXACTLY equals *module_name*. Raises TargetModuleNotFoundError
    if none does; raises SnapshotFailedError if the module snapshot itself
    could not be created (for example because the process already exited
    between find_process_by_name and this call). The snapshot handle is
    always closed, on every path.
    """
    snapshot = api.create_toolhelp32_snapshot(TH32CS_SNAPMODULE, pid)
    if _is_invalid_handle(snapshot):
        raise SnapshotFailedError(
            "CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid=%d) failed%s -- "
            "the process may have exited, or access was denied." %
            (pid, _last_error_suffix(api)))
    try:
        entry = api.module32_first(snapshot)
        while entry is not None:
            exe_path_basename = os.path.basename(entry.exe_path) if entry.exe_path else ""
            if _names_equal(entry.module_name, module_name) or \
                    _names_equal(exe_path_basename, module_name):
                return entry
            entry = api.module32_next(snapshot)
    finally:
        api.close_handle(snapshot)
    raise TargetModuleNotFoundError(
        "process pid=%d has no module named exactly %r (checked szModule and "
        "the basename of szExePath, both exact case-insensitive match only)." %
        (pid, module_name))


def open_process_read_only(api, pid: int) -> int:
    """OpenProcess(PROCESS_ACCESS_RIGHTS, ..., pid) via the tool's one call
    site (Win32Api.open_process). Raises OpenProcessFailedError, with the
    exact access mask requested in the message, if refused.
    """
    handle = api.open_process(pid)
    if _is_invalid_handle(handle):
        raise OpenProcessFailedError(
            "OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ = 0x%04x, "
            "pid=%d) was refused%s. This tool never requests more than these "
            "two read-only rights, so a refusal here is either 'the process "
            "already exited' or a genuine access-denied (run as the same user "
            "that owns the game process; do not run elevated to force this -- "
            "that changes what this run can honestly claim about itself)." %
            (PROCESS_ACCESS_RIGHTS, pid, _last_error_suffix(api)))
    return handle


def run_i01(api, process_name: str) -> dict:
    """The whole of capability I-01: find the process, open it read-only
    (proving the access actually holds, per plan.md 8.2's requirement that
    the handle itself carry no write/inject rights), enumerate its modules,
    and return the base address + image size of *process_name*'s own
    module. Every handle opened here is closed before this function returns
    or raises, on every path.

    Returns a plain dict: {"pid", "process_name", "base_address",
    "image_size_bytes", "exe_path"}. "exe_path" is MODULEENTRY32W's own
    szExePath -- the exact file path the OS loader mapped for this live
    process, straight from Module32FirstW/Module32NextW, never a path
    supplied on the command line or cached from a previous run. It exists in
    this dict specifically so a caller (main() below, and any later
    capability that needs to establish or re-confirm build identity) can
    feed it to establish_build_identity() without re-deriving it -- see that
    function's docstring for why self-establishing identity from THIS field,
    every run, is not optional (LOG-0048/LOG-0049). Raises one of the
    EriError subclasses above on any failure -- never returns None, never
    degrades.
    """
    process = find_process_by_name(api, process_name)
    process_handle = open_process_read_only(api, process.pid)
    try:
        module = find_module_in_process(api, process.pid, process_name)
    finally:
        api.close_handle(process_handle)
    return {
        "pid": process.pid,
        "process_name": process.exe_file,
        "base_address": module.base_address,
        "image_size_bytes": module.size,
        "exe_path": module.exe_path,
    }


# --------------------------------------------------------------------------- #
# I-02: enumerate objects via the candidate GUObjectArray (plan.md 8.2), and
# VERIFY it via live structural behaviour rather than merely re-reading it
# and trusting the static signature match -- see the module docstring's
# "WHAT I-02 IS" section and research/evidence/RF-05/README.md for the full
# reasoning and the struct layout this is built from.
# --------------------------------------------------------------------------- #

def rva_to_live_va(base_address: int, rva: int) -> int:
    """live_base_address + RVA -- THE one place this arithmetic happens.

    Every static-analysis candidate (RF-05, RF-06, RF-07, PE-01, ...) is
    recorded as an RVA (offset from the PE's declared ImageBase), NEVER as a
    live virtual address, because ASLR is active for this image at runtime
    even though S-06 separately found zero relocation entries inside
    executable sections (explained by heavy RIP-relative addressing needing
    no relocation fixups -- "no .reloc entries in .text" is NOT the same
    fact as "no ASLR", and the two must never be conflated). Confirmed
    directly this session: this build's live process is NOT loaded at its
    declared PE ImageBase (0x140000000) -- see run_i01()'s own base_address
    read, which came back a different value entirely.

    The live VA of any such candidate is therefore ALWAYS
    live_base_address (THIS session's own I-01 read, never cached from a
    previous session or a different process launch) + RVA (a fixed,
    build-specific constant: RVA = static_candidate_VA - declared_ImageBase).
    Every future ERI capability (I-03 onward) that needs to turn a
    static-analysis candidate into a live address should call this function
    rather than reimplementing the addition slightly differently each time.
    """
    return base_address + rva


# GUObjectArray candidate: research/evidence/RF-05/README.md, static VA
# 0x147a78ed0 against declared PE ImageBase 0x140000000 -> RVA 0x07a78ed0.
# HYPOTHESIS, class I, oracle binary-analysis, confidence 0.65 (RF-05's own
# grade) -- this is exactly the candidate I-02 exists to check against live
# structural behaviour, not to assume still holds because the RVA is
# unchanged. research/builds/misery-24953925-ue5.4.4-bace50f7185d/sigscan/
# RF-05-sigscan.json separately confirms all 5 RF-05 signatures still match
# this new build's exe, unique, at their original RVAs -- good STATIC reason
# to expect this candidate still holds, but plan.md 564-566's ceiling on a
# static-analysis offset applies regardless, which is the entire reason this
# capability exists.
DEFAULT_GUOBJECTARRAY_RVA = 0x07A78ED0

# FUObjectArray struct offsets, all relative to the GUObjectArray candidate's
# own base address (research/evidence/RF-05/README.md's struct-layout table,
# itself read from Engine/Source/Runtime/CoreUObject/Public/UObject/
# UObjectArray.h, UE 5.4.4 CL 35576357). Only the fields I-02 actually reads
# are named here; the ones RF-05 read but I-02 does not need
# (ObjFirstGCIndex, OpenForDisregardForGC, PreAllocatedObjects, MaxChunks)
# are intentionally omitted rather than defined-and-unused.
GUOBJECTARRAY_OFFSET_OBJECTS = 0x10          # FUObjectItem** Objects
GUOBJECTARRAY_OFFSET_MAX_ELEMENTS = 0x20     # int32 MaxElements
GUOBJECTARRAY_OFFSET_NUM_ELEMENTS = 0x24     # int32 NumElements

# FChunkedFixedUObjectArray::GetObjectPtr addressing (RF-05/README.md,
# UObjectArray.h:638-654): NumElementsPerChunk is a compile-time constant
# 64*1024 = 2^16, hence a shift-by-16/mask-0xFFFF, not a division.
NUM_ELEMENTS_PER_CHUNK = 1 << 16

# sizeof(FUObjectItem) = 20 bytes of fields, padded to 24 for pointer
# alignment (RF-05/README.md) -- the per-element stride the chunk walk uses.
SIZEOF_FUOBJECTITEM = 0x18
FUOBJECTITEM_OFFSET_OBJECT = 0x00            # UObjectBase* Object, first field

# Check 1 (NumElements/MaxElements plausibility) ceiling -- see
# evaluate_struct_invariants()'s own docstring for the reasoning.
MAX_PLAUSIBLE_MAX_ELEMENTS = 100_000_000

# Check 2 (vtable-plausibility sample) pass threshold and defaults -- see
# sample_walk_objects()'s own docstring for the reasoning behind the number.
SAMPLE_PASS_FRACTION_THRESHOLD = 0.80
DEFAULT_I02_SAMPLE_SIZE = 32
DEFAULT_I02_MAX_SCAN_INDICES = 200_000

# Check 3 (growth) default poll interval, seconds.
DEFAULT_I02_POLL_INTERVAL_SECONDS = 2.0


def _read_i32(api, handle: int, address: int) -> int:
    """Signed little-endian int32 at *address*. ObjLastNonGCIndex/
    MaxObjectsNotConsideredByGC/MaxElements/NumElements are all declared
    `int32` in source (RF-05/README.md), so this reads SIGNED, not unsigned:
    a genuinely negative NumElements/MaxElements is possible corrupted or
    implausible data, and evaluate_struct_invariants() below must be able to
    see that it is negative, rather than have it silently wrap to a huge
    unsigned value first.
    """
    return struct.unpack("<i", api.read_process_memory(handle, address, 4))[0]


def _read_u64(api, handle: int, address: int) -> int:
    """Unsigned little-endian uint64 at *address*. Every pointer-sized field
    this capability reads (Objects, a chunk pointer, FUObjectItem::Object, a
    UObject's own vtable pointer) is a 64-bit address on this x64 target,
    never signed.
    """
    return struct.unpack("<Q", api.read_process_memory(handle, address, 8))[0]


def _read_u16(api, handle: int, address: int) -> int:
    """Unsigned little-endian uint16 at *address* -- I-03's own
    FNameEntryHeader read (decode_fname_entry_id()), the ONE 16-bit field
    this tool ever reads. Unsigned because FNameEntryHeader's three bitfields
    (bIsWide/LowercaseProbeHash/Len) are packed into a plain `uint16` in
    source (NameTypes.h), never a signed integer.
    """
    return struct.unpack("<H", api.read_process_memory(handle, address, 2))[0]


def _read_u32(api, handle: int, address: int) -> int:
    """Unsigned little-endian uint32 at *address* -- I-03's own FNameEntryId
    read (FName::ComparisonIndex, NamePrivate's first 4 bytes on a live
    UObject; the sample_object_names() reflection probe reads this). Unsigned
    because FNameEntryId::Value is declared `uint32` in source (NameTypes.h),
    and a raw FNameEntryId is never negative/signed.
    """
    return struct.unpack("<I", api.read_process_memory(handle, address, 4))[0]


def _read_u8(api, handle: int, address: int) -> int:
    """Unsigned 8-bit byte at *address* -- I-06's own FBoolProperty field
    reads (FieldSize/ByteOffset/ByteMask/FieldMask, UnrealType.h:2383-2389),
    the first single-byte field this tool ever reads. Routed through the
    SAME single Win32Api.read_process_memory call site every other _read_*
    helper in this file already uses -- see the module docstring's "exactly
    one ReadProcessMemory call site" guarantee, unaffected by adding this
    function (it is a new CALLER of that one method, never a second one).
    """
    return struct.unpack("<B", api.read_process_memory(handle, address, 1))[0]


def evaluate_struct_invariants(num_elements: int, max_elements: int) -> dict:
    """Check (1) of RF-05/README.md's "What a runtime observation would need
    to show to move this above HYPOTHESIS": NumElements/MaxElements must be
    PLAUSIBLE, not merely readable. Never raises -- an implausible reading
    is a STRUCTURAL REFUTATION of the candidate, a valid research outcome,
    not a tool error (see the module docstring's "STRUCTURAL REFUTATION IS A
    RESULT, NOT AN ERROR" section).

    Three conditions, ALL required to PASS:
      * 0 < NumElements -- a genuine, populated object registry has objects
        in it; RF-05/README.md's own expectation is thousands to low
        millions for a running UE process, but even the loosest reading
        requires at least one live object.
      * NumElements <= MaxElements -- MaxElements is the allocated capacity
        (AllocateObjectPool computes it from MaxChunks*NumElementsPerChunk);
        a live count exceeding its own declared capacity is structurally
        impossible for the real struct, and is strong evidence this address
        is not it.
      * MaxElements < MAX_PLAUSIBLE_MAX_ELEMENTS (100,000,000) -- an
        allocated-capacity field reading in the hundreds of millions or
        billions is not "a UE object array that hasn't filled up yet", it is
        noise (wrong address, or a read that landed on unrelated memory).
        100,000,000 is chosen as a ceiling far above any plausible UE
        MaxObjectsInGame/MaxObjectsInEditor cvar value (typically low
        millions at the very most) while still being generous enough that no
        legitimate build could trip it by simply having a large project.
    """
    reasons = []
    if not (num_elements > 0):
        reasons.append("NumElements (%d) is not > 0" % num_elements)
    if not (num_elements <= max_elements):
        reasons.append(
            "NumElements (%d) exceeds MaxElements (%d)" % (num_elements, max_elements))
    if not (max_elements < MAX_PLAUSIBLE_MAX_ELEMENTS):
        reasons.append(
            "MaxElements (%d) exceeds the plausibility ceiling (%d)" %
            (max_elements, MAX_PLAUSIBLE_MAX_ELEMENTS))
    passed = not reasons
    return {
        "num_elements": num_elements,
        "max_elements": max_elements,
        "pass": passed,
        "reason": None if passed else "; ".join(reasons),
    }


def _vtable_pointer_in_module_range(pointer: int, base_address: int, image_size_bytes: int) -> bool:
    """True iff *pointer* falls inside [base_address, base_address+image_size_bytes)
    -- a plausible vtable pointer lives in the SAME module's .rdata/.text,
    never in the heap or a different module. This is the SAME check
    sample_walk_objects() below already used inline for a sampled UObject's
    own vtable pointer; factored out here (I-04) so that capability's own
    structural-validation check (3) -- "the first 8 bytes at ClassPrivate's
    own address look like a vtable pointer" -- reuses the IDENTICAL formula
    rather than re-deriving it a second time, per the "reuse I-02's own
    vtable-pointer check" instruction this capability was specified from.
    sample_walk_objects() itself was updated to call this too, so there is
    exactly one place this comparison is expressed in the whole file.
    """
    return base_address <= pointer < base_address + image_size_bytes


def _locate_object_pointer(api, handle: int, objects_ptr: int, index: int) -> int | None:
    """FChunkedFixedUObjectArray::GetObjectPtr's own shift-16/mask-0xFFFF/
    stride-24 addressing (RF-05/README.md), factored out of I-02's own
    sample_walk_objects so I-03's own "/Script/MISERY live reflection" probe
    (sample_object_names() below) can reuse the IDENTICAL chunk-walk
    arithmetic rather than re-deriving it a second time -- see the module
    docstring's "WHAT I-03 IS" section. sample_walk_objects itself was
    rewritten to call this too, so there is exactly one place this
    arithmetic is expressed in the whole file, not two that could silently
    drift apart.

    Returns FUObjectItem[*index*].Object -- the object pointer -- or None if
    either the chunk itself was never allocated (Blocks[chunk_index] == 0)
    or the slot itself is a freed/never-allocated null. Lets
    ReadProcessMemoryFailedError propagate from EITHER of its two reads (the
    chunk pointer, the slot's Object field) unchanged -- callers that want
    "unreadable is like null, not a tool error" (both sample_walk_objects and
    sample_object_names) catch it themselves at the call site; a caller that
    instead wants a foundational-read failure to abort outright simply does
    not catch it.
    """
    chunk_index = index >> 16
    within_chunk_index = index & 0xFFFF
    chunk_base = _read_u64(api, handle, objects_ptr + chunk_index * 8)
    if chunk_base == 0:
        return None
    item_addr = chunk_base + within_chunk_index * SIZEOF_FUOBJECTITEM
    object_ptr = _read_u64(api, handle, item_addr + FUOBJECTITEM_OFFSET_OBJECT)
    return object_ptr if object_ptr != 0 else None


def sample_walk_objects(api, handle: int, objects_ptr: int, num_elements: int,
                        base_address: int, image_size_bytes: int,
                        sample_size: int = DEFAULT_I02_SAMPLE_SIZE,
                        max_scan_indices: int = DEFAULT_I02_MAX_SCAN_INDICES) -> dict:
    """Check (2) of RF-05/README.md's list: walk a BOUNDED sample of live
    indices using FChunkedFixedUObjectArray::GetObjectPtr's own
    shift-16/mask-0xFFFF/stride-24 arithmetic, and for each sampled non-null
    FUObjectItem::Object pointer, read the UObject's own first 8 bytes (its
    vtable pointer, per RF-05/PE-01's own established finding that
    UObjectBase's destructor is virtual) and check it falls inside
    [base_address, base_address + image_size_bytes) -- a plausible vtable
    lives in the SAME module's .rdata/.text, never in the heap, never in a
    different module.

    Never walks the whole array: indices 0..num_elements are scanned in
    order, stopping as soon as *sample_size* NON-NULL objects have been
    examined, or *max_scan_indices* index slots have been looked at,
    whichever comes first -- max_scan_indices exists purely so a corrupted
    (implausibly huge, or all-null) NumElements cannot turn this into an
    unbounded scan; it is not itself a plausibility signal.

    A read failure (ReadProcessMemoryFailedError) while merely LOCATING a
    candidate object (reading a chunk pointer, or a slot's Object field) is
    treated as an unreadable slot and skipped, exactly like a null slot --
    the target process's own memory layout can legitimately have unmapped or
    since-freed chunks, and this is a SCANNING concern, not a sample result.
    A read failure while reading the VTABLE POINTER of an object THIS
    function already decided to sample counts as a FAILED sample (a "torn
    read during concurrent GC" is exactly the scenario RF-05/README.md's own
    method anticipates) -- it does not silently skip to the next index,
    because that object was already committed to the sample the moment its
    Object pointer was found non-null.

    Threshold: PASS iff at least one object was examined AND the pass
    fraction is >= SAMPLE_PASS_FRACTION_THRESHOLD (0.80). This project's own
    judgment call, recorded here for a future reader to evaluate: a handful
    of failures from a torn read during concurrent GC (RF-05/README.md's own
    framing) is plausible and should NOT by itself refute the candidate, but
    a majority-failing sample cannot plausibly be explained by transient GC
    noise alone and IS strong evidence against the candidate. 0.80 sits well
    above what GC-related noise alone should ever produce (a handful out of
    dozens, not one in five) while still being well below 1.00, so an
    occasional torn read never flips a genuine candidate to REFUTED on its
    own.
    """
    examined = 0
    passed = 0
    failed = 0
    scanned = 0
    index = 0
    image_start = base_address
    image_end = base_address + image_size_bytes
    scan_limit = max_scan_indices if num_elements <= 0 else min(num_elements, max_scan_indices)

    while index < scan_limit and examined < sample_size:
        scanned += 1
        try:
            object_ptr = _locate_object_pointer(api, handle, objects_ptr, index)
        except ReadProcessMemoryFailedError:
            index += 1
            continue  # unreadable slot -- a scanning concern, not a sample.

        if object_ptr is None:
            index += 1
            continue  # a freed/never-allocated slot, or an unallocated chunk.

        examined += 1
        try:
            vtable_ptr = _read_u64(api, handle, object_ptr)
            plausible = _vtable_pointer_in_module_range(
                vtable_ptr, base_address, image_size_bytes)
        except ReadProcessMemoryFailedError:
            plausible = False  # a torn read on an already-committed sample.

        if plausible:
            passed += 1
        else:
            failed += 1
        index += 1

    pass_fraction = (passed / examined) if examined else 0.0
    if examined == 0:
        reason = (
            "no non-null FUObjectItem.Object pointer was found in the "
            "%d index slot(s) scanned (scan_limit=%d) -- either the array "
            "is genuinely empty, or this is not the object array." %
            (scanned, scan_limit))
        check_passed = False
    else:
        check_passed = pass_fraction >= SAMPLE_PASS_FRACTION_THRESHOLD
        reason = None if check_passed else (
            "only %d of %d sampled objects (%.1f%%) had a vtable pointer "
            "inside [0x%x, 0x%x) -- below the %.0f%% pass threshold." %
            (passed, examined, pass_fraction * 100, image_start, image_end,
             SAMPLE_PASS_FRACTION_THRESHOLD * 100))

    return {
        "sample_size_requested": sample_size,
        "sample_size_examined": examined,
        "pass_count": passed,
        "fail_count": failed,
        "pass_fraction": pass_fraction,
        "pass_fraction_threshold": SAMPLE_PASS_FRACTION_THRESHOLD,
        "indices_scanned": scanned,
        "max_scan_indices": max_scan_indices,
        "pass": check_passed,
        "reason": reason,
    }


def run_i02(api, process_handle: int, base_address: int, image_size_bytes: int,
           guobjectarray_rva: int = DEFAULT_GUOBJECTARRAY_RVA,
           sample_size: int = DEFAULT_I02_SAMPLE_SIZE,
           poll_interval_seconds: float = DEFAULT_I02_POLL_INTERVAL_SECONDS,
           max_scan_indices: int = DEFAULT_I02_MAX_SCAN_INDICES,
           sleep_fn=time.sleep) -> dict:
    """The whole of capability I-02: verify the RF-05 GUObjectArray candidate
    against LIVE structural behaviour, implementing exactly the three checks
    research/evidence/RF-05/README.md's own "What a runtime observation would
    need to show to move this above HYPOTHESIS" section names (its 4th item,
    cross-checking FName via RF-06, is explicitly out of scope for I-02 --
    that is I-03's job).

    *base_address*/*image_size_bytes* MUST be from THIS SAME session's own
    run_i01() read, never cached from a previous session -- ASLR means the
    live base address changes on every process launch (see
    rva_to_live_va()'s own docstring); using a stale base_address here would
    silently compute the wrong live VA and either read garbage or read a
    different build launched at a coincidentally similar address.

    Never raises for a candidate that fails one, two, or all three checks --
    that is a valid, reportable REFUTATION (see the module docstring's
    "STRUCTURAL REFUTATION IS A RESULT, NOT AN ERROR" section). DOES let
    ReadProcessMemoryFailedError propagate for the handful of foundational
    reads this function cannot proceed without at all (the two NumElements
    reads, MaxElements, and the Objects pointer): a hard failure or partial
    read on one of THOSE is the tool being unable to attempt the check, not a
    structural finding about the candidate. Per-sample reads inside the walk
    (check 2) are a different matter and are handled inside
    sample_walk_objects() itself, never raised out of this function.

    Returns a plain dict: {"guobjectarray_rva", "guobjectarray_rva_hex",
    "guobjectarray_live_va", "guobjectarray_live_va_hex",
    "check_struct_invariants", "check_sample_walk",
    "check_growth_non_decreasing", "structurally_consistent"} -- three
    per-check sub-dicts, each carrying its own "pass" boolean and reasoning,
    plus one collapsed "structurally_consistent" verdict that is true iff ALL
    THREE individually pass (plan.md's own grading discipline: a record must
    not average distinct findings into one number, so every per-check
    boolean is kept alongside the collapsed one, never replaced by it).
    """
    guobjectarray_va = rva_to_live_va(base_address, guobjectarray_rva)

    # Check (1): NumElements/MaxElements plausibility -- also produces the
    # FIRST of the two NumElements reads check (3) needs.
    num_elements_first = _read_i32(
        api, process_handle, guobjectarray_va + GUOBJECTARRAY_OFFSET_NUM_ELEMENTS)
    max_elements = _read_i32(
        api, process_handle, guobjectarray_va + GUOBJECTARRAY_OFFSET_MAX_ELEMENTS)
    check_struct_invariants = evaluate_struct_invariants(num_elements_first, max_elements)

    # Check (2): sample walk, attempted regardless of whether check (1)
    # passed -- an independent structural signal in its own right, and the
    # walk itself is safe (bounded) even against an implausible count.
    objects_ptr = _read_u64(
        api, process_handle, guobjectarray_va + GUOBJECTARRAY_OFFSET_OBJECTS)
    check_sample_walk = sample_walk_objects(
        api, process_handle, objects_ptr, num_elements_first, base_address,
        image_size_bytes, sample_size=sample_size, max_scan_indices=max_scan_indices)

    # Check (3): two NumElements reads, separated in time, must be
    # non-decreasing -- RF-05/README.md's own pass criterion is
    # "non-decreasing", NOT "increased": a static menu with no gameplay
    # activity legitimately does not grow NumElements in a short poll
    # window, and that must not be misreported as a refutation.
    sleep_fn(poll_interval_seconds)
    num_elements_second = _read_i32(
        api, process_handle, guobjectarray_va + GUOBJECTARRAY_OFFSET_NUM_ELEMENTS)
    non_decreasing = num_elements_second >= num_elements_first
    check_growth_non_decreasing = {
        "num_elements_first": num_elements_first,
        "num_elements_second": num_elements_second,
        "poll_interval_seconds": poll_interval_seconds,
        "non_decreasing": non_decreasing,
        "pass": non_decreasing,
    }

    structurally_consistent = (
        check_struct_invariants["pass"]
        and check_sample_walk["pass"]
        and check_growth_non_decreasing["pass"])

    return {
        "guobjectarray_rva": guobjectarray_rva,
        "guobjectarray_rva_hex": "0x%x" % guobjectarray_rva,
        "guobjectarray_live_va": guobjectarray_va,
        "guobjectarray_live_va_hex": "0x%x" % guobjectarray_va,
        "check_struct_invariants": check_struct_invariants,
        "check_sample_walk": check_sample_walk,
        "check_growth_non_decreasing": check_growth_non_decreasing,
        "structurally_consistent": structurally_consistent,
        # Exposed so a later capability in THIS SAME run (I-03's own
        # "/Script/MISERY live reflection" probe, sample_object_names()
        # below) can reuse the objects pointer and NumElements THIS check
        # already fetched, rather than re-reading them a second time --
        # "reuse I-02's sampling, do not re-walk the array from scratch" per
        # the task that specified this reuse. Neither field is copied into
        # build_i02_document()'s own output (that function only ever copies
        # the specific named fields it always has -- see its own docstring),
        # so adding these here is backward compatible with every existing
        # caller/test that builds a run_i02()-shaped dict by hand.
        "objects_ptr_live_va": objects_ptr,
        "num_elements": num_elements_first,
    }


# --------------------------------------------------------------------------- #
# I-03: resolve an FName (an FNameEntryId) to its string text by reading
# FNamePool's own internal block table directly -- plan.md 8.2, RF-06's
# candidate (research/evidence/RF-06/README.md). See the module docstring's
# "WHAT I-03 IS" section for the full reasoning; this section implements it.
# --------------------------------------------------------------------------- #

# FNamePool/bNamePoolInitialized candidates: research/evidence/RF-06/README.md,
# static VAs 0x1479c2180 / 0x147995e5e against declared PE ImageBase
# 0x140000000 -> RVAs 0x079c2180 / 0x07995e5e. HYPOTHESIS, class I, oracle
# binary-analysis, confidence 0.60 (RF-06's own grade, slightly below RF-05's
# 0.65 -- see that README's "Grade" section for why). Both live in the
# module's own .data section (RF-06/README.md's own "Attempt to refute"
# section), so, like the GUObjectArray candidate, the live VA is
# rva_to_live_va(base_address, rva) -- THIS session's own I-01 base_address,
# never a cached one (ASLR).
DEFAULT_NAMEPOOL_RVA = 0x079C2180
DEFAULT_NAME_POOL_INITIALIZED_RVA = 0x07995E5E

# FNameEntryAllocator::Blocks[FNameMaxBlocks] offset within NamePoolData/
# FNamePool -- RF-06/README.md's own disassembly-confirmed `+0x10` (both
# checked callers dereference `*(puVar15 + Block*8 + 0x10)`), matching
# source: FNameEntryAllocator is FNamePool's own first member
# (UnrealNames.cpp:1514+), but Blocks[FNameMaxBlocks] is FNameEntryAllocator's
# own LAST declared member (source line 697), preceded by
# `mutable FRWLock Lock; uint32 CurrentBlock; uint32 CurrentByteCursor;`
# (UnrealNames.cpp:694-696) -- Lock is a single 8-byte SRWLOCK wrapper (no
# vtable), so Lock(8B) + CurrentBlock(4B) + CurrentByteCursor(4B) = 0x10 bytes
# precede Blocks[], exactly matching this constant. This also matches the
# `InitializeSRWLock(param_1)` RF-06's own decompile of the constructor shows
# as the very first instruction, before the `memset` that zeroes Blocks[].
NAMEPOOL_OFFSET_BLOCKS = 0x10

# FNameEntryHandle/FNameEntryAllocator addressing (UnrealNames.cpp:235,
# "FNameBlockOffsetBits = 16", cited in RF-06/README.md): Block = id>>16,
# Offset = id&0xFFFF, both confirmed a second, independent way in RF-06's own
# two checked callers ("(Block>>16 or param>>0x10) * 8" / "(Offset&0xFFFF)*2").
FNAME_BLOCK_OFFSET_BITS = 16

# FNameEntryAllocator::Stride (UnrealNames.cpp:443, "enum { Stride =
# alignof(FNameEntry) }") -- the per-entry stride Offset is scaled by to
# reach an FNameEntry's own address within a block. RF-06/README.md's own
# callers independently confirm this as the `*2` in `(Offset&0xFFFF)*2`.
FNAME_ENTRY_STRIDE = 2

# sizeof(FNameEntryHeader) (NameTypes.h) -- character data begins exactly
# this many bytes after an FNameEntry's own address, because this build's
# WITH_CASE_PRESERVING_NAME=0 (RF-06's own disassembly-confirmed build-config
# fact: the 256-shard constructor loop matches the #else/non-case-preserving
# branch) compiles OUT FNameEntry's leading ComparisonId field, leaving
# Header as FNameEntry's own first (and only, before the character union)
# member.
FNAME_ENTRY_HEADER_SIZE_BYTES = 2

# FNameEntryHeader's bit layout (NameTypes.h, WITH_CASE_PRESERVING_NAME==0
# branch, read from the actual header file, not assumed from the plan/task
# prompt -- see the module docstring's "WHAT I-03 IS" section):
#     uint16 bIsWide : 1;
#     uint16 LowercaseProbeHash : 5;
#     uint16 Len : 10;
# packed into ONE uint16. MSVC (this build's compiler -- plan.md A-06)
# allocates successive bitfields of a shared underlying type starting from
# the LEAST significant bit, in declaration order: bit 0 is bIsWide, bits
# 1-5 are LowercaseProbeHash, bits 6-15 are Len. This is confirmed, not
# merely assumed, by decode_fname_entry_id() actually decoding FNameEntryId
# 0 to the literal text "None" against a live process (RF-06/README.md's own
# prescribed confirmation step) -- see run_i03()'s own docstring and
# tests/test_eri_i03.py's synthetic id=0 round-trip test, which pins this
# exact bit order independent of any live process. If a future build instead
# uses WITH_CASE_PRESERVING_NAME=1 (this one does not -- confirmed by RF-06),
# the header shape changes to bIsWide:1 + Len:15 and these constants would
# need updating; this file makes no attempt to auto-detect that.
FNAME_HEADER_IS_WIDE_MASK = 0x1
FNAME_HEADER_LEN_SHIFT = 6
FNAME_HEADER_LEN_MASK = 0x3FF  # 10 bits -- naturally bounds Len to 0..1023,
# so a garbage/corrupted header can never make decode_fname_entry_id() below
# attempt an unbounded read: the field WIDTH itself, not a runtime check, is
# what keeps the character-data read small even against a completely wrong
# candidate address.

# UObjectBase's own NamePrivate.ComparisonIndex (FName's first 4 bytes, the
# FNameEntryId component -- NOT the trailing Number suffix) byte offset,
# derived from Engine/Source/Runtime/CoreUObject/Public/UObject/UObjectBase.h
# 's own member declaration order (read in full, not assumed):
#     +0x00  vtable pointer (8B)      -- UObjectBase declares a virtual
#                                         destructor; RF-05/README.md's own
#                                         disassembly of the dtor at
#                                         0x1412c1e40 independently confirms
#                                         this: it begins by writing a vtable
#                                         pointer, "standard C++ dtor-chain
#                                         codegen".
#     +0x08  EObjectFlags ObjectFlags (4B)
#     +0x0C  int32 InternalIndex      (4B)  <- CROSS-CHECK: RF-05/README.md's
#                                              OWN disassembly of the same
#                                              destructor independently found
#                                              "Object->InternalIndex, offset
#                                              0xc" (quoted verbatim). This
#                                              source-order derivation lands
#                                              on the SAME +0xc with no
#                                              adjustment needed -- the two
#                                              independent methods (read the
#                                              header; read the disassembly)
#                                              agree, which is the whole
#                                              point of doing both.
#     +0x10  ClassPrivate (TNonAccessTrackedObjectPtr<UClass>, 8B -- an
#            FObjectPtr wrapping FObjectHandle, which is EITHER a plain
#            UObject* (UE_WITH_OBJECT_HANDLE_LATE_RESOLVE off) or a single
#            UPTRINT-sized packed ref (...on) -- 8 bytes either way; see
#            ObjectHandle.h)
#     +0x18  NamePrivate (FName, 8B: ComparisonIndex (FNameEntryId, 4B) at
#            +0x18 itself, then Number (uint32, 4B) at +0x1C -- NameTypes.h's
#            own static_assert(STRUCT_OFFSET(FName, ComparisonIndex) == 0)
#            confirms ComparisonIndex is FName's own first member)
#     +0x20  OuterPrivate (8B) -- UE_STORE_OBJECT_LIST_INTERNAL_INDEX (which
#            would insert an extra int32 ObjectListInternalIndex between
#            NamePrivate and OuterPrivate) defaults OFF and nothing in this
#            build's evidence suggests it is compiled on, so nothing is
#            inserted here.
# No padding is needed anywhere in this layout: every field up to +0x10 is
# 4-byte, +0x10/+0x18/+0x20 are all naturally 8-/4-byte aligned already, so
# the byte offsets above are exact, not merely "close enough".
DEFAULT_NAME_PRIVATE_OFFSET = 0x18

# sample_object_names()'s own default sample size -- deliberately larger
# than I-02's own DEFAULT_I02_SAMPLE_SIZE (32). I-02's sample only needs
# enough objects to judge vtable plausibility, a STATISTICAL question (32 is
# already generous for that). This probe is instead a NEEDLE search for one
# SPECIFIC object (the "MISERY" UPackage) among what is likely tens of
# thousands of live UObjects in a running game, so a larger bound buys a
# meaningfully better -- though, per the task that specified this probe,
# still explicitly NOT exhaustive -- chance of that one object happening to
# land in the sample. Chosen as a bound, not tuned against a real process
# (no live process was used to pick this number); a future run against the
# real game may want to raise --i03-reflection-sample-size further if this
# default misses.
DEFAULT_I03_REFLECTION_SAMPLE_SIZE = 512

# The literal FName text this probe searches for by default.
#
# CORRECTED 2026-08-27, after the first live run (research/instrument-runs/
# 2026-08-27T145831Z-fullscan/i03-fnamepool.json): the assumption this
# constant originally encoded -- that a UPackage object's own NamePrivate
# holds only its leaf name ("MISERY"), with the full "/Script/MISERY" path
# requiring a separate walk of the Outer chain -- was WRONG. The live decode
# showed every engine/game UPackage's own NamePrivate holds its FULL
# "/Script/<Module>" path directly (e.g. "/Script/CoreUObject",
# "/Script/Engine", and this build's own "/Script/MISERY" -- found verbatim
# in the decoded_names list of that run, without any Outer-chain walk).
# Searching for the bare leaf "MISERY" therefore returned misery_found=False
# even though the package WAS present in the very same sample -- a real
# false negative from an untested assumption, not a tool defect; the probe's
# own decoded_names list (which records everything decoded, regardless of
# what target_name was searched for) is what caught it. Kept as a plain
# constant, not re-verified against every other object kind (a
# non-UPackage UObject's NamePrivate may still be a bare leaf name -- this
# correction is specific to what was actually observed, package objects).
MISERY_PACKAGE_TARGET_NAME = "/Script/MISERY"


def decode_fname_entry_id(api, handle: int, namepool_live_va: int,
                          name_entry_id: int) -> dict:
    """Decode a single FNameEntryId to its string text, per RF-06/README.md's
    own recovered arithmetic:

        Block  = name_entry_id >> FNAME_BLOCK_OFFSET_BITS
        Offset = name_entry_id & 0xFFFF
        block_base = read_u64(namepool_live_va + NAMEPOOL_OFFSET_BLOCKS + Block*8)
        entry_ptr  = block_base + Offset * FNAME_ENTRY_STRIDE
        header     = read_u16(entry_ptr)                    # FNameEntryHeader
        (bIsWide, Len) decoded from header per the bit layout documented
        above FNAME_HEADER_IS_WIDE_MASK
        character data begins at entry_ptr + FNAME_ENTRY_HEADER_SIZE_BYTES,
        Len characters, ANSI (1B/char) if not bIsWide else UTF-16LE (2B/char)

    Lets ReadProcessMemoryFailedError propagate from the block-pointer read
    and the header read -- both are FOUNDATIONAL to attempting this decode
    at all (see the module docstring's "STRUCTURAL REFUTATION IS A RESULT,
    NOT AN ERROR" section: a hard read failure here means the tool could not
    even ATTEMPT the check, never a finding about the candidate). The
    character-data read (once Len/bIsWide are known) is likewise allowed to
    propagate for the same reason -- Len is bounded to 0..1023 by the field
    width itself (FNAME_HEADER_LEN_MASK), so even a garbage header cannot
    turn this into a large or unbounded read.

    Does NOT raise for a successfully-read-but-undecodable byte sequence (an
    ANSI/UTF-16LE decode error) -- that is exactly the "decoded garbage
    instead of a real name" refutation case RF-06/README.md's own
    confirmation step anticipates failing loudly about; it is reported
    honestly in the returned dict ('text': None, 'decode_error': the
    UnicodeDecodeError's own message, 'raw_bytes_hex': every byte actually
    read) rather than raised, so a caller (run_i03(), or a human reading the
    output JSON) can see exactly what was read even when it doesn't decode.

    Returns a plain dict: {'block', 'offset', 'block_base_hex',
    'entry_ptr_hex', 'header_u16_hex', 'is_wide', 'length', 'raw_bytes_hex',
    'text' (str, or None if length==0 was never true but decode failed),
    'decode_error' (None on success)}. A genuinely zero-length name decodes
    to 'text': "" (an empty string is not itself evidence of anything wrong
    -- FNameEntry supports it), which is why 'text' is None ONLY on an
    actual decode error, never conflated with "empty".
    """
    block = name_entry_id >> FNAME_BLOCK_OFFSET_BITS
    offset = name_entry_id & 0xFFFF
    block_base = _read_u64(api, handle, namepool_live_va + NAMEPOOL_OFFSET_BLOCKS + block * 8)
    entry_ptr = block_base + offset * FNAME_ENTRY_STRIDE
    header_u16 = _read_u16(api, handle, entry_ptr)
    is_wide = bool(header_u16 & FNAME_HEADER_IS_WIDE_MASK)
    length = (header_u16 >> FNAME_HEADER_LEN_SHIFT) & FNAME_HEADER_LEN_MASK

    text = ""
    decode_error = None
    raw_bytes = b""
    if length > 0:
        byte_len = length * (2 if is_wide else 1)
        raw_bytes = api.read_process_memory(
            handle, entry_ptr + FNAME_ENTRY_HEADER_SIZE_BYTES, byte_len)
        try:
            text = raw_bytes.decode("utf-16-le") if is_wide else raw_bytes.decode("ascii")
        except UnicodeDecodeError as error:
            text = None
            decode_error = str(error)

    return {
        "block": block,
        "offset": offset,
        "block_base_hex": "0x%x" % block_base,
        "entry_ptr_hex": "0x%x" % entry_ptr,
        "header_u16_hex": "0x%04x" % header_u16,
        "is_wide": is_wide,
        "length": length,
        "raw_bytes_hex": raw_bytes.hex(),
        "text": text,
        "decode_error": decode_error,
    }


def run_i03(api, process_handle: int, base_address: int, image_size_bytes: int,
           namepool_rva: int = DEFAULT_NAMEPOOL_RVA,
           name_pool_initialized_rva: int = DEFAULT_NAME_POOL_INITIALIZED_RVA,
           name_entry_id: int = 0) -> dict:
    """The whole of capability I-03's own FNameEntryId decode, implementing
    the first two of RF-06/README.md's own "What a runtime observation would
    need to show to move this above HYPOTHESIS" steps (the third, the
    "/Script/MISERY" cross-check against a live UObject found via I-02, is
    sample_object_names() below, run separately by main() since it also
    needs I-02's own objects_ptr/num_elements):

      1. Read bNamePoolInitialized; report honestly (never assume) whether
         it is nonzero.
      2. If it IS nonzero, decode *name_entry_id* via decode_fname_entry_id()
         above. When *name_entry_id* == 0 (EName::None, the one case with a
         KNOWN expected answer -- source: UnrealNames.cpp's own REGISTER_NAME
         loop registers it first, per RF-06/README.md), also set
         'decoded_as_expected' to whether the decoded text is exactly "None"
         -- RF-06/README.md's own prescribed confirmation, verbatim.

    *base_address*/*image_size_bytes* MUST be from THIS SAME session's own
    run_i01() read, never cached (ASLR) -- identical requirement to
    run_i02()'s own, for the identical reason (rva_to_live_va()'s own
    docstring). *image_size_bytes* is accepted but not itself used by this
    function's own reads (both RF-06 candidates are read directly by their
    live VA, with no bounds check against the image needed for the decode
    arithmetic itself); it is kept as a parameter for signature symmetry
    with run_i02() and because a future strengthening of this check (an
    "is namepool_live_va inside the module's own mapped image" plausibility
    signal, mirroring I-02's own vtable-in-range check) would need it and
    should not have to change every call site to add it later.

    If bNamePoolInitialized reads as ZERO, this function does NOT attempt
    the decode at all (there would be nothing valid to read yet) -- it
    returns with 'pool_initialized': False and 'decoded'/'decoded_as_expected'
    both None, reported honestly rather than assumed-initialized. This
    should not happen for a running game observed well past its earliest
    bootstrap (RF-06/README.md's own expectation: "true almost immediately
    after process start"), but it is a real possible reading, not an error.

    Never raises for a decode that does not match the expected "None" text
    -- see the module docstring's "STRUCTURAL REFUTATION IS A RESULT, NOT AN
    ERROR" section: that is a valid, reportable refutation of the RF-06
    candidate or the bit-layout assumption, returned as data
    ('decoded_as_expected': False, plus every byte decode_fname_entry_id()
    actually read, for a human to diagnose). DOES let
    ReadProcessMemoryFailedError propagate from the bNamePoolInitialized read
    and from decode_fname_entry_id()'s own foundational reads -- a hard
    Win32 failure there means this capability could not even ATTEMPT the
    check, the same distinction run_i02() draws for its own foundational
    reads.

    Returns a plain dict: {'namepool_rva'/'namepool_rva_hex',
    'namepool_live_va'/'namepool_live_va_hex',
    'name_pool_initialized_rva'/'..._hex',
    'name_pool_initialized_live_va'/'..._hex', 'pool_initialized',
    'name_entry_id', 'decoded' (decode_fname_entry_id()'s own dict, or None
    if the pool was not initialized), 'decoded_as_expected' (bool, or None
    when name_entry_id != 0 -- there is no known expected answer to compare
    against for any other id, or when the pool was not initialized)}.
    """
    namepool_va = rva_to_live_va(base_address, namepool_rva)
    name_pool_initialized_va = rva_to_live_va(base_address, name_pool_initialized_rva)

    initialized_byte = api.read_process_memory(process_handle, name_pool_initialized_va, 1)
    pool_initialized = bool(initialized_byte[0])

    decoded = None
    decoded_as_expected = None
    if pool_initialized:
        decoded = decode_fname_entry_id(api, process_handle, namepool_va, name_entry_id)
        if name_entry_id == 0:
            decoded_as_expected = (decoded["text"] == "None")

    return {
        "namepool_rva": namepool_rva,
        "namepool_rva_hex": "0x%x" % namepool_rva,
        "namepool_live_va": namepool_va,
        "namepool_live_va_hex": "0x%x" % namepool_va,
        "name_pool_initialized_rva": name_pool_initialized_rva,
        "name_pool_initialized_rva_hex": "0x%x" % name_pool_initialized_rva,
        "name_pool_initialized_live_va": name_pool_initialized_va,
        "name_pool_initialized_live_va_hex": "0x%x" % name_pool_initialized_va,
        "pool_initialized": pool_initialized,
        "name_entry_id": name_entry_id,
        "decoded": decoded,
        "decoded_as_expected": decoded_as_expected,
    }


def sample_object_names(api, handle: int, objects_ptr: int, num_elements: int,
                        namepool_live_va: int, name_private_offset: int,
                        sample_size: int = DEFAULT_I03_REFLECTION_SAMPLE_SIZE,
                        max_scan_indices: int = DEFAULT_I02_MAX_SCAN_INDICES,
                        target_name: str = MISERY_PACKAGE_TARGET_NAME) -> dict:
    """The operator's own stated next milestone after I-02+I-03 land: a
    "/Script/MISERY live reflection" attempt -- a BOUNDED, honestly-reported
    search for the literal leaf FName "MISERY" (a UPackage object's own Name,
    NOT the full "/Script/MISERY" path -- building a full path means walking
    the Outer chain, explicitly out of scope here) among a sample of live
    UObject pointers.

    Reuses _locate_object_pointer() -- the SAME shift-16/mask-0xFFFF/
    stride-24 chunk-addressing arithmetic I-02's own sample_walk_objects
    uses to find populated FUObjectItem.Object slots -- rather than
    re-deriving the walk a second time ("reuse I-02's sampling, do not
    re-walk the array from scratch", per the task that specified this
    probe). For each located object, reads its own
    NamePrivate.ComparisonIndex (the FNameEntryId, 4 bytes, at
    *name_private_offset* bytes into the object -- see
    DEFAULT_NAME_PRIVATE_OFFSET's own comment for how that offset was
    derived from UObjectBase.h and cross-checked against RF-05's own
    independently-found InternalIndex==+0xc) and decodes it via
    decode_fname_entry_id().

    HONESTY, EXPLICIT (this is load-bearing, not a footnote -- per the task
    that specified this probe): this is a PLAUSIBLE, NOT EXHAUSTIVE search.
    The live UObject universe for a running UE game is likely tens of
    thousands of objects; a bounded sample of at most *sample_size* objects,
    scanned starting from index 0, may simply never reach the one UPackage
    object named "MISERY" even if every single piece of the apparatus this
    probe depends on (the RF-05 GUObjectArray candidate, the RF-06 FNamePool
    candidate, the decode arithmetic, the NamePrivate offset) is completely
    correct. A negative result ('misery_found': False) is therefore NEVER
    itself evidence against any of those things -- it means only "not found
    in the objects this particular bounded sample happened to examine". The
    returned dict states this in its own 'note' field, in the output data
    itself, so a downstream reader of the JSON never has to reconstruct this
    caveat from this docstring alone.

    A read failure LOCATING a slot (chunk pointer, Object field -- inside
    _locate_object_pointer()) is skipped, identically to
    sample_walk_objects()'s own "unreadable is like null" handling: it is a
    scanning concern, not a probe result. A read failure reading an
    ALREADY-located object's own NamePrivate field, or anywhere inside
    decode_fname_entry_id() for an object already committed to the sample,
    is counted as one decode failure and skipped, never allowed to abort the
    whole probe -- a torn read during a concurrent GC pass is exactly as
    plausible here as it is for I-02's own vtable read.

    Returns a plain dict: {'sample_size_requested', 'max_scan_indices',
    'indices_scanned', 'objects_examined', 'decode_failures',
    'decoded_names' (every name text this run actually decoded, in the ORDER
    found, duplicates included -- deliberately not deduplicated or filtered,
    so a human reader can judge overall plausibility: real UE object/class
    names, garbage, or a mix -- from the full list, not a single boolean),
    'target_name', 'misery_found' (bool: target_name in decoded_names),
    'note' (the bounded-sample honesty caveat above, restated in the output
    itself)}.
    """
    scan_limit = max_scan_indices if num_elements <= 0 else min(num_elements, max_scan_indices)
    index = 0
    scanned = 0
    examined = 0
    decode_failures = 0
    decoded_names: list = []

    while index < scan_limit and examined < sample_size:
        scanned += 1
        try:
            object_ptr = _locate_object_pointer(api, handle, objects_ptr, index)
        except ReadProcessMemoryFailedError:
            index += 1
            continue  # unreadable slot -- a scanning concern, not a sample.

        if object_ptr is None:
            index += 1
            continue  # a freed/never-allocated slot, or an unallocated chunk.

        examined += 1
        try:
            name_entry_id = _read_u32(api, handle, object_ptr + name_private_offset)
            decoded = decode_fname_entry_id(api, handle, namepool_live_va, name_entry_id)
        except ReadProcessMemoryFailedError:
            decode_failures += 1
            index += 1
            continue  # a torn read on an already-committed sample.

        if decoded["text"] is None:
            decode_failures += 1
        else:
            decoded_names.append(decoded["text"])
        index += 1

    misery_found = target_name in decoded_names
    return {
        "sample_size_requested": sample_size,
        "max_scan_indices": max_scan_indices,
        "indices_scanned": scanned,
        "objects_examined": examined,
        "decode_failures": decode_failures,
        "decoded_names": decoded_names,
        "target_name": target_name,
        "misery_found": misery_found,
        "note": (
            "bounded, NOT exhaustive sample: %d live object(s) were actually "
            "examined (sample_size_requested=%d, indices_scanned=%d of "
            "max_scan_indices=%d) -- misery_found=False means the target "
            "name was not among THOSE objects, never proof it is absent "
            "from the live process as a whole; see sample_object_names()'s "
            "own docstring." % (examined, sample_size, scanned, max_scan_indices)),
    }


# --------------------------------------------------------------------------- #
# I-04: dump UClass instances with their inheritance-adjacent identity
# (plan.md 8.2 item 8.2, "Дамп UClass с иерархией наследования") -- the
# first real UObject/UClass TRAVERSAL, not a bounded sample. See the module
# docstring's "WHAT I-04 IS" section for the full algorithm and its
# deliberate scope boundary.
# --------------------------------------------------------------------------- #

# UObjectBase field offsets I-04 additionally needs. DEFAULT_NAME_PRIVATE_OFFSET
# (+0x18, I-03's own constant) is REUSED verbatim above -- never redeclared.
#
# +0x10 ClassPrivate: falls straight out of UObjectBase.h's own member
# declaration order (see DEFAULT_NAME_PRIVATE_OFFSET's own comment above for
# the full field-by-field derivation, cross-checked against RF-05's own
# independent disassembly finding InternalIndex==+0xc) -- immediately
# follows InternalIndex (+0x0c, 4 bytes), naturally 8-byte aligned already.
DEFAULT_CLASS_PRIVATE_OFFSET = 0x10

# +0x20 OuterPrivate: the ONE genuinely new offset I-04 introduces, and it
# required zero new guessing -- it falls straight out of two ALREADY-verified
# facts: NamePrivate's own offset (+0x18) and NameTypes.h's own
# static_assert that FName is exactly 8 bytes (STRUCT_OFFSET(FName, Number)
# == 4, sizeof(Number) == 4, i.e. ComparisonIndex(4B)+Number(4B) == 8B) --
# confirmed live this session by I-03's own decode of exactly the +0x18
# ComparisonIndex field. +0x18 + 8 == +0x20.
DEFAULT_OUTER_PRIVATE_OFFSET = 0x20

# The class-identity fixed point's own seed and its cross-check literals --
# see find_uclass_self_reference()/find_blueprint_generated_class_address()
# below and the module docstring's "WHAT I-04 IS" section. Both literal
# object_path strings were directly, live-decoded this session (LOG-0051,
# research/instrument-runs/2026-08-27T145831Z-confirmed/i03-fnamepool.json's
# misery_reflection.decoded_names carries both bare names "Class" and
# "BlueprintGeneratedClass" among its 26 258 decoded entries), so these are
# not invented literals -- they are what this exact live process already
# proved it can decode.
UCLASS_SELF_REFERENCE_NAME = "Class"
UCLASS_SELF_REFERENCE_OBJECT_PATH = "/Script/CoreUObject.Class"
BLUEPRINT_GENERATED_CLASS_NAME = "BlueprintGeneratedClass"
BLUEPRINT_GENERATED_CLASS_OBJECT_PATH = "/Script/Engine.BlueprintGeneratedClass"

# The GENERAL name-suffix test find_meta_type_roots() and run_i04()'s own
# per-object is_blueprint_generated classification both use, chosen instead
# of hardcoding "BlueprintGeneratedClass" as the only recognized meta-type
# name -- see find_meta_type_roots()'s own docstring for why: real UE 5.4
# ships more than one native subclass playing this exact role
# (UWidgetBlueprintGeneratedClass, UAnimBlueprintGeneratedClass), all named
# by this same UE convention, and a fixed enumeration would silently miss
# any of them (a real defect a targeted layout+safety review found and this
# constant/the functions using it fix).
META_TYPE_NAME_SUFFIX = "GeneratedClass"

# Bounds I-04 introduces, all overridable via their own CLI flag (see
# build_arg_parser() below) -- never a second hardcoded copy of any of them.
DEFAULT_I04_MAX_OUTER_DEPTH = 16
DEFAULT_I04_MAX_FIXED_POINT_PASSES = 8
DEFAULT_I04_GAME_SAMPLE_CAP = 25


def _pointer_is_plausible(address: int) -> bool:
    """Cheap, universal plausibility check for any CANDIDATE POINTER I-04
    considers reading (an object's own address, its ClassPrivate, its
    OuterPrivate): non-null and 8-byte aligned, since every UObject
    allocation is pointer-aligned. Deliberately does NOT check the value
    against the module's own image range -- that check is for a
    VTABLE-POINTER-shaped value only (_vtable_pointer_in_module_range
    above), because an object/Class/Outer address is heap-allocated and
    legitimately falls OUTSIDE the module image; conflating the two checks
    would reject every real object address I-04 is meant to examine.
    """
    return address != 0 and address % 8 == 0


def _classify_object(api, handle: int, object_ptr: int, *, base_address: int,
                     image_size_bytes: int, namepool_live_va: int,
                     class_private_offset: int, name_private_offset: int,
                     outer_private_offset: int) -> dict:
    """Read and validate ONE already-located candidate UObject's identity
    fields -- the module docstring's I-04 "structural validation" checks
    1-3, exactly. NEVER raises ReadProcessMemoryFailedError: every read here
    is on an object *_locate_object_pointer* already found non-null, so any
    read failure encountered while examining ITS OWN fields is a TORN read
    on an already-committed candidate -- the SAME "torn read during
    concurrent GC" treatment sample_walk_objects()'s own vtable read and
    sample_object_names()'s own NamePrivate read already establish (their
    own docstrings), never a propagated tool error. A hard/partial
    ReadProcessMemory failure while merely LOCATING a candidate (the chunk
    pointer, the FUObjectItem.Object field) is a walk_object_universe()
    concern, not this function's -- this function is only ever called with
    a non-null object_ptr walk_object_universe() already located.

    Returns a dict, ALWAYS shaped the same way regardless of which check
    failed (so callers -- objects_by_address, resolve_object_path -- never
    need to special-case a missing key): {'valid' (bool, True iff checks 1-3
    ALL passed), 'rejection_kind' (one of 'pointer_alignment',
    'read_failure', 'name_decode', 'class_pointer_implausible', or None when
    valid), 'rejection_reason' (human text, or None), 'name_text' (str or
    None), 'name_ok' (bool -- True iff the object's OWN address was
    plausible AND its FName decoded without error, REGARDLESS of whether
    ClassPrivate itself later failed check 3 -- this is deliberately weaker
    than 'valid', because object_path construction (check 4/5) only ever
    needs an ancestor's name, never its own class-pointer plausibility; see
    resolve_object_path()'s own docstring), 'class_ptr' (int or None -- only
    ever set when 'valid' is True), 'outer_ptr' (int, 0 for 'no Outer', or
    None only when name_ok is False and no read was ever attempted),
    'outer_ok' (bool -- True iff outer_ptr is 0/null OR passed the same
    plausibility check as any other candidate pointer; a False outer_ok
    does NOT itself invalidate the object's own basic identity, only its
    own usability as an ANCESTOR in someone else's object_path walk)}.
    """
    record = {
        "valid": False, "rejection_kind": None, "rejection_reason": None,
        "name_text": None, "name_ok": False,
        "class_ptr": None, "outer_ptr": None, "outer_ok": False,
    }

    # Check 1: the object pointer itself must be a plausible candidate
    # BEFORE any read is attempted at all -- a corrupted/misaligned address
    # must never be dereferenced, per the module docstring's structural-
    # validation section.
    if not _pointer_is_plausible(object_ptr):
        record["rejection_kind"] = "pointer_alignment"
        record["rejection_reason"] = (
            "object pointer 0x%x is not a plausible (non-null, 8-byte-"
            "aligned) address" % object_ptr)
        return record

    try:
        name_entry_id = _read_u32(api, handle, object_ptr + name_private_offset)
        decoded = decode_fname_entry_id(api, handle, namepool_live_va, name_entry_id)
        class_ptr = _read_u64(api, handle, object_ptr + class_private_offset)
        outer_ptr = _read_u64(api, handle, object_ptr + outer_private_offset)
    except ReadProcessMemoryFailedError as error:
        record["rejection_kind"] = "read_failure"
        record["rejection_reason"] = (
            "read failure on an already-located object at 0x%x: %s" %
            (object_ptr, error))
        return record

    record["outer_ptr"] = outer_ptr
    record["outer_ok"] = (outer_ptr == 0) or _pointer_is_plausible(outer_ptr)

    # Check 2: a valid FName entry -- decode_fname_entry_id()'s own
    # decode_error must be None. (Len is naturally capped 0..1023 by its own
    # bit width already, per I-03's own FNAME_HEADER_LEN_MASK -- no
    # additional bound needed here.)
    if decoded["decode_error"] is not None:
        record["rejection_kind"] = "name_decode"
        record["rejection_reason"] = (
            "FName decode error at 0x%x: %s" % (object_ptr, decoded["decode_error"]))
        return record

    record["name_text"] = decoded["text"]
    record["name_ok"] = True

    # Check 3: ClassPrivate points to something plausible -- non-null,
    # 8-byte aligned, AND the first 8 bytes at that address look like a
    # vtable pointer inside the module's own image range.
    if not _pointer_is_plausible(class_ptr):
        record["rejection_kind"] = "class_pointer_implausible"
        record["rejection_reason"] = (
            "ClassPrivate 0x%x is not a plausible (non-null, 8-byte-aligned) "
            "address" % class_ptr)
        return record

    try:
        class_vtable = _read_u64(api, handle, class_ptr)
    except ReadProcessMemoryFailedError as error:
        record["rejection_kind"] = "read_failure"
        record["rejection_reason"] = (
            "read failure on ClassPrivate 0x%x's own vtable pointer: %s" %
            (class_ptr, error))
        return record

    if not _vtable_pointer_in_module_range(class_vtable, base_address, image_size_bytes):
        record["rejection_kind"] = "class_pointer_implausible"
        record["rejection_reason"] = (
            "ClassPrivate 0x%x's own vtable pointer 0x%x is outside the "
            "module image range [0x%x, 0x%x)" %
            (class_ptr, class_vtable, base_address, base_address + image_size_bytes))
        return record

    record["valid"] = True
    record["class_ptr"] = class_ptr
    return record


def walk_object_universe(api, handle: int, objects_ptr: int, num_elements: int,
                         base_address: int, image_size_bytes: int,
                         namepool_live_va: int,
                         class_private_offset: int = DEFAULT_CLASS_PRIVATE_OFFSET,
                         name_private_offset: int = DEFAULT_NAME_PRIVATE_OFFSET,
                         outer_private_offset: int = DEFAULT_OUTER_PRIVATE_OFFSET,
                         max_scan_indices: int = DEFAULT_I02_MAX_SCAN_INDICES) -> dict:
    """Walks EVERY located index (bounded only by *max_scan_indices*, a
    safety cap against a corrupted/implausibly huge NumElements -- NOT a
    statistical sample size like I-02/I-03's own bounded probes; I-04 IS the
    first real traversal, see the module docstring's "WHAT I-04 IS"
    section), locating each non-null object via _locate_object_pointer()
    (I-02's own chunk-walk arithmetic, reused verbatim -- never re-derived)
    and validating/decoding it via _classify_object() above.

    A read failure while merely LOCATING a slot (chunk pointer, the
    FUObjectItem.Object field) is skipped, identically to I-02's own
    sample_walk_objects()/I-03's own sample_object_names() -- a scanning
    concern, not a census entry; never raised, never counted against
    'objects_located'.

    Returns {'objects_by_address': dict[int, dict] (every LOCATED object's
    own _classify_object() record, keyed by its own address -- this is what
    resolve_object_path() below walks the Outer chain through, purely via
    dict lookups, without any further memory read: the SAME reads
    _classify_object() already made for every object cover every possible
    Outer target too, since every live object's own index was visited),
    'indices_scanned', 'objects_located' (non-null slots), 'valid_count'
    (checks 1-3 all passed), 'rejected_counts' (dict, one entry per
    _classify_object() 'rejection_kind' value)}.
    """
    scan_limit = max_scan_indices if num_elements <= 0 else min(num_elements, max_scan_indices)
    objects_by_address: dict = {}
    indices_scanned = 0
    objects_located = 0
    valid_count = 0
    rejected_counts = {
        "pointer_alignment": 0, "read_failure": 0,
        "name_decode": 0, "class_pointer_implausible": 0,
    }

    index = 0
    while index < scan_limit:
        indices_scanned += 1
        try:
            object_ptr = _locate_object_pointer(api, handle, objects_ptr, index)
        except ReadProcessMemoryFailedError:
            index += 1
            continue  # unreadable slot -- a scanning concern, not a census entry.
        if object_ptr is None:
            index += 1
            continue  # a freed/never-allocated slot, or an unallocated chunk.

        objects_located += 1
        record = _classify_object(
            api, handle, object_ptr, base_address=base_address,
            image_size_bytes=image_size_bytes, namepool_live_va=namepool_live_va,
            class_private_offset=class_private_offset,
            name_private_offset=name_private_offset,
            outer_private_offset=outer_private_offset)
        objects_by_address[object_ptr] = record
        if record["valid"]:
            valid_count += 1
        else:
            rejected_counts[record["rejection_kind"]] += 1
        index += 1

    return {
        "objects_by_address": objects_by_address,
        "indices_scanned": indices_scanned,
        "objects_located": objects_located,
        "valid_count": valid_count,
        "rejected_counts": rejected_counts,
    }


def resolve_object_path(start_address: int, objects_by_address: dict, *,
                        max_depth: int = DEFAULT_I04_MAX_OUTER_DEPTH) -> dict:
    """Builds *start_address*'s own canonical object_path by walking its
    Outer chain -- start_address -> its Outer -> its Outer's Outer -> ...
    -- purely via dict lookups into *objects_by_address*
    (walk_object_universe()'s own output: every live object this run
    located, keyed by its own address), never a further memory read: the
    object every real Outer pointer can possibly reference was already
    visited by the SAME full-array walk that built this dict, because I-04
    walks every live index, not a bounded sample.

    BOUNDED (max_depth hops, default 16) and CYCLE-PROTECTED (an address
    that repeats within THIS ONE walk is a traversal failure, not an
    infinite loop) -- a corrupted or maliciously-looping Outer chain must
    never be able to hang this function. Exceeding max_depth without
    terminating is likewise reported as a traversal failure, never raised
    and never silently truncated into a plausible-looking wrong answer.

    Algorithm (this session's own confirmed fact, LOG-0051: a UPackage's own
    NamePrivate already holds its FULL "/Script/<Module>" or "/Game/<...>"
    path, never a bare leaf name):
      * Outer == null immediately (a top-level object, typically a
        UPackage): object_path = its own decoded name; package = that same
        name IF it looks like a package (starts with "/"), else None (and
        a note is set -- an unusual, best-effort case, never silently
        assumed fine).
      * Outer non-null, Outer's own Outer null (the common, single-level
        case -- an object owned directly by its package): object_path =
        Outer's decoded name + "." + O's own decoded name, matching real
        UE GetPathName() convention. package = the Outer's own name.

        KNOWN, DELIBERATE CONVENTION MISMATCH against the sibling offline
        record: the already-committed research/reflection/
        misery-24826585-ue5.4.4-0eef3715244b/classes.jsonl (RF-01, a
        DIFFERENT build, 24826585) stores the identical kind of class's
        object_path with a "/" join instead, e.g.
        "/Script/MISERY/MiseryBlueprintFunctionLibrary" (not
        "/Script/MISERY.MiseryBlueprintFunctionLibrary"). This function
        intentionally does NOT match that convention: "." is what real UE
        GetPathName() actually produces (also the exact form
        research/schema/reflection-record.schema.json's own object_path
        field documents as its example, "/Script/MISERY.MiseryCharacter"),
        so runtime-sourced records use "." on purpose. A reader joining or
        matching class records BETWEEN RF-01's classes.jsonl and this
        capability's own classes.jsonl by object_path string will need to
        normalize one convention to the other first (e.g. compare raw_name
        + package instead, both of which agree across the two sources) --
        this is flagged here explicitly rather than silently left for a
        future reader to discover by a failed string match.
      * Deeper nesting (3+ levels): every ancestor from the outermost
        NON-package down to O itself is joined with ":" (the real UE
        subobject delimiter), prefixed by "<package>." -- e.g.
        "/Game/Foo.Bar:Baz". A reasonable, standard approximation; this
        function does not attempt component-path/array-index subtleties
        beyond it.
      * The outermost ancestor is recognized as a package heuristically:
        its decoded name starts with "/" (every package name observed live
        this session started with "/", e.g. "/Script/...", "/Game/...").
        When the walk terminates on an ancestor whose name does NOT start
        with "/", that is unusual: object_path is still built, best-effort,
        but 'ok' is still True and 'note' records the anomaly rather than
        silently assuming it is fine.

    Returns {'object_path' (str or None), 'package' (str or None), 'ok'
    (bool -- False only for an actual traversal FAILURE: cycle, unresolved
    ancestor, or exceeded max_depth -- never False merely for the "unusual
    top-level name" case above, which still produces a best-effort path),
    'note' (str or None -- set for both the failure case and the "unusual"
    best-effort case, so a caller never has to reconstruct the caveat from
    this docstring alone)}.
    """
    chain: list = []
    visited: set = set()
    address = start_address

    for _ in range(max_depth):
        if address in visited:
            return {
                "object_path": None, "package": None, "ok": False,
                "note": "cycle detected in the Outer chain at 0x%x" % address,
            }
        visited.add(address)

        record = objects_by_address.get(address)
        if record is None or not record.get("name_ok"):
            return {
                "object_path": None, "package": None, "ok": False,
                "note": (
                    "Outer chain unresolved: the object at 0x%x was not "
                    "located by this run's own walk, or its own FName "
                    "failed to decode" % address),
            }
        chain.append(record["name_text"])

        outer_ptr = record.get("outer_ptr")
        if outer_ptr in (0, None):
            break  # terminated: this ancestor has no Outer -- top level.
        if not record.get("outer_ok", True):
            return {
                "object_path": None, "package": None, "ok": False,
                "note": (
                    "OuterPrivate of the object at 0x%x is not a plausible "
                    "pointer" % address),
            }
        address = outer_ptr
    else:
        return {
            "object_path": None, "package": None, "ok": False,
            "note": (
                "Outer chain exceeded max depth (%d) without terminating" %
                max_depth),
        }

    top_level = chain[-1]
    looks_like_package = top_level.startswith("/")
    if len(chain) == 1:
        object_path = chain[0]
        package = chain[0] if looks_like_package else None
    else:
        rest = list(reversed(chain[:-1]))  # outermost-non-package ... self
        object_path = top_level + "." + rest[0] + "".join(":" + name for name in rest[1:])
        package = top_level if looks_like_package else None

    note = None if looks_like_package else (
        "outermost ancestor %r does not start with '/' -- unusual; "
        "object_path is best-effort" % top_level)
    return {"object_path": object_path, "package": package, "ok": True, "note": note}


def canonicalize_object_path(path: str | None) -> str | None:
    """Normalizes an object_path's package/name JOIN CHARACTER to the real
    UE GetPathName() convention ("."), so a runtime-sourced record and an
    offline-sourced record naming the SAME object compare equal even when
    they were written with the two different join conventions this project
    has ALREADY produced (see resolve_object_path()'s own "KNOWN, DELIBERATE
    CONVENTION MISMATCH" paragraph above, and this session's own explicit
    request to have this normalizer ready before the next semantic diff --
    NOT to run that diff now).

    The two motivating, this-session-specific example strings, which MUST
    canonicalize to the identical result (pinned by
    tests/test_eri_i06.py):
      * "/Script/MISERY.MiseryFocusSubsystem" -- resolve_object_path()'s own
        runtime output, real GetPathName() convention, ALREADY canonical.
      * "/Script/MISERY/MiseryFocusSubsystem" -- the OLD offline RF-01
        convention already committed verbatim in research/reflection/
        misery-24826585-ue5.4.4-0eef3715244b/classes.jsonl.

    ALGORITHM: find the LAST "/" in *path*. If nothing after it contains a
    ".", this is the OLD slash-joined convention -- replace that last "/"
    with "." (this is the ONE join the old convention gets wrong; every
    "/" before it is a genuine package-path separator, e.g. the "/Script/"
    prefix itself, and is left untouched). Otherwise (a "." already appears
    after the last "/", OR *path* has no "/" at all -- a bare leaf name with
    no package prefix) *path* is returned UNCHANGED: it is either already
    canonical, or has no package/name join to normalize in the first place.

    IDEMPOTENT BY CONSTRUCTION, not merely by coincidence: after the single
    replacement, the character at the position of the former last "/" is
    now ".", so a SECOND call's own rfind("/") -- if any "/" remains at all,
    e.g. the "/Script/" prefix -- lands on an EARLIER "/", after which a "."
    now unavoidably appears (the one this call just inserted, or one already
    there); the "already canonical" branch then returns the string
    unchanged. tests/test_eri_i06.py pins this directly: calling this
    function twice on either example string is a no-op the second time.

    Does NOT mutate, rewrite, or re-normalize any already-committed file --
    this is a plain, pure string function. research/reflection/
    misery-24826585-ue5.4.4-0eef3715244b/classes.jsonl (build-specific,
    already-committed research artifact for build 24826585) is NEVER
    silently rewritten by this or any other function in this file;
    normalization happens only at COMPARISON/diff time, by calling this
    function on a copy of the string being compared, exactly as this
    docstring's own two example strings are compared in the test suite.

    *path* of None returns None unchanged (mirrors every other nullable
    object_path field in this file -- "no path" is not "no join to fix").
    """
    if path is None:
        return None
    last_slash = path.rfind("/")
    if last_slash == -1:
        return path  # no package separator at all -- nothing to normalize.
    after_last_slash = path[last_slash + 1:]
    if "." in after_last_slash:
        return path  # already dot-joined after the last "/" -- canonical already.
    return path[:last_slash] + "." + after_last_slash


def find_uclass_self_reference(objects_by_address: dict, *,
                               path_resolver) -> dict | None:
    """The class-identity fixed point's own SEED: the object whose own
    ClassPrivate address equals its OWN address (UClass::StaticClass()->
    ClassPrivate == itself, a genuine architectural fixed point in real UE
    reflection, not a hack). Cross-checked, never merely trusted because it
    happens to be self-referential: its own decoded name must be
    UCLASS_SELF_REFERENCE_NAME ("Class") AND its own object_path (via
    *path_resolver*, normally resolve_object_path() bound to the SAME
    objects_by_address this candidate came from) must be exactly
    UCLASS_SELF_REFERENCE_OBJECT_PATH ("/Script/CoreUObject.Class") --
    both literal values this session already live-decoded once (LOG-0051),
    not invented here.

    Every self-referential candidate found is examined (not just the
    first) in case a corrupted/implausible object happens to also satisfy
    the bare self-reference test; only one that ALSO cross-checks is ever
    returned. Returns None -- never a guessed/fabricated seed -- when no
    candidate exists at all, or none of the candidates found cross-check.
    That is a hard structural failure for the whole capability: run_i04()
    reports zero UClass instances found rather than build on an unverified
    seed.
    """
    for address, record in objects_by_address.items():
        if not record["valid"] or record["class_ptr"] != address:
            continue
        if record["name_text"] != UCLASS_SELF_REFERENCE_NAME:
            continue
        resolved = path_resolver(address)
        if resolved["ok"] and resolved["object_path"] == UCLASS_SELF_REFERENCE_OBJECT_PATH:
            return {"address": address, "object_path_result": resolved}
    return None


def find_blueprint_generated_class_address(round1_members: set, objects_by_address: dict,
                                           *, path_resolver) -> int | None:
    """Among *round1_members* (every object whose ClassPrivate == the
    seed's own address), find the ONE whose own decoded name is EXACTLY
    BLUEPRINT_GENERATED_CLASS_NAME ("BlueprintGeneratedClass") AND whose own
    object_path (via *path_resolver*) is exactly
    BLUEPRINT_GENERATED_CLASS_OBJECT_PATH ("/Script/Engine.BlueprintGeneratedClass")
    -- the SAME "find it, then verify it, never just trust the name"
    discipline find_uclass_self_reference() applies to the seed itself.
    Returns None, honestly, when no round-1 member cross-checks.

    This is now ONE cross-checked, specifically-verified data point
    (run_i04()'s own blueprint_generated_class_address_hex field) among
    POSSIBLY SEVERAL meta-type roots find_meta_type_roots() discovers more
    generally by name pattern -- see compute_class_identity()'s own
    docstring for why a single hardcoded address is not enough on its own
    to decide is_blueprint_generated for every object.
    """
    for address in round1_members:
        record = objects_by_address[address]
        if record["name_text"] != BLUEPRINT_GENERATED_CLASS_NAME:
            continue
        resolved = path_resolver(address)
        if resolved["ok"] and resolved["object_path"] == BLUEPRINT_GENERATED_CLASS_OBJECT_PATH:
            return address
    return None


def find_meta_type_roots(round1_members: set, objects_by_address: dict) -> dict:
    """Among *round1_members* (every object whose ClassPrivate == the
    seed's own address -- i.e. every native "type descriptor" object:
    "Class" itself, "ScriptStruct", "Function", "Enum",
    "BlueprintGeneratedClass", and every ordinary native UClass like
    MiseryFocusSubsystem), find every one that is ITSELF a "meta-type" --
    a type whose OWN instances are themselves classes, not ordinary
    objects -- by NAME PATTERN: its own decoded name ends with
    "GeneratedClass" (META_TYPE_NAME_SUFFIX).

    WHY A NAME-SUFFIX PATTERN, not a fixed enumeration of specific names:
    real UE 5.4 has more than one native subclass of UBlueprintGeneratedClass
    that plays this exact "class of a Blueprint asset" role --
    UWidgetBlueprintGeneratedClass (Engine/Source/Runtime/UMG/Public/
    Blueprint/WidgetBlueprintGeneratedClass.h) and
    UAnimBlueprintGeneratedClass (Engine/Source/Runtime/Engine/Classes/
    Animation/AnimBlueprintGeneratedClass.h) are both real, distinct
    engine types, both named with the "GeneratedClass" suffix by UE's own
    convention, and this project has no exhaustive, verified list of every
    such type this specific build ships (there could be others this
    session never observed). A name-suffix test generalizes to catch any
    of them -- present, or not yet seen -- WITHOUT hardcoding each one
    individually the way the plain "BlueprintGeneratedClass"-only check
    (find_blueprint_generated_class_address(), still called separately for
    its own specific cross-checked report) originally did.

    WHY THIS STAYS SOUND (does not sweep in ordinary leaf classes like
    MiseryFocusSubsystem or ordinary struct/function descriptors):
    "GeneratedClass" is not a generic word -- it is UE's own, specific
    naming convention for exactly this one architectural role (a class
    whose OWN instances are Blueprint-asset classes), and no ordinary
    native gameplay class this project has observed is named that way.
    This is a real but bounded risk (a native class COULD theoretically be
    named ending in "GeneratedClass" without playing this role) --
    documented, not hidden: every promoted root is still cross-checked by
    compute_class_identity() against round1_members (i.e. its own
    ClassPrivate really is "Class" -- it cannot be an arbitrary /Game
    object, since round1_members is already restricted to that).

    Returns {name_text: address} for every round1_member whose name ends
    with META_TYPE_NAME_SUFFIX -- always includes "BlueprintGeneratedClass"
    itself when present (its own name ends with "GeneratedClass" too), so
    find_blueprint_generated_class_address()'s separate, path-verified
    result is redundant with (and cross-checks) one entry of this dict,
    not a disjoint computation.
    """
    return {
        record["name_text"]: address
        for address, record in ((a, objects_by_address[a]) for a in round1_members)
        if record["name_text"].endswith(META_TYPE_NAME_SUFFIX)
    }


def compute_class_identity(objects_by_address: dict, seed_address: int, *,
                           path_resolver,
                           max_passes: int = DEFAULT_I04_MAX_FIXED_POINT_PASSES) -> dict:
    """The class-identity fixed point. Grows class_address_universe from
    the seed PLUS every discovered "meta-type" root (find_meta_type_roots()
    above), never from "any address already a member of the growing
    universe" in general (see below for why that general rule is wrong).

    CORRECTED 2026-08-27 (twice in the same session -- see git history /
    RESEARCH_LOG.md for both corrections): a targeted layout+safety review
    of the ORIGINAL I-04 pass found that growing from exactly two FIXED
    roots {seed_address, blueprint_generated_class_address} misses
    UWidgetBlueprintGeneratedClass / UAnimBlueprintGeneratedClass instances
    (real, distinct native UE 5.4 types -- see find_meta_type_roots()'s own
    docstring for the source citations) -- on a real UE5 game using UMG
    (almost certainly true of MISERY), that would have silently excluded
    what is likely the LARGEST category of real /Game Blueprint assets. A
    FIRST attempted fix (collapsing to "class_address_universe is simply
    every distinct ClassPrivate value seen, no roots at all") was ALSO
    wrong, caught by this project's own test suite before being trusted:
    it implicitly assumed every genuinely-loaded UClass has at least one
    live INSTANCE pointing at it (e.g. its own CDO) in THIS snapshot,
    which is not the actual definition of "is a UClass" -- a Blueprint
    class ASSET is a UClass because of WHAT IT IS (an instance of
    BlueprintGeneratedClass or a sibling meta-type), not because of
    whether anything else happens to already be an instance OF IT. THIS
    version restores the "grow from known meta-type roots" shape, fixing
    only the actual defect (roots were too narrowly and permanently fixed
    at exactly two), while keeping the meta-type root discovery itself
    GENERAL (name-suffix, not individually hardcoded).

    Round 1: round1_members = {O : O.ClassPrivate == seed_address}.
    class_address_universe = {seed_address} | round1_members. Every native
    "type descriptor" object -- "Class" itself, "ScriptStruct", "Function",
    "Enum", "BlueprintGeneratedClass", "WidgetBlueprintGeneratedClass",
    "AnimBlueprintGeneratedClass" (if this build has it), and every
    ordinary native UClass (MiseryFocusSubsystem, ...) -- is caught here in
    one pass, because ALL of them are native C++ types whose own metaclass
    is literally "Class".

    Root promotion: find_meta_type_roots(round1_members, ...) finds every
    round1_member whose OWN name ends with "GeneratedClass" -- this is a
    SET, not one fixed address, and can be 1, 2, 3+ elements depending on
    what this specific live build actually has loaded. roots =
    {seed_address} | {every discovered meta-type root's address}.

    Round 2+ (bounded, until convergence or *max_passes*, default 8): any
    object whose ClassPrivate is IN roots (a FIXED set, never grown further
    after round 1 -- see "WHY NOT..." below) and not yet in the universe
    joins. This catches real Blueprint class ASSETS under /Game for EVERY
    discovered meta-type (their own metaclass is one of the roots) in one
    or two more passes; normal UE reflection has no deeper nesting than
    this (a Blueprint asset's class is a meta-type; a meta-type's class is
    "Class"; there is no third tier), so convergence at pass 2 or 3 is the
    expected, not merely hoped-for, outcome.

    WHY roots STAYS FIXED after round 1 (never "any address already in the
    universe joins" in general): real UE semantics mean an ORDINARY
    GAMEPLAY INSTANCE of any class already in the universe has its own
    ClassPrivate equal to THAT class's address too -- e.g. a live, ordinary
    UMiseryFocusSubsystem instance's own ClassPrivate IS MiseryFocusSubsystem's
    address, and MiseryFocusSubsystem joins the universe in round 1 (it is
    a native class, found via round1_members). Under a truly general
    closure rule, once MiseryFocusSubsystem is "in the universe", that
    instance's ClassPrivate would ALSO be "a member of the universe",
    wrongly admitting the instance itself as "a UClass" too. Restricting
    growth to the FIXED, verified roots set (never re-derived from the
    growing universe itself) is what keeps this precise -- every
    class_address_universe member beyond round 1 is provably an instance
    of a KNOWN meta-type, never an instance of an ordinary leaf class.

    is_blueprint_generated for a classified object O is decided by
    run_i04() (not here): it resolves what O's OWN ClassPrivate's decoded
    name IS and checks whether that name ends with "GeneratedClass" --
    the SAME name-suffix test find_meta_type_roots() uses to discover
    roots in the first place, applied per-object at classification time.

    find_uclass_self_reference()'s seed remains required and cross-checked
    exactly as always -- the one non-negotiable anchor this whole
    computation is built from.

    Returns {'class_address_universe' (set[int]), 'round1_size' (int),
    'meta_type_roots' (dict[name, address hex] -- every discovered root
    beyond the seed, for the report), 'blueprint_generated_class_address'
    (int or None, from find_blueprint_generated_class_address(), kept for
    report continuity and as a cross-check against meta_type_roots),
    'passes_run' (int), 'converged' (bool)}.
    """
    round1_members = {
        address for address, record in objects_by_address.items()
        if record["valid"] and record["class_ptr"] == seed_address}
    universe = {seed_address} | round1_members

    bgc_address = find_blueprint_generated_class_address(
        round1_members, objects_by_address, path_resolver=path_resolver)
    meta_type_roots = find_meta_type_roots(round1_members, objects_by_address)

    roots = {seed_address} | set(meta_type_roots.values())

    passes_run = 1
    converged = False
    for _ in range(max(max_passes - 1, 0)):
        passes_run += 1
        new_members = {
            address for address, record in objects_by_address.items()
            if record["valid"] and record["class_ptr"] in roots
            and address not in universe}
        if not new_members:
            converged = True
            break
        universe |= new_members
    else:
        converged = False  # exhausted max_passes still growing -- logged by run_i04()'s own note.

    return {
        "class_address_universe": universe,
        "round1_size": len(round1_members),
        "meta_type_roots": {name: "0x%x" % addr for name, addr in meta_type_roots.items()},
        "blueprint_generated_class_address": bgc_address,
        "passes_run": passes_run,
        "converged": converged,
    }


def _summarize_walk(walk: dict) -> dict:
    return {
        "indices_scanned": walk["indices_scanned"],
        "objects_located": walk["objects_located"],
        "valid_count": walk["valid_count"],
        "rejected_counts": walk["rejected_counts"],
    }


def run_i04(api, process_handle: int, base_address: int, image_size_bytes: int,
           objects_ptr: int, num_elements: int, namepool_live_va: int,
           class_private_offset: int = DEFAULT_CLASS_PRIVATE_OFFSET,
           name_private_offset: int = DEFAULT_NAME_PRIVATE_OFFSET,
           outer_private_offset: int = DEFAULT_OUTER_PRIVATE_OFFSET,
           max_scan_indices: int = DEFAULT_I02_MAX_SCAN_INDICES,
           max_outer_depth: int = DEFAULT_I04_MAX_OUTER_DEPTH,
           max_fixed_point_passes: int = DEFAULT_I04_MAX_FIXED_POINT_PASSES) -> dict:
    """The whole of capability I-04: walk_object_universe() (every located
    object's ClassPrivate/NamePrivate/OuterPrivate, validated) ->
    find_uclass_self_reference() (the seed, cross-checked) ->
    compute_class_identity() (the meta-type-rooted fixed point) -> object_path +
    is_blueprint_generated for every classified UClass instance.

    *objects_ptr*/*num_elements* MUST be from THIS SAME run's own I-02
    result (never re-walked from scratch -- see the module docstring's
    "WHAT I-04 IS" section); *namepool_live_va* MUST be from THIS SAME run's
    own I-03 result, for the identical reason.

    Never raises for "seed not found" -- that is a hard structural failure
    for the whole capability, reported honestly as zero UClass instances
    found (see find_uclass_self_reference()'s own docstring), not a tool
    malfunction. DOES let ReadProcessMemoryFailedError propagate from
    nothing new here -- every per-object read this function's own callees
    make is already caught and converted into a rejection/failure count
    by _classify_object()/walk_object_universe(), mirroring I-02/I-03's own
    established split (a hard failure LOCATING a slot, or examining an
    ALREADY-located object's own fields, is a scanning/torn-read concern,
    never a propagated tool error for THIS capability, since it introduces
    no new foundational array-level read of its own -- objects_ptr/
    num_elements/namepool_live_va were already foundationally read by I-02/
    I-03 before this function was ever called).

    Returns a plain dict -- see the module docstring's "WHAT I-04 IS"
    section and this function's own field names below for the shape; the
    'classes' list carries one entry per classified UClass instance, with
    'module'/'module_origin'/'package' NOT yet filled in (that is
    classify_classes_by_module()'s own job, run separately by main() so
    this function stays a pure "what did the walk find" result).

    ADDITIVE FIELD, PE-02 (research/evidence/PE-01/README.md's own evidence
    track, see the module docstring's "WHAT PE-02 IS" section): the returned
    dict also carries 'objects_by_address' -- walk_object_universe()'s own
    already-computed dict, unchanged, threaded straight through -- so a
    caller (main(), when --run-pe02-vtable-scan is given) can sample I-04's
    OWN already-walked, already-validated object universe without this
    function re-walking GUObjectArray a second time or main() needing to
    call walk_object_universe() itself. Present on BOTH return paths below
    (seed found or not), because the walk itself always completes before
    the seed search even begins. This is a PURE ADDITION to I-04's own
    return shape -- build_i04_document() does not read this key (it only
    ever extracts the specific fields it already extracted before this was
    added), so nothing about I-04's own committed i04-classes.json/
    classes.jsonl output changes.
    """
    walk = walk_object_universe(
        api, process_handle, objects_ptr, num_elements, base_address, image_size_bytes,
        namepool_live_va, class_private_offset=class_private_offset,
        name_private_offset=name_private_offset, outer_private_offset=outer_private_offset,
        max_scan_indices=max_scan_indices)
    objects_by_address = walk["objects_by_address"]

    def path_of(address: int) -> dict:
        return resolve_object_path(address, objects_by_address, max_depth=max_outer_depth)

    seed = find_uclass_self_reference(objects_by_address, path_resolver=path_of)
    if seed is None:
        return {
            "seed_found": False,
            "seed_address_hex": None,
            "class_address_universe_size": 0,
            "round1_size": 0,
            "blueprint_generated_class_address_hex": None,
            "meta_type_roots": {},
            "fixed_point_passes_run": 0,
            "fixed_point_converged": None,
            "walk": _summarize_walk(walk),
            "classes": [],
            "objects_by_address": objects_by_address,
            "note": (
                "seed search failed: no valid object was found whose "
                "ClassPrivate equals its own address AND whose decoded "
                "name/object_path cross-check to %r/%r -- I-04 reports "
                "ZERO UClass instances found rather than build on an "
                "unverified seed (see find_uclass_self_reference()'s own "
                "docstring)." %
                (UCLASS_SELF_REFERENCE_NAME, UCLASS_SELF_REFERENCE_OBJECT_PATH)),
        }

    fixed_point = compute_class_identity(
        objects_by_address, seed["address"], path_resolver=path_of,
        max_passes=max_fixed_point_passes)
    bgc_address = fixed_point["blueprint_generated_class_address"]

    # Integrity check on the corrected (2026-08-27) class_address_universe
    # definition: the seed ("Class", self-referential) must be its own
    # witness -- seed.ClassPrivate == seed_address, so seed_address is
    # trivially a member of {record.class_ptr for valid records}. Asserted,
    # not merely assumed: if this ever fails, the walk itself is broken in
    # a way compute_class_identity()'s own docstring does not anticipate,
    # and that is exactly the kind of silent failure this project's own
    # discipline says must surface, not be papered over.
    assert seed["address"] in fixed_point["class_address_universe"], (
        "seed %r not in its own class_address_universe -- the corrected "
        "class-identity computation (compute_class_identity()'s own "
        "docstring) is unsound for this walk; do not trust classes below." %
        seed["address"])

    # Iterate objects_by_address (a dict, insertion-ordered == this run's own
    # scan order) rather than class_address_universe (a plain set, whose
    # iteration order is NOT deterministic/reproducible across runs) --
    # membership-tested against the set, order taken from the dict. This is
    # what makes select_game_sample()'s own "preserves scan order" claim
    # actually true, and this document's own row order reproducible.
    classes = []
    for address in objects_by_address:
        if address not in fixed_point["class_address_universe"]:
            continue
        record = objects_by_address[address]
        resolved = path_of(address)
        # is_blueprint_generated (CORRECTED 2026-08-27, see
        # compute_class_identity()'s own docstring for the full reasoning):
        # resolve what O's OWN ClassPrivate's decoded name IS -- the
        # type-descriptor object O is an instance of -- and check whether
        # THAT name ends with META_TYPE_NAME_SUFFIX ("GeneratedClass"), the
        # SAME general name-suffix test find_meta_type_roots() used to
        # discover roots in the first place (deliberately the SAME
        # constant/test, not a second, possibly-drifting copy) -- so this
        # also catches UWidgetBlueprintGeneratedClass/
        # UAnimBlueprintGeneratedClass instances (real UE 5.4 native
        # subclasses of UBlueprintGeneratedClass), not only the literal
        # "BlueprintGeneratedClass" type itself. None (genuinely
        # undetermined), never guessed, when O's own class_ptr was not
        # itself a validly-classified object in this same walk.
        class_descriptor = objects_by_address.get(record["class_ptr"])
        if class_descriptor is None or not class_descriptor["valid"]:
            is_blueprint_generated = None
        else:
            is_blueprint_generated = class_descriptor["name_text"].endswith(
                META_TYPE_NAME_SUFFIX)
        classes.append({
            "address": address,
            "address_hex": "0x%x" % address,
            "raw_name": record["name_text"],
            "object_path": resolved["object_path"],
            "package": resolved["package"],
            "object_path_ok": resolved["ok"],
            "object_path_note": resolved["note"],
            "is_blueprint_generated": is_blueprint_generated,
        })

    return {
        "seed_found": True,
        "seed_address_hex": "0x%x" % seed["address"],
        "class_address_universe_size": len(fixed_point["class_address_universe"]),
        "round1_size": fixed_point["round1_size"],
        "blueprint_generated_class_address_hex": (
            "0x%x" % bgc_address if bgc_address is not None else None),
        "meta_type_roots": fixed_point["meta_type_roots"],
        "fixed_point_passes_run": fixed_point["passes_run"],
        "fixed_point_converged": fixed_point["converged"],
        "walk": _summarize_walk(walk),
        "classes": classes,
        "objects_by_address": objects_by_address,
        "note": None if fixed_point["converged"] else (
            "the class-identity fixed point did NOT converge within "
            "max_fixed_point_passes=%d -- class_address_universe was still "
            "growing when the pass bound was hit; the reported set is a "
            "LOWER BOUND, not necessarily complete. See "
            "compute_class_identity()'s own docstring for why this should "
            "not normally happen against real UE 5.4 reflection data." %
            max_fixed_point_passes),
    }


def classify_classes_by_module(classes: list) -> dict:
    """Buckets run_i04()'s own 'classes' list by module/package, per I-04's
    own committed-artifact scope (module docstring's "WHAT I-04 IS"
    section): every /Script/MISERY class is written to classes.jsonl in
    full; /Game classes get a small BOUNDED sample (select_game_sample()
    below), never an exhaustive dump; everything else (native engine
    modules -- /Script/Engine, /Script/CoreUObject, etc. -- and anything
    unclassified) is counted only, never persisted.

    module_origin classification is DELIBERATELY MINIMAL here: only
    "game-misery" (module == "/Script/MISERY" exactly, matching RF-02's own
    established classification string verbatim) is ever asserted; every
    other module -- including genuine engine modules -- is left
    "unclassified", NOT guessed as "engine", because RF-02's own engine/
    game-plugin classification method (checking a module name against UE
    5.4.4's actual module list at the correct changelist) is out of scope
    for this pass and this function does not attempt to reproduce it from
    a name pattern alone (research/schema/reflection-record.schema.json's
    own module_origin description: "reported, never guessed").

    Returns {'misery': list[dict], 'game': list[dict], 'other': list[dict]}
    -- each entry is one of *classes*'s own dicts, enriched with 'module'
    and 'module_origin'.
    """
    misery: list = []
    game: list = []
    other: list = []
    for record in classes:
        package = record["package"]
        module = package if (package and package.startswith("/Script/")) else None
        module_origin = "game-misery" if module == "/Script/MISERY" else "unclassified"
        enriched = dict(record, module=module, module_origin=module_origin)
        if module == "/Script/MISERY":
            misery.append(enriched)
        elif package and package.startswith("/Game/"):
            game.append(enriched)
        else:
            other.append(enriched)
    return {"misery": misery, "game": game, "other": other}


def select_game_sample(game_classes: list, cap: int = DEFAULT_I04_GAME_SAMPLE_CAP) -> list:
    """A small, BOUNDED sample of *game_classes* (classify_classes_by_module()'s
    own 'game' bucket) to actually WRITE to classes.jsonl -- never the full
    set found, per I-04's own committed-artifact scope. Prioritizes
    is_blueprint_generated=True entries first (the task this capability was
    specified from: "especially ones classified is_blueprint_generated=
    true"), then fills any remaining capacity with the rest, each group
    preserving its own original (scan) order for reproducibility. The FULL
    count of *game_classes* (before this cap) is reported separately by
    run_i04()/build_i04_document() regardless of how many are actually
    written here -- this function only ever decides what gets PERSISTED.
    """
    blueprint_generated = [c for c in game_classes if c["is_blueprint_generated"] is True]
    rest = [c for c in game_classes if c["is_blueprint_generated"] is not True]
    return (blueprint_generated + rest)[:cap]


def build_i04_document(*, result: dict, build_key: str, recorded_at: str | None,
                       identity_self_established: bool, build_key_cross_checked: bool,
                       known_build: bool, build_id: str | None,
                       misery_classes_count: int, game_classes_total_count: int,
                       game_classes_sample_count: int, other_classes_count: int) -> dict:
    """The I-04 raw output document -- research/instrument-runs/<run>/
    i04-classes.json, the SAME "raw single-run data document, no evidence
    envelope" shape as build_i01_document()/build_i02_document()/
    build_i03_document() (see build_i01_document()'s own docstring for the
    is_record()/MARKER_KEYS reasoning this mirrors verbatim -- none of the
    fields here is a marker key either). classes.jsonl (a SEPARATE artifact,
    built by build_i04_class_record() below and written by main()) is where
    the actual GRADED knowledge-base claims live; this document is this
    run's own bookkeeping/summary, including the honest full counts for
    everything this pass deliberately does NOT persist (engine-module
    classes, and every /Game class beyond the bounded sample cap) -- see
    the module docstring's "WHAT I-04 IS" section for why those counts
    matter even though the rows themselves are not committed.
    """
    return {
        "capability": CAPABILITY_ID_I04,
        "seed_found": result["seed_found"],
        "seed_address_hex": result["seed_address_hex"],
        "class_address_universe_size": result["class_address_universe_size"],
        "round1_size": result["round1_size"],
        "blueprint_generated_class_address_hex": result["blueprint_generated_class_address_hex"],
        "fixed_point_passes_run": result["fixed_point_passes_run"],
        "fixed_point_converged": result["fixed_point_converged"],
        "walk": result["walk"],
        "misery_classes_count": misery_classes_count,
        "game_classes_total_count": game_classes_total_count,
        "game_classes_sample_count": game_classes_sample_count,
        "other_classes_count": other_classes_count,
        "note": result["note"],
        "build_key": build_key,
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
    }


# The MISERY-cross-check source cited on every /Script/MISERY class_record
# row (build_i04_class_record() below, cross_checked=True) -- see that
# function's own docstring, and the module docstring's confidence/MIX-SPLIT
# reasoning, for why this is a DIFFERENT build than the one this run
# observed, and why that is stated plainly rather than glossed over.
_I04_MISERY_CROSS_CHECK_SOURCE = {
    "method": (
        "RF-01: structured decode of the ScriptObjects chunk of "
        "global.ucas, a DIFFERENT build (misery-24826585-ue5.4.4-"
        "0eef3715244b) than this record's own build_key"),
    "artifact": "research/reflection/misery-24826585-ue5.4.4-0eef3715244b/classes.jsonl",
    "locator": None,
    "note": (
        "CROSS-BUILD corroboration, not a same-build second reading: RF-01's "
        "own record is for build 24826585; this record is for a different "
        "build. The evidentiary value is that the SAME five native "
        "/Script/MISERY class names recur, independently, across a static "
        "offline decode of an earlier build and a live runtime read of the "
        "current build -- strong evidence these are genuine, stable native "
        "classes of the game's own root module, not a coincidental or "
        "misread name. It does NOT independently confirm anything about "
        "THIS record's own build_key, since RF-01 never read this build "
        "at all -- that is why this cross-check alone earns 0.90, not "
        "higher, and why it is stated explicitly here rather than folded "
        "silently into a same-build-looking 'second source'."),
}


def build_i04_class_record(entry: dict, *, build_key: str, recorded_at: str,
                           cross_checked: bool) -> dict:
    """One classes.jsonl row (research/schema/reflection-record.schema.json's
    class_record branch, composed with kb-record.schema.json's envelope) for
    ONE entry of classify_classes_by_module()'s own enriched 'classes' list.

    *cross_checked* selects the MIX-SPLIT evidence grading the task this
    capability was specified from explicitly asked for, justified here
    rather than applied as one blanket number to every record kind:

      * True (every /Script/MISERY class, always -- exactly the ~5 rows
        matching research/reflection/misery-24826585-ue5.4.4-
        0eef3715244b/classes.jsonl's own 5 names): confidence 0.90,
        evidence_level OBSERVED, oracle ["runtime-reflection",
        "global-ucas"], TWO sources -- this run's own I-04 traversal, plus
        _I04_MISERY_CROSS_CHECK_SOURCE above. 0.90 matches LOG-0051's own
        confidence for the SAME live GUObjectArray/FNamePool apparatus this
        record is built from, and is defensible by the SAME "two
        independent methods" criterion kb-record.schema.json's own envelope
        already requires for confidence >= 0.80 (plan.md 10.3): a runtime
        read of build 24953925, cross-checked by an INDEPENDENT static
        decode of build 24826585's global.ucas finding the identical five
        names. It is explicitly NOT claimed as strong as an offline decode
        of THIS SAME build would be (RF-01 never read this build), which is
        exactly why it stays at 0.90 rather than reaching for 0.95+ (that
        band additionally needs, per plan.md 10.3, every one of six
        criteria stated line-by-line -- not attempted here, matching
        LOG-0051's own stated reason for staying at 0.90 rather than
        higher).
      * False (every /Game class in the bounded sample -- there is no
        offline cross-check for a SPECIFIC compiled Blueprint asset, only
        this ONE live read): confidence 0.75, evidence_level OBSERVED,
        oracle ["runtime-reflection"], ONE source. Deliberately kept BELOW
        the kb-record.schema.json envelope's own 0.80 threshold: at 0.75 the
        single-source exemption never needs to be argued for at all (the
        schema's own "confidence >= 0.80 needs >= 2 sources" rule, plan.md
        task EV-03, simply does not apply below it) -- 0.75 is chosen as
        the class-I band plan.md 10.2 itself describes as "one strong ...
        confirmation" (0.60-0.79), near its own top, reflecting that this
        IS a strong single method (a live runtime read via a
        cross-validated GUObjectArray/FNamePool apparatus, not a guess),
        just one without ANY independent corroboration for this specific
        object -- unlike the MISERY classes, nothing else in this
        repository has ever independently observed this particular
        Blueprint asset existing.

    Fields the task this capability was specified from explicitly scoped
    OUT (never guessed, never half-implemented, all explicitly null):
    cdo_name, is_native, is_abstract, within_class, config_name, interfaces,
    property_count, function_count, super, super_object_path, size,
    alignment, class_flags_raw, class_cast_flags_raw, flags_raw -- every one
    of these needs a UObject-, UField-, UStruct- or UClass-specific field
    I-04 deliberately never reads (see the module docstring's "WHAT I-04
    IS" section, "SCOPE" paragraph).
    """
    confidence = 0.90 if cross_checked else 0.75
    oracle = (["runtime-reflection", "global-ucas"] if cross_checked
             else ["runtime-reflection"])
    sources = [{
        "method": (
            "I-04: FUObjectArray walk (I-02's own chunk-walk arithmetic, "
            "reused) + ClassPrivate/NamePrivate/OuterPrivate reads "
            "(UObjectBase.h offsets +0x%x/+0x%x/+0x%x) + FNamePool decode "
            "(I-03's own decode_fname_entry_id, reused) + the ClassPrivate "
            "self-reference fixed point" %
            (DEFAULT_CLASS_PRIVATE_OFFSET, DEFAULT_NAME_PRIVATE_OFFSET,
             DEFAULT_OUTER_PRIVATE_OFFSET)),
        "artifact": None,
        "locator": entry["address_hex"],
        "note": (
            "oracle runtime-reflection. The address is this live UObject's "
            "own address in THIS run's process -- not stable across a "
            "relaunch (ASLR/heap allocation), recorded only for this run's "
            "own audit trail."),
    }]
    if cross_checked:
        sources.append(dict(_I04_MISERY_CROSS_CHECK_SOURCE))

    claim_type = "native-class-exists" if cross_checked else "asset-exists"
    claim = (
        "the live MISERY-Win64-Shipping.exe process (build_key %s) has a "
        "UObject at %s that IS a UClass instance named %r, object_path %r" %
        (build_key, entry["address_hex"], entry["raw_name"], entry["object_path"]))
    notes = None if entry["object_path_ok"] else (
        "object_path is best-effort: %s" % entry["object_path_note"])

    return {
        "kind": "class",
        "raw_name": entry["raw_name"],
        "object_path": entry["object_path"],
        "package": entry["package"],
        "module": entry["module"],
        "module_origin": entry["module_origin"],
        "flags_raw": None,
        "super": None,
        "super_object_path": None,
        "size": None,
        "alignment": None,
        "class_flags_raw": None,
        "class_cast_flags_raw": None,
        "cdo_name": None,
        "is_native": None,
        "is_blueprint_generated": entry["is_blueprint_generated"],
        "is_abstract": None,
        "within_class": None,
        "config_name": None,
        "interfaces": None,
        "property_count": None,
        "function_count": None,
        "claim": claim,
        "claim_type": claim_type,
        "claim_class": "I",
        "evidence_level": "OBSERVED",
        "confidence": confidence,
        "oracle": oracle,
        "sources": sources,
        "build_key": build_key,
        "recorded_at": recorded_at,
        "method": "I-04",
        "refutation_attempt": (
            "if the ClassPrivate self-reference fixed point were wrong, an "
            "object with a non-UClass ClassPrivate could still be admitted "
            "into class_address_universe -- refuted by requiring the SEED "
            "itself to cross-check its own decoded name/object_path against "
            "the known literals 'Class'/'/Script/CoreUObject.Class' before "
            "the fixed point runs at all; by requiring "
            "'BlueprintGeneratedClass' to pass the identical by-name/"
            "by-object_path cross-check before it is ever promoted to a "
            "growth root; and by growing the universe from EXACTLY those "
            "two verified roots, never from 'anything already in the "
            "universe', which would (and, unverified, could) also sweep in "
            "ordinary gameplay object instances of any native class already "
            "found -- see compute_class_identity()'s own docstring for the "
            "full worked reason this specific, narrower rule was chosen."),
        "notes": notes,
        "semantic_alias": None,
    }


def dump_jsonl(records: list) -> str:
    """Deterministic JSONL serialization: one compact (sorted-key) JSON
    object per line, LF-terminated -- the SAME shape
    tools/reflection/global_ucas.py's own dump_jsonl() produces (no indent,
    unlike this file's own dump_json()'s pretty-printed single-document
    form), matching the already-committed research/reflection/*/classes.jsonl
    convention (research/reflection/misery-24826585-ue5.4.4-0eef3715244b/
    classes.jsonl's own 5 lines are exactly this shape).
    """
    return "".join(
        json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
        for record in records)


# --------------------------------------------------------------------------- #
# I-06 -- FProperty decoder. Every offset below is an ABSOLUTE byte offset
# from the FField/FProperty-derived OBJECT's own address (the same address a
# UStruct::ChildProperties entry, or any FField's own Next pointer, already
# gives you) -- never relative to some other field's own end. Source:
# Engine/Source/Runtime/CoreUObject/Public/UObject/Field.h, UnrealType.h,
# EnumProperty.h, TextProperty.h, ObjectMacros.h, Set.h, Map.h; UE 5.4.4
# CL 35576357. See the module docstring's "WHAT I-06 IS" section for the
# capability-level rationale this block implements.
# --------------------------------------------------------------------------- #

# FField (Field.h:447), total size 0x30. Field.h:489 gives FField a VIRTUAL
# destructor, so FField objects DO have a vtable at +0x00 -- unlike
# FFieldClass below, which does not.
FFIELD_CLASS_PRIVATE_OFFSET = 0x08   # FFieldClass* ClassPrivate (Field.h:452)
FFIELD_OWNER_OFFSET = 0x10           # FFieldVariant Owner (Field.h:472)
FFIELD_NEXT_OFFSET = 0x18            # FField* Next (Field.h:475)
FFIELD_NAME_PRIVATE_OFFSET = 0x20    # FName NamePrivate (Field.h:478)
FFIELD_SIZE_BYTES = 0x30

# FFieldVariant (Field.h:264-339): an 8-byte TAGGED POINTER union. The low
# bit of the raw stored 8-byte value is the UObjectMask tag (Field.h:272,
# "static constexpr uintptr_t UObjectMask = 0x1"): 1 means Owner is a
# UObject* with the tag bit OR'd into the stored pointer by the
# FFieldVariant(const UObject*) constructor (Field.h:299-304); 0 means Owner
# is a plain FField* (Field.h:289-293's FFieldVariant(const FField*)
# constructor asserts !IsUObject(), i.e. a real FField* is guaranteed
# naturally 8-byte-aligned already and needs no masking at all). See
# _decode_ffield_owner() below.
FFIELD_OWNER_UOBJECT_TAG_MASK = 0x1

# FFieldClass (Field.h:62-94) -- the "type object" for an FField, analogous
# to UClass but NOT a UObject, NOT a member of GUObjectArray, and with NO
# vtable (a non-virtual destructor, Field.h:94) -- an FFieldClass pointer is
# therefore validated by _pointer_is_plausible() ALONE (see
# decode_property_type() below); I-04's own vtable-in-module-range check
# (_vtable_pointer_in_module_range()) does not apply here, because there is
# no vtable to check.
FFIELDCLASS_NAME_OFFSET = 0x00        # FName Name (Field.h:67)
FFIELDCLASS_SUPERCLASS_OFFSET = 0x20  # FFieldClass* SuperClass (Field.h:75) --
# Name(8B)+Id(8B)+CastFlags(8B)+ClassFlags(EClassFlags, 4B)+4B padding for
# SuperClass's own 8-byte pointer alignment = 0x20 (Field.h:66-76, spot-
# checked directly this session).

# FProperty : public FField (UnrealType.h:162), base offsets +0x30 onward,
# total size 0x70 -- every type-specific field below is an ABSOLUTE offset
# from the SAME property-object base address, not "relative to +0x70".
FPROPERTY_ARRAY_DIM_OFFSET = 0x30        # int32 ArrayDim
FPROPERTY_ELEMENT_SIZE_OFFSET = 0x34     # int32 ElementSize
FPROPERTY_PROPERTY_FLAGS_OFFSET = 0x38   # EPropertyFlags -- uint64 (ObjectMacros.h:395)
FPROPERTY_REP_INDEX_OFFSET = 0x40        # uint16 RepIndex
FPROPERTY_OFFSET_INTERNAL_OFFSET = 0x44  # int32 Offset_Internal (1B padding at +0x43
# for BlueprintReplicationCondition, a private uint8 at +0x42)
# +0x48/+0x50/+0x58/+0x60: four FProperty* linked-list pointers this
# capability never reads -- PropertyLinkNext/NextRef/DestructorLinkNext/
# PostConstructLinkNext (UnrealType.h:180-186) -- accounted for here only so
# the jump from Offset_Internal to RepNotifyFunc's own offset below is not
# mistaken for adjacent fields; they occupy exactly the 0x20 bytes between.
FPROPERTY_REP_NOTIFY_FUNC_OFFSET = 0x68  # FName RepNotifyFunc
FPROPERTY_SIZE_BYTES = 0x70

# Type-specific fields, every offset ABSOLUTE from the property object's own
# base address (all >= FPROPERTY_SIZE_BYTES).
FBOOLPROPERTY_FIELD_SIZE_OFFSET = 0x70    # uint8 (UnrealType.h:2375-2389)
FBOOLPROPERTY_BYTE_OFFSET_OFFSET = 0x71   # uint8 -- schema field bool_byte_offset
FBOOLPROPERTY_BYTE_MASK_OFFSET = 0x72     # uint8
FBOOLPROPERTY_FIELD_MASK_OFFSET = 0x73    # uint8 -- schema field bool_field_mask
# UnrealType.h:2388's own doc comment on FieldMask is explicit and
# authoritative: "Mask of the field with the property value. Either equal
# to ByteMask or 255 in case of 'bool' type." -- confirmed a second,
# independent way this session by IsNativeBool() (UnrealType.h:2503-2505),
# which is defined as exactly `return FieldMask == 0xff;`. Therefore
# is_bitfield := (FieldMask != 0xFF) is read directly off the engine's own
# source, not inferred or guessed.
FBOOLPROPERTY_FULL_BYTE_FIELD_MASK = 0xFF

FOBJECTPROPERTY_PROPERTY_CLASS_OFFSET = 0x70  # TObjectPtr<UClass> PropertyClass
# (FObjectPropertyBase, UnrealType.h:2536) -- inherited unchanged by
# FObjectProperty (UnrealType.h:2875) and FClassProperty (UnrealType.h:3184)
# below, both confirmed by direct Read this session to add no field before
# their own type-specific additions.
FCLASSPROPERTY_META_CLASS_OFFSET = 0x78       # TObjectPtr<UClass> MetaClass (UnrealType.h:3189)
FSTRUCTPROPERTY_STRUCT_OFFSET = 0x70          # TObjectPtr<UScriptStruct> Struct (UnrealType.h:6019)
FENUMPROPERTY_UNDERLYING_PROP_OFFSET = 0x70   # FNumericProperty* UnderlyingProp (EnumProperty.h:118)
FENUMPROPERTY_ENUM_OFFSET = 0x78              # TObjectPtr<UEnum> Enum (EnumProperty.h:119)
FARRAYPROPERTY_ARRAY_FLAGS_OFFSET = 0x70      # EArrayPropertyFlags -- uint8
# (ObjectMacros.h:491) -- not persisted to any schema field, read only if
# ever needed for a future capability; I-06 does not read it at all.
FARRAYPROPERTY_INNER_OFFSET = 0x78            # FProperty* Inner (UnrealType.h:3571) --
# 7 bytes of padding after ArrayFlags(1B) for Inner's own 8-byte pointer alignment.
FSETPROPERTY_ELEMENT_PROP_OFFSET = 0x70       # FProperty* ElementProp (UnrealType.h:3885)
FMAPPROPERTY_KEY_PROP_OFFSET = 0x70           # FProperty* KeyProp (UnrealType.h:3721)
FMAPPROPERTY_VALUE_PROP_OFFSET = 0x78         # FProperty* ValueProp

# FFieldClass::Name string values -- CORRECTED LIVE, this pass, against the
# real process (build misery-24953925-ue5.4.4-bace50f7185d): Field.h's own
# IMPLEMENT_FIELD macro (Field.h:243-252) does pass the F-prefixed literal
# ("static FFieldClass StaticFieldClass(TEXT(#TClass), ...)", TClass e.g.
# FBoolProperty) -- but FFieldClass's own CONSTRUCTOR (Field.cpp:46-61)
# explicitly STRIPS that leading "F" before storing it:
#   check(InCPPName[0] == 'F');
#   Name = ++InCPPName;   // "Skip the 'F' prefix for the name"
# so the stored FFieldClass::Name is "BoolProperty", never "FBoolProperty".
# A prior pass this session (AND both this pass's own adversarial source
# reviews) stopped at the macro's own stringification and never followed
# the token into the constructor body it feeds -- caught only once a LIVE
# read decoded a real FFieldClass::Name as literally "BoolProperty" for a
# genuine bStartEditing bool property (research/instrument-runs/
# 2026-08-27T154643Z-i06-fixed), which is what these constants below now
# hold and what decode_property_type() dispatches on. The F-prefixed,
# canonical C++ type name (matching reflection-record.schema.json's own
# property_class field examples, "FBoolProperty" etc.) is reconstructed by
# decode_property_type() ONLY when populating the OUTPUT record -- by
# prepending "F" back, an operation this SAME constructor invariant
# (InCPPName[0] must be 'F') guarantees is always exactly reversible for
# every FField-derived type this codebase's IMPLEMENT_FIELD macro ever
# registers, never a guess.
FFIELDCLASS_NAME_PROPERTY = "Property"
FFIELDCLASS_NAME_NUMERICPROPERTY = "NumericProperty"
FFIELDCLASS_NAME_BOOLPROPERTY = "BoolProperty"
FFIELDCLASS_NAME_OBJECTPROPERTY = "ObjectProperty"
FFIELDCLASS_NAME_CLASSPROPERTY = "ClassProperty"
FFIELDCLASS_NAME_STRUCTPROPERTY = "StructProperty"
FFIELDCLASS_NAME_ENUMPROPERTY = "EnumProperty"
FFIELDCLASS_NAME_ARRAYPROPERTY = "ArrayProperty"
FFIELDCLASS_NAME_SETPROPERTY = "SetProperty"
FFIELDCLASS_NAME_MAPPROPERTY = "MapProperty"
FFIELDCLASS_NAME_NAMEPROPERTY = "NameProperty"
FFIELDCLASS_NAME_STRPROPERTY = "StrProperty"
FFIELDCLASS_NAME_TEXTPROPERTY = "TextProperty"

# UStruct::ChildProperties -- THE entry point for I-06's own traversal -- an
# FField* (may legitimately be null: a class with zero own properties is
# valid, not an error).
#
# CORRECTED LIVE, this pass, against the real MISERY-Win64-Shipping.exe
# process (build misery-24953925-ue5.4.4-bace50f7185d) -- a prior session
# phase's own derivation (UObjectBase(0x28) -> UField adds Next(+0x28, UField
# total 0x30) -> UStruct adds SuperStruct(+0x30)/Children(+0x38)/
# ChildProperties(+0x40)) missed a SECOND, conditionally-compiled base class
# of UStruct: Class.h:382-385 declares
#   class UStruct : public UField
#   #if USTRUCT_FAST_ISCHILDOF_IMPL == USTRUCT_ISCHILDOF_STRUCTARRAY
#       , private FStructBaseChain
#   #endif
# and ObjectMacros.h:40-46 resolves USTRUCT_FAST_ISCHILDOF_IMPL to
# USTRUCT_ISCHILDOF_STRUCTARRAY (2) whenever UE_EDITOR is 0 -- i.e. in EVERY
# non-editor build, including this project's own Shipping target. The
# private base is laid out (declaration-order, standard MSVC multiple-
# inheritance rule) BETWEEN UField's own subobject and UStruct's own
# "Variables" section: FStructBaseChain (Class.h:349-372) itself holds
# StructBaseChainArray (FStructBaseChain**, 8B) + NumStructBasesInChainMinusOne
# (int32, 4B) + 4B trailing pad for the next subobject's 8-byte alignment =
# 16 bytes -- pushing UField's own Next(+0x28) forward by 0x10 before
# UStruct's own SuperStruct/Children/ChildProperties begin.
#
# CORRECTED layout: UField total 0x30 (unchanged) -> FStructBaseChain
# subobject +0x30..+0x3F (StructBaseChainArray+0x30, NumStructBasesInChain
# MinusOne+0x38) -> UStruct's OWN members start at +0x40: SuperStruct+0x40,
# Children+0x48, ChildProperties+0x50, PropertiesSize+0x58, MinAlignment
# +0x5c.
#
# CAUGHT BY A LIVE READ, not source re-reading alone: the FIRST I-06 run
# against the real process (2026-08-27T153951Z-i06) rejected every single
# ChildProperties-chain node (48 rejections across 25 proof-set classes,
# 0 properties accepted) because +0x40 was, in this build, actually reading
# NumStructBasesInChainMinusOne's own trailing bytes as a pointer -- a
# SMALL, structurally-implausible integer (e.g. NumStructBasesInChainMinusOne
# == 2 for a 3-deep inheritance chain, read as the low 32 bits of a
# supposed 8-byte FField pointer). Diagnosed by a raw, read-only memory dump
# (scratchpad diag_childprops.py/diag_childprops2.py) against the SAME live
# process instance, confirming +0x50 instead: a plausible pointer that,
# dereferenced, yields a real FField object (its own vtable DIFFERENT from
# the owning UClass's own vtable, its ClassPrivate pointing into the
# module's own static-data range -- exactly where the IMPLEMENT_FIELD macro's
# `static FFieldClass StaticFieldClass(...)` lives -- and its own Owner
# FFieldVariant round-tripping EXACTLY to the owning class's own address).
# Both independent adversarial source reviews this pass (offset re-
# derivation AND traversal-safety) reproduced the WRONG +0x40 value from the
# same prior-phase docstring without independently re-reading Class.h:382-385
# themselves -- this is the exact "two reviews trusting the same stale
# citation instead of the primary source" failure mode LOG-0052 already
# warns about for a different offset; recorded here so it is not repeated a
# third time.
USTRUCT_CHILD_PROPERTIES_OFFSET = 0x50

# select_i06_proof_set()'s own engine-class name-preference order (searched
# in THIS order over I-04's own full walked class universe, stopping once
# --i06-engine-class-cap classes are found or the list is exhausted -- never
# an error when a name is not found in this specific build, see
# select_i06_engine_proof_classes()'s own docstring).
I06_ENGINE_CLASS_NAME_PREFERENCE = (
    "Object", "Actor", "Struct", "Class", "Pawn", "ActorComponent", "SceneComponent",
)

# Bounds I-06 introduces, all overridable via their own CLI flag (see
# build_arg_parser() below) -- never a second hardcoded copy of any of them,
# matching the DEFAULT_I04_MAX_OUTER_DEPTH/DEFAULT_I04_MAX_FIXED_POINT_
# PASSES/DEFAULT_I04_GAME_SAMPLE_CAP naming convention.
DEFAULT_I06_MAX_PROPERTY_CHAIN_LENGTH = 1024      # UStruct::ChildProperties' own
# Next-linked sibling chain -- generous, no realistic UStruct has anywhere
# near this many DIRECT (non-inherited) properties.
DEFAULT_I06_MAX_SUPERCLASS_DEPTH = 16              # FFieldClass::SuperClass chain walk.
DEFAULT_I06_MAX_CONTAINER_NESTING_DEPTH = 4        # Inner/KeyProp/ValueProp/
# UnderlyingProp recursion -- generous for a realistic TArray<TArray<X>>.
DEFAULT_I06_PROOF_SET_ENGINE_CLASS_CAP = 5


def _decode_ffield_owner(raw_value: int) -> dict:
    """Decodes FField::Owner (Field.h:472), an 8-byte FFieldVariant TAGGED
    POINTER union -- see FFIELD_OWNER_UOBJECT_TAG_MASK's own comment above
    for the full Field.h citation this implements. Never raises: *raw_value*
    is already-read data, and every 8-byte value (including 0, a legitimately
    null/never-set Owner) has a well-defined decode under this scheme.

    Returns {'is_uobject': bool, 'address': int} -- 'address' is the REAL
    pointer value: *raw_value* with the tag bit masked off when
    'is_uobject' is True, or *raw_value* unchanged (already untagged, by the
    FField* constructor's own assertion) when False.
    """
    is_uobject = bool(raw_value & FFIELD_OWNER_UOBJECT_TAG_MASK)
    address = (raw_value & ~FFIELD_OWNER_UOBJECT_TAG_MASK) if is_uobject else raw_value
    return {"is_uobject": is_uobject, "address": address}


def _walk_fieldclass_super_chain(api, handle: int, fieldclass_ptr: int, *,
                                 namepool_live_va: int,
                                 max_depth: int = DEFAULT_I06_MAX_SUPERCLASS_DEPTH) -> dict:
    """Walks FFieldClass::SuperClass (Field.h:75) from *fieldclass_ptr*
    up to the root, decoding each ancestor's own FFieldClass::Name
    (Field.h:67) via I-03's own decode_fname_entry_id() -- reused, never a
    second FName decoder. BOUNDED (*max_depth* hops) and CYCLE-PROTECTED (an
    address that repeats within THIS ONE walk is a traversal failure) --
    mirrors resolve_object_path()'s own Outer-chain walk exactly, applied to
    a DIFFERENT, simpler chain (FFieldClass::SuperClass is a plain single-
    parent pointer, never the fixed-point-identity problem I-04's own
    ClassPrivate walk had to solve).

    This is the SOLE dispatch mechanism decode_property_type() below uses to
    determine (a) whether a ChildProperties-chain entry really IS an
    FProperty-derived object before applying any FProperty-specific offset,
    and (b) whether a leaf numeric type (FIntProperty, FFloatProperty,
    FByteProperty, ...) is a descendant of FNumericProperty (the generic
    fallback for every numeric leaf, all confirmed architecturally to add
    zero extra fields beyond FProperty itself -- see the module docstring's
    "WHAT I-06 IS" section). No EClassCastFlags/CASTCLASS_* bit is ever read
    for this purpose -- name-string + SuperClass-chain-walk is the proven,
    non-guessing approach this session's own findings established; a second,
    CastFlags-based dispatch mechanism is deliberately not introduced.

    Never raises ReadProcessMemoryFailedError -- a read failure walking an
    ALREADY-LOCATED FFieldClass pointer (found via an already-validated
    FField's own ClassPrivate, or a prior ancestor's own SuperClass) is a
    torn-read scanning concern here too, exactly like I-04's own
    _classify_object()/walk_object_universe() precedent for a UObject's own
    fields -- converted into 'ok': False with an explanatory 'note', never
    propagated (see the module docstring's own "THE 'ALL OR NOTHING' WRITE
    GUARANTEE" section for why this is the correct mirror of I-04's own
    established split, not a departure from it).

    Returns {'names': list[str] (every successfully-decoded ancestor's own
    FFieldClass::Name, in walk order, fieldclass_ptr's own name first --
    empty only when the FIRST hop itself failed), 'ok': bool (True iff the
    chain terminated normally, at SuperClass==0, without a cycle, a read
    failure, a name-decode failure, or exceeding *max_depth*), 'note':
    str | None (explains why 'ok' is False; None when True)}.
    """
    names: list = []
    visited: set = set()
    address = fieldclass_ptr

    for _ in range(max_depth):
        if not _pointer_is_plausible(address):
            return {"names": names, "ok": False,
                    "note": "FFieldClass pointer 0x%x is not a plausible "
                            "(non-null, 8-byte-aligned) address" % address}
        if address in visited:
            return {"names": names, "ok": False,
                    "note": "cycle detected in FFieldClass::SuperClass "
                            "chain at 0x%x" % address}
        visited.add(address)

        try:
            name_entry_id = _read_u32(api, handle, address + FFIELDCLASS_NAME_OFFSET)
            super_ptr = _read_u64(api, handle, address + FFIELDCLASS_SUPERCLASS_OFFSET)
        except ReadProcessMemoryFailedError as error:
            return {"names": names, "ok": False,
                    "note": "read failure walking FFieldClass::SuperClass "
                            "at 0x%x: %s" % (address, error)}

        decoded = decode_fname_entry_id(api, handle, namepool_live_va, name_entry_id)
        if decoded["decode_error"] is not None:
            return {"names": names, "ok": False,
                    "note": "FFieldClass::Name decode error at 0x%x: %s" %
                            (address, decoded["decode_error"])}
        names.append(decoded["text"])

        if super_ptr == 0:
            return {"names": names, "ok": True, "note": None}
        address = super_ptr
    else:
        return {"names": names, "ok": False,
                "note": "FFieldClass::SuperClass chain exceeded max_depth "
                        "(%d) without terminating" % max_depth}


def _resolve_uobject_handle_name(api, handle: int, uobject_ptr: int, *,
                                 namepool_live_va: int,
                                 objects_by_address: dict | None,
                                 name_private_offset: int = DEFAULT_NAME_PRIVATE_OFFSET
                                 ) -> dict:
    """Best-effort raw-name resolution for a UObject-typed property field --
    FObjectPropertyBase::PropertyClass, FClassProperty::MetaClass,
    FStructProperty::Struct, FEnumProperty::Enum. Every one of these is
    declared TObjectPtr<T> in source; read here as a RAW 8-byte value and
    treated as a plain UObject* address, which is correct for this build
    (UE_WITH_OBJECT_HANDLE_LATE_RESOLVE off -- the SAME assumption
    DEFAULT_NAME_PRIVATE_OFFSET's own comment already makes for
    UObjectBase::ClassPrivate, not re-derived here).

    TWO-TIER resolution, cheapest/most-validated first:
      1. *objects_by_address* (I-04's own already-validated walk result,
         when the caller has one in hand): a dict hit whose own 'name_ok'
         is True means this exact address was ALREADY read and structurally
         validated by THIS SAME run's own I-02-array walk -- reusing it
         costs no new memory read at all. This tier is OPTIONAL and, in
         this pass's own main() wiring, is never actually populated (doing
         so would require widening run_i04()'s own already-established
         return contract, which this pass deliberately does not touch --
         see the module docstring's "WHAT I-06 IS" section); it exists so a
         FUTURE in-process caller that already holds I-04's own
         objects_by_address can skip the redundant read described in tier 2.
      2. A direct, best-effort NamePrivate read+decode (I-03's own
         decode_fname_entry_id(), reused) -- bypassing I-04's own
         ClassPrivate-vtable check entirely, since this function only ever
         needs a NAME, never full UClass identity/validity. Every UClass/
         UScriptStruct/UEnum a live FProperty can reference is itself a
         live UObject with a NamePrivate at the SAME standard offset, so
         this fallback always applies.

    Never raises: a read/decode failure at either tier is reported as data
    ('name': None, 'note': the reason), never guessed and never propagated
    -- the referenced type simply could not be named this run, which is
    itself a reportable, honest outcome (folded into the owning property's
    own 'notes' field by the caller, never silently dropped).

    Returns {'name': str | None, 'source': 'i04-walk' | 'direct-read' | None,
    'note': str | None}.
    """
    if not _pointer_is_plausible(uobject_ptr):
        return {"name": None, "source": None,
                "note": "handle 0x%x is not a plausible (non-null, "
                        "8-byte-aligned) UObject address" % uobject_ptr}

    if objects_by_address is not None:
        cached = objects_by_address.get(uobject_ptr)
        if cached is not None and cached.get("name_ok"):
            return {"name": cached["name_text"], "source": "i04-walk", "note": None}

    try:
        name_entry_id = _read_u32(api, handle, uobject_ptr + name_private_offset)
        decoded = decode_fname_entry_id(api, handle, namepool_live_va, name_entry_id)
    except ReadProcessMemoryFailedError as error:
        return {"name": None, "source": None,
                "note": "direct NamePrivate read failed at 0x%x: %s" %
                        (uobject_ptr, error)}
    if decoded["decode_error"] is not None:
        return {"name": None, "source": None,
                "note": "direct NamePrivate decode failed at 0x%x: %s" %
                        (uobject_ptr, decoded["decode_error"])}
    return {"name": decoded["text"], "source": "direct-read", "note": None}


def _decode_bool_property(api, handle: int, field_ptr: int) -> tuple:
    """FBoolProperty (UnrealType.h:2375), +0x70..+0x73. See
    FBOOLPROPERTY_FULL_BYTE_FIELD_MASK's own comment for the is_bitfield
    derivation's exact source citation. Returns (fields: dict, note: str|None)
    -- 'note' is set only when the read FieldMask violates the engine's own
    documented invariant (neither ByteMask nor 0xFF), a genuine, reportable
    anomaly, never silently hidden.
    """
    field_size = _read_u8(api, handle, field_ptr + FBOOLPROPERTY_FIELD_SIZE_OFFSET)
    byte_offset = _read_u8(api, handle, field_ptr + FBOOLPROPERTY_BYTE_OFFSET_OFFSET)
    byte_mask = _read_u8(api, handle, field_ptr + FBOOLPROPERTY_BYTE_MASK_OFFSET)
    field_mask = _read_u8(api, handle, field_ptr + FBOOLPROPERTY_FIELD_MASK_OFFSET)
    fields = {
        "type_name": "bool",
        "bool_byte_offset": byte_offset,
        "bool_field_mask": "0x%02x" % field_mask,
        "is_bitfield": field_mask != FBOOLPROPERTY_FULL_BYTE_FIELD_MASK,
    }
    note = None
    if field_mask not in (byte_mask, FBOOLPROPERTY_FULL_BYTE_FIELD_MASK):
        note = (
            "FBoolProperty invariant violated at 0x%x: FieldMask (0x%02x, "
            "FieldSize=%d) is neither ByteMask (0x%02x) nor 0xff -- "
            "UnrealType.h:2388's own documented invariant does not hold "
            "here; the raw reading above is still reported as-is." %
            (field_ptr, field_mask, field_size, byte_mask))
    return fields, note


def _decode_object_property(api, handle: int, field_ptr: int, *,
                            namepool_live_va: int, objects_by_address: dict | None) -> tuple:
    """FObjectPropertyBase::PropertyClass (UnrealType.h:2536), +0x70."""
    property_class_ptr = _read_u64(api, handle, field_ptr + FOBJECTPROPERTY_PROPERTY_CLASS_OFFSET)
    resolved = _resolve_uobject_handle_name(
        api, handle, property_class_ptr, namepool_live_va=namepool_live_va,
        objects_by_address=objects_by_address)
    fields = {"class_name": resolved["name"]}
    note = None if resolved["name"] is not None else (
        "FObjectProperty::PropertyClass at 0x%x could not be resolved to a "
        "name: %s" % (property_class_ptr, resolved["note"]))
    return fields, note


def _decode_class_property(api, handle: int, field_ptr: int, *,
                           namepool_live_va: int, objects_by_address: dict | None) -> tuple:
    """FClassProperty (UnrealType.h:3184) : public FObjectProperty --
    PropertyClass at +0x70 (inherited, resolved identically to
    _decode_object_property()) plus MetaClass at +0x78 (UnrealType.h:3189),
    decoded as a bonus and folded into 'notes' only (reflection-record.
    schema.json's property_record has no dedicated meta_class field -- see
    the module docstring's "WHAT I-06 IS" section)."""
    property_class_ptr = _read_u64(api, handle, field_ptr + FOBJECTPROPERTY_PROPERTY_CLASS_OFFSET)
    meta_class_ptr = _read_u64(api, handle, field_ptr + FCLASSPROPERTY_META_CLASS_OFFSET)
    resolved = _resolve_uobject_handle_name(
        api, handle, property_class_ptr, namepool_live_va=namepool_live_va,
        objects_by_address=objects_by_address)
    meta_resolved = _resolve_uobject_handle_name(
        api, handle, meta_class_ptr, namepool_live_va=namepool_live_va,
        objects_by_address=objects_by_address)
    fields = {"class_name": resolved["name"]}
    notes = []
    if resolved["name"] is None:
        notes.append("FClassProperty::PropertyClass at 0x%x could not be "
                     "resolved: %s" % (property_class_ptr, resolved["note"]))
    if meta_resolved["name"] is not None:
        notes.append("MetaClass=%r (0x%x)" % (meta_resolved["name"], meta_class_ptr))
    else:
        notes.append("MetaClass at 0x%x could not be resolved: %s" %
                     (meta_class_ptr, meta_resolved["note"]))
    return fields, "; ".join(notes)


def _decode_struct_property(api, handle: int, field_ptr: int, *,
                            namepool_live_va: int, objects_by_address: dict | None) -> tuple:
    """FStructProperty (UnrealType.h:6019) -- Struct at +0x70. Does NOT
    recurse into the referenced UScriptStruct's own ChildProperties (out of
    scope for this pass, see the module docstring's "WHAT I-06 IS" section)
    -- only its own raw_name is recorded."""
    struct_ptr = _read_u64(api, handle, field_ptr + FSTRUCTPROPERTY_STRUCT_OFFSET)
    resolved = _resolve_uobject_handle_name(
        api, handle, struct_ptr, namepool_live_va=namepool_live_va,
        objects_by_address=objects_by_address)
    fields = {"struct_name": resolved["name"]}
    note = None if resolved["name"] is not None else (
        "FStructProperty::Struct at 0x%x could not be resolved: %s" %
        (struct_ptr, resolved["note"]))
    return fields, note


def _decode_enum_property(api, handle: int, field_ptr: int, *,
                          namepool_live_va: int, objects_by_address: dict | None,
                          max_superclass_depth: int, max_container_depth: int,
                          container_depth: int) -> tuple:
    """FEnumProperty (EnumProperty.h:28 -- NOT UnrealType.h, a genuine
    location surprise found this session) -- UnderlyingProp at +0x70
    (EnumProperty.h:118, a NESTED FField, decoded recursively via THIS SAME
    decode_property_type() -- architecturally a numeric leaf with 0 extra
    fields itself, per the module docstring) and Enum at +0x78
    (EnumProperty.h:119, resolved the same way as struct_name/class_name).
    UnderlyingProp is decoded for STRUCTURAL VALIDATION/completeness only --
    reflection-record.schema.json's property_record has no dedicated field
    for it (an FEnumProperty's own ElementSize, already captured as this
    property's own 'size', already carries the underlying width); a failed
    UnderlyingProp decode is folded into 'notes', never treated as
    invalidating the Enum property's OWN enum_name/base fields."""
    underlying_ptr = _read_u64(api, handle, field_ptr + FENUMPROPERTY_UNDERLYING_PROP_OFFSET)
    enum_ptr = _read_u64(api, handle, field_ptr + FENUMPROPERTY_ENUM_OFFSET)
    resolved = _resolve_uobject_handle_name(
        api, handle, enum_ptr, namepool_live_va=namepool_live_va,
        objects_by_address=objects_by_address)
    fields = {"enum_name": resolved["name"]}
    notes = []
    if resolved["name"] is None:
        notes.append("FEnumProperty::Enum at 0x%x could not be resolved: %s" %
                     (enum_ptr, resolved["note"]))
    underlying_decoded = decode_property_type(
        api, handle, underlying_ptr, namepool_live_va=namepool_live_va,
        objects_by_address=objects_by_address,
        max_superclass_depth=max_superclass_depth,
        max_container_depth=max_container_depth, container_depth=container_depth + 1)
    if underlying_decoded["valid"]:
        notes.append("UnderlyingProp=%s at 0x%x" %
                     (underlying_decoded["property_class"], underlying_ptr))
    else:
        notes.append("UnderlyingProp at 0x%x did not decode as a valid "
                     "FProperty: %s" % (underlying_ptr, underlying_decoded["rejection_reason"]))
    return fields, "; ".join(notes)


def _decode_array_property(api, handle: int, field_ptr: int, *,
                           namepool_live_va: int, objects_by_address: dict | None,
                           max_superclass_depth: int, max_container_depth: int,
                           container_depth: int) -> tuple:
    """FArrayProperty (UnrealType.h:3571) -- Inner at +0x78 (7 bytes padding
    after ArrayFlags at +0x70, which I-06 does not read). Inner is a full
    nested FField/FProperty object elsewhere in memory, decoded recursively
    via THIS SAME decode_property_type() and reduced to the schema's own
    property_type_ref shape (_to_property_type_ref()) for the 'inner' field."""
    inner_ptr = _read_u64(api, handle, field_ptr + FARRAYPROPERTY_INNER_OFFSET)
    inner_decoded = decode_property_type(
        api, handle, inner_ptr, namepool_live_va=namepool_live_va,
        objects_by_address=objects_by_address,
        max_superclass_depth=max_superclass_depth,
        max_container_depth=max_container_depth, container_depth=container_depth + 1)
    fields = {"inner": _to_property_type_ref(inner_decoded), "type_name": "TArray"}
    note = None if inner_decoded["valid"] else (
        "FArrayProperty::Inner at 0x%x did not decode as a valid FProperty: "
        "%s" % (inner_ptr, inner_decoded["rejection_reason"]))
    return fields, note


def _decode_set_property(api, handle: int, field_ptr: int, *,
                         namepool_live_va: int, objects_by_address: dict | None,
                         max_superclass_depth: int, max_container_depth: int,
                         container_depth: int) -> tuple:
    """FSetProperty (UnrealType.h:3885) -- ElementProp at +0x70 (SetLayout at
    +0x78, FScriptSetLayout, is not read -- not required by the schema).
    Emitted as the schema's own 'inner' field (per reflection-record.
    schema.json's own description: "the Inner of an FArrayProperty or
    FSetProperty"), identically to FArrayProperty's own Inner above."""
    element_ptr = _read_u64(api, handle, field_ptr + FSETPROPERTY_ELEMENT_PROP_OFFSET)
    element_decoded = decode_property_type(
        api, handle, element_ptr, namepool_live_va=namepool_live_va,
        objects_by_address=objects_by_address,
        max_superclass_depth=max_superclass_depth,
        max_container_depth=max_container_depth, container_depth=container_depth + 1)
    fields = {"inner": _to_property_type_ref(element_decoded), "type_name": "TSet"}
    note = None if element_decoded["valid"] else (
        "FSetProperty::ElementProp at 0x%x did not decode as a valid "
        "FProperty: %s" % (element_ptr, element_decoded["rejection_reason"]))
    return fields, note


def _decode_map_property(api, handle: int, field_ptr: int, *,
                         namepool_live_va: int, objects_by_address: dict | None,
                         max_superclass_depth: int, max_container_depth: int,
                         container_depth: int) -> tuple:
    """FMapProperty (UnrealType.h:3721) -- KeyProp at +0x70, ValueProp at
    +0x78 (MapLayout at +0x80/MapFlags at +0x98 are not read -- not required
    by the schema). Emitted as the schema's own 'key_type'/'value_type'
    fields."""
    key_ptr = _read_u64(api, handle, field_ptr + FMAPPROPERTY_KEY_PROP_OFFSET)
    value_ptr = _read_u64(api, handle, field_ptr + FMAPPROPERTY_VALUE_PROP_OFFSET)
    key_decoded = decode_property_type(
        api, handle, key_ptr, namepool_live_va=namepool_live_va,
        objects_by_address=objects_by_address,
        max_superclass_depth=max_superclass_depth,
        max_container_depth=max_container_depth, container_depth=container_depth + 1)
    value_decoded = decode_property_type(
        api, handle, value_ptr, namepool_live_va=namepool_live_va,
        objects_by_address=objects_by_address,
        max_superclass_depth=max_superclass_depth,
        max_container_depth=max_container_depth, container_depth=container_depth + 1)
    fields = {
        "key_type": _to_property_type_ref(key_decoded),
        "value_type": _to_property_type_ref(value_decoded),
        "type_name": "TMap",
    }
    notes = []
    if not key_decoded["valid"]:
        notes.append("FMapProperty::KeyProp at 0x%x did not decode as a "
                     "valid FProperty: %s" % (key_ptr, key_decoded["rejection_reason"]))
    if not value_decoded["valid"]:
        notes.append("FMapProperty::ValueProp at 0x%x did not decode as a "
                     "valid FProperty: %s" % (value_ptr, value_decoded["rejection_reason"]))
    return fields, "; ".join(notes)


def _to_property_type_ref(decoded: dict | None) -> dict | None:
    """Reduces a decode_property_type() result to reflection-record.
    schema.json's own property_type_ref shape (property_class, type_name,
    size, struct_name, enum_name, class_name, inner) -- used to embed a
    container's element type (FArrayProperty/FSetProperty's own Inner,
    FMapProperty's own KeyProp/ValueProp) inside its OWNING property_record.
    property_type_ref's own schema closes with additionalProperties: false,
    so every OTHER decode_property_type() field ('valid', 'rejection_kind',
    'owner_raw', 'notes', 'next_ptr', ...) is deliberately dropped here --
    those are this capability's own internal bookkeeping, never part of the
    committed schema shape.

    Returns None when *decoded* is None or was not a valid FProperty-derived
    decode -- an invalid/unreadable Inner/KeyProp/ValueProp is reported via
    the OWNING property's own 'notes' field (see each _decode_*_property()
    helper above), never invented as a fabricated property_type_ref.
    """
    if decoded is None or not decoded["valid"]:
        return None
    return {
        "property_class": decoded["property_class"],
        "type_name": decoded["type_name"],
        "size": decoded["size"],
        "struct_name": decoded["struct_name"],
        "enum_name": decoded["enum_name"],
        "class_name": decoded["class_name"],
        "inner": decoded["inner"],
    }


def decode_property_type(api, handle: int, field_ptr: int, *, namepool_live_va: int,
                         objects_by_address: dict | None = None,
                         max_superclass_depth: int = DEFAULT_I06_MAX_SUPERCLASS_DEPTH,
                         max_container_depth: int = DEFAULT_I06_MAX_CONTAINER_NESTING_DEPTH,
                         container_depth: int = 0) -> dict:
    """Decodes ONE FField-derived object given ONLY its own address --
    nothing about "is this on a UStruct's ChildProperties chain" is baked
    in anywhere below, DELIBERATELY (see the module docstring's "REUSE,
    EXPLICITLY" paragraph): this is what lets walk_property_chain() below
    and every one of the six container-nesting helpers above
    (_decode_array_property/_decode_set_property/_decode_map_property/
    _decode_enum_property, all four of which call THIS function recursively
    for their own Inner/ElementProp/KeyProp+ValueProp/UnderlyingProp) share
    ONE decoder, and lets a FUTURE capability (I-05, a UFunction's own
    parameter list -- explicitly out of scope for this pass) reuse it too,
    without this function ever needing to know either caller exists.

    ALGORITHM (the module's own "Traversal algorithm" steps 1-3 and 5-7;
    step 4, the Owner ROUND-TRIP validation against a specific expected
    owner address, is deliberately NOT done here -- this function has no
    way to know what that expected address should be for a nested Inner/
    KeyProp/ValueProp/UnderlyingProp call, only walk_property_chain() below,
    which DOES know the owning class's own address, performs it):
      1. *field_ptr* itself must be a plausible (non-null, 8-byte-aligned)
         address (_pointer_is_plausible(), reused from I-04) -- rejected
         BEFORE any read is attempted, exactly like I-04's own check 1.
      2. Read ClassPrivate/Owner/Next/NamePrivate's own FNameEntryId in ONE
         batch (cheap, and Next/Owner are needed regardless of what happens
         next -- see walk_property_chain()'s own docstring for why having
         Next available even when a LATER check rejects this node matters).
         A read failure on this batch is this node's own foundational read
         failure (see the module docstring's "THE 'ALL OR NOTHING' WRITE
         GUARANTEE" section for why this mirrors I-04's per-object
         precedent, not I-02's/I-03's foundational-single-read one) --
         converted to rejection_kind='read_failure', never propagated.
      3. ClassPrivate must be a plausible pointer (step 2's own rule, mirrored
         for FFieldClass -- no vtable check, see FFIELDCLASS_NAME_OFFSET's
         own comment above for why).
      4. Resolve FFieldClass::Name and walk its own SuperClass chain
         (_walk_fieldclass_super_chain()) -- a chain-walk FAILURE (cycle,
         exceeded depth, a read/decode failure mid-chain -- "we could not
         determine") is rejection_kind='superclass_chain_failure'; a chain
         that resolves COMPLETELY but never includes "FProperty"
         ("we determined it is NOT one") is rejection_kind='not_a_property'
         -- two DIFFERENT findings, never conflated (mirrors I-02's/I-03's
         own "tool malfunction vs structural refutation" split, applied at
         field-decode granularity).
      5. Decode FField::NamePrivate (I-03's own decode_fname_entry_id(),
         reused) -> raw_name. A decode error here is rejection_kind=
         'name_decode'.
      6. Read FProperty's own base fields (+0x30..+0x6F): ArrayDim,
         ElementSize, PropertyFlags, RepIndex, Offset_Internal,
         RepNotifyFunc. RepNotifyFunc is decoded via decode_fname_entry_id()
         too; when its own FNameEntryId decodes to the literal text "None"
         (the CONFIRMED id==0 mapping I-03/RF-06 already established, see
         decode_fname_entry_id()'s own module docstring citation -- NOT a
         newly-invented sentinel), or when it fails to decode at all (a
         property with CPF_RepNotify unset ordinarily has RepNotifyFunc
         zero-initialized, i.e. NAME_None, so a decode error here is
         peripheral, non-fatal metadata, not core identity), rep_notify_func
         is left null and, on an actual decode ERROR only, a note is
         recorded -- "no RepNotify function" is never itself worth a note,
         matching decode_fname_entry_id()'s own "empty is not evidence of
         anything wrong" convention.
      7. Dispatch on the FFieldClass name string (exact match against the
         12 named types, OR "is a descendant of FNumericProperty" for the
         generic numeric leaf case) to read type-specific fields -- see each
         _decode_*_property() helper above.

    NEVER raises ReadProcessMemoryFailedError itself -- every read failure
    anywhere in this function (the base FField batch, the FProperty base
    fields, a type-specific dispatch read) is caught and converted into
    rejection_kind='read_failure', for the SAME reason
    _walk_fieldclass_super_chain() above never propagates one: every read
    this function makes is on an ALREADY-LOCATED candidate (mirrors I-04's
    established precedent; see the module docstring's own "THE 'ALL OR
    NOTHING' WRITE GUARANTEE" section for the full reasoning).

    A STRUCTURALLY-IMPLAUSIBLE-BUT-SUCCESSFULLY-READ value is DATA, never
    raised: every rejection path below returns a plain dict with
    'valid': False and an explanatory 'rejection_kind'/'rejection_reason',
    exactly like I-04's own _classify_object().

    Returns a dict, ALWAYS shaped the same way regardless of which check
    failed or succeeded (callers never need to special-case a missing key):
    {'valid' (bool), 'rejection_kind' (str | None, one of
    'container_depth_exceeded'/'pointer_alignment'/'read_failure'/
    'class_pointer_implausible'/'superclass_chain_failure'/'not_a_property'/
    'name_decode', or None when valid), 'rejection_reason' (str | None),
    'address_hex' (str), 'raw_name' (str | None), 'property_class'
    (str | None -- the FFieldClass::Name, only set once step 4 succeeds),
    'array_dim'/'size'/'total_size'/'offset' (int | None),
    'property_flags_raw' (str | None, '0x...' hex text), 'rep_index'
    (int | None), 'rep_notify_func' (str | None), 'type_name' (str | None),
    'bool_byte_offset'/'bool_field_mask'/'is_bitfield' (FBoolProperty only,
    else None), 'struct_name'/'enum_name'/'class_name' (str | None),
    'inner'/'key_type'/'value_type' (dict | None, ALREADY property_type_ref-
    shaped via _to_property_type_ref() when set -- never the full internal
    decode dict), 'owner_raw' (int | None, the RAW un-decoded 8-byte
    FFieldVariant value), 'owner_is_uobject' (bool | None),
    'owner_address' (int | None, the DECODED/untagged address --
    walk_property_chain() below is what actually validates this against an
    expected owner, this function only ever reads and decodes it),
    'next_ptr' (int | None -- set as soon as step 2's own batch read
    succeeds, REGARDLESS of whether a LATER step then rejects this node;
    see walk_property_chain()'s own docstring for why this matters),
    'notes' (list[str], internal bookkeeping -- joined into one string by
    the caller that builds a property_record; NOT itself a schema field)}.
    """
    record = {
        "valid": False, "rejection_kind": None, "rejection_reason": None,
        "address_hex": "0x%x" % field_ptr,
        "raw_name": None, "property_class": None,
        "array_dim": None, "size": None, "total_size": None, "offset": None,
        "property_flags_raw": None, "rep_index": None, "rep_notify_func": None,
        "type_name": None, "bool_byte_offset": None, "bool_field_mask": None,
        "is_bitfield": None, "struct_name": None, "enum_name": None,
        "class_name": None, "inner": None, "key_type": None, "value_type": None,
        "owner_raw": None, "owner_is_uobject": None, "owner_address": None,
        "next_ptr": None, "notes": [],
    }

    if container_depth > max_container_depth:
        record["rejection_kind"] = "container_depth_exceeded"
        record["rejection_reason"] = (
            "container nesting exceeded max_container_depth=%d at 0x%x" %
            (max_container_depth, field_ptr))
        return record

    # Step 1.
    if not _pointer_is_plausible(field_ptr):
        record["rejection_kind"] = "pointer_alignment"
        record["rejection_reason"] = (
            "FField pointer 0x%x is not a plausible (non-null, 8-byte-"
            "aligned) address" % field_ptr)
        return record

    # Step 2.
    try:
        class_ptr = _read_u64(api, handle, field_ptr + FFIELD_CLASS_PRIVATE_OFFSET)
        owner_raw = _read_u64(api, handle, field_ptr + FFIELD_OWNER_OFFSET)
        next_ptr = _read_u64(api, handle, field_ptr + FFIELD_NEXT_OFFSET)
        name_entry_id = _read_u32(api, handle, field_ptr + FFIELD_NAME_PRIVATE_OFFSET)
    except ReadProcessMemoryFailedError as error:
        record["rejection_kind"] = "read_failure"
        record["rejection_reason"] = (
            "read failure on FField base fields at 0x%x: %s" % (field_ptr, error))
        return record

    owner_decoded = _decode_ffield_owner(owner_raw)
    record["owner_raw"] = owner_raw
    record["owner_is_uobject"] = owner_decoded["is_uobject"]
    record["owner_address"] = owner_decoded["address"]
    record["next_ptr"] = next_ptr

    # Step 3.
    if not _pointer_is_plausible(class_ptr):
        record["rejection_kind"] = "class_pointer_implausible"
        record["rejection_reason"] = (
            "FField::ClassPrivate 0x%x is not a plausible (non-null, "
            "8-byte-aligned) address" % class_ptr)
        return record

    # Step 4.
    chain = _walk_fieldclass_super_chain(
        api, handle, class_ptr, namepool_live_va=namepool_live_va,
        max_depth=max_superclass_depth)
    if not chain["ok"]:
        record["rejection_kind"] = "superclass_chain_failure"
        record["rejection_reason"] = chain["note"]
        return record

    # chain["names"] holds the RAW, F-STRIPPED strings FFieldClass::Name
    # actually stores at runtime (Field.cpp:46-61's own "Skip the 'F' prefix
    # for the name" -- see FFIELDCLASS_NAME_PROPERTY's own comment above);
    # *property_class* (bare) is what every dispatch comparison below uses.
    # The OUTPUT record's own 'property_class' field, and every human-
    # readable message built from it, reconstructs the canonical F-prefixed
    # C++ type name ("FBoolProperty", matching reflection-record.schema.
    # json's own property_class field examples) by prepending "F" back --
    # an operation the SAME constructor invariant (InCPPName[0] must be 'F')
    # guarantees is always exactly reversible, never a guess.
    property_class = chain["names"][0]
    canonical_property_class = "F" + property_class
    record["property_class"] = canonical_property_class
    if FFIELDCLASS_NAME_PROPERTY not in chain["names"]:
        canonical_chain = " -> ".join("F" + n for n in chain["names"])
        record["rejection_kind"] = "not_a_property"
        record["rejection_reason"] = (
            "FFieldClass %r's own SuperClass chain (%s) never reaches %r "
            "-- this FField is not an FProperty-derived object" %
            (canonical_property_class, canonical_chain, "F" + FFIELDCLASS_NAME_PROPERTY))
        return record

    # Step 5.
    decoded_name = decode_fname_entry_id(api, handle, namepool_live_va, name_entry_id)
    if decoded_name["decode_error"] is not None:
        record["rejection_kind"] = "name_decode"
        record["rejection_reason"] = (
            "FField::NamePrivate decode error at 0x%x: %s" %
            (field_ptr, decoded_name["decode_error"]))
        return record
    record["raw_name"] = decoded_name["text"]

    # Step 6.
    try:
        array_dim = _read_i32(api, handle, field_ptr + FPROPERTY_ARRAY_DIM_OFFSET)
        element_size = _read_i32(api, handle, field_ptr + FPROPERTY_ELEMENT_SIZE_OFFSET)
        property_flags = _read_u64(api, handle, field_ptr + FPROPERTY_PROPERTY_FLAGS_OFFSET)
        rep_index = _read_u16(api, handle, field_ptr + FPROPERTY_REP_INDEX_OFFSET)
        offset_internal = _read_i32(api, handle, field_ptr + FPROPERTY_OFFSET_INTERNAL_OFFSET)
        rep_notify_func_id = _read_u32(api, handle, field_ptr + FPROPERTY_REP_NOTIFY_FUNC_OFFSET)
    except ReadProcessMemoryFailedError as error:
        record["rejection_kind"] = "read_failure"
        record["rejection_reason"] = (
            "read failure on FProperty base fields at 0x%x: %s" % (field_ptr, error))
        return record

    record["array_dim"] = array_dim
    record["size"] = element_size
    record["total_size"] = element_size * array_dim
    record["offset"] = offset_internal
    record["property_flags_raw"] = "0x%x" % property_flags
    record["rep_index"] = rep_index

    rep_notify_decoded = decode_fname_entry_id(api, handle, namepool_live_va, rep_notify_func_id)
    if rep_notify_decoded["decode_error"] is not None:
        record["notes"].append(
            "RepNotifyFunc FNameEntryId 0x%x failed to decode: %s" %
            (rep_notify_func_id, rep_notify_decoded["decode_error"]))
    elif rep_notify_decoded["text"] != "None":
        record["rep_notify_func"] = rep_notify_decoded["text"]
    # else: NAME_None (the confirmed id==0 -> "None" mapping, I-03/RF-06) --
    # "no RepNotify function", left null, no note (matches decode_fname_
    # entry_id()'s own "empty/none is not evidence of anything wrong"
    # convention -- this is not a newly-invented sentinel).

    # Step 7: dispatch.
    try:
        if property_class == FFIELDCLASS_NAME_BOOLPROPERTY:
            fields, note = _decode_bool_property(api, handle, field_ptr)
        elif property_class == FFIELDCLASS_NAME_CLASSPROPERTY:
            fields, note = _decode_class_property(
                api, handle, field_ptr, namepool_live_va=namepool_live_va,
                objects_by_address=objects_by_address)
        elif property_class == FFIELDCLASS_NAME_OBJECTPROPERTY:
            fields, note = _decode_object_property(
                api, handle, field_ptr, namepool_live_va=namepool_live_va,
                objects_by_address=objects_by_address)
        elif property_class == FFIELDCLASS_NAME_STRUCTPROPERTY:
            fields, note = _decode_struct_property(
                api, handle, field_ptr, namepool_live_va=namepool_live_va,
                objects_by_address=objects_by_address)
        elif property_class == FFIELDCLASS_NAME_ENUMPROPERTY:
            fields, note = _decode_enum_property(
                api, handle, field_ptr, namepool_live_va=namepool_live_va,
                objects_by_address=objects_by_address,
                max_superclass_depth=max_superclass_depth,
                max_container_depth=max_container_depth, container_depth=container_depth)
        elif property_class == FFIELDCLASS_NAME_ARRAYPROPERTY:
            fields, note = _decode_array_property(
                api, handle, field_ptr, namepool_live_va=namepool_live_va,
                objects_by_address=objects_by_address,
                max_superclass_depth=max_superclass_depth,
                max_container_depth=max_container_depth, container_depth=container_depth)
        elif property_class == FFIELDCLASS_NAME_SETPROPERTY:
            fields, note = _decode_set_property(
                api, handle, field_ptr, namepool_live_va=namepool_live_va,
                objects_by_address=objects_by_address,
                max_superclass_depth=max_superclass_depth,
                max_container_depth=max_container_depth, container_depth=container_depth)
        elif property_class == FFIELDCLASS_NAME_MAPPROPERTY:
            fields, note = _decode_map_property(
                api, handle, field_ptr, namepool_live_va=namepool_live_va,
                objects_by_address=objects_by_address,
                max_superclass_depth=max_superclass_depth,
                max_container_depth=max_container_depth, container_depth=container_depth)
        elif property_class == FFIELDCLASS_NAME_NAMEPROPERTY:
            fields, note = {"type_name": "FName"}, None
        elif property_class == FFIELDCLASS_NAME_STRPROPERTY:
            fields, note = {"type_name": "FString"}, None
        elif property_class == FFIELDCLASS_NAME_TEXTPROPERTY:
            fields, note = {"type_name": "FText"}, None
        elif FFIELDCLASS_NAME_NUMERICPROPERTY in chain["names"]:
            # every numeric leaf (FIntProperty, FFloatProperty, FByteProperty,
            # FDoubleProperty, FInt8/16/64Property, FUInt16/32/64Property,
            # FLargeWorldCoordinatesRealProperty, ...) -- architecturally 0
            # extra fields beyond FProperty itself (module docstring). No
            # type_name: property_class already carries the precise type,
            # and a "pretty name" cannot be derived losslessly from the
            # FFieldClass name string alone (correctness over guessing).
            fields, note = {}, None
        else:
            fields, note = {}, (
                "property_class %r has no type-specific decoder in this "
                "I-06 pass (in scope: FBoolProperty/FObjectProperty/"
                "FClassProperty/FStructProperty/FEnumProperty/FArrayProperty/"
                "FSetProperty/FMapProperty/FNameProperty/FStrProperty/"
                "FTextProperty/every FNumericProperty descendant) -- base "
                "FProperty fields only" % canonical_property_class)
    except ReadProcessMemoryFailedError as error:
        record["rejection_kind"] = "read_failure"
        record["rejection_reason"] = (
            "read failure decoding %r-specific fields at 0x%x: %s" %
            (canonical_property_class, field_ptr, error))
        return record

    record.update(fields)
    if note:
        record["notes"].append(note)

    record["valid"] = True
    return record


def walk_property_chain(api, handle: int, child_properties_ptr: int, *,
                        namepool_live_va: int, owner_address: int,
                        objects_by_address: dict | None = None,
                        max_chain_length: int = DEFAULT_I06_MAX_PROPERTY_CHAIN_LENGTH,
                        max_superclass_depth: int = DEFAULT_I06_MAX_SUPERCLASS_DEPTH,
                        max_container_depth: int = DEFAULT_I06_MAX_CONTAINER_NESTING_DEPTH
                        ) -> dict:
    """Walks ONE UStruct's own ChildProperties/Next-linked FField sibling
    chain, decoding each node via decode_property_type() above and applying
    the ONE validation decode_property_type() itself deliberately does not
    (its own docstring, step 4): the OWNER ROUND-TRIP -- a top-level
    ChildProperties entry's own FField::Owner MUST decode as a UObject*
    (tag bit 1) whose masked address equals *owner_address* (the owning
    class's OWN address, i.e. this is a genuine self-consistency invariant
    of THIS class's own property chain, not merely "some Owner value is
    present"). A node failing this check is counted ('owner_mismatch') and
    documented, never silently trusted into the accepted list -- the SAME
    "structural refutation is data" discipline as every other rejection
    kind in this file.

    *child_properties_ptr* == 0 is a VALID, legitimate "this class declares
    zero of its own properties" result -- returns immediately with an empty
    'accepted' list and 'ok': True, never treated as an error (mirrors
    walk_object_universe()'s own "a freed/never-allocated slot" non-error
    precedent, applied to the one-time null-ChildProperties case instead).

    BOUNDED (*max_chain_length* siblings) and CYCLE-PROTECTED (an address
    repeating within THIS ONE class's own chain walk is a traversal failure)
    -- mirrors resolve_object_path()'s own Outer-chain walk exactly.
    Crucially, a REJECTED node (decode_property_type() returned
    'valid': False, OR the Owner round-trip failed) does NOT by itself abort
    the walk: as long as decode_property_type() managed to read the node's
    own Next pointer (its own 'next_ptr' is set as soon as step 2 of ITS OWN
    algorithm succeeds, REGARDLESS of what a later step then decides -- see
    decode_property_type()'s own docstring), the walk continues past it,
    counting the rejection and moving on -- exactly the module docstring's
    own "count it, document the reason, do not crash, do not silently skip
    without accounting" rule for a SuperClass-chain rejection, applied here
    at the sibling-chain level too. The walk can ONLY be aborted by a node
    whose own Next was never even read (rejected at decode_property_type()'s
    own step 1 or step 2) -- there is no address left to continue from.

    Returns {'accepted': list[dict] (decode_property_type() results, in
    chain order, EVERY entry 'valid'==True AND Owner-round-tripped -- this
    list's own 0-based enumeration IS the ordinal the caller assigns; a
    rejected node consumes NO ordinal slot, per the module's own algorithm
    step 8), 'nodes_visited' (int, every node the walk actually reached,
    accepted or not), 'rejected_counts' (dict[str, int], one entry per
    rejection_kind PLUS 'owner_mismatch'), 'ok' (bool -- False only for an
    actual traversal FAILURE: cycle, an unreadable first node, or exceeded
    max_chain_length -- never False merely because SOME nodes were
    rejected), 'note' (str | None)}.
    """
    rejected_counts: dict = {}
    accepted: list = []

    if child_properties_ptr == 0:
        return {"accepted": accepted, "nodes_visited": 0,
                "rejected_counts": rejected_counts, "ok": True, "note": None}

    visited: set = set()
    address = child_properties_ptr
    nodes_visited = 0

    for _ in range(max_chain_length):
        if address in visited:
            return {"accepted": accepted, "nodes_visited": nodes_visited,
                    "rejected_counts": rejected_counts, "ok": False,
                    "note": "cycle detected in FField::Next chain at 0x%x" % address}
        visited.add(address)
        nodes_visited += 1

        decoded = decode_property_type(
            api, handle, address, namepool_live_va=namepool_live_va,
            objects_by_address=objects_by_address,
            max_superclass_depth=max_superclass_depth,
            max_container_depth=max_container_depth, container_depth=0)

        if decoded["valid"]:
            if decoded["owner_is_uobject"] and decoded["owner_address"] == owner_address:
                accepted.append(decoded)
            else:
                rejected_counts["owner_mismatch"] = rejected_counts.get("owner_mismatch", 0) + 1
        else:
            kind = decoded["rejection_kind"]
            rejected_counts[kind] = rejected_counts.get(kind, 0) + 1

        next_ptr = decoded["next_ptr"]
        if next_ptr is None:
            return {"accepted": accepted, "nodes_visited": nodes_visited,
                    "rejected_counts": rejected_counts, "ok": False,
                    "note": (
                        "chain walk aborted at 0x%x: this node's own Next "
                        "pointer was never read (rejected before the base "
                        "FField field batch could be read) -- %s" %
                        (address, decoded["rejection_reason"]))}
        if next_ptr == 0:
            return {"accepted": accepted, "nodes_visited": nodes_visited,
                    "rejected_counts": rejected_counts, "ok": True, "note": None}
        address = next_ptr
    else:
        return {"accepted": accepted, "nodes_visited": nodes_visited,
                "rejected_counts": rejected_counts, "ok": False,
                "note": "FField::Next chain exceeded max_chain_length (%d) "
                        "without terminating" % max_chain_length}


def select_i06_engine_proof_classes(all_classes: list, *,
                                    cap: int = DEFAULT_I06_PROOF_SET_ENGINE_CLASS_CAP) -> list:
    """A small, deterministic, name-preference-ordered selection of
    well-known engine classes from *all_classes* -- run_i04()'s OWN full
    'classes' list (every classified UClass instance THIS run's own walk
    found, not merely the /Script/MISERY+/Game subset build_i04_document()
    ever WRITES to classes.jsonl) -- for I-06's proof set. A PURE, in-memory
    filter: this function never reads process memory itself and never
    triggers a new GUObjectArray walk.

    Searched in I06_ENGINE_CLASS_NAME_PREFERENCE's own listed order (every
    occurrence of "Object" considered before ever looking for "Actor", not
    scan order), so the result is REPRODUCIBLE across two runs against the
    same live process regardless of which name happened to appear earlier
    in this run's own GUObjectArray walk. Stops once *cap* classes are found
    or the preference list is exhausted. A well-known name this specific
    build does not have (should not normally happen for any of these seven
    -- all core Engine/CoreUObject types -- but is not itself an error) is
    simply skipped; the caller's own report states exactly which ones WERE
    found, never treats a miss as a failure.
    """
    by_name: dict = {}
    for entry in all_classes:
        name = entry["raw_name"]
        if name not in by_name:  # first occurrence in scan order wins.
            by_name[name] = entry

    selected = []
    for name in I06_ENGINE_CLASS_NAME_PREFERENCE:
        if len(selected) >= cap:
            break
        entry = by_name.get(name)
        if entry is not None:
            selected.append(entry)
    return selected


def select_i06_proof_set(*, misery_classes: list, game_sample: list, all_classes: list,
                         engine_class_cap: int = DEFAULT_I06_PROOF_SET_ENGINE_CLASS_CAP
                         ) -> list:
    """The complete I-06 proof set (module docstring's "PROOF-SET-FIRST, NOT
    A FULL DUMP" section): every /Script/MISERY class (I-04's own 'misery'
    bucket, in full -- never capped) + I-04's own already-bounded /Game
    sample (game_sample -- ALREADY capped by --i04-game-sample-cap; this
    function does not re-select or re-cap it) + up to *engine_class_cap*
    well-known engine classes (select_i06_engine_proof_classes() above).
    Deterministic and reproducible: every input is itself already a
    deterministic, in-memory selection over data I-04 already validated in
    THIS SAME run -- this function triggers NO new GUObjectArray read.

    De-duplicates by address (architecturally impossible for these three
    inputs to overlap -- misery_classes/game_sample are /Script/MISERY and
    /Game respectively, engine_classes are neither -- but a plain
    address-set guard costs nothing and keeps this function correct even if
    that invariant were ever violated by a future change to any of the
    three selectors).
    """
    engine_classes = select_i06_engine_proof_classes(all_classes, cap=engine_class_cap)
    seen: set = set()
    combined = []
    for entry in list(misery_classes) + list(game_sample) + engine_classes:
        if entry["address"] in seen:
            continue
        seen.add(entry["address"])
        combined.append(entry)
    return combined


def run_i06(api, process_handle: int, namepool_live_va: int,
           objects_by_address: dict | None, proof_set_classes: list, *,
           max_chain_length: int = DEFAULT_I06_MAX_PROPERTY_CHAIN_LENGTH,
           max_superclass_depth: int = DEFAULT_I06_MAX_SUPERCLASS_DEPTH,
           max_container_depth: int = DEFAULT_I06_MAX_CONTAINER_NESTING_DEPTH,
           child_properties_offset: int = USTRUCT_CHILD_PROPERTIES_OFFSET) -> dict:
    """The whole of capability I-06: for every class in *proof_set_classes*
    (select_i06_proof_set()'s own output -- I-04's already-classified,
    already-validated class list from THIS SAME run, never re-walked),
    read its own UStruct::ChildProperties (+0x50) and walk_property_chain()
    from there.

    *namepool_live_va* MUST be from THIS SAME run's own I-03 result, for the
    identical "reuse, never re-establish" reason run_i04() already
    documents for its own namepool_live_va parameter.

    A ChildProperties read failure for ONE class is recorded on that class's
    own entry ('child_properties_read_ok': False) and this function
    continues with the REMAINING classes in the proof set -- see the module
    docstring's own "THE 'ALL OR NOTHING' WRITE GUARANTEE" section for why
    this mirrors I-04's own per-object read-failure precedent (a torn read
    on an already-located, already-validated candidate) rather than I-02's/
    I-03's foundational-single-read one: each proof-set class's own
    ChildProperties field is independent memory, and one class's failure
    says nothing about any other class's own field.

    Never raises. Returns a plain dict: {'classes' (list[dict], one entry
    per *proof_set_classes* member, each {'class_address' (int),
    'class_raw_name' (str), 'object_path' (str | None),
    'child_properties_ptr_hex' (str | None), 'child_properties_read_ok'
    (bool), 'child_properties_read_error' (str | None), 'properties'
    (list[dict], walk_property_chain()'s own 'accepted' list -- full
    decode_property_type() dicts, NOT yet reduced to property_record shape;
    build_i06_property_record() does that per-entry, with the ordinal being
    this list's own 0-based position), 'nodes_visited' (int),
    'rejected_counts' (dict), 'chain_ok' (bool), 'chain_note' (str | None)}),
    'classes_examined' (int, len(proof_set_classes)),
    'properties_accepted_total' (int, sum of every class's own accepted
    count), 'rejected_counts_total' (dict, summed across every class)}.
    """
    classes_out = []
    total_accepted = 0
    total_rejected_counts: dict = {}

    for class_entry in proof_set_classes:
        class_address = class_entry["address"]
        try:
            child_properties_ptr = _read_u64(
                api, process_handle, class_address + child_properties_offset)
        except ReadProcessMemoryFailedError as error:
            classes_out.append({
                "class_address": class_address, "class_raw_name": class_entry["raw_name"],
                "object_path": class_entry.get("object_path"),
                "child_properties_ptr_hex": None,
                "child_properties_read_ok": False,
                "child_properties_read_error": str(error),
                "properties": [], "nodes_visited": 0, "rejected_counts": {},
                "chain_ok": False, "chain_note": None,
            })
            continue

        chain = walk_property_chain(
            api, process_handle, child_properties_ptr, namepool_live_va=namepool_live_va,
            owner_address=class_address, objects_by_address=objects_by_address,
            max_chain_length=max_chain_length, max_superclass_depth=max_superclass_depth,
            max_container_depth=max_container_depth)

        classes_out.append({
            "class_address": class_address, "class_raw_name": class_entry["raw_name"],
            "object_path": class_entry.get("object_path"),
            "child_properties_ptr_hex": "0x%x" % child_properties_ptr,
            "child_properties_read_ok": True, "child_properties_read_error": None,
            "properties": chain["accepted"], "nodes_visited": chain["nodes_visited"],
            "rejected_counts": chain["rejected_counts"],
            "chain_ok": chain["ok"], "chain_note": chain["note"],
        })
        total_accepted += len(chain["accepted"])
        for kind, count in chain["rejected_counts"].items():
            total_rejected_counts[kind] = total_rejected_counts.get(kind, 0) + count

    return {
        "classes": classes_out,
        "classes_examined": len(proof_set_classes),
        "properties_accepted_total": total_accepted,
        "rejected_counts_total": total_rejected_counts,
    }


def build_i06_document(*, result: dict, build_key: str, recorded_at: str | None,
                       identity_self_established: bool, build_key_cross_checked: bool,
                       known_build: bool, build_id: str | None) -> dict:
    """The I-06 raw output document -- research/instrument-runs/<run>/
    i06-properties.json, the SAME "raw single-run data document, no
    evidence envelope" shape as build_i01_document()/.../build_i04_document()
    (see build_i01_document()'s own docstring for the is_record()/
    MARKER_KEYS reasoning this mirrors verbatim). properties.jsonl (a
    SEPARATE artifact, built from run_i06()'s own 'classes'[*]['properties']
    entries via build_i06_property_record() and written by main()) is where
    the actual GRADED knowledge-base claims live; this document is this
    run's own bookkeeping/summary, one row per proof-set class, honest about
    every class whose own ChildProperties read failed or whose own chain
    walk did not fully complete ('chain_ok': False) -- never silently
    dropped from this summary even when it contributed zero properties.
    """
    return {
        "capability": CAPABILITY_ID_I06,
        "classes_examined": result["classes_examined"],
        "properties_accepted_total": result["properties_accepted_total"],
        "rejected_counts_total": result["rejected_counts_total"],
        "classes": [
            {
                "class_address_hex": "0x%x" % c["class_address"],
                "class_raw_name": c["class_raw_name"],
                "object_path": c["object_path"],
                "child_properties_ptr_hex": c["child_properties_ptr_hex"],
                "child_properties_read_ok": c["child_properties_read_ok"],
                "child_properties_read_error": c["child_properties_read_error"],
                "property_count": len(c["properties"]),
                "nodes_visited": c["nodes_visited"],
                "rejected_counts": c["rejected_counts"],
                "chain_ok": c["chain_ok"],
                "chain_note": c["chain_note"],
            }
            for c in result["classes"]
        ],
        "build_key": build_key,
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
    }


def build_i06_property_record(decoded: dict, *, owner: str, owner_kind: str,
                              ordinal: int, build_key: str, recorded_at: str) -> dict:
    """One properties.jsonl row (research/schema/reflection-record.schema.json's
    property_record branch) for ONE ACCEPTED top-level ChildProperties-chain
    entry -- *decoded* MUST be an already-valid, already-Owner-round-tripped
    decode_property_type() result (walk_property_chain() never places a
    rejected node in its own 'accepted' list, so this function never has to
    re-check 'valid' itself).

    CONFIDENCE IS ALWAYS 0.75, EVERY RECORD, NO EXCEPTION -- see the module
    docstring's own "CONFIDENCE HAS NO POSSIBLE CEILING ABOVE 0.79 FOR THIS
    CAPABILITY, EVER" section for the full reasoning this mirrors: research/
    reflection/misery-24826585-ue5.4.4-0eef3715244b/README.md's own "Почему
    properties.jsonl пуст -- и всегда будет пуст" section proves NO offline
    cross-check for a property record can EVER exist, for any build, because
    FProperty is not a UObject and cannot appear in the ScriptObjects chunk
    global.ucas is built from. Unlike build_i04_class_record()'s own
    MIX-SPLIT (0.90 cross-checked / 0.75 single-source), there is no
    "cross-checked" branch here at all -- every property record is
    single-source by the FORMAT's own construction, not by this run's own
    bad luck, so 0.75 (plan.md 10.2's own "one strong ... confirmation" band,
    0.60-0.79, near its own top) is not merely THIS record's grade, it is
    the entire capability's own permanent ceiling.

    Fields this pass deliberately leaves null (module docstring's "SCOPE,
    DELIBERATELY" section): cpp_type (no lossless C++ declaration
    reconstruction attempted), interface_name/function_signature (out of
    scope -- no FInterfaceProperty/FDelegateProperty/
    FMulticastDelegateProperty decoder in this pass), is_blueprint_visible/
    is_editable/is_transient/is_config (no individual EPropertyFlags bit
    decoding -- only the raw property_flags_raw hex word).
    """
    claim = (
        "the live MISERY-Win64-Shipping.exe process (build_key %s) has a "
        "property named %r (property_class %r) at ordinal %d of %s %r, "
        "byte offset %s, size %s" %
        (build_key, decoded["raw_name"], decoded["property_class"], ordinal,
         owner_kind, owner, decoded["offset"], decoded["size"]))
    notes = "; ".join(decoded["notes"]) if decoded["notes"] else None

    return {
        "kind": "property",
        "raw_name": decoded["raw_name"],
        "owner": owner,
        "owner_kind": owner_kind,
        "ordinal": ordinal,
        "ordinal_basis": "runtime-link-order",
        "offset": decoded["offset"],
        "size": decoded["size"],
        "array_dim": decoded["array_dim"],
        "total_size": decoded["total_size"],
        "property_class": decoded["property_class"],
        "type_name": decoded["type_name"],
        "cpp_type": None,
        "property_flags_raw": decoded["property_flags_raw"],
        "rep_index": decoded["rep_index"],
        "rep_notify_func": decoded["rep_notify_func"],
        "bool_byte_offset": decoded["bool_byte_offset"],
        "bool_field_mask": decoded["bool_field_mask"],
        "is_bitfield": decoded["is_bitfield"],
        "inner": decoded["inner"],
        "key_type": decoded["key_type"],
        "value_type": decoded["value_type"],
        "struct_name": decoded["struct_name"],
        "enum_name": decoded["enum_name"],
        "class_name": decoded["class_name"],
        "interface_name": None,
        "function_signature": None,
        "is_blueprint_visible": None,
        "is_editable": None,
        "is_transient": None,
        "is_config": None,
        "claim": claim,
        "claim_type": "class-property",
        "claim_class": "I",
        "evidence_level": "OBSERVED",
        "confidence": 0.75,
        "oracle": ["runtime-reflection"],
        "sources": [{
            "method": (
                "I-06: UStruct::ChildProperties chain walk (+0x%x) + "
                "FField/FProperty field reads (Field.h/UnrealType.h "
                "offsets) + FNamePool decode (I-03's own "
                "decode_fname_entry_id, reused) + FFieldClass::SuperClass "
                "chain walk for type dispatch" % USTRUCT_CHILD_PROPERTIES_OFFSET),
            "artifact": None,
            "locator": decoded["address_hex"],
            "note": (
                "oracle runtime-reflection. The address is this live "
                "FField/FProperty object's own address in THIS run's "
                "process -- not stable across a relaunch (ASLR/heap "
                "allocation), recorded only for this run's own audit trail."),
        }],
        "build_key": build_key,
        "recorded_at": recorded_at,
        "method": "I-06",
        "refutation_attempt": (
            "if this ChildProperties-chain entry were not really an "
            "FProperty, this would have been refuted by the "
            "FFieldClass::SuperClass chain walk failing to reach "
            "'FProperty' (rejection_kind='not_a_property') before a single "
            "FProperty-specific offset was ever applied; if the FField's "
            "own Owner did not round-trip to this class's own address "
            "(tag bit=1, masked pointer == the class's own address), the "
            "node would have been rejected as 'owner_mismatch' and never "
            "reached this record at all; if any foundational read on this "
            "already-located node failed, it would have been rejected as "
            "'read_failure', never silently reported as though it decoded. "
            "This record has NO POSSIBLE OFFLINE CROSS-CHECK, for any "
            "build, ever: FProperty is not a UObject and cannot appear in "
            "the ScriptObjects chunk global.ucas is built from (research/"
            "reflection/misery-24826585-ue5.4.4-0eef3715244b/README.md's "
            "own 'Почему properties.jsonl пуст' section) -- confidence is "
            "capped at 0.75 (one strong method, runtime-validated, no "
            "possible independent corroboration) for exactly this reason, "
            "never higher, for any property record this capability will "
            "ever produce."),
        "notes": notes,
        "semantic_alias": None,
    }


# --------------------------------------------------------------------------- #
# I-05 -- UFunction decoder. REUSES decode_property_type()/walk_property_
# chain() (I-06, immediately above) COMPLETELY UNCHANGED for a UFunction's
# own parameter list: a UFunction's parameters, including its own return
# value, are its own "child properties" in UE's reflection system --
# literally the SAME UStruct::ChildProperties/FField::Next linked list I-06
# already walks for a class's own member variables, at the SAME
# USTRUCT_CHILD_PROPERTIES_OFFSET (+0x50), because UFunction : public
# UStruct (Class.h:1789, single, unconditional inheritance -- unlike
# UStruct's own conditional FStructBaseChain base, confirmed by grep). See
# the module docstring's "WHAT I-05 IS" section for the full algorithm, the
# two already-corrected I-06 offset bugs this capability was designed to
# stay skeptical of on its OWN new offsets, and the MANDATORY EMPIRICAL
# SELF-CHECK this capability builds in specifically because one of its own
# new offsets (USTRUCT_TOTAL_SIZE_SHIPPING below) has not yet been
# empirically read-and-eyeballed against a live process the way
# USTRUCT_CHILD_PROPERTIES_OFFSET/FPROPERTY_PROPERTY_FLAGS_OFFSET/etc. were
# before I-06 was trusted.
# --------------------------------------------------------------------------- #

# UField::Next (Class.h -- UField's own single new member: the next field in
# the linked list). UObjectBase's own total size is already established at
# 0x28 by I-03's own DEFAULT_NAME_PRIVATE_OFFSET(+0x18) + I-04's own
# DEFAULT_OUTER_PRIVATE_OFFSET(+0x20) + OuterPrivate's own proven 8-byte
# pointer width = +0x28 -- the SAME arithmetic the I-06 module docstring's
# own "WHAT I-06 IS" section already states in full ("UObjectBase's own 0x28
# total size + UField's own Next at +0x28 (UField total 0x30)"), reused here
# verbatim, not re-derived. UObjectBaseUtility and UObject each contribute
# zero additional fields between UObjectBase and UField in this build --
# this is the SAME already-stated arithmetic USTRUCT_CHILD_PROPERTIES_
# OFFSET's own already-live-corrected derivation is built from, not a new
# guess.
DEFAULT_UFIELD_NEXT_OFFSET = 0x28

# UStruct::Children (Class.h -- "Pointer to start of linked list of child
# fields"), +0x08 before USTRUCT_CHILD_PROPERTIES_OFFSET (+0x50) -- the SAME
# UStruct layout USTRUCT_CHILD_PROPERTIES_OFFSET's own comment above already
# spells out in full (SuperStruct+0x40, Children+0x48, ChildProperties+0x50,
# PropertiesSize+0x58, MinAlignment+0x5c), reused verbatim. This is the
# FIRST time this file actually READS Children -- I-04 never did (it only
# ever read UObjectBase's own three fields); I-06 never did either (it only
# ever read ChildProperties). A UClass's own Children holds UField-DERIVED
# UObject children (in UE5, primarily UFunction, since properties moved to
# the separate FField tree) -- a DIFFERENT linked list from ChildProperties,
# walked via UField::Next (DEFAULT_UFIELD_NEXT_OFFSET), never FField::Next
# (FFIELD_NEXT_OFFSET) -- see walk_children_chain()'s own docstring.
USTRUCT_CHILDREN_OFFSET = 0x48

# UStruct's own TOTAL size in this Shipping build (WITH_EDITORONLY_DATA=0,
# CoreMiscDefines.h, standard for any non-Editor packaged target) -- i.e.
# where UFunction's OWN fields (FunctionFlags/NumParms/ParmsSize/
# ReturnValueOffset below) begin, relative to a UFunction object's own
# address. Built on I-06's own already-live-validated ChildProperties(+0x50)/
# PropertiesSize(+0x58)/MinAlignment(+0x5c), continuing through UStruct's
# remaining own members (Class.h): Script (TArray<uint8>, +0x60, 0x10 bytes
# -- AllocatorInstance(8B)+ArrayNum(4B)+ArrayMax(4B), TArray's own
# declaration, Array.h:3231-3233) -> +0x70; PropertyLink(FProperty*,+0x70)
# -> +0x78; RefLink(FProperty*,+0x78) -> +0x80; DestructorLink(FProperty*,
# +0x80) -> +0x88; PostConstructLink(FProperty*,+0x88) -> +0x90;
# ScriptAndPropertyObjectReferences(TArray<TObjectPtr<UObject>>, +0x90, also
# 0x10 bytes) -> +0xA0; UnresolvedScriptProperties
# (FUnresolvedScriptPropertiesArray*,+0xA0) -> +0xA8 (PropertyWrappers/
# FieldPathSerialNumber, Class.h, are #if WITH_EDITORONLY_DATA -- compiled
# OUT in Shipping, contribute 0 bytes); UnversionedGameSchema
# (const FUnversionedStructSchema*, NOT under WITH_EDITORONLY_DATA,+0xA8)
# -> +0xB0 (UnversionedEditorSchema/GetSchemaHash/
# bHasAssetRegistrySearchableProperties are #if WITH_EDITORONLY_DATA --
# compiled OUT).
#
# LIVE-CONFIRMED (research/instrument-runs/2026-08-27T170335Z-i05-v2/):
# run_i05()'s own MANDATORY EMPIRICAL SELF-CHECK (NumParms vs the accepted,
# CPF_Parm-filtered ChildProperties-chain count -- see run_i05()'s own
# docstring) reported num_parms_cross_check = {'match': 247, 'mismatch': 0}
# against the real live process -- every one of 247 real UFunctions in the
# proof set, zero exceptions. This figure was treated with EXACTLY the same
# suspicion USTRUCT_CHILD_PROPERTIES_OFFSET deserved before IT was corrected
# live (see that constant's own comment above: a prior +0x40 figure, careful
# source reading, reviewed twice, still turned out wrong until a live read
# caught it) -- the self-check below existed specifically so this offset
# would not be trusted on citation alone. It has now been. An EARLIER live
# run (research/instrument-runs/2026-08-27T165856Z-i05/, before the CPF_Parm
# filter existed) DID initially show 15/247 mismatches -- investigated and
# found to be a real UE semantic distinction (Blueprint local variables vs.
# true parameters, both living on the same ChildProperties chain), not an
# offset error -- see run_i05()'s own docstring for the full story.
USTRUCT_TOTAL_SIZE_SHIPPING = 0xB0

# UFunction's own fields (Class.h:1789 onward), absolute offsets from a
# UFunction object's own address -- i.e. USTRUCT_TOTAL_SIZE_SHIPPING plus
# UFunction's own declaration order. Only these four are ever read; RPCId/
# RPCResponseId (+0xBA/+0xBC) and everything after -- including every
# #if UE_BLUEPRINT_EVENTGRAPH_FASTCALLS/#if WITH_LIVE_CODING conditionally-
# compiled field and the native Func pointer -- are DELIBERATELY never read
# (real, unresolved conditional-compilation uncertainty this pass does not
# attempt to resolve; native_func_address/bytecode_size stay explicitly null
# on every function_record this capability writes -- see the module
# docstring's "WHAT I-05 IS" section).
UFUNCTION_FUNCTION_FLAGS_OFFSET = 0xB0        # EFunctionFlags, uint32 (Script.h:130, Class.h:1797)
UFUNCTION_NUM_PARMS_OFFSET = 0xB4             # uint8 NumParms (Class.h:1802)
UFUNCTION_PARMS_SIZE_OFFSET = 0xB6            # uint16 ParmsSize (Class.h:1804; +0xB5 is 1 byte of padding)
UFUNCTION_RETURN_VALUE_OFFSET_OFFSET = 0xB8   # uint16 ReturnValueOffset (Class.h:1806)

# EFunctionFlags bits I-05 decodes (Script.h:130-169) -- EXACT values, not
# re-derived; is_native/is_static/is_event/is_net/net_flags_raw are the only
# EFunctionFlags-derived fields reflection-record.schema.json's
# function_record has room for, so no other bit is decoded.
FUNC_NET = 0x00000040
FUNC_NET_RELIABLE = 0x00000080
FUNC_NATIVE = 0x00000400
FUNC_EVENT = 0x00000800
FUNC_STATIC = 0x00002000
FUNC_NET_MULTICAST = 0x00004000
FUNC_NET_SERVER = 0x00200000
FUNC_NET_CLIENT = 0x01000000
# net_flags_raw's own mask -- every replication-related bit reflection-
# record.schema.json's own net_flags_raw field names in its description
# ("NetMulticast, NetServer, NetClient, NetReliable"), PLUS FUNC_NET itself
# (is_net already reports the base bit as a boolean, but net_flags_raw's own
# schema description, "Replication-related flag bits", reads most naturally
# as including the base Net bit too, not only its four sub-qualifiers).
I05_NET_FLAGS_MASK = (
    FUNC_NET | FUNC_NET_RELIABLE | FUNC_NET_MULTICAST | FUNC_NET_SERVER | FUNC_NET_CLIENT)

# EPropertyFlags bits I-05 decodes per parameter (ObjectMacros.h:395-464) --
# EXACT values, not re-derived. CPF_CONST_PARM/CPF_PARM are defined for
# completeness/future use but are not currently surfaced as their own schema
# field (reflection-record.schema.json's parameter items object has no
# is_const/is_parm field).
CPF_CONST_PARM = 0x0000000000000002
CPF_PARM = 0x0000000000000080
CPF_OUT_PARM = 0x0000000000000100
CPF_RETURN_PARM = 0x0000000000000400
CPF_REFERENCE_PARM = 0x0000000008000000

# The UClass literally named "Function" (/Script/CoreUObject.Function) --
# EVERY live UFunction instance's own ClassPrivate equals THIS class's own
# address, found ONCE per run by exact raw_name match over I-04's OWN
# already-computed full class list (find_function_class_address() below),
# never re-walked, never guessed. This is a single exact-address equality
# check, deliberately simpler than I-04's own class-identity fixed point
# (compute_class_identity()), precisely because I-05 already knows exactly
# what it is looking for by name -- see the module docstring's "WHAT I-05
# IS" section.
UFUNCTION_METACLASS_RAW_NAME = "Function"

# Bounds I-05 introduces, all overridable via their own CLI flag (see
# build_arg_parser() below) -- matching the DEFAULT_I06_MAX_PROPERTY_CHAIN_
# LENGTH naming convention. I-05 reuses I-06's own --i06-max-chain-length/
# --i06-max-superclass-depth/--i06-max-container-depth DIRECTLY for a
# function's own parameter (ChildProperties) chain walk -- see run_i05()'s
# own docstring for why introducing a second, parallel set of flags for the
# SAME underlying decode_property_type()/walk_property_chain() bound would
# only invite the two silently drifting apart. DEFAULT_I05_MAX_CHILDREN_
# CHAIN_LENGTH is the ONE genuinely new bound this capability introduces,
# for the NEW UClass::Children/UField::Next chain walk_children_chain()
# below performs.
DEFAULT_I05_MAX_CHILDREN_CHAIN_LENGTH = 1024


def find_function_class_address(all_classes: list) -> int | None:
    """The live address of the UClass literally named "Function"
    (UFUNCTION_METACLASS_RAW_NAME), found by exact raw_name match over
    *all_classes* -- I-04's OWN full walked class universe (run_i04()'s own
    'classes' list, THIS SAME run, never re-walked -- the SAME data
    select_i06_engine_proof_classes() already draws from). A PURE, in-memory
    filter: never reads process memory, never triggers a new GUObjectArray
    walk.

    First occurrence wins (mirrors select_i06_engine_proof_classes()'s own
    "first occurrence in scan order wins" convention) -- in a real live
    class universe there is exactly one class named "Function", so this is
    a determinism safety net, not a meaningful disambiguation rule.

    Returns None, honestly, when no class named "Function" was found in
    *all_classes* this run -- a genuine, reportable, non-fatal condition
    (run_i05() reports zero UFunctions found rather than guess an address);
    never raises, never fabricates a value.
    """
    for entry in all_classes:
        if entry["raw_name"] == UFUNCTION_METACLASS_RAW_NAME:
            return entry["address"]
    return None


def _classify_child_field(api, handle: int, field_ptr: int, *, namepool_live_va: int,
                          owner_address: int, function_class_address: int,
                          class_private_offset: int = DEFAULT_CLASS_PRIVATE_OFFSET,
                          name_private_offset: int = DEFAULT_NAME_PRIVATE_OFFSET,
                          outer_private_offset: int = DEFAULT_OUTER_PRIVATE_OFFSET,
                          ufield_next_offset: int = DEFAULT_UFIELD_NEXT_OFFSET) -> dict:
    """Reads and validates ONE already-located UClass::Children-chain node's
    identity fields -- the module docstring's I-05 "Discovering which of a
    class's Children are UFunction instances" algorithm, steps 1-5, exactly.
    Mirrors _classify_object()'s own shape (I-04) applied to a DIFFERENT
    linked list (UClass::Children/UField::Next, never ChildProperties/
    FField::Next) and a DIFFERENT identity question ("is this node's own
    ClassPrivate exactly the live 'Function' class address", never I-04's
    own vtable-in-module-range check or class-identity fixed point).

    NEVER raises ReadProcessMemoryFailedError: every read here is on an
    ALREADY-LOCATED node (walk_children_chain() only ever calls this on an
    address it already validated as plausible, or received as a prior
    node's own Next pointer) -- a read failure is a torn-read scanning
    concern, mirrored from I-04's/I-06's own established precedent (see the
    module docstring's "THE 'ALL OR NOTHING' WRITE GUARANTEE" section),
    never propagated.

    Returns a dict, ALWAYS shaped the same way: {'valid' (bool, True iff
    this node is a real, readable UField whose own OuterPrivate round-trips
    to *owner_address* AND whose own ClassPrivate exactly equals
    *function_class_address* -- i.e. "this really is one of this class's own
    UFunction children"), 'rejection_kind' (one of 'pointer_alignment'/
    'read_failure'/'name_decode'/'outer_mismatch'/'not_a_function', or None
    when valid -- 'not_a_function' is a STRUCTURAL FINDING, not an error,
    exactly like decode_property_type()'s own 'not_a_property': this node IS
    a real UField, it is simply not a UFunction), 'rejection_reason'
    (str | None), 'name_text' (str | None), 'class_ptr' (int | None),
    'outer_ptr' (int | None), 'next_ptr' (int | None -- set as soon as the
    base field batch read succeeds, REGARDLESS of whether a later check then
    rejects this node -- mirrors decode_property_type()'s own 'next_ptr'
    field, for the identical reason: walk_children_chain() below needs it to
    continue past a rejected/non-function node without aborting the whole
    chain)}.
    """
    record = {
        "valid": False, "rejection_kind": None, "rejection_reason": None,
        "name_text": None, "class_ptr": None, "outer_ptr": None, "next_ptr": None,
    }

    # Step 1.
    if not _pointer_is_plausible(field_ptr):
        record["rejection_kind"] = "pointer_alignment"
        record["rejection_reason"] = (
            "UField pointer 0x%x is not a plausible (non-null, 8-byte-"
            "aligned) address" % field_ptr)
        return record

    # Step 2.
    try:
        class_ptr = _read_u64(api, handle, field_ptr + class_private_offset)
        outer_ptr = _read_u64(api, handle, field_ptr + outer_private_offset)
        name_entry_id = _read_u32(api, handle, field_ptr + name_private_offset)
        next_ptr = _read_u64(api, handle, field_ptr + ufield_next_offset)
    except ReadProcessMemoryFailedError as error:
        record["rejection_kind"] = "read_failure"
        record["rejection_reason"] = (
            "read failure on UField base fields at 0x%x: %s" % (field_ptr, error))
        return record

    record["class_ptr"] = class_ptr
    record["outer_ptr"] = outer_ptr
    record["next_ptr"] = next_ptr

    decoded = decode_fname_entry_id(api, handle, namepool_live_va, name_entry_id)
    if decoded["decode_error"] is not None:
        record["rejection_kind"] = "name_decode"
        record["rejection_reason"] = (
            "UField::NamePrivate decode error at 0x%x: %s" %
            (field_ptr, decoded["decode_error"]))
        return record
    record["name_text"] = decoded["text"]

    # Step 3: Outer round-trip -- the SAME "Owner round-trip is a strong
    # self-consistency invariant" philosophy walk_property_chain() already
    # applies to FField::Owner, here applied to a plain UObject::OuterPrivate
    # pointer instead (compared directly, no tag-bit decoding needed --
    # OuterPrivate is never tagged, unlike FFieldVariant).
    if outer_ptr != owner_address:
        record["rejection_kind"] = "outer_mismatch"
        record["rejection_reason"] = (
            "OuterPrivate 0x%x of the UField at 0x%x does not round-trip to "
            "the owning class's own address 0x%x" %
            (outer_ptr, field_ptr, owner_address))
        return record

    # Steps 4-5: "is a UFunction" iff ClassPrivate EXACTLY equals the live
    # "Function" class address -- anything else is simply not what this
    # capability is looking for, never an error.
    if class_ptr != function_class_address:
        record["rejection_kind"] = "not_a_function"
        record["rejection_reason"] = (
            "ClassPrivate 0x%x of the UField at 0x%x (named %r) is not the "
            "'Function' meta-class address 0x%x" %
            (class_ptr, field_ptr, decoded["text"], function_class_address))
        return record

    record["valid"] = True
    return record


def walk_children_chain(api, handle: int, children_ptr: int, *, namepool_live_va: int,
                        owner_address: int, function_class_address: int,
                        class_private_offset: int = DEFAULT_CLASS_PRIVATE_OFFSET,
                        name_private_offset: int = DEFAULT_NAME_PRIVATE_OFFSET,
                        outer_private_offset: int = DEFAULT_OUTER_PRIVATE_OFFSET,
                        ufield_next_offset: int = DEFAULT_UFIELD_NEXT_OFFSET,
                        max_chain_length: int = DEFAULT_I05_MAX_CHILDREN_CHAIN_LENGTH
                        ) -> dict:
    """Walks ONE UClass's own Children/UField::Next sibling chain (Class.h's
    own "Pointer to start of linked list of child fields", UStruct::Children
    -- a DIFFERENT linked list from ChildProperties/FField::Next, holding
    UField-DERIVED UObject children, primarily UFunction in UE5 since
    properties moved to the separate FField tree), classifying each node via
    _classify_child_field() above -- mirrors walk_property_chain()'s own
    bounded/cycle-protected/all-rejections-counted shape exactly, applied to
    a DIFFERENT chain and a DIFFERENT pair of offsets (I-04's own
    ClassPrivate/NamePrivate/OuterPrivate UObjectBase offsets, reused
    unchanged, plus this capability's own new UField::Next -- never
    FField-specific offsets, since a Children-chain entry is a plain UObject,
    not an FField).

    *children_ptr* == 0 is a VALID, legitimate "this class declares zero of
    its own child fields" result -- returns immediately, 'ok': True, never
    treated as an error (mirrors walk_property_chain()'s own null-
    ChildProperties precedent).

    BOUNDED (*max_chain_length* siblings) and CYCLE-PROTECTED (an address
    repeating within THIS ONE class's own chain walk is a traversal
    failure) -- mirrors walk_property_chain()/resolve_object_path()'s own
    walks exactly. A REJECTED node (not a plausible pointer at all, a read
    failure, a name-decode failure, an Outer mismatch, or simply "not a
    UFunction") does NOT by itself abort the walk, PROVIDED this node's own
    Next pointer was successfully read (_classify_child_field()'s own
    'next_ptr' is set as soon as its own step 2 succeeds, regardless of what
    a later step then decides) -- the walk continues past it, counting the
    rejection and moving on, exactly like walk_property_chain()'s own
    "rejected node does not abort the walk" rule. The walk can ONLY be
    aborted by a node whose own Next was never even read (rejected at
    _classify_child_field()'s own step 1 or step 2) -- there is no address
    left to continue from.

    Returns {'accepted': list[dict] (one {'address': int, 'raw_name': str}
    per node whose OWN ClassPrivate is exactly *function_class_address* AND
    whose own OuterPrivate round-tripped to *owner_address* -- in chain
    order; this list's own 0-based enumeration is NOT itself a meaningful
    ordinal the way walk_property_chain()'s own 'accepted' list is, since
    UClass::Children order carries no declared-parameter-order semantics --
    run_i05() below re-derives each accepted function's own parameter order
    from ITS OWN ChildProperties chain, never from this list's position),
    'nodes_visited' (int, every node the walk actually reached, accepted or
    not), 'rejected_counts' (dict[str, int], one entry per
    _classify_child_field() 'rejection_kind' value, including the benign
    'not_a_function' finding), 'ok' (bool -- False only for an actual
    traversal FAILURE: cycle, an unreadable first node, or exceeded
    max_chain_length -- never False merely because some nodes were
    rejected/were not functions), 'note' (str | None)}.
    """
    rejected_counts: dict = {}
    accepted: list = []

    if children_ptr == 0:
        return {"accepted": accepted, "nodes_visited": 0,
                "rejected_counts": rejected_counts, "ok": True, "note": None}

    visited: set = set()
    address = children_ptr
    nodes_visited = 0

    for _ in range(max_chain_length):
        if address in visited:
            return {"accepted": accepted, "nodes_visited": nodes_visited,
                    "rejected_counts": rejected_counts, "ok": False,
                    "note": "cycle detected in UField::Next chain at 0x%x" % address}
        visited.add(address)
        nodes_visited += 1

        classified = _classify_child_field(
            api, handle, address, namepool_live_va=namepool_live_va,
            owner_address=owner_address, function_class_address=function_class_address,
            class_private_offset=class_private_offset,
            name_private_offset=name_private_offset,
            outer_private_offset=outer_private_offset,
            ufield_next_offset=ufield_next_offset)

        if classified["valid"]:
            accepted.append({"address": address, "raw_name": classified["name_text"]})
        else:
            kind = classified["rejection_kind"]
            rejected_counts[kind] = rejected_counts.get(kind, 0) + 1

        next_ptr = classified["next_ptr"]
        if next_ptr is None:
            return {"accepted": accepted, "nodes_visited": nodes_visited,
                    "rejected_counts": rejected_counts, "ok": False,
                    "note": (
                        "chain walk aborted at 0x%x: this node's own Next "
                        "pointer was never read (rejected before the base "
                        "UField field batch could be read) -- %s" %
                        (address, classified["rejection_reason"]))}
        if next_ptr == 0:
            return {"accepted": accepted, "nodes_visited": nodes_visited,
                    "rejected_counts": rejected_counts, "ok": True, "note": None}
        address = next_ptr
    else:
        return {"accepted": accepted, "nodes_visited": nodes_visited,
                "rejected_counts": rejected_counts, "ok": False,
                "note": "UField::Next chain exceeded max_chain_length (%d) "
                        "without terminating" % max_chain_length}


def _decode_ufunction_base_fields(api, handle: int, function_address: int) -> dict:
    """Reads a UFunction's OWN FunctionFlags/NumParms/ParmsSize/
    ReturnValueOffset (+0xB0/+0xB4/+0xB6/+0xB8 -- see USTRUCT_TOTAL_SIZE_
    SHIPPING's own comment for the derivation and its own unverified-status
    warning). Nothing past ReturnValueOffset is ever read -- see the module
    docstring's "WHAT I-05 IS" section for why.

    NEVER raises: a read failure on an already-located, already-classified
    UFunction node (walk_children_chain() already validated its identity via
    the Children/UField::Next chain before this is ever called) is a torn
    read on an already-committed candidate, mirrored from I-04's/I-06's own
    established precedent -- converted to 'valid': False, never propagated.

    Returns {'valid' (bool), 'rejection_reason' (str | None),
    'function_flags' (int | None), 'num_parms' (int | None), 'parms_size'
    (int | None), 'return_value_offset' (int | None)}.
    """
    record = {
        "valid": False, "rejection_reason": None, "function_flags": None,
        "num_parms": None, "parms_size": None, "return_value_offset": None,
    }
    try:
        function_flags = _read_u32(api, handle, function_address + UFUNCTION_FUNCTION_FLAGS_OFFSET)
        num_parms = _read_u8(api, handle, function_address + UFUNCTION_NUM_PARMS_OFFSET)
        parms_size = _read_u16(api, handle, function_address + UFUNCTION_PARMS_SIZE_OFFSET)
        return_value_offset = _read_u16(
            api, handle, function_address + UFUNCTION_RETURN_VALUE_OFFSET_OFFSET)
    except ReadProcessMemoryFailedError as error:
        record["rejection_reason"] = (
            "read failure on UFunction base fields at 0x%x: %s" %
            (function_address, error))
        return record
    record.update({
        "valid": True, "function_flags": function_flags, "num_parms": num_parms,
        "parms_size": parms_size, "return_value_offset": return_value_offset,
    })
    return record


def run_i05(api, process_handle: int, namepool_live_va: int, all_classes: list,
           proof_set_classes: list, *,
           children_max_chain_length: int = DEFAULT_I05_MAX_CHILDREN_CHAIN_LENGTH,
           property_max_chain_length: int = DEFAULT_I06_MAX_PROPERTY_CHAIN_LENGTH,
           max_superclass_depth: int = DEFAULT_I06_MAX_SUPERCLASS_DEPTH,
           max_container_depth: int = DEFAULT_I06_MAX_CONTAINER_NESTING_DEPTH,
           children_offset: int = USTRUCT_CHILDREN_OFFSET,
           child_properties_offset: int = USTRUCT_CHILD_PROPERTIES_OFFSET,
           ufield_next_offset: int = DEFAULT_UFIELD_NEXT_OFFSET) -> dict:
    """The whole of capability I-05: find the live 'Function' meta-class
    address (find_function_class_address(), over *all_classes* -- I-04's OWN
    full walked class universe, THIS SAME run); for every class in
    *proof_set_classes* (select_i06_proof_set()'s own output, REUSED
    verbatim -- see the module docstring's "PROOF SET" section for why this
    is a real data dependency on I-04 alone, never on I-06), read its own
    UClass::Children (+0x48) and walk_children_chain() from there to find
    which children are UFunction instances; for each one, read its own base
    fields (_decode_ufunction_base_fields()) and walk its OWN
    UStruct::ChildProperties (+0x50, the SAME field/offset I-06 already
    reads for a CLASS's own properties -- UFunction : public UStruct) via
    I-06's OWN walk_property_chain()/decode_property_type(), COMPLETELY
    UNCHANGED, with owner_address set to the FUNCTION's own address (never
    the owning class's) -- a UFunction's own parameters are ITS OWN child
    properties, not the owning class's.

    *namepool_live_va* MUST be from THIS SAME run's own I-03 result, for the
    identical "reuse, never re-establish" reason run_i04()/run_i06() already
    document for their own namepool_live_va parameter.

    MANDATORY EMPIRICAL SELF-CHECK (see USTRUCT_TOTAL_SIZE_SHIPPING's own
    comment for why this specific check exists): for every UFunction this
    walk decodes, NumParms (read directly from the UFunction's own field, at
    the USTRUCT_TOTAL_SIZE_SHIPPING-derived offset -- LIVE-CONFIRMED, see
    below) is compared against the number of entries walk_property_chain()
    actually ACCEPTED on that SAME function's own ChildProperties chain AND
    carry CPF_Parm (0x80, ObjectMacros.h:406, "Function/When call
    parameter") -- read via I-06's OWN already-live-verified
    USTRUCT_CHILD_PROPERTIES_OFFSET.

    THE CPF_Parm FILTER ITSELF WAS A LIVE FINDING, not a source-derived
    assumption: the FIRST live run of I-05 against the real process
    (research/instrument-runs/2026-08-27T165856Z-i05/, before this filter
    existed) reported 15 "mismatches" out of 247 functions, EVERY ONE on a
    Blueprint-generated ('_C') class, and EVERY ONE with accepted_count >
    NumParms (never the reverse) -- e.g. BP_SGKGameInstance_C::LoadControls:
    NumParms=0, but 39 accepted ChildProperties-chain entries. Inspecting
    those 39 entries directly showed every single one lacking CPF_Parm
    (names like 'Temp_int_Loop_Counter_Variable',
    'CallFunc_Add_IntInt_ReturnValue', 'K2Node_DynamicCast_bSuccess' --
    unmistakably Blueprint-compiler-generated LOCAL variables of the
    function body, not parameters), while EVERY native /Script/MISERY
    function's own accepted entries already carried CPF_Parm on 100% of
    them (e.g. MiseryBlueprintFunctionLibrary::KeepSlateKeyboardFocus's own
    single accepted entry is named literally 'ReturnValue',
    CPF_Parm=CPF_OutParm=CPF_ReturnParm=True -- the exact real UE convention
    for a function's return value). This is real, well-known UE behavior (a
    Blueprint function's ChildProperties chain holds ALL of its properties,
    parameters AND local variables alike; NumParms counts only the former)
    -- NOT evidence against USTRUCT_TOTAL_SIZE_SHIPPING. After adding this
    filter, a SECOND live run against the SAME process
    (research/instrument-runs/2026-08-27T170335Z-i05-v2/) reported
    num_parms_cross_check = {'match': 247, 'mismatch': 0} -- EVERY function
    in the proof set, zero exceptions, confirming USTRUCT_TOTAL_SIZE_SHIPPING
    directly: had it been wrong the way ChildProperties' own +0x40 was, this
    aggregate count would show it exactly as starkly as the ChildProperties
    bug showed itself in I-06 (0 properties accepted). Local (non-CPF_Parm)
    entries are still real, successfully-decoded data -- never silently
    discarded -- they are excluded from 'parameters' (the schema's own
    parameter list) and from the NumParms comparison, but counted separately
    (this function's own return value's 'local_variable_count', and each
    class's own 'functions'[*] entry) so nothing found is ever unaccounted
    for.

    These are two INDEPENDENT readings of "how many parameters does this
    function have" that agree if, and only if, USTRUCT_TOTAL_SIZE_SHIPPING is
    correct for this build -- persistent disagreement across the whole proof
    set, AFTER the CPF_Parm filter above, would have been strong, actionable
    evidence it is not (none was found -- see the 247/247 result above),
    exactly the kind of self-check that would have caught the ChildProperties
    (+0x40 -> +0x50) bug faster than source re-reading alone did. A mismatch
    is NEVER silently accepted: it is counted (this function's own return
    value's 'num_parms_cross_check' dict) and the affected function_record's
    own 'notes' field states it plainly (build_i05_function_record()). The
    record is still WRITTEN, not discarded, even on a mismatch --
    "structurally implausible but successfully read = data, never raised"
    applies here exactly as everywhere else in this file.

    Never raises. A Children read failure for ONE class, or a UFunction
    base-field/ChildProperties read failure for ONE function, is recorded on
    that class's/function's own entry and this function continues with the
    REMAINDER of the proof set -- mirrors run_i06()'s own per-class
    ChildProperties-read-failure precedent (see the module docstring's
    "THE 'ALL OR NOTHING' WRITE GUARANTEE" section).

    Returns a plain dict: {'function_class_found' (bool),
    'function_class_address_hex' (str | None), 'classes' (list[dict], one
    entry per *proof_set_classes* member -- {'class_address' (int),
    'class_raw_name' (str), 'object_path' (str | None), 'children_ptr_hex'
    (str | None), 'children_read_ok' (bool), 'children_read_error'
    (str | None), 'functions' (list[dict], one per accepted UFunction --
    'address', 'address_hex', 'raw_name', 'function_flags', 'num_parms',
    'parms_size', 'return_value_offset', 'parameters' (walk_property_chain()'s
    own 'accepted' list, CPF_Parm-FILTERED, full decode_property_type() dicts,
    NOT yet reduced to function_record shape -- see this function's own
    "MANDATORY EMPIRICAL SELF-CHECK" paragraph above for why the filter
    exists), 'local_variable_count' (int, the accepted ChildProperties-chain
    entries that were NOT CPF_Parm-flagged, i.e. Blueprint-compiler-generated
    local variables -- real data, simply not part of 'parameters'),
    'num_parms_matches_accepted_count' (bool),
    'param_chain_ok' (bool), 'param_chain_note' (str | None),
    'param_chain_nodes_visited' (int)), 'nodes_visited' (int, the Children
    chain's own), 'rejected_counts' (dict, the Children chain's own),
    'chain_ok' (bool), 'chain_note' (str | None)}), 'classes_examined' (int),
    'functions_accepted_total' (int), 'rejected_counts_total' (dict, summed
    across every Children-chain walk, every ChildProperties/parameter chain
    walk, and every UFunction base-field/ChildProperties read failure),
    'num_parms_cross_check' ({'match': int, 'mismatch': int, 'mismatches':
    list[dict]}), 'note' (str | None)}.
    """
    function_class_address = find_function_class_address(all_classes)
    if function_class_address is None:
        return {
            "function_class_found": False, "function_class_address_hex": None,
            "classes": [], "classes_examined": len(proof_set_classes),
            "functions_accepted_total": 0, "rejected_counts_total": {},
            "num_parms_cross_check": {"match": 0, "mismatch": 0, "mismatches": []},
            "note": (
                "%r was not found in this run's own I-04 class universe -- "
                "I-05 cannot identify any UFunction this run; reported "
                "honestly rather than guessed (see "
                "find_function_class_address()'s own docstring)." %
                UFUNCTION_METACLASS_RAW_NAME),
        }

    classes_out = []
    total_accepted = 0
    total_rejected_counts: dict = {}
    cross_check_match = 0
    cross_check_mismatch = 0
    cross_check_mismatches: list = []

    def _bump(counts: dict, kind: str) -> None:
        counts[kind] = counts.get(kind, 0) + 1

    for class_entry in proof_set_classes:
        class_address = class_entry["address"]
        try:
            children_ptr = _read_u64(api, process_handle, class_address + children_offset)
        except ReadProcessMemoryFailedError as error:
            classes_out.append({
                "class_address": class_address, "class_raw_name": class_entry["raw_name"],
                "object_path": class_entry.get("object_path"),
                "children_ptr_hex": None, "children_read_ok": False,
                "children_read_error": str(error), "functions": [],
                "nodes_visited": 0, "rejected_counts": {}, "chain_ok": False,
                "chain_note": None,
            })
            continue

        chain = walk_children_chain(
            api, process_handle, children_ptr, namepool_live_va=namepool_live_va,
            owner_address=class_address, function_class_address=function_class_address,
            ufield_next_offset=ufield_next_offset, max_chain_length=children_max_chain_length)
        for kind, count in chain["rejected_counts"].items():
            total_rejected_counts[kind] = total_rejected_counts.get(kind, 0) + count

        functions_out = []
        for child in chain["accepted"]:
            function_address = child["address"]
            base_fields = _decode_ufunction_base_fields(api, process_handle, function_address)
            if not base_fields["valid"]:
                _bump(total_rejected_counts, "function_base_read_failure")
                continue

            try:
                parameters_ptr = _read_u64(
                    api, process_handle, function_address + child_properties_offset)
            except ReadProcessMemoryFailedError:
                _bump(total_rejected_counts, "function_base_read_failure")
                continue

            param_chain = walk_property_chain(
                api, process_handle, parameters_ptr, namepool_live_va=namepool_live_va,
                owner_address=function_address, max_chain_length=property_max_chain_length,
                max_superclass_depth=max_superclass_depth,
                max_container_depth=max_container_depth)
            for kind, count in param_chain["rejected_counts"].items():
                total_rejected_counts[kind] = total_rejected_counts.get(kind, 0) + count

            # CPF_Parm (0x80) is what actually distinguishes a true PARAMETER
            # from a Blueprint-compiler-generated LOCAL variable of the
            # function body -- both live on the SAME ChildProperties chain,
            # but only the former belongs in 'parameters' or in the
            # NumParms comparison below (see this function's own docstring's
            # "THE CPF_Parm FILTER ITSELF WAS A LIVE FINDING" paragraph for
            # the live evidence this filter is based on). Local entries are
            # real, successfully-decoded data -- counted, never discarded.
            true_parameters = [
                entry for entry in param_chain["accepted"]
                if int(entry["property_flags_raw"], 16) & CPF_PARM]
            local_variable_count = len(param_chain["accepted"]) - len(true_parameters)

            accepted_count = len(true_parameters)
            num_parms_matches = (base_fields["num_parms"] == accepted_count)
            if num_parms_matches:
                cross_check_match += 1
            else:
                cross_check_mismatch += 1
                cross_check_mismatches.append({
                    "function_raw_name": child["raw_name"],
                    "owner_class_raw_name": class_entry["raw_name"],
                    "num_parms": base_fields["num_parms"],
                    "accepted_parameter_count": accepted_count,
                    "local_variable_count": local_variable_count,
                })

            functions_out.append({
                "address": function_address, "address_hex": "0x%x" % function_address,
                "raw_name": child["raw_name"],
                "function_flags": base_fields["function_flags"],
                "num_parms": base_fields["num_parms"],
                "parms_size": base_fields["parms_size"],
                "return_value_offset": base_fields["return_value_offset"],
                "parameters": true_parameters,
                "local_variable_count": local_variable_count,
                "num_parms_matches_accepted_count": num_parms_matches,
                "param_chain_ok": param_chain["ok"],
                "param_chain_note": param_chain["note"],
                "param_chain_nodes_visited": param_chain["nodes_visited"],
            })
            total_accepted += 1

        classes_out.append({
            "class_address": class_address, "class_raw_name": class_entry["raw_name"],
            "object_path": class_entry.get("object_path"),
            "children_ptr_hex": "0x%x" % children_ptr, "children_read_ok": True,
            "children_read_error": None, "functions": functions_out,
            "nodes_visited": chain["nodes_visited"],
            "rejected_counts": chain["rejected_counts"],
            "chain_ok": chain["ok"], "chain_note": chain["note"],
        })

    return {
        "function_class_found": True,
        "function_class_address_hex": "0x%x" % function_class_address,
        "classes": classes_out, "classes_examined": len(proof_set_classes),
        "functions_accepted_total": total_accepted,
        "rejected_counts_total": total_rejected_counts,
        "num_parms_cross_check": {
            "match": cross_check_match, "mismatch": cross_check_mismatch,
            "mismatches": cross_check_mismatches,
        },
        "note": None,
    }


def build_i05_document(*, result: dict, build_key: str, recorded_at: str | None,
                       identity_self_established: bool, build_key_cross_checked: bool,
                       known_build: bool, build_id: str | None) -> dict:
    """The I-05 raw output document -- research/instrument-runs/<run>/
    i05-functions.json, the SAME "raw single-run data document, no evidence
    envelope" shape as build_i04_document()/build_i06_document(). functions.jsonl
    (a SEPARATE artifact, built from run_i05()'s own 'classes'[*]['functions']
    entries via build_i05_function_record() and written by main()) is where
    the actual GRADED knowledge-base claims live; this document is this
    run's own bookkeeping/summary -- including the MANDATORY EMPIRICAL
    SELF-CHECK's own aggregate match/mismatch counts, reported prominently
    here specifically so a human deciding whether to trust
    USTRUCT_TOTAL_SIZE_SHIPPING (see that constant's own comment) never has
    to dig through functions.jsonl row-by-row to find it.
    """
    return {
        "capability": CAPABILITY_ID_I05,
        "function_class_found": result["function_class_found"],
        "function_class_address_hex": result["function_class_address_hex"],
        "classes_examined": result["classes_examined"],
        "functions_accepted_total": result["functions_accepted_total"],
        "rejected_counts_total": result["rejected_counts_total"],
        "num_parms_cross_check": result["num_parms_cross_check"],
        "classes": [
            {
                "class_address_hex": "0x%x" % c["class_address"],
                "class_raw_name": c["class_raw_name"],
                "object_path": c["object_path"],
                "children_ptr_hex": c["children_ptr_hex"],
                "children_read_ok": c["children_read_ok"],
                "children_read_error": c["children_read_error"],
                "function_count": len(c["functions"]),
                "nodes_visited": c["nodes_visited"],
                "rejected_counts": c["rejected_counts"],
                "chain_ok": c["chain_ok"],
                "chain_note": c["chain_note"],
            }
            for c in result["classes"]
        ],
        "note": result["note"],
        "build_key": build_key,
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
    }


def build_i05_function_record(function_entry: dict, *, owner: str, build_key: str,
                              recorded_at: str) -> dict:
    """One functions.jsonl row (research/schema/reflection-record.schema.json's
    function_record branch) for ONE ACCEPTED UFunction *function_entry*
    (run_i05()'s own per-function dict -- see run_i05()'s own docstring for
    its exact shape).

    CONFIDENCE IS ALWAYS 0.75, EVERY RECORD, NO EXCEPTION -- mirrors
    build_i06_property_record()'s own reasoning: every function_record this
    pass writes is single-source, oracle=["runtime-reflection"] only,
    always -- no offline cross-check is attempted this pass (research/
    reflection/misery-24826585-ue5.4.4-0eef3715244b/functions.jsonl's own 18
    HYPOTHESIS-graded named functions are a DIFFERENT build's DIFFERENT
    method -- RF-01's own name-only decode, no structural detail;
    reconciling the two is a legitimate FUTURE enhancement, explicitly out
    of scope for this pass).

    Fields this pass deliberately leaves null (module docstring's "WHAT I-05
    IS" section, out-of-scope offsets): native_func_address, bytecode_size --
    neither RPCId/RPCResponseId nor the native Func pointer nor Blueprint
    bytecode is ever read this pass.
    """
    function_flags = function_entry["function_flags"]
    net_flags_raw = "0x%x" % (function_flags & I05_NET_FLAGS_MASK)

    parameters = []
    return_parm_count = 0
    for ordinal, decoded in enumerate(function_entry["parameters"]):
        flags_int = int(decoded["property_flags_raw"], 16)
        is_return = bool(flags_int & CPF_RETURN_PARM)
        if is_return:
            return_parm_count += 1
        parameters.append({
            "ordinal": ordinal,
            "name": decoded["raw_name"],
            "type_name": decoded["type_name"],
            "property_class": decoded["property_class"],
            "offset": decoded["offset"],
            "size": decoded["size"],
            "flags_raw": decoded["property_flags_raw"],
            "is_return": is_return,
            "is_out": bool(flags_int & CPF_OUT_PARM),
            "is_reference": bool(flags_int & CPF_REFERENCE_PARM),
        })

    notes = []
    if not function_entry["num_parms_matches_accepted_count"]:
        notes.append(
            "MANDATORY EMPIRICAL SELF-CHECK MISMATCH: NumParms (%s) "
            "disagrees with the number of accepted ChildProperties-chain "
            "entries (%d) -- see USTRUCT_TOTAL_SIZE_SHIPPING's own comment "
            "in eri.py; this function's own FunctionFlags/ParmsSize/"
            "ReturnValueOffset/parameters should not yet be trusted until a "
            "human resolves this." %
            (function_entry["num_parms"], len(parameters)))
    if return_parm_count > 1:
        notes.append(
            "structural anomaly: %d parameters carry CPF_ReturnParm "
            "(expected at most 1) -- the return-value identification is "
            "ambiguous for this function; left visible rather than guessed."
            % return_parm_count)
    if not function_entry["param_chain_ok"]:
        notes.append(
            "parameter ChildProperties chain walk did not complete "
            "cleanly: %s" % function_entry["param_chain_note"])
    if function_entry["local_variable_count"] > 0:
        notes.append(
            "%d ChildProperties-chain entries were accepted but excluded "
            "from 'parameters': they do not carry CPF_Parm (0x%x), i.e. "
            "they are local variables of this function's own body (common "
            "for Blueprint-generated functions), not true parameters -- see "
            "run_i05()'s own docstring for the live evidence this "
            "distinction is based on." %
            (function_entry["local_variable_count"], CPF_PARM))

    claim = (
        "the live MISERY-Win64-Shipping.exe process (build_key %s) has a "
        "UFunction named %r owned by class %r, FunctionFlags 0x%x, %d "
        "parameter(s) (NumParms=%s)" %
        (build_key, function_entry["raw_name"], owner, function_flags,
         len(parameters), function_entry["num_parms"]))

    return {
        "kind": "function",
        "raw_name": function_entry["raw_name"],
        "owner": owner,
        "function_flags_raw": "0x%x" % function_flags,
        "num_parms": function_entry["num_parms"],
        "parms_size": function_entry["parms_size"],
        "return_value_offset": function_entry["return_value_offset"],
        "is_native": bool(function_flags & FUNC_NATIVE),
        "is_static": bool(function_flags & FUNC_STATIC),
        "is_event": bool(function_flags & FUNC_EVENT),
        "is_net": bool(function_flags & FUNC_NET),
        "net_flags_raw": net_flags_raw,
        "native_func_address": None,
        "bytecode_size": None,
        "parameters": parameters,
        "claim": claim,
        "claim_type": "native-class-exists",
        "claim_class": "I",
        "evidence_level": "OBSERVED",
        "confidence": 0.75,
        "oracle": ["runtime-reflection"],
        "sources": [{
            "method": (
                "I-05: UClass::Children chain walk (+0x%x) + UField::Next "
                "(+0x%x) + ClassPrivate/NamePrivate/OuterPrivate reads "
                "(I-04's own UObjectBase.h offsets, reused) to identify the "
                "UFunction, + UFunction base field reads (Class.h offsets "
                "+0x%x/+0x%x/+0x%x/+0x%x, relative to USTRUCT_TOTAL_SIZE_"
                "SHIPPING=+0x%x) + UStruct::ChildProperties chain walk "
                "(+0x%x, I-06's own walk_property_chain()/"
                "decode_property_type(), reused unchanged) for the "
                "parameter list" %
                (USTRUCT_CHILDREN_OFFSET, DEFAULT_UFIELD_NEXT_OFFSET,
                 UFUNCTION_FUNCTION_FLAGS_OFFSET, UFUNCTION_NUM_PARMS_OFFSET,
                 UFUNCTION_PARMS_SIZE_OFFSET, UFUNCTION_RETURN_VALUE_OFFSET_OFFSET,
                 USTRUCT_TOTAL_SIZE_SHIPPING, USTRUCT_CHILD_PROPERTIES_OFFSET)),
            "artifact": None,
            "locator": function_entry["address_hex"],
            "note": (
                "oracle runtime-reflection. The address is this live "
                "UFunction object's own address in THIS run's process -- "
                "not stable across a relaunch (ASLR/heap allocation), "
                "recorded only for this run's own audit trail."),
        }],
        "build_key": build_key,
        "recorded_at": recorded_at,
        "method": "I-05",
        "refutation_attempt": (
            "if a UClass::Children-chain node were not really a UFunction, "
            "this would have been refuted by its own ClassPrivate not "
            "exactly equalling the live 'Function' meta-class address "
            "(rejection_kind='not_a_function' in walk_children_chain()); if "
            "its own OuterPrivate did not round-trip to the owning class's "
            "own address, it would have been rejected as 'outer_mismatch' "
            "and never reached this record; if the USTRUCT_TOTAL_SIZE_"
            "SHIPPING(+0x%x) offset assumption this record's own "
            "FunctionFlags/NumParms/ParmsSize/ReturnValueOffset rest on "
            "were wrong for this build, this function's own NumParms would "
            "systematically disagree with the number of parameters "
            "walk_property_chain() actually accepts on its own "
            "independently-offset ChildProperties chain -- see this "
            "record's own 'notes' field, and run_i05()'s own "
            "'num_parms_cross_check' aggregate, for whether that happened "
            "this run. This record has NO POSSIBLE OFFLINE CROSS-CHECK for "
            "any build, ever, for the SAME reason build_i06_property_"
            "record() already documents for FProperty -- confidence is "
            "capped at 0.75, never higher, for any function record this "
            "capability will ever produce." % USTRUCT_TOTAL_SIZE_SHIPPING),
        "notes": "; ".join(notes) if notes else None,
        "semantic_alias": None,
    }


# --------------------------------------------------------------------------- #
# PE-02: live vtable-slot evidence for the PE-01 UObject::ProcessEvent
# HYPOTHESIS (research/evidence/PE-01/README.md) -- see the module
# docstring's "WHAT PE-02 IS" section for the full algorithm, why this is
# NOT a plan.md 8.2 "I-0N" capability id, and why it therefore never appears
# in manifest.json's own capabilities_enabled array. Reuses I-04's OWN
# already-walked, already-validated objects_by_address dict from THIS SAME
# run (run_i04()'s own additive 'objects_by_address' return key) -- never
# re-walks GUObjectArray.
# --------------------------------------------------------------------------- #

# PE-01/README.md's own HYPOTHESIS: slot 77 (0-indexed), byte offset
# 77*8 == 616 == 0x268, under the UE_WITH_IRIS=1 assumption -- the SOLE
# ambiguity in that whole static count (see PE-01/README.md's "Часть 3" for
# the full derivation). Overridable via --processevent-vtable-slot,
# DELIBERATELY: the whole point of this capability is to gather live
# evidence FOR OR AGAINST 77 itself, so it must never be hardcoded
# un-overridably.
DEFAULT_PROCESSEVENT_VTABLE_SLOT = 77

# Large enough to see a real cross-class distribution, small enough to stay
# fast against a ~26 000-object live GUObjectArray -- unlike I-04's own full
# walk, PE-02 is a bounded SAMPLE by design (module docstring's "WHAT PE-02
# IS" section): the evidentiary value here is CLASS DIVERSITY across a few
# hundred objects, not exhaustive coverage.
DEFAULT_PE02_VTABLE_SAMPLE_SIZE = 500


def _vtable_slot_byte_offset(slot: int) -> int:
    """*slot* (a 0-indexed C++ vtable slot number, PE-01/README.md's own
    counting convention) to a byte offset -- every vtable entry on this x64
    target is one 8-byte pointer, so byte_offset = slot * 8. Kept as a tiny
    named function, not an inline '* 8', so DEFAULT_PROCESSEVENT_VTABLE_SLOT
    and --processevent-vtable-slot stay expressed as the SLOT NUMBER
    PE-01/README.md itself reasons about, with the byte-offset arithmetic
    (and its own citation) in exactly one place.
    """
    return slot * 8


def _classify_processevent_vtable_candidate(api, handle: int, object_ptr: int,
                                            class_ptr: int, objects_by_address: dict, *,
                                            base_address: int, image_size_bytes: int,
                                            vtable_slot_offset: int) -> dict:
    """Reads and validates ONE already-classified (I-04 'valid': True)
    UObject's OWN vtable pointer, then the candidate function pointer stored
    at its vtable_slot_offset'th slot -- the two-step read PE-02 exists to
    perform for a single sampled object.

    READ THIS BEFORE TOUCHING THIS FUNCTION -- it is easy to confuse two
    DIFFERENT vtable reads already present elsewhere in this file.
    _classify_object()'s own check 3 (I-04, above) reads the vtable pointer
    at CLASS_PTR's own address -- the vtable of the UClass "type
    descriptor" object *object_ptr* is an INSTANCE of, used there only to
    sanity-check that ClassPrivate looks like a real UObject-derived
    pointer. That is NOT what this function reads. PE-02 needs
    *object_ptr*'s OWN personal instance vtable, at object_ptr + 0x00,
    because ProcessEvent dispatches virtually through the CALLING
    instance's own vtable, never through its class descriptor's vtable (the
    class descriptor is itself a separate UObject, with its own vtable,
    appropriate to UClass -- not to whatever concrete class object_ptr is
    an instance of). This function therefore performs a FRESH read of
    object_ptr + 0x00; nothing computed by walk_object_universe()/
    _classify_object() for THIS SAME address is reused for this read,
    because nothing there ever read this address for this purpose.

    NEVER raises: every read here is on an object I-04's OWN walk already
    LOCATED and structurally validated ('valid': True) in THIS SAME run --
    a read failure on it is a torn read on an already-committed candidate,
    the IDENTICAL _classify_object()/walk_property_chain() precedent this
    whole file already establishes (module docstring's "STRUCTURAL
    REFUTATION IS A RESULT, NOT AN ERROR" / I-06's own "ALL OR NOTHING"
    sections), never propagated -- converted to a counted per-object
    rejection instead.

    Returns a dict, ALWAYS the same shape regardless of which check failed:
    {'object_address_hex', 'object_class_raw_name' (str or None -- the
    OWNER class's own decoded name, resolved via a PURE in-memory lookup of
    *class_ptr* into *objects_by_address* using 'name_ok' (never 'valid' --
    the SAME deliberately-weaker-than-'valid' field resolve_object_path()
    already uses for an ancestor's name, per _classify_object()'s own
    docstring: only the class's own NAME is needed here, never its own
    class-pointer plausibility), NEVER a new memory read; honestly None,
    never guessed, when unresolvable), 'vtable_ptr_hex'/'vtable_ptr_decimal'
    (str/int or None), 'candidate_va_hex'/'candidate_va_decimal' (str/int or
    None), 'candidate_rva_hex'/'candidate_rva_decimal' (str/int or None --
    decimal MAY be negative, hex formatted "-0x..." in that case, when
    candidate_va falls below base_address; a negative RVA is real data, not
    an error), 'candidate_in_module_range' (bool or None),
    'accepted' (bool -- True iff EVERY check below passed), 'rejection_kind'
    (None, or one of 'vtable_pointer_implausible',
    'vtable_out_of_module_range', 'vtable_read_failure', 'slot_read_failure',
    'candidate_pointer_implausible', 'candidate_out_of_module_range'),
    'rejection_reason' (human text or None)}.

    THE MODULE-RANGE CHECK ON THE CANDIDATE (the last gate below) IS
    DELIBERATELY WEAK, STATED HERE AND AGAIN IN THE MODULE DOCSTRING:
    practically every function pointer belonging to this 138MB Shipping
    image passes it. It stays a real GATE ('accepted' False otherwise,
    excluded from aggregate_processevent_vtable_candidates()'s own tally)
    only because an address outside the image cannot be meaningfully
    expressed as an RVA any static tool could look up at all -- passing it
    is not itself evidence of anything; the real evidence this capability
    produces is the cross-object, cross-class DISTRIBUTION computed
    downstream, never a single object's own pass/fail here.
    """
    record = {
        "object_address_hex": "0x%x" % object_ptr,
        "object_class_raw_name": None,
        "vtable_ptr_hex": None, "vtable_ptr_decimal": None,
        "candidate_va_hex": None, "candidate_va_decimal": None,
        "candidate_rva_hex": None, "candidate_rva_decimal": None,
        "candidate_in_module_range": None,
        "accepted": False,
        "rejection_kind": None,
        "rejection_reason": None,
    }

    class_descriptor = objects_by_address.get(class_ptr)
    if class_descriptor is not None and class_descriptor["name_ok"]:
        record["object_class_raw_name"] = class_descriptor["name_text"]

    try:
        vtable_ptr = _read_u64(api, handle, object_ptr)
    except ReadProcessMemoryFailedError as error:
        record["rejection_kind"] = "vtable_read_failure"
        record["rejection_reason"] = (
            "read failure on an already-located object's own vtable "
            "pointer at 0x%x: %s" % (object_ptr, error))
        return record
    record["vtable_ptr_hex"] = "0x%x" % vtable_ptr
    record["vtable_ptr_decimal"] = vtable_ptr

    if not _pointer_is_plausible(vtable_ptr):
        record["rejection_kind"] = "vtable_pointer_implausible"
        record["rejection_reason"] = (
            "object 0x%x's own vtable pointer 0x%x is not a plausible "
            "(non-null, 8-byte-aligned) address" % (object_ptr, vtable_ptr))
        return record

    if not _vtable_pointer_in_module_range(vtable_ptr, base_address, image_size_bytes):
        record["rejection_kind"] = "vtable_out_of_module_range"
        record["rejection_reason"] = (
            "object 0x%x's own vtable pointer 0x%x is outside the module "
            "image range [0x%x, 0x%x)" %
            (object_ptr, vtable_ptr, base_address, base_address + image_size_bytes))
        return record

    try:
        candidate_va = _read_u64(api, handle, vtable_ptr + vtable_slot_offset)
    except ReadProcessMemoryFailedError as error:
        record["rejection_kind"] = "slot_read_failure"
        record["rejection_reason"] = (
            "read failure on vtable 0x%x's own slot at +0x%x: %s" %
            (vtable_ptr, vtable_slot_offset, error))
        return record
    record["candidate_va_hex"] = "0x%x" % candidate_va
    record["candidate_va_decimal"] = candidate_va

    # Deliberately NOT _pointer_is_plausible() here: that check requires
    # 8-byte alignment, a real contract for HEAP-allocated data (every
    # UObject/vtable pointer this file elsewhere validates) but NOT for a
    # CODE address -- x86-64 has no alignment requirement for a CALL/JMP
    # target, and MSVC does not guarantee every function entry point lands
    # on an 8-byte boundary (only common/likely for a large, hot function,
    # never certain). Applying the heap-pointer rule to a candidate function
    # pointer risks REJECTING the correct ProcessEvent address outright and
    # manufacturing a false "slot 77 refuted" result from a mismatched
    # check, not from real evidence -- exactly the class of error this
    # capability exists to avoid. Only non-null is required here; the module
    # -range check below is the real (and, as documented above, still weak)
    # gate.
    if candidate_va == 0:
        record["rejection_kind"] = "candidate_pointer_implausible"
        record["rejection_reason"] = (
            "candidate function pointer at vtable 0x%x slot +0x%x is null" %
            (vtable_ptr, vtable_slot_offset))
        return record

    candidate_rva = candidate_va - base_address
    record["candidate_rva_decimal"] = candidate_rva
    record["candidate_rva_hex"] = (
        "0x%x" % candidate_rva if candidate_rva >= 0 else "-0x%x" % -candidate_rva)
    in_range = 0 <= candidate_rva < image_size_bytes
    record["candidate_in_module_range"] = in_range
    if not in_range:
        record["rejection_kind"] = "candidate_out_of_module_range"
        record["rejection_reason"] = (
            "candidate function pointer 0x%x (rva %s) falls outside the "
            "module image range [0, 0x%x)" %
            (candidate_va, record["candidate_rva_hex"], image_size_bytes))
        return record

    record["accepted"] = True
    return record


def scan_processevent_vtable_candidates(
        api, handle: int, objects_by_address: dict, *, base_address: int,
        image_size_bytes: int, vtable_slot: int = DEFAULT_PROCESSEVENT_VTABLE_SLOT,
        sample_size: int = DEFAULT_PE02_VTABLE_SAMPLE_SIZE) -> dict:
    """Samples up to *sample_size* VALID ('valid': True) objects from I-04's
    OWN *objects_by_address* (walk_object_universe()'s own dict, insertion-
    ordered == I-04's own scan order, matching select_game_sample()'s own
    "preserves scan order" precedent for reproducible row order), and runs
    _classify_processevent_vtable_candidate() on each. Never re-walks
    GUObjectArray -- every address sampled here was already located AND
    structurally validated by I-04's OWN walk in THIS SAME run.

    If fewer than *sample_size* valid objects exist, uses all of them --
    NEVER an error (module docstring's "WHAT PE-02 IS" section). If
    *objects_by_address* holds no valid object at all (should not normally
    happen given --run-pe02-vtable-scan requires --run-i04, which already
    requires a successful walk, but handled honestly regardless), returns
    zero samples, never raises.

    Never raises: every per-object read this makes is routed through
    _classify_processevent_vtable_candidate(), which never raises (its own
    docstring) -- a read failure on one sampled object is a counted
    rejection, and scanning continues to the next sampled object.

    Returns {'vtable_slot', 'vtable_slot_offset_hex', 'sample_size_requested',
    'valid_objects_available' (total valid objects I-04's walk found, for
    honesty about how representative this sample is), 'sample_size_used'
    (how many were actually examined), 'accepted_count', 'rejected_counts'
    (dict, one entry per _classify_processevent_vtable_candidate()
    'rejection_kind' value actually observed), 'objects' (the full
    per-object list, in sampled order)}.
    """
    vtable_slot_offset = _vtable_slot_byte_offset(vtable_slot)
    valid_addresses = [
        address for address, entry in objects_by_address.items() if entry["valid"]]
    valid_objects_available = len(valid_addresses)
    sampled_addresses = (
        valid_addresses[:sample_size] if sample_size > 0 else [])

    objects: list = []
    accepted_count = 0
    rejected_counts: dict = {}
    for address in sampled_addresses:
        class_ptr = objects_by_address[address]["class_ptr"]
        entry = _classify_processevent_vtable_candidate(
            api, handle, address, class_ptr, objects_by_address,
            base_address=base_address, image_size_bytes=image_size_bytes,
            vtable_slot_offset=vtable_slot_offset)
        objects.append(entry)
        if entry["accepted"]:
            accepted_count += 1
        else:
            rejected_counts[entry["rejection_kind"]] = (
                rejected_counts.get(entry["rejection_kind"], 0) + 1)

    return {
        "vtable_slot": vtable_slot,
        "vtable_slot_offset_hex": "0x%x" % vtable_slot_offset,
        "sample_size_requested": sample_size,
        "valid_objects_available": valid_objects_available,
        "sample_size_used": len(sampled_addresses),
        "accepted_count": accepted_count,
        "rejected_counts": rejected_counts,
        "objects": objects,
    }


def aggregate_processevent_vtable_candidates(objects: list) -> dict:
    """Pure aggregation over scan_processevent_vtable_candidates()'s own
    'objects' list -- no memory read, no API argument, so this is
    independently unit-testable against a synthetic list. Tallies every
    ACCEPTED (module docstring's "WHAT PE-02 IS": a rejected candidate
    contributes no RVA to tally) candidate by its own candidate_rva, and for
    each DISTINCT rva counts not only how many object INSTANCES observed it
    but how many DISTINCT object CLASSES observed it -- the stronger of the
    two signals per the module docstring's own reasoning: ProcessEvent is
    inherited from UObject, so a class-independent slot value recurring
    across MANY different classes is exactly what the PE-01 HYPOTHESIS
    predicts, whereas the same instance count concentrated in ONE class is
    far weaker evidence. An object whose own owning class could not be
    resolved (object_class_raw_name is None) still counts toward
    instance_count, but is tracked separately as
    unresolved_class_instance_count, never silently folded into
    distinct_class_count as if it were one more named class.

    Returns {'candidate_tally' (list, MOST-COMMON FIRST -- sorted by
    instance_count descending, candidate_rva_decimal ascending as a
    deterministic tiebreak; each entry: 'candidate_rva_hex',
    'candidate_rva_decimal', 'instance_count', 'distinct_class_count',
    'class_names' (sorted list of distinct non-None owner names),
    'unresolved_class_instance_count'), 'top_candidate' (candidate_tally[0],
    or None when the tally is empty), 'minority_candidates'
    (candidate_tally[1:] -- every OTHER distinct accepted candidate, each
    either a genuine per-class ProcessEvent override or evidence the whole
    slot/method is wrong; this function draws NO conclusion between those
    two readings, per the module docstring's own explicit instruction)}.
    """
    buckets: dict = {}
    for entry in objects:
        if not entry["accepted"]:
            continue
        rva = entry["candidate_rva_decimal"]
        bucket = buckets.setdefault(rva, {
            "candidate_rva_hex": entry["candidate_rva_hex"],
            "candidate_rva_decimal": rva,
            "instance_count": 0,
            "class_names": set(),
            "unresolved_class_instance_count": 0,
        })
        bucket["instance_count"] += 1
        name = entry["object_class_raw_name"]
        if name is None:
            bucket["unresolved_class_instance_count"] += 1
        else:
            bucket["class_names"].add(name)

    candidate_tally = []
    for bucket in buckets.values():
        class_names_sorted = sorted(bucket["class_names"])
        candidate_tally.append({
            "candidate_rva_hex": bucket["candidate_rva_hex"],
            "candidate_rva_decimal": bucket["candidate_rva_decimal"],
            "instance_count": bucket["instance_count"],
            "distinct_class_count": len(class_names_sorted),
            "class_names": class_names_sorted,
            "unresolved_class_instance_count": bucket["unresolved_class_instance_count"],
        })
    candidate_tally.sort(
        key=lambda c: (-c["instance_count"], c["candidate_rva_decimal"]))

    return {
        "candidate_tally": candidate_tally,
        "top_candidate": candidate_tally[0] if candidate_tally else None,
        "minority_candidates": candidate_tally[1:],
    }


def run_pe02_vtable_scan(
        api, handle: int, objects_by_address: dict, *, base_address: int,
        image_size_bytes: int, vtable_slot: int = DEFAULT_PROCESSEVENT_VTABLE_SLOT,
        sample_size: int = DEFAULT_PE02_VTABLE_SAMPLE_SIZE) -> dict:
    """The whole of PE-02: scan_processevent_vtable_candidates() (per-object
    read + validate, on a bounded sample of I-04's OWN already-walked
    objects_by_address) -> aggregate_processevent_vtable_candidates() (a
    pure tally of the accepted candidates). See the module docstring's
    "WHAT PE-02 IS" section for the full algorithm and its deliberate
    non-goals (no disassembly, no conclusion, no confidence grading).

    Never raises -- see scan_processevent_vtable_candidates()'s own
    docstring; this function adds no read of its own.
    """
    scan = scan_processevent_vtable_candidates(
        api, handle, objects_by_address, base_address=base_address,
        image_size_bytes=image_size_bytes, vtable_slot=vtable_slot,
        sample_size=sample_size)
    aggregate = aggregate_processevent_vtable_candidates(scan["objects"])
    return {
        "vtable_slot": scan["vtable_slot"],
        "vtable_slot_offset_hex": scan["vtable_slot_offset_hex"],
        "sample_size_requested": scan["sample_size_requested"],
        "valid_objects_available": scan["valid_objects_available"],
        "sample_size_used": scan["sample_size_used"],
        "accepted_count": scan["accepted_count"],
        "rejected_counts": scan["rejected_counts"],
        "objects": scan["objects"],
        "candidate_tally": aggregate["candidate_tally"],
        "top_candidate": aggregate["top_candidate"],
        "minority_candidates": aggregate["minority_candidates"],
        "note": (
            "RAW DATA ONLY, NO CONCLUSION: 'resolves into the module's own "
            "address range' is a necessary-but-not-sufficient structural "
            "check that practically every function pointer in this image "
            "passes; the actual evidence is the cross-class DISTRIBUTION in "
            "candidate_tally above. This capability does not decide whether "
            "top_candidate is really UObject::ProcessEvent -- that requires "
            "separate, human-run static disassembly correlation (pyghidra_"
            "scripts/dump_function.py) against ScriptCore.cpp:1971's own "
            "source structure, out of scope for this instrument."),
    }


def build_pe02_document(*, result: dict, build_key: str, recorded_at: str | None,
                        identity_self_established: bool, build_key_cross_checked: bool,
                        known_build: bool, build_id: str | None) -> dict:
    """The PE-02 raw output document -- research/instrument-runs/<run>/
    pe02-vtable-scan.json, the SAME "raw single-run data document, no
    evidence envelope" shape build_i01_document()/build_i02_document()/.../
    build_i04_document() already establish (see build_i01_document()'s own
    docstring for the is_record()/MARKER_KEYS reasoning this mirrors
    verbatim -- none of the fields here, including 'capability' below, is a
    MARKER_KEYS name). Unlike i04-classes.json, this document carries the
    FULL per-object sample list -- bounded to a few hundred rows by
    --pe02-vtable-sample-size, small enough to persist completely, unlike
    I-04's own ~26 000-object census.

    This is explicitly NOT a schema-graded knowledge-base record: no
    claim/confidence/oracle envelope, and this capability's own 'capability'
    field is informational text only ("PE-02" is not in
    instrument-run-manifest.schema.json's closed eri_capability_id enum,
    and this document is never validated against that schema at all -- see
    CAPABILITY_ID_PE02's own comment). A human writes the graded verdict to
    RESEARCH_LOG.md separately, after reviewing this file and running
    static disassembly correlation on whatever RVA(s) it surfaces.
    """
    return {
        "capability": CAPABILITY_ID_PE02,
        "evidence_track": "PE-01 (research/evidence/PE-01/README.md)",
        "vtable_slot": result["vtable_slot"],
        "vtable_slot_offset_hex": result["vtable_slot_offset_hex"],
        "sample_size_requested": result["sample_size_requested"],
        "valid_objects_available": result["valid_objects_available"],
        "sample_size_used": result["sample_size_used"],
        "accepted_count": result["accepted_count"],
        "rejected_counts": result["rejected_counts"],
        "objects": result["objects"],
        "candidate_tally": result["candidate_tally"],
        "top_candidate": result["top_candidate"],
        "minority_candidates": result["minority_candidates"],
        "note": result["note"],
        "build_key": build_key,
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
    }


# --------------------------------------------------------------------------- #
# I-14: which .pak containers is this process actually running with?
#
# WHAT THIS IS FOR, AND WHAT IT DELIBERATELY IS NOT
# -------------------------------------------------
# CT-03 asks one question: does the game discover and mount an external .pak
# placed in a directory it scans? Answering it needs the engine's OWN list of
# mounted containers -- not the filesystem, which says only what exists, and
# not a log, because Shipping compiles logging out (the game's Logs/ directory
# is empty). So this capability reads FPakPlatformFile::PakFiles and nothing
# else. It is not a filesystem inspector and must not grow into one.
#
# WHY THE EXISTING ANCHORS CANNOT REACH IT
# ----------------------------------------
# FPakPlatformFile is not a UObject. GUObjectArray (I-02), FNamePool (I-03) and
# the whole UObject graph I-04..I-06 walk simply do not contain it, and nothing
# in that graph points at it. I-14 therefore needs its own anchor, which is the
# only genuinely new thing here.
#
# THE ANCHOR
# ----------
# FPlatformFileManager::Get() (PlatformFileManager.cpp:164-169) is a
# function-local static. MSVC constant-initialised it, so -- unlike most magic
# statics -- there is NO thread-safe-static guard and no _Init_thread_header
# call; Get() is literally `lea rax,[rip+disp]; ret`. The manager's only member
# is `IPlatformFile* TopmostPlatformFile` at offset 0 (PlatformFileManager.h:17-24,
# with USE_ATOMIC_PLATFORM_FILE == WITH_EDITOR == 0 here), so the singleton's
# address IS the address of that pointer.
#
# From there the platform-file chain is walked. A reader cannot CALL the virtual
# GetLowerLevel(), but it does not need to: every wrapper compiles that override
# to a five-byte accessor, so the offset can be decoded statically from the
# function's own bytes:
#     48 8B 41 dd C3   mov rax,[rcx+dd]; ret   -> lower level at this + dd
#     33 C0 C3         xor eax,eax;     ret    -> bottom of the chain
# Decoding rather than assuming keeps the walk correct if a wrapper is ever
# inserted above the pak layer (a different command line can do that).
#
# IDENTITY IS BY VTABLE, NOT BY POSITION
# --------------------------------------
# A node is the FPakPlatformFile iff its vtable pointer equals the known
# FPakPlatformFile vtable. Each FPakFile is confirmed the same way, and it has
# TWO vtable pointers, because `class FPakFile : FNoncopyable, public
# FRefCountBase, public IPakFile` puts an IPakFile subobject at +0x10. That
# second vptr is easy to overlook and getting it wrong shifts every subsequent
# field: the IPakFile accessors are compiled against the secondary-base `this`,
# so their displacements are relative to FPakFile+0x10, not to the object start.
#
# THE RVAs ARE CANDIDATES, VERIFIED LIVE -- exactly like I-02's GUObjectArray
# and I-03's FNamePool. They are defaults, overridable, and every one of them is
# checked structurally before anything is believed. They were derived by
# byte-pattern matching directly against the target image rather than from the
# project's Ghidra database, because that database was imported from the
# PREVIOUS build: same file size, but ~27.6M bytes differ, concentrated in a
# ~26MB tail of .text. The values below happened to be identical in both builds
# (all cited extents byte-compared), but that is a fact about this pair of
# builds and not a guarantee -- which is precisely why nothing here is trusted
# without the live checks in _validate_pak_file().
# --------------------------------------------------------------------------- #

CAPABILITY_ID_I14 = "I-14"

# &FPlatformFileManager::TopmostPlatformFile (the singleton's only member).
DEFAULT_PLATFORM_FILE_MANAGER_RVA = 0x0795BFD0
# Identity predicates.
DEFAULT_PAKPLATFORMFILE_VTABLE_RVA = 0x060E3760
DEFAULT_PAKFILE_VTABLE_PRIMARY_RVA = 0x060E3728
DEFAULT_PAKFILE_VTABLE_IPAKFILE_RVA = 0x060E3730

# IPlatformFile vtable slot of GetLowerLevel(), from the declaration order in
# GenericPlatformFile.h:275-841 (slot 14 is GetName, and slot 66 the final
# virtual, which pins the length).
IPLATFORMFILE_GETLOWERLEVEL_SLOT = 12

FPAKPLATFORMFILE_LOWERLEVEL_OFFSET = 0x08
FPAKPLATFORMFILE_PAKFILES_OFFSET = 0x10      # TArray: Data +0x10, Num +0x18, Max +0x1C

FPAKLISTENTRY_SIZE = 0x10
FPAKLISTENTRY_READORDER_OFFSET = 0x00
FPAKLISTENTRY_PAKFILE_OFFSET = 0x08

FPAKFILE_NUMREFS_OFFSET = 0x08
FPAKFILE_IPAKFILE_VPTR_OFFSET = 0x10
FPAKFILE_PAKFILENAME_OFFSET = 0x18           # FString
FPAKFILE_INFO_OFFSET = 0x78                  # FPakInfo, in-memory sizeof 0x50
FPAKFILE_MOUNTPOINT_OFFSET = 0xC8            # FString
FPAKFILE_NUMENTRIES_OFFSET = 0x1F8
FPAKFILE_CACHEDTOTALSIZE_OFFSET = 0x208
FPAKFILE_ISVALID_OFFSET = 0x211
FPAKFILE_PAKCHUNKINDEX_OFFSET = 0x218
FPAKFILE_ISMOUNTED_OFFSET = 0x259

FPAKINFO_MAGIC_OFFSET = 0x00
FPAKINFO_VERSION_OFFSET = 0x04
FPAKINFO_INDEXOFFSET_OFFSET = 0x08
FPAKINFO_INDEXSIZE_OFFSET = 0x10

PAK_FILE_MAGIC = 0x5A6F12E1
PAK_FILE_VERSION_LAST = 12

# FString is one TArray<TCHAR>: Data +0x00, ArrayNum +0x08, ArrayMax +0x0C, and
# ArrayNum INCLUDES the terminator (UnrealString.h.inl:1082-1085).
FSTRING_NUM_OFFSET = 0x08
FSTRING_MAX_OFFSET = 0x0C
DEFAULT_I14_MAX_CHAIN_HOPS = 16
DEFAULT_I14_MAX_PAKS = 4096
MAX_FSTRING_CHARS = 65536


def read_fstring(api, handle: int, address: int) -> dict:
    """Decode one FString, refusing anything that does not look like a real
    UE string rather than returning plausible garbage.

    Returns {'ok', 'text', 'num', 'max', 'reason'}. A null Data pointer with
    Num == 0 is the legitimate empty string, not a failure.
    """
    out = {"ok": False, "text": None, "num": None, "max": None, "reason": None}
    try:
        data_ptr = _read_u64(api, handle, address)
        num = _read_u32(api, handle, address + FSTRING_NUM_OFFSET)
        maximum = _read_u32(api, handle, address + FSTRING_MAX_OFFSET)
    except ReadProcessMemoryFailedError as error:
        out["reason"] = "read failed: %s" % error
        return out
    out["num"], out["max"] = num, maximum
    if num == 0 and data_ptr == 0:
        out["ok"], out["text"] = True, ""
        return out
    if not (0 < num <= maximum <= MAX_FSTRING_CHARS):
        out["reason"] = "implausible Num/Max (%d/%d)" % (num, maximum)
        return out
    if data_ptr == 0 or (data_ptr & 1) or not _pointer_is_plausible(data_ptr & ~7):
        out["reason"] = "implausible Data pointer 0x%x" % data_ptr
        return out
    try:
        raw = api.read_process_memory(handle, data_ptr, num * 2)
    except ReadProcessMemoryFailedError as error:
        out["reason"] = "buffer read failed: %s" % error
        return out
    if raw[-2:] != b"\x00\x00":
        out["reason"] = "not NUL-terminated"
        return out
    try:
        text = raw[:-2].decode("utf-16-le")
    except UnicodeDecodeError as error:
        out["reason"] = "not valid UTF-16LE: %s" % error
        return out
    if any(ord(ch) < 0x20 for ch in text):
        out["reason"] = "control characters in text"
        return out
    out["ok"], out["text"] = True, text
    return out


def decode_lower_level_accessor(api, handle: int, function_address: int) -> dict:
    """Statically decode a GetLowerLevel() override's five bytes.

    Returns {'kind': 'offset'|'null'|'unknown', 'offset', 'bytes'}. 'null'
    means `xor eax,eax; ret` -- the bottom of the chain.
    """
    out = {"kind": "unknown", "offset": None, "bytes": None}
    try:
        code = api.read_process_memory(handle, function_address, 5)
    except ReadProcessMemoryFailedError:
        return out
    out["bytes"] = code.hex()
    if code[:3] == b"\x33\xc0\xc3":
        out["kind"] = "null"
    elif code[0] == 0x48 and code[1] == 0x8B and code[2] == 0x41 and code[4] == 0xC3:
        out["kind"] = "offset"
        out["offset"] = code[3]
    return out


def walk_platform_file_chain(api, handle: int, base_address: int, image_size_bytes: int,
                             *, platform_file_manager_rva: int,
                             pak_vtable_rva: int,
                             max_hops: int = DEFAULT_I14_MAX_CHAIN_HOPS) -> dict:
    """Follow TopmostPlatformFile down the wrapper chain until the node whose
    vtable is FPakPlatformFile's. Never calls a virtual; decodes each
    GetLowerLevel() instead."""
    result = {"chain": [], "pak_platform_file": None, "found": False, "note": None}
    manager_va = base_address + platform_file_manager_rva
    pak_vtable_va = base_address + pak_vtable_rva
    try:
        node = _read_u64(api, handle, manager_va)
    except ReadProcessMemoryFailedError as error:
        result["note"] = ("could not read TopmostPlatformFile at 0x%x: %s"
                          % (manager_va, error))
        return result
    for _ in range(max_hops):
        if not _pointer_is_plausible(node):
            result["note"] = "implausible platform-file pointer 0x%x" % node
            return result
        try:
            vptr = _read_u64(api, handle, node)
        except ReadProcessMemoryFailedError as error:
            result["note"] = "could not read vptr of 0x%x: %s" % (node, error)
            return result
        hop = {"object_hex": "0x%x" % node, "vptr_hex": "0x%x" % vptr,
               "vptr_rva_hex": ("0x%x" % (vptr - base_address)
                                if base_address <= vptr < base_address + image_size_bytes
                                else None),
               "is_pak_platform_file": vptr == pak_vtable_va}
        result["chain"].append(hop)
        if vptr == pak_vtable_va:
            result["pak_platform_file"] = node
            result["found"] = True
            return result
        if not (base_address <= vptr < base_address + image_size_bytes):
            result["note"] = "vtable 0x%x is outside the module image" % vptr
            return result
        try:
            fn = _read_u64(api, handle, vptr + IPLATFORMFILE_GETLOWERLEVEL_SLOT * 8)
        except ReadProcessMemoryFailedError as error:
            result["note"] = "could not read GetLowerLevel slot: %s" % error
            return result
        decoded = decode_lower_level_accessor(api, handle, fn)
        hop["get_lower_level"] = decoded
        if decoded["kind"] == "null":
            result["note"] = ("reached the bottom of the platform-file chain "
                              "without finding FPakPlatformFile")
            return result
        if decoded["kind"] != "offset":
            result["note"] = ("GetLowerLevel at 0x%x is not a recognised 5-byte "
                              "accessor (bytes %s)" % (fn, decoded["bytes"]))
            return result
        try:
            node = _read_u64(api, handle, node + decoded["offset"])
        except ReadProcessMemoryFailedError as error:
            result["note"] = "could not follow lower level: %s" % error
            return result
    result["note"] = "chain did not terminate within %d hops" % max_hops
    return result


def _validate_pak_file(api, handle: int, pak_file: int, base_address: int, *,
                       primary_vtable_rva: int, ipakfile_vtable_rva: int) -> dict:
    """Structural checks on one candidate FPakFile. The two vtable pointers are
    the strong test; the rest is defence in depth."""
    checks = {}
    try:
        checks["vptr_primary"] = (
            _read_u64(api, handle, pak_file) == base_address + primary_vtable_rva)
        checks["vptr_ipakfile"] = (
            _read_u64(api, handle, pak_file + FPAKFILE_IPAKFILE_VPTR_OFFSET)
            == base_address + ipakfile_vtable_rva)
        num_refs = _read_u32(api, handle, pak_file + FPAKFILE_NUMREFS_OFFSET)
        checks["num_refs_sane"] = 1 <= num_refs <= (1 << 20)
        magic = _read_u32(api, handle, pak_file + FPAKFILE_INFO_OFFSET
                          + FPAKINFO_MAGIC_OFFSET)
        checks["pak_magic"] = magic == PAK_FILE_MAGIC
        version = _read_u32(api, handle, pak_file + FPAKFILE_INFO_OFFSET
                            + FPAKINFO_VERSION_OFFSET)
        checks["pak_version_sane"] = 1 <= version <= PAK_FILE_VERSION_LAST
    except ReadProcessMemoryFailedError as error:
        checks["read_error"] = str(error)
        return {"ok": False, "checks": checks}
    return {"ok": all(v is True for v in checks.values()), "checks": checks}


def run_i14(api, process_handle: int, base_address: int, image_size_bytes: int, *,
            platform_file_manager_rva: int = DEFAULT_PLATFORM_FILE_MANAGER_RVA,
            pak_vtable_rva: int = DEFAULT_PAKPLATFORMFILE_VTABLE_RVA,
            pakfile_primary_vtable_rva: int = DEFAULT_PAKFILE_VTABLE_PRIMARY_RVA,
            pakfile_ipakfile_vtable_rva: int = DEFAULT_PAKFILE_VTABLE_IPAKFILE_RVA,
            max_paks: int = DEFAULT_I14_MAX_PAKS) -> dict:
    """The whole of capability I-14: report the .pak containers this process
    currently has mounted, each identified by its own filename and mount point
    rather than by position in a list.

    Never raises for "not found" -- an honest empty answer with a note beats a
    confident wrong one, the same contract I-04 uses for its seed search.
    """
    walk = walk_platform_file_chain(
        api, process_handle, base_address, image_size_bytes,
        platform_file_manager_rva=platform_file_manager_rva,
        pak_vtable_rva=pak_vtable_rva)
    result = {
        "capability": CAPABILITY_ID_I14,
        "platform_file_manager_rva_hex": "0x%x" % platform_file_manager_rva,
        "chain": walk["chain"],
        "pak_platform_file_found": walk["found"],
        "pak_platform_file_hex": ("0x%x" % walk["pak_platform_file"]
                                  if walk["pak_platform_file"] else None),
        "mounted_pak_count": 0,
        "mounted_paks": [],
        "note": walk["note"],
    }
    if not walk["found"]:
        return result

    pak_pf = walk["pak_platform_file"]
    try:
        data_ptr = _read_u64(api, process_handle, pak_pf + FPAKPLATFORMFILE_PAKFILES_OFFSET)
        array_num = _read_u32(api, process_handle, pak_pf + FPAKPLATFORMFILE_PAKFILES_OFFSET + 8)
        array_max = _read_u32(api, process_handle, pak_pf + FPAKPLATFORMFILE_PAKFILES_OFFSET + 12)
        lower_level = _read_u64(api, process_handle, pak_pf + FPAKPLATFORMFILE_LOWERLEVEL_OFFSET)
    except ReadProcessMemoryFailedError as error:
        result["note"] = "could not read PakFiles: %s" % error
        return result

    result["lower_level_hex"] = "0x%x" % lower_level
    result["pak_files_array"] = {"data_hex": "0x%x" % data_ptr,
                                 "num": array_num, "max": array_max}
    if not (0 <= array_num <= array_max <= max_paks):
        result["note"] = ("PakFiles array is implausible (Num %d, Max %d) -- refusing "
                          "to walk it" % (array_num, array_max))
        return result
    if array_num and not _pointer_is_plausible(data_ptr):
        result["note"] = "PakFiles.Data 0x%x is implausible" % data_ptr
        return result

    entries = []
    for index in range(array_num):
        entry_address = data_ptr + index * FPAKLISTENTRY_SIZE
        record = {"index": index}
        try:
            record["read_order"] = _read_u32(
                api, process_handle, entry_address + FPAKLISTENTRY_READORDER_OFFSET)
            pak_file = _read_u64(
                api, process_handle, entry_address + FPAKLISTENTRY_PAKFILE_OFFSET)
        except ReadProcessMemoryFailedError as error:
            record["rejected"] = "entry read failed: %s" % error
            entries.append(record)
            continue
        record["pak_file_hex"] = "0x%x" % pak_file
        if not _pointer_is_plausible(pak_file):
            record["rejected"] = "implausible FPakFile pointer"
            entries.append(record)
            continue
        validation = _validate_pak_file(
            api, process_handle, pak_file, base_address,
            primary_vtable_rva=pakfile_primary_vtable_rva,
            ipakfile_vtable_rva=pakfile_ipakfile_vtable_rva)
        record["validation"] = validation["checks"]
        if not validation["ok"]:
            record["rejected"] = "failed structural validation"
            entries.append(record)
            continue
        filename = read_fstring(api, process_handle, pak_file + FPAKFILE_PAKFILENAME_OFFSET)
        mount = read_fstring(api, process_handle, pak_file + FPAKFILE_MOUNTPOINT_OFFSET)
        record["pak_filename"] = filename["text"]
        record["pak_filename_ok"] = filename["ok"]
        record["mount_point"] = mount["text"]
        record["mount_point_ok"] = mount["ok"]
        if not filename["ok"]:
            record["pak_filename_reason"] = filename["reason"]
        if not mount["ok"]:
            record["mount_point_reason"] = mount["reason"]
        try:
            record["num_entries"] = _read_u32(
                api, process_handle, pak_file + FPAKFILE_NUMENTRIES_OFFSET)
            record["cached_total_size"] = _read_u64(
                api, process_handle, pak_file + FPAKFILE_CACHEDTOTALSIZE_OFFSET)
            record["pak_version"] = _read_u32(
                api, process_handle,
                pak_file + FPAKFILE_INFO_OFFSET + FPAKINFO_VERSION_OFFSET)
            record["index_offset"] = _read_u64(
                api, process_handle,
                pak_file + FPAKFILE_INFO_OFFSET + FPAKINFO_INDEXOFFSET_OFFSET)
            record["index_size"] = _read_u64(
                api, process_handle,
                pak_file + FPAKFILE_INFO_OFFSET + FPAKINFO_INDEXSIZE_OFFSET)
            chunk_index = _read_u32(
                api, process_handle, pak_file + FPAKFILE_PAKCHUNKINDEX_OFFSET)
            record["pakchunk_index"] = chunk_index - (1 << 32) if chunk_index >> 31 else chunk_index
            raw_flags = api.read_process_memory(
                process_handle, pak_file + FPAKFILE_ISVALID_OFFSET, 1)
            record["is_valid"] = bool(raw_flags[0])
            raw_mounted = api.read_process_memory(
                process_handle, pak_file + FPAKFILE_ISMOUNTED_OFFSET, 1)
            record["is_mounted"] = bool(raw_mounted[0])
        except ReadProcessMemoryFailedError as error:
            record["detail_read_error"] = str(error)
        entries.append(record)

    accepted = [e for e in entries if "rejected" not in e]
    result["mounted_paks"] = entries
    result["mounted_pak_count"] = len(accepted)
    result["rejected_count"] = len(entries) - len(accepted)
    return result


def build_i14_document(*, result: dict, build_key: str, recorded_at: str | None,
                       identity_self_established: bool, build_key_cross_checked: bool,
                       known_build: bool, build_id: str | None) -> dict:
    """The I-14 knowledge-base record."""
    names = [e.get("pak_filename") for e in result["mounted_paks"]
             if "rejected" not in e and e.get("pak_filename")]
    return {
        "capability": CAPABILITY_ID_I14,
        "claim": ("the live MISERY-Win64-Shipping.exe process (build_key %s) has %d .pak "
                  "container(s) mounted: %s"
                  % (build_key, result["mounted_pak_count"],
                     ", ".join(repr(n) for n in names) or "none")),
        "claim_type": "other",
        "claim_type_note": (
            "a report of which containers one running process currently has mounted is a "
            "statement about that process at that moment, not a durable fact about the "
            "game build; no plan.md 10.5 matrix row describes it."),
        "evidence_level": "OBSERVED",
        # 0.75, matching every other single-capability document here (I-05,
        # I-06). This artifact records ONE act of measurement -- one traversal,
        # one moment -- and plan.md 10.3 v2.2 requires two independent methods
        # for an interpretive claim from 0.80 up. The corroborated version of
        # this claim, cross-checked against the container's own bytes on disk,
        # is graded separately and higher in RESEARCH_LOG.md; putting that
        # grade here would be exactly the "restating promotes" defect 10.1
        # forbids, since the tool itself performs no such cross-check.
        "confidence": 0.75,
        "claim_class": "I",
        "oracle": ["runtime-reflection"],
        "method": CAPABILITY_ID_I14,
        "sources": [{"method": CAPABILITY_ID_I14}],
        "refutation_attempt": (
            "if the chain walk had landed on something that is not an FPakPlatformFile, "
            "the vtable equality test would have rejected it rather than reporting its "
            "bytes as a pak list; if an FPakListEntry pointed at something that is not an "
            "FPakFile, the two-vtable test plus the FPakInfo magic would have rejected it; "
            "if the FString offsets were wrong, the decode would have failed the "
            "NUL-termination and UTF-16 checks instead of yielding a plausible name. The "
            "decisive external check is that the decoded filename, mount point, pak "
            "version, index offset/size and total size of an already-known container can "
            "be compared against that container's own bytes on disk."),
        "pak_platform_file_found": result["pak_platform_file_found"],
        "mounted_pak_count": result["mounted_pak_count"],
        "mounted_paks": result["mounted_paks"],
        "chain": result["chain"],
        "note": result["note"],
        "build_key": build_key,
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
    }


# --------------------------------------------------------------------------- #
# document building -- the I-01 JSON output, and the manifest.json required
# by research/schema/instrument-run-manifest.schema.json.
# --------------------------------------------------------------------------- #

BUILD_KEY_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def validate_build_key(build_key: str) -> None:
    """Fail loudly, before opening a single handle, if --build-key is not
    the canonical 'sha256:<64 lowercase hex>' shape
    (research/schema/kb-record.schema.json #/$defs/build_key). Both the
    I-01 document and manifest.json carry this value, and the manifest MUST
    validate against instrument-run-manifest.schema.json -- a malformed
    build_key would only be caught later, at write time, if this check did
    not exist, which is a worse failure (partial work already done) than
    catching it at argument-parse time.
    """
    if not BUILD_KEY_PATTERN.match(build_key):
        raise ValueError(
            "--build-key %r does not match the required shape "
            "'sha256:<64 lowercase hex characters>' "
            "(research/schema/kb-record.schema.json #/$defs/build_key). "
            "Compute it with sha256sum on "
            "MISERY\\Binaries\\Win64\\MISERY-Win64-Shipping.exe, or copy the "
            "value from an existing research/builds/<key>/ entry." % build_key)


# --------------------------------------------------------------------------- #
# identity self-establishment (LOG-0048/LOG-0049) -- see the module docstring's
# "IDENTITY IS SELF-ESTABLISHED" section and BuildKeyMismatchError above for
# why this exists. Every live attach session computes ITS OWN build_key from
# the file the OS loader actually mapped; a supplied --build-key is at most a
# cross-check against that, never the source of truth. Future capabilities
# (I-02, I-03, ...) that need to know or re-confirm which build they are
# reading should call establish_build_identity() with the SAME
# result["exe_path"] run_i01() already returns, rather than re-deriving any
# part of this by hand -- that keeps "identity is self-established" a single
# fact computed in one place, not a convention every capability has to
# remember to reimplement.
# --------------------------------------------------------------------------- #

HASH_BUFFER_BYTES = 1 << 20  # 1 MiB, same streaming convention as
# tools/inventory/snapshot_install.py's hash_file / tools/fingerprint's
# stream_digests / research/schema/kb-record.schema.json #/$defs/sha256's own
# implied streaming contract: one bounded buffer, reused via readinto(), so
# peak additional memory is HASH_BUFFER_BYTES regardless of file size -- a
# Shipping.exe here is ~130 MB and must never be read into memory whole.

DEFAULT_BUILDS_INDEX_PATH = os.path.join(_REPO_ROOT, "research", "builds", "index.json")


def compute_file_sha256(path: str, buf_size: int = HASH_BUFFER_BYTES) -> str:
    """Lowercase hex sha256 digest of *path* (research/schema/kb-record.schema.json
    #/$defs/sha256's own shape, no 'sha256:' prefix), computed in ONE streaming
    pass with a single bounded buffer reused via readinto() -- never a whole-file
    read. Callers that need the canonical 'sha256:<64 hex>' build_key form
    prefix this return value themselves (see establish_build_identity below).

    This is the function that makes identity SELF-established rather than
    merely asserted: called on module.exe_path -- the exact file the OS
    loader mapped for the live process this run attached to, per
    MODULEENTRY32W's szExePath -- its result is data this run measured
    itself, not a value any caller supplied or any previous run cached. See
    the module docstring's "IDENTITY IS SELF-ESTABLISHED" section for why
    that distinction is the entire point (LOG-0048/LOG-0049).
    """
    digest = hashlib.sha256()
    buffer = bytearray(buf_size)
    view = memoryview(buffer)
    with open(path, "rb", buffering=0) as handle:
        while True:
            read = handle.readinto(buffer)
            if not read:
                break
            digest.update(view[:read])
    return digest.hexdigest()


def lookup_known_build(build_key: str, index_path: str = DEFAULT_BUILDS_INDEX_PATH
                       ) -> tuple[bool, str | None]:
    """(known_build, build_id) for *build_key* against research/builds/index.json
    (or *index_path*, the seam tests use to avoid touching the real committed
    index) -- a dict keyed literally by 'sha256:<hex>' (see that file itself).

    READ-ONLY INFORMATIONAL BOOKKEEPING ONLY. This exists to answer one
    question -- "has this exact build been seen and registered before, and if
    so under which build_id" -- for the I-01 document and the manifest to
    record. It deliberately does nothing else: it does not change what I-01
    reads (base_address/image_size are reported identically whether the
    build is known or not), and it must NEVER be used to pull an RVA,
    address, or signature from a DIFFERENT build's research/evidence/
    directory -- an unknown build gets no bindings/candidates inherited from
    a previous one, and neither does a known one, from this function alone.
    Candidate-lookup/signature-matching against a known build's evidence is
    out of scope here by design; only the KNOWN/UNKNOWN fact and the
    build_id string are surfaced.

    A missing index file is treated as "unknown", not as an error -- the
    index is a convenience registry, not something I-01's own read depends
    on, and an early or stripped-down checkout may not have one yet. A
    present-but-malformed index file DOES raise (json.JSONDecodeError, a
    ValueError subclass main() already handles the same way as every other
    fail-loud EriError), because silently swallowing a corrupt registry file
    would hide a genuine bug rather than an absent-and-expected one.
    """
    try:
        with open(index_path, "r", encoding="utf-8") as handle:
            index = json.load(handle)
    except FileNotFoundError:
        return False, None
    entry = index.get(build_key)
    if entry is None:
        return False, None
    build_id = entry.get("build_id")
    return True, (str(build_id) if build_id is not None else None)


def establish_build_identity(*, exe_path: str, given_build_key: str | None,
                             builds_index_path: str = DEFAULT_BUILDS_INDEX_PATH) -> dict:
    """THE one place identity is established for this tool (LOG-0048/LOG-0049).
    Every live attach session calls this, and self-computes its own build_key
    from *exe_path* -- MODULEENTRY32W's szExePath for the module this run
    actually found, i.e. run_i01()'s own result["exe_path"], never a path
    passed on the command line or cached from a previous run. Future
    capabilities that need build identity should call this function with
    that same exe_path rather than reimplementing any part of it.

    *given_build_key* is None when --build-key was not passed (the normal,
    preferred way to invoke this tool from now on): the self-computed hash
    becomes the authoritative build_key, and this function never opens
    research/builds/index.json for anything but the informational
    known/unknown lookup below.

    *given_build_key*, if not None, is treated ONLY as a cross-check, never
    as a source of truth: on a match, this run proceeds, and the returned
    'build_key_cross_checked' is True so the output documents can state that
    the supplied value was INDEPENDENTLY CONFIRMED, not merely asserted. On
    a mismatch, raises BuildKeyMismatchError -- stating both the supplied and
    the self-computed value plainly -- BEFORE this function returns, which is
    before main() writes a single output file. This is the exact check that
    would have caught LOG-0048/LOG-0049 at the moment it happened, instead of
    requiring a human to notice it afterward by hand.

    Also performs the read-only known/unknown-build lookup (see
    lookup_known_build) against *builds_index_path* and folds its result in.

    Returns {"build_key", "identity_self_established" (always True),
    "build_key_cross_checked", "known_build", "build_id"}.
    """
    self_computed_hex = compute_file_sha256(exe_path)
    self_computed_build_key = "sha256:%s" % self_computed_hex

    if given_build_key is not None:
        if given_build_key != self_computed_build_key:
            raise BuildKeyMismatchError(
                "--build-key %r does not match the build actually attached to: "
                "this run independently computed %r from module.exe_path (%r), "
                "the file the OS loader mapped for the process it just found. "
                "This is exactly the class of mistake LOG-0048/LOG-0049 recorded "
                "on 2026-08-27 (a --build-key copied from earlier work, not "
                "rechecked, at the exact moment Steam had silently updated the "
                "game) -- see BuildKeyMismatchError's own docstring. Nothing was "
                "written; rerun with the correct --build-key, or omit --build-key "
                "entirely and let this run's own self-computed hash be the "
                "authoritative build_key." %
                (given_build_key, self_computed_build_key, exe_path))
        build_key = given_build_key
        cross_checked = True
    else:
        build_key = self_computed_build_key
        cross_checked = False

    known_build, build_id = lookup_known_build(build_key, builds_index_path)

    return {
        "build_key": build_key,
        "identity_self_established": True,
        "build_key_cross_checked": cross_checked,
        "known_build": known_build,
        "build_id": build_id,
    }


def build_i01_document(*, result: dict, build_key: str, recorded_at: str | None,
                       identity_self_established: bool, build_key_cross_checked: bool,
                       known_build: bool, build_id: str | None) -> dict:
    """The I-01 output document (task item 6 / README 'Как запускать').

    JSON, not JSONL: this is one process's one snapshot, a single object.
    A later multi-capability ERI export (I-16, once I-02+ exist) can add a
    JSONL sibling that emits one line per capability's own record without
    changing this function or this document's shape -- 'capability' is
    already a field of this object precisely so a JSONL row built the same
    way is self-describing without a wrapper.

    Deliberately does NOT carry 'evidence_level'/'oracle' fields, even
    though the read this document reports is, in fact, OBSERVED via the
    runtime-reflection oracle. This matches the rest of the repository's
    convention for raw evidence artifacts (research/evidence/*/*.json never
    self-grades either): tools/kb/validate.py's is_record() heuristic
    treats ANY dict carrying an evidence_level/oracle marker key as a
    full knowledge-base record and then demands confidence/sources[]/
    claim_type on it too (plan.md 10.2/10.4/10.5) -- fields this raw,
    single-run data document has no business carrying, since the actual
    graded claim belongs in the sibling manifest.json (build_manifest()
    below, which DOES carry the full envelope) or in a future
    RESEARCH_LOG.md entry that cites this file by path and sha256, per
    this project's established C-13 discipline. Re-adding these two keys
    here would make every future run fail tools/kb/validate.py.

    Also carries identity_self_established/build_key_cross_checked/
    known_build/build_id (LOG-0048/LOG-0049 -- see establish_build_identity's
    own docstring and the module docstring's "IDENTITY IS SELF-ESTABLISHED"
    section for why): none of these four is a marker key in
    tools/kb/validate.py's MARKER_KEYS ("evidence_level", "claim_type",
    "oracle", "confidence"), so adding them does not trip is_record() into
    treating this raw document as a full knowledge-base record -- do not
    widen this set to include any of those four marker names for the same
    reason evidence_level/oracle are excluded above.
    """
    base_address = int(result["base_address"])
    return {
        "capability": CAPABILITY_ID,
        "process_name": result["process_name"],
        # PID is a research artifact of THIS run, not a stable identifier
        # across runs: Windows reassigns PIDs, and the same MISERY process
        # relaunched gets a different one. Never key persisted research
        # data on pid alone -- build_key + recorded_at is the reproducible
        # identity; pid is only useful to correlate within one live session.
        "pid": int(result["pid"]),
        "base_address_hex": "0x%x" % base_address,
        "base_address_decimal": base_address,
        "image_size_bytes": int(result["image_size_bytes"]),
        "build_key": build_key,
        # identity is SELF-established every run, never merely asserted by a
        # caller-supplied --build-key (LOG-0048/LOG-0049): see
        # establish_build_identity(). identity_self_established is always
        # True for a document this function produced through main()'s normal
        # flow. build_key_cross_checked is True only when --build-key WAS
        # given AND matched the self-computed hash -- i.e. build_key above
        # was INDEPENDENTLY CONFIRMED, not merely asserted; False means
        # build_key above IS the self-computed hash itself (no --build-key
        # was given, the normal/preferred invocation from now on).
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        # known_build/build_id: read-only informational bookkeeping from
        # research/builds/index.json (lookup_known_build) -- whether this
        # exact build_key has a registry entry, and if so its build_id.
        # Never changes what I-01 reads, and never a signal to reuse
        # candidates/bindings from a different build's research/evidence/.
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
    }


def build_i02_document(*, result: dict, build_key: str, recorded_at: str | None,
                       identity_self_established: bool, build_key_cross_checked: bool,
                       known_build: bool, build_id: str | None) -> dict:
    """The I-02 output document -- structural-invariant verification of
    RF-05's candidate GUObjectArray against a LIVE process. *result* is
    run_i02()'s own return dict; see that function's docstring for the exact
    three checks and research/evidence/RF-05/README.md for the struct layout
    and arithmetic this is built from.

    Carries every field of *result* verbatim -- the RVA and live VA checked,
    all three per-check sub-dicts (each with its own 'pass' boolean and
    reasoning text), and the collapsed 'structurally_consistent' verdict --
    plus never averages the three checks into that one collapsed field
    without also keeping each individually visible (plan.md's own grading
    discipline: a record must not average distinct findings into one
    number).

    Deliberately does NOT carry 'evidence_level'/'oracle', for the identical
    is_record() reason build_i01_document's own docstring explains in full:
    none of the fields here (including the four identity fields below) is in
    tools/kb/validate.py's MARKER_KEYS, so this stays a raw, single-run data
    document, never a full knowledge-base record on its own -- the graded
    claim (does this run's evidence move RF-05 above HYPOTHESIS) belongs in
    a future RESEARCH_LOG.md entry that cites this file by path and sha256,
    per this project's established C-13 discipline, not in this document
    itself.

    Carries identity_self_established/build_key_cross_checked/known_build/
    build_id, mirrored from the SAME establish_build_identity() call main()
    already made for the I-01 document in this same run -- I-02 never
    re-establishes identity independently, it is downstream of the one
    identity fact this run already computed for itself (LOG-0048/LOG-0049).
    """
    return {
        "capability": CAPABILITY_ID_I02,
        "guobjectarray_rva_hex": result["guobjectarray_rva_hex"],
        "guobjectarray_rva_decimal": int(result["guobjectarray_rva"]),
        "guobjectarray_live_va_hex": result["guobjectarray_live_va_hex"],
        "guobjectarray_live_va_decimal": int(result["guobjectarray_live_va"]),
        "check_struct_invariants": result["check_struct_invariants"],
        "check_sample_walk": result["check_sample_walk"],
        "check_growth_non_decreasing": result["check_growth_non_decreasing"],
        "structurally_consistent": bool(result["structurally_consistent"]),
        "build_key": build_key,
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
    }


def build_i03_document(*, result: dict, build_key: str, recorded_at: str | None,
                       identity_self_established: bool, build_key_cross_checked: bool,
                       known_build: bool, build_id: str | None,
                       misery_reflection: dict | None = None) -> dict:
    """The I-03 output document -- FNamePool decode verification (RF-06's
    candidate) plus, optionally, the "/Script/MISERY live reflection" probe.
    *result* is run_i03()'s own return dict; see that function's docstring
    for the exact fields, and research/evidence/RF-06/README.md for the
    struct layout and arithmetic this is built from.

    *misery_reflection* is sample_object_names()'s own return dict when
    main() ran that probe (--run-i03-reflection), else None -- kept as an
    explicit optional field rather than a second output document, matching
    this task's own "your call on shape, but keep it consistent" latitude:
    both halves are readings from the SAME live process, in the SAME run, so
    one document rather than two avoids forcing a reader to correlate two
    files by build_key/recorded_at to see the whole I-03 picture.

    Deliberately does NOT carry 'evidence_level'/'oracle', for the identical
    is_record() reason build_i01_document's and build_i02_document's own
    docstrings explain in full: none of the fields here (including the four
    identity fields below) is in tools/kb/validate.py's MARKER_KEYS, so this
    stays a raw, single-run data document, never a full knowledge-base
    record on its own -- the graded claim (does this run's evidence move
    RF-06 above HYPOTHESIS, and separately, was "/Script/MISERY" found)
    belongs in a future RESEARCH_LOG.md entry that cites this file by path
    and sha256, per this project's established C-13 discipline, not in this
    document itself.

    Carries identity_self_established/build_key_cross_checked/known_build/
    build_id, mirrored from the SAME establish_build_identity() call main()
    already made for the I-01 document in this same run -- I-03 never
    re-establishes identity independently, exactly like I-02.
    """
    return {
        "capability": CAPABILITY_ID_I03,
        "namepool_rva_hex": result["namepool_rva_hex"],
        "namepool_rva_decimal": int(result["namepool_rva"]),
        "namepool_live_va_hex": result["namepool_live_va_hex"],
        "namepool_live_va_decimal": int(result["namepool_live_va"]),
        "name_pool_initialized_rva_hex": result["name_pool_initialized_rva_hex"],
        "name_pool_initialized_rva_decimal": int(result["name_pool_initialized_rva"]),
        "name_pool_initialized_live_va_hex": result["name_pool_initialized_live_va_hex"],
        "name_pool_initialized_live_va_decimal": int(result["name_pool_initialized_live_va"]),
        "pool_initialized": bool(result["pool_initialized"]),
        "name_entry_id": int(result["name_entry_id"]),
        "decoded": result["decoded"],
        "decoded_as_expected": result["decoded_as_expected"],
        "misery_reflection": misery_reflection,
        "build_key": build_key,
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
    }


def build_manifest(*, run_id: str, arguments: list, tool_version: str,
                   build_key: str, executed_at: str, recorded_at: str,
                   artifacts: list[str] | None,
                   identity_self_established: bool, build_key_cross_checked: bool,
                   known_build: bool, build_id: str | None,
                   capabilities_enabled: list[str] | None = None) -> dict:
    """research/instrument-runs/<timestamp>/manifest.json, conforming to
    research/schema/instrument-run-manifest.schema.json.

    instrument_level 'eri' + capabilities_enabled ['I-01'] only (this pass
    implements nothing else). verify_install_before/after are null: this
    tool never invokes tools/inventory/verify_install.py itself, and the
    schema's own instrument_level=='eri' conditional (as opposed to its
    'ipp' branch, which forces both fields to type object) leaves null
    legal here -- research/instrument-runs/README.md states the before/after
    pair is RECOMMENDED for ERI and MANDATORY only for IPP (plan.md 8.5); the
    schema enforces exactly that asymmetry. If a caller ran verify_install.py
    around this session by hand, that result belongs in a hand-edited copy
    of this manifest, not in this tool's own output -- this tool has no way
    to know it happened.

    Envelope fields (evidence_level/confidence/sources/oracle/build_key/
    recorded_at) are inherited from kb-record.schema.json's own
    #/$defs/envelope via the schema's allOf, exactly as the schema's own
    header comment states; they are supplied here as plain properties of
    the returned dict because that composition is structural on the JSON
    Schema side, not something this Python function needs to mirror.
    confidence is kept below 0.80 deliberately: this record's oracle is
    'runtime-reflection', which kb-record.schema.json's class_p_shape does
    NOT admit for class P, so a confidence >= 0.80 would trigger the
    envelope's 'sources needs >= 2 independent methods' rule -- and a
    single instrument run legitimately has exactly one source, itself.

    claim_type is 'other' with a one-sentence claim_type_note: a manifest's
    claim ("this run happened, against this build, with these arguments,
    with exactly these capabilities on") is a bookkeeping fact about the
    RESEARCH PROCESS, not one of the plan.md 10.5 matrix's fourteen rows
    about the game -- tools/kb/validate.py's own lint_record() demands
    claim_type by default (EV-04) and, once it is 'other', a justification
    field naming why no row fits (JUSTIFICATION_KEYS); omitting claim_type
    entirely is legal per kb-record.schema.json ("optional") but fails this
    project's stricter validator policy, so it is supplied here rather than
    left for every future caller to rediscover.

    identity_self_established/build_key_cross_checked/known_build/build_id
    (research/schema/instrument-run-manifest.schema.json's own properties for
    each, added for LOG-0048/LOG-0049): the same identity-self-establishment
    facts build_i01_document() records on its sibling output document, kept
    on this manifest too so the run's own bookkeeping record states plainly
    HOW its build_key was obtained, not only what it is -- see
    establish_build_identity()'s docstring for the full rule this encodes.

    capabilities_enabled: which I-* ids actually ran this session -- ['I-01']
    when None/omitted (this function's original, still-default behaviour,
    preserved so every caller written before I-02 existed keeps working
    unchanged), or ['I-01', 'I-02'] when the caller also ran I-02 in the same
    session (I-02 depends on I-01's own base_address/image_size read, so it
    is never enabled alone). 'sources' below is derived from this same list,
    one {'method': <id>} entry per capability actually enabled, rather than
    hardcoding I-01 -- each enabled capability is a distinct method this
    run's own claim ("this run happened, with exactly these capabilities
    on") rests on.
    """
    capability_ids = list(capabilities_enabled) if capabilities_enabled else [CAPABILITY_ID]
    return {
        "run_id": run_id,
        "instrument_level": "eri",
        "arguments": list(arguments),
        "tool_version": tool_version,
        "capabilities_enabled": capability_ids,
        "verify_install_before": None,
        "verify_install_after": None,
        "executed_at": executed_at,
        "artifacts": artifacts,
        "evidence_level": "OBSERVED",
        "confidence": 0.75,
        "sources": [{"method": capability_id} for capability_id in capability_ids],
        "oracle": ["runtime-reflection"],
        "claim_type": "other",
        "claim_type_note": (
            "a manifest records that a research instrument ran, not a fact "
            "about the game; no plan.md 10.5 matrix row describes an "
            "instrument-run bookkeeping record (research/schema/"
            "instrument-run-manifest.schema.json 'claim_type_note')."
        ),
        "build_key": build_key,
        # identity self-establishment, mirrored from the I-01 document (see
        # build_i01_document's own comment on these same four fields and
        # establish_build_identity's docstring) -- LOG-0048/LOG-0049.
        "identity_self_established": bool(identity_self_established),
        "build_key_cross_checked": bool(build_key_cross_checked),
        "known_build": bool(known_build),
        "build_id": build_id,
        "recorded_at": recorded_at,
        "notes": (
            "Written by %s (capabilities: %s). recorded_at/executed_at are "
            "real wall-clock time unless --recorded-at pinned them; "
            "--no-timestamp affects only the sibling I-01 output document's "
            "own 'recorded_at' field, never this manifest's, because "
            "instrument-run-manifest.schema.json requires both to be "
            "non-null timestamps at all times." %
            (GENERATOR_NAME, ", ".join(capability_ids))
        ),
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

DEFAULT_PROCESS_NAME = "MISERY-Win64-Shipping.exe"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eri.py",
        description=(
            "ERI capability I-01: find the target process, open it "
            "PROCESS_QUERY_INFORMATION|PROCESS_VM_READ only, and read the "
            "base address and image size of its own module (plan.md 8.2). "
            "Optionally also capability I-02 (--run-i02): verify the RF-05 "
            "candidate GUObjectArray against live structural behaviour. "
            "Optionally also capability I-03 (--run-i03): decode an "
            "FNameEntryId to text via the RF-06 candidate FNamePool, and "
            "optionally (--run-i03-reflection, needs --run-i02 too) a "
            "bounded '/Script/MISERY live reflection' probe over live "
            "UObject names. Writes nothing, injects nothing, hooks nothing, "
            "calls no game function."),
    )
    parser.add_argument(
        "--process-name", default=DEFAULT_PROCESS_NAME, metavar="NAME",
        help="exact (case-insensitive) executable filename to find; NEVER a "
             "substring match (default: %s)" % DEFAULT_PROCESS_NAME)
    parser.add_argument(
        "--build-key", required=False, default=None, metavar="sha256:HEX",
        help="OPTIONAL cross-check against the build_key this run establishes "
             "for ITSELF by hashing the live process's own module.exe_path -- "
             "'sha256:<64 lowercase hex>' (research/schema/kb-record.schema.json "
             "#/$defs/build_key). NEVER the source of truth (LOG-0048/LOG-0049: "
             "a cached/supplied build_key silently outlived a Steam update once "
             "already). Omit this flag -- the normal, preferred way to invoke "
             "this tool -- and the self-computed hash becomes the authoritative "
             "build_key. If given and it does NOT match what this run "
             "independently computed, the run fails loudly with "
             "BuildKeyMismatchError before writing anything; if it matches, the "
             "output documents record that it was independently confirmed.")
    parser.add_argument(
        "--recorded-at", default=None, metavar="ISO8601",
        help="pin the I-01 document's and the manifest's timestamp fields to "
             "this exact ISO-8601 UTC value, for a byte-identical rerun")
    parser.add_argument(
        "--no-timestamp", action="store_true",
        help="omit recorded_at from the I-01 output document (sets it to "
             "null), so two runs against an unchanged target produce "
             "byte-identical JSON for that document. Has no effect on "
             "manifest.json, whose recorded_at/executed_at the schema "
             "requires to be non-null always -- use --recorded-at for a "
             "deterministic manifest too.")
    parser.add_argument(
        "--out", default=None, metavar="PATH",
        help="I-01 process-info JSON output path")
    parser.add_argument(
        "--manifest-out", default=None, metavar="PATH",
        help="manifest.json output path (research/schema/"
             "instrument-run-manifest.schema.json)")
    parser.add_argument(
        "--run-dir", default=None, metavar="DIR",
        help="convenience: sets --out to <run-dir>/i01-process-info.json and "
             "--manifest-out to <run-dir>/manifest.json when either is not "
             "given explicitly, and sets the manifest's run_id to this "
             "directory's own basename (research/instrument-runs/<timestamp>/ "
             "by convention -- see research/instrument-runs/README.md)")
    parser.add_argument(
        "--run-id", default=None, metavar="ID",
        help="manifest.json's run_id; defaults to the basename of --run-dir "
             "if given, else the run's own executed_at timestamp")
    parser.add_argument(
        "--json", action="store_true",
        help="also print a machine-readable one-line summary to stdout")
    parser.add_argument(
        "--run-i02", action="store_true",
        help="also run capability I-02: verify the RF-05 candidate "
             "GUObjectArray against LIVE structural behaviour (plan.md 8.2, "
             "research/evidence/RF-05/README.md's own 'What a runtime "
             "observation would need to show to move this above HYPOTHESIS' "
             "section). Requires I-01's own base_address/image_size from "
             "THIS SAME run -- never enabled standalone. A refuted "
             "candidate is a valid, reported research outcome, not a "
             "failed run (see eri.py's module docstring 'STRUCTURAL "
             "REFUTATION IS A RESULT, NOT AN ERROR').")
    parser.add_argument(
        "--guobjectarray-rva", default=None, metavar="HEX",
        help="override the candidate GUObjectArray RVA I-02 checks "
             "(default: the RF-05 candidate, 0x%x -- research/evidence/"
             "RF-05/README.md). Accepts '0x...' or a plain decimal/hex "
             "string as Python's int(x, 0) understands it." %
             DEFAULT_GUOBJECTARRAY_RVA)
    parser.add_argument(
        "--i02-sample-size", type=int, default=DEFAULT_I02_SAMPLE_SIZE,
        metavar="N",
        help="I-02 check 2: how many non-null sampled objects' vtable "
             "pointers to examine before stopping (default: %d)" %
             DEFAULT_I02_SAMPLE_SIZE)
    parser.add_argument(
        "--i02-poll-interval-seconds", type=float,
        default=DEFAULT_I02_POLL_INTERVAL_SECONDS, metavar="SECONDS",
        help="I-02 check 3: how long to wait between the two NumElements "
             "reads (default: %.1f)" % DEFAULT_I02_POLL_INTERVAL_SECONDS)
    parser.add_argument(
        "--i02-max-scan-indices", type=int,
        default=DEFAULT_I02_MAX_SCAN_INDICES, metavar="N",
        help="I-02 check 2: hard cap on how many object-array index slots "
             "may be looked at while searching for --i02-sample-size "
             "non-null objects, so a corrupted (implausibly huge, or "
             "all-null) NumElements cannot turn the sample walk into an "
             "unbounded scan (default: %d)" % DEFAULT_I02_MAX_SCAN_INDICES)
    parser.add_argument(
        "--i02-out", default=None, metavar="PATH",
        help="I-02 GUObjectArray-verification JSON output path; defaults "
             "to <run-dir>/i02-guobjectarray.json when --run-dir is given")
    parser.add_argument(
        "--run-i03", action="store_true",
        help="also run capability I-03: decode an FNameEntryId to text via "
             "the RF-06 candidate FNamePool (plan.md 8.2, research/evidence/"
             "RF-06/README.md's own 'What a runtime observation would need "
             "to show to move this above HYPOTHESIS' steps 1-2). By default "
             "decodes FNameEntryId 0 (EName::None), the one case with a "
             "known expected answer ('None') -- see --i03-name-entry-id. "
             "Requires I-01's own base_address/image_size from THIS SAME "
             "run -- never enabled standalone. A decode that does not match "
             "the expected text for id=0 is a valid, reported structural "
             "refutation, not a failed run (see eri.py's module docstring "
             "'STRUCTURAL REFUTATION IS A RESULT, NOT AN ERROR').")
    parser.add_argument(
        "--namepool-rva", default=None, metavar="HEX",
        help="override the candidate FNamePool/NamePoolData RVA I-03 reads "
             "(default: the RF-06 candidate, 0x%x -- research/evidence/"
             "RF-06/README.md). Accepts '0x...' or a plain decimal/hex "
             "string as Python's int(x, 0) understands it." %
             DEFAULT_NAMEPOOL_RVA)
    parser.add_argument(
        "--name-pool-initialized-rva", default=None, metavar="HEX",
        help="override the candidate bNamePoolInitialized guard-byte RVA "
             "I-03 reads (default: the RF-06 candidate, 0x%x -- "
             "research/evidence/RF-06/README.md)." %
             DEFAULT_NAME_POOL_INITIALIZED_RVA)
    parser.add_argument(
        "--i03-name-entry-id", type=lambda s: int(s, 0),
        default=0, metavar="ID",
        help="which FNameEntryId to decode (default: 0, EName::None -- the "
             "one id with a known expected decoded text, 'None'). Accepts "
             "'0x...' or a plain decimal/hex string.")
    parser.add_argument(
        "--i03-out", default=None, metavar="PATH",
        help="I-03 FNamePool-decode JSON output path; defaults to "
             "<run-dir>/i03-fnamepool.json when --run-dir is given")
    parser.add_argument(
        "--run-i03-reflection", action="store_true",
        help="also run the '/Script/MISERY live reflection' probe: search "
             "a bounded sample of live UObjects (found via I-02's own "
             "chunk-walk arithmetic) for one whose decoded name equals the "
             "literal leaf FName 'MISERY'. Requires BOTH --run-i02 (for the "
             "GUObjectArray objects pointer/NumElements) and --run-i03 (for "
             "the FNamePool decode) in THIS SAME run -- never enabled "
             "standalone. This is a bounded, NOT exhaustive search: a miss "
             "is reported honestly as 'not found in this sample', never as "
             "a refutation of anything (see sample_object_names()'s own "
             "docstring in eri.py).")
    parser.add_argument(
        "--i03-reflection-sample-size", type=int,
        default=DEFAULT_I03_REFLECTION_SAMPLE_SIZE, metavar="N",
        help="--run-i03-reflection: how many non-null live objects' names "
             "to decode before stopping (default: %d -- deliberately larger "
             "than --i02-sample-size's own default, since this is a needle "
             "search for one specific object rather than a statistical "
             "vtable-plausibility sample; see DEFAULT_I03_REFLECTION_SAMPLE_"
             "SIZE's own comment in eri.py)" % DEFAULT_I03_REFLECTION_SAMPLE_SIZE)
    parser.add_argument(
        "--i03-reflection-max-scan-indices", type=int,
        default=DEFAULT_I02_MAX_SCAN_INDICES, metavar="N",
        help="--run-i03-reflection: hard cap on how many object-array index "
             "slots may be looked at while searching for "
             "--i03-reflection-sample-size non-null objects (default: %d, "
             "same default as --i02-max-scan-indices)" %
             DEFAULT_I02_MAX_SCAN_INDICES)
    parser.add_argument(
        "--name-private-offset", default=None, metavar="HEX",
        help="override the byte offset of UObjectBase::NamePrivate's own "
             "FNameEntryId component (default: 0x%x -- derived from "
             "UObjectBase.h and cross-checked against RF-05's own "
             "InternalIndex==+0xc finding; see DEFAULT_NAME_PRIVATE_OFFSET's "
             "own comment in eri.py)." % DEFAULT_NAME_PRIVATE_OFFSET)
    parser.add_argument(
        "--run-i04", action="store_true",
        help="also run capability I-04: dump UClass instances with their "
             "inheritance-adjacent identity (plan.md 8.2, 'Дамп UClass с "
             "иерархией наследования') by walking EVERY located UObject in "
             "I-02's own GUObjectArray (not a bounded sample), decoding "
             "each one's own NamePrivate via I-03's own FNamePool decode, "
             "and classifying which ones ARE UClass instances via a "
             "ClassPrivate self-reference fixed point -- never by reading "
             "any UClass/UStruct/UField-specific field (see eri.py's own "
             "module docstring, 'WHAT I-04 IS', for the exact algorithm and "
             "its scope boundary). Requires BOTH --run-i02 and --run-i03 in "
             "THIS SAME run -- never enabled standalone. Writes a raw JSON "
             "summary (--i04-out) and a SEPARATE classes.jsonl artifact "
             "(--classes-jsonl-out): every /Script/MISERY class found, plus "
             "a small bounded /Game sample -- never the hundreds of native "
             "engine classes this walk also finds (their total count is "
             "reported, never persisted).")
    parser.add_argument(
        "--class-private-offset", default=None, metavar="HEX",
        help="override the byte offset of UObjectBase::ClassPrivate "
             "(default: 0x%x -- derived from UObjectBase.h's own member "
             "declaration order; see DEFAULT_CLASS_PRIVATE_OFFSET's own "
             "comment in eri.py)." % DEFAULT_CLASS_PRIVATE_OFFSET)
    parser.add_argument(
        "--outer-private-offset", default=None, metavar="HEX",
        help="override the byte offset of UObjectBase::OuterPrivate "
             "(default: 0x%x -- the ONE genuinely new offset I-04 "
             "introduces; see DEFAULT_OUTER_PRIVATE_OFFSET's own comment "
             "in eri.py)." % DEFAULT_OUTER_PRIVATE_OFFSET)
    parser.add_argument(
        "--i04-max-scan-indices", type=int, default=DEFAULT_I02_MAX_SCAN_INDICES,
        metavar="N",
        help="I-04: hard cap on how many GUObjectArray index slots are "
             "examined -- I-04 is NOT a bounded sample like I-02/I-03's own "
             "probes, it walks every located object up to this cap "
             "(default: %d, same default as --i02-max-scan-indices)" %
             DEFAULT_I02_MAX_SCAN_INDICES)
    parser.add_argument(
        "--i04-max-outer-depth", type=int, default=DEFAULT_I04_MAX_OUTER_DEPTH,
        metavar="N",
        help="I-04: bound on how many Outer hops object_path construction "
             "follows before treating the walk as a traversal failure "
             "(default: %d)" % DEFAULT_I04_MAX_OUTER_DEPTH)
    parser.add_argument(
        "--i04-max-fixed-point-passes", type=int,
        default=DEFAULT_I04_MAX_FIXED_POINT_PASSES, metavar="N",
        help="I-04: bound on how many passes the ClassPrivate self-"
             "reference fixed point iterates before giving up on "
             "convergence (default: %d)" % DEFAULT_I04_MAX_FIXED_POINT_PASSES)
    parser.add_argument(
        "--i04-game-sample-cap", type=int, default=DEFAULT_I04_GAME_SAMPLE_CAP,
        metavar="N",
        help="I-04: cap on how many /Game/* UClass instances (Blueprint-"
             "generated ones prioritized) are WRITTEN to classes.jsonl -- "
             "the full count found is still reported in the raw i04 "
             "document and CLI summary regardless of this cap (default: "
             "%d)" % DEFAULT_I04_GAME_SAMPLE_CAP)
    parser.add_argument(
        "--i04-out", default=None, metavar="PATH",
        help="I-04 raw JSON output path; defaults to <run-dir>/"
             "i04-classes.json when --run-dir is given")
    parser.add_argument(
        "--classes-jsonl-out", default=None, metavar="PATH",
        help="I-04's classes.jsonl output path (research/schema/"
             "reflection-record.schema.json's class_record branch); "
             "defaults to <run-dir>/classes.jsonl when --run-dir is given. "
             "The operator must pass this explicitly to write to the final "
             "committed location, research/reflection/<build_id>/"
             "classes.jsonl -- this tool does not auto-derive that path "
             "from build identity, matching every other per-capability "
             "output path in this file")
    parser.add_argument(
        "--run-i06", action="store_true",
        help="also run capability I-06: decode FProperty for a small, "
             "proof-set-first sample of already-classified classes (plan.md "
             "8.2, 'Декодер FProperty') by walking each class's own "
             "UStruct::ChildProperties (+0x50) Next-linked FField chain, "
             "resolving each entry's FFieldClass name via a SuperClass "
             "chain walk (never a hardcoded EClassCastFlags bit), and "
             "reading FProperty's own base fields plus the 12 named "
             "type-specific field sets (see eri.py's own module docstring, "
             "'WHAT I-06 IS', for the exact algorithm and its scope "
             "boundary -- no ProcessEvent, no UFunction, no individual "
             "EPropertyFlags bit decoding, no UScriptStruct-owned property "
             "traversal). Requires --run-i04 in THIS SAME run -- never "
             "enabled standalone, and never re-walks GUObjectArray itself: "
             "the proof set is a deterministic, bounded selection over "
             "I-04's own already-classified class list (every "
             "/Script/MISERY class, I-04's own bounded /Game sample, and "
             "up to --i06-engine-class-cap well-known engine classes). "
             "Writes a raw JSON summary (--i06-out) and a SEPARATE "
             "properties.jsonl artifact (--properties-jsonl-out).")
    parser.add_argument(
        "--child-properties-offset", default=None, metavar="HEX",
        help="override the byte offset of UStruct::ChildProperties "
             "(default: 0x%x -- UObjectBase(0x28)+UField's own Next(+0x28, "
             "total 0x30)+a private FStructBaseChain base subobject "
             "(+0x30..+0x3F, present in every non-editor/Shipping build)+"
             "UStruct's own SuperStruct(+0x40)/Children(+0x48)/"
             "ChildProperties(+0x50); see "
             "USTRUCT_CHILD_PROPERTIES_OFFSET's own comment in eri.py)." %
             USTRUCT_CHILD_PROPERTIES_OFFSET)
    parser.add_argument(
        "--i06-max-chain-length", type=int,
        default=DEFAULT_I06_MAX_PROPERTY_CHAIN_LENGTH, metavar="N",
        help="I-06: bound on how many siblings UStruct::ChildProperties' "
             "own Next-linked FField chain is walked before treating the "
             "walk as a traversal failure (default: %d)" %
             DEFAULT_I06_MAX_PROPERTY_CHAIN_LENGTH)
    parser.add_argument(
        "--i06-max-superclass-depth", type=int,
        default=DEFAULT_I06_MAX_SUPERCLASS_DEPTH, metavar="N",
        help="I-06: bound on how many FFieldClass::SuperClass hops the "
             "type-dispatch walk follows before treating it as a traversal "
             "failure (default: %d)" % DEFAULT_I06_MAX_SUPERCLASS_DEPTH)
    parser.add_argument(
        "--i06-max-container-depth", type=int,
        default=DEFAULT_I06_MAX_CONTAINER_NESTING_DEPTH, metavar="N",
        help="I-06: bound on how deeply a container property's own Inner/"
             "KeyProp/ValueProp/UnderlyingProp is recursively decoded "
             "(default: %d, generous for a realistic TArray<TArray<X>>)" %
             DEFAULT_I06_MAX_CONTAINER_NESTING_DEPTH)
    parser.add_argument(
        "--i06-engine-class-cap", type=int,
        default=DEFAULT_I06_PROOF_SET_ENGINE_CLASS_CAP, metavar="N",
        help="I-06: cap on how many well-known engine classes "
             "(I06_ENGINE_CLASS_NAME_PREFERENCE order) are added to the "
             "proof set beyond the /Script/MISERY and /Game classes I-04 "
             "already selected (default: %d)" %
             DEFAULT_I06_PROOF_SET_ENGINE_CLASS_CAP)
    parser.add_argument(
        "--i06-out", default=None, metavar="PATH",
        help="I-06 raw JSON output path; defaults to <run-dir>/"
             "i06-properties.json when --run-dir is given")
    parser.add_argument(
        "--properties-jsonl-out", default=None, metavar="PATH",
        help="I-06's properties.jsonl output path (research/schema/"
             "reflection-record.schema.json's property_record branch); "
             "defaults to <run-dir>/properties.jsonl when --run-dir is "
             "given. The operator must pass this explicitly to write to "
             "the final committed location, research/reflection/"
             "<build_id>/properties.jsonl -- this tool does not "
             "auto-derive that path from build identity, matching every "
             "other per-capability output path in this file")
    parser.add_argument(
        "--run-i05", action="store_true",
        help="also run capability I-05: decode UFunction (plan.md 8.2, "
             "'Декодер UFunction') -- FunctionFlags, its own parameter list "
             "(walked via the SAME UStruct::ChildProperties/FField::Next "
             "mechanism I-06 already uses, reused completely unchanged, "
             "since UFunction : public UStruct), which parameter (if any) "
             "is the return value, and parameter order (see eri.py's own "
             "module docstring, 'WHAT I-05 IS', for the exact algorithm, "
             "its scope boundary, and the MANDATORY EMPIRICAL SELF-CHECK "
             "this capability builds in for its own newly-introduced, "
             "not-yet-live-verified UStruct-total-size offset). Requires "
             "--run-i04 in THIS SAME run -- never enabled standalone, and "
             "never re-walks GUObjectArray itself: the proof set is the "
             "SAME deterministic, bounded selection over I-04's own "
             "already-classified class list that I-06 already uses "
             "(select_i06_proof_set(), reused verbatim). Deliberately does "
             "NOT require --run-i06: I-05 uses nothing run_i06() itself "
             "computes. Writes a raw JSON summary (--i05-out) and a "
             "SEPARATE functions.jsonl artifact (--functions-jsonl-out).")
    parser.add_argument(
        "--children-offset", default=None, metavar="HEX",
        help="override the byte offset of UStruct::Children (default: "
             "0x%x -- see USTRUCT_CHILDREN_OFFSET's own comment in eri.py)."
             % USTRUCT_CHILDREN_OFFSET)
    parser.add_argument(
        "--ufield-next-offset", default=None, metavar="HEX",
        help="override the byte offset of UField::Next (default: 0x%x -- "
             "see DEFAULT_UFIELD_NEXT_OFFSET's own comment in eri.py)." %
             DEFAULT_UFIELD_NEXT_OFFSET)
    parser.add_argument(
        "--i05-children-max-chain-length", type=int,
        default=DEFAULT_I05_MAX_CHILDREN_CHAIN_LENGTH, metavar="N",
        help="I-05: bound on how many siblings UClass::Children's own "
             "UField::Next-linked chain is walked before treating the walk "
             "as a traversal failure (default: %d). I-05 reuses I-06's own "
             "--i06-max-chain-length/--i06-max-superclass-depth/"
             "--i06-max-container-depth DIRECTLY for a function's own "
             "parameter (ChildProperties) chain walk -- there is no "
             "separate --i05-* flag for those, deliberately, since it is "
             "the identical underlying bound." %
             DEFAULT_I05_MAX_CHILDREN_CHAIN_LENGTH)
    parser.add_argument(
        "--i05-out", default=None, metavar="PATH",
        help="I-05 raw JSON output path; defaults to <run-dir>/"
             "i05-functions.json when --run-dir is given")
    parser.add_argument(
        "--functions-jsonl-out", default=None, metavar="PATH",
        help="I-05's functions.jsonl output path (research/schema/"
             "reflection-record.schema.json's function_record branch); "
             "defaults to <run-dir>/functions.jsonl when --run-dir is "
             "given. The operator must pass this explicitly to write to "
             "the final committed location, research/reflection/"
             "<build_id>/functions.jsonl -- this tool does not "
             "auto-derive that path from build identity, matching every "
             "other per-capability output path in this file")
    parser.add_argument(
        "--run-i14", action="store_true",
        help="also run I-14: report which .pak containers this process "
             "currently has MOUNTED, read from the engine's own "
             "FPakPlatformFile::PakFiles list rather than from the "
             "filesystem. Each container is identified by its own decoded "
             "PakFilename and MountPoint, not by position. Independent of "
             "every other capability: the pak system is not a UObject, so "
             "this shares nothing with I-02/I-03/I-04 and can run alone. "
             "Strictly read-only, like every other capability here.")
    parser.add_argument(
        "--i14-out", metavar="PATH",
        help="I-14 JSON output path; defaults to <run-dir>/i14-mounted-paks.json "
             "when --run-dir is given")
    parser.add_argument(
        "--platform-file-manager-rva", type=lambda v: int(v, 0),
        default=DEFAULT_PLATFORM_FILE_MANAGER_RVA, metavar="RVA",
        help="override the FPlatformFileManager singleton RVA I-14 anchors on "
             "(default 0x%x). Its only member is TopmostPlatformFile at offset "
             "0, so this address IS that pointer. A candidate, verified live: "
             "the chain walk refuses to believe any node whose vtable is not "
             "FPakPlatformFile's." % DEFAULT_PLATFORM_FILE_MANAGER_RVA)
    parser.add_argument(
        "--pak-platform-file-vtable-rva", type=lambda v: int(v, 0),
        default=DEFAULT_PAKPLATFORMFILE_VTABLE_RVA, metavar="RVA",
        help="override the FPakPlatformFile vtable RVA used as I-14's identity "
             "predicate (default 0x%x)" % DEFAULT_PAKPLATFORMFILE_VTABLE_RVA)
    parser.add_argument(
        "--run-pe02-vtable-scan", action="store_true",
        help="also run PE-02: gather LIVE evidence for the PE-01 "
             "UObject::ProcessEvent vtable-slot HYPOTHESIS (research/"
             "evidence/PE-01/README.md, slot 77 / byte offset 0x268) by "
             "reading, for a bounded sample of I-04's OWN already-"
             "classified valid objects, each object's OWN instance vtable "
             "pointer and the candidate function pointer stored at "
             "--processevent-vtable-slot's own slot, then tallying the "
             "resulting candidate addresses by frequency AND by how many "
             "DISTINCT object classes observed each one (see eri.py's own "
             "module docstring, 'WHAT PE-02 IS', for the full algorithm and "
             "why this is NOT a plan.md 8.2 'I-0N' capability id). Requires "
             "--run-i04 in THIS SAME run -- never enabled standalone, and "
             "never re-walks GUObjectArray itself: the sample is drawn from "
             "I-04's own already-walked, already-validated objects_by_"
             "address. Writes a raw JSON summary (--pe02-out) only, no "
             "JSONL, no confidence grading, no conclusion -- this "
             "capability surfaces data for a human to separately correlate "
             "against static disassembly (pyghidra_scripts/dump_"
             "function.py), by hand, outside this tool.")
    parser.add_argument(
        "--processevent-vtable-slot", default=None, metavar="N",
        help="override the 0-indexed C++ vtable slot PE-02 reads as the "
             "ProcessEvent candidate (default: %d, byte offset 0x%x -- "
             "PE-01/README.md's own HYPOTHESIS under the UE_WITH_IRIS=1 "
             "assumption; would be slot 76/0x260 under UE_WITH_IRIS=0, the "
             "one ambiguity that static count could not resolve). This is "
             "the SLOT NUMBER, not a byte offset -- see "
             "DEFAULT_PROCESSEVENT_VTABLE_SLOT's own comment in eri.py. "
             "Accepts '0x...' or a plain decimal/hex string as Python's "
             "int(x, 0) understands it." %
             (DEFAULT_PROCESSEVENT_VTABLE_SLOT,
              _vtable_slot_byte_offset(DEFAULT_PROCESSEVENT_VTABLE_SLOT)))
    parser.add_argument(
        "--pe02-vtable-sample-size", type=int,
        default=DEFAULT_PE02_VTABLE_SAMPLE_SIZE, metavar="N",
        help="PE-02: how many of I-04's own valid objects to sample "
             "(default: %d; if fewer valid objects exist, all of them are "
             "used, never treated as an error)" % DEFAULT_PE02_VTABLE_SAMPLE_SIZE)
    parser.add_argument(
        "--pe02-out", default=None, metavar="PATH",
        help="PE-02 raw JSON output path; defaults to <run-dir>/"
             "pe02-vtable-scan.json when --run-dir is given")
    return parser


def _resolve_output_paths(args: argparse.Namespace) -> tuple[str, str]:
    out_path = args.out
    manifest_path = args.manifest_out
    if args.run_dir:
        if out_path is None:
            out_path = os.path.join(args.run_dir, "i01-process-info.json")
        if manifest_path is None:
            manifest_path = os.path.join(args.run_dir, "manifest.json")
    if not out_path or not manifest_path:
        raise ValueError(
            "both --out and --manifest-out are required unless --run-dir is "
            "given (it supplies defaults for whichever of the two is not "
            "passed explicitly)")
    return out_path, manifest_path


def _resolve_i02_output_path(args: argparse.Namespace) -> str | None:
    """None when --run-i02 was not given (nothing to resolve). Otherwise the
    I-02 output path: --i02-out if given explicitly, else
    <run-dir>/i02-guobjectarray.json via the same --run-dir convenience
    --out/--manifest-out already use. Raises ValueError, at parse time,
    before any handle is opened, if --run-i02 was given with neither
    --i02-out nor --run-dir to derive it from -- the same "fail loudly
    before doing any work" shape _resolve_output_paths above already has for
    --out/--manifest-out.
    """
    if not args.run_i02:
        return None
    if args.i02_out:
        return args.i02_out
    if args.run_dir:
        return os.path.join(args.run_dir, "i02-guobjectarray.json")
    raise ValueError(
        "--run-i02 requires --i02-out unless --run-dir is given (it "
        "supplies the default <run-dir>/i02-guobjectarray.json)")


def _resolve_i03_output_path(args: argparse.Namespace) -> str | None:
    """None when --run-i03 was not given (nothing to resolve). Otherwise the
    I-03 output path: --i03-out if given explicitly, else
    <run-dir>/i03-fnamepool.json via the same --run-dir convenience
    --out/--manifest-out/--i02-out already use. Raises ValueError, before
    any handle is opened, if --run-i03 was given with neither --i03-out nor
    --run-dir to derive it from -- identical shape to
    _resolve_i02_output_path above.
    """
    if not args.run_i03:
        return None
    if args.i03_out:
        return args.i03_out
    if args.run_dir:
        return os.path.join(args.run_dir, "i03-fnamepool.json")
    raise ValueError(
        "--run-i03 requires --i03-out unless --run-dir is given (it "
        "supplies the default <run-dir>/i03-fnamepool.json)")


def _validate_i03_reflection_requirements(args: argparse.Namespace) -> None:
    """Raises ValueError, before any handle is opened, if --run-i03-reflection
    was given without BOTH --run-i02 (the probe needs its own objects
    pointer/NumElements) and --run-i03 (the probe needs its own FNamePool
    decode function) in this SAME invocation -- the same "fail loudly before
    doing any work" discipline every other CLI-shape check in this file
    already follows, rather than discovering the missing dependency only
    after I-01 (and possibly I-02 or I-03 alone) has already run.
    """
    if not args.run_i03_reflection:
        return
    missing = []
    if not args.run_i02:
        missing.append("--run-i02")
    if not args.run_i03:
        missing.append("--run-i03")
    if missing:
        raise ValueError(
            "--run-i03-reflection requires %s in this same invocation -- "
            "the '/Script/MISERY' probe reuses I-02's own GUObjectArray "
            "objects pointer/NumElements and I-03's own FNamePool decode, "
            "and is never run standalone." % " and ".join(missing))


def _resolve_i04_output_path(args: argparse.Namespace) -> str | None:
    """None when --run-i04 was not given. Otherwise the I-04 raw-JSON output
    path: --i04-out if given explicitly, else <run-dir>/i04-classes.json via
    the same --run-dir convenience --out/--i02-out/--i03-out already use.
    Raises ValueError, before any handle is opened, if --run-i04 was given
    with neither --i04-out nor --run-dir -- identical shape to
    _resolve_i02_output_path/_resolve_i03_output_path above.
    """
    if not args.run_i04:
        return None
    if args.i04_out:
        return args.i04_out
    if args.run_dir:
        return os.path.join(args.run_dir, "i04-classes.json")
    raise ValueError(
        "--run-i04 requires --i04-out unless --run-dir is given (it "
        "supplies the default <run-dir>/i04-classes.json)")


def _resolve_classes_jsonl_path(args: argparse.Namespace) -> str | None:
    """None when --run-i04 was not given. Otherwise I-04's classes.jsonl
    output path: --classes-jsonl-out if given explicitly, else
    <run-dir>/classes.jsonl -- the SAME --run-dir convenience every other
    per-capability output path in this file uses, deliberately NOT an
    auto-derived research/reflection/<build_id>/ path (see
    --classes-jsonl-out's own help text: the operator passes that
    explicitly when writing to the final committed location).
    """
    if not args.run_i04:
        return None
    if args.classes_jsonl_out:
        return args.classes_jsonl_out
    if args.run_dir:
        return os.path.join(args.run_dir, "classes.jsonl")
    raise ValueError(
        "--run-i04 requires --classes-jsonl-out unless --run-dir is given "
        "(it supplies the default <run-dir>/classes.jsonl)")


def _validate_i04_requirements(args: argparse.Namespace) -> None:
    """Raises ValueError, before any handle is opened, if --run-i04 was
    given without BOTH --run-i02 (I-04 reuses its own GUObjectArray objects
    pointer/NumElements, never re-walking the array from scratch) and
    --run-i03 (I-04 reuses its own FNamePool decode, never adding a second
    FNamePool-reading code path) in this SAME invocation -- the identical
    "fail loudly before doing any work" shape
    _validate_i03_reflection_requirements above already established.
    """
    if not args.run_i04:
        return
    missing = []
    if not args.run_i02:
        missing.append("--run-i02")
    if not args.run_i03:
        missing.append("--run-i03")
    if missing:
        raise ValueError(
            "--run-i04 requires %s in this same invocation -- I-04 reuses "
            "I-02's own GUObjectArray objects pointer/NumElements and "
            "I-03's own FNamePool decode, and is never run standalone." %
            " and ".join(missing))


def _resolve_i06_output_path(args: argparse.Namespace) -> str | None:
    """None when --run-i06 was not given. Otherwise the I-06 raw-JSON output
    path: --i06-out if given explicitly, else <run-dir>/i06-properties.json
    via the same --run-dir convenience --out/--i02-out/--i03-out/--i04-out
    already use. Raises ValueError, before any handle is opened, if
    --run-i06 was given with neither --i06-out nor --run-dir -- identical
    shape to _resolve_i04_output_path above.
    """
    if not args.run_i06:
        return None
    if args.i06_out:
        return args.i06_out
    if args.run_dir:
        return os.path.join(args.run_dir, "i06-properties.json")
    raise ValueError(
        "--run-i06 requires --i06-out unless --run-dir is given (it "
        "supplies the default <run-dir>/i06-properties.json)")


def _resolve_properties_jsonl_path(args: argparse.Namespace) -> str | None:
    """None when --run-i06 was not given. Otherwise I-06's properties.jsonl
    output path: --properties-jsonl-out if given explicitly, else
    <run-dir>/properties.jsonl -- the SAME --run-dir convenience every other
    per-capability output path in this file uses, deliberately NOT an
    auto-derived research/reflection/<build_id>/ path (see
    --properties-jsonl-out's own help text: the operator passes that
    explicitly when writing to the final committed location).
    """
    if not args.run_i06:
        return None
    if args.properties_jsonl_out:
        return args.properties_jsonl_out
    if args.run_dir:
        return os.path.join(args.run_dir, "properties.jsonl")
    raise ValueError(
        "--run-i06 requires --properties-jsonl-out unless --run-dir is "
        "given (it supplies the default <run-dir>/properties.jsonl)")


def _validate_i06_requirements(args: argparse.Namespace) -> None:
    """Raises ValueError, before any handle is opened, if --run-i06 was
    given without --run-i04 in this SAME invocation -- I-06 reuses I-04's
    own already-classified class list as its proof set and never re-walks
    GUObjectArray itself (I-04's own _validate_i04_requirements() already
    separately guarantees --run-i02/--run-i03 whenever --run-i04 is given,
    so I-06 does not need to re-state that transitive requirement here --
    the identical "fail loudly before doing any work" shape
    _validate_i04_requirements above already established).
    """
    if not args.run_i06:
        return
    if not args.run_i04:
        raise ValueError(
            "--run-i06 requires --run-i04 in this same invocation -- I-06 "
            "reuses I-04's own already-classified class list as its proof "
            "set, and never re-walks GUObjectArray itself.")


def _resolve_i05_output_path(args: argparse.Namespace) -> str | None:
    """None when --run-i05 was not given. Otherwise the I-05 raw-JSON output
    path: --i05-out if given explicitly, else <run-dir>/i05-functions.json
    via the same --run-dir convenience every other per-capability output
    path in this file uses. Raises ValueError, before any handle is opened,
    if --run-i05 was given with neither --i05-out nor --run-dir -- identical
    shape to _resolve_i06_output_path above.
    """
    if not args.run_i05:
        return None
    if args.i05_out:
        return args.i05_out
    if args.run_dir:
        return os.path.join(args.run_dir, "i05-functions.json")
    raise ValueError(
        "--run-i05 requires --i05-out unless --run-dir is given (it "
        "supplies the default <run-dir>/i05-functions.json)")


def _resolve_functions_jsonl_path(args: argparse.Namespace) -> str | None:
    """None when --run-i05 was not given. Otherwise I-05's functions.jsonl
    output path: --functions-jsonl-out if given explicitly, else
    <run-dir>/functions.jsonl -- the SAME --run-dir convenience every other
    per-capability output path in this file uses, deliberately NOT an
    auto-derived research/reflection/<build_id>/ path (see
    --functions-jsonl-out's own help text: the operator passes that
    explicitly when writing to the final committed location).
    """
    if not args.run_i05:
        return None
    if args.functions_jsonl_out:
        return args.functions_jsonl_out
    if args.run_dir:
        return os.path.join(args.run_dir, "functions.jsonl")
    raise ValueError(
        "--run-i05 requires --functions-jsonl-out unless --run-dir is "
        "given (it supplies the default <run-dir>/functions.jsonl)")


def _validate_i05_requirements(args: argparse.Namespace) -> None:
    """Raises ValueError, before any handle is opened, if --run-i05 was
    given without --run-i04 in this SAME invocation -- I-05 reuses I-04's
    own already-classified class list (both as its proof set, via
    select_i06_proof_set(), and to find the 'Function' meta-class address by
    name) and never re-walks GUObjectArray itself. DELIBERATELY does not
    require --run-i06, unlike this file's own _validate_i06_requirements()
    shape might suggest by analogy -- I-05 uses NOTHING run_i06() itself
    computes (only I-04's own data), so requiring --run-i06 anyway would be
    requiring a capability this one has no actual data dependency on, the
    exact mistake the module docstring's "PROOF SET" section warns against
    (mirrors I-06's OWN choice not to require --run-i02/--run-i03 directly,
    since those are I-04's own already-separately-guaranteed transitive
    requirements, not I-06's own).
    """
    if not args.run_i05:
        return
    if not args.run_i04:
        raise ValueError(
            "--run-i05 requires --run-i04 in this same invocation -- I-05 "
            "reuses I-04's own already-classified class list as its proof "
            "set and to find the 'Function' meta-class address by name, "
            "and never re-walks GUObjectArray itself.")


def _resolve_i14_output_path(args: argparse.Namespace) -> str | None:
    """None when --run-i14 was not given. Otherwise --i14-out if explicit, else
    <run-dir>/i14-mounted-paks.json -- the same --run-dir convenience every
    other per-capability output path here uses, and the same fail-before-any-
    handle-is-opened contract."""
    if not args.run_i14:
        return None
    if args.i14_out:
        return args.i14_out
    if args.run_dir:
        return os.path.join(args.run_dir, "i14-mounted-paks.json")
    raise ValueError(
        "--run-i14 requires --i14-out unless --run-dir is given (it supplies "
        "the default <run-dir>/i14-mounted-paks.json)")


def _resolve_pe02_output_path(args: argparse.Namespace) -> str | None:
    """None when --run-pe02-vtable-scan was not given. Otherwise the PE-02
    raw-JSON output path: --pe02-out if given explicitly, else <run-dir>/
    pe02-vtable-scan.json via the same --run-dir convenience every other
    per-capability output path in this file uses. Raises ValueError, before
    any handle is opened, if --run-pe02-vtable-scan was given with neither
    --pe02-out nor --run-dir -- identical shape to _resolve_i04_output_path/
    _resolve_i05_output_path above.
    """
    if not args.run_pe02_vtable_scan:
        return None
    if args.pe02_out:
        return args.pe02_out
    if args.run_dir:
        return os.path.join(args.run_dir, "pe02-vtable-scan.json")
    raise ValueError(
        "--run-pe02-vtable-scan requires --pe02-out unless --run-dir is "
        "given (it supplies the default <run-dir>/pe02-vtable-scan.json)")


def _validate_pe02_requirements(args: argparse.Namespace) -> None:
    """Raises ValueError, before any handle is opened, if
    --run-pe02-vtable-scan was given without --run-i04 in this SAME
    invocation -- PE-02 (research/evidence/PE-01/README.md's own evidence
    track, NOT a plan.md 8.2 'I-0N' capability, see the module docstring's
    "WHAT PE-02 IS" section) reuses I-04's own already-walked, already-
    validated objects_by_address dict as its sampling population, and never
    re-walks GUObjectArray itself -- the identical "fail loudly before doing
    any work" shape _validate_i06_requirements()/_validate_i05_requirements()
    above already establish.
    """
    if not args.run_pe02_vtable_scan:
        return
    if not args.run_i04:
        raise ValueError(
            "--run-pe02-vtable-scan requires --run-i04 in this same "
            "invocation -- PE-02 reuses I-04's own already-walked, "
            "already-validated objects_by_address dict as its sampling "
            "population, and never re-walks GUObjectArray itself.")


def _parse_int_literal(value: str | None, default: int, flag_name: str) -> int:
    """*default* when *value* is None (the normal case); otherwise
    int(value, 0) so '0x7a78ed0', '0X7A78ED0' and a plain decimal string are
    all accepted -- matching Python's own int-literal grammar rather than
    inventing a narrower one. Raises ValueError (caught by main()'s existing
    except clause, exactly like a malformed --build-key) on anything else,
    BEFORE any handle is opened. Shared by every RVA/offset-override CLI
    flag in this file (--guobjectarray-rva, --namepool-rva,
    --name-pool-initialized-rva, --name-private-offset) so the same parsing
    rule and error message shape is not re-derived once per flag.
    """
    if value is None:
        return default
    try:
        return int(value, 0)
    except ValueError:
        raise ValueError(
            "%s %r is not a valid integer literal -- give a hex value like "
            "'0x7a78ed0' or a plain decimal string." % (flag_name, value))


def _parse_guobjectarray_rva(value: str | None) -> int:
    return _parse_int_literal(value, DEFAULT_GUOBJECTARRAY_RVA, "--guobjectarray-rva")


def _parse_namepool_rva(value: str | None) -> int:
    return _parse_int_literal(value, DEFAULT_NAMEPOOL_RVA, "--namepool-rva")


def _parse_name_pool_initialized_rva(value: str | None) -> int:
    return _parse_int_literal(
        value, DEFAULT_NAME_POOL_INITIALIZED_RVA, "--name-pool-initialized-rva")


def _parse_name_private_offset(value: str | None) -> int:
    return _parse_int_literal(value, DEFAULT_NAME_PRIVATE_OFFSET, "--name-private-offset")


def _parse_class_private_offset(value: str | None) -> int:
    return _parse_int_literal(value, DEFAULT_CLASS_PRIVATE_OFFSET, "--class-private-offset")


def _parse_outer_private_offset(value: str | None) -> int:
    return _parse_int_literal(value, DEFAULT_OUTER_PRIVATE_OFFSET, "--outer-private-offset")


def _parse_child_properties_offset(value: str | None) -> int:
    return _parse_int_literal(
        value, USTRUCT_CHILD_PROPERTIES_OFFSET, "--child-properties-offset")


def _parse_children_offset(value: str | None) -> int:
    return _parse_int_literal(value, USTRUCT_CHILDREN_OFFSET, "--children-offset")


def _parse_ufield_next_offset(value: str | None) -> int:
    return _parse_int_literal(value, DEFAULT_UFIELD_NEXT_OFFSET, "--ufield-next-offset")


def _parse_processevent_vtable_slot(value: str | None) -> int:
    return _parse_int_literal(
        value, DEFAULT_PROCESSEVENT_VTABLE_SLOT, "--processevent-vtable-slot")


def _write_guarded(document: dict, path: str, *, what: str) -> str:
    """dump_json(document) to *path*, refusing any path inside the game
    installation (plan.md decision D-01) and creating the parent directory
    if needed. Returns the resolved path pathguard checked and wrote to.
    """
    resolved = pathguard.check_output_path(
        path, pathguard.CONFIGURED_INSTALL_ROOTS[0], what=what)
    parent = os.path.dirname(resolved)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(resolved, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dump_json(document))
    return resolved


def _write_guarded_jsonl(records: list, path: str, *, what: str) -> str:
    """dump_jsonl(records) to *path* -- the SAME pathguard-checked,
    parent-directory-creating write _write_guarded() above performs for a
    single JSON document, but for I-04's own classes.jsonl (a LIST of
    records, one JSON object per line, never a single pretty-printed
    document). An empty *records* list writes a legitimately empty file --
    "zero records", not an error; see research/reflection/README.md's own
    "Пустой JSONL самодостаточен и честен" section for why an empty JSONL
    is never treated as a stub/placeholder needing special-casing here.
    """
    resolved = pathguard.check_output_path(
        path, pathguard.CONFIGURED_INSTALL_ROOTS[0], what=what)
    parent = os.path.dirname(resolved)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(resolved, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dump_jsonl(records))
    return resolved


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        if args.build_key is not None:
            # Format only, at parse time, cheap and before any handle is
            # opened -- exactly like before. This is NOT a truth check: a
            # well-formed but WRONG --build-key is caught later, only after
            # this run has self-computed its own build_key, by
            # establish_build_identity() raising BuildKeyMismatchError
            # (LOG-0048/LOG-0049). See the module docstring's "IDENTITY IS
            # SELF-ESTABLISHED" section.
            validate_build_key(args.build_key)
        out_path, manifest_path = _resolve_output_paths(args)
        i02_out_path = _resolve_i02_output_path(args)  # None unless --run-i02
        i03_out_path = _resolve_i03_output_path(args)  # None unless --run-i03
        i04_out_path = _resolve_i04_output_path(args)  # None unless --run-i04
        classes_jsonl_path = _resolve_classes_jsonl_path(args)  # None unless --run-i04
        i06_out_path = _resolve_i06_output_path(args)  # None unless --run-i06
        properties_jsonl_path = _resolve_properties_jsonl_path(args)  # None unless --run-i06
        i05_out_path = _resolve_i05_output_path(args)  # None unless --run-i05
        functions_jsonl_path = _resolve_functions_jsonl_path(args)  # None unless --run-i05
        i14_out_path = _resolve_i14_output_path(args)    # None unless --run-i14
        pe02_out_path = _resolve_pe02_output_path(args)  # None unless --run-pe02-vtable-scan
        guobjectarray_rva = _parse_guobjectarray_rva(args.guobjectarray_rva)
        namepool_rva = _parse_namepool_rva(args.namepool_rva)
        name_pool_initialized_rva = _parse_name_pool_initialized_rva(
            args.name_pool_initialized_rva)
        name_private_offset = _parse_name_private_offset(args.name_private_offset)
        class_private_offset = _parse_class_private_offset(args.class_private_offset)
        outer_private_offset = _parse_outer_private_offset(args.outer_private_offset)
        child_properties_offset = _parse_child_properties_offset(args.child_properties_offset)
        children_offset = _parse_children_offset(args.children_offset)
        ufield_next_offset = _parse_ufield_next_offset(args.ufield_next_offset)
        processevent_vtable_slot = _parse_processevent_vtable_slot(
            args.processevent_vtable_slot)
        # --run-i03-reflection needs both --run-i02 and --run-i03 in this
        # same invocation -- checked here, before any handle is opened, same
        # "fail loudly before doing any work" discipline as every other
        # CLI-shape check in this function.
        _validate_i03_reflection_requirements(args)
        # --run-i04 needs both --run-i02 and --run-i03 too -- identical
        # discipline, checked before any handle is opened.
        _validate_i04_requirements(args)
        # --run-i06 needs --run-i04 too -- identical discipline, checked
        # before any handle is opened.
        _validate_i06_requirements(args)
        # --run-i05 needs --run-i04 too (but deliberately NOT --run-i06 --
        # see _validate_i05_requirements()'s own docstring) -- identical
        # discipline, checked before any handle is opened.
        _validate_i05_requirements(args)
        # --run-pe02-vtable-scan needs --run-i04 too (PE-02 is not a
        # plan.md 8.2 'I-0N' capability -- see the module docstring's "WHAT
        # PE-02 IS" section) -- identical discipline, checked before any
        # handle is opened.
        _validate_pe02_requirements(args)

        # Layer 1 first, exactly like the pyghidra_scripts family: a refused
        # output path costs nothing, so it is checked before a single Win32
        # handle is opened.
        pathguard.check_output_path(
            out_path, pathguard.CONFIGURED_INSTALL_ROOTS[0], what="--out")
        pathguard.check_output_path(
            manifest_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
            what="--manifest-out")
        if i02_out_path is not None:
            pathguard.check_output_path(
                i02_out_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="--i02-out")
        if i03_out_path is not None:
            pathguard.check_output_path(
                i03_out_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="--i03-out")
        if i04_out_path is not None:
            pathguard.check_output_path(
                i04_out_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="--i04-out")
        if classes_jsonl_path is not None:
            pathguard.check_output_path(
                classes_jsonl_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="--classes-jsonl-out")
        if i06_out_path is not None:
            pathguard.check_output_path(
                i06_out_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="--i06-out")
        if properties_jsonl_path is not None:
            pathguard.check_output_path(
                properties_jsonl_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="--properties-jsonl-out")
        if i05_out_path is not None:
            pathguard.check_output_path(
                i05_out_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="--i05-out")
        if functions_jsonl_path is not None:
            pathguard.check_output_path(
                functions_jsonl_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="--functions-jsonl-out")
        if pe02_out_path is not None:
            pathguard.check_output_path(
                pe02_out_path, pathguard.CONFIGURED_INSTALL_ROOTS[0],
                what="--pe02-out")

        i01_recorded_at = (
            args.recorded_at if args.recorded_at
            else (None if args.no_timestamp else now_iso_utc()))
        manifest_timestamp = args.recorded_at if args.recorded_at else now_iso_utc()

        run_id = args.run_id
        if not run_id:
            run_id = (os.path.basename(os.path.normpath(args.run_dir))
                      if args.run_dir else manifest_timestamp)

        api = Win32Api()
        result = run_i01(api, args.process_name)

        # Identity is SELF-established here, from result["exe_path"] -- the
        # file the OS loader actually mapped for the process this run just
        # found -- BEFORE any output document is built or written. A
        # mismatched --build-key raises BuildKeyMismatchError right here,
        # which means NOTHING this run produces (I-01 document, I-02
        # document, manifest) is ever written for a run whose supplied
        # build_key does not match what was actually observed
        # (LOG-0048/LOG-0049).
        identity = establish_build_identity(
            exe_path=result["exe_path"], given_build_key=args.build_key)

        # I-02, if requested, runs BEFORE anything is written -- same reason
        # as identity above: if run_i02() raises (a genuine tool failure,
        # never a mere structural refutation -- see run_i02()'s own
        # docstring), this run must write NOTHING at all, not an I-01
        # document with no manifest to explain it. I-02 opens its OWN handle
        # via the tool's one open_process_read_only()/Win32Api.open_process
        # call site -- the SAME PROCESS_ACCESS_RIGHTS-only access I-01
        # itself already established and closed; PROCESS_ACCESS_RIGHTS is
        # unchanged (still PROCESS_QUERY_INFORMATION | PROCESS_VM_READ only,
        # nothing more), and ReadProcessMemory needs nothing beyond the
        # PROCESS_VM_READ bit that access already carries.
        i02_result = None
        if args.run_i02:
            i02_handle = open_process_read_only(api, result["pid"])
            try:
                i02_result = run_i02(
                    api, i02_handle, result["base_address"], result["image_size_bytes"],
                    guobjectarray_rva=guobjectarray_rva,
                    sample_size=args.i02_sample_size,
                    poll_interval_seconds=args.i02_poll_interval_seconds,
                    max_scan_indices=args.i02_max_scan_indices)
            finally:
                api.close_handle(i02_handle)

        # I-14 is deliberately independent of every other capability: the pak
        # system is not in the UObject graph, so I-14 shares no state with
        # I-02/I-03/I-04 and needs only I-01's base address and image size. It
        # therefore opens its own handle and runs whenever asked, alone if that
        # is all that was asked for.
        i14_result = None
        if args.run_i14:
            i14_handle = open_process_read_only(api, result["pid"])
            try:
                i14_result = run_i14(
                    api, i14_handle, result["base_address"], result["image_size_bytes"],
                    platform_file_manager_rva=args.platform_file_manager_rva,
                    pak_vtable_rva=args.pak_platform_file_vtable_rva)
            finally:
                api.close_handle(i14_handle)

        # I-03, if requested, ALSO runs before anything is written -- same
        # reason as I-02 above. I-03 opens its OWN fresh handle (I-02's own
        # handle, if any, is already closed by this point) via the tool's
        # one open_process_read_only()/Win32Api.open_process call site; the
        # "/Script/MISERY" reflection probe (--run-i03-reflection), if also
        # requested, runs inside this SAME handle's try/finally, reusing
        # i02_result's own already-fetched objects_ptr/num_elements
        # (_validate_i03_reflection_requirements already guaranteed i02_result
        # is not None here whenever args.run_i03_reflection is True).
        i03_result = None
        misery_reflection_result = None
        # I-04, if requested, runs in this SAME i03_handle's try/finally --
        # it reuses i02_result's own objects_ptr/num_elements AND i03_result's
        # own namepool_live_va (_validate_i04_requirements already guaranteed
        # both are not None here whenever args.run_i04 is True), the
        # identical "reuse, never re-walk/re-establish" reasoning
        # --run-i03-reflection's own block above already follows.
        i04_result = None
        i04_class_buckets = None
        i04_game_sample = None
        i06_result = None
        i05_result = None
        pe02_result = None
        if args.run_i03:
            i03_handle = open_process_read_only(api, result["pid"])
            try:
                i03_result = run_i03(
                    api, i03_handle, result["base_address"], result["image_size_bytes"],
                    namepool_rva=namepool_rva,
                    name_pool_initialized_rva=name_pool_initialized_rva,
                    name_entry_id=args.i03_name_entry_id)
                if args.run_i03_reflection:
                    misery_reflection_result = sample_object_names(
                        api, i03_handle, i02_result["objects_ptr_live_va"],
                        i02_result["num_elements"], i03_result["namepool_live_va"],
                        name_private_offset,
                        sample_size=args.i03_reflection_sample_size,
                        max_scan_indices=args.i03_reflection_max_scan_indices)
                if args.run_i04:
                    i04_result = run_i04(
                        api, i03_handle, result["base_address"], result["image_size_bytes"],
                        i02_result["objects_ptr_live_va"], i02_result["num_elements"],
                        i03_result["namepool_live_va"],
                        class_private_offset=class_private_offset,
                        name_private_offset=name_private_offset,
                        outer_private_offset=outer_private_offset,
                        max_scan_indices=args.i04_max_scan_indices,
                        max_outer_depth=args.i04_max_outer_depth,
                        max_fixed_point_passes=args.i04_max_fixed_point_passes)
                    if i04_result["seed_found"]:
                        i04_class_buckets = classify_classes_by_module(i04_result["classes"])
                        i04_game_sample = select_game_sample(
                            i04_class_buckets["game"], cap=args.i04_game_sample_cap)
                    else:
                        i04_class_buckets = {"misery": [], "game": [], "other": []}
                        i04_game_sample = []
                    # I-06, if requested, runs in this SAME i03_handle's
                    # try/finally -- it reuses I-04's own already-classified,
                    # already-validated class list from THIS SAME run
                    # (i04_result["classes"], i04_class_buckets["misery"],
                    # i04_game_sample) as a deterministic, in-memory proof-set
                    # selection (select_i06_proof_set()), and I-03's own
                    # namepool_live_va -- never re-walking GUObjectArray, per
                    # _validate_i06_requirements()'s own requirement.
                    if args.run_i06:
                        i06_proof_set = select_i06_proof_set(
                            misery_classes=i04_class_buckets["misery"],
                            game_sample=i04_game_sample,
                            all_classes=i04_result["classes"],
                            engine_class_cap=args.i06_engine_class_cap)
                        i06_result = run_i06(
                            api, i03_handle, i03_result["namepool_live_va"], None,
                            i06_proof_set,
                            max_chain_length=args.i06_max_chain_length,
                            max_superclass_depth=args.i06_max_superclass_depth,
                            max_container_depth=args.i06_max_container_depth,
                            child_properties_offset=child_properties_offset)
                    # I-05, if requested, ALSO runs in this SAME i03_handle's
                    # try/finally -- it reuses I-04's own already-classified
                    # class list from THIS SAME run EXACTLY the way I-06
                    # does above (i04_result["classes"], i04_class_buckets
                    # ["misery"], i04_game_sample -> select_i06_proof_set(),
                    # reused verbatim, never a second proof-set selector) and
                    # I-03's own namepool_live_va -- never re-walking
                    # GUObjectArray. DELIBERATELY independent of
                    # args.run_i06 -- I-05 uses nothing run_i06() itself
                    # computes (see _validate_i05_requirements()'s own
                    # docstring), so it runs whenever args.run_i05 is set,
                    # whether or not --run-i06 was ALSO given this same run.
                    if args.run_i05:
                        i05_proof_set = select_i06_proof_set(
                            misery_classes=i04_class_buckets["misery"],
                            game_sample=i04_game_sample,
                            all_classes=i04_result["classes"],
                            engine_class_cap=args.i06_engine_class_cap)
                        i05_result = run_i05(
                            api, i03_handle, i03_result["namepool_live_va"],
                            i04_result["classes"], i05_proof_set,
                            children_max_chain_length=args.i05_children_max_chain_length,
                            property_max_chain_length=args.i06_max_chain_length,
                            max_superclass_depth=args.i06_max_superclass_depth,
                            max_container_depth=args.i06_max_container_depth,
                            children_offset=children_offset,
                            child_properties_offset=child_properties_offset,
                            ufield_next_offset=ufield_next_offset)
                    # PE-02, if requested, ALSO runs in this SAME
                    # i03_handle's try/finally -- it reuses I-04's OWN
                    # already-walked, already-validated objects_by_address
                    # dict from THIS SAME run (i04_result["objects_by_
                    # address"], run_i04()'s own additive return key) as its
                    # sampling population, and never re-walks GUObjectArray
                    # itself. PE-02 is NOT a plan.md 8.2 'I-0N' capability
                    # (module docstring's "WHAT PE-02 IS" section) -- it is
                    # the second entry in the PE-01 evidence track
                    # (research/evidence/PE-01/README.md), gathering LIVE
                    # evidence for that static HYPOTHESIS. DELIBERATELY
                    # independent of args.run_i06/args.run_i05 -- PE-02 uses
                    # nothing either of them computes, only I-04's own
                    # objects_by_address, so it runs whenever
                    # args.run_pe02_vtable_scan is set regardless of which
                    # other --run-i0N flags were ALSO given this same run.
                    if args.run_pe02_vtable_scan:
                        pe02_result = run_pe02_vtable_scan(
                            api, i03_handle, i04_result["objects_by_address"],
                            base_address=result["base_address"],
                            image_size_bytes=result["image_size_bytes"],
                            vtable_slot=processevent_vtable_slot,
                            sample_size=args.pe02_vtable_sample_size)
            finally:
                api.close_handle(i03_handle)

        document = build_i01_document(
            result=result, build_key=identity["build_key"], recorded_at=i01_recorded_at,
            identity_self_established=identity["identity_self_established"],
            build_key_cross_checked=identity["build_key_cross_checked"],
            known_build=identity["known_build"], build_id=identity["build_id"])
        written_out = _write_guarded(document, out_path, what="--out")

        capabilities_enabled = [CAPABILITY_ID]
        artifacts = [_repo_relative(written_out)]
        i02_document = None
        written_i02_out = None
        if i02_result is not None:
            i02_document = build_i02_document(
                result=i02_result, build_key=identity["build_key"],
                recorded_at=i01_recorded_at,
                identity_self_established=identity["identity_self_established"],
                build_key_cross_checked=identity["build_key_cross_checked"],
                known_build=identity["known_build"], build_id=identity["build_id"])
            written_i02_out = _write_guarded(i02_document, i02_out_path, what="--i02-out")
            capabilities_enabled.append(CAPABILITY_ID_I02)
            artifacts.append(_repo_relative(written_i02_out))

        i03_document = None
        written_i03_out = None
        if i03_result is not None:
            i03_document = build_i03_document(
                result=i03_result, build_key=identity["build_key"],
                recorded_at=i01_recorded_at,
                identity_self_established=identity["identity_self_established"],
                build_key_cross_checked=identity["build_key_cross_checked"],
                known_build=identity["known_build"], build_id=identity["build_id"],
                misery_reflection=misery_reflection_result)
            written_i03_out = _write_guarded(i03_document, i03_out_path, what="--i03-out")
            capabilities_enabled.append(CAPABILITY_ID_I03)
            artifacts.append(_repo_relative(written_i03_out))

        i04_document = None
        written_i04_out = None
        written_classes_jsonl = None
        if i04_result is not None:
            i04_document = build_i04_document(
                result=i04_result, build_key=identity["build_key"],
                recorded_at=i01_recorded_at,
                identity_self_established=identity["identity_self_established"],
                build_key_cross_checked=identity["build_key_cross_checked"],
                known_build=identity["known_build"], build_id=identity["build_id"],
                misery_classes_count=len(i04_class_buckets["misery"]),
                game_classes_total_count=len(i04_class_buckets["game"]),
                game_classes_sample_count=len(i04_game_sample),
                other_classes_count=len(i04_class_buckets["other"]))
            written_i04_out = _write_guarded(i04_document, i04_out_path, what="--i04-out")
            capabilities_enabled.append(CAPABILITY_ID_I04)
            artifacts.append(_repo_relative(written_i04_out))

            # classes.jsonl is a SEPARATE artifact, in the format research/
            # schema/reflection-record.schema.json's class_record branch
            # defines -- every /Script/MISERY class (cross_checked=True,
            # confidence 0.90) plus the bounded /Game sample
            # (cross_checked=False, confidence 0.75); see
            # build_i04_class_record()'s own docstring for the full MIX-SPLIT
            # grading reasoning. recorded_at here is manifest_timestamp, NOT
            # i01_recorded_at -- kb-record.schema.json's own envelope
            # requires a non-null recorded_at on every row always, unlike the
            # raw i0N-*.json documents, which may carry a null one under
            # --no-timestamp.
            classes_jsonl_rows = (
                [build_i04_class_record(
                    entry, build_key=identity["build_key"],
                    recorded_at=manifest_timestamp, cross_checked=True)
                 for entry in i04_class_buckets["misery"]] +
                [build_i04_class_record(
                    entry, build_key=identity["build_key"],
                    recorded_at=manifest_timestamp, cross_checked=False)
                 for entry in i04_game_sample])
            written_classes_jsonl = _write_guarded_jsonl(
                classes_jsonl_rows, classes_jsonl_path, what="--classes-jsonl-out")
            artifacts.append(_repo_relative(written_classes_jsonl))

        i06_document = None
        written_i06_out = None
        written_properties_jsonl = None
        if i06_result is not None:
            i06_document = build_i06_document(
                result=i06_result, build_key=identity["build_key"],
                recorded_at=i01_recorded_at,
                identity_self_established=identity["identity_self_established"],
                build_key_cross_checked=identity["build_key_cross_checked"],
                known_build=identity["known_build"], build_id=identity["build_id"])
            written_i06_out = _write_guarded(i06_document, i06_out_path, what="--i06-out")
            capabilities_enabled.append(CAPABILITY_ID_I06)
            artifacts.append(_repo_relative(written_i06_out))

            # properties.jsonl is a SEPARATE artifact, in the format
            # research/schema/reflection-record.schema.json's property_record
            # branch defines -- EVERY accepted property from EVERY proof-set
            # class, confidence 0.75 always (build_i06_property_record()'s
            # own docstring: this capability has NO possible cross-checked
            # branch, ever, unlike I-04's own MIX-SPLIT). ordinal is each
            # class's own 'properties' list's 0-based position -- ONLY
            # accepted/validated nodes ever appear there (walk_property_
            # chain()'s own docstring), so a rejected node never consumes an
            # ordinal slot. recorded_at is manifest_timestamp, NOT
            # i01_recorded_at, for the SAME reason build_i04_class_record()'s
            # own rows already use it (kb-record.schema.json's own envelope
            # requires a non-null recorded_at on every row always).
            properties_jsonl_rows = [
                build_i06_property_record(
                    decoded, owner=class_entry["class_raw_name"], owner_kind="class",
                    ordinal=ordinal, build_key=identity["build_key"],
                    recorded_at=manifest_timestamp)
                for class_entry in i06_result["classes"]
                for ordinal, decoded in enumerate(class_entry["properties"])
            ]
            written_properties_jsonl = _write_guarded_jsonl(
                properties_jsonl_rows, properties_jsonl_path, what="--properties-jsonl-out")
            artifacts.append(_repo_relative(written_properties_jsonl))

        i05_document = None
        written_i05_out = None
        written_functions_jsonl = None
        if i05_result is not None:
            i05_document = build_i05_document(
                result=i05_result, build_key=identity["build_key"],
                recorded_at=i01_recorded_at,
                identity_self_established=identity["identity_self_established"],
                build_key_cross_checked=identity["build_key_cross_checked"],
                known_build=identity["known_build"], build_id=identity["build_id"])
            written_i05_out = _write_guarded(i05_document, i05_out_path, what="--i05-out")
            capabilities_enabled.append(CAPABILITY_ID_I05)
            artifacts.append(_repo_relative(written_i05_out))

            # functions.jsonl is a SEPARATE artifact, in the format
            # research/schema/reflection-record.schema.json's function_record
            # branch defines -- EVERY accepted UFunction from EVERY proof-set
            # class, confidence 0.75 always (build_i05_function_record()'s own
            # docstring: this capability has NO possible cross-checked
            # branch, ever, exactly like I-06's own property_record). Written
            # even when i05_result["function_class_found"] is False -- an
            # empty functions.jsonl is then a legitimately empty, honest
            # result, never a stub (see _write_guarded_jsonl()'s own
            # docstring/research/reflection/README.md's own "Пустой JSONL
            # самодостаточен и честен" section). recorded_at is
            # manifest_timestamp, NOT i01_recorded_at, for the SAME reason
            # build_i06_property_record()'s own rows already use it
            # (kb-record.schema.json's own envelope requires a non-null
            # recorded_at on every row always).
            functions_jsonl_rows = [
                build_i05_function_record(
                    function_entry, owner=class_entry["class_raw_name"],
                    build_key=identity["build_key"], recorded_at=manifest_timestamp)
                for class_entry in i05_result["classes"]
                for function_entry in class_entry["functions"]
            ]
            written_functions_jsonl = _write_guarded_jsonl(
                functions_jsonl_rows, functions_jsonl_path, what="--functions-jsonl-out")
            artifacts.append(_repo_relative(written_functions_jsonl))

        i14_document = None
        written_i14_out = None
        if i14_result is not None:
            i14_document = build_i14_document(
                result=i14_result, build_key=identity["build_key"],
                recorded_at=i01_recorded_at,
                identity_self_established=identity["identity_self_established"],
                build_key_cross_checked=identity["build_key_cross_checked"],
                known_build=identity["known_build"], build_id=identity["build_id"])
            written_i14_out = _write_guarded(i14_document, i14_out_path, what="--i14-out")
            # Unlike PE-02, I-14 IS a plan.md 8.2 capability id and belongs in
            # capabilities_enabled -- instrument-run-manifest.schema.json's own
            # eri_capability_id enum is closed to "I-01".."I-16" and I-14 is
            # inside it.
            capabilities_enabled.append(CAPABILITY_ID_I14)
            artifacts.append(_repo_relative(written_i14_out))

        pe02_document = None
        written_pe02_out = None
        if pe02_result is not None:
            pe02_document = build_pe02_document(
                result=pe02_result, build_key=identity["build_key"],
                recorded_at=i01_recorded_at,
                identity_self_established=identity["identity_self_established"],
                build_key_cross_checked=identity["build_key_cross_checked"],
                known_build=identity["known_build"], build_id=identity["build_id"])
            written_pe02_out = _write_guarded(pe02_document, pe02_out_path, what="--pe02-out")
            # PE-02 is DELIBERATELY never appended to capabilities_enabled --
            # it is not a plan.md 8.2 'I-0N' capability id, and
            # instrument-run-manifest.schema.json's own eri_capability_id
            # enum is closed to "I-01".."I-16"; appending "PE-02" there
            # would be a schema violation, not a style nit (see
            # CAPABILITY_ID_PE02's own comment and the module docstring's
            # "WHAT PE-02 IS" section). Its own output path is still
            # recorded, in 'artifacts' below, which is unconstrained.
            artifacts.append(_repo_relative(written_pe02_out))

        manifest = build_manifest(
            run_id=run_id, arguments=list(sys.argv[1:] if argv is None else argv),
            tool_version=GENERATOR_VERSION, build_key=identity["build_key"],
            executed_at=manifest_timestamp, recorded_at=manifest_timestamp,
            artifacts=artifacts,
            identity_self_established=identity["identity_self_established"],
            build_key_cross_checked=identity["build_key_cross_checked"],
            known_build=identity["known_build"], build_id=identity["build_id"],
            capabilities_enabled=capabilities_enabled)
        written_manifest = _write_guarded(manifest, manifest_path, what="--manifest-out")

        if args.json:
            summary = {
                "pid": result["pid"],
                "process_name": result["process_name"],
                "base_address_hex": document["base_address_hex"],
                "image_size_bytes": result["image_size_bytes"],
                "build_key": identity["build_key"],
                "build_key_cross_checked": identity["build_key_cross_checked"],
                "known_build": identity["known_build"],
                "build_id": identity["build_id"],
                "out": written_out,
                "manifest_out": written_manifest,
            }
            if i02_document is not None:
                summary["i02_out"] = written_i02_out
                summary["i02_structurally_consistent"] = i02_document["structurally_consistent"]
            if i03_document is not None:
                summary["i03_out"] = written_i03_out
                summary["i03_decoded_as_expected"] = i03_document["decoded_as_expected"]
                if misery_reflection_result is not None:
                    summary["i03_misery_found"] = misery_reflection_result["misery_found"]
            if i04_document is not None:
                summary["i04_out"] = written_i04_out
                summary["classes_jsonl_out"] = written_classes_jsonl
                summary["i04_seed_found"] = i04_document["seed_found"]
                summary["i04_misery_classes_count"] = i04_document["misery_classes_count"]
                summary["i04_game_classes_total_count"] = (
                    i04_document["game_classes_total_count"])
                summary["i04_game_classes_sample_count"] = (
                    i04_document["game_classes_sample_count"])
                summary["i04_other_classes_count"] = i04_document["other_classes_count"]
            if i06_document is not None:
                summary["i06_out"] = written_i06_out
                summary["properties_jsonl_out"] = written_properties_jsonl
                summary["i06_classes_examined"] = i06_document["classes_examined"]
                summary["i06_properties_accepted_total"] = (
                    i06_document["properties_accepted_total"])
            if i05_document is not None:
                summary["i05_out"] = written_i05_out
                summary["functions_jsonl_out"] = written_functions_jsonl
                summary["i05_function_class_found"] = i05_document["function_class_found"]
                summary["i05_classes_examined"] = i05_document["classes_examined"]
                summary["i05_functions_accepted_total"] = (
                    i05_document["functions_accepted_total"])
                summary["i05_num_parms_cross_check"] = i05_document["num_parms_cross_check"]
            if pe02_document is not None:
                summary["pe02_out"] = written_pe02_out
                summary["pe02_vtable_slot"] = pe02_document["vtable_slot"]
                summary["pe02_sample_size_used"] = pe02_document["sample_size_used"]
                summary["pe02_top_candidate"] = pe02_document["top_candidate"]
                summary["pe02_minority_candidate_count"] = len(
                    pe02_document["minority_candidates"])
            print(dump_json(summary))
        else:
            print(
                "pid=%d base_address=%s image_size_bytes=%d"
                % (result["pid"], document["base_address_hex"], result["image_size_bytes"]),
                file=sys.stderr)
            print(
                "build_key=%s (%s) known_build=%s build_id=%s" % (
                    identity["build_key"],
                    "self-computed, independently confirmed by --build-key"
                    if identity["build_key_cross_checked"] else "self-computed",
                    identity["known_build"],
                    identity["build_id"]),
                file=sys.stderr)
            print("written: %s" % written_out, file=sys.stderr)
            if i02_document is not None:
                print(
                    "I-02: guobjectarray_live_va=%s structurally_consistent=%s "
                    "(check_struct_invariants=%s check_sample_walk=%s "
                    "check_growth_non_decreasing=%s)" % (
                        i02_document["guobjectarray_live_va_hex"],
                        i02_document["structurally_consistent"],
                        i02_document["check_struct_invariants"]["pass"],
                        i02_document["check_sample_walk"]["pass"],
                        i02_document["check_growth_non_decreasing"]["pass"]),
                    file=sys.stderr)
                print("written: %s" % written_i02_out, file=sys.stderr)
            if i03_document is not None:
                print(
                    "I-03: namepool_live_va=%s pool_initialized=%s "
                    "name_entry_id=%d decoded_text=%r decoded_as_expected=%s" % (
                        i03_document["namepool_live_va_hex"],
                        i03_document["pool_initialized"],
                        i03_document["name_entry_id"],
                        (i03_document["decoded"]["text"]
                         if i03_document["decoded"] is not None else None),
                        i03_document["decoded_as_expected"]),
                    file=sys.stderr)
                if misery_reflection_result is not None:
                    print(
                        "I-03 reflection: objects_examined=%d misery_found=%s "
                        "decoded_names_sample=%r" % (
                            misery_reflection_result["objects_examined"],
                            misery_reflection_result["misery_found"],
                            misery_reflection_result["decoded_names"][:10]),
                        file=sys.stderr)
                print("written: %s" % written_i03_out, file=sys.stderr)
            if i04_document is not None:
                print(
                    "I-04: seed_found=%s class_address_universe_size=%d "
                    "misery_classes_count=%d game_classes_total_count=%d "
                    "game_classes_sample_count=%d other_classes_count=%d" % (
                        i04_document["seed_found"],
                        i04_document["class_address_universe_size"],
                        i04_document["misery_classes_count"],
                        i04_document["game_classes_total_count"],
                        i04_document["game_classes_sample_count"],
                        i04_document["other_classes_count"]),
                    file=sys.stderr)
                print("written: %s" % written_i04_out, file=sys.stderr)
                print("written: %s" % written_classes_jsonl, file=sys.stderr)
            if i06_document is not None:
                print(
                    "I-06: classes_examined=%d properties_accepted_total=%d "
                    "rejected_counts_total=%r" % (
                        i06_document["classes_examined"],
                        i06_document["properties_accepted_total"],
                        i06_document["rejected_counts_total"]),
                    file=sys.stderr)
                print("written: %s" % written_i06_out, file=sys.stderr)
                print("written: %s" % written_properties_jsonl, file=sys.stderr)
            if i05_document is not None:
                print(
                    "I-05: function_class_found=%s classes_examined=%d "
                    "functions_accepted_total=%d num_parms_cross_check=%r "
                    "rejected_counts_total=%r" % (
                        i05_document["function_class_found"],
                        i05_document["classes_examined"],
                        i05_document["functions_accepted_total"],
                        i05_document["num_parms_cross_check"],
                        i05_document["rejected_counts_total"]),
                    file=sys.stderr)
                print("written: %s" % written_i05_out, file=sys.stderr)
                print("written: %s" % written_functions_jsonl, file=sys.stderr)
            if pe02_document is not None:
                top = pe02_document["top_candidate"]
                print(
                    "PE-02: vtable_slot=%d sample_size=%d "
                    "top_candidate_rva=%s "
                    "distinct_classes_observing_top_candidate=%s "
                    "minority_candidates=%d" % (
                        pe02_document["vtable_slot"],
                        pe02_document["sample_size_used"],
                        top["candidate_rva_hex"] if top is not None else None,
                        top["distinct_class_count"] if top is not None else None,
                        len(pe02_document["minority_candidates"])),
                    file=sys.stderr)
                print("written: %s" % written_pe02_out, file=sys.stderr)
            print("written: %s" % written_manifest, file=sys.stderr)
        return 0
    except (EriError, pathguard.OutputPathRefused, ValueError) as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except OSError as error:
        print("error: %s" % error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
