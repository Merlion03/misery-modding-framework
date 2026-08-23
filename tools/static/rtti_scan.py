#!/usr/bin/env python3
"""Read-only MSVC RTTI scanner (plan.md task S-10).

The question this tool exists to answer
---------------------------------------
plan.md 7.3 row S-10 asks whether the game executable carries MSVC run-time type
information, and plan.md 7.4 puts the answer first in the static-analysis queue
because it changes the cost of the whole of section 7 by an order of magnitude.
``research/unknowns.md`` records the prior: Unreal Engine is normally compiled
with RTTI off, so the expected answer is negative.

A *positive* answer therefore deserves more scepticism than a negative one, and
a negative answer must never be confused with "the scanner did not look
properly". Both failure directions are real and this module is built around
them:

* every layer of the MSVC RTTI graph is parsed and **cross-checked against the
  next one**, so a positive result has to survive five independent consistency
  conditions rather than one string match;
* the surface that was searched is reported explicitly -- which sections, which
  byte ranges, which alignments -- so a null result is a statement about a named
  surface and not about the file as a whole;
* three deliberate refutation probes run on every invocation (see
  :func:`build_refutation_probes`), each of which is designed to *break* the
  headline conclusion rather than support it.

What "usable RTTI" means here, and why the answer is not `strings | grep`
------------------------------------------------------------------------
The presence of the byte string ``.?AV`` proves almost nothing on its own: it is
also what a compiler emits for a type merely named in a ``catch`` clause, and it
survives in unrelated data. Useful RTTI -- the kind that names a *vtable* and
therefore an object at run time -- is a five-level graph, and this tool walks all
five::

    vtable[-1]  --->  RTTICompleteObjectLocator
                        .pTypeDescriptor      ---> TypeDescriptor  (mangled name)
                        .pClassDescriptor     ---> RTTIClassHierarchyDescriptor
                                                     .pBaseClassArray
                                                        ---> RTTIBaseClassDescriptor[]
                                                               .pTypeDescriptor ---> ...

A locator with no reachable vtable buys nothing, so the vtable reachability pass
is not optional decoration: it is the difference between "the compiler mentioned
this type" and "an object of this type can be identified from its first eight
bytes".

The structures, and where their layout comes from
-------------------------------------------------
The four record layouts below are the published MSVC ABI, which is the
``external-doc`` oracle: per plan.md 10.5 that proves how *the Microsoft
toolchain* lays these structures out, and nothing whatsoever about this build.
That is exactly why the output is split into two layers (see below) and why the
decoded layer is capped well under the literal layer.

``TypeDescriptor`` (``_TypeDescriptor``, x64)::

    +0x00  void*  pVFTable    virtual table of type_info
    +0x08  void*  spare       always 0 in a linked image
    +0x10  char   name[]      NUL-terminated, always begins ".?A"

``RTTICompleteObjectLocator`` (x64 form, signature 1)::

    +0x00  DWORD  signature         1 on PE32+, 0 on PE32
    +0x04  DWORD  offset            offset of this vftable within the object
    +0x08  DWORD  cdOffset          constructor displacement
    +0x0C  DWORD  pTypeDescriptor   image-base-relative
    +0x10  DWORD  pClassDescriptor  image-base-relative
    +0x14  DWORD  pSelf             image-base-relative, points at THIS record

``RTTIClassHierarchyDescriptor``::

    +0x00  DWORD  signature         0
    +0x04  DWORD  attributes        bit 0 multiple inheritance, bit 1 virtual
    +0x08  DWORD  numBaseClasses    includes the class itself
    +0x0C  DWORD  pBaseClassArray   image-base-relative -> DWORD[numBaseClasses]

``RTTIBaseClassDescriptor``::

    +0x00  DWORD  pTypeDescriptor   image-base-relative
    +0x04  DWORD  numContainedBases
    +0x08  int    where.mdisp
    +0x0C  int    where.pdisp
    +0x10  int    where.vdisp
    +0x14  DWORD  attributes
    +0x18  DWORD  pClassDescriptor  image-base-relative

The ``pSelf`` field is the single most valuable structural property in the whole
format for a scanner: it makes a complete object locator **self-identifying**. A
4-byte-aligned position whose first DWORD is 1 and whose sixth DWORD equals its
own image-relative address is not something random data produces at any rate
worth worrying about, and it is verified for every candidate before anything
else is believed. On PE32 there is no ``pSelf``; the PE32 path is therefore
weaker by construction and says so in the output.

Two output layers, never merged (plan.md 10.3)
----------------------------------------------
Exactly as ``tools/fingerprint/container_info.py`` does for containers, this tool
emits its evidence twice and never averages the two:

``literal_reads``
    Class **P**. One record per read: target, file offset, length, raw bytes, and
    a citable ``claim`` sentence that states the offset and the length and stops
    there. It does not name what the bytes are. Every one of these ranges is read
    a second time through an independently opened handle before the record is
    allowed to say it reproduced (plan.md 10.3 class-P criterion 2 executed, not
    asserted). The sample is bounded and deterministic -- see ``--literal-samples``
    -- because 600-odd structures times four reads each is a log, not evidence.

``type_descriptors`` / ``complete_object_locators`` / ``summary``
    Class **I**. These name the fields, decode the mangled names, attribute the
    classes to their owners and count things. Every one of those steps is an
    interpretation resting on the published MSVC ABI and on naming conventions,
    so the whole layer is graded class I whatever the offsets are.

The MSVC name decoder
---------------------
``research/unknowns.md`` S-10 asks what the names *decode to*, not how many there
are, because "628 type descriptors" and "628 type descriptors all belonging to
ICU" are opposite answers to the question the milestone is really asking. The
decoder in this file is a from-scratch implementation of the subset of the MSVC
decorated-name grammar that a type-descriptor name can contain: qualified names,
nested classes, anonymous namespaces, template-ids with type and integral
arguments, function types as template arguments, pointer and reference
declarators, pointer-to-member-function types, arrays, and the 0-9 back-reference
table.

The back-reference semantics are the part that is easy to get subtly wrong and
that silently corrupts names when wrong, so they are stated here: a
template-argument list runs in its **own** back-reference context, the template's
own simple name is memorised as the first entry of that new context, and the
rendered template-id is memorised into the *enclosing* context after the argument
list closes. Getting this wrong turns ``std::allocator<char>`` into
``allocator<char>::allocator<char>`` in exactly the places where MSVC compresses
hardest, which is every STL name in the image.

Anything the decoder cannot parse is **counted and reported by mangled form**,
never silently dropped and never guessed at: "we decoded 628 of 628" and "we
decoded 600 of 628 and here are the 28" are different findings and the second one
must not be able to masquerade as the first.

Ownership attribution
---------------------
The split the milestone actually needs -- MSVC/CRT internals, statically linked
third-party libraries, Unreal Engine, game-specific -- is a *naming-convention
inference* and is graded accordingly. The rules are table-driven and printed with
the results so a reviewer can disagree with a specific rule instead of with a
verdict. Two independent signals are available:

1. the root namespace or the Unreal Hungarian prefix of the decoded name;
2. optionally (``--ue-source-root``) whether the identifier is declared anywhere
   in a local Unreal Engine source tree. That is a genuinely independent method
   on a different oracle (``filesystem``), and it is what allows a UE-shaped name
   that is *absent* from the engine tree to be promoted from "unattributed" to
   "game-specific candidate" instead of being guessed either way.

Safety properties (plan.md 1.5, decisions D-01 and D-04)
--------------------------------------------------------
* The target is opened ``"rb"`` and only ever read. Nothing inside a game
  installation is created, modified, moved or deleted.
* The only paths written are ``--out`` and ``--jsonl-out``, and both go through
  ``tools/inventory/pathguard.check_output_path`` **before** any file is opened.
  The guard is imported, never reimplemented.
* D-04: ``MISERY\\Binaries\\Win64\\MISERY.exe`` is a read-only oracle. This tool
  will happily scan it, and stamps ``"d04_oracle_only": true`` on the document
  when it does, because a conclusion reached there has to be re-verified on
  ``MISERY-Win64-Shipping.exe`` before it counts.

Memory (plan.md F-04)
---------------------
Nothing is read whole. The name scan, the locator scan and the vtable-reference
scan each stream the target through one reused chunk with a bounded overlap, and
every count taken from the file is clamped before it becomes a loop bound or an
allocation. Peak additional memory is the chunk plus the result tables, which for
the 134 MB target measured a few tens of megabytes.

Determinism
-----------
Sorted keys, indent 2, LF, UTF-8 without BOM, trailing newline. Records are
emitted in ascending RVA order. Two runs over an unchanged file differ only in
``generated_at`` and in the ``elapsed_seconds`` timings, which live in their own
object so a diff can ignore them.

Standard library only.

CLI
---
    python tools/static/rtti_scan.py <image.exe>
    python tools/static/rtti_scan.py <image.exe> --json
    python tools/static/rtti_scan.py <image.exe> --out workspace/rtti/x.json \\
                                                 --jsonl-out workspace/rtti/rtti.jsonl

Exit codes: 0 the scan completed (whatever the verdict), 2 usage / I/O error /
unparseable input. A negative verdict is a successful run, not a failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import time
from array import array
from collections import Counter
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
for _extra in (os.path.join(_TOOLS, "inventory"), os.path.join(_TOOLS, "fingerprint")):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never
# reimplemented: pathguard is the single place where "is this path inside the
# game installation" is decided.
import pathguard  # noqa: E402  (sys.path is prepared just above)

# The PE layer is F-01's, not ours. Re-deriving section tables and RVA
# translation here would give this tool a second, differently-buggy opinion
# about where .rdata is, and the whole point of the wave-1 parser is that there
# is one.
import pe_info  # noqa: E402

GENERATOR_NAME = "tools/static/rtti_scan.py"
GENERATOR_VERSION = "1.0.0"

PEFormatError = pe_info.PEFormatError


# --------------------------------------------------------------------------- #
# hard limits. Every one of these bounds a number that is READ FROM THE FILE
# and must therefore never be believed.
# --------------------------------------------------------------------------- #

SCAN_CHUNK = 8 << 20             # streaming window for every pass
MAX_TD_NAME_BYTES = 2048         # longest decorated name we will follow
SCAN_OVERLAP = MAX_TD_NAME_BYTES + 64
MAX_TYPE_DESCRIPTORS = 1 << 18   # 262144
MAX_LOCATORS = 1 << 18
MAX_BASE_CLASSES = 4096          # numBaseClasses from the file
MAX_VTABLE_SLOTS = 4096          # how far a vtable is followed
MAX_VTABLE_REFS_PER_LOCATOR = 64
MAX_DEMANGLE_INPUT = 4096
MAX_DEMANGLE_DEPTH = 64
MAX_DEMANGLE_STEPS = 20000
DEFAULT_LITERAL_SAMPLES = 6
UE_SOURCE_SUFFIXES = (".h", ".cpp", ".inl", ".hpp", ".cc")
UE_SOURCE_MAX_FILE = 8 << 20

# Confidence ceiling is 0.99 (plan.md 10.2); 1.00 is forbidden anywhere.
CONFIDENCE_LITERAL = 0.99
CONFIDENCE_DECODED_CORROBORATED = 0.85
CONFIDENCE_DECODED_SINGLE_METHOD = 0.79

# The x64 complete-object-locator signature. On PE32 the field is 0 and the
# record has no pSelf, which is why the two paths are graded differently.
COL_SIGNATURE_PE32PLUS = 1
COL_SIGNATURE_PE32 = 0
COL_SIZE_PE32PLUS = 24
COL_SIZE_PE32 = 20
CHD_SIZE = 16
BCD_SIZE = 28
TD_HEADER_SIZE = 16              # pVFTable + spare, before name[]

# The four kinds an RTTI type-descriptor name can start with. "W" is followed by
# one digit naming the enum's underlying type.
TD_NAME_RE = re.compile(rb"\.\?A[VUWT][^\x00]{0,%d}?@@\x00" % MAX_TD_NAME_BYTES)

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_CNT_CODE = 0x00000020

# plan.md 10.3 class-P criterion 2 is MANDATORY for the whole 0.80-0.99 band and
# tools/kb/validate.py checks that the record SAYS the method was re-run. A
# record may only say it if it is true, so every literal read really is
# performed twice -- see confirm_literal_reads.
RERUN_CONFIRMED = (
    "Method re-run and reproduced within this run: every range in this group was read "
    "a second time through a second, independently opened file handle and the two "
    "reads agree byte for byte. The limit of that attestation, stated plainly: it is a "
    "re-read of the same file on the same machine, so it catches a transient read, a "
    "seek error and a bookkeeping mistake -- it does not catch reading the wrong file."
)
RERUN_NOT_CONFIRMED = (
    "Method NOT reproduced: the second read of this range disagreed with the first, or "
    "could not be performed. plan.md 10.3 criterion 2 is therefore unmet and this "
    "reading must not be relied on until it is explained."
)

# The per-source "oracle" key of kb-record.schema.json#/$defs/source is
# deliberately NOT set on any source object below. It is legal in the schema but
# it makes tools/kb/validate.py read every source object as a whole knowledge-base
# record; container_info.py hit the same wall and documents it as
# SOURCE_ORACLE_OMITTED. The oracle is stated in the note instead, and the
# record-level "oracle" list is unaffected.


# --------------------------------------------------------------------------- #
# MSVC decorated-name decoder
# --------------------------------------------------------------------------- #

class DemangleError(Exception):
    """A decorated name the decoder does not understand.

    Carries the offset into the mangled string so an unsupported form can be
    reported precisely instead of as "some names failed".
    """

    def __init__(self, message: str, position: int) -> None:
        super().__init__("%s (at character %d)" % (message, position))
        self.message = message
        self.position = position


# Primitive type codes. Two tables because the '_' escape opens a second space.
PRIMITIVE = {
    "X": "void", "D": "char", "C": "signed char", "E": "unsigned char",
    "F": "short", "G": "unsigned short", "H": "int", "I": "unsigned int",
    "J": "long", "K": "unsigned long", "M": "float", "N": "double",
    "O": "long double",
}
PRIMITIVE_UNDERSCORE = {
    "N": "bool", "J": "__int64", "K": "unsigned __int64", "W": "wchar_t",
    "Q": "char8_t", "S": "char16_t", "U": "char32_t", "D": "__int8",
    "E": "unsigned __int8", "F": "__int16", "G": "unsigned __int16",
    "H": "__int32", "I": "unsigned __int32", "L": "__int128",
    "M": "unsigned __int128", "T": "std::nullptr_t", "Z": "...",
}
CALLING_CONVENTION = {
    "A": "__cdecl", "B": "__cdecl", "C": "__pascal", "D": "__pascal",
    "E": "__thiscall", "F": "__thiscall", "G": "__stdcall", "H": "__stdcall",
    "I": "__fastcall", "J": "__fastcall", "M": "__clrcall", "N": "__clrcall",
    "O": "__eabi", "P": "__eabi", "Q": "__vectorcall",
}
CV_QUALIFIER = {"A": "", "B": " const", "C": " volatile", "D": " const volatile"}
MEMBER_CV_QUALIFIER = {"Q": "", "R": " const", "S": " volatile",
                       "T": " const volatile"}
POINTER_SELF_QUALIFIER = {"P": "", "Q": " const", "R": " volatile",
                          "S": " const volatile", "A": "", "B": " volatile"}
ENUM_UNDERLYING = {"0": "char", "1": "unsigned char", "2": "short",
                   "3": "unsigned short", "4": "int", "5": "unsigned int",
                   "6": "long", "7": "unsigned long"}
TYPE_DESCRIPTOR_KIND = {"V": "class", "U": "struct", "T": "union", "W": "enum"}
ANONYMOUS_NAMESPACE = "`anonymous namespace'"
BACKREF_TABLE_SIZE = 10


class _Decoder:
    """One decoding run over one decorated name.

    Deliberately a fresh object per name: the back-reference table is per-symbol
    state and sharing it between names is the classic way to produce plausible
    nonsense.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.names: list[str] = []
        self.depth = 0
        self.steps = 0

    # -- primitives --------------------------------------------------------- #

    def _step(self) -> None:
        """Budget guard: a malformed name must not become an unbounded loop."""
        self.steps += 1
        if self.steps > MAX_DEMANGLE_STEPS:
            raise DemangleError("decoder step budget exhausted", self.pos)

    def at_end(self) -> bool:
        return self.pos >= len(self.text)

    def peek(self, count: int = 1) -> str:
        return self.text[self.pos:self.pos + count]

    def take(self, count: int = 1) -> str:
        if self.pos + count > len(self.text):
            raise DemangleError("name ends in the middle of a token", self.pos)
        piece = self.text[self.pos:self.pos + count]
        self.pos += count
        return piece

    def eat(self, literal: str) -> bool:
        if self.text.startswith(literal, self.pos):
            self.pos += len(literal)
            return True
        return False

    def expect(self, literal: str) -> None:
        if not self.eat(literal):
            raise DemangleError("expected %r" % literal, self.pos)

    def memorize(self, text: str) -> None:
        """Add *text* to the back-reference table, MSVC's rules.

        Ten entries maximum, duplicates not re-added: both are the compressor's
        rules, and a decoder that keeps a longer or a duplicated table decodes
        later digits to the wrong name rather than failing loudly.
        """
        if len(self.names) >= BACKREF_TABLE_SIZE or text in self.names:
            return
        self.names.append(text)

    # -- numbers ------------------------------------------------------------ #

    def number(self) -> int:
        """MSVC integer encoding.

        ``?`` prefixes a negative value. A single decimal digit encodes 1..10.
        Anything else is a base-16 run over 'A'..'P' terminated by '@', so
        ``BAPPPP@`` is 0x10FFFF and ``A@`` is 0.
        """
        negative = self.eat("?")
        head = self.peek()
        if head.isdigit():
            self.pos += 1
            value = int(head) + 1
        else:
            value = 0
            while True:
                self._step()
                if self.at_end():
                    raise DemangleError("number is not terminated", self.pos)
                digit = self.take()
                if digit == "@":
                    break
                if "A" <= digit <= "P":
                    value = (value << 4) + (ord(digit) - 65)
                else:
                    raise DemangleError("bad digit %r in number" % digit,
                                        self.pos - 1)
        return -value if negative else value

    # -- names -------------------------------------------------------------- #

    def simple_name(self, memorize: bool = True) -> str:
        end = self.text.find("@", self.pos)
        if end < 0:
            raise DemangleError("unterminated identifier", self.pos)
        name = self.text[self.pos:end]
        self.pos = end + 1
        if not name:
            raise DemangleError("empty identifier", self.pos)
        if memorize:
            self.memorize(name)
        return name

    def anonymous_namespace(self) -> str:
        self.expect("?A")
        if self.eat("0x"):
            while not self.at_end() and self.peek() in "0123456789abcdefABCDEF":
                self.pos += 1
        self.expect("@")
        return ANONYMOUS_NAMESPACE

    def template_name(self, memorize: bool) -> str:
        """``?$Name@<args>@`` -- and the back-reference scoping that goes with it.

        A template argument list runs in its OWN back-reference context; the
        template's own simple name is the first entry of that new context; the
        rendered template-id is memorised into the ENCLOSING context once the
        argument list has closed. See the module docstring: getting this wrong
        corrupts precisely the STL names MSVC compresses hardest.
        """
        self.expect("?$")
        enclosing = self.names
        self.names = []
        base = self.simple_name(memorize=True)
        arguments = self.template_arguments()
        self.names = enclosing
        rendered = "%s<%s>" % (base, arguments) if arguments else "%s<>" % base
        if memorize:
            self.memorize(rendered)
        return rendered

    def name_piece(self) -> str:
        self._step()
        head = self.peek()
        if head.isdigit():
            index = int(self.take())
            if index >= len(self.names):
                raise DemangleError(
                    "back-reference %d but only %d names are memorised"
                    % (index, len(self.names)), self.pos)
            return self.names[index]
        if self.text.startswith("?$", self.pos):
            return self.template_name(memorize=True)
        if self.text.startswith("?A", self.pos):
            return self.anonymous_namespace()
        if head == "?":
            raise DemangleError("unsupported name form %r" % self.peek(4), self.pos)
        return self.simple_name(memorize=True)

    def qualified_name(self) -> str:
        """Innermost name first in the encoding, outermost first in the output."""
        self.depth += 1
        if self.depth > MAX_DEMANGLE_DEPTH:
            raise DemangleError("nesting deeper than %d" % MAX_DEMANGLE_DEPTH,
                                self.pos)
        try:
            parts = [self.name_piece()]
            while True:
                self._step()
                if self.at_end():
                    raise DemangleError("unterminated scope chain", self.pos)
                if self.eat("@"):
                    break
                parts.append(self.name_piece())
            return "::".join(reversed(parts))
        finally:
            self.depth -= 1

    # -- template arguments -------------------------------------------------- #

    def template_arguments(self) -> str:
        parts: list[str] = []
        while True:
            self._step()
            if self.at_end():
                raise DemangleError("unterminated template argument list", self.pos)
            if self.eat("@"):
                break
            # Empty parameter pack / pack separator: encoded, but renders as
            # nothing. Consuming and continuing is the whole handling.
            if self.eat("$$$V") or self.eat("$$V") or self.eat("$$Z") or self.eat("$S"):
                continue
            if self.eat("$$Y"):
                parts.append(self.qualified_name())
                continue
            if self.eat("$$B"):
                parts.append(self.type())
                continue
            if self.eat("$0"):
                parts.append(str(self.number()))
                continue
            if self.eat("$2"):
                mantissa = self.number()
                exponent = self.number()
                parts.append("%de%d" % (mantissa, exponent))
                continue
            if (self.text.startswith("$1", self.pos)
                    or self.text.startswith("$H", self.pos)
                    or self.text.startswith("$I", self.pos)
                    or self.text.startswith("$J", self.pos)):
                raise DemangleError(
                    "pointer-to-member / address-of template argument %r"
                    % self.peek(4), self.pos)
            parts.append(self.type())
        return ",".join(parts)

    # -- types --------------------------------------------------------------- #

    def type(self) -> str:
        self._step()
        self.depth += 1
        if self.depth > MAX_DEMANGLE_DEPTH:
            raise DemangleError("nesting deeper than %d" % MAX_DEMANGLE_DEPTH,
                                self.pos)
        try:
            return self._type_inner()
        finally:
            self.depth -= 1

    def _type_inner(self) -> str:
        if self.at_end():
            raise DemangleError("type is truncated", self.pos)
        # The '$' escapes have to be tested before the single-letter tables,
        # because '$' is not in them and the longest match wins.
        if self.text.startswith("$$A8@@", self.pos):
            self.pos += 6
            return self.function_type()
        if self.text.startswith("$$A6", self.pos):
            self.pos += 4
            return self.function_type()
        if self.text.startswith("$$Q", self.pos) or self.text.startswith("$$R", self.pos):
            self.pos += 3
            return self.pointer_body("&&")
        if self.text.startswith("$$T", self.pos):
            self.pos += 3
            return "std::nullptr_t"
        if self.text.startswith("$$C", self.pos):
            self.pos += 3
            return self.type()
        head = self.peek()
        if head == "_":
            self.pos += 1
            code = self.take()
            if code in PRIMITIVE_UNDERSCORE:
                return PRIMITIVE_UNDERSCORE[code]
            raise DemangleError("unknown primitive '_%s'" % code, self.pos - 1)
        if head in PRIMITIVE:
            self.pos += 1
            return PRIMITIVE[head]
        if head in "VUT":
            self.pos += 1
            return self.qualified_name()
        if head == "W":
            self.pos += 1
            underlying = self.take()
            if underlying not in ENUM_UNDERLYING:
                raise DemangleError("bad enum underlying type %r" % underlying,
                                    self.pos - 1)
            return self.qualified_name()
        if head in "PQRSAB":
            self.pos += 1
            sigil = "&" if head in "AB" else "*"
            return self.pointer_body(sigil, POINTER_SELF_QUALIFIER[head])
        if head == "Y":
            return self.array()
        raise DemangleError("unsupported type code %r" % self.peek(4), self.pos)

    def pointer_body(self, sigil: str, self_qualifier: str = "") -> str:
        # Extended qualifiers on the pointer ITSELF: E is __ptr64 (universal on
        # x64), I is __restrict, F is __unaligned. None of them change the type
        # for our purposes, so they are consumed and not rendered.
        while not self.at_end() and self.peek() in "EIF":
            self.pos += 1
        if self.peek() in "67":
            self.pos += 1
            return_type, convention, parameters = self.function_parts()
            return "%s (%s %s)(%s)" % (return_type, convention, sigil, parameters)
        if self.peek() == "8":
            self.pos += 1
            owner = self.qualified_name()
            while not self.at_end() and self.peek() in "EIF":
                self.pos += 1
            cv = self.peek()
            if cv not in CV_QUALIFIER:
                raise DemangleError("bad this-qualifier %r" % cv, self.pos)
            self.pos += 1
            return_type, convention, parameters = self.function_parts()
            return "%s (%s %s::%s)(%s)%s" % (return_type, convention, owner,
                                             sigil, parameters,
                                             CV_QUALIFIER[cv])
        if self.peek() == "Y":
            return "%s %s" % (self.array(), sigil)
        head = self.peek()
        if head in MEMBER_CV_QUALIFIER:
            self.pos += 1
            owner = self.qualified_name()
            pointee = self.type()
            return "%s %s::%s%s" % (pointee, owner, sigil,
                                    MEMBER_CV_QUALIFIER[head])
        qualifier = CV_QUALIFIER.get(head)
        if qualifier is None:
            raise DemangleError("bad pointee qualifier %r" % head, self.pos)
        self.pos += 1
        return "%s%s %s%s" % (self.type(), qualifier, sigil, self_qualifier)

    def array(self) -> str:
        self.expect("Y")
        rank = self.number()
        if rank < 0 or rank > 64:
            raise DemangleError("implausible array rank %d" % rank, self.pos)
        dimensions = [self.number() for _ in range(rank)]
        head = self.peek()
        qualifier = ""
        if head in CV_QUALIFIER:
            self.pos += 1
            qualifier = CV_QUALIFIER[head]
        element = self.type()
        return element + qualifier + "".join("[%d]" % d for d in dimensions)

    def function_parts(self) -> tuple[str, str, str]:
        code = self.take()
        convention = CALLING_CONVENTION.get(code)
        if convention is None:
            raise DemangleError("bad calling convention %r" % code, self.pos - 1)
        return self.return_type(), convention, self.parameters()

    def function_type(self) -> str:
        return_type, convention, parameters = self.function_parts()
        return "%s %s(%s)" % (return_type, convention, parameters)

    def return_type(self) -> str:
        if self.eat("@"):
            return "void"
        if self.eat("?"):
            head = self.peek()
            if head in CV_QUALIFIER:
                self.pos += 1
                return self.type() + CV_QUALIFIER[head]
        return self.type()

    def parameters(self) -> str:
        if self.eat("X"):
            self.eat("Z")
            return "void"
        parts: list[str] = []
        while True:
            self._step()
            if self.at_end():
                raise DemangleError("parameter list is truncated", self.pos)
            if self.eat("@"):
                self.eat("Z")
                break
            if self.eat("Z"):
                parts.append("...")
                break
            parts.append(self.type())
        return ",".join(parts) if parts else "void"


def demangle_type_descriptor(mangled: str) -> tuple[str, str]:
    """Decode one RTTI type-descriptor name into ``(kind, qualified name)``.

    *mangled* is the whole ``.?A...@@`` string as it appears in the image.
    Raises :class:`DemangleError` -- which the caller COUNTS AND REPORTS rather
    than swallowing, because "we could not read 28 of these" is a finding.
    """
    if len(mangled) > MAX_DEMANGLE_INPUT:
        raise DemangleError("name longer than %d characters" % MAX_DEMANGLE_INPUT, 0)
    if not mangled.startswith(".?A"):
        raise DemangleError("not an RTTI type-descriptor name", 0)
    body = mangled[3:]
    if not body:
        raise DemangleError("type-descriptor name has no body", 3)
    tag = body[0]
    if tag == "W":
        if len(body) < 2 or body[1] not in ENUM_UNDERLYING:
            raise DemangleError("enum descriptor without an underlying type", 4)
        decoder = _Decoder(body[2:])
        kind = "enum"
    elif tag in ("V", "U", "T"):
        decoder = _Decoder(body[1:])
        kind = TYPE_DESCRIPTOR_KIND[tag]
    else:
        raise DemangleError("unknown type-descriptor tag %r" % tag, 3)
    name = decoder.qualified_name()
    if not decoder.at_end():
        raise DemangleError("trailing %r after a complete name"
                            % decoder.text[decoder.pos:], decoder.pos)
    return kind, name


# --------------------------------------------------------------------------- #
# ownership attribution
# --------------------------------------------------------------------------- #
# These tables are the whole of the attribution rule, and they are printed with
# the results on purpose: a reviewer must be able to disagree with one row
# rather than with a verdict. Attribution is a naming-convention INFERENCE and
# nothing in this section is ever graded above class I.

BUCKET_CRT = "msvc-crt-stl"
BUCKET_THIRD_PARTY = "third-party"
BUCKET_UNREAL = "unreal-engine"
BUCKET_GAME = "game-specific-candidate"
BUCKET_UNATTRIBUTED = "unattributed"
BUCKET_ORDER = (BUCKET_CRT, BUCKET_THIRD_PARTY, BUCKET_UNREAL, BUCKET_GAME,
                BUCKET_UNATTRIBUTED)

# Root namespaces / unqualified names owned by the Microsoft toolchain.
CRT_ROOTS = {
    "std": "MSVC C++ standard library",
    "stdext": "MSVC standard library extensions",
    "Concurrency": "MSVC Concurrency Runtime",
    "type_info": "MSVC RTTI runtime",
    "__non_rtti_object": "MSVC RTTI runtime",
    "_com_error": "MSVC COM support library (comdef.h)",
    "_com_ptr_t": "MSVC COM support library (comdef.h)",
    "__crt": "MSVC C runtime",
    "_Crt_new_delete": "MSVC C++ standard library",
}

# Root namespaces owned by a statically linked third-party library. The value is
# the library, not a guess about why it is linked.
THIRD_PARTY_ROOTS = {
    "icu_64": "ICU 64 (International Components for Unicode)",
    "icu_65": "ICU 65",
    "icu": "ICU",
    "Imf_3_2": "OpenEXR 3.2 (IlmImf)",
    "Iex_3_2": "OpenEXR 3.2 (Iex exception hierarchy)",
    "IlmThread_3_2": "OpenEXR 3.2 (IlmThread)",
    "Imath_3_1": "Imath 3.1",
    "draco": "Google Draco",
    "mkvparser": "libwebm (mkvparser)",
    "mkvmuxer": "libwebm (mkvmuxer)",
    "webm": "libwebm",
    "vraudio": "Resonance Audio",
    "absl": "Abseil",
    "google": "Google (protobuf / gRPC family)",
    "rapidjson": "RapidJSON",
    "Eigen": "Eigen",
    "physx": "NVIDIA PhysX",
    "nvidia": "NVIDIA",
    "embree": "Intel Embree",
    "oidn": "Intel Open Image Denoise",
    "tbb": "Intel oneTBB",
    "OIIO": "OpenImageIO",
    "USTC": "third-party",
    "libtorch": "PyTorch",
    "_priv_exr_context_t": "OpenEXR 3.2 (C API context)",
}

# Unqualified third-party class names that carry no namespace at all. Kept as an
# explicit list because a heuristic cannot distinguish "C" for a DirectShow base
# class from "C" for anything else.
THIRD_PARTY_EXACT = {
    # Microsoft DirectShow base classes (strmbase / BaseClasses).
    "CUnknown": "Microsoft DirectShow base classes (strmbase)",
    "CBaseObject": "Microsoft DirectShow base classes (strmbase)",
    "CBaseFilter": "Microsoft DirectShow base classes (strmbase)",
    "CBasePin": "Microsoft DirectShow base classes (strmbase)",
    "CBaseOutputPin": "Microsoft DirectShow base classes (strmbase)",
    "CDynamicOutputPin": "Microsoft DirectShow base classes (strmbase)",
    "CBaseAllocator": "Microsoft DirectShow base classes (strmbase)",
    "CMemAllocator": "Microsoft DirectShow base classes (strmbase)",
    "CMediaSample": "Microsoft DirectShow base classes (strmbase)",
    "CEnumPins": "Microsoft DirectShow base classes (strmbase)",
    "CEnumMediaTypes": "Microsoft DirectShow base classes (strmbase)",
    "CSource": "Microsoft DirectShow base classes (strmbase)",
    "CSourceStream": "Microsoft DirectShow base classes (strmbase)",
    "CAMThread": "Microsoft DirectShow base classes (strmbase)",
    "CCritSec": "Microsoft DirectShow base classes (strmbase)",
    "CAutoCriticalSection": "Microsoft DirectShow base classes (strmbase)",
    "CSingletonCriticalSection": (
        "NVIDIA NVAPI -- the byte-identical decorated name .?AVCSingletonCriticalSection@@ "
        "occurs in Engine/Source/ThirdParty/NVIDIA/nvapi/amd64/nvapi64.lib of a local "
        "UE 5.4 installation. INFERRED, not observed on this build"),
}

# Root namespaces of the engine itself.
UNREAL_ROOTS = {
    "UE", "UE4", "UE5", "SharedPointerInternals", "Chaos", "ChaosInterface",
    "Audio", "AudioModulation", "Nanite", "Trace", "TraceServices", "Verse",
    "AutoRTFM", "CoreUObject", "Metasound", "Freetype2", "Interchange",
    "UnrealBuildTool", "Algo", "Concepts", "UE_Core",
}

# The Unreal Hungarian prefix rule: one convention letter followed by an
# upper-case letter. F struct/class, U UObject-derived, A AActor-derived,
# S SWidget-derived, T template, I interface, E enum. "C" is deliberately NOT in
# this set -- it is the MFC/ATL/DirectShow convention, not Unreal's.
UNREAL_PREFIX_RE = re.compile(r"^[FUASTIE][A-Z]")

ATTRIBUTION_RULES = (
    "1. root == a name in CRT_ROOTS                       -> msvc-crt-stl",
    "2. root == a name in THIRD_PARTY_ROOTS               -> third-party",
    "3. full name in THIRD_PARTY_EXACT                    -> third-party",
    "4. root == a name in UNREAL_ROOTS                    -> unreal-engine",
    "5. root matches ^[FUASTIE][A-Z] (Unreal Hungarian)   -> unreal-engine",
    "6. rule 5 matched AND --ue-source-root was given AND the identifier is "
    "absent from that tree -> game-specific-candidate",
    "7. anything else                                     -> unattributed",
)


def root_identifier(name: str) -> str:
    """The outermost namespace of a decoded name, or the name itself.

    Template arguments are stripped first: the owner of
    ``icu_64::LocaleCacheKey<icu_64::SharedCalendar>`` is decided by
    ``icu_64``, never by what happens to be inside the angle brackets.
    """
    depth = 0
    for index, character in enumerate(name):
        if character == "<":
            depth += 1
        elif character == ">":
            depth = max(0, depth - 1)
        elif depth == 0 and name.startswith("::", index):
            return name[:index]
    cut = name.find("<")
    return name if cut < 0 else name[:cut]


def bare_identifier(name: str) -> str:
    """The root with any template argument list removed -- a grep-able token."""
    root = root_identifier(name)
    cut = root.find("<")
    return root if cut < 0 else root[:cut]


def classify_name(kind: str, name: str) -> dict:
    """Attribute one decoded class name to an owner. Always class I."""
    root = root_identifier(name)
    bare = bare_identifier(name)
    if root in CRT_ROOTS:
        return {"bucket": BUCKET_CRT, "owner": CRT_ROOTS[root],
                "rule": "root in CRT_ROOTS", "root": root}
    if root in THIRD_PARTY_ROOTS:
        return {"bucket": BUCKET_THIRD_PARTY, "owner": THIRD_PARTY_ROOTS[root],
                "rule": "root in THIRD_PARTY_ROOTS", "root": root}
    if bare in THIRD_PARTY_EXACT:
        return {"bucket": BUCKET_THIRD_PARTY, "owner": THIRD_PARTY_EXACT[bare],
                "rule": "name in THIRD_PARTY_EXACT", "root": root}
    if root == ANONYMOUS_NAMESPACE or name.startswith(ANONYMOUS_NAMESPACE):
        return {"bucket": BUCKET_UNATTRIBUTED,
                "owner": None,
                "rule": ("declared in an anonymous namespace; the decorated name "
                         "carries no owner and attribution by name is impossible"),
                "root": root}
    if root in UNREAL_ROOTS:
        return {"bucket": BUCKET_UNREAL, "owner": "Unreal Engine",
                "rule": "root in UNREAL_ROOTS", "root": root}
    if UNREAL_PREFIX_RE.match(bare):
        return {"bucket": BUCKET_UNREAL, "owner": "Unreal Engine (by naming convention)",
                "rule": "root matches the Unreal Hungarian prefix ^[FUASTIE][A-Z]",
                "root": root}
    return {"bucket": BUCKET_UNATTRIBUTED, "owner": None,
            "rule": "no rule matched", "root": root}


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hex_bytes(raw: bytes) -> str:
    return raw.hex()


def dump_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


class SectionMap:
    """Section lookup plus the two address translations the scan needs.

    ``pe_info.PEHeaders`` already answers RVA -> file offset; the RTTI walk also
    needs the reverse (a name is found at a file offset and its structures are
    addressed by RVA) and a fast "is this RVA executable" predicate for the
    vtable slot test.
    """

    def __init__(self, headers) -> None:
        self.headers = headers
        self.sections = [s for s in headers.sections if s["rsize"] > 0]
        self.executable = [
            s for s in self.sections
            if s["characteristics"] & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)
        ]

    def offset_to_rva(self, offset: int) -> int | None:
        for section in self.sections:
            start = section["raw_pointer"]
            if start <= offset < start + section["rsize"]:
                return section["rva"] + (offset - start)
        return None

    def section_of_rva(self, rva: int) -> dict | None:
        for section in self.sections:
            span = max(section["vsize"], section["rsize"])
            if span and section["rva"] <= rva < section["rva"] + span:
                return section
        return None

    def section_of_offset(self, offset: int) -> dict | None:
        for section in self.sections:
            start = section["raw_pointer"]
            if start <= offset < start + section["rsize"]:
                return section
        return None

    def is_executable_rva(self, rva: int) -> bool:
        for section in self.executable:
            span = max(section["vsize"], section["rsize"])
            if span and section["rva"] <= rva < section["rva"] + span:
                return True
        return False


def select_scan_sections(section_map: SectionMap, names: tuple[str, ...] | None,
                         skip: tuple[str, ...]) -> list[dict]:
    """The surface a pass will actually search, as a list of sections.

    Returned rather than assumed so the document can PRINT the surface. A null
    result is only meaningful next to the range it is null over.

    ``skip`` applies to the DEFAULT surface only. When the caller names sections
    explicitly the names win, including ``.text`` -- that is the point: proving a
    null result over the sections the default excludes is the refutation the
    negative direction of S-10 needs, and a flag that silently declined to search
    where it was told would make that impossible.
    """
    chosen = []
    for section in section_map.sections:
        if names is not None:
            if section["name"] in names:
                chosen.append(section)
            continue
        if section["name"] in skip:
            continue
        chosen.append(section)
    return chosen


def describe_sections(sections: list[dict]) -> list[dict]:
    return [{
        "name": section["name"],
        "rva": section["rva"],
        "file_offset": section["raw_pointer"],
        "raw_size": section["rsize"],
        "virtual_size": section["vsize"],
        "characteristics": "0x%08x" % section["characteristics"],
    } for section in sections]


def iter_section_chunks(image, section: dict, chunk: int, overlap: int):
    """Yield ``(file_offset_of_chunk_start, bytes)`` covering a section's raw data.

    One reused window with a bounded overlap so a structure straddling a chunk
    boundary is still seen exactly once by the caller's de-duplication. Peak
    memory is chunk + overlap regardless of section size.
    """
    start = section["raw_pointer"]
    remaining = section["rsize"]
    position = 0
    tail = b""
    tail_origin = start
    while remaining > 0:
        want = min(chunk, remaining)
        block = image.read_at(start + position, want, "section scan")
        data = tail + block
        yield tail_origin, data
        position += want
        remaining -= want
        if overlap and len(data) > overlap:
            tail = data[-overlap:]
            tail_origin = start + position - len(tail)
        else:
            tail = b""
            tail_origin = start + position


# --------------------------------------------------------------------------- #
# pass 1 -- type descriptors
# --------------------------------------------------------------------------- #

def scan_type_descriptors(image, headers, section_map: SectionMap,
                          sections: list[dict], warnings: list[str]) -> dict:
    """Find every ``.?A...@@`` name and the ``TypeDescriptor`` in front of it.

    Two numbers come out of this, and they are NOT the same number:

    ``name_string_count``
        how many byte strings of the right shape exist. This is the number a
        ``strings | grep`` would give, and on its own it means very little.

    ``type_descriptors``
        how many of those are preceded by a structurally valid descriptor
        header: a ``spare`` field of zero and a ``pVFTable`` that lands inside
        the image. The strongest check is left to the caller: in a real image
        every descriptor shares ONE ``pVFTable`` (``type_info``'s), so the modal
        value and its share are reported and a low share is a red flag, not a
        detail.
    """
    records: list[dict] = []
    name_strings = 0
    seen_offsets: set[int] = set()
    truncated = False

    for section in sections:
        for origin, data in iter_section_chunks(image, section, SCAN_CHUNK,
                                                SCAN_OVERLAP):
            for match in TD_NAME_RE.finditer(data):
                name_offset = origin + match.start()
                if name_offset in seen_offsets:
                    continue
                seen_offsets.add(name_offset)
                name_strings += 1
                if len(records) >= MAX_TYPE_DESCRIPTORS:
                    truncated = True
                    continue
                raw_name = match.group()[:-1]
                descriptor_offset = name_offset - TD_HEADER_SIZE
                if descriptor_offset < section["raw_pointer"]:
                    # The name sits in the first 16 bytes of the section, so
                    # there is no room for a header in front of it.
                    continue
                header = image.read_at(descriptor_offset, TD_HEADER_SIZE,
                                       "TypeDescriptor header")
                vftable_va, spare = struct.unpack("<QQ", header)
                descriptor_rva = section_map.offset_to_rva(descriptor_offset)
                if descriptor_rva is None:
                    continue
                in_image = (headers.image_base <= vftable_va
                            < headers.image_base + headers.size_of_image)
                records.append({
                    "type_descriptor_rva": descriptor_rva,
                    "type_descriptor_file_offset": descriptor_offset,
                    "name_rva": descriptor_rva + TD_HEADER_SIZE,
                    "name_file_offset": name_offset,
                    "name_length": len(raw_name),
                    "mangled": raw_name.decode("latin-1"),
                    "vftable_va": vftable_va,
                    "vftable_rva": (vftable_va - headers.image_base) if in_image else None,
                    "spare": spare,
                    "section": section["name"],
                    "header_hex": header.hex(),
                })

    if truncated:
        warnings.append(
            "the type-descriptor table hit the %d-record limit; the counts below "
            "are a floor, not a total" % MAX_TYPE_DESCRIPTORS)

    records.sort(key=lambda item: item["type_descriptor_rva"])
    vftables = Counter(record["vftable_va"] for record in records)
    modal_vftable, modal_count = (vftables.most_common(1)[0] if vftables
                                  else (None, 0))
    structurally_valid = [
        record for record in records
        if record["spare"] == 0
        and record["vftable_rva"] is not None
        and record["vftable_va"] == modal_vftable
    ]
    return {
        "name_string_count": name_strings,
        "records": records,
        "structurally_valid": structurally_valid,
        "modal_vftable_va": modal_vftable,
        "modal_vftable_rva": ((modal_vftable - headers.image_base)
                              if modal_vftable is not None else None),
        "modal_vftable_share": (modal_count / len(records)) if records else None,
        "distinct_vftables": len(vftables),
        "nonzero_spare_count": sum(1 for r in records if r["spare"] != 0),
        "truncated": truncated,
    }


# --------------------------------------------------------------------------- #
# pass 2 -- complete object locators
# --------------------------------------------------------------------------- #

def scan_complete_object_locators(image, headers, section_map: SectionMap,
                                  sections: list[dict],
                                  descriptor_rvas: frozenset[int],
                                  warnings: list[str]) -> dict:
    """Find every ``RTTICompleteObjectLocator``, by two independent predicates.

    ``strict``
        PE32+ only. ``signature == 1`` and ``pSelf`` equals the record's own
        image-relative address. This is self-identifying: the record certifies
        its own location, and nothing else in the scan depends on the type
        descriptor table being right.

    ``loose``
        ``signature`` is 0 or 1 and ``pTypeDescriptor`` lands exactly on a
        descriptor found by pass 1. This predicate does NOT use ``pSelf``, so it
        is the PE32 path -- and on PE32+ it is a refutation probe: if it finds
        locators the strict scan missed, the strict count is an undercount and
        the headline number is wrong.

        Taken alone this predicate is far too permissive, and measurably so: an
        ``RTTIBaseClassDescriptor`` also begins with a ``pTypeDescriptor`` field,
        so every position twelve bytes in front of one matches. The raw candidate
        set is therefore only an intermediate -- :func:`validate_locator_candidates`
        filters it by walking the class hierarchy, and the probe compares the
        *validated* set against the strict set. Both numbers are reported so the
        filtering is visible instead of implicit.

    Both are 4-byte-aligned walks. MSVC emits these records into read-only data
    at natural alignment; an unaligned walk would multiply the false-positive
    surface by four for no gain, and that choice is stated in the output.
    """
    is_pe32_plus = headers.pe_format == "PE32+"
    record_size = COL_SIZE_PE32PLUS if is_pe32_plus else COL_SIZE_PE32
    words_needed = record_size // 4

    strict: list[int] = []
    loose: list[int] = []
    truncated = False
    scanned_bytes = 0

    # A record is `record_size` bytes wide, so the last `words_needed - 1` words
    # of a chunk cannot be tested as a record START. Without an overlap a locator
    # straddling a chunk boundary is silently missed -- an undercount that no
    # output would show, which is the one failure mode this whole tool exists to
    # avoid. The window therefore steps back by record_size - 4 on every advance,
    # and duplicates are removed afterwards.
    overlap = record_size - 4
    for section in sections:
        base_offset = section["raw_pointer"]
        base_rva = section["rva"]
        size = section["rsize"]
        position = 0
        while position < size:
            want = min(SCAN_CHUNK, size - position) & ~3
            if want == 0:
                break
            block = image.read_at(base_offset + position, want, "locator scan")
            words = array("I")
            words.frombytes(block)
            if sys.byteorder != "little":  # pragma: no cover - x86/x64 hosts only
                words.byteswap()
            chunk_rva = base_rva + position
            limit = len(words) - words_needed + 1
            for index in range(max(0, limit)):
                signature = words[index]
                if signature > COL_SIGNATURE_PE32PLUS:
                    continue
                here = chunk_rva + index * 4
                type_descriptor = words[index + 3]
                if (is_pe32_plus and signature == COL_SIGNATURE_PE32PLUS
                        and words[index + 5] == here):
                    if len(strict) < MAX_LOCATORS:
                        strict.append(here)
                    else:
                        truncated = True
                if type_descriptor in descriptor_rvas:
                    if len(loose) < MAX_LOCATORS:
                        loose.append(here)
                    else:
                        truncated = True
            scanned_bytes += want
            if position + want >= size:
                break
            # Step back so a record spanning the boundary is seen whole. The
            # step-back is a multiple of 4, so the 4-byte alignment of the walk
            # is preserved.
            position += max(4, want - overlap)

    if truncated:
        warnings.append(
            "the complete-object-locator scan hit the %d-record limit; the counts "
            "below are a floor" % MAX_LOCATORS)
    # The overlap above can report a boundary-straddling record twice.
    strict = sorted(set(strict))
    loose = sorted(set(loose))
    return {
        "strict_rvas": strict,
        "loose_candidate_rvas": loose,
        "record_size": record_size,
        "alignment": 4,
        "scanned_bytes": scanned_bytes,
        "pe32_plus": is_pe32_plus,
        "truncated": truncated,
    }


def validate_locator_candidates(headers, candidates: list[int],
                                descriptor_rvas: frozenset[int],
                                is_pe32_plus: bool) -> list[int]:
    """Keep only the loose candidates whose class hierarchy actually chains.

    This is the pSelf-independent predicate that is worth something. A position
    survives only if its ``pClassDescriptor`` reaches a hierarchy descriptor with
    ``signature == 0``, a plausible ``numBaseClasses``, a readable base class
    array, and a first base class descriptor that names the very type descriptor
    the candidate points at. Three pointers followed in three directions have to
    agree, which the coincidental matches on the front of a base class descriptor
    cannot do.
    """
    kept: list[int] = []
    for rva in candidates:
        try:
            locator = read_locator(headers, rva, is_pe32_plus)
        except PEFormatError:
            continue
        if locator["type_descriptor_rva"] not in descriptor_rvas:
            continue
        hierarchy = read_hierarchy(headers, locator["class_descriptor_rva"],
                                   locator["type_descriptor_rva"],
                                   descriptor_rvas)
        if hierarchy["problem"] is not None:
            continue
        if hierarchy["first_base_is_self"] is not True:
            continue
        kept.append(rva)
    return kept


def read_locator(headers, rva: int, is_pe32_plus: bool) -> dict:
    size = COL_SIZE_PE32PLUS if is_pe32_plus else COL_SIZE_PE32
    raw = headers.read_rva(rva, size, "RTTICompleteObjectLocator")
    fields = struct.unpack("<%dI" % (size // 4), raw)
    record = {
        "rva": rva,
        "signature": fields[0],
        "offset": fields[1],
        "cd_offset": fields[2],
        "type_descriptor_rva": fields[3],
        "class_descriptor_rva": fields[4],
        "self_rva": fields[5] if is_pe32_plus else None,
        "raw_hex": raw.hex(),
    }
    record["self_rva_matches"] = (None if not is_pe32_plus
                                  else record["self_rva"] == rva)
    return record


# --------------------------------------------------------------------------- #
# pass 3 -- class hierarchy descriptors and base class arrays
# --------------------------------------------------------------------------- #

def read_hierarchy(headers, class_descriptor_rva: int,
                   own_type_descriptor_rva: int,
                   descriptor_rvas: frozenset[int]) -> dict:
    """Read one ``RTTIClassHierarchyDescriptor`` and walk its base class array.

    The coherence conditions, all of which are reported per record rather than
    assumed:

    * ``signature`` is 0;
    * ``numBaseClasses`` is at least 1 and within :data:`MAX_BASE_CLASSES`;
    * the base class array is fully readable on disk;
    * **the first base class descriptor describes the class itself.** MSVC
      always puts the class at index 0 of its own base class array, so this is a
      free, strong cross-check between two structures reached by two different
      pointers.
    """
    result = {
        "class_descriptor_rva": class_descriptor_rva,
        "readable": False,
        "signature": None,
        "attributes": None,
        "attributes_decoded": None,
        "base_class_count": None,
        "base_class_array_rva": None,
        "base_class_array_readable": None,
        "first_base_is_self": None,
        "base_type_descriptor_rvas": [],
        "unknown_base_type_descriptors": 0,
        "problem": None,
    }
    try:
        raw = headers.read_rva(class_descriptor_rva, CHD_SIZE,
                               "RTTIClassHierarchyDescriptor")
    except PEFormatError as error:
        result["problem"] = "class hierarchy descriptor unreadable: %s" % error
        return result
    signature, attributes, count, array_rva = struct.unpack("<4I", raw)
    result.update({
        "readable": True,
        "signature": signature,
        "attributes": attributes,
        "attributes_decoded": sorted(
            flag for bit, flag in ((1, "multiple-inheritance"),
                                   (2, "virtual-inheritance"),
                                   (4, "ambiguous"))
            if attributes & bit),
        "base_class_count": count,
        "base_class_array_rva": array_rva,
    })
    if signature != 0:
        result["problem"] = "signature is %d, expected 0" % signature
        return result
    if not 1 <= count <= MAX_BASE_CLASSES:
        result["problem"] = ("numBaseClasses is %d, outside [1, %d]"
                             % (count, MAX_BASE_CLASSES))
        return result
    try:
        raw_array = headers.read_rva(array_rva, 4 * count, "base class array")
    except PEFormatError as error:
        result["base_class_array_readable"] = False
        result["problem"] = "base class array unreadable: %s" % error
        return result
    result["base_class_array_readable"] = True
    pointers = array("I")
    pointers.frombytes(raw_array)
    if sys.byteorder != "little":  # pragma: no cover
        pointers.byteswap()

    base_type_descriptors: list[int] = []
    unknown = 0
    for index, base_rva in enumerate(pointers):
        try:
            base_raw = headers.read_rva(base_rva, BCD_SIZE,
                                        "RTTIBaseClassDescriptor")
        except PEFormatError:
            unknown += 1
            continue
        base_type_descriptor = struct.unpack("<I", base_raw[:4])[0]
        base_type_descriptors.append(base_type_descriptor)
        if base_type_descriptor not in descriptor_rvas:
            unknown += 1
        if index == 0:
            result["first_base_is_self"] = (
                base_type_descriptor == own_type_descriptor_rva)
    result["base_type_descriptor_rvas"] = base_type_descriptors
    result["unknown_base_type_descriptors"] = unknown
    return result


# --------------------------------------------------------------------------- #
# pass 4 -- vtable reachability
# --------------------------------------------------------------------------- #

def scan_vtable_references(image, headers, section_map: SectionMap,
                           sections: list[dict], locator_rvas: frozenset[int],
                           warnings: list[str]) -> dict:
    """Find the pointer-sized slots that hold ``image_base + locator_rva``.

    A complete object locator is reachable from code only through the hidden
    slot immediately *before* a vtable, so this is the pass that decides whether
    the RTTI found so far is worth anything. Every 8-byte-aligned (4 on PE32)
    position in the searched sections is compared against the locator set; a hit
    at address ``L`` means the vtable begins at ``L + pointer_size``.

    Streaming, one reused window, no per-hit re-read of the file.
    """
    pointer_size = headers.pointer_size
    fmt = "Q" if pointer_size == 8 else "I"
    image_base = headers.image_base
    references: dict[int, list[int]] = {}
    scanned_bytes = 0
    for section in sections:
        base_offset = section["raw_pointer"]
        base_rva = section["rva"]
        remaining = section["rsize"]
        position = 0
        while remaining > 0:
            want = min(SCAN_CHUNK, remaining)
            want -= want % pointer_size
            if want == 0:
                break
            block = image.read_at(base_offset + position, want,
                                  "vtable reference scan")
            values = array(fmt)
            values.frombytes(block)
            if sys.byteorder != "little":  # pragma: no cover
                values.byteswap()
            chunk_rva = base_rva + position
            for index, value in enumerate(values):
                if value <= image_base:
                    continue
                candidate = value - image_base
                if candidate in locator_rvas:
                    slots = references.setdefault(candidate, [])
                    if len(slots) < MAX_VTABLE_REFS_PER_LOCATOR:
                        slots.append(chunk_rva + index * pointer_size)
                    else:
                        warnings.append(
                            "locator at RVA 0x%x is referenced more than %d times; "
                            "the reference list is truncated"
                            % (candidate, MAX_VTABLE_REFS_PER_LOCATOR))
            position += want
            remaining -= want
            scanned_bytes += want
    return {"references": references, "scanned_bytes": scanned_bytes,
            "alignment": pointer_size}


def measure_vtable(headers, section_map: SectionMap, slot_rva: int) -> dict:
    """How many consecutive executable-looking slots follow the locator slot.

    "Usable" is defined narrowly and stated: the vtable starts one pointer after
    the locator slot, and a slot counts while it holds an address inside a
    section marked executable. The walk stops at the first slot that does not,
    which is how a vtable actually ends in a linked image (the next thing in
    ``.rdata`` is another structure, not code).
    """
    pointer_size = headers.pointer_size
    fmt = "<Q" if pointer_size == 8 else "<I"
    start = slot_rva + pointer_size
    count = 0
    first_slot = None
    while count < MAX_VTABLE_SLOTS:
        try:
            raw = headers.read_rva(start + count * pointer_size, pointer_size,
                                   "vtable slot")
        except PEFormatError:
            break
        value = struct.unpack(fmt, raw)[0]
        if value <= headers.image_base:
            break
        target = value - headers.image_base
        if not section_map.is_executable_rva(target):
            break
        if first_slot is None:
            first_slot = target
        count += 1
    section = section_map.section_of_rva(start)
    return {
        "vtable_rva": start,
        "code_slot_count": count,
        "first_slot_rva": first_slot,
        "section": section["name"] if section else None,
    }


# --------------------------------------------------------------------------- #
# optional: how many vtable-shaped runs exist at all (the coverage denominator)
# --------------------------------------------------------------------------- #

VTABLE_CENSUS_THRESHOLDS = (4, 8, 16)


def vtable_census(image, headers, section_map: SectionMap,
                  sections: list[dict]) -> dict:
    """Count runs of consecutive pointer slots that address executable sections.

    This exists for one reason: "RTTI covers 587 classes" is not an answer to
    "how much does RTTI reduce the cost of static RE" without a denominator, and
    the denominator is how many polymorphic classes the image has *in total*.

    It is an APPROXIMATION and is labelled as one everywhere it appears. A run of
    N consecutive slots holding executable addresses is vtable-shaped, but so is
    a jump table, a dispatch array or a static table of function pointers, and a
    vtable with fewer than N virtual functions is missed. Three thresholds are
    reported rather than one so a reader can see how sensitive the number is to
    the choice. plan.md S-09 (``tools/static/vtable_scan.py``) owns the real
    inventory; this is a bounded side-measurement so that the S-10 verdict can
    state a ratio instead of a bare count.
    """
    pointer_size = headers.pointer_size
    fmt = "Q" if pointer_size == 8 else "I"
    image_base = headers.image_base
    runs = {threshold: 0 for threshold in VTABLE_CENSUS_THRESHOLDS}
    total_code_slots = 0
    current_run = 0

    def close(length: int) -> None:
        for threshold in VTABLE_CENSUS_THRESHOLDS:
            if length >= threshold:
                runs[threshold] += 1

    for section in sections:
        current_run = 0
        base_offset = section["raw_pointer"]
        remaining = section["rsize"]
        position = 0
        while remaining > 0:
            want = min(SCAN_CHUNK, remaining)
            want -= want % pointer_size
            if want == 0:
                break
            block = image.read_at(base_offset + position, want, "vtable census")
            values = array(fmt)
            values.frombytes(block)
            if sys.byteorder != "little":  # pragma: no cover
                values.byteswap()
            for value in values:
                if value > image_base and section_map.is_executable_rva(
                        value - image_base):
                    current_run += 1
                    total_code_slots += 1
                else:
                    if current_run:
                        close(current_run)
                    current_run = 0
            position += want
            remaining -= want
        if current_run:
            close(current_run)
    return {
        "sections": [section["name"] for section in sections],
        "pointer_slots_addressing_executable_sections": total_code_slots,
        "runs_by_minimum_length": {str(k): v for k, v in sorted(runs.items())},
        "caveat": (
            "APPROXIMATION, not an inventory. A vtable-shaped run may be a jump "
            "table or a static function-pointer table, and a vtable shorter than "
            "the threshold is missed. plan.md S-09 owns the real vtable inventory; "
            "this number exists only to give the S-10 coverage ratio a denominator."
        ),
    }


# --------------------------------------------------------------------------- #
# optional corroboration: is this identifier declared in an Unreal source tree?
# --------------------------------------------------------------------------- #

def corroborate_against_source(root: str, identifiers: list[str],
                               warnings: list[str]) -> dict:
    """One streaming pass over a source tree, answering "is each name declared here".

    A second, INDEPENDENT method on a different oracle (``filesystem``) for the
    Unreal attribution: the naming convention says a name looks like the engine's,
    this says the engine actually declares it. The distinction matters most for
    the names the convention CANNOT place -- a UE-shaped identifier that is
    absent from the engine tree is the only positive evidence for
    "game-specific" that this tool can produce.

    Bounded: one regular expression over the whole identifier set, files read one
    at a time with a size cap, no file kept after it is searched.
    """
    result = {
        "root": os.path.abspath(root),
        "available": os.path.isdir(root),
        "files_scanned": 0,
        "bytes_scanned": 0,
        "found": {},
        "elapsed_seconds": None,
    }
    if not result["available"]:
        warnings.append("--ue-source-root %r is not a directory; the source "
                        "corroboration pass did not run" % root)
        return result
    wanted = sorted({name for name in identifiers if name and name.isidentifier()})
    if not wanted:
        return result
    pattern = re.compile(
        rb"\b(" + b"|".join(re.escape(name.encode("ascii")) for name in wanted)
        + rb")\b")
    found: dict[str, str] = {}
    started = time.monotonic()
    files = 0
    scanned = 0
    for directory, subdirectories, filenames in os.walk(root):
        # Never enter build output: it is large, it is generated, and a name
        # found only there says nothing about what the engine declares.
        skip_dirs = (".git", "Intermediate", "Binaries", "DerivedDataCache")
        subdirectories[:] = [d for d in subdirectories if d not in skip_dirs]
        for filename in filenames:
            if not filename.endswith(UE_SOURCE_SUFFIXES):
                continue
            path = os.path.join(directory, filename)
            try:
                if os.path.getsize(path) > UE_SOURCE_MAX_FILE:
                    continue
                with open(path, "rb") as handle:
                    blob = handle.read(UE_SOURCE_MAX_FILE)
            except OSError:
                continue
            files += 1
            scanned += len(blob)
            for match in pattern.finditer(blob):
                name = match.group(1).decode("ascii")
                if name not in found:
                    found[name] = os.path.relpath(path, root).replace("\\", "/")
            if len(found) == len(wanted):
                break
        if len(found) == len(wanted):
            break
    result.update({
        "files_scanned": files,
        "bytes_scanned": scanned,
        "found": found,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "identifiers_requested": wanted,
    })
    return result


# --------------------------------------------------------------------------- #
# evidence layer 1 (class P): literal reads
# --------------------------------------------------------------------------- #

def literal_read(target: str, decoded_field: str, offset: int, raw: bytes,
                 note: str | None = None) -> dict:
    """One class-P record: a literal read at a determinate place, and nothing more.

    ``claim`` is the citable sentence. It states the offset AND the length --
    which plan.md 10.3 v2.4 makes mandatory for the ``binary-analysis`` oracle to
    be class P at all -- and it stops short of naming what the bytes are.
    ``decoded_field`` is a join key into the interpretive layer, not part of the
    claim.
    """
    length = len(raw)
    plural = "byte" if length == 1 else "bytes"
    claim = "%d %s at offset %d of %s are %s" % (
        length, plural, offset, target, hex_bytes(raw))
    return {
        "decoded_field": decoded_field,
        "interpretation_lives_in": (
            "the matching entry of type_descriptors[] / complete_object_locators[] "
            "in the same document -- plan.md 10.3, the A-07 / A-07i split"),
        "target": target,
        "offset": offset,
        "length": length,
        "bytes_hex": hex_bytes(raw),
        "claim": claim,
        "evidence": {
            "evidence_level": "OBSERVED",
            "claim_class": "P",
            "confidence": CONFIDENCE_LITERAL,
            "oracle": ["binary-analysis"],
            "sources": [{
                "method": "S-10",
                "artifact": None,
                "locator": "%s@%d+%d" % (target, offset, length),
                # The reproduction clause is filled in by confirm_literal_reads
                # once the second read has actually happened. Never pre-filled:
                # an attestation written before the check is a claim about the
                # author's intention, not about the file.
                "note": ("oracle binary-analysis. Read by %s, read-only. "
                         "Reproduction: PENDING." % GENERATOR_NAME),
            }],
            "read_locus": {
                "target": target,
                "address_kind": "file-offset",
                "offset": offset,
                "length": length,
                "bytes_hex": hex_bytes(raw),
                "note": note,
            },
            # The note IS the claim, on purpose. tools/kb/validate.py derives the
            # claim class of a reduced annotation from this string alone, and
            # plan.md 10.3 v2.4 admits binary-analysis into class P only when the
            # claim states a determinate address AND an extent and does not name
            # what the bytes are. A note that talked ABOUT the record instead of
            # stating it derived class I and dragged the whole 0.99 band's
            # two-method requirement with it -- the grading has to be able to see
            # the sentence it is grading. The pointer to the interpretive half
            # lives in `interpretation_lives_in` above, outside the graded object,
            # because naming a structure inside this string is exactly what would
            # disqualify it.
            "note": ("%s. This record gives the position and the extent, and "
                     "nothing else." % claim),
        },
    }


def confirm_literal_reads(path: str, literals: list[dict], target: str,
                          warnings: list[str]) -> bool:
    """Perform every literal read a SECOND time and stamp the result onto each record.

    plan.md 10.3 class-P criterion 2 executed rather than asserted. The second
    pass uses a freshly opened handle and seeks independently. On any
    disagreement nothing is adjusted: the failure is recorded on the record and
    the reading stands as unreproduced.
    """
    reproduced = True
    try:
        with open(path, "rb", buffering=0) as handle:
            for read in literals:
                handle.seek(read["offset"])
                again = handle.read(read["length"])
                if hex_bytes(again) != read["bytes_hex"]:
                    reproduced = False
                    warnings.append(
                        "%s: the second read of %d bytes at offset %d gave %s but the "
                        "first gave %s -- the reading did NOT reproduce"
                        % (target, read["length"], read["offset"], hex_bytes(again),
                           read["bytes_hex"]))
    except OSError as error:
        reproduced = False
        warnings.append("%s: the confirming re-read could not be performed: %s"
                        % (target, error))
    attestation = RERUN_CONFIRMED if reproduced else RERUN_NOT_CONFIRMED
    for read in literals:
        read["reproduced"] = reproduced
        read["evidence"]["sources"][0]["note"] = (
            "oracle binary-analysis. Read by %s, read-only. %s"
            % (GENERATOR_NAME, attestation))
        read["evidence"]["note"] = "%s %s" % (read["evidence"]["note"], attestation)
    return reproduced


def decoded_annotation(target: str, corroborated: bool, corroboration_note: str,
                       corroboration_oracle: str = "binary-analysis") -> dict:
    """The class-I annotation for the interpretive layer.

    INFERRED, therefore class I unconditionally (plan.md 10.3), whatever the
    offsets are. 0.85 only when a second, independent method actually
    corroborated the reading, 0.79 otherwise, because plan.md 10.3 wants two
    independent methods from 0.80 up and re-reading the same bytes is not a
    second method.
    """
    sources = [{
        "method": "S-10",
        "artifact": None,
        "locator": target,
        "note": ("oracle binary-analysis + external-doc. Field decode against the "
                 "published MSVC RTTI record layout (TypeDescriptor, "
                 "RTTICompleteObjectLocator, RTTIClassHierarchyDescriptor, "
                 "RTTIBaseClassDescriptor)."),
    }]
    oracles = ["binary-analysis", "external-doc"]
    if corroborated:
        sources.append({
            "method": "S-10",
            "artifact": None,
            "locator": target,
            "independent_of": ["S-10/field-decode"],
            "note": ("oracle %s. Second, independent method: %s"
                     % (corroboration_oracle, corroboration_note)),
        })
        if corroboration_oracle not in oracles:
            oracles.append(corroboration_oracle)
    return {
        "evidence_level": "INFERRED",
        "claim_class": "I",
        "confidence": (CONFIDENCE_DECODED_CORROBORATED if corroborated
                       else CONFIDENCE_DECODED_SINGLE_METHOD),
        "oracle": sorted(oracles),
        "sources": sources,
        "read_locus": None,
        "note": (
            "Interpretive: this record NAMES the byte ranges, decodes the mangled "
            "names and attributes the classes to owners, which leans on the "
            "published MSVC ABI (external-doc -- proves how the Microsoft "
            "toolchain lays these records out, not what this build contains) and "
            "on naming conventions. The primitive half is in literal_reads[]. %s"
            % corroboration_note
        ),
    }


# --------------------------------------------------------------------------- #
# refutation probes
# --------------------------------------------------------------------------- #

def build_refutation_probes(descriptors: dict, locators: dict,
                            classes: list[dict], summary: dict) -> list[dict]:
    """Three checks whose PURPOSE is to break the headline conclusion.

    A scan that only produces supporting numbers cannot tell a real finding from
    a broken scanner, so each probe below states what result would refute the
    verdict and reports whether that happened.
    """
    probes: list[dict] = []

    # Probe 1: is the positive finding an artefact of a loose pattern?
    valid = len(descriptors["structurally_valid"])
    total = len(descriptors["records"])
    share = descriptors["modal_vftable_share"]
    probes.append({
        "id": "P1-type-descriptor-coherence",
        "question": (
            "Could the .?A name strings be incidental data rather than real "
            "TypeDescriptor records?"),
        "refuting_result": (
            "a low share of records agreeing on one pVFTable, or a substantial "
            "number of non-zero spare fields -- either would mean the 16 bytes in "
            "front of the names are not a descriptor header"),
        "observed": {
            "name_strings": descriptors["name_string_count"],
            "structurally_valid": valid,
            "distinct_pvftable_values": descriptors["distinct_vftables"],
            "modal_pvftable_share": share,
            "nonzero_spare": descriptors["nonzero_spare_count"],
        },
        "refuted_the_conclusion": bool(
            total and (share is None or share < 0.95)),
    })

    # Probe 2: does the strict, self-identifying predicate undercount?
    strict = set(locators["strict_rvas"])
    loose = set(locators["loose_validated_rvas"])
    only_loose = sorted(loose - strict)
    probes.append({
        "id": "P2-locator-predicate-disagreement",
        "question": (
            "Does the strict pSelf predicate miss complete object locators that a "
            "predicate not using pSelf would find?"),
        "refuting_result": (
            "a non-empty set of positions that satisfy the validated loose "
            "predicate but not the strict one -- the headline locator count would "
            "then be a floor and the scan would be undercounting"),
        "observed": {
            "strict": len(strict),
            "loose_candidates": len(locators["loose_candidate_rvas"]),
            "loose_validated": len(loose),
            "loose_only": len(only_loose),
            "loose_only_rvas": ["0x%x" % rva for rva in only_loose[:32]],
            "strict_only": len(strict - loose),
        },
        "refuted_the_conclusion": bool(only_loose),
    })

    # Probe 3: is the RTTI actually attached to anything callable?
    without_vtable = [c for c in classes if c["vtable"] is None
                      or c["vtable"]["code_slot_count"] < 1]
    probes.append({
        "id": "P3-vtable-reachability",
        "question": (
            "Are the locators attached to real vtables, or are they orphaned "
            "records that identify nothing?"),
        "refuting_result": (
            "locators with no referencing pointer, or with a following slot run "
            "that contains no address in an executable section -- such a locator "
            "buys nothing for reverse engineering"),
        "observed": {
            "locators_resolved": len(classes),
            "with_reachable_vtable": len(classes) - len(without_vtable),
            "without_reachable_vtable": len(without_vtable),
            "examples_without": ["0x%x" % c["locator"]["rva"]
                                 for c in without_vtable[:16]],
        },
        "refuted_the_conclusion": bool(classes) and len(without_vtable) > 0,
    })

    # Probe 4: does the answer survive at the level the milestone cares about?
    # A positive RTTI finding that covers only the CRT is a negative answer to
    # the question S-10 is actually asking, and the probe says so numerically.
    buckets = summary["by_bucket"]
    engine_and_game = (buckets.get(BUCKET_UNREAL, 0) + buckets.get(BUCKET_GAME, 0))
    probes.append({
        "id": "P4-coverage-is-not-of-the-target",
        "question": (
            "Even if RTTI is present, does it cover the classes this project needs "
            "-- engine and game types -- or only libraries?"),
        "refuting_result": (
            "an engine+game share close to zero, which makes a structurally "
            "positive finding useless for the purpose S-10 exists to serve"),
        "observed": {
            "by_bucket": buckets,
            "engine_plus_game": engine_and_game,
            "engine_plus_game_share": (engine_and_game / len(classes)) if classes else None,
        },
        "refuted_the_conclusion": bool(classes) and engine_and_game == 0,
    })
    return probes


# --------------------------------------------------------------------------- #
# top-level analysis
# --------------------------------------------------------------------------- #

def _verdict(descriptors: dict, classes: list[dict], warnings: list[str],
             scan_complete: bool) -> tuple[str, str]:
    """FOUND / NOT FOUND WITHIN TESTED SURFACE / UNKNOWN, and why.

    Never a bare "RTTI is absent": the negative verdict names the surface it is
    negative over, because that is the only honest form of a null result from a
    scanner.
    """
    usable = [c for c in classes
              if c["vtable"] is not None and c["vtable"]["code_slot_count"] >= 1]
    if not scan_complete:
        return ("UNKNOWN",
                "the scan did not complete over the whole intended surface; the "
                "counts below cover only what was read")
    if usable:
        return ("FOUND",
                "%d complete object locators resolve to a type descriptor, a class "
                "hierarchy descriptor and a vtable whose first slots address "
                "executable sections" % len(usable))
    if classes:
        return ("UNKNOWN",
                "%d complete object locators were found but none of them sits in "
                "front of a vtable that addresses executable code; the structures "
                "exist but nothing was shown to use them" % len(classes))
    if descriptors["name_string_count"]:
        return ("UNKNOWN",
                "%d decorated name strings were found but no complete object "
                "locator resolved against them; names without locators do not "
                "identify objects"
                % descriptors["name_string_count"])
    return ("NOT FOUND WITHIN TESTED SURFACE",
            "no decorated type-descriptor name and no complete object locator "
            "occurs in the sections listed under tested_surface")


def analyze(path: str, *, literal_samples: int = DEFAULT_LITERAL_SAMPLES,
            name_sections: tuple[str, ...] | None = None,
            locator_sections: tuple[str, ...] | None = None,
            ue_source_root: str | None = None,
            want_vtable_census: bool = False,
            want_file_digest: bool = True) -> dict:
    """Scan *path* and return the whole document. Read-only, bounded, streaming."""
    warnings: list[str] = []
    timings: dict[str, float] = {}
    started_total = time.monotonic()

    with pe_info.Image.open(path) as image:
        headers = pe_info.PEHeaders(image)
        warnings.extend(headers.warnings)
        section_map = SectionMap(headers)

        # The surface. Default: every section that carries initialised data and
        # is not code, relocations or resources. Names live in .data (the
        # descriptor's pVFTable needs a relocation, so the record cannot be in a
        # read-only section); locators and vtables live in .rdata. Both defaults
        # are wider than that, deliberately: a build that puts them elsewhere
        # must not read as "absent".
        skip = (".text", ".pdata", ".reloc", ".rsrc")
        name_surface = select_scan_sections(section_map, name_sections, skip)
        locator_surface = select_scan_sections(section_map, locator_sections, skip)

        started = time.monotonic()
        descriptors = scan_type_descriptors(image, headers, section_map,
                                            name_surface, warnings)
        timings["type_descriptor_scan"] = round(time.monotonic() - started, 3)

        descriptor_rvas = frozenset(record["type_descriptor_rva"]
                                    for record in descriptors["structurally_valid"])
        descriptor_by_rva = {record["type_descriptor_rva"]: record
                             for record in descriptors["structurally_valid"]}

        started = time.monotonic()
        locators = scan_complete_object_locators(image, headers, section_map,
                                                 locator_surface, descriptor_rvas,
                                                 warnings)
        timings["locator_scan"] = round(time.monotonic() - started, 3)

        is_pe32_plus = locators["pe32_plus"]
        started = time.monotonic()
        locators["loose_validated_rvas"] = validate_locator_candidates(
            headers, locators["loose_candidate_rvas"], descriptor_rvas,
            is_pe32_plus)
        timings["loose_candidate_validation"] = round(time.monotonic() - started, 3)
        # On PE32+ the strict, self-identifying predicate is the headline set. On
        # PE32 there is no pSelf field at all, so the validated loose set is the
        # only one available -- and the document says which was used.
        primary_rvas = (locators["strict_rvas"] if is_pe32_plus
                        else locators["loose_validated_rvas"])

        started = time.monotonic()
        vtable_scan = scan_vtable_references(image, headers, section_map,
                                             locator_surface,
                                             frozenset(primary_rvas), warnings)
        timings["vtable_reference_scan"] = round(time.monotonic() - started, 3)

        # ---- assemble one record per locator ------------------------------- #
        started = time.monotonic()
        classes: list[dict] = []
        demangle_failures: list[dict] = []
        for rva in primary_rvas:
            try:
                locator = read_locator(headers, rva, is_pe32_plus)
            except PEFormatError as error:
                warnings.append("locator at RVA 0x%x unreadable: %s" % (rva, error))
                continue
            descriptor = descriptor_by_rva.get(locator["type_descriptor_rva"])
            hierarchy = read_hierarchy(headers, locator["class_descriptor_rva"],
                                       locator["type_descriptor_rva"],
                                       descriptor_rvas)
            mangled = descriptor["mangled"] if descriptor else None
            kind = None
            decoded = None
            decode_error = None
            if mangled is not None:
                try:
                    kind, decoded = demangle_type_descriptor(mangled)
                except DemangleError as error:
                    decode_error = error.message
                    demangle_failures.append({"mangled": mangled,
                                              "reason": error.message,
                                              "position": error.position})
            attribution = (classify_name(kind, decoded) if decoded
                           else {"bucket": BUCKET_UNATTRIBUTED, "owner": None,
                                 "rule": "the decorated name could not be decoded",
                                 "root": None})
            slots = vtable_scan["references"].get(rva, [])
            vtable = measure_vtable(headers, section_map, slots[0]) if slots else None
            classes.append({
                "locator": locator,
                "type_descriptor": descriptor,
                "hierarchy": hierarchy,
                "mangled": mangled,
                "kind": kind,
                "decoded_name": decoded,
                "decode_error": decode_error,
                "attribution": attribution,
                "vtable_slot_rvas": slots,
                "vtable": vtable,
            })
        timings["record_assembly"] = round(time.monotonic() - started, 3)

        # ---- every descriptor, decoded, whether or not it has a locator ---- #
        located = {c["type_descriptor"]["type_descriptor_rva"]
                   for c in classes if c["type_descriptor"]}
        type_descriptor_records: list[dict] = []
        for record in descriptors["structurally_valid"]:
            kind = None
            decoded = None
            decode_error = None
            try:
                kind, decoded = demangle_type_descriptor(record["mangled"])
            except DemangleError as error:
                decode_error = error.message
                if not any(f["mangled"] == record["mangled"]
                           for f in demangle_failures):
                    demangle_failures.append({"mangled": record["mangled"],
                                              "reason": error.message,
                                              "position": error.position})
            attribution = (classify_name(kind, decoded) if decoded
                           else {"bucket": BUCKET_UNATTRIBUTED, "owner": None,
                                 "rule": "the decorated name could not be decoded",
                                 "root": None})
            type_descriptor_records.append({
                "type_descriptor_rva": record["type_descriptor_rva"],
                "type_descriptor_file_offset": record["type_descriptor_file_offset"],
                "name_file_offset": record["name_file_offset"],
                "name_length": record["name_length"],
                "section": record["section"],
                "mangled": record["mangled"],
                "kind": kind,
                "decoded_name": decoded,
                "decode_error": decode_error,
                "attribution": attribution,
                "has_complete_object_locator":
                    record["type_descriptor_rva"] in located,
            })

        # ---- optional denominator for the coverage ratio -------------------- #
        census = None
        if want_vtable_census:
            started = time.monotonic()
            census = vtable_census(image, headers, section_map, locator_surface)
            timings["vtable_census"] = round(time.monotonic() - started, 3)

        # ---- optional second method for the attribution -------------------- #
        source_check = None
        if ue_source_root:
            wanted = sorted({
                bare_identifier(item["decoded_name"])
                for item in type_descriptor_records
                if item["decoded_name"]
                and item["attribution"]["bucket"] in (BUCKET_UNREAL,
                                                      BUCKET_UNATTRIBUTED)
            })
            source_check = corroborate_against_source(ue_source_root, wanted,
                                                      warnings)
            declared = source_check["found"]
            for item in type_descriptor_records + classes:
                decoded = item.get("decoded_name")
                if not decoded:
                    continue
                token = bare_identifier(decoded)
                if token not in (source_check.get("identifiers_requested") or ()):
                    continue
                attribution = item["attribution"]
                if token in declared:
                    attribution["ue_source_declaration"] = declared[token]
                    if attribution["bucket"] == BUCKET_UNATTRIBUTED:
                        attribution["bucket"] = BUCKET_UNREAL
                        attribution["owner"] = "Unreal Engine"
                        attribution["rule"] = (
                            "declared in the Unreal Engine source tree given by "
                            "--ue-source-root")
                else:
                    attribution["ue_source_declaration"] = None
                    if attribution["bucket"] == BUCKET_UNREAL:
                        attribution["bucket"] = BUCKET_GAME
                        attribution["rule"] = (
                            "matches the Unreal naming convention but is NOT declared "
                            "anywhere in the Unreal Engine source tree given by "
                            "--ue-source-root")
                        attribution["owner"] = None

        # ---- summary -------------------------------------------------------- #
        by_bucket = Counter(c["attribution"]["bucket"] for c in classes)
        by_bucket_descriptors = Counter(item["attribution"]["bucket"]
                                        for item in type_descriptor_records)
        by_owner = Counter(c["attribution"]["owner"] or "(none)" for c in classes)
        with_vtable = [c for c in classes
                       if c["vtable"] and c["vtable"]["code_slot_count"] >= 1]
        coherent = [c for c in classes
                    if c["type_descriptor"] is not None
                    and c["hierarchy"]["readable"]
                    and c["hierarchy"]["problem"] is None
                    and c["hierarchy"]["first_base_is_self"] is True]
        slot_counts = [c["vtable"]["code_slot_count"] for c in with_vtable]

        summary = {
            "verdict": None,
            "verdict_reason": None,
            "name_strings_found": descriptors["name_string_count"],
            "type_descriptors_structurally_valid": len(descriptors["structurally_valid"]),
            "type_descriptors_decoded": sum(
                1 for item in type_descriptor_records if item["decoded_name"]),
            "type_descriptors_undecoded": sum(
                1 for item in type_descriptor_records if not item["decoded_name"]),
            "complete_object_locators_strict": len(locators["strict_rvas"]),
            "complete_object_locators_loose_candidates":
                len(locators["loose_candidate_rvas"]),
            "complete_object_locators_loose_validated":
                len(locators["loose_validated_rvas"]),
            "complete_object_locators_used": len(primary_rvas),
            "locators_resolving_to_a_type_descriptor": sum(
                1 for c in classes if c["type_descriptor"] is not None),
            "locators_with_coherent_hierarchy": len(coherent),
            "locators_with_reachable_vtable": len(with_vtable),
            "vtable_code_slots_total": sum(slot_counts),
            "vtable_code_slots_min": min(slot_counts) if slot_counts else None,
            "vtable_code_slots_max": max(slot_counts) if slot_counts else None,
            "distinct_base_type_descriptors": len({
                rva for c in classes
                for rva in c["hierarchy"]["base_type_descriptor_rvas"]}),
            "by_bucket": {bucket: by_bucket.get(bucket, 0) for bucket in BUCKET_ORDER},
            "by_bucket_type_descriptors": {
                bucket: by_bucket_descriptors.get(bucket, 0) for bucket in BUCKET_ORDER},
            "by_owner": dict(sorted(by_owner.items())),
        }
        scan_complete = not (descriptors["truncated"] or locators["truncated"])
        verdict, reason = _verdict(descriptors, classes, warnings, scan_complete)
        summary["verdict"] = verdict
        summary["verdict_reason"] = reason

        probes = build_refutation_probes(descriptors, locators, classes, summary)

        # ---- class-P literal layer ------------------------------------------ #
        literals: list[dict] = []
        target = os.path.basename(path)
        sample_descriptors = _spread(descriptors["structurally_valid"],
                                     literal_samples)
        for record in sample_descriptors:
            literals.append(literal_read(
                target, "TypeDescriptor.pVFTable+spare",
                record["type_descriptor_file_offset"],
                bytes.fromhex(record["header_hex"]),
                note="the 16 bytes immediately preceding a NUL-terminated "
                     "byte string that begins '.?A'"))
            name_bytes = image.read_at(record["name_file_offset"],
                                       record["name_length"], "descriptor name")
            literals.append(literal_read(
                target, "TypeDescriptor.name",
                record["name_file_offset"], name_bytes,
                note="a NUL-terminated byte string; the NUL is not included in "
                     "the length"))
        for record in _spread(classes, literal_samples):
            offset = headers.rva_to_offset(record["locator"]["rva"])
            if offset is None:
                continue
            literals.append(literal_read(
                target, "RTTICompleteObjectLocator",
                offset, bytes.fromhex(record["locator"]["raw_hex"]),
                note="a %d-byte, 4-byte-aligned range in a section carrying "
                     "initialised data" % locators["record_size"]))
        confirm_literal_reads(path, literals, target, warnings)

        file_sha256 = None
        if want_file_digest:
            digest = hashlib.sha256()
            for _position, chunk in image.iter_chunks(0, image.size):
                digest.update(chunk)
            file_sha256 = digest.hexdigest()

        timings["total"] = round(time.monotonic() - started_total, 3)

        annotation = decoded_annotation(
            target,
            corroborated=bool(with_vtable) and bool(coherent),
            corroboration_note=(
                "the locator set was reached twice by two structures that do not "
                "share a pointer -- once from the type descriptor table (a "
                "pTypeDescriptor field landing exactly on a descriptor found by a "
                "byte-pattern scan) and once from the vtable side (a pointer-sized "
                "slot holding image_base + locator_rva, followed by slots addressing "
                "executable sections); %d of %d locators also have a class hierarchy "
                "descriptor whose first base class descriptor names the class itself"
                % (len(coherent), len(classes))
                if (with_vtable and coherent) else
                "no second method corroborated the reading"),
        )

        document = {
            "file": {
                "path": os.path.abspath(path),
                "name": target,
                "size": image.size,
                "sha256": file_sha256,
                "pe_format": headers.pe_format,
                "machine": headers.machine,
                "image_base": headers.image_base,
                "size_of_image": headers.size_of_image,
            },
            "generated_at": now_iso_utc(),
            "generator": GENERATOR_NAME,
            "generator_version": GENERATOR_VERSION,
            "task": "S-10",
            "d04_oracle_only": _is_d04_oracle(path),
            "tested_surface": {
                "type_descriptor_name_sections": describe_sections(name_surface),
                "locator_and_vtable_sections": describe_sections(locator_surface),
                "sections_not_searched": sorted(
                    s["name"] for s in section_map.sections
                    if s not in name_surface and s not in locator_surface),
                "name_pattern": TD_NAME_RE.pattern.decode("latin-1"),
                "locator_alignment": locators["alignment"],
                "vtable_pointer_alignment": vtable_scan["alignment"],
                "locator_bytes_scanned": locators["scanned_bytes"],
                "vtable_bytes_scanned": vtable_scan["scanned_bytes"],
                "not_tested": [
                    "packed, encrypted or runtime-generated code is out of scope: "
                    "only the on-disk image is read",
                    "sections whose raw size is zero hold nothing on disk and "
                    "cannot be searched",
                    "the virtual tail of a section (vsize beyond rsize) is "
                    "zero-filled by the loader and is not on disk",
                ],
            },
            "type_descriptor_scan": {
                "name_string_count": descriptors["name_string_count"],
                "structurally_valid_count": len(descriptors["structurally_valid"]),
                "modal_pvftable_va": descriptors["modal_vftable_va"],
                "modal_pvftable_rva": descriptors["modal_vftable_rva"],
                "modal_pvftable_share": descriptors["modal_vftable_share"],
                "distinct_pvftable_values": descriptors["distinct_vftables"],
                "nonzero_spare_count": descriptors["nonzero_spare_count"],
                "truncated": descriptors["truncated"],
            },
            "locator_scan": {
                "strict_count": len(locators["strict_rvas"]),
                "loose_candidate_count": len(locators["loose_candidate_rvas"]),
                "loose_validated_count": len(locators["loose_validated_rvas"]),
                "predicate_used": ("strict" if locators["pe32_plus"]
                                   else "loose_validated (PE32 has no pSelf field)"),
                "record_size": locators["record_size"],
                "predicate_strict": ("signature == 1 and pSelf == the record's own "
                                     "image-relative address"),
                "predicate_loose_candidate": (
                    "signature in {0, 1} and pTypeDescriptor lands on a type "
                    "descriptor found by the name scan"),
                "predicate_loose_validated": (
                    "the candidate predicate, plus pClassDescriptor reaching a "
                    "hierarchy descriptor with signature 0, a plausible "
                    "numBaseClasses, a readable base class array, and a first base "
                    "class descriptor naming the candidate's own type descriptor"),
                "truncated": locators["truncated"],
            },
            "demangler": {
                "decoded": summary["type_descriptors_decoded"],
                "failed": summary["type_descriptors_undecoded"],
                "failures": sorted(demangle_failures,
                                   key=lambda item: item["mangled"])[:64],
            },
            "attribution_rules": list(ATTRIBUTION_RULES),
            "ue_source_corroboration": source_check,
            "vtable_census": census,
            "summary": summary,
            "refutation_probes": probes,
            "type_descriptors": type_descriptor_records,
            "classes": [_public_class(c) for c in classes],
            "literal_reads": literals,
            "decoded_annotation": annotation,
            "timings_seconds": timings,
            "warnings": sorted(set(warnings)),
        }
        return document


def _is_d04_oracle(path: str) -> bool:
    """True for the second, 282 MB MISERY.exe -- decision D-04's read-only oracle.

    Stamped on the document rather than refused, because reading it is allowed
    and useful; what is not allowed is letting a conclusion reached there stand
    without re-verification on the Shipping binary.
    """
    normalised = os.path.abspath(path).replace("\\", "/").lower()
    return normalised.endswith("/binaries/win64/misery.exe")


def _spread(items: list, count: int) -> list:
    """A deterministic, evenly spaced sample -- never just the first N.

    The first N records of a descriptor table all come from the same translation
    unit, so a sample taken from the front is a sample of one compiler
    invocation. Spreading it across the table is the difference between evidence
    and an anecdote.
    """
    if count <= 0 or not items:
        return []
    if len(items) <= count:
        return list(items)
    step = (len(items) - 1) / (count - 1) if count > 1 else 1
    picked = []
    seen = set()
    for index in range(count):
        position = int(round(index * step))
        position = min(position, len(items) - 1)
        if position not in seen:
            seen.add(position)
            picked.append(items[position])
    return picked


def _public_class(record: dict) -> dict:
    """One assembled class record, with the internal join fields dropped."""
    descriptor = record["type_descriptor"]
    return {
        "locator_rva": record["locator"]["rva"],
        "locator": record["locator"],
        "type_descriptor_rva": record["locator"]["type_descriptor_rva"],
        "type_descriptor_file_offset": (descriptor["type_descriptor_file_offset"]
                                        if descriptor else None),
        "name_file_offset": descriptor["name_file_offset"] if descriptor else None,
        "mangled": record["mangled"],
        "kind": record["kind"],
        "decoded_name": record["decoded_name"],
        "decode_error": record["decode_error"],
        "attribution": record["attribution"],
        "hierarchy": record["hierarchy"],
        "vtable_slot_rvas": record["vtable_slot_rvas"],
        "vtable": record["vtable"],
    }


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def jsonl_lines(document: dict) -> list[str]:
    """The ``rtti.jsonl`` artifact of plan.md S-10: one JSON object per class.

    Deliberately flat and small: this is the file the rest of section 7 will
    join against, and it should not carry the whole evidence apparatus on every
    row. The grading lives once, in the full document.
    """
    lines = []
    for record in document["classes"]:
        lines.append(json.dumps({
            "build_target": document["file"]["name"],
            "locator_rva": record["locator_rva"],
            "type_descriptor_rva": record["type_descriptor_rva"],
            "vtable_rva": record["vtable"]["vtable_rva"] if record["vtable"] else None,
            "vtable_code_slots": (record["vtable"]["code_slot_count"]
                                  if record["vtable"] else 0),
            "mangled": record["mangled"],
            "kind": record["kind"],
            "decoded_name": record["decoded_name"],
            "bucket": record["attribution"]["bucket"],
            "owner": record["attribution"]["owner"],
            "base_class_count": record["hierarchy"]["base_class_count"],
            "offset": record["locator"]["offset"],
            "cd_offset": record["locator"]["cd_offset"],
        }, sort_keys=True, ensure_ascii=False))
    return lines


def format_summary(document: dict, name_limit: int = 25) -> str:
    out: list[str] = []
    add = out.append
    summary = document["summary"]
    file_info = document["file"]

    add("%s (%s %s)" % (file_info["path"], GENERATOR_NAME, GENERATOR_VERSION))
    add("  %s, image base 0x%x, %d bytes on disk"
        % (file_info["pe_format"], file_info["image_base"], file_info["size"]))
    if document["d04_oracle_only"]:
        add("  D-04: this file is the read-only ORACLE. Any conclusion drawn here "
            "must be re-verified on MISERY-Win64-Shipping.exe before it counts.")
    add("")
    add("VERDICT: %s" % summary["verdict"])
    add("  %s" % summary["verdict_reason"])
    add("")
    add("Tested surface")
    for section in document["tested_surface"]["type_descriptor_name_sections"]:
        add("  names    %-10s file [%d, %d)  %d bytes"
            % (section["name"], section["file_offset"],
               section["file_offset"] + section["raw_size"], section["raw_size"]))
    for section in document["tested_surface"]["locator_and_vtable_sections"]:
        add("  locators %-10s file [%d, %d)  %d bytes"
            % (section["name"], section["file_offset"],
               section["file_offset"] + section["raw_size"], section["raw_size"]))
    add("  not searched: %s"
        % (", ".join(document["tested_surface"]["sections_not_searched"]) or "none"))
    add("")
    add("Structures")
    scan = document["type_descriptor_scan"]
    add("  name strings '.?A...@@'          : %d" % scan["name_string_count"])
    add("  structurally valid TypeDescriptor: %d" % scan["structurally_valid_count"])
    add("  distinct pVFTable values         : %d (modal share %s)"
        % (scan["distinct_pvftable_values"],
           "-" if scan["modal_pvftable_share"] is None
           else "%.4f" % scan["modal_pvftable_share"]))
    add("  modal pVFTable                   : %s"
        % ("none" if scan["modal_pvftable_va"] is None
           else "0x%x (RVA 0x%x)" % (scan["modal_pvftable_va"],
                                     scan["modal_pvftable_rva"])))
    add("  non-zero spare fields            : %d" % scan["nonzero_spare_count"])
    locator = document["locator_scan"]
    add("  COL, strict predicate            : %d" % locator["strict_count"])
    add("  COL, loose candidates            : %d" % locator["loose_candidate_count"])
    add("  COL, loose validated             : %d" % locator["loose_validated_count"])
    add("  COL resolving to a TypeDescriptor: %d"
        % summary["locators_resolving_to_a_type_descriptor"])
    add("  COL with a coherent hierarchy    : %d"
        % summary["locators_with_coherent_hierarchy"])
    add("  COL with a reachable vtable      : %d"
        % summary["locators_with_reachable_vtable"])
    add("  vtable code slots, min/max/total : %s / %s / %d"
        % (summary["vtable_code_slots_min"], summary["vtable_code_slots_max"],
           summary["vtable_code_slots_total"]))
    add("  distinct base TypeDescriptors    : %d"
        % summary["distinct_base_type_descriptors"])
    add("")
    add("Name decoding")
    add("  decoded %d, failed %d" % (document["demangler"]["decoded"],
                                     document["demangler"]["failed"]))
    for failure in document["demangler"]["failures"][:10]:
        add("    FAILED %s" % failure["reason"])
        add("           %s" % failure["mangled"][:160])
    add("")
    add("Ownership (locators with RTTI, by attribution bucket)")
    for bucket in BUCKET_ORDER:
        add("  %-26s %d" % (bucket, summary["by_bucket"][bucket]))
    add("  same split over all type descriptors:")
    for bucket in BUCKET_ORDER:
        add("    %-24s %d" % (bucket, summary["by_bucket_type_descriptors"][bucket]))
    add("")
    add("Owners")
    for owner, count in sorted(summary["by_owner"].items(),
                               key=lambda item: (-item[1], item[0])):
        add("  %-6d %s" % (count, owner))
    add("")
    interesting = [c for c in document["classes"]
                   if c["attribution"]["bucket"] in (BUCKET_UNREAL, BUCKET_GAME,
                                                     BUCKET_UNATTRIBUTED)]
    add("Engine / game / unattributed classes (%d)" % len(interesting))
    for record in interesting[:name_limit]:
        add("  %-26s %-8s %s"
            % (record["attribution"]["bucket"], record["kind"] or "-",
               record["decoded_name"] or record["mangled"]))
        add("      COL 0x%x  vtable %s  slots %s  bases %s"
            % (record["locator_rva"],
               "0x%x" % record["vtable"]["vtable_rva"] if record["vtable"] else "none",
               record["vtable"]["code_slot_count"] if record["vtable"] else 0,
               record["hierarchy"]["base_class_count"]))
    if len(interesting) > name_limit:
        add("  ... %d more" % (len(interesting) - name_limit))
    add("")
    add("Refutation probes")
    for probe in document["refutation_probes"]:
        add("  %-36s %s" % (probe["id"],
                            "REFUTED THE CONCLUSION" if probe["refuted_the_conclusion"]
                            else "did not refute"))
        add("      %s" % probe["question"])
        add("      observed: %s" % json.dumps(probe["observed"], sort_keys=True))
    census = document["vtable_census"]
    if census is not None:
        add("")
        add("Vtable census (APPROXIMATION -- S-09 owns the real inventory)")
        add("  pointer slots addressing executable sections: %d"
            % census["pointer_slots_addressing_executable_sections"])
        for threshold, count in sorted(census["runs_by_minimum_length"].items(),
                                       key=lambda item: int(item[0])):
            covered = document["summary"]["locators_with_reachable_vtable"]
            add("  runs of >= %-3s consecutive code slots  : %-8d "
                "RTTI covers %s"
                % (threshold, count,
                   "-" if not count else "%.4f" % (covered / count)))
    source = document["ue_source_corroboration"]
    if source is not None:
        add("")
        add("Unreal source corroboration (%s)" % source["root"])
        if not source["available"]:
            add("  the tree was not available; the pass did not run")
        else:
            add("  %d files, %d bytes, %s s; %d of %d identifiers declared there"
                % (source["files_scanned"], source["bytes_scanned"],
                   source["elapsed_seconds"], len(source["found"]),
                   len(source.get("identifiers_requested") or ())))
    add("")
    add("Literal reads (class P): %d ranges, all re-read through a second handle: %s"
        % (len(document["literal_reads"]),
           "reproduced" if all(r.get("reproduced") for r in document["literal_reads"])
           else "AT LEAST ONE DID NOT REPRODUCE"))
    add("Timings (s): %s" % json.dumps(document["timings_seconds"], sort_keys=True))
    if document["warnings"]:
        add("")
        add("Warnings")
        for line in document["warnings"]:
            add("  %s" % line)
    return "\n".join(out)


def write_text(text: str, out_path: str, install_root: str, what: str) -> str:
    """Write *text* to *out_path*, refusing any path inside an installation.

    The guard runs before the file is opened, so a refused path leaves nothing
    behind -- not even a truncated file.
    """
    target = pathguard.check_output_path(out_path, install_root, what=what)
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return target


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rtti_scan.py",
        description=(
            "Read-only MSVC RTTI scanner (plan.md task S-10). Prints a human "
            "summary by default; --json prints the machine-readable document. "
            "Refuses any output path that resolves inside a game installation "
            "(D-01)."),
    )
    parser.add_argument("path", help="the PE image to read (opened read-only)")
    parser.add_argument("--json", action="store_true",
                        help="print the JSON document instead of the summary")
    parser.add_argument("--jsonl", action="store_true",
                        help="print the per-class JSONL artifact to stdout")
    parser.add_argument("--out", default=None,
                        help=("write the JSON document here; refused (exit 2) if it "
                              "resolves inside a game installation, before anything "
                              "is opened"))
    parser.add_argument("--jsonl-out", default=None,
                        help="write the per-class rtti.jsonl artifact here")
    parser.add_argument("--install-dir", default=None,
                        help=("installation root the output guard checks against "
                              "(default: auto-detected from the input path)"))
    parser.add_argument("--name-sections", default=None, metavar="A,B",
                        help=("comma-separated section names to search for "
                              "decorated names (default: every section with raw "
                              "data except .text/.pdata/.reloc/.rsrc)"))
    parser.add_argument("--locator-sections", default=None, metavar="A,B",
                        help="same, for the locator and vtable passes")
    parser.add_argument("--ue-source-root", default=None, metavar="DIR",
                        help=("an Unreal Engine source tree; enables the second, "
                              "independent attribution method and the only positive "
                              "test for 'game-specific'"))
    parser.add_argument("--literal-samples", type=int,
                        default=DEFAULT_LITERAL_SAMPLES, metavar="N",
                        help=("how many evenly spaced structures to record as "
                              "class-P literal reads (default: %d)"
                              % DEFAULT_LITERAL_SAMPLES))
    parser.add_argument("--names", type=int, default=25, metavar="N",
                        help="how many engine/game/unattributed names to print")
    parser.add_argument("--vtable-census", action="store_true",
                        help=("also count vtable-shaped pointer runs, to give the "
                              "coverage ratio a denominator; an APPROXIMATION, and "
                              "plan.md S-09 owns the real inventory"))
    parser.add_argument("--no-digest", action="store_true",
                        help="skip the whole-file sha256")
    return parser


def _split_sections(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    return tuple(part.strip() for part in value.split(",") if part.strip())


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not os.path.isfile(args.path):
        print("error: not a file: %s" % args.path, file=sys.stderr)
        return 2
    if args.literal_samples < 0:
        print("error: --literal-samples must not be negative", file=sys.stderr)
        return 2

    install_root = args.install_dir or pe_info.detect_install_root(args.path)

    # Layer 1 (plan.md 1.5 / D-01) is checked before any parsing, so a refused
    # path costs nothing and leaves nothing behind. write_text checks again.
    checked: dict[str, str] = {}
    for flag, value in (("--out", args.out), ("--jsonl-out", args.jsonl_out)):
        if not value:
            continue
        try:
            checked[flag] = pathguard.check_output_path(value, install_root,
                                                        what=flag)
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2

    try:
        document = analyze(
            args.path,
            literal_samples=args.literal_samples,
            name_sections=_split_sections(args.name_sections),
            locator_sections=_split_sections(args.locator_sections),
            ue_source_root=args.ue_source_root,
            want_vtable_census=args.vtable_census,
            want_file_digest=not args.no_digest,
        )
    except PEFormatError as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2
    except OSError as error:
        print("error: %s: %s" % (args.path, error), file=sys.stderr)
        return 2

    written: list[str] = []
    try:
        if "--out" in checked:
            written.append(write_text(dump_json(document), checked["--out"],
                                      install_root, "--out"))
        if "--jsonl-out" in checked:
            body = "".join(line + "\n" for line in jsonl_lines(document))
            written.append(write_text(body, checked["--jsonl-out"], install_root,
                                      "--jsonl-out"))
    except pathguard.OutputPathRefused as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except OSError as error:
        print("error: cannot write: %s" % error, file=sys.stderr)
        return 2

    if args.json:
        sys.stdout.write(dump_json(document))
    elif args.jsonl:
        for line in jsonl_lines(document):
            sys.stdout.write(line + "\n")
    else:
        print(format_summary(document, name_limit=args.names))
        for path in written:
            print("\nwritten: %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
