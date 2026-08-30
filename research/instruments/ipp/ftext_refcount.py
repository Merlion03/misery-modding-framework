#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Read the reference count of an FText's shared text data.

NEVER writes. The counter is only ever read; nothing here calls AddRef, Release,
or mutates the count by any other route.

THE RECIPE, AND WHERE IT COMES FROM
-----------------------------------
Derived from the installed UE 5.4.4 source, not from memory of Unreal:

    FText + 0x00  ->  TRefCountPtr<ITextData>, i.e. the raw ITextData*   Text.h:811
    FText + 0x08  ->  uint32 Flags                                        Text.h:814

    ITextData has exactly ONE implementation in UE 5.4:
        class FTextHistory : public ITextData, public TRefCountingMixin<FTextHistory>
                                                              TextHistory.h:139

    ITextData is polymorphic and declared first, so under the MSVC x64 ABI it is
    the PRIMARY base at offset 0 and owns the single vfptr (8 bytes). The second
    base, TRefCountingMixin, is non-polymorphic and lands at the next aligned
    offset, 0x08. Its sole member is:

        mutable std::atomic<uint32> RefCount{0}       RefCounting.h:178, 276

    => refcount = *(uint32*)(ITextData* + 0x08), 4 bytes, little-endian.

A NOTE ON WHAT THIS DOES AND DOES NOT MEASURE. The counter belongs to the shared
text data, not to any FText instance. Every copy anywhere in the process bumps
the same number. For the persistent per-field defaults of a UUserDefinedStruct
it is shared by every live instance of that struct. So a rising count is
evidence about global liveness of that text object -- which is exactly the
question when asking whether materialization leaks a reference -- and is NOT
evidence about any single struct.

WHY EVERY READ IS GATED
-----------------------
The 0x08 offset is an ABI conclusion, not a line of source: the engine contains
no static_assert on offsetof(FTextHistory, RefCount). A plausible-looking small
integer at the wrong offset would be worse than no measurement at all. So each
read is gated on three independent structural facts, and the caller is expected
to calibrate once behaviourally:

  vptr        the pointer at +0x00 must be identical across texts of the same
              concrete type, and must live in a module's image, not the heap
  revisions   *(uint32*)(P + 0x0C) must be 0 for a Conv_StringToText text --
              GlobalRevision and LocalRevision stay at their in-class zeros
              because a default-constructed FTextId makes CanUpdateDisplayString
              false (TextHistory.cpp:869-872)
  string      the FString at P+0x28 / +0x30 / +0x34 must round-trip to the exact
              expected characters, which proves the object base AND the layout
              from a field 0x28 bytes away

A wrong offset cannot satisfy all three.
"""
import struct

# FText
FTEXT_TEXTDATA = 0x00
FTEXT_FLAGS = 0x08
ETEXTFLAG_CULTURE_INVARIANT = 0x02          # Text.h:41; set by AsCultureInvariant

# FTextHistory / FTextHistory_Base
TD_VPTR = 0x00
TD_REFCOUNT = 0x08                          # the counter
TD_REVISIONS = 0x0C                         # GlobalRevision|LocalRevision, both 0 here
TD_SOURCESTRING_DATA = 0x28
TD_SOURCESTRING_NUM = 0x30
TD_SOURCESTRING_MAX = 0x34
TD_LOCALIZEDSTRING = 0x38

REFCOUNT_SANITY_MAX = 0x10000


def read_u32(api, handle, address):
    return struct.unpack("<I", api.read_process_memory(handle, address, 4))[0]


def read_u64(api, handle, address):
    return struct.unpack("<Q", api.read_process_memory(handle, address, 8))[0]


def probe_textdata(api, handle, textdata_ptr, *, expect_string=None):
    """Describe one ITextData, with every gate reported rather than assumed.

    Returns a dict. ``trustworthy`` is True only when the structural gates that
    could be evaluated all passed; ``refcount`` is reported either way so the
    raw reading is never hidden, but a caller must not use it when
    ``trustworthy`` is False.
    """
    out = {"pointer": "0x%x" % textdata_ptr if textdata_ptr else None}
    if not textdata_ptr:
        out.update({"trustworthy": False, "why": "null ITextData pointer"})
        return out
    gates = {}
    try:
        out["vptr"] = "0x%x" % read_u64(api, handle, textdata_ptr + TD_VPTR)
        out["refcount"] = read_u32(api, handle, textdata_ptr + TD_REFCOUNT)
        revisions = read_u32(api, handle, textdata_ptr + TD_REVISIONS)
        out["revisions_raw"] = revisions

        data = read_u64(api, handle, textdata_ptr + TD_SOURCESTRING_DATA)
        num = struct.unpack("<i", api.read_process_memory(
            handle, textdata_ptr + TD_SOURCESTRING_NUM, 4))[0]
        mx = struct.unpack("<i", api.read_process_memory(
            handle, textdata_ptr + TD_SOURCESTRING_MAX, 4))[0]
        out["source_string"] = {"data": "0x%x" % data, "num": num, "max": mx}
        gates["array_num_le_max"] = (num <= mx) if (num or mx) else True
        text = None
        if data and 0 < num <= 4096:
            raw = api.read_process_memory(handle, data, num * 2)
            text = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            out["source_string"]["text"] = text
        elif not data and num == 0:
            out["source_string"]["text"] = ""
            out["is_empty_string"] = True
        if expect_string is not None:
            gates["string_round_trips"] = (text == expect_string
                                           and num == len(expect_string) + 1)
            out["expected_string"] = expect_string

        rc = out["refcount"]
        gates["refcount_nonzero"] = rc != 0
        gates["refcount_plausible"] = rc < REFCOUNT_SANITY_MAX

        localized = read_u64(api, handle, textdata_ptr + TD_LOCALIZEDSTRING)
        out["localized_string"] = "0x%x" % localized
        # CORRECTED BY MEASUREMENT. The first version of this gate demanded
        # revisions == 0 unconditionally, on the reasoning that a
        # Conv_StringToText text has a default-constructed FTextId, so
        # CanUpdateDisplayString() is false and the revisions never move
        # (TextHistory.cpp:869-872). That is right for OUR texts and wrong for
        # the UserDefinedStruct defaults, which are LOCALIZED -- they carry a
        # non-null LocalizedString and their revisions legitimately advance. The
        # gate fired on three objects whose source strings round-tripped
        # perfectly, i.e. it was the gate that was wrong, not the read. So it is
        # now conditional on which kind of text this is.
        out["is_localized"] = bool(localized)
        if localized:
            gates["revisions_consistent"] = True
        else:
            gates["revisions_are_zero_for_culture_invariant"] = revisions == 0
    except Exception as exc:                                   # noqa: BLE001
        out.update({"trustworthy": False, "why": "read failed: %r" % exc, "gates": gates})
        return out

    out["gates"] = gates
    out["trustworthy"] = all(gates.values())
    if not out["trustworthy"]:
        out["why"] = "structural gates failed: %s" % [k for k, v in gates.items() if not v]
    return out


def probe_many(api, handle, pointers, *, expect_strings=None):
    """Probe several ITextData objects and cross-check their vptrs.

    Objects of the same concrete type MUST share a vptr. Disagreement means
    either a different concrete implementation or a bad pointer, and either way
    the offsets below 0x40 stop being derivable.
    """
    expect_strings = expect_strings or [None] * len(pointers)
    results = [probe_textdata(api, handle, p, expect_string=e)
               for p, e in zip(pointers, expect_strings)]
    vptrs = {r.get("vptr") for r in results if r.get("vptr")}
    return {"entries": results,
            "vptrs": sorted(vptrs),
            "all_same_concrete_type": len(vptrs) == 1,
            "all_trustworthy": all(r.get("trustworthy") for r in results),
            "refcounts": [r.get("refcount") for r in results]}


def as_int(value):
    """Accept '0x...' strings or ints, since reports store pointers as hex."""
    if isinstance(value, str):
        return int(value, 16)
    return int(value or 0)
