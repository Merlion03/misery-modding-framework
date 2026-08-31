#!/usr/bin/env python3
"""The binding profile: everything about ONE game build that cannot be resolved.

WHAT BELONGS IN HERE, AND WHY THE LINE IS WHERE IT IS
-----------------------------------------------------
Stage 5B splits what the runtime needs to know in two:

  * **build-specific measured facts** -> this profile. Addresses that exist only
    because this executable was linked this way, vtable slot indices, the
    ParmsSize a reflected function must have, the offset a struct field must sit
    at. None of these can be discovered from a running process without guessing,
    and guessing is exactly what an unsupported build must never get.
  * **per-run dynamic facts** -> ``runtime/MiseryRuntime/Internal/Resolver``.
    Object pointers, UFunction addresses, live instances. These differ every
    launch, so a profile could not carry them even in principle.

The two meet at the fail-closed check: the resolver finds something, the profile
says what it must be, and a disagreement stops the runtime instead of being
absorbed. A profile is therefore not a convenience -- it is the thing that turns
"we found an object called ItemList" into "we found the ItemList this framework
was built against".

WHY THE PROFILE IS EMITTED RATHER THAN HAND-WRITTEN
---------------------------------------------------
Every number in here already exists somewhere in this repository, attached to
the run that measured it. Re-typing them into a JSON file would create a second
copy that nothing compares, which is how the ModId rule drifted across three
stages. So the emitter READS the measured constants and records, per fact, where
it read them from; ``tests/test_bindings.py`` then asserts the emitted profile
still equals its sources. Drift becomes a failing test rather than a wrong
address in a shipping game.

WHY THIS TOOL MAY IMPORT FROM research/
---------------------------------------
It is a build-time emitter, not part of the runtime. What ships is the JSON it
produces; nothing under research/ is loaded by the game. The dependency runs in
the safe direction: the tool that writes the profile reads the record that
proved it.

CODE BYTES ARE THE ACTUAL GUARD
-------------------------------
An RVA on its own is a number that used to be right. Each code address in the
profile therefore carries the first 16 bytes found at it, read from the shipped
executable. The runtime compares those bytes against live memory before it uses
the address for anything. A Steam patch that moves a function does not produce a
subtly wrong call -- it produces a byte mismatch and a refusal.
"""
import argparse
import datetime
import hashlib
import json
import os
import struct
import sys

TOOL_VERSION = "1.0.0"
BINDINGS_VERSION = 1

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------- sources ----
def measured_sources():
    """Every build-specific constant, with the module that measured it.

    Imported rather than copied. If a research constant moves, this emitter
    moves with it and the test that compares them stays green; if somebody edits
    the emitted JSON by hand instead, that same test goes red.
    """
    import eri                                                  # noqa: E402
    import cr01c1_controller as c1                              # noqa: E402
    import fts_controller as fts                                # noqa: E402

    # Code addresses: verified byte-for-byte against live memory before use.
    code = {
        "add_ticker": (fts.RVA_ADD_TICKER, "research/instruments/ipp/fts_controller.py"),
        "get_core_ticker": (fts.RVA_GET_CORE_TICKER,
                            "research/instruments/ipp/fts_controller.py"),
        "fmemory_malloc": (fts.RVA_FMEMORY_MALLOC,
                           "research/instruments/ipp/fts_controller.py"),
        # Measured in CR-01C5's resolve(): base + these, all eight byte-verified
        # live == disk before the probe would run.
        "fmemory_free": (0xFA0090, "research/evidence/CR-01C5 resolve()"),
        "set_root_flags": (0x1210E60, "research/evidence/CR-01C5 resolve()"),
        "clear_root_flags": (0x11BB340, "research/evidence/CR-01C5 resolve()"),
    }
    # Data addresses: there are no stable bytes at a live global, so these are
    # checked structurally by the resolver instead (a chunk count that is not
    # plausible, or a name block that will not decode, fails the same way).
    data = {
        "guobjectarray": (eri.DEFAULT_GUOBJECTARRAY_RVA,
                          "research/instruments/eri/eri.py"),
        "namepool": (eri.DEFAULT_NAMEPOOL_RVA, "research/instruments/eri/eri.py"),
        "name_pool_initialized": (eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,
                                  "research/instruments/eri/eri.py"),
    }
    slots = {
        # Proven by agreement across three unrelated CDOs rather than by one
        # lucky read -- see CR-01C1.
        "process_event": (c1.PE_SLOT, "research/instruments/ipp/cr01c1_controller.py"),
        "datatable_add_row": (95, "research/evidence/CR-01C4B"),
        "datatable_remove_row": (94, "research/evidence/CR-01C4B"),
        "scriptstruct_initialize": (96, "research/evidence/CR-01C4B"),
        "scriptstruct_destroy": (97, "research/evidence/CR-01C4B"),
    }
    return code, data, slots


# Reflected functions, and what each must look like before it may be called.
# Copied from the gate() calls CR-01C5 makes: the same numbers, in the file that
# now owns them for production, and compared against that controller by a test.
#
# FORBID is the net/authority mask. A function carrying any of those bits is one
# the engine may replicate, and calling it locally would be a gameplay decision
# made by accident.
FUNCTION_FORBID_FLAGS = 0x0138C0C4
FUNCTION_GATES = {
    "GameplayStatics::SpawnObject":
        {"parms_size": 24, "return_value_offset": None, "require_flags": 0x2400},
    "KismetTextLibrary::Conv_StringToText":
        {"parms_size": 32, "return_value_offset": 16, "require_flags": 0x2400},
    "KismetTextLibrary::Conv_TextToString":
        {"parms_size": 32, "return_value_offset": 16, "require_flags": 0x2400},
    "KismetSystemLibrary::LoadAsset_Blocking":
        {"parms_size": 48, "return_value_offset": 40, "require_flags": 0x2400},
    "KismetSystemLibrary::Conv_SoftObjectReferenceToString":
        {"parms_size": 56, "return_value_offset": 40, "require_flags": 0x2400},
    "BP_SGKFunctions_C::SGK ItemDetails":
        {"parms_size": 2336, "return_value_offset": None, "require_flags": 0},
    "BP_MasterInventory_C::AddItem":
        {"parms_size": 120, "return_value_offset": None, "require_flags": 0},
    "BP_MasterInventory_C::RemoveItem":
        {"parms_size": 83, "return_value_offset": None, "require_flags": 0},
}

# The row struct the Items backend writes. Offsets are read from the CR-01B
# reflection dump rather than restated, and only the fields the framework
# actually touches are carried: a profile that listed all 32 would be asserting
# things no code checks.
ROW_STRUCT_NAME = "S_ItemDetails"
ROW_STRUCT_FIELDS = ("Name", "ShortName", "Description", "Weight", "Width",
                     "Height", "AllowStacking", "MaxStack", "StaticMesh",
                     "WorldClass", "UIDetails", "ItemOffsets")
STRUCT_DEFS = os.path.join(REPO, "research", "evidence", "CR-01B",
                           "structs-defs.json")
# The struct's PropertiesSize, from the run that wrote a row through engine
# AddRow and hashed all 496 vanilla rows at this width. The resolver reads the
# live value; this is what it must equal.
ROW_STRUCT_SIZE_SOURCE = os.path.join(REPO, "research", "evidence", "CR-01C5",
                                      "retired-demo-state.json")

# UDataTable member offsets. UE 5.4 layout facts, restated here because the
# runtime reads them through the profile and a version mismatch must be visible
# in one place.
OBJECT_LAYOUT = {
    "datatable_rowstruct": 40,
    "datatable_parent_tables": 176,
    "ustruct_properties_size": 0x58,
}


# ------------------------------------------------------------------- PE ------
def section_bytes(image, rva, count):
    """The bytes at *rva*, found through the PE section table.

    The same walk the research controllers use. It returns None rather than
    guessing when an RVA falls outside every section's raw data, because an
    address that is not backed by file data is not an address this profile can
    make a promise about.
    """
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    sections = struct.unpack_from("<H", image, pe + 6)[0]
    opt_size = struct.unpack_from("<H", image, pe + 20)[0]
    table = pe + 24 + opt_size
    for index in range(sections):
        entry = table + index * 40
        virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", image, entry + 8)
        if virt_addr <= rva < virt_addr + max(virt_size, raw_size) and \
                rva - virt_addr < raw_size:
            start = raw_ptr + (rva - virt_addr)
            return image[start:start + count]
    return None


def image_size(image):
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    return struct.unpack_from("<I", image, pe + 24 + 56)[0]


# -------------------------------------------------------------- emitting ----
class BindingsError(Exception):
    pass


def row_struct_size():
    with open(ROW_STRUCT_SIZE_SOURCE, encoding="utf-8") as handle:
        state = json.load(handle)
    size = state.get("struct_size")
    if not isinstance(size, int) or size <= 0:
        raise BindingsError("%s states no usable struct_size"
                            % ROW_STRUCT_SIZE_SOURCE)
    return size


def row_struct_offsets():
    with open(STRUCT_DEFS, encoding="utf-8") as handle:
        defs = json.load(handle)
    if ROW_STRUCT_NAME not in defs:
        raise BindingsError("%s is not in %s" % (ROW_STRUCT_NAME, STRUCT_DEFS))
    # Field names carry a GUID suffix the cooker generates; the logical name is
    # the part before the first underscore, which is what the resolver matches
    # on and what the profile therefore records.
    found = {}
    for field in defs[ROW_STRUCT_NAME]["fields"]:
        logical = field["name"].split("_")[0]
        if logical in found:
            raise BindingsError(
                "two fields of %s share the logical name %r -- the prefix rule "
                "does not identify them and the profile will not guess"
                % (ROW_STRUCT_NAME, logical))
        found[logical] = int(field["offset"])
    missing = [name for name in ROW_STRUCT_FIELDS if name not in found]
    if missing:
        raise BindingsError("%s has no field(s) %s" % (ROW_STRUCT_NAME, missing))
    return {name: found[name] for name in ROW_STRUCT_FIELDS}


def emit(exe_path, build_id, build_key, engine, *, generated_at=None):
    """Build the profile for the executable at *exe_path*.

    Nothing here trusts the caller's *build_key*: the digest is recomputed from
    the file, and a mismatch is refused. A profile whose key came from anywhere
    but the bytes it describes is a profile that can be pointed at the wrong
    build.
    """
    with open(exe_path, "rb") as handle:
        image = handle.read()
    digest = "sha256:" + hashlib.sha256(image).hexdigest()
    if build_key and digest != build_key:
        raise BindingsError("%s hashes to %s, not the requested %s"
                            % (exe_path, digest, build_key))

    code, data, slots = measured_sources()
    addresses = {}
    for name, (rva, source) in sorted(code.items()):
        raw = section_bytes(image, rva, 16)
        if raw is None:
            raise BindingsError("rva 0x%X (%s) is not backed by file data"
                                % (rva, name))
        addresses[name] = {"kind": "code", "rva": rva,
                           "bytes": raw.hex(), "source": source}
    for name, (rva, source) in sorted(data.items()):
        addresses[name] = {"kind": "data", "rva": rva, "source": source}

    profile = {
        "bindings_version": BINDINGS_VERSION,
        "generated_by": "tools/modplatform/bindings.py %s" % TOOL_VERSION,
        "generated_at": generated_at or (
            datetime.datetime.now(datetime.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")),
        "build": {
            "build_id": build_id,
            "build_key": digest,
            "image_size_bytes": image_size(image),
            "file_size_bytes": len(image),
            "engine_version": engine["engine_version"],
            "engine_cl": engine["engine_cl"],
            "build_configuration": engine["build_configuration"],
        },
        "addresses": addresses,
        "vtable_slots": {name: {"slot": value, "source": source}
                         for name, (value, source) in sorted(slots.items())},
        "functions": {
            "forbid_flags": FUNCTION_FORBID_FLAGS,
            "gates": {name: dict(gate)
                      for name, gate in sorted(FUNCTION_GATES.items())},
        },
        "row_struct": {
            "name": ROW_STRUCT_NAME,
            "size": row_struct_size(),
            "fields": row_struct_offsets(),
            "source": "research/evidence/CR-01B/structs-defs.json",
            "size_source": "research/evidence/CR-01C5/retired-demo-state.json",
        },
        "object_layout": dict(OBJECT_LAYOUT),
    }
    return profile


def engine_from_index(build_key):
    """Engine identity, read from the build registry rather than restated."""
    path = os.path.join(REPO, "research", "builds", "index.json")
    with open(path, encoding="utf-8") as handle:
        index = json.load(handle)
    if build_key not in index:
        raise BindingsError("%s is not a registered build" % build_key)
    entry = index[build_key]
    fingerprint_rel = entry.get("artifacts", {}).get("fingerprint_json")
    engine = {"engine_version": entry.get("engine_version"),
              "engine_cl": None, "build_configuration": None}
    if fingerprint_rel:
        with open(os.path.join(REPO, fingerprint_rel), encoding="utf-8") as handle:
            fingerprint = json.load(handle)
        group = fingerprint.get("engine") or {}
        engine["engine_cl"] = group.get("engine_cl")
        engine["build_configuration"] = group.get("build_configuration")
    for key, value in engine.items():
        if value in (None, ""):
            raise BindingsError("the build registry does not state %s for %s"
                                % (key, build_key))
    return entry["build_id"], engine


def write(profile, out_path):
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(profile, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return out_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True,
                        help="MISERY-Win64-Shipping.exe to describe")
    parser.add_argument("--out", required=True)
    parser.add_argument("--build-key", default=None,
                        help="expected sha256:...; recomputed and checked")
    args = parser.parse_args(argv)

    with open(args.exe, "rb") as handle:
        digest = "sha256:" + hashlib.sha256(handle.read()).hexdigest()
    build_key = args.build_key or digest
    build_id, engine = engine_from_index(build_key)
    profile = emit(args.exe, build_id, build_key, engine)
    write(profile, args.out)
    print(json.dumps({"out": args.out, "build_id": build_id,
                      "build_key": profile["build"]["build_key"],
                      "addresses": len(profile["addresses"]),
                      "gates": len(profile["functions"]["gates"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
