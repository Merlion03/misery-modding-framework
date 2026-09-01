#!/usr/bin/env python3
"""E-3c runtime proof: does the child bind to MISERY's real class?

    production Steam launch
      -> mod package mounted normally
      -> child class loads
      -> Child.SuperStruct == the real BP_StaticMasterItem_C UClass*,
         independently resolved by the production resolver
      -> an inherited member deliberately absent from the surrogate resolves
      -> the child is constructed and its ancestry reaches the real parent

Bounded by research/evidence/E-3c/preregistration.md.

POINTER IDENTITY, NOT NAME MATCHING
-----------------------------------
The surrogate and the real parent share an object path BY DESIGN -- that is the
whole mechanism. So a name or path match proves nothing here, and the
pre-registration says so. What distinguishes them is which UClass object the
child's SuperStruct actually points at, and the answer has to come from
somewhere that never heard of this experiment.

It does: the production resolver resolves BP_StaticMasterItem_C on its own, as
the content anchor it calls "world item class", and Step 3 taught the runtime to
log every anchor's InternalIndex, SerialNumber and address. That log line is
written by production code doing its ordinary job, and the child's SuperStruct is
compared against it.

WHY "IS THE SURROGATE LOADED" IS NOT A PATH QUESTION
-----------------------------------------------------
The real parent legitimately occupies the path the surrogate was authored at, so
"no object at that path" would be the wrong check and would fail on a correct
run. The surrogate is EMPTY -- no properties at all -- while the real parent has
fifteen. So the class occupying that path is identified by what it contains, and
a container read-back has already shown our mod ships no package there.
"""
import argparse
import ctypes
import json
import os
import re
import struct
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "runner"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "mods"),
           os.path.join(REPO, "tools", "modplatform")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                                        # noqa: E402
import cr01c3_recon as recon                                      # noqa: E402
import install as installer                                       # noqa: E402
import ipp_controller as ipp                                      # noqa: E402
import lifecycle                                                  # noqa: E402
import readiness                                                  # noqa: E402
import stage5b_bindings as sb                                     # noqa: E402

CHILD_CLASS = "BP_MiseryTestWorldItem_C"
PARENT_CLASS = "BP_StaticMasterItem_C"
PARENT_PACKAGE = ("/Game/SurvivalGameKitV2/Blueprints/Items/WorldItems/"
                  "BP_StaticMasterItem")
CHILD_PACKAGE = "/Game/Mods/e3cprobe/BP_MiseryTestWorldItem"
# Chosen from the real parent's reflected members (CR-01
# master-classes-i05-i06.json): a plain int, safe to read, and gameplay-real.
# The S0 surrogate has NO properties, so any inherited member discriminates --
# this one is simply the least ambiguous to read.
INHERITED_PROPERTY = "ItemAmount"

# UE 5.4.4 layout, established by prior lifecycle work.
OFF_CLASS_PRIVATE = 0x10
OFF_SUPER_STRUCT = 0x40
OFF_CHILD_PROPERTIES = 0x50
OFF_PROPERTIES_SIZE = 0x58

DLL_NAME = "ipp_e3c_probe.dll"
IO_MAGIC = 0x4950502D45334300
IO_PROTO = 1
# Must match E3cIo in probe_e3c.cpp, field for field.
IO_HEAD = "<QII" + "Q" * 12
IO_TAIL = "<" + "Q" * 6 + "Q" * 7 + "Q" * 12 + "I" * 6
IO_PATH_CHARS = 256
IO_SIZE = (struct.calcsize(IO_HEAD) + 3 * IO_PATH_CHARS * 2 +
           struct.calcsize(IO_TAIL))
WORK = r"D:\UEScratch\E3C"


def build_probe():
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    ue = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"
    src = os.path.join(REPO, "research", "instruments", "ipp", "probe_e3c",
                       "probe_e3c.cpp")
    build_dir = os.path.join(REPO, "workspace", "msvc-probe")
    os.makedirs(build_dir, exist_ok=True)
    # A FRESH NAME PER RUN.
    #
    # A probe injected into a live game stays mapped: this project refuses to
    # unload a DLL the engine may still hold a pointer into, and would rather
    # leak a module than risk a use-after-free. So the previous run's copy is
    # still open and cannot be overwritten, and the build writes a new name
    # rather than fighting it.
    global DLL_NAME
    index = 0
    while True:
        DLL_NAME = "ipp_e3c_probe_%d.dll" % index
        out = os.path.join(build_dir, DLL_NAME)
        if not os.path.isfile(out):
            break
        try:
            os.remove(out)          # a previous run's copy nobody holds
            break
        except OSError:
            index += 1              # still mapped somewhere; take the next
    defs = ("/DPLATFORM_WINDOWS=1 /DPLATFORM_MICROSOFT=1 /DPLATFORM_64BITS=1 "
            "/DUE_BUILD_SHIPPING=1 /DUE_BUILD_DEVELOPMENT=0 /DUE_BUILD_TEST=0 "
            "/DUE_BUILD_DEBUG=0 /DWITH_EDITOR=0 /DWITH_EDITORONLY_DATA=0 "
            "/DWITH_ENGINE=0 /DWITH_SERVER_CODE=1 "
            "/DWITH_UNREAL_DEVELOPER_TOOLS=0 /DWITH_PLUGIN_SUPPORT=0 "
            "/DWITH_ACCESSIBILITY=0 /DIS_MONOLITHIC=1 /DIS_PROGRAM=0 "
            "/DCORE_API= /DCOREUOBJECT_API= /DTRACELOG_API= /DUNICODE /D_UNICODE "
            "/DPLATFORM_EXCEPTIONS_DISABLED=0 /D_WIN32_WINNT=0x0A00 "
            "/DWINVER=0x0A00 /DNTDDI_VERSION=0x0A000000 "
            "/DUBT_COMPILED_PLATFORM=Windows "
            "/DOVERRIDE_PLATFORM_HEADER_NAME=Windows")
    inc = ('/I"%s\\Core\\Public" /I"%s\\TraceLog\\Public" /I"%s\\Core\\Internal"'
           % (ue, ue, ue))
    bat = os.path.join(build_dir, "_build_e3c.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as handle:
        handle.write("@echo off\r\n")
        handle.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        handle.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s" /Fe:"%s" '
                     '/link /INCREMENTAL:NO\r\n' % (defs, inc, src, out))
    result = subprocess.run([bat], capture_output=True, text=True,
                            cwd=build_dir, shell=True)
    if not os.path.isfile(out):
        raise SystemExit("probe_e3c.cpp did not build (rc=%s):\n%s\n%s"
                         % (result.returncode, result.stdout[-3000:],
                            result.stderr[-1500:]))
    return out


def read_runtime_log(install_root):
    path = sb.fc.framework_path(install_root, "runtime.log")
    if not os.path.isfile(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


ANCHOR = re.compile(r"generation (\d+) anchor (.+?): index (-?\d+), "
                    r"serial (-?\d+), (0x[0-9a-f]+)")


def resolver_world_item_class(log):
    """The production resolver's OWN answer for BP_StaticMasterItem_C.

    Taken from the newest generation that named it, because an older
    generation's address belongs to a world that may since have been replaced.
    """
    best = None
    for gen, label, index, serial, address in ANCHOR.findall(log):
        if label.strip() == "world item class":
            entry = {"generation": int(gen), "index": int(index),
                     "serial": int(serial), "address": int(address, 16)}
            if best is None or entry["generation"] >= best["generation"]:
                best = entry
    return best


def class_chain(api, handle, class_address, limit=24):
    """SuperStruct chain, read out of process."""
    chain, cursor, seen = [], class_address, set()
    while cursor and cursor not in seen and len(chain) < limit:
        seen.add(cursor)
        chain.append(cursor)
        cursor = eri._read_u64(api, handle, cursor + OFF_SUPER_STRUCT)
    return chain


def properties_of(api, handle, struct_address, namepool, objects):
    """FProperty records on ONE struct, not its ancestors.

    eri.walk_property_chain is the project's own walker and is used rather than
    a hand-rolled Next-pointer loop: it applies the owner round-trip check --
    every top-level entry's FField::Owner must decode back to this struct --
    which is exactly the validation that stops a chain walk from wandering into
    unrelated memory and reporting whatever it finds there as a property.
    """
    head = eri._read_u64(api, handle, struct_address + OFF_CHILD_PROPERTIES)
    if not head:
        return []
    walked = eri.walk_property_chain(
        api, handle, head, namepool_live_va=namepool,
        owner_address=struct_address, objects_by_address=objects)
    return walked.get("accepted", [])


def utf16_field(text):
    raw = text.encode("utf-16-le")
    pad = IO_PATH_CHARS * 2 - len(raw)
    if pad < 2:
        raise SystemExit("%r does not fit the probe's path field" % text)
    return raw + b"\x00" * pad


def pack_io(addresses):
    head = struct.pack(
        IO_HEAD, IO_MAGIC, IO_PROTO, 0,
        addresses["add_ticker"], addresses["get_core_ticker"],
        addresses["fmemory_malloc"], addresses["fmemory_free"],
        addresses["process_event"], addresses["cdo_stringlib"],
        addresses["fn_conv_str_to_name"], addresses["cdo_syslib"],
        addresses["fn_load_asset_blocking"], addresses["cdo_gameplaystatics"],
        addresses["fn_spawn_object"], addresses["transient_package"])
    paths = (utf16_field(CHILD_PACKAGE) + utf16_field(CHILD_CLASS) +
             utf16_field(INHERITED_PROPERTY))
    tail = struct.pack(IO_TAIL, *([0] * 31))
    raw = head + paths + tail
    assert len(raw) == IO_SIZE, (len(raw), IO_SIZE)
    return raw


def unpack_io(raw):
    offset = struct.calcsize(IO_HEAD) + 3 * IO_PATH_CHARS * 2
    f = struct.unpack(IO_TAIL, raw[offset:offset + struct.calcsize(IO_TAIL)])
    return {"package_fname": f[0], "asset_fname": f[1], "loaded": f[2],
            "child_class": f[3], "constructed": f[4],
            "constructed_class": f[5],
            "child_super_struct": f[6], "child_properties_size": f[7],
            "parent_properties_size": f[8], "member_fname": f[9],
            "member_owner": f[10], "member_offset": f[11],
            "child_own_member_found": f[12],
            "chain": [x for x in f[13:25] if x],
            "registered_ok": f[25], "worker_tid": f[26], "ran": f[27],
            "callback_tid": f[28], "callback_count": f[29], "step": f[30]}


def resolve_probe_inputs(api, handle, base, profile, objects, namepool):
    """Everything the probe needs, resolved from the live process.

    The three carrier addresses come from the binding profile with their
    recorded bytes re-checked; the CDOs and reflected functions are found by
    name in the object graph, the same way every controller in this project
    finds them.
    """
    out = {}
    for name in ("add_ticker", "get_core_ticker", "fmemory_malloc",
                 "fmemory_free"):
        entry = profile["addresses"][name]
        address = base + entry["rva"]
        expected = bytes.fromhex(entry["bytes"])
        live = api.read_process_memory(handle, address, len(expected))
        if live != expected:
            raise SystemExit("%s does not match the profile" % name)
        out[name] = address

    def find_one(name, class_name=None):
        found = [a for a, r in objects.items()
                 if r.get("valid") and r.get("name_text") == name and
                 (class_name is None or
                  (objects.get(r.get("class_ptr") or 0) or {}).get("name_text")
                  == class_name)]
        if len(found) != 1:
            raise SystemExit("expected exactly one %r, found %d"
                             % (name, len(found)))
        return found[0]

    out["cdo_stringlib"] = find_one("Default__KismetStringLibrary")
    out["cdo_syslib"] = find_one("Default__KismetSystemLibrary")
    out["cdo_gameplaystatics"] = find_one("Default__GameplayStatics")
    out["transient_package"] = find_one("/Engine/Transient")

    # ProcessEvent from a CDO's vtable slot, the derivation the profile records
    # and the production backend already uses.
    slot = profile["vtable_slots"]["process_event"]["slot"]
    vtable = eri._read_u64(api, handle, out["cdo_gameplaystatics"])
    out["process_event"] = eri._read_u64(api, handle, vtable + slot * 8)

    meta = recon.find_function_meta(objects)
    if meta is None:
        raise SystemExit("the Function meta-class was not found")

    def fn_on(owner_name, function_name):
        owner = find_one(owner_name, "Class")
        for candidate in recon.class_functions(api, handle, namepool, owner,
                                               meta):
            if candidate.get("raw_name") == function_name:
                return candidate["address"]
        raise SystemExit("%s::%s was not found" % (owner_name, function_name))

    out["fn_conv_str_to_name"] = fn_on("KismetStringLibrary",
                                       "Conv_StringToName")
    out["fn_load_asset_blocking"] = fn_on("KismetSystemLibrary",
                                          "LoadAsset_Blocking")
    out["fn_spawn_object"] = fn_on("GameplayStatics", "SpawnObject")
    return out


def fire_probe(pid, dll_path, io_bytes):
    """Inject, Init, Run, read back. Modelled on the transition probe."""
    k = ipp._k32()
    hproc = k.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, pid)
    if not hproc:
        raise SystemExit("OpenProcess failed: %d" % ctypes.get_last_error())
    remote_path = remote_io = 0
    try:
        encoded = (dll_path + "\0").encode("utf-16-le")
        remote_path = k.VirtualAllocEx(hproc, None, len(encoded),
                                       ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                       ipp.PAGE_READWRITE)
        written = ctypes.c_size_t(0)
        k.WriteProcessMemory(hproc, ctypes.c_void_p(remote_path), encoded,
                             len(encoded), ctypes.byref(written))
        load_library = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"),
                                        b"LoadLibraryW")
        thread = k.CreateRemoteThread(hproc, None, 0, load_library, remote_path,
                                      0, None)
        if not thread or k.WaitForSingleObject(thread, 30000) != 0:
            raise SystemExit("LoadLibraryW failed or timed out")
        k.CloseHandle(thread)

        remote_base = ipp.find_remote_module_base(k, pid, DLL_NAME)
        if not remote_base:
            raise SystemExit("the probe DLL is not mapped in the target")

        remote_io = k.VirtualAllocEx(hproc, None, IO_SIZE,
                                     ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                     ipp.PAGE_READWRITE)
        k.WriteProcessMemory(hproc, ctypes.c_void_p(remote_io), io_bytes,
                             IO_SIZE, ctypes.byref(written))

        codes = {}
        for export in ("Init", "Run"):
            rva = ipp.find_export_rva(dll_path, export)
            thread = k.CreateRemoteThread(hproc, None, 0, remote_base + rva,
                                          remote_io, 0, None)
            if not thread:
                raise SystemExit("CreateRemoteThread(%s) failed" % export)
            if k.WaitForSingleObject(thread, 60000) != 0:
                raise SystemExit("%s timed out" % export)
            code = ctypes.c_ulong(0)
            k.GetExitCodeThread(thread, ctypes.byref(code))
            k.CloseHandle(thread)
            codes[export] = "0x%x" % code.value
            if code.value != 0:
                raise SystemExit("%s returned 0x%x" % (export, code.value))

        deadline = time.time() + 120
        state = {}
        while time.time() < deadline:
            buf = (ctypes.c_ubyte * IO_SIZE)()
            got = ctypes.c_size_t(0)
            if k.ReadProcessMemory(hproc, ctypes.c_void_p(remote_io), buf,
                                   IO_SIZE, ctypes.byref(got)):
                state = unpack_io(bytes(buf))
                if state.get("ran"):
                    break
            time.sleep(1.0)
        state["export_codes"] = codes
        return state
    finally:
        for pointer in (remote_io, remote_path):
            if pointer:
                try:
                    k.VirtualFreeEx(hproc, ctypes.c_void_p(pointer), 0,
                                    ipp.MEM_RELEASE)
                except Exception:                                  # noqa: BLE001
                    pass
        k.CloseHandle(hproc)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--install-root", default=installer.DEFAULT_INSTALL)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    checks = []

    def check(label, ok, detail=""):
        checks.append({"check": label, "pass": bool(ok), "detail": str(detail)})
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", label,
                               "" if ok else "  -- %s" % detail))
        return bool(ok)

    report = {"experiment": "E-3c", "phase": "runtime"}

    live = lifecycle.find_processes()
    if len(live) != 1:
        raise SystemExit("expected exactly one live MISERY process, found %d"
                         % len(live))
    pid = live[0]["pid"]
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    base, size = i01["base_address"], i01["image_size_bytes"]
    handle = eri.open_process_read_only(api, pid)
    report["pid"] = pid

    try:
        print("=== the production resolver's own answer ===")
        log = read_runtime_log(a.install_root)
        anchor = resolver_world_item_class(log)
        report["resolver_anchor"] = anchor
        if not check("the production resolver resolved the real parent class",
                     anchor is not None,
                     "no 'world item class' anchor in the runtime log"):
            write(report, checks, a.out)
            return 1
        print("   generation %d: index %d, serial %d, 0x%x"
              % (anchor["generation"], anchor["index"], anchor["serial"],
                 anchor["address"]))

        # ---- the loader precondition, evidenced in three parts ------------
        #
        # Addendum 1: mounted and registered does not imply loaded, and
        # successful loading is not inheritance success. The three facts are
        # recorded separately so they cannot be conflated afterwards.
        print("\n=== before: is the child already present? ===")
        namepool, objects = recon.universe(api, handle, base, size)
        report["objects_walked_before"] = len(objects)

        def find_by_name(where, name):
            return [address for address, record in where.items()
                    if record.get("valid") and record.get("name_text") == name]

        before = find_by_name(objects, CHILD_CLASS)
        report["child_before"] = ["0x%x" % c for c in before]
        check("the child class is ABSENT before the load request",
              not before,
              "found %d already loaded -- a later 'present' would prove nothing"
              % len(before))

        print("\n=== requesting the child by its cooked object path ===")
        profile = json.load(open(sb.fc.framework_path(a.install_root,
                                                      "bindings.json"),
                                 encoding="utf-8"))
        inputs = resolve_probe_inputs(api, handle, base, profile, objects,
                                      namepool)
        report["probe_inputs"] = {k: "0x%x" % v for k, v in inputs.items()}
        print("   %s.%s" % (CHILD_PACKAGE, CHILD_CLASS))
        dll = build_probe()
        state = fire_probe(pid, dll, pack_io(inputs))
        report["probe_io"] = state
        print("   probe: step=%s loaded=0x%x constructed=0x%x"
              % (state.get("step"), state.get("loaded") or 0,
                 state.get("constructed") or 0))
        check("the probe ran one callback on the game thread",
              state.get("callback_count") == 1 and state.get("ran") == 1, state)
        check("LoadAsset_Blocking returned an object for the child path",
              bool(state.get("loaded")),
              "step %s -- 0 means the engine did not resolve the path"
              % state.get("step"))

        # ---- the proof, from readings taken while everything was alive ----
        #
        # The probe records; this judges. Nothing it recorded knows what the
        # answer should be: the parent address below came from the production
        # resolver's own content-anchor pass, which has never heard of E-3c.
        #
        # Read on the game thread rather than out of process because nothing
        # roots what the probe creates. The first attempt walked the universe
        # seconds later and found the addresses collected -- an unreferenced
        # object in the transient package does not survive a GC, and reading
        # garbage back would have looked like a failed load.
        print("\n=== after the load: what the probe recorded ===")
        loaded_class = state.get("child_class") or 0
        report["child_class"] = "0x%x" % loaded_class
        check("the child class is PRESENT after the load request",
              loaded_class != 0,
              "LoadAsset_Blocking returned nothing at step %s"
              % state.get("step"))
        if loaded_class == 0:
            write(report, checks, a.out)
            return 1
        child = loaded_class
        print("   child class      0x%x" % child)

        # ---- 1 + 2: pointer identity, not a name match --------------------
        super_struct = state.get("child_super_struct") or 0
        print("   child SuperStruct        0x%x" % super_struct)
        print("   resolver's parent UClass 0x%x" % anchor["address"])
        check("the child's SuperStruct IS the resolver's parent UClass "
              "(pointer identity)",
              super_struct == anchor["address"],
              "0x%x vs 0x%x" % (super_struct, anchor["address"]))

        # ---- 4: constructed, and its ancestry ------------------------------
        chain = state.get("chain") or []
        report["constructed_chain"] = ["0x%x" % c for c in chain]
        print("   constructed 0x%x, class 0x%x"
              % (state.get("constructed") or 0,
                 state.get("constructed_class") or 0))
        print("   instance ancestry: %s"
              % " -> ".join("0x%x" % c for c in chain))
        check("the child was constructed through "
              "UGameplayStatics::SpawnObject",
              bool(state.get("constructed")), "step %s" % state.get("step"))
        check("the constructed object's class is the child class",
              state.get("constructed_class") == child,
              "0x%x vs child 0x%x" % (state.get("constructed_class") or 0,
                                      child))
        check("the constructed instance's ancestry reaches the real parent",
              anchor["address"] in chain, report["constructed_chain"])

        # ---- 3: an inherited member the S0 surrogate does not have ---------
        owner = state.get("member_owner") or 0
        report["inherited_member"] = {
            "name": INHERITED_PROPERTY,
            "owner": "0x%x" % owner,
            "offset": state.get("member_offset"),
            "declared_by_child": bool(state.get("child_own_member_found"))}
        print("   %s: owner 0x%x, offset %s"
              % (INHERITED_PROPERTY, owner, state.get("member_offset")))
        check("the inherited member resolves through the child",
              owner != 0,
              "%s was not found on the child's chain" % INHERITED_PROPERTY)
        check("it is owned by the REAL parent, not declared by the child",
              owner == anchor["address"] and
              not state.get("child_own_member_found"),
              "owner 0x%x, parent 0x%x, child-declared %s"
              % (owner, anchor["address"],
                 bool(state.get("child_own_member_found"))))
        # The S0 surrogate is empty, so the member's mere presence already
        # discriminates; its offset matching the value measured on the real
        # parent by CR-01 is a second, independent agreement.
        check("the member sits at the offset CR-01 measured on the real parent",
              state.get("member_offset") == 688,
              "%s vs 688" % state.get("member_offset"))

        # ---- 5: the surrogate is not what the child bound to ---------------
        child_size = state.get("child_properties_size") or 0
        parent_size = state.get("parent_properties_size") or 0
        report["properties_size"] = {"child": child_size,
                                     "parent": parent_size}
        print("   PropertiesSize: parent %d, child %d"
              % (parent_size, child_size))
        # An empty Actor surrogate would leave the child at AActor's size with
        # no ItemAmount at all. Both facts above already exclude that; this is
        # the size-level statement of the same thing.
        check("the child inherited a real layout, not an empty surrogate's",
              child_size >= parent_size > 700,
              "child %d, parent %d" % (child_size, parent_size))

    finally:
        try:
            api.close_handle(handle)
        except Exception:                                          # noqa: BLE001
            pass

    write(report, checks, a.out)
    return 0 if all(c["pass"] for c in checks) else 1


def write(report, checks, path):
    report["checks"] = checks
    report["passed"] = sum(1 for c in checks if c["pass"])
    report["failed"] = sum(1 for c in checks if not c["pass"])
    report["verdict"] = "PASS" if report["failed"] == 0 else "FAIL"
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, default=str)
        handle.write("\n")
    print("\n%s -- %d passed, %d failed -> %s"
          % (report["verdict"], report["passed"], report["failed"], path))


if __name__ == "__main__":
    raise SystemExit(main())
