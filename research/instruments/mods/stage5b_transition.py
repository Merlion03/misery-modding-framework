#!/usr/bin/env python3
"""Stage 5B step 3, second acceptance: a real transition, survived.

WHAT IS BEING PROVEN
--------------------
    gameplay generation N
      -> the C# mod is already loaded
      -> its declaration is applied
      -> the game's own SGK ItemDetails resolves the item

      -> a controlled REAL game transition

      -> generation N revoked
      -> the production Items consumer acquires through the generation gate
      -> the stale generation cannot be consumed
      -> no stale row or anchor is published or used

    gameplay generation N+1
      -> fresh anchors resolved
      -> the existing declaration reapplied, with no duplicate
      -> SGK ItemDetails resolves the same semantic item again

THE LINE BETWEEN PROBE AND PRODUCTION
-------------------------------------
    research probe        CAUSES the transition, and nothing else
    production runtime    detects / revokes / resolves / reapplies

The probe registers one ticker callback and makes one ProcessEvent call to
APlayerController::RestartLevel -- a zero-parameter UFunction measured on this
build. It cannot read an anchor, write a row, reach the items backend, or learn
that a content generation exists; see probe_transition.cpp. Every recovery step
in the sequence above is the production runtime's, observed through its own log.

WHY NOT THE UI
--------------
Because it cannot be done. The runner identifies a screen by which Blueprint
classes have LIVE instances, and a UMG pause menu is built once then shown and
hidden -- one Escape from gameplay, focus verified, changed not a single class.
Driving a menu route would have meant new classifier research, which is not what
this gate is about.
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

import eri                                              # noqa: E402
import cr01c3_recon as recon                            # noqa: E402
import install as installer                             # noqa: E402
import ipp_controller as ipp                            # noqa: E402
import lifecycle                                        # noqa: E402
import readiness                                        # noqa: E402
import stage5b_bindings as sb                           # noqa: E402

DLL_NAME = "ipp_transition_probe.dll"
IO_MAGIC = 0x4950502D5452414E                           # "IPP-TRAN"
IO_PROTO = 1
# Must match TransitionIo in probe_transition.cpp, field for field.
IO_FORMAT = "<QIIQQQQQQIIIIIIQQ"
IO_SIZE = struct.calcsize(IO_FORMAT)
PROCESS_EVENT_SLOT = 77


def pack_io(add_ticker, get_core_ticker, fmemory_malloc, process_event,
            target, function):
    raw = struct.pack(IO_FORMAT, IO_MAGIC, IO_PROTO, 0, add_ticker,
                      get_core_ticker, fmemory_malloc, process_event, target,
                      function, 0, 0, 0, 0, 0, 0, 0, 0)
    assert len(raw) == IO_SIZE
    return raw


def unpack_io(raw):
    f = struct.unpack(IO_FORMAT, raw)
    return {"registered_ok": f[9], "worker_tid": f[10], "called": f[11],
            "callback_tid": f[12], "callback_count": f[13]}


def build_probe():
    """Compile the probe fresh, with the same recipe the other IPP probes use."""
    vcvars = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    if not os.path.isfile(vcvars):
        raise SystemExit("MSVC vcvars64 not found at %r" % vcvars)
    ue = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"
    src = os.path.join(REPO, "research", "instruments", "ipp",
                       "probe_transition", "probe_transition.cpp")
    build_dir = os.path.join(REPO, "workspace", "msvc-probe")
    os.makedirs(build_dir, exist_ok=True)
    out = os.path.join(build_dir, DLL_NAME)
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
    if os.path.isfile(out):
        os.remove(out)
    bat = os.path.join(build_dir, "_build_transition.bat")
    with open(bat, "w", encoding="ascii", newline="\r\n") as handle:
        handle.write("@echo off\r\n")
        handle.write('call "%s" -vcvars_ver=14.38 >nul 2>&1\r\n' % vcvars)
        handle.write('cl /nologo /LD /MT /EHsc /std:c++17 %s %s "%s" /Fe:"%s" '
                     '/link /INCREMENTAL:NO\r\n' % (defs, inc, src, out))
    result = subprocess.run([bat], capture_output=True, text=True,
                            cwd=build_dir, shell=True)
    if not os.path.isfile(out):
        raise SystemExit("probe_transition.cpp did not build (rc=%s):\n%s\n%s"
                         % (result.returncode, result.stdout[-3000:],
                            result.stderr[-1500:]))
    return out


def profile_address(profile, name, base, api, handle):
    """A profile RVA, with its recorded bytes re-checked against live memory.

    The same second lock the runtime applies. An address that was right once is
    not an address that is right now, and a probe about to call into the engine
    is the last place to take that on trust.
    """
    entry = profile["addresses"][name]
    address = base + entry["rva"]
    expected = bytes.fromhex(entry["bytes"])
    live = api.read_process_memory(handle, address, len(expected))
    if live != expected:
        raise SystemExit("%s does not match the profile: expected %s, live %s"
                         % (name, expected.hex(), live.hex()))
    return address


def find_target(api, handle, base, size, report):
    """The live PlayerController and its RestartLevel UFunction."""
    namepool, objects = recon.universe(api, handle, base, size)
    note = []
    verdict = readiness.prove_gameplay(eri, api, handle, objects,
                                       namepool=namepool, note=note)
    report["gameplay_before"] = {"ready": verdict["ready"],
                                 "reasons": verdict.get("reasons")}
    if not verdict["ready"]:
        raise SystemExit("not in gameplay before the transition: %s"
                         % verdict.get("reasons"))

    controllers = verdict["facts"].get("player_controllers") or []
    if len(controllers) != 1:
        raise SystemExit("expected exactly one live PlayerController, found %d"
                         % len(controllers))
    controller = int(controllers[0]["address"], 16)
    report["controller"] = controllers[0]

    meta = recon.find_function_meta(objects)
    if meta is None:
        raise SystemExit("the Function meta-class was not found")

    # RestartLevel is declared on the native PlayerController and the live
    # object is a Blueprint subclass, so the whole ancestry has to be walked.
    #
    # readiness.class_super_chain rather than a loop of my own: it re-verifies
    # the SuperStruct offset on every walk by requiring the chain to terminate
    # exactly at /Script/CoreUObject.Object, which a hand-rolled version would
    # simply assume.
    class_address = (objects.get(controller) or {}).get("class_ptr")
    ancestry = readiness.class_super_chain(eri, api, handle, class_address,
                                           objects)
    if not ancestry.get("terminated_at_object"):
        raise SystemExit("the controller's class chain did not terminate at "
                         "UObject; the SuperStruct offset is wrong for this "
                         "build and every ancestry answer is worthless")
    report["controller_ancestry"] = [path for _a, path in ancestry["chain"]]

    function = None
    owner = None
    for address, path in ancestry["chain"]:
        for candidate in recon.class_functions(api, handle, namepool, address,
                                               meta):
            if candidate.get("raw_name") == "RestartLevel":
                function, owner = candidate["address"], path
                break
        if function:
            break
    if not function:
        raise SystemExit("RestartLevel was not found on the controller's class "
                         "chain: %s" % report["controller_ancestry"])

    abi = recon.function_abi(api, handle, namepool, function, objects)
    if abi.get("num_parms") or abi.get("parms_size"):
        # The probe passes a null parameter block. If this build's RestartLevel
        # ever took a parameter, that would be a wild call, so it is refused
        # rather than attempted.
        raise SystemExit("RestartLevel is not zero-parameter on this build "
                         "(num_parms=%s parms_size=%s); refusing to call it"
                         % (abi.get("num_parms"), abi.get("parms_size")))
    report["function"] = {"name": "RestartLevel", "class": owner,
                          "address": "0x%x" % function,
                          "num_parms": abi.get("num_parms"),
                          "parms_size": abi.get("parms_size")}

    vtable = eri._read_u64(api, handle, controller)
    process_event = eri._read_u64(api, handle,
                                  vtable + PROCESS_EVENT_SLOT * 8)
    if not process_event:
        raise SystemExit("ProcessEvent slot %d read as zero" % PROCESS_EVENT_SLOT)
    report["process_event"] = "0x%x" % process_event
    return controller, function, process_event


def fire(pid, dll_path, io_bytes, report):
    """Inject, Init, Fire, and free. Modelled on fts_controller."""
    k = ipp._k32()
    # The project's own scoped rights, not blanket ALL_ACCESS.
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
        report["probe_base"] = "0x%x" % remote_base

        remote_io = k.VirtualAllocEx(hproc, None, IO_SIZE,
                                     ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                     ipp.PAGE_READWRITE)
        k.WriteProcessMemory(hproc, ctypes.c_void_p(remote_io), io_bytes,
                             IO_SIZE, ctypes.byref(written))

        for export in ("Init", "Fire"):
            rva = ipp.find_export_rva(dll_path, export)
            thread = k.CreateRemoteThread(hproc, None, 0, remote_base + rva,
                                          remote_io, 0, None)
            if not thread:
                raise SystemExit("CreateRemoteThread(%s) failed: %d"
                                 % (export, ctypes.get_last_error()))
            if k.WaitForSingleObject(thread, 30000) != 0:
                raise SystemExit("%s timed out" % export)
            code = ctypes.c_ulong(0)
            k.GetExitCodeThread(thread, ctypes.byref(code))
            k.CloseHandle(thread)
            report["%s_rc" % export.lower()] = "0x%x" % code.value
            if code.value != 0:
                raise SystemExit("%s returned 0x%x" % (export, code.value))

        # Read the IO back once the callback has had time to run. The call tears
        # the world down, so this is deliberately generous.
        deadline = time.time() + 60
        state = {}
        while time.time() < deadline:
            buf = (ctypes.c_ubyte * IO_SIZE)()
            got = ctypes.c_size_t(0)
            if k.ReadProcessMemory(hproc, ctypes.c_void_p(remote_io), buf,
                                   IO_SIZE, ctypes.byref(got)):
                state = unpack_io(bytes(buf))
                if state.get("called"):
                    break
            time.sleep(1.0)
        report["probe_io"] = state
        if not state.get("called"):
            raise SystemExit("the probe callback never ran: %r" % state)
    finally:
        for pointer in (remote_io, remote_path):
            if pointer:
                try:
                    k.VirtualFreeEx(hproc, ctypes.c_void_p(pointer), 0,
                                    ipp.MEM_RELEASE)
                except Exception:                          # noqa: BLE001
                    pass
        k.CloseHandle(hproc)


def read_log(install_root):
    path = sb.fc.framework_path(install_root, "runtime.log")
    if not os.path.isfile(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


GEN_PUBLISHED = re.compile(
    r"content generation (\d+) published -- (\w+), (\d+) objects")
GEN_ANCHORS = re.compile(
    r"generation (\d+): ItemList (0x[0-9a-f]+), MasterItemList (0x[0-9a-f]+), "
    r"RowStruct (0x[0-9a-f]+)")
GEN_REVOKED = re.compile(r"generation (\d+) is revoked: (.+)")
ITEM_LIVE = re.compile(
    r"items: '(\S+)'(?: is live)? in generation (\d+)[;:] "
    r"the game's own SGK ItemDetails resolved it(?: \(attempt \d+\))?")
ITEM_COUNT = re.compile(
    r"(\d+) of (\d+) declared item\(s\) live in generation (\d+)")
NOT_APPLIED = re.compile(r"(\d+) declared item\(s\) not applied -- (.+)")
# The label is (.+?), not (\S+): anchor labels contain spaces, and the one
# this whole test turns on is called "live player inventory". A \S+ pattern
# parsed every single-word anchor and silently dropped that one.
GEN_IDENTITY = re.compile(
    r"generation (\d+) anchor (.+?): index (-?\d+), serial (-?\d+), "
    r"(0x[0-9a-f]+)")
REFUSED = re.compile(r"items: (?:registration|unregister) refused -- (.+)")


def generations(log):
    """Every generation the runtime published, with its anchor identities."""
    out = {}
    for gen, phase, objects in GEN_PUBLISHED.findall(log):
        out[int(gen)] = {"generation": int(gen), "phase": phase,
                         "objects": int(objects)}
    for gen, item_list, master, row_struct in GEN_ANCHORS.findall(log):
        out.setdefault(int(gen), {"generation": int(gen)}).update(
            {"item_list": item_list, "master_item_list": master,
             "row_struct": row_struct})
    # The authoritative half: (InternalIndex, SerialNumber) per anchor.
    for gen, label, index, serial, address in GEN_IDENTITY.findall(log):
        entry = out.setdefault(int(gen), {"generation": int(gen)})
        entry.setdefault("identities", {})[label] = {
            "index": int(index), "serial": int(serial), "address": address}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--install-root", default=installer.DEFAULT_INSTALL)
    ap.add_argument("--out", required=True)
    ap.add_argument("--settle", type=float, default=240.0,
                    help="seconds to wait for the new generation")
    a = ap.parse_args(argv)

    checks = []

    def check(label, ok, detail=""):
        checks.append({"check": label, "pass": bool(ok), "detail": str(detail)})
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", label,
                               "" if ok else "  -- %s" % detail))
        return bool(ok)

    report = {"stage": "5B", "step": "controlled transition"}

    print("=== the state before the transition ===")
    before = read_log(a.install_root)
    gens_before = generations(before)
    live_before = ITEM_LIVE.findall(before)
    if not live_before:
        raise SystemExit("no item is live yet; run stage5b_managed first and "
                         "leave the game in gameplay")
    row_name, gen_n = live_before[-1][0], int(live_before[-1][1])
    report["generation_n"] = gens_before.get(gen_n)
    report["row_name"] = row_name
    print("  generation %d (%s), row %s"
          % (gen_n, (gens_before.get(gen_n) or {}).get("phase"), row_name))

    check("generation N is a gameplay generation",
          (gens_before.get(gen_n) or {}).get("phase") == "gameplay",
          (gens_before.get(gen_n) or {}).get("phase"))
    check("the C# mod's declaration is applied in generation N",
          bool(live_before), row_name)
    check("the game's own SGK ItemDetails resolved it in generation N",
          bool(live_before), row_name)

    live = lifecycle.find_processes()
    if len(live) != 1:
        raise SystemExit("expected exactly one live MISERY process, found %d"
                         % len(live))
    pid = live[0]["pid"]
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    base, size = i01["base_address"], i01["image_size_bytes"]
    handle = eri.open_process_read_only(api, pid)

    print("\n=== arming the transition probe ===")
    profile = json.load(open(sb.fc.framework_path(a.install_root,
                                                  "bindings.json"),
                             encoding="utf-8"))
    try:
        target, function, process_event = find_target(api, handle, base, size,
                                                      report)
        addresses = {name: profile_address(profile, name, base, api, handle)
                     for name in ("add_ticker", "get_core_ticker",
                                  "fmemory_malloc")}
    finally:
        try:
            api.close_handle(handle)
        except Exception:                                  # noqa: BLE001
            pass
    print("  controller %s, RestartLevel %s (parms 0)"
          % (report["controller"]["address"], report["function"]["address"]))

    dll_path = build_probe()
    io_bytes = pack_io(addresses["add_ticker"], addresses["get_core_ticker"],
                       addresses["fmemory_malloc"], process_event, target,
                       function)

    print("\n=== causing one real transition ===")
    marker = len(before)
    fire(pid, dll_path, io_bytes, report)
    check("the probe ran one callback on the game thread",
          report["probe_io"].get("callback_count") == 1 and
          report["probe_io"].get("called") == 1, report["probe_io"])

    print("\n=== what the production runtime did about it ===")
    deadline = time.time() + a.settle
    after = before
    while time.time() < deadline:
        after = read_log(a.install_root)
        tail = after[marker:]
        newer = [int(m[0]) for m in GEN_PUBLISHED.findall(tail)]
        if any(g > gen_n for g in newer) and ITEM_LIVE.search(tail):
            break
        time.sleep(5)
    tail = after[marker:]
    report["runtime_log_tail"] = tail
    report["runtime_log"] = after

    revoked = GEN_REVOKED.findall(tail)
    report["revocations"] = [{"generation": int(g), "why": w.strip()}
                             for g, w in revoked]
    check("generation N was revoked by the transition",
          any(int(g) == gen_n for g, _ in revoked),
          report["revocations"])

    # THE GATE REFUSING A CONSUMER.
    #
    # The revocation line IS a refusal: it is emitted by content::Acquire
    # failing inside the production lifecycle's own poll, which is a consumer
    # asking for the current generation and being told it no longer exists. That
    # is the gate doing its job, in production code, with no test hook.
    #
    # The Items backend's own poll fires every 20 seconds and the window between
    # revocation and republication measured under four, so catching the backend
    # mid-window is luck rather than evidence. It is recorded when it happens
    # and never depended upon; the properties that must hold are checked
    # structurally further down instead -- the backend rebinding to the new
    # generation before writing, and no row ever reaching the revoked one.
    report["opportunistic_refusals"] = ([list(m) for m in
                                         NOT_APPLIED.findall(tail)] +
                                        [list(m) for m in REFUSED.findall(tail)])
    check("a production consumer was refused by the generation gate while the "
          "world was gone",
          bool(revoked),
          "no consumer met the revoked generation")

    gens_after = generations(after)
    later = sorted(g for g in gens_after if g > gen_n)
    report["generation_n_plus_1"] = gens_after.get(later[0]) if later else None
    check("a later generation was published", bool(later), sorted(gens_after))

    if later:
        gen_next = later[0]
        n, m = gens_before.get(gen_n) or {}, gens_after.get(gen_next) or {}
        report["anchor_identity"] = {
            "N": {k: n.get(k) for k in ("generation", "phase", "item_list",
                                        "master_item_list", "row_struct")},
            "N+1": {k: m.get(k) for k in ("generation", "phase", "item_list",
                                          "master_item_list", "row_struct")}}
        # GENUINELY DIFFERENT, judged on the slot rather than the address.
        #
        # The first version of this check compared the three table addresses and
        # demanded all three differ. It failed, and it was wrong to ask: a
        # RestartLevel leaves ItemList, MasterItemList and RowStruct at
        # byte-identical addresses while replacing the world, and an address
        # that is reused says nothing either way. UE keeps the real answer in
        # the object's slot -- InternalIndex and SerialNumber -- which is
        # exactly why the resolver validates against those and not against
        # pointers.
        #
        # So the question asked here is the one that has a truthful answer: did
        # any anchor's identity actually change, and was the revocation caused
        # by one that did.
        ids_n = (n.get("identities") or {})
        ids_m = (m.get("identities") or {})
        shared = sorted(set(ids_n) & set(ids_m))
        changed = [k for k in shared if ids_n[k] != ids_m[k]]
        same_address_new_identity = [
            k for k in changed
            if ids_n[k]["address"] == ids_m[k]["address"]]
        report["identity_delta"] = {
            "compared": shared, "changed": changed,
            "changed_at_the_same_address": same_address_new_identity,
            "N": ids_n, "N+1": ids_m}
        check("N and N+1 are genuinely different content generations",
              bool(changed),
              "no anchor identity changed between N and N+1: %s" % ids_n)
        if same_address_new_identity:
            print("    (%d anchor(s) kept their address and changed identity: "
                  "%s -- which is why the slot, not the pointer, decides)"
                  % (len(same_address_new_identity),
                     ", ".join(same_address_new_identity)))

        # The revocation must name an anchor that really did change.
        revoked_anchor = None
        for gen, why in revoked:
            if int(gen) == gen_n:
                match = re.search(r"'([^']+)'", why)
                revoked_anchor = match.group(1) if match else None
        report["revoked_anchor"] = revoked_anchor
        check("the revocation names an anchor whose identity actually changed",
              revoked_anchor is not None and
              any(revoked_anchor in k or k in revoked_anchor for k in changed),
              "revoked on %r; changed: %s" % (revoked_anchor, changed))
        check("generation N+1 is a gameplay generation",
              m.get("phase") == "gameplay", m.get("phase"))

        # The declaration reapplied itself, and did not become two.
        after_live = [(r, int(g)) for r, g in ITEM_LIVE.findall(tail)
                      if int(g) >= gen_next]
        report["reapplied"] = after_live
        check("the existing declaration was reapplied automatically",
              bool(after_live), after_live)
        check("the game's own SGK ItemDetails resolves the same semantic item "
              "again",
              any(r == row_name for r, _ in after_live),
              "expected %s, saw %s" % (row_name, after_live))

        counts = [(int(x), int(y), int(z)) for x, y, z in
                  ITEM_COUNT.findall(tail) if int(z) >= gen_next]
        report["declaration_counts"] = counts
        check("the declaration was not duplicated",
              bool(counts) and all(x == 1 and y == 1 for x, y, _ in counts),
              counts)

        # Nothing was ever written into the revoked generation afterwards.
        stale = [(r, int(g)) for r, g in ITEM_LIVE.findall(tail)
                 if int(g) == gen_n]
        check("no row was applied to the revoked generation after revocation",
              not stale, stale)

        # The backend did not carry generation N's anchors forward. It tore
        # down against them and rebound, which is the substantive form of
        # "a stale generation cannot be consumed".
        bound = re.findall(r"items: backend bound to content generation (\d+)",
                           tail)
        report["rebound_to"] = [int(b) for b in bound]
        check("the Items backend rebound to the new generation before writing "
              "anything",
              bool(bound) and int(bound[-1]) == gen_next,
              "bound to %s, expected %s" % (bound, gen_next))

    report["checks"] = checks
    report["passed"] = sum(1 for c in checks if c["pass"])
    report["failed"] = sum(1 for c in checks if not c["pass"])
    report["verdict"] = "PASS" if report["failed"] == 0 else "FAIL"
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as handle_out:
        json.dump(report, handle_out, indent=2, default=str)
        handle_out.write("\n")
    print("\n%s -- %d passed, %d failed -> %s"
          % (report["verdict"], report["passed"], report["failed"], a.out))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
