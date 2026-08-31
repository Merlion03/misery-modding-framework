#!/usr/bin/env python3
"""Exercise the C++ resolver across the phases a real session goes through.

WHY THIS IS SEPARATE FROM THE ORACLE CROSS-CHECK
------------------------------------------------
The cross-check proves the C++ resolver agrees with the Python oracle, and it
can only run where the oracle can: in gameplay, on an untouched process, because
the oracle asserts the vanilla ParentTables baseline before it will answer.

The resolver has to work in places the oracle refuses to go -- most importantly
the main menu, where there is no player and therefore no player inventory. So
this file injects the runtime directly, with no AggregateSession and no oracle,
and asks the resolver the same question in each phase.

CONTENT IDENTITY IS NOT STABLE ACROSS A LOAD, AND THAT IS NOT A DEFECT
----------------------------------------------------------------------
Measured here: the item tables, the game's own Blueprint classes, their CDOs and
their UFunctions are destroyed and recreated when the menu world is replaced by
the game world. They hold one address while content is loaded without a player,
and another once gameplay is reached. Every sample is a fresh resolution, so
this is visible rather than hidden -- and the consequence is the point: a
content pointer resolved before gameplay is dangling by the time the player
exists. The runtime must resolve content at gameplay and must not cache it
across that boundary.

ABSENCE IS NOT FAILURE
----------------------
The lifecycle specification says the live player inventory does not exist before
gameplay. A resolver that reported the main menu as a resolution failure would
be wrong about the lifecycle rather than about the process, and it would make
the runtime refuse to start on a perfectly healthy game. So "absent" is a
first-class answer here, and the startup anchors still resolve at the menu
because those exist from process start.

WHAT THE MENU CONTAINS IS NOT AN INVARIANT
------------------------------------------
An earlier version of this file asserted that the item tables are absent at the
main menu, on the strength of two launches that showed exactly that. A third
launch, same build and same save, had the ENTIRE content set resolvable at the
menu with nothing loaded by the player. Two observations were mistaken for a
rule.

So menu content is now RECORDED, not asserted, and the checks are limited to
what actually holds every time: the resolver never claims gameplay at the menu
(there is no player), the startup phase always resolves, and a content request
is answered consistently with what the survey just found. When the menu does
carry content, that is not a curiosity -- those are precisely the anchors the
subsequent load destroys and recreates, which makes it the clearest available
demonstration of why content must not be cached across a load.
"""
import argparse
import ctypes
import json
import os
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "mods"),
           os.path.join(REPO, "tools", "modplatform")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                        # noqa: E402
import ipp_controller as ipp                      # noqa: E402
import gt01_controller as gt                      # noqa: E402
import nativebuild as nb                          # noqa: E402
import p04_controller as p04                      # noqa: E402
import bindings as bindings_tool                 # noqa: E402
import stage5b_resolver_check as check_mod        # noqa: E402

STEAM_RUN = "steam://run/2119830"
# The save-entry machine allows 240s for the level load alone, and the cycle
# waits on readiness before that; this has to outlast the whole of it.
TRANSITION_TIMEOUT_S = 1500
TRANSITION_POLL_S = 4.0
RUNTIME_DLL = "MiseryRuntimeStage5.dll"

COST_KEYS = ("object_count", "build_us", "resolve_us", "validate_us", "reads",
             "vqueries", "cache_hits", "queued_us", "game_thread_id",
             "slices", "max_slice_us", "max_slice_index", "objects_processed",
             "restarts",
             "revalidation_failures", "requested_phase", "completed_phase")

# The acceptance bar for one game-thread slice. The budget is 2ms; the final
# slice additionally does anchor resolution and the live re-validation, so it is
# legitimately the longest. 8ms is under half a 60fps frame and still far below
# the 481ms the unchunked walk cost -- if a slice ever approaches this, the
# budget or the final step needs splitting further.
MAX_SLICE_US = 8000


def cost_of(sample):
    """What one resolution cost, or None if it never ran.

    Every resolve in this file goes through here. The first version recorded
    cost only at the menu, which meant the EXPENSIVE phase -- gameplay, with an
    order of magnitude more objects -- was the one phase with no measurement,
    and a budget was nearly sized off an extrapolation instead.
    """
    if sample.get("rc") != 0:
        return None
    return {k: sample.get(k) for k in COST_KEYS}


BUILD_KEY = ("sha256:bace50f7185d095d03ee18a2fea701c747810c31f2037bda21e"
             "a57a81f013331")


class Injected(object):
    """The runtime, loaded into a live process. No session, no aggregate.

    Deliberately the smallest thing that can call one export: the point of the
    menu phase is to ask the resolver a question in a state where the heavier
    machinery cannot even initialise.
    """

    def __init__(self, dll_path, profile):
        self.dll = dll_path
        self.profile = profile
        self.k, _ = gt._k32full()
        i01 = eri.run_i01(eri.Win32Api(), eri.DEFAULT_PROCESS_NAME)
        self.pid = i01["pid"]
        self.base = i01["base_address"]
        # Derived from THIS process's base. Every launch is rebased, so a
        # carrier computed once and reused would point into the wrong image.
        self.carrier = check_mod.carrier_from_bindings(profile, self.base)
        self.handle = self.k.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, self.pid)
        if not self.handle:
            raise RuntimeError("OpenProcess failed")
        path_bytes = (dll_path + "\x00").encode("utf-16-le")
        remote_path = self.k.VirtualAllocEx(self.handle, None, len(path_bytes),
                                            ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                            ipp.PAGE_READWRITE)
        written = ctypes.c_size_t(0)
        self.k.WriteProcessMemory(self.handle, remote_path, path_bytes,
                                  len(path_bytes), ctypes.byref(written))
        loader = self.k.GetProcAddress(self.k.GetModuleHandleW("kernel32.dll"),
                                       b"LoadLibraryW")
        thread = self.k.CreateRemoteThread(self.handle, None, 0, loader,
                                           remote_path, 0, None)
        self.k.WaitForSingleObject(thread, ipp.WAIT_TIMEOUT_MS)
        self.k.CloseHandle(thread)
        # The path string was only needed for the duration of the call.
        self.k.VirtualFreeEx(self.handle, remote_path, 0, ipp.MEM_RELEASE)
        self.module = ipp.find_remote_module_base(self.k, self.pid,
                                                  os.path.basename(dll_path))
        if self.module is None:
            raise RuntimeError("the runtime did not load")

        # ONE buffer, for every question this injection will ever ask. The
        # transition phase polls for as long as a level load takes, so a page
        # per call would be a steady leak of committed memory inside a running
        # game -- and the run that needs the most samples would leak the most.
        self.io = self.k.VirtualAllocEx(self.handle, None, check_mod.IO_SIZE,
                                        ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                        ipp.PAGE_READWRITE)
        if not self.io:
            raise RuntimeError("VirtualAllocEx for the resolver IO failed")

    # Returned when the call could not be MADE, as opposed to the resolver
    # answering badly. The two are different findings and conflating them once
    # cost a whole run: a transient CreateRemoteThread failure during a level
    # load raised out of the sampling loop and destroyed two green launches'
    # worth of record along with the third.
    CALL_FAILED = -1

    def resolve(self, require_phase, world_class="BP_StaticMasterItem_C"):
        packed = check_mod.pack_io(
            self.base + int(self.profile["addresses"]["guobjectarray"]["rva"]),
            self.base + int(self.profile["addresses"]["namepool"]["rva"]),
            require_phase, world_class, self.carrier)
        try:
            written = ctypes.c_size_t(0)
            self.k.WriteProcessMemory(self.handle, self.io, packed, len(packed),
                                      ctypes.byref(written))
            p04.call_export(self.k, self.handle, self.module, self.dll,
                            "Stage5ResolveDump", self.io, ipp.WAIT_TIMEOUT_MS)
            buffer = ctypes.create_string_buffer(check_mod.IO_SIZE)
            read = ctypes.c_size_t(0)
            self.k.ReadProcessMemory(self.handle, self.io, buffer,
                                     check_mod.IO_SIZE, ctypes.byref(read))
            return check_mod.unpack_io(buffer.raw)
        except Exception as exc:                                   # noqa: BLE001
            # Reported, never raised. Whether the process became unreachable is
            # a fact about the RUN, and a run that throws it away cannot say
            # when it happened or what state the game was in.
            return {"rc": self.CALL_FAILED, "error": "%s: %s"
                    % (type(exc).__name__, exc), "json": "", "done": 0,
                    "object_count": 0, "call_failed": True}

    def close(self):
        """Give the page back. Best effort: the process may already be gone,
        and a teardown that raised would hide the result of the run."""
        try:
            if self.io:
                self.k.VirtualFreeEx(self.handle, self.io, 0, ipp.MEM_RELEASE)
                self.io = None
            if self.handle:
                self.k.CloseHandle(self.handle)
                self.handle = None
        except Exception:                                          # noqa: BLE001
            pass


def close_game(timeout=45):
    subprocess.run(["taskkill", "/IM", "MISERY-Win64-Shipping.exe", "/F"],
                   capture_output=True, text=True)
    api = eri.Win32Api()
    for _ in range(timeout):
        time.sleep(1)
        try:
            eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
        except Exception:                                          # noqa: BLE001
            return True
    return False


def launch_to_menu(settle=50.0, timeout=300):
    """Start the game and stop at the main menu -- no save entry."""
    os.startfile(STEAM_RUN)
    api = eri.Win32Api()
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(2)
        try:
            eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
            time.sleep(settle)
            return True
        except Exception:                                          # noqa: BLE001
            continue
    return False


def start_gameplay_entry(out_dir):
    """Drive the ALREADY-RUNNING process from the menu into gameplay.

    ``--skip-restart`` is the whole point. The default cycle tears the game down
    and launches its own, which would throw away the injected runtime and make
    the transition unobservable: we would be comparing two processes, not
    watching one cross a level load. Reusing the live process means the resolver
    answering at the menu and the resolver answering in gameplay are the same
    resolver, in the same process, either side of a real content load.

    ITS OUTPUT GOES TO FILES, NOT TO PIPES, AND THAT IS NOT A STYLE CHOICE
    ---------------------------------------------------------------------
    The runner prints its whole cycle report -- 26 KB of JSON -- to stdout when
    it finishes. This caller cannot read that while it is sampling, because it
    is busy sampling; and a child writing 26 KB into a pipe nobody drains
    blocks forever once the pipe buffer fills. The child then never exits, so
    ``poll()`` never returns, so the sampling loop runs to its deadline with
    the game sitting in gameplay the whole time -- which on this game means the
    character starves and the next launch meets the death screen.

    That happened. Files have no such limit, so the child runs to completion
    and the loop ends when the work ends.
    """
    os.makedirs(out_dir, exist_ok=True)
    out = open(os.path.join(out_dir, "entry.stdout.txt"), "w",
               encoding="utf-8", errors="replace")
    err = open(os.path.join(out_dir, "entry.stderr.txt"), "w",
               encoding="utf-8", errors="replace")
    process = subprocess.Popen(
        [sys.executable,
         os.path.join(REPO, "research", "instruments", "runner", "runner.py"),
         "cycle", "--skip-restart", "--probe", "recon"],
        stdout=out, stderr=err, text=True)
    process._misery_logs = (out, err)                              # noqa: SLF001
    return process


def finish_gameplay_entry(process, out_dir):
    """Wait for the entry cycle and return what it wrote to stderr."""
    try:
        process.wait(timeout=300)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=60)
    for handle in getattr(process, "_misery_logs", ()):
        try:
            handle.close()
        except Exception:                                          # noqa: BLE001
            pass
    path = os.path.join(out_dir, "entry.stderr.txt")
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    return ""


def main(argv=None):
    # Line-buffered, unconditionally. The previous run was interrupted after
    # forty minutes and produced an empty log, because Python block-buffers
    # stdout when it is a pipe. Progress you cannot see is progress you cannot
    # resume from.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:                                              # noqa: BLE001
        pass

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--launches", type=int, default=3)
    a = ap.parse_args(argv)

    checks = []

    def check(label, ok, detail=""):
        checks.append({"check": label, "pass": bool(ok), "detail": str(detail)})
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", label,
                               "" if ok else "  -- %s" % detail))
        return bool(ok)

    internal = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
    # Exactly the resolver, its game-thread path, and the carrier. The managed
    # host and the CR-01C5 probe are deliberately NOT linked in: this artifact
    # exists to exercise resolution, and every extra translation unit in it is
    # something that could explain a result instead of the resolver.
    runtime = nb.build_dll(
        [os.path.join(internal, n) for n in
         ("Resolver.cpp", "ResolverDump.cpp", "ResolveOnGameThread.cpp",
          "UE54TickerCarrier.cpp")],
        RUNTIME_DLL)

    # The profile production reads, emitted for the installed executable.
    exe = os.path.join(r"D:\Games\Steam\steamapps\common\MISERY", "MISERY",
                       "Binaries", "Win64", "MISERY-Win64-Shipping.exe")
    build_id, engine = bindings_tool.engine_from_index(BUILD_KEY)
    profile = bindings_tool.emit(exe, build_id, BUILD_KEY, engine)

    report = {"stage": "5B", "phases": [], "runtime": runtime,
              "profile_build_id": profile["build"]["build_id"]}

    def save(verdict):
        """Write what is known so far. Called after every launch, so an
        interrupted run still says how far it got and where it stopped."""
        report["checks"] = checks
        report["passed"] = sum(1 for c in checks if c["pass"])
        report["failed"] = sum(1 for c in checks if not c["pass"])
        report["verdict"] = verdict
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, default=str)
            handle.write("\n")

    save("INCOMPLETE")
    ALL_ANCHORS = [k for k in check_mod.COMPARED if k != "row_struct_size"]
    # Measured, not assumed: these are the anchors the survey finds at the main
    # menu, i.e. the ones the engine has before any level is loaded.
    STARTUP_ANCHORS = [
        "transient_package", "datatable_class", "composite_class",
        "texture2d_class", "staticmesh_class", "actor_class",
        "cdo_gameplaystatics", "cdo_stringlib", "cdo_textlib", "cdo_syslib",
        "fn_spawn_object", "fn_conv_str_to_name", "fn_str_to_text",
        "fn_text_to_str", "fn_load_asset_blocking", "fn_soft_to_string",
    ]

    for launch in range(1, a.launches + 1):
        label = "launch %d" % launch
        print("\n=== %s: fresh start -> main menu ===" % label)
        close_game()
        if not check("%s: the game reached the main menu" % label,
                     launch_to_menu()):
            save("INCOMPLETE")
            continue

        injected = Injected(runtime, profile)

        # SURVEY first: resolve everything, fail nothing, and record what the
        # menu actually has. This is the measurement the phase assignment rests
        # on, repeated every run so the assignment cannot quietly go stale.
        survey = injected.resolve(check_mod.PHASE_SURVEY)
        content_present = False
        report["phases"].append({"launch": launch, "phase": "menu-survey",
                                 "result": survey})
        check("%s [menu]: the survey completed" % label, survey["rc"] == 0,
              survey["error"][:200])
        if survey["rc"] == 0:
            print("      (game thread: %d slices, LONGEST %dus at slice #%d | "
                  "walk %dus + "
                  "anchors %dus + validate %dus over %d objects; %d reads, "
                  "%d vq, %d cached, %d restart(s))"
                  % (survey["slices"], survey["max_slice_us"],
                     survey["max_slice_index"], survey["build_us"],
                     survey["resolve_us"],
                     survey["validate_us"], survey["object_count"],
                     survey["reads"], survey["vqueries"], survey["cache_hits"],
                     survey["restarts"]))
            report["phases"][-1]["cost"] = {
                k: survey[k] for k in ("queued_us", "build_us", "resolve_us",
                                       "reads", "vqueries", "cache_hits")}
            # The region cache is what makes a whole walk affordable on the game
            # thread. If it stopped working the walk would be one syscall per
            # field again, and the right response would be to chunk the walk --
            # so this must be visible rather than silently slow.
            check("%s [menu]: the per-walk region cache is doing its job -- far "
                  "fewer syscalls than reads" % label,
                  survey["reads"] > 0 and
                  survey["vqueries"] * 20 < survey["reads"],
                  "%d VirtualQuery for %d reads"
                  % (survey["vqueries"], survey["reads"]))
        if survey["rc"] == 0:
            answers = json.loads(survey["json"])
            report["phases"][-1]["missing"] = answers.get("missing")
            check("%s [menu]: every STARTUP anchor is present" % label,
                  all(int(answers[k]) != 0 for k in STARTUP_ANCHORS),
                  [k for k in STARTUP_ANCHORS if int(answers[k]) == 0])
            # WHAT IS PRESENT AT THE MENU IS NOT AN INVARIANT, AND ASSERTING IT
            # WAS WAS WRONG.
            # Two launches showed no item tables at the menu and a third, on the
            # same build with the same save, showed the ENTIRE content set
            # resolvable there with nothing loaded by the player. So it is
            # recorded rather than asserted, and only what actually holds is
            # checked below.
            content_present = (int(answers["item_list"]) != 0 and
                               int(answers["master_item_list"]) != 0)
            report["phases"][-1]["content_present_at_menu"] = content_present
            report["phases"][-1]["reached_phase"] = int(answers["reached_phase"])
            print("      (menu carries content: %s, reached phase %d)"
                  % (content_present, int(answers["reached_phase"])))

            # This IS invariant, on every launch: there is no player at the menu,
            # so the resolver must never claim gameplay there. A resolver that
            # did would let the runtime start item work with no inventory to
            # register against.
            check("%s [menu]: the resolver never claims gameplay at the menu"
                  % label, int(answers["reached_phase"]) < 2,
                  answers["reached_phase"])

        # Asking for STARTUP at the menu must succeed...
        startup = injected.resolve(check_mod.PHASE_STARTUP)
        check("%s [menu]: the startup phase resolves" % label,
              startup["rc"] == 0, startup["error"][:200])

        # ...and asking for CONTENT must be ANSWERED CONSISTENTLY with what the
        # survey just found -- which is the real property. When content is
        # absent the request must fail and name the phase; when the menu happens
        # to carry it, the request may succeed, and the anchors it returns are
        # then exactly the doomed ones the transition phase watches change.
        content = injected.resolve(check_mod.PHASE_CONTENT)
        if survey["rc"] == 0 and content_present:
            check("%s [menu]: content was present, so the content phase "
                  "resolved -- and these are the anchors the load will replace"
                  % label, content["rc"] == 0, content["error"][:160])
        else:
            check("%s [menu]: content was absent, so the content phase fails "
                  "with a named reason, not a guess" % label,
                  content["rc"] != 0 and "content phase" in content["error"],
                  content["error"][:160])

        # ...and gameplay likewise, for its own reason.
        play_at_menu = injected.resolve(check_mod.PHASE_GAMEPLAY)
        check("%s [menu]: the gameplay phase fails too" % label,
              play_at_menu["rc"] != 0, play_at_menu["error"][:160])

        # ---- the load transition, watched from inside ---------------------
        # Not "menu, then later gameplay". The save-entry machine runs in
        # another process while THIS loop keeps asking the resolver the same
        # question, so the level load is sampled while it is in flight. That is
        # the state the specification calls transitional, and the requirement is
        # that the resolver reports it rather than treating it as broken.
        print("\n=== %s: menu -> gameplay, sampled across the load ===" % label)
        entry_dir = os.path.join(os.path.dirname(os.path.abspath(a.out)),
                                 "entry-%d" % launch)
        entry = start_gameplay_entry(entry_dir)
        samples = []
        began = time.time()
        deadline = began + TRANSITION_TIMEOUT_S
        while time.time() < deadline:
            sample = injected.resolve(check_mod.PHASE_SURVEY)
            row = {"t": round(time.time() - began, 1), "rc": sample["rc"],
                   "error": sample["error"][:160]}
            if sample["rc"] == 0:
                seen = json.loads(sample["json"])
                row["reached_phase"] = int(seen["reached_phase"])
                row["anchors"] = {k: int(seen[k]) for k in ALL_ANCHORS}
                row["game_thread_id"] = sample["game_thread_id"]
                row["cost"] = cost_of(sample)
            samples.append(row)
            if entry.poll() is not None:
                break
            time.sleep(TRANSITION_POLL_S)
        err = finish_gameplay_entry(entry, entry_dir)
        # One more sample, AFTER the entry cycle has finished. The loop's last
        # sample was taken before its exit check, so without this the recorded
        # end state could be from a moment before gameplay settled -- and the
        # run would look like a resolver that stopped short when in fact the
        # sampler did.
        final = injected.resolve(check_mod.PHASE_SURVEY)
        if final["rc"] == 0:
            seen = json.loads(final["json"])
            samples.append({"t": round(time.time() - began, 1), "rc": 0,
                            "error": "", "reached_phase": int(seen["reached_phase"]),
                            "anchors": {k: int(seen[k]) for k in ALL_ANCHORS}})
        else:
            samples.append({"t": round(time.time() - began, 1),
                            "rc": final["rc"], "error": final["error"][:160]})
        report["phases"].append({"launch": launch, "phase": "transition",
                                 "samples": samples,
                                 "entry_returncode": entry.returncode,
                                 "entry_stderr": (err or "")[-400:]})
        if not check("%s: reached gameplay" % label, entry.returncode == 0,
                     (err or "")[-300:]):
            injected.close()
            save("INCOMPLETE")
            continue

        ok_samples = [r for r in samples if r["rc"] == 0]
        unreachable = [r for r in samples if r.get("call_failed")]
        answered_badly = [r for r in samples
                          if r["rc"] != 0 and not r.get("call_failed")]
        # Two different findings, kept apart. "We could not ask" is about the
        # process or the harness; "it answered badly" is about the resolver.
        # Reporting them as one number hides whichever is not happening.
        check("%s [transition]: the process stayed reachable for every sample"
              % label, not unreachable,
              [(r["t"], r["error"][:80]) for r in unreachable][:3])
        check("%s [transition]: the resolver answered at every sample it was "
              "asked -- absence is reported, never a hard failure" % label,
              not answered_badly and len(samples) >= 2,
              [(r["t"], r["error"][:80]) for r in answered_badly][:3])

        phases_seen = [r["reached_phase"] for r in ok_samples]
        check("%s [transition]: the phase never went backwards" % label,
              all(b >= a for a, b in zip(phases_seen, phases_seen[1:])),
              phases_seen)
        # Began before the player existed and ended after. NOT "began at
        # startup": a menu that already carries content starts this window at
        # phase 1, which launch 3 demonstrated and which is not a defect. What
        # must hold is that the window really spans the boundary being measured.
        check("%s [transition]: the sampling spanned the boundary -- began "
              "below gameplay and ended at gameplay" % label,
              bool(phases_seen) and phases_seen[0] < 2 and
              phases_seen[-1] == 2, phases_seen)

        # Engine-level identity must be INVARIANT across a level load: those
        # objects are not content and the load must not move them. An anchor
        # that changed here would mean the resolver had been reading something
        # transient and calling it an engine class.
        drifted = [k for k in STARTUP_ANCHORS
                   if len({r["anchors"][k] for r in ok_samples}) != 1]
        check("%s [transition]: every STARTUP anchor kept one identity across "
              "the whole load" % label, not drifted, drifted)

        # Content anchors DO change identity across this load, and that is the
        # game's design rather than a defect: measured on this build, each of
        # ItemList, MasterItemList, the RowStruct, the world item class, the SGK
        # CDO and the three Blueprint UFunctions holds one address while content
        # is loaded but the player is not in the world, and a different one once
        # gameplay is reached. The menu world's generation of that content is
        # destroyed and the game world's created.
        #
        # Each sample here is a FRESH resolution, so differing answers either
        # side of a destroy-and-recreate are correct. What would be a defect is
        # unbounded churn, a change WITHIN a phase, or instability once gameplay
        # is reached -- because that last one is the state the runtime actually
        # resolves in and uses. All three are checked.
        #
        # The consequence for the runtime is the reason this is measured at all:
        # a content pointer resolved before gameplay is DANGLING once the player
        # exists, so it must never be cached across that boundary.
        churn, within_phase = [], []
        for key in ALL_ANCHORS:
            live = [(r["reached_phase"], r["anchors"][key]) for r in ok_samples
                    if r["anchors"][key] != 0]
            if len({value for _phase, value in live}) > 2:
                churn.append(key)
            by_phase = {}
            for phase, value in live:
                by_phase.setdefault(phase, set()).add(value)
            for phase, values in sorted(by_phase.items()):
                if len(values) > 1:
                    within_phase.append("%s@phase%d" % (key, phase))
        check("%s [transition]: no anchor churned -- at most the one "
              "destroy-and-recreate the load performs" % label, not churn, churn)
        check("%s [transition]: no anchor changed identity WITHIN a phase; every "
              "change is at a phase boundary" % label,
              not within_phase, within_phase)

        play_samples = [r for r in ok_samples if r["reached_phase"] == 2]
        unstable = [k for k in ALL_ANCHORS
                    if len({r["anchors"][k] for r in play_samples}) > 1]
        check("%s [transition]: once gameplay is reached every anchor is "
              "constant -- the state the runtime resolves in and uses" % label,
              bool(play_samples) and not unstable,
              unstable or "no gameplay samples")

        # ---- gameplay, in the SAME process the menu was measured in --------
        play = injected.resolve(check_mod.PHASE_GAMEPLAY)
        report["phases"].append({"launch": launch, "phase": "gameplay",
                                 "result": play, "cost": cost_of(play)})
        if play["rc"] == 0:
            print("      (GAMEPLAY: %d slices, LONGEST %dus at slice #%d | "
                  "walk %dus + "
                  "anchors %dus + validate %dus over %d objects; %d reads, "
                  "%d vq, %d cached, %d restart(s), %d revalidation failure(s))"
                  % (play["slices"], play["max_slice_us"],
                     play["max_slice_index"], play["build_us"],
                     play["resolve_us"], play["validate_us"],
                     play["object_count"], play["reads"], play["vqueries"],
                     play["cache_hits"], play["restarts"],
                     play["revalidation_failures"]))
        check("%s [gameplay]: the resolver succeeded" % label, play["rc"] == 0,
              play["error"][:200])
        if play["rc"] == 0:
            answers = json.loads(play["json"])
            check("%s [gameplay]: the live player inventory resolved" % label,
                  bool(answers["player_inventory_present"]))
            check("%s [gameplay]: every anchor resolved" % label,
                  all(int(answers[k]) != 0 for k in ALL_ANCHORS),
                  [k for k in ALL_ANCHORS if int(answers[k]) == 0])
            check("%s [gameplay]: the resolver reports phase=gameplay" % label,
                  int(answers["reached_phase"]) == 2, answers["reached_phase"])

            # THE point of chunking. Not "the work finished" -- an unchunked walk
            # also finishes -- but that no single game-thread slice was long
            # enough for a player to see. The unchunked form cost 481ms here.
            check("%s [gameplay]: no single game-thread slice exceeded %dus"
                  % (label, MAX_SLICE_US),
                  0 < play["max_slice_us"] <= MAX_SLICE_US,
                  "longest slice %dus" % play["max_slice_us"])
            # And that it really was sliced. A budget silently ignored would show
            # up here as one enormous slice that still passed everything else.
            check("%s [gameplay]: the walk really was spread over many ticks"
                  % label, play["slices"] >= 10,
                  "%d slice(s)" % play["slices"])
            check("%s [gameplay]: every slot was examined at least once" % label,
                  play["objects_processed"] >= play["object_count"],
                  "processed %d, universe %d"
                  % (play["objects_processed"], play["object_count"]))
            check("%s [gameplay]: the phase did not move under the walk" % label,
                  play["completed_phase"] >= play["requested_phase"],
                  "requested %d, completed %d"
                  % (play["requested_phase"], play["completed_phase"]))
            check("%s [gameplay]: nothing published failed live re-validation"
                  % label, play["revalidation_failures"] == 0,
                  play["revalidation_failures"])

            # DEATH/RESPAWN, structurally. The runner will not kill the player
            # to reach the death screen -- saveentry.UI_STATES records that
            # decision and its reason, and it stands. What CAN be measured
            # without making a gameplay decision is the thing a death would
            # threaten: the discriminator is the Outer, the Outer is the
            # CONTROLLER, and the controller is exactly the object measured to
            # survive when BP_SGKMasterCharacter_C drops to zero. A dead pawn
            # therefore cannot invalidate this anchor -- it was never hung off
            # the pawn.
            outer = int(answers["player_inventory_outer"])
            check("%s [gameplay]: the inventory anchor hangs off the controller, "
                  "not the pawn, so a death cannot invalidate it" % label,
                  outer != 0 and outer != int(answers["player_inventory"]),
                  "outer=0x%x" % outer)

            # Determinism, measured on the ANCHORS. The whole JSON also carries
            # object_count, which a live game changes continuously -- comparing
            # that would measure the game, not the resolver.
            again = injected.resolve(check_mod.PHASE_GAMEPLAY)
            same = (again["rc"] == 0 and
                    all(json.loads(again["json"])[k] == answers[k]
                        for k in ALL_ANCHORS))
            check("%s [gameplay]: two resolutions of one process agree on every "
                  "anchor" % label, same, "repeat rc=%s" % again["rc"])

            # THE claim this stage's invocation change rests on. Resolution is
            # supposed to happen on the game thread; the only way to test that
            # is for the code to report which thread ran it. Every resolution in
            # this process -- menu, mid-load, gameplay -- must name the SAME
            # non-zero thread, because a walk landing on whichever caller asked
            # is exactly the model that was removed.
            threads = {survey.get("game_thread_id"),
                       startup.get("game_thread_id"),
                       play.get("game_thread_id"),
                       again.get("game_thread_id")}
            threads |= {r["game_thread_id"] for r in ok_samples
                        if r.get("game_thread_id")}
            threads.discard(None)
            threads.discard(0)
            check("%s: every resolution ran on ONE engine thread, not on the "
                  "caller's" % label, len(threads) == 1, sorted(threads))
            report["phases"].append({"launch": launch, "phase": "threading",
                                     "thread_ids": sorted(threads)})

        injected.close()
        save("INCOMPLETE")

    close_game()
    failed = sum(1 for c in checks if not c["pass"])
    save("PASS" if failed == 0 else "FAIL")
    print("\n%s -- %d passed, %d failed -> %s"
          % (report["verdict"], report["passed"], report["failed"], a.out))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
