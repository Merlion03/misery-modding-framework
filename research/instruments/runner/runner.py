#!/usr/bin/env python3
"""The unattended MISERY research runner.

    runner.py cycle --probe <name>

One cycle is the loop this project has been doing by hand between every probe:

    graceful probe shutdown -> close MISERY -> prove the old process is gone
      -> container cleanup/staging -> container + install integrity
      -> launch through Steam -> find the NEW pid -> fingerprint it
      -> wait for the runtime to be inspectable -> reach the configured save
      -> PROVE the player runtime from live objects -> start the probe

WHAT THIS IS NOT
----------------
Not a production loader, not a mod loader, not a new gameplay capability. It
introduces no ABI primitive, calls no UFunction, and writes nothing into the
game process. Every game-side read it performs already existed in
``research/instruments/eri`` or in the CR-01C controllers; this file is
orchestration around them plus the readiness invariants in ``readiness.py``.

The Steam installation stays read-only (D-01). The only directory this runner
writes into that is not inside the repository is
``%LOCALAPPDATA%\\MISERY\\Saved\\Paks``, and every such write goes through
``tools/inventory/pathguard.check_output_path`` first.

FAIL CLOSED, EVERYWHERE
-----------------------
Wrong build, wrong process count, unmountable container, unexpected leftover
container, install mismatch, timeout, missing player, wrong authority, wrong
screen, a SuperStruct chain that does not terminate at UObject -- each of these
stops the cycle with a named reason and a written report. None of them degrade
into "probably fine": a runner that guesses is worse than one that stops,
because its output looks exactly like a correct run.

ADDRESSES ARE NEVER REUSED ACROSS A RESTART
-------------------------------------------
Structurally, not by discipline: ``session.py`` can only carry non-address
fields across a process boundary, and every address this cycle uses is resolved
against the pid it just found, after the build identity of that pid's own image
has been confirmed.

EVIDENCE PER CYCLE
------------------
``research/instrument-runs/<timestamp>/`` gets ``manifest.json`` (the project's
existing instrument-run schema, written by ``ipp.write_manifest``),
``cycle.json`` (every phase, its verdict, its facts), ``containers.json``, and
``verify_install_before/after.json``. Nothing about a cycle lives only in a
terminal.
"""
import argparse
import json
import os
import subprocess
import sys
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
RUNNER_DIR = os.path.dirname(os.path.abspath(__file__))
for _path in (RUNNER_DIR,
              os.path.join(REPO_ROOT, "research", "instruments", "eri"),
              os.path.join(REPO_ROOT, "research", "instruments", "ipp"),
              os.path.join(REPO_ROOT, "tools", "inventory")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import eri                      # noqa: E402
import ipp_controller as ipp    # noqa: E402
import cr01c3_recon as recon    # noqa: E402
import probe_teardown           # noqa: E402

import containers               # noqa: E402
import lifecycle                # noqa: E402
import readiness                # noqa: E402
import saveentry                # noqa: E402
import session as session_state  # noqa: E402

TOOL_VERSION = "misery-runner-0.1.0"

# Read-only ERI capabilities the cycle exercises. The runner adds none of its
# own: it is orchestration, and its manifest says so.
RUNNER_CAPABILITIES = ["I-01", "I-02", "I-03", "I-04", "I-06"]
DEFAULT_CONFIG = os.path.join(RUNNER_DIR, "runner-config.json")

# The probe registry. Fail-closed BY CONSTRUCTION, in the same spirit as
# ipp_controller's own ALLOWED_FUNCTION_NAMES: a probe the runner can start is
# one that is named here, not one whose path a caller can pass in. `armed`
# entries mutate live game state and are refused unless --allow-armed-probe is
# given AND the escalation they belong to is already recorded (plan.md 8.4);
# the runner does not create escalations, it only refuses to bypass them.
PROBES = {
    "recon": {
        "script": "research/instruments/ipp/cr01c3_recon.py",
        "argv": ["--out", "{run_dir}/recon.json"],
        "armed": False,
        "what": "CR-01C3 read-only recon: inventory classes, live instances, authority",
    },
    "eri-i01": {
        "script": "research/instruments/eri/eri.py",
        "argv": ["--run-dir", "{run_dir}"],
        "armed": False,
        "what": "ERI I-01: process identity, base address, image size",
    },
    "eri-objects": {
        "script": "research/instruments/eri/eri.py",
        "argv": ["--run-i02", "--run-i03", "--run-dir", "{run_dir}"],
        "armed": False,
        "what": "ERI I-02/I-03: GUObjectArray census and FNamePool",
    },
}


class CycleFailed(Exception):
    """A named, reported stop. Carries the phase so the report can say where."""

    def __init__(self, phase, reason):
        super().__init__("%s: %s" % (phase, reason))
        self.phase = phase
        self.reason = reason


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------

def load_config(path=None):
    path = path or DEFAULT_CONFIG
    if not os.path.isfile(path):
        raise CycleFailed("config", "no runner config at %s" % path)
    with open(path, encoding="utf-8") as f:
        config = json.load(f)
    for required in ("build", "save_entry", "containers", "expect"):
        if required not in config:
            raise CycleFailed("config", "runner config is missing %r" % required)
    return config


# --------------------------------------------------------------------------
# phases
# --------------------------------------------------------------------------

def phase_teardown(config, state, note):
    """Step 1-3: stop what we loaded, close the game, prove it is gone.

    The graceful probe shutdown is attempted ONLY when this runner has the
    remote addresses that make it meaningful -- i.e. when the recorded process
    is still the same live process. Without them the module is left where it
    is and the report says so: the process is about to die anyway, and dying
    takes the ticker, the dispatcher and the module together (LOG-0093 finding
    9). What is never done is a FreeLibrary on a module whose stop handshake
    was not confirmed; that is the failure probe_teardown.py exists to prevent.
    """
    out = {"probe_shutdown": None, "closed": [], "proved_gone": None}
    live = lifecycle.find_processes()
    out["live_before"] = live
    old_pids = [p["pid"] for p in live]

    if state.loaded_probe_module:
        if state.pid in old_pids and state.remote_module_base and state.remote_io:
            out["probe_shutdown"] = {
                "attempted": False,
                "reason": "a graceful in-process handshake needs the loading controller's "
                          "own IO reader; the runner does not synthesize one. The module "
                          "dies with the process below.",
                "module": state.loaded_probe_module}
            note.append("probe %s still loaded in pid %s; it will die with the process"
                        % (state.loaded_probe_module, state.pid))
        else:
            out["probe_shutdown"] = {
                "attempted": False,
                "reason": "recorded probe module belongs to a process that is no longer "
                          "live; nothing to shut down",
                "module": state.loaded_probe_module}

    for process in live:
        out["closed"].append(lifecycle.close_process(process["pid"], note=note))
    out["proved_gone"] = lifecycle.prove_gone(
        old_pids, timeout_s=config.get("timeouts", {}).get("prove_gone_s", 30), note=note)
    return out


def phase_containers(config, run_dir, note, dry_run=False):
    """Step 4-5: cleanup/staging, then prove every staged container is coherent."""
    spec = config["containers"]
    out = {"profile": spec, "applied": None, "check": None}
    stage_dir = spec.get("stage_dir") or containers.DEFAULT_STAGE_DIR
    if spec.get("apply"):
        out["applied"] = containers.apply_profile(spec, stage_dir=stage_dir, dry_run=dry_run)
        note.append("staging applied: %d removed, %d staged"
                    % (len(out["applied"]["removed"]), len(out["applied"]["staged"])))
    check = containers.check_stage_dir(stage_dir, spec.get("expect"))
    out["check"] = check
    report_path = os.path.join(run_dir, "containers.json")
    with open(report_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(check, f, indent=2, sort_keys=True)
        f.write("\n")
    out["report_artifact"] = os.path.relpath(report_path, REPO_ROOT).replace(os.sep, "/")
    if not check["consistent"]:
        raise CycleFailed("containers", "staged containers are not consistent: %s"
                          % json.dumps({"unexpected": check["unexpected_containers"],
                                        "missing": check["missing_containers"],
                                        "unmountable": [c["name"] for c in check["containers"]
                                                        if not c["mountable"]]}))
    note.append("containers consistent: %r" % check["present_containers"])
    return out


def phase_install_integrity(run_dir, tag, note, mode="fast"):
    """Step 5b: the installation itself is unchanged (D-01 layer 3)."""
    summary = ipp.run_verify_install(run_dir, tag, mode=mode)
    note.append("verify_install %s: %s (%d serious, %d benign)"
                % (tag, summary["result"], summary["serious_count"], summary["benign_count"]))
    if summary["result"] == "mismatch":
        raise CycleFailed("install-integrity",
                          "verify_install reports %d serious findings (%s)"
                          % (summary["serious_count"], summary.get("report_artifact")))
    return summary


def phase_launch(config, note, excluded_pids):
    """Step 6-8: launch through Steam, find the NEW pid, fingerprint it."""
    timeouts = config.get("timeouts", {})
    requested_at = lifecycle.launch_through_steam(note=note)
    process = lifecycle.wait_for_new_process(
        excluded_pids=excluded_pids, requested_at=requested_at,
        timeout_s=timeouts.get("new_process_s", 240), note=note)
    fingerprint = lifecycle.fingerprint_process(
        ipp, process, expected_sha256=config["build"]["expected_sha256"], note=note)
    return {"requested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(requested_at)),
            "process": process, "fingerprint": fingerprint}


def phase_runtime_ready(config, api, handle, base, size, note):
    """Step 9: the runtime is inspectable. A measured predicate, never a sleep."""
    timeouts = config.get("timeouts", {})
    return readiness.wait_runtime_inspectable(
        eri, api, handle, base, size,
        timeout_s=timeouts.get("runtime_inspectable_s", 300),
        interval_s=timeouts.get("runtime_poll_interval_s", 2.0),
        min_objects=config.get("expect", {}).get("min_objects_started", 50000),
        note=note)


def _gameplay_snapshot(api, handle, base, size, config, note):
    """One full read-only census + gameplay verdict."""
    namepool, objects = recon.universe(api, handle, base, size)
    verdict = readiness.prove_gameplay(eri, api, handle, objects, namepool=namepool,
                                       expect=config.get("expect", {}), note=note)
    return namepool, objects, verdict


def phase_save_entry_and_proof(config, api, handle, base, size, pid, note):
    """Step 10-11: reach the configured save, then PROVE the player runtime.

    Order matters and is deliberate: the strategy acts, and the proof runs
    afterwards on a fresh census. The proof also runs BEFORE the strategy, so a
    cycle that is already in the session (``--save-entry none``, or a strategy
    that happened to be unnecessary) is not made to press keys at a live game.
    """
    timeouts = config.get("timeouts", {})
    entry_config = config["save_entry"]

    namepool, objects, verdict = _gameplay_snapshot(api, handle, base, size, config, note)
    if verdict["ready"]:
        note.append("already in the configured session before any entry action")
        return {"entry": {"strategy": "none", "acted": False,
                          "note": "the session was already loaded"},
                "proof": verdict, "namepool": namepool, "objects": objects}

    window = lifecycle.find_main_window(pid)

    census = {"namepool": None}
    expected_start = None
    for process in lifecycle.find_processes():
        if process["pid"] == pid:
            expected_start = process["start_time"]

    def check_alive():
        """Did the game die under us? Answered before every census.

        Without this, a crash surfaces as an unreadable-memory error from deep
        inside the object walk -- true, but it reads like a tool defect. A crash
        during a save load is a normal thing to happen to this game, and the
        cycle should say "the game exited" in those words. The start time is
        compared too: a pid that is alive but is a DIFFERENT process is a crash
        plus a Steam restart, not a survivor.
        """
        identity = lifecycle.process_identity(pid)
        if identity is None:
            raise CycleFailed("crash", "the game process (pid %d) exited during the "
                                       "cycle. Look in the Saved/Crashes directory under "
                                       "%%LOCALAPPDATA%%/MISERY for a report; the next "
                                       "cycle starts clean." % pid)
        if expected_start and identity[0] and identity[0] != expected_start:
            raise CycleFailed("crash", "pid %d is no longer the process this cycle "
                                       "launched (start %s, now %s)"
                              % (pid, expected_start, identity[0]))

    def snapshot():
        """One fresh read-only census. The state machine classifies from this."""
        check_alive()
        census["namepool"], objects = recon.universe(api, handle, base, size)
        return objects

    def is_gameplay(objects):
        return readiness.prove_gameplay(eri, api, handle, objects,
                                        namepool=census["namepool"],
                                        expect=config.get("expect", {}))["ready"]

    expect = config.get("expect", {})
    context = {
        "note": note,
        "hwnd": window[0] if window else None,
        "snapshot": snapshot,
        "is_gameplay": is_gameplay,
        "save_slot": expect.get("save_slot"),
        "save_dir": expect.get("save_dir"),
        "save_row_geometry": entry_config.get("save_row_geometry"),
        "await_condition": lambda condition, timeout_s, label: _await_condition(
            condition, api, handle, base, size, config, note,
            timeout_s=timeout_s, label=label),
    }
    strategy = saveentry.build(entry_config.get("strategy", "manual"), entry_config)
    entry = strategy.run(context)

    deadline = time.time() + timeouts.get("save_entry_s", 600)
    last = verdict
    while time.time() < deadline:
        check_alive()
        namepool, objects, last = _gameplay_snapshot(api, handle, base, size, config, note)
        if last["ready"]:
            return {"entry": entry, "proof": last, "namepool": namepool, "objects": objects}
        time.sleep(timeouts.get("gameplay_poll_interval_s", 5.0))
    raise CycleFailed("gameplay-proof",
                      "the player runtime invariants never held within %ds. Last reasons: %s"
                      % (timeouts.get("save_entry_s", 600), "; ".join(last["reasons"])))


def _await_condition(condition, api, handle, base, size, config, note, *, timeout_s, label):
    """Poll the live graph for one declared condition from a save-entry step."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if "objects_at_least" in condition:
            reading = readiness.probe_runtime_once(eri, api, handle, base, size)
            if reading["num_elements"] >= int(condition["objects_at_least"]):
                note.append("%s: object count reached %d" % (label, reading["num_elements"]))
                return True
        elif "object_named" in condition:
            _np, objects = recon.universe(api, handle, base, size)
            wanted = condition["object_named"]
            if any(r.get("name_text") == wanted for r in objects.values() if r.get("valid")):
                note.append("%s: live object named %r appeared" % (label, wanted))
                return True
        elif condition.get("settle"):
            readiness.wait_runtime_inspectable(
                eri, api, handle, base, size, timeout_s=max(10, int(timeout_s)),
                min_objects=config.get("expect", {}).get("min_objects_started", 50000),
                note=note)
            return True
        else:
            raise CycleFailed("save-entry", "unknown await condition %r" % (condition,))
        time.sleep(2.0)
    raise CycleFailed("save-entry", "%s: condition %r never held within %ds"
                      % (label, condition, timeout_s))


def phase_probe(name, run_dir, note, *, allow_armed=False):
    """Step 12: start the requested probe as its own process.

    A separate process on purpose: the probe controllers each own their run
    directory, their manifest and their own escalation record, and the runner
    must not become a place where those get bypassed by being imported.
    """
    entry = PROBES.get(name)
    if entry is None:
        raise CycleFailed("probe", "unknown probe %r (registered: %s)"
                          % (name, ", ".join(sorted(PROBES))))
    if entry["armed"] and not allow_armed:
        raise CycleFailed("probe",
                          "probe %r mutates live game state and is refused without "
                          "--allow-armed-probe and its own recorded escalation (plan.md 8.4)"
                          % name)
    script = os.path.join(REPO_ROOT, entry["script"])
    argv = [arg.format(run_dir=run_dir.replace(os.sep, "/")) for arg in entry["argv"]]
    command = [sys.executable, script] + argv
    note.append("starting probe %r: %s" % (name, " ".join(command)))
    result = subprocess.run(command, capture_output=True, text=True, cwd=REPO_ROOT)
    stdout_path = os.path.join(run_dir, "probe-%s.stdout.txt" % name)
    stdout = result.stdout or ""

    # Most of these probes print the same JSON they also write as their own
    # artifact. Capturing it again doubles the run directory for nothing: the
    # recon probe alone produced two byte-identical 1.6 MB files. When the
    # captured stdout is exactly a file the probe wrote into this run
    # directory, record a pointer to it instead of a second copy. Evidence is
    # not lost -- it is named once instead of twice.
    duplicate_of = None
    for sibling in sorted(os.listdir(run_dir)):
        sibling_path = os.path.join(run_dir, sibling)
        if sibling.startswith("probe-") or not os.path.isfile(sibling_path):
            continue
        try:
            with open(sibling_path, encoding="utf-8") as f:
                if f.read() == stdout:
                    duplicate_of = sibling
                    break
        except (OSError, UnicodeDecodeError):
            continue

    with open(stdout_path, "w", encoding="utf-8", newline="\n") as f:
        if duplicate_of:
            f.write("stdout was byte-identical to %s, which this probe wrote itself.\n"
                    "Not duplicated here; read that file.\n" % duplicate_of)
        else:
            f.write(stdout)
        if result.stderr:
            f.write("\n--- stderr ---\n" + result.stderr)
    return {"probe": name, "what": entry["what"], "command": command,
            "returncode": result.returncode,
            "stdout_duplicate_of": duplicate_of,
            "stdout_artifact": os.path.relpath(stdout_path, REPO_ROOT).replace(os.sep, "/")}


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def _new_run_dir(explicit=None):
    run_id = (explicit and os.path.basename(explicit)) or \
        time.strftime("%Y-%m-%dT%H%M%SZ-runner", time.gmtime())
    run_dir = explicit or os.path.join(REPO_ROOT, "research", "instrument-runs", run_id)
    os.makedirs(run_dir, exist_ok=True)
    return run_dir


def _write_cycle_report(run_dir, report):
    path = os.path.join(run_dir, "cycle.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=2, sort_keys=True, default=str)
        f.write("\n")
    return os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")


def cmd_cycle(args):
    config = load_config(args.config)
    run_dir = _new_run_dir(args.run_dir)
    note = []
    report = {"tool_version": TOOL_VERSION, "run_id": os.path.basename(run_dir),
              "probe": args.probe, "phases": {}, "verdict": "INCOMPLETE"}
    state_path = args.session_state or session_state.default_path(REPO_ROOT)
    state, extra, why = session_state.load(state_path, lifecycle.process_identity)
    report["session_state"] = {"path": state_path, "did_not_apply_because": why,
                               "carried": state.to_dict()}
    artifacts = []
    verify_before = verify_after = None
    handle = None
    exit_code = 0
    try:
        if args.skip_restart:
            note.append("--skip-restart: reusing the live process, no teardown or launch")
            live = lifecycle.find_processes()
            if len(live) != 1:
                raise CycleFailed("reuse", "expected exactly one live MISERY process, found %d"
                                  % len(live))
            process = live[0]
            fingerprint = lifecycle.fingerprint_process(
                ipp, process, expected_sha256=config["build"]["expected_sha256"], note=note)
            report["phases"]["launch"] = {"process": process, "fingerprint": fingerprint,
                                          "reused": True}
        else:
            report["phases"]["teardown"] = phase_teardown(config, state, note)
            verify_before = phase_install_integrity(run_dir, "before", note,
                                                    mode=args.verify_mode)
            if verify_before.get("report_artifact"):
                artifacts.append(verify_before["report_artifact"])
            report["phases"]["containers"] = phase_containers(config, run_dir, note,
                                                              dry_run=args.dry_run_staging)
            artifacts.append(report["phases"]["containers"]["report_artifact"])
            excluded = [p["pid"] for p in report["phases"]["teardown"]["live_before"]]
            report["phases"]["launch"] = phase_launch(config, note, excluded)

        process = report["phases"]["launch"]["process"]
        pid = process["pid"]

        api = eri.Win32Api()
        i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
        if i01["pid"] != pid:
            raise CycleFailed("identity", "ERI found pid %d but this cycle launched %d"
                              % (i01["pid"], pid))
        base, size = i01["base_address"], i01["image_size_bytes"]
        report["phases"]["address_space"] = {
            "pid": pid, "base_address": "0x%x" % base, "image_size_bytes": size,
            "note": "resolved in THIS process after its own build identity was confirmed; "
                    "no address from any previous process is used"}
        handle = eri.open_process_read_only(api, pid)

        report["phases"]["runtime_ready"] = phase_runtime_ready(
            config, api, handle, base, size, note)
        gameplay = phase_save_entry_and_proof(config, api, handle, base, size, pid, note)
        report["phases"]["save_entry"] = gameplay["entry"]
        report["phases"]["gameplay_proof"] = {"ready": gameplay["proof"]["ready"],
                                              "reasons": gameplay["proof"]["reasons"],
                                              "facts": gameplay["proof"]["facts"]}
        report["verdict"] = "READY_FOR_PROBE"
        note.append("READY_FOR_PROBE")

        if args.probe:
            report["phases"]["probe"] = phase_probe(args.probe, run_dir, note,
                                                    allow_armed=args.allow_armed_probe)
            artifacts.append(report["phases"]["probe"]["stdout_artifact"])
            report["verdict"] = ("PROBE_STARTED"
                                 if report["phases"]["probe"]["returncode"] == 0
                                 else "PROBE_FAILED")

        session_state.save(state_path,
                           session_state.ProcessScopedState(
                               pid=pid, start_time=process["start_time"],
                               exe_path=process["exe_path"],
                               build_sha256=report["phases"]["launch"]["fingerprint"]["observed_sha256"],
                               base_address=base, image_size_bytes=size),
                           extra={"last_run_id": os.path.basename(run_dir),
                                  "last_verdict": report["verdict"]})
    except (CycleFailed, lifecycle.LifecycleError, readiness.NotReady,
            saveentry.SaveEntryError, containers.ContainerError, ipp.Blocked,
            eri.EriError) as exc:
        report["verdict"] = "BLOCKED"
        report["blocked_reason"] = str(exc)
        report["blocked_phase"] = getattr(exc, "phase", None)
        note.append("BLOCKED: %s" % exc)
        exit_code = 2
    finally:
        if handle is not None:
            try:
                eri.Win32Api().close_handle(handle)
            except Exception:                          # noqa: BLE001
                pass
        if not args.skip_restart and lifecycle.find_processes():
            try:
                verify_after = phase_install_integrity(run_dir, "after", note,
                                                       mode=args.verify_mode)
                if verify_after.get("report_artifact"):
                    artifacts.append(verify_after["report_artifact"])
            except CycleFailed as exc:
                note.append("post-cycle install check: %s" % exc)
                verify_after = None
        report["note"] = note
        artifacts.append(_write_cycle_report(run_dir, report))
        # The ERI capabilities this cycle actually exercised, from the closed
        # vocabulary research/schema/instrument-run-manifest.schema.json defines.
        # An earlier draft invented "RUNNER-CYCLE" and the validator rightly
        # rejected it: the runner is not a new capability, it is orchestration
        # over I-01 (process identity), I-02/I-03 (GUObjectArray + FNamePool),
        # I-04 (the object-universe walk recon.universe performs) and I-06 (the
        # FProperty decoder that resolves AController::Pawn). Naming those is
        # both truthful and inside the vocabulary.
        ipp.write_manifest(run_dir, arguments=sys.argv[1:],
                           capabilities_enabled=RUNNER_CAPABILITIES,
                           build_sha256=config["build"]["expected_sha256"],
                           verify_before=verify_before, verify_after=verify_after,
                           artifacts=artifacts, instrument_level="eri")
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    print("\n%s" % report["verdict"], file=sys.stderr)
    return exit_code


def cmd_status(args):
    """Read-only: what is running, what is staged, what the session state says."""
    config = load_config(args.config) if os.path.isfile(args.config or DEFAULT_CONFIG) else {}
    state_path = args.session_state or session_state.default_path(REPO_ROOT)
    state, extra, why = session_state.load(state_path, lifecycle.process_identity)
    out = {
        "steam_running": lifecycle.steam_is_running(),
        "misery_processes": lifecycle.find_processes(),
        "session_state": {"path": state_path, "did_not_apply_because": why,
                          "process": state.to_dict(), "extra": extra},
        "containers": containers.check_stage_dir(
            (config.get("containers") or {}).get("stage_dir"),
            (config.get("containers") or {}).get("expect")),
        "probes": {name: entry["what"] + (" [ARMED]" if entry["armed"] else "")
                   for name, entry in PROBES.items()},
    }
    print(json.dumps(out, indent=2, sort_keys=True, default=str))
    return 0


def cmd_ready(args):
    """Prove the gameplay invariants against the process that is running now."""
    config = load_config(args.config)
    note = []
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    handle = eri.open_process_read_only(api, i01["pid"])
    try:
        namepool, objects = recon.universe(api, handle, i01["base_address"],
                                           i01["image_size_bytes"])
        verdict = readiness.prove_gameplay(eri, api, handle, objects, namepool=namepool,
                                           expect=config.get("expect", {}), note=note)
    finally:
        api.close_handle(handle)
    verdict["note"] = note
    verdict["pid"] = i01["pid"]
    print(json.dumps(verdict, indent=2, sort_keys=True, default=str))
    return 0 if verdict["ready"] else 1


def cmd_calibrate(args):
    """Rung 1 of the save-entry ladder, answered with measurements.

    Against whatever state the game is in right now, record: the live object
    census, which known non-session state (if any) we are in, the gameplay
    verdict with its reasons, and EVERY UFunction carrying FUNC_Exec -- the
    complete list of console commands this build supports. That list is the
    evidence for or against a supported continue mechanism; a keyboard sequence
    should only be written after it comes back without one.
    """
    config = load_config(args.config)
    note = []
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    handle = eri.open_process_read_only(api, i01["pid"])
    run_dir = _new_run_dir(args.run_dir)
    out = {"pid": i01["pid"], "run_id": os.path.basename(run_dir)}
    try:
        namepool, objects = recon.universe(api, handle, i01["base_address"],
                                           i01["image_size_bytes"])
        out["objects"] = len(objects)
        out["gameplay"] = readiness.prove_gameplay(eri, api, handle, objects,
                                                   namepool=namepool,
                                                   expect=config.get("expect", {}), note=note)
        window = lifecycle.find_main_window(i01["pid"])
        out["window"] = {"hwnd": "0x%x" % window[0], "title": window[1]} if window else None
        out["session_interactive"] = saveentry.session_is_interactive()
        if args.exec_commands:
            out["exec_commands"] = saveentry.find_exec_commands(
                eri, recon, api, handle, namepool, objects)
            out["exec_command_count"] = len(out["exec_commands"])
    finally:
        api.close_handle(handle)
    out["note"] = note
    path = os.path.join(run_dir, "calibrate.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2, sort_keys=True, default=str)
        f.write("\n")
    out["artifact"] = os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")
    print(json.dumps(out, indent=2, sort_keys=True, default=str))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="runner.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--session-state", default=None)
    parser.add_argument("--run-dir", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    cycle = sub.add_parser("cycle", help="the full teardown -> launch -> ready -> probe cycle")
    cycle.add_argument("--probe", default=None,
                       help="registered probe to start once READY_FOR_PROBE is reached")
    cycle.add_argument("--allow-armed-probe", action="store_true",
                       help="permit a probe that mutates live game state (needs its own ESC record)")
    cycle.add_argument("--skip-restart", action="store_true",
                       help="reuse the running process; no teardown, no relaunch, no staging")
    cycle.add_argument("--dry-run-staging", action="store_true",
                       help="report the staging actions without performing them")
    cycle.add_argument("--verify-mode", choices=("fast", "full"), default="fast")
    cycle.set_defaults(func=cmd_cycle)

    status = sub.add_parser("status", help="read-only view of processes, containers, state")
    status.set_defaults(func=cmd_status)

    ready = sub.add_parser("ready", help="prove the gameplay invariants against the live process")
    ready.set_defaults(func=cmd_ready)

    calibrate = sub.add_parser("calibrate",
                               help="measure the current screen state and the supported console commands")
    calibrate.add_argument("--exec-commands", action="store_true",
                           help="enumerate every live UFunction carrying FUNC_Exec (slow)")
    calibrate.set_defaults(func=cmd_calibrate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
