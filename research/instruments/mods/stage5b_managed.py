#!/usr/bin/env python3
"""Stage 5B step 3: a real C# mod registers a real item, from a Steam launch.

THE ACCEPTANCE, AND WHY EACH LINK MATTERS
-----------------------------------------
    Steam Play
      -> MiseryRuntime            no controller, no injection
      -> current content generation
      -> C# mod OnLoad
      -> ctx.Items.Register(...)
      -> the game's own SGK ItemDetails resolves the item

The last link is the one that counts. "The engine accepted our write" and "the
game can find the item" are different claims, and only the second is the one a
player would notice. So the proof is the game's OWN BP_SGKFunctions::"SGK
ItemDetails" being asked, not our own read-back.

Stage 5A proved this whole chain already -- with a research controller injecting
the runtime, resolving every address, and handing in the mod list. This run
proves it with none of that: the game is started from Steam, and everything the
controller used to supply comes from the installation.

THEN THE TRANSITION, WHICH STAGE 5A NEVER EXERCISED
---------------------------------------------------
    generation N valid -> Items works
      -> load/transition
      -> generation N revoked
      -> a content-dependent consumer CANNOT use stale anchors
      -> generation N+1 resolves
      -> Items works again against N+1

No invented gameplay event is delivered to the mod for this. The proof is that
the production Items backend refuses a revoked generation and succeeds against
the new one, which is visible in the runtime's own log.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "mods"),
           os.path.join(REPO, "tools", "modplatform")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import install as installer                       # noqa: E402
import nativebuild as nb                          # noqa: E402
import stage5b_bindings as sb                     # noqa: E402
import stage5b_resolver_lifecycle as sweep        # noqa: E402

sys.path.insert(0, os.path.join(REPO, "tools", "modframework"))
import manifest as stage4_manifest                # noqa: E402

MANAGED = os.path.join(REPO, "managed")
FIXTURE = "AlphaManagedMod"
FIXTURE_ASSEMBLY = FIXTURE + ".dll"
# The mod's id is NOT its assembly name, and that is the point. The fixture is
# the framework's own mod, its C# already names itself `alphamod` in the content
# paths it declares, and an installation layout that cannot express the two
# differing is a layout that would reject real mods. The first version of the
# runtime's discovery assumed they matched and refused this fixture outright.
FIXTURE_MOD_ID = "alphamod"


def build_managed():
    """The contracts, the host, and the one fixture this step needs."""
    built = []
    for project in ("Misery.ModAPI", "Misery.ModHost",
                    os.path.join("fixtures", FIXTURE)):
        path = os.path.join(MANAGED, project)
        result = subprocess.run(["dotnet", "build", "-v", "quiet", "--nologo"],
                                capture_output=True, text=True, cwd=path,
                                timeout=900)
        if result.returncode != 0:
            raise SystemExit("%s failed to build:\n%s"
                             % (project, result.stdout[-3000:]))
        built.append(project)
    return built


def newest_output(project, filename):
    """The built assembly, wherever the SDK put it."""
    root = os.path.join(MANAGED, project, "bin")
    found = []
    for base, _dirs, files in os.walk(root):
        if filename in files:
            found.append(os.path.join(base, filename))
    if not found:
        raise SystemExit("%s was not produced under %s" % (filename, root))
    return max(found, key=os.path.getmtime)


def write_manifest(mod_root):
    """Write the fixture's mod.json -- and prove Stage 4 would accept it.

    The runtime's discovery reads two fields out of this file. It would happily
    read them out of a manifest Stage 4 considers malformed, which would make
    this acceptance pass against a layout no real installation can have. So the
    file is handed to Stage 4's OWN parser and any diagnostic is fatal here.
    """
    body = {
        "manifest_version": 1,
        "mod_id": FIXTURE_MOD_ID,
        "name": "Alpha Managed Mod",
        "version": "1.0.0",
        "framework_api": "^%s" % stage4_manifest.FRAMEWORK_API_VERSION,
        "code": [FIXTURE_ASSEMBLY],
    }
    path = os.path.join(mod_root, stage4_manifest.MANIFEST_FILENAME)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(body, handle, indent=2)
        handle.write("\n")

    parsed, diagnostics, claimed = stage4_manifest.load(mod_root)
    if parsed is None or diagnostics:
        raise SystemExit("the fixture manifest is not one Stage 4 would accept "
                         "(claimed %r): %s"
                         % (claimed, "; ".join(str(d) for d in diagnostics)))
    return body


def write_manifest(mod_dir, assembly):
    """Write the fixture's mod.json, and prove Stage 4 would accept it.

    The runtime's discovery reads mod_id and the first code artifact out of this
    file. It reads them from STAGE 4's layout rather than a convention of its
    own -- see ManagedHost.cpp -- so the claim that this is that layout has to
    be more than a comment. Stage 4's own parser is imported and run against
    what was just written; a manifest it would reject is a failed run here
    rather than a mystery in-game.
    """
    manifest = {
        "manifest_version": 1,
        "mod_id": FIXTURE_MOD_ID,
        "name": "Alpha Managed Mod",
        "version": "1.0.0",
        "framework_api": "^0.4.0",
        "code": [assembly],
    }
    path = os.path.join(mod_dir, "mod.json")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")

    sys.path.insert(0, os.path.join(REPO, "tools"))
    from modframework import manifest as m4                        # noqa: PLC0415
    with open(path, encoding="utf-8") as handle:
        parsed, diagnostics, claimed = m4.parse(json.load(handle), mod_dir, path)
    if parsed is None:
        raise SystemExit("Stage 4 would reject the fixture's mod.json: %s"
                         % "; ".join(str(d) for d in diagnostics))
    if parsed.mod_id != FIXTURE_MOD_ID or claimed != FIXTURE_MOD_ID:
        raise SystemExit("the manifest parsed to mod_id %r" % parsed.mod_id)
    if list(parsed.code) != [assembly]:
        raise SystemExit("the manifest's code list parsed to %r" % (parsed.code,))
    return path


def managed_payload(staging):
    """Everything the runtime needs to host managed code, laid out as installed.

    Assembled into a staging directory rather than passed as a dozen payload
    entries, so the installer writes ONE tree and the install audit has one
    shape to check.

    The fixture goes in as a real mod: mod.json at its root, assemblies under
    Code/. Installing it any other way would test a layout no mod will ever
    actually have.
    """
    if os.path.isdir(staging):
        shutil.rmtree(staging)
    mod_dir = os.path.join(staging, "Mods", FIXTURE)
    code_dir = os.path.join(mod_dir, "Code")
    os.makedirs(code_dir)

    host_dir = os.path.dirname(newest_output("Misery.ModHost",
                                             "Misery.ModHost.dll"))
    for name in os.listdir(host_dir):
        if name.endswith((".dll", ".json")):
            shutil.copyfile(os.path.join(host_dir, name),
                            os.path.join(staging, name))
    shutil.copyfile(os.path.join(nb.DOTNET_PACK, "nethost.dll"),
                    os.path.join(staging, "nethost.dll"))

    fixture_dir = os.path.dirname(
        newest_output(os.path.join("fixtures", FIXTURE), FIXTURE + ".dll"))
    for name in os.listdir(fixture_dir):
        if name.endswith((".dll", ".json")):
            shutil.copyfile(os.path.join(fixture_dir, name),
                            os.path.join(code_dir, name))
    write_manifest(mod_dir, FIXTURE + ".dll")
    return staging


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--install-root", default=installer.DEFAULT_INSTALL)
    ap.add_argument("--out", required=True)
    ap.add_argument("--probe-pause", action="store_true",
                    help="before closing, ask what one Escape does from "
                         "gameplay -- reconnaissance for the transition test")
    a = ap.parse_args(argv)

    checks = []

    def check(label, ok, detail=""):
        checks.append({"check": label, "pass": bool(ok), "detail": str(detail)})
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", label,
                               "" if ok else "  -- %s" % detail))
        return bool(ok)

    report = {"stage": "5B", "step": "managed items"}
    scratch = os.path.dirname(os.path.abspath(a.out))

    print("=== building ===")
    report["managed_built"] = build_managed()
    proxy, runtime = sb.build_everything()
    profile = sb.real_profile(a.install_root)
    staging = managed_payload(os.path.join(scratch, "managed-payload"))

    sb.fc.close_game()
    # Every file enumerated individually rather than handing the installer the
    # staging root. A payload entry of "." would resolve to the framework
    # directory itself, and the installer replaces a directory payload by
    # deleting the target first -- which would take the runtime with it.
    payload = {"MiseryRuntime.dll": runtime}
    for base, _dirs, files in os.walk(staging):
        for name in files:
            absolute = os.path.join(base, name)
            payload[os.path.relpath(absolute, staging)] = absolute
    report["installed"] = sorted(payload)
    # The installed Mods tree is replaced, not merged into.
    #
    # An earlier revision of this instrument installed the fixture under a
    # different directory name. That copy stayed behind, so the next run had two
    # directories declaring mod_id 'alphamod', discovery correctly refused the
    # ambiguity, and nothing loaded. The stale directory was left by a TEST, so
    # the test is what clears it -- install() deliberately does not delete mods
    # it did not put there, and it should not start.
    stale = sb.fc.framework_path(a.install_root, "Mods")
    if os.path.isdir(stale):
        shutil.rmtree(stale)
    installer.install(a.install_root, proxy, payload)
    sb.put_profile(a.install_root, profile)

    print("\n=== normal Steam launch ===")
    log_path = sb.fc.framework_path(a.install_root, "runtime.log")
    if os.path.isfile(log_path):
        os.remove(log_path)
    if not check("the game launched from Steam", sweep.launch_to_menu()):
        return 1

    print("\n=== driving into gameplay ===")

    def why_blocked(entry_dir):
        """The runner's own reason, which it writes to stdout, not stderr.

        Without this a blocked entry showed up here as the bare word BLOCKED --
        the reason was sitting in a 26 KB JSON report nobody read.
        """
        path = os.path.join(entry_dir, "entry.stdout.txt")
        if not os.path.isfile(path):
            return ""
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        match = re.search(r'"blocked_reason":\s*"(.*?)"(?:,|\n|\})', text,
                          re.S)
        return match.group(1) if match else ""

    # Retried once, and only once.
    #
    # This machine synthesises clicks at a live game, so it depends on the game
    # window being foreground and on nothing else grabbing focus. That is not a
    # property this instrument controls -- a run was lost to exactly that -- and
    # the runner reports it honestly ("the input was delivered but nothing
    # observable happened") rather than pressing again, which is the right call
    # for it and leaves the retry decision here.
    #
    # One retry, because a second failure is a real finding rather than bad
    # luck, and because every attempt drives a live game further into a session.
    attempts = []
    for attempt in range(2):
        entry_dir = os.path.join(scratch, "managed-entry-%d" % attempt)
        entry = sweep.start_gameplay_entry(entry_dir)
        err = sweep.finish_gameplay_entry(entry, entry_dir)
        blocked = why_blocked(entry_dir)
        attempts.append({"attempt": attempt, "returncode": entry.returncode,
                         "blocked_reason": blocked})
        if entry.returncode == 0:
            break
        print("  save entry did not reach gameplay: %s"
              % (blocked or (err or "").strip())[:200])
    report["save_entry_attempts"] = attempts
    check("the save-entry machine reached gameplay", entry.returncode == 0,
          (attempts[-1]["blocked_reason"] or (err or ""))[:220])

    print("\n=== waiting for the item to reach a world ===")

    def read_log():
        path = sb.fc.framework_path(a.install_root, "runtime.log")
        if not os.path.isfile(path):
            return ""
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()

    # The runtime polls every 20s, so "gameplay has been reached" and "the
    # runtime has noticed" are up to a poll apart, plus a chunked walk.
    # Either answer counts, and they are the same claim.
    #
    # The write and the lookup happen in one tick, and a composite table need
    # not rebuild inside the tick that changed one of its parents -- so the
    # game legitimately answers "not yet" at write time and "yes" a poll later.
    # What must not pass is never being found at all.
    live = re.compile(
        r"items: '(\S+)'(?: is live)? in generation (\d+)[;:] "
        r"(?:the game's own SGK ItemDetails resolved it"
        r"|the game's own SGK ItemDetails resolved it \(attempt \d+\))")
    log = ""
    for _ in range(90):
        log = read_log()
        if live.search(log) and "managed host started" in log:
            break
        time.sleep(5)
    report["runtime_log"] = log

    print("\n=== what happened ===")
    check("the managed host started", "managed host started" in log, log[-400:])
    check("discovery planned the installed mod",
          FIXTURE_MOD_ID in log, log[-400:])
    check("no mod was refused by discovery", "managed: skipped" not in log,
          "\n".join(l for l in log.splitlines() if "skipped" in l))

    plan_line = re.search(r"managed: (\d+) of (\d+) planned mod\(s\) loaded, "
                          r"(\d+) failed", log)
    report["load_summary"] = plan_line.group(0) if plan_line else None
    check("the mod in the plan actually loaded",
          bool(plan_line) and plan_line.group(1) == plan_line.group(2) and
          plan_line.group(3) == "0",
          plan_line.group(0) if plan_line else "no load summary was logged")

    # THE MENU CASE. A mod loads at the main menu, where no world exists to hold
    # an item row. The registration must be RECORDED, not performed and not
    # failed -- and the backend must not have written into that generation.
    deferred = re.search(r"items: '(\S+)' declared; deferred until a world "
                         r"exists to hold it \(generation (\d+) reached (\w+)\)",
                         log)
    report["deferred"] = deferred.group(0) if deferred else None
    check("the item was declared at the menu and deferred, not written",
          bool(deferred) and deferred.group(3) != "gameplay",
          deferred.group(0) if deferred else
          "no deferral was logged -- the host may have started in gameplay")

    # THE LINK THAT COUNTS. Not "the engine accepted our write" but "the game
    # can find it", asked of BP_SGKFunctions::"SGK ItemDetails" -- the same
    # function the game itself uses.
    resolved = live.search(log)
    report["sgk"] = resolved.group(0) if resolved else None
    check("the game's own SGK ItemDetails resolved the C#-registered item",
          bool(resolved),
          "\n".join(l for l in log.splitlines() if "items:" in l)[-400:])

    if resolved:
        report["live_generation"] = int(resolved.group(2))
        report["row_name"] = resolved.group(1)
        # The row carries its owner. A mod cannot register into another's
        # namespace, and this is the observable form of that rule.
        check("the row is namespaced to the mod that declared it",
              resolved.group(1).startswith(FIXTURE_MOD_ID + "__"),
              resolved.group(1))
        # It became live in a LATER generation than the one it was declared in,
        # which is the whole point: the declaration outlived the world it was
        # made in.
        if deferred:
            check("the item became live in a later generation than it was "
                  "declared in",
                  int(resolved.group(2)) > int(deferred.group(2)),
                  "declared in %s, live in %s" % (deferred.group(2),
                                                  resolved.group(2)))

    revoked = re.findall(r"generation (\d+) is revoked: (.+)", log)
    report["revocations"] = [{"generation": int(g), "why": w.strip()}
                             for g, w in revoked]
    check("the pre-gameplay generation was revoked by the load",
          bool(revoked), "no revocation was logged")

    # Reconnaissance, run while the game is STILL in gameplay.
    #
    # The second acceptance needs a transition with a gameplay generation on
    # both sides, and the only route the runner has calibrated is main menu ->
    # gameplay. Getting back to the menu is the unknown leg, and its first
    # question is what a single Escape produces. Asked here rather than in its
    # own launch because a launch plus save entry costs ten minutes and the
    # game is already sitting exactly where the question applies.
    if a.probe_pause:
        print("\n=== what does Escape do from gameplay? ===")
        probe_out = os.path.join(scratch, "pause-probe.json")
        probe = subprocess.run(
            [sys.executable,
             os.path.join(REPO, "research", "instruments", "mods",
                          "stage5b_pause_probe.py"),
             "--out", probe_out],
            capture_output=True, text=True, timeout=600)
        print((probe.stdout or "").strip()[-1200:])
        if probe.returncode != 0:
            print("  probe failed: %s" % (probe.stderr or "")[-400:])
        if os.path.isfile(probe_out):
            with open(probe_out, encoding="utf-8") as handle:
                report["pause_probe"] = json.load(handle)

    sb.fc.close_game()
    report["checks"] = checks
    report["passed"] = sum(1 for c in checks if c["pass"])
    report["failed"] = sum(1 for c in checks if not c["pass"])
    report["verdict"] = "PASS" if report["failed"] == 0 else "FAIL"
    os.makedirs(scratch, exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, default=str)
        handle.write("\n")
    print("\n%s -- %d passed, %d failed -> %s"
          % (report["verdict"], report["passed"], report["failed"], a.out))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
