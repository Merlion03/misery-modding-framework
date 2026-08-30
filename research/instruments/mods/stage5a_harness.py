#!/usr/bin/env python3
"""Stage 5A: build and run the off-game managed-hosting acceptance.

WHAT THIS PROVES, AND WHAT IT DELIBERATELY DOES NOT
---------------------------------------------------
It runs the REAL architecture -- native bridge, hostfxr, CoreCLR, the managed
host, per-mod collectible contexts, independently built C# mods -- with one
substitution: a recording items backend instead of MISERY's live aggregate
table. That single function pointer is the only difference from the in-game run.

Everything about managed hosting is therefore answered here: assembly loading,
OnLoad, C# logging, C# -> native semantic calls, the native -> trampoline ->
callback direction, the full load/unload/reload lifecycle, whether an
AssemblyLoadContext actually collects, failure isolation and the threading
contract. What is NOT answered here is the one thing only MISERY can answer:
whether a live item really appears in the game. That is the in-game run.

The mod set comes from the Stage 4 load plan wherever one is available, and the
fixture paths are passed in -- nothing is hardcoded into the runtime.
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "tools", "modplatform"),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import nativebuild as nb                                           # noqa: E402

MANAGED = os.path.join(REPO, "managed")
STAGE = os.path.join(nb.BUILD_DIR, "stage")

# The healthy pair first: the acceptance takes plan[0] and plan[1] as the two
# mods it exercises the full lifecycle with, and everything after that as a
# broken fixture to prove isolation against.
HEALTHY = ("alphamod", "AlphaManagedMod"), ("betamod", "BetaManagedMod")
BROKEN = (
    ("throwonloadmod", "ThrowOnLoadMod"),
    ("throwincallbackmod", "ThrowInCallbackMod"),
    ("throwonunloadmod", "ThrowOnUnloadMod"),
    ("noentrypointmod", "NoEntryPointMod"),
    ("futureapimod", "FutureApiMod"),
)


def run(command, cwd=None, timeout=900):
    return subprocess.run(command, capture_output=True, text=True, cwd=cwd,
                          timeout=timeout, shell=isinstance(command, str))


def build_managed():
    """Build the contracts, the host and every fixture."""
    built = []
    for project in ["Misery.ModAPI", "Misery.ModHost"]:
        path = os.path.join(MANAGED, project)
        result = run(["dotnet", "build", "-v", "quiet", "--nologo"], cwd=path)
        if result.returncode != 0:
            raise SystemExit("%s failed to build:\n%s" % (project, result.stdout[-3000:]))
        built.append(project)
    for _mod_id, name in HEALTHY + BROKEN:
        path = os.path.join(MANAGED, "fixtures", name)
        result = run(["dotnet", "build", "-v", "quiet", "--nologo"], cwd=path)
        if result.returncode != 0:
            raise SystemExit("%s failed to build:\n%s" % (name, result.stdout[-3000:]))
        built.append(name)
    return built


def build_native():
    bridge = nb.build_dll(
        [os.path.join(REPO, "runtime", "MiseryRuntime", "Internal",
                      "BridgeTables.cpp")], "MiseryBridge.dll")
    harness = nb.build_exe(
        [os.path.join(REPO, "runtime", "tests", "managed_host_harness.cpp")],
        "managed_host_harness.exe",
        extra='/I"%s" "%s" ole32.lib advapi32.lib'
              % (nb.DOTNET_PACK, os.path.join(nb.DOTNET_PACK, "libnethost.lib")))
    return bridge, harness


def stage():
    """Lay the host out the way it will actually be deployed.

    Each mod gets its OWN folder, because each gets its own load context that
    resolves dependencies from beside its assembly. Sharing one folder would
    make the test pass for a reason the real layout would not reproduce.
    """
    if os.path.isdir(STAGE):
        shutil.rmtree(STAGE)
    os.makedirs(STAGE)

    host_bin = os.path.join(MANAGED, "Misery.ModHost", "bin", "Debug", "net8.0")
    for pattern in ("*.dll", "*.json"):
        for path in glob.glob(os.path.join(host_bin, pattern)):
            shutil.copy2(path, STAGE)

    # nethost.dll must sit beside whatever calls get_hostfxr_path.
    nethost = os.path.join(nb.DOTNET_PACK, "nethost.dll")
    if os.path.isfile(nethost):
        shutil.copy2(nethost, STAGE)
        shutil.copy2(nethost, nb.BUILD_DIR)

    placed = {}
    for mod_id, name in HEALTHY + BROKEN:
        folder = os.path.join(STAGE, "mods", mod_id)
        os.makedirs(folder, exist_ok=True)
        source = os.path.join(MANAGED, "fixtures", name, "bin", "Debug", "net8.0")
        for path in glob.glob(os.path.join(source, "*.dll")):
            # The contract assembly must come from the DEFAULT context, so it is
            # deliberately not copied beside the mod: a mod shipping its own copy
            # would load a second Misery.ModAPI and its IMod would not be the
            # host's IMod.
            if os.path.basename(path) == "Misery.ModAPI.dll":
                continue
            shutil.copy2(path, folder)
        placed[mod_id] = os.path.join(folder, name + ".dll")
    return placed


def load_plan_order(root):
    """Take the mod order from the Stage 4 resolver when a tree is present."""
    try:
        sys.path.insert(0, os.path.join(REPO, "tools", "modframework"))
        sys.path.insert(0, os.path.join(REPO, "tools", "modkit"))
        import resolve                                             # noqa: PLC0415
        plan, _report = resolve.plan_from_root(root, check_artifacts=False)
        return list(plan.load_order), None
    except Exception as error:                                     # noqa: BLE001
        return None, "%s: %s" % (type(error).__name__, error)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mods-root", default="D:/UEScratch/ModsRoot")
    ap.add_argument("--out", required=True)
    ap.add_argument("--skip-build", action="store_true")
    a = ap.parse_args(argv)

    report = {"stage": "5A", "off_game": True}
    if not a.skip_build:
        report["managed_built"] = build_managed()
    bridge, harness = build_native()
    report["bridge"] = bridge
    report["harness"] = harness
    placed = stage()
    report["staged"] = placed

    order, plan_error = load_plan_order(a.mods_root)
    report["stage4_load_order"] = order
    report["stage4_error"] = plan_error
    # The healthy pair is ordered BY THE STAGE 4 PLAN when one resolves, so the
    # managed host is driven by the same ordering the rest of the framework uses
    # rather than by this script's opinion.
    healthy = [mod_id for mod_id, _ in HEALTHY]
    if order:
        ranked = [m for m in order if m in placed]
        healthy = ranked + [m for m in healthy if m not in ranked]
    plan_arg = ";".join("%s=%s" % (mod_id, placed[mod_id])
                        for mod_id in healthy if mod_id in placed)
    for mod_id, _name in BROKEN:
        plan_arg += ";%s=%s" % (mod_id, placed[mod_id])
    report["plan_arg"] = plan_arg

    host_assembly = os.path.join(STAGE, "Misery.ModHost.dll")
    result = run([harness, bridge, host_assembly, plan_arg], cwd=nb.BUILD_DIR)
    report["harness_exit"] = result.returncode
    report["stdout"] = result.stdout
    report["stderr"] = result.stderr[-4000:]

    parsed = None
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and "\"checks\"" in line:
            try:
                parsed = json.loads(line)
            except ValueError:
                pass
    report["acceptance"] = parsed

    if parsed:
        print("\n=== Stage 5A: managed hosting, off game ===")
        for check in parsed.get("checks", []):
            print("  [%s] %s%s" % ("PASS" if check["pass"] else "FAIL",
                                   check["check"],
                                   "" if check["pass"]
                                   else "  -- " + check.get("detail", "")))
        print("\n%s -- %d passed, %d failed"
              % ("PASS" if parsed.get("ok") else "FAIL", parsed.get("passed", 0),
                 parsed.get("failed", 0)))
    else:
        print(result.stdout[-4000:])
        print(result.stderr[-2000:])

    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, default=str)
        handle.write("\n")
    ok = bool(parsed and parsed.get("ok")) and result.returncode == 0
    print("-> %s" % a.out)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
