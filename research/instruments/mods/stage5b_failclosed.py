#!/usr/bin/env python3
"""Stage 5B: the refusals, each proven with a real Steam launch.

WHY EVERY CASE GETS ITS OWN LAUNCH
----------------------------------
The claim being tested is "an unsupported build never continues with guessed
bindings", and the only place that claim is true or false is a real process
start. A unit test of the decision function would be testing the function, not
the loader, the search order, the proxy, or what the game does when our code
declines to run.

WHAT "FAIL CLOSED" HAS TO MEAN, MEASURED
----------------------------------------
Three things at once, and all three are checked every time:

  * the bootstrap refuses, and SAYS which rule refused
  * the runtime is NOT loaded into the process
  * the game is still running -- vanilla, not degraded

The third matters most. A framework that declines to load and takes the game
with it has not failed closed; it has failed.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "tools", "modplatform")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                                        # noqa: E402
import install as installer                                       # noqa: E402

STEAM_RUN = "steam://run/2119830"
KNOWN_BUILD = ("bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331")


def framework_path(install_root, *parts):
    return os.path.join(installer.framework_dir(install_root), *parts)


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


def launch_and_observe(install_root, settle=22.0, timeout=300):
    """Start the game through Steam and read what the bootstrap decided."""
    log = framework_path(install_root, "bootstrap.log")
    if os.path.isfile(log):
        os.remove(log)
    os.startfile(STEAM_RUN)
    api = eri.Win32Api()
    pid = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(2)
        try:
            pid = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)["pid"]
            break
        except Exception:                                          # noqa: BLE001
            continue
    if pid is None:
        return {"pid": None, "log": "", "alive": False, "modules": []}
    time.sleep(settle)
    text = ""
    if os.path.isfile(log):
        with open(log, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    alive = True
    try:
        eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    except Exception:                                              # noqa: BLE001
        alive = False
    return {"pid": pid, "log": text, "alive": alive,
            "runtime_loaded": module_loaded(pid, "MiseryRuntime.dll"),
            "proxy_loaded": module_loaded(pid, "dwmapi.dll")}


def module_loaded(pid, name):
    """Is a module present in the live process? Read, not assumed."""
    result = subprocess.run(
        ["tasklist", "/M", name.replace(".dll", "*"), "/FI", "PID eq %d" % pid],
        capture_output=True, text=True)
    return name.lower() in result.stdout.lower()


def write_bindings(install_root, build_key, extra=None):
    payload = {"build_key": "sha256:" + build_key,
               "generated_for": "stage 5B fail-closed exercise"}
    if extra:
        payload.update(extra)
    path = framework_path(install_root, "bindings.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    return path


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

    report = {"stage": "5B", "cases": {}}
    bindings = framework_path(a.install_root, "bindings.json")
    runtime = framework_path(a.install_root, "MiseryRuntime.dll")

    cases = [
        ("no bindings at all", lambda: os.path.isfile(bindings) and
         os.remove(bindings), "no bindings file"),
        ("bindings for a DIFFERENT build",
         lambda: write_bindings(a.install_root, "0" * 64), "do not describe this build"),
        ("bindings match but the runtime is missing",
         lambda: (write_bindings(a.install_root, KNOWN_BUILD),
                  os.path.isfile(runtime) and os.remove(runtime)),
         "could not be loaded"),
    ]

    for name, prepare, expected in cases:
        print("\n=== %s ===" % name)
        close_game()
        prepare()
        observed = launch_and_observe(a.install_root)
        report["cases"][name] = observed
        check("[%s] the game launched" % name, observed["pid"] is not None,
              str(observed["pid"]))
        check("[%s] the bootstrap ran and wrote a decision" % name,
              bool(observed["log"]), "no log")
        check("[%s] it computed this build's fingerprint" % name,
              KNOWN_BUILD in observed["log"], observed["log"][:200])
        check("[%s] it FAILED CLOSED, naming the rule" % name,
              "FAIL CLOSED" in observed["log"] and expected in observed["log"],
              observed["log"][-300:])
        check("[%s] the runtime was NOT loaded" % name,
              not observed.get("runtime_loaded"), "MiseryRuntime.dll present")
        check("[%s] the game is still running, vanilla" % name, observed["alive"],
              "the game died")

    print("\n=== the proxy itself is harmless across consecutive launches ===")
    for attempt in (1, 2):
        close_game()
        observed = launch_and_observe(a.install_root, settle=18.0)
        report["cases"]["consecutive launch %d" % attempt] = observed
        check("consecutive launch %d started" % attempt,
              observed["pid"] is not None, str(observed["pid"]))
        check("consecutive launch %d is still running" % attempt,
              observed["alive"], "the game died")
        check("consecutive launch %d still refuses" % attempt,
              "FAIL CLOSED" in observed["log"], observed["log"][-200:])

    close_game()
    report["checks"] = checks
    report["passed"] = sum(1 for c in checks if c["pass"])
    report["failed"] = sum(1 for c in checks if not c["pass"])
    report["verdict"] = "PASS" if report["failed"] == 0 else "FAIL"
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, default=str)
        handle.write("\n")
    print("\n%s -- %d passed, %d failed -> %s"
          % (report["verdict"], report["passed"], report["failed"], a.out))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
