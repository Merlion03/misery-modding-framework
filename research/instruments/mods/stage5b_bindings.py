#!/usr/bin/env python3
"""Stage 5B step 1: the runtime consumes bindings on a normal Steam launch.

WHAT THIS PROVES THAT THE FAIL-CLOSED SUITE DOES NOT
----------------------------------------------------
``stage5b_failclosed.py`` proves the PROXY refuses: no bindings, bindings for
another build, no runtime. Every one of its cases stops before MiseryRuntime is
loaded, so none of them says anything about what the runtime does when it IS
handed a profile.

This file starts where that one stops. A real profile is emitted for the
installed executable, installed beside the proxy, and the game is started from
Steam with no research controller in the picture at all. The runtime's own log
is then the evidence: did it read the profile, did it check every recorded code
address against live memory, did it wait for the engine rather than sleeping at
it, and did the startup anchors resolve.

THE SECOND LOCK IS THE POINT OF THE NEGATIVE CASES
---------------------------------------------------
The proxy's check is a substring match for this build's digest somewhere in the
bindings file -- cheap, and deliberately weak, because its job is only to avoid
loading the runtime for an obviously wrong profile. The runtime's check is the
real one. So the negative cases here are all built to PASS the proxy and be
refused by the runtime: the digest stays somewhere in the file while the thing
that matters is wrong. A profile that only failed the cheap check would prove
nothing about the second lock.

Each case is its own Steam launch, and the game must still be running vanilla
afterwards, because a framework that declines to start and takes the game with
it has not failed closed.
"""
import argparse
import json
import os
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "tools", "modplatform")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import bindings as bindings_tool                                  # noqa: E402
import install as installer                                       # noqa: E402
import nativebuild as nb                                          # noqa: E402
import stage5b_failclosed as fc                                   # noqa: E402

KNOWN_BUILD = fc.KNOWN_BUILD
BUILD_KEY = "sha256:" + KNOWN_BUILD


def exe_path(install_root):
    return os.path.join(installer.binaries_dir(install_root),
                        "MISERY-Win64-Shipping.exe")


# The only paths this framework is allowed to have created, relative to the
# install root and in the form verify_install reports them.
ALLOWED_SURFACE_PREFIXES = ("MISERY/Binaries/Win64/dwmapi.dll",
                            "MISERY/Binaries/Win64/MiseryFramework/")


def install_surface_findings(out_dir):
    """Every way the game tree now differs from its committed baseline.

    WHY THIS IS RUN AS PART OF THE ACCEPTANCE, NOT AS A COURTESY
    -----------------------------------------------------------
    "The game installation stays read-only except for the minimal designed
    bootstrap surface" is a claim about the whole tree, and the only way to
    make it is to compare the whole tree. verify_install classifies ANY
    addition as serious, which is exactly the instrument wanted here: it lists
    every difference, and the acceptance then asserts that each one is inside
    the designed surface. A run that quietly modified a game file, or dropped a
    file somewhere else, fails on the path -- not on a judgement call.
    """
    index_path = os.path.join(REPO, "research", "builds", "index.json")
    with open(index_path, encoding="utf-8") as handle:
        index = json.load(handle)
    entry = index.get(BUILD_KEY)
    if entry is None:
        raise RuntimeError("no build registry entry for %s" % BUILD_KEY)
    inventory = os.path.join(REPO, entry["artifacts"]["install_inventory_json"])
    os.makedirs(out_dir, exist_ok=True)
    report = os.path.join(out_dir, "verify_install.json")
    subprocess.run(
        [sys.executable,
         os.path.join(REPO, "tools", "inventory", "verify_install.py"),
         inventory, "--json", report, "--fast"],
        capture_output=True, text=True, timeout=1800)
    with open(report, encoding="utf-8") as handle:
        return json.load(handle)


def build_everything():
    """The proxy and the runtime, from source, every run.

    Built rather than reused so the run cannot accidentally be measuring a
    stale DLL from an earlier experiment -- which has already happened once in
    this project and cost an afternoon.
    """
    # One list, in nativebuild. See MISERY_RUNTIME_SOURCES for why it is not
    # written out here.
    runtime = nb.build_dll(nb.runtime_sources(REPO), "MiseryRuntime.dll")
    proxy_dir = os.path.join(REPO, "runtime", "MiseryBootstrap")
    # advapi32 for the CryptoAPI hash. The proxy fingerprints the executable
    # itself, which is the whole basis of the fail-closed gate, so this is not an
    # incidental dependency.
    #
    # Recorded HERE deliberately: until now the proxy's link line existed only in
    # an ad-hoc shell command from an earlier session, so the committed tree could
    # not rebuild the artifact it shipped. A recipe that lives in somebody's
    # terminal history is not a recipe.
    proxy = nb.build_proxy(
        proxy_dir, "dwmapi.dll",
        [os.path.join(proxy_dir, "MiseryBootstrap.cpp"),
         os.path.join(proxy_dir, "dwmapi_proxy.cpp")],
        os.path.join(proxy_dir, "dwmapi_proxy.def"),
        os.path.join(proxy_dir, "dwmapi_proxy.asm"),
        libs="advapi32.lib")
    return proxy, runtime


def real_profile(install_root):
    build_id, engine = bindings_tool.engine_from_index(BUILD_KEY)
    return bindings_tool.emit(exe_path(install_root), build_id, BUILD_KEY,
                              engine)


def put_profile(install_root, profile):
    path = fc.framework_path(install_root, "bindings.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(profile, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path


def observe(install_root, settle=45.0):
    """Launch, then read BOTH logs: the proxy's decision and the runtime's."""
    runtime_log = fc.framework_path(install_root, "runtime.log")
    if os.path.isfile(runtime_log):
        os.remove(runtime_log)
    observed = fc.launch_and_observe(install_root, settle=settle)
    text = ""
    if os.path.isfile(runtime_log):
        with open(runtime_log, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    observed["runtime_log"] = text
    return observed


def corrupt_one_code_byte(profile):
    """Change one recorded byte of one function.

    This is the case that decides whether the profile's bytes are a guard or
    decoration: the address is right, the file is otherwise perfect, and the
    only thing wrong is that the runtime was told to expect something the
    process does not contain.
    """
    bad = json.loads(json.dumps(profile))
    entry = bad["addresses"]["add_ticker"]
    first = entry["bytes"][:2]
    flipped = "%02x" % (int(first, 16) ^ 0xFF)
    entry["bytes"] = flipped + entry["bytes"][2:]
    return bad


def wrong_build_but_past_the_proxy(profile):
    """A profile for another build that the proxy's substring check lets through.

    The digest is left in a note field, so the cheap check finds it and the
    runtime is loaded -- which is exactly the situation the runtime's own
    identity check exists for.
    """
    bad = json.loads(json.dumps(profile))
    bad["_note"] = ("this file mentions %s so the proxy's substring check "
                    "passes; build.build_key below does not" % BUILD_KEY)
    bad["build"]["build_key"] = "sha256:" + "0" * 64
    return bad


def unknown_version(profile):
    bad = json.loads(json.dumps(profile))
    bad["bindings_version"] = 2
    return bad


def address_outside_the_image(profile):
    bad = json.loads(json.dumps(profile))
    bad["addresses"]["fmemory_malloc"]["rva"] = bad["build"]["image_size_bytes"]
    return bad


def another_engine(profile):
    bad = json.loads(json.dumps(profile))
    bad["build"]["engine_version"] = "5.5.0"
    return bad


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--install-root", default=installer.DEFAULT_INSTALL)
    ap.add_argument("--out", required=True)
    ap.add_argument("--launches", type=int, default=3,
                    help="how many consecutive good launches to require")
    a = ap.parse_args(argv)

    checks = []

    def check(label, ok, detail=""):
        checks.append({"check": label, "pass": bool(ok), "detail": str(detail)})
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", label,
                               "" if ok else "  -- %s" % detail))
        return bool(ok)

    report = {"stage": "5B", "step": "bindings", "cases": {}}

    proxy, runtime = build_everything()
    report["built"] = {"proxy": proxy, "runtime": runtime}
    profile = real_profile(a.install_root)
    report["profile_build_id"] = profile["build"]["build_id"]

    fc.close_game()
    installer.install(a.install_root, proxy, {"MiseryRuntime.dll": runtime})

    # ---- the positive path, several times over -------------------------
    for attempt in range(1, a.launches + 1):
        name = "good launch %d" % attempt
        print("\n=== %s ===" % name)
        fc.close_game()
        put_profile(a.install_root, profile)
        observed = observe(a.install_root)
        report["cases"][name] = observed
        log = observed["runtime_log"]

        check("[%s] the game launched" % name, observed["pid"] is not None,
              str(observed["pid"]))
        check("[%s] the proxy handed over instead of refusing" % name,
              "FAIL CLOSED" not in observed["log"], observed["log"][-300:])
        check("[%s] the runtime was loaded into the process" % name,
              bool(observed.get("runtime_loaded")), "MiseryRuntime.dll absent")
        check("[%s] the runtime read the profile for THIS build" % name,
              profile["build"]["build_id"] in log, log[:300])
        check("[%s] every recorded code address matched live memory" % name,
              "matches live memory" in log, log[-400:])
        check("[%s] it waited for the engine and said so, rather than "
              "sleeping at it" % name, "the engine is up after" in log,
              log[-400:])
        check("[%s] the object universe built" % name, "live objects" in log,
              log[-400:])
        check("[%s] the startup anchors resolved" % name,
              "startup anchors resolved" in log, log[-400:])
        check("[%s] nothing failed closed" % name, "FAIL CLOSED" not in log,
              log[-400:])
        check("[%s] the game is still running" % name, observed["alive"],
              "the game died")

    # ---- profiles the PROXY accepts and the RUNTIME must not -----------
    negatives = [
        ("one recorded code byte is wrong", corrupt_one_code_byte,
         "does not hold the code the profile recorded"),
        ("the profile describes another build", wrong_build_but_past_the_proxy,
         "but this executable hashes to"),
        ("an unknown bindings_version", unknown_version,
         "bindings_version 2"),
        ("an address outside the image", address_outside_the_image,
         "outside the image"),
        ("a profile for another engine", another_engine, "engine 5.5.0"),
    ]
    for name, mangle, expected in negatives:
        print("\n=== %s ===" % name)
        fc.close_game()
        put_profile(a.install_root, mangle(profile))
        observed = observe(a.install_root, settle=30.0)
        report["cases"][name] = observed
        log = observed["runtime_log"]

        check("[%s] the game launched" % name, observed["pid"] is not None,
              str(observed["pid"]))
        # The point of these cases: the cheap check must NOT be what caught it.
        check("[%s] the proxy let it through, so the runtime's own check is "
              "what is being tested" % name,
              "FAIL CLOSED" not in observed["log"], observed["log"][-300:])
        check("[%s] the runtime FAILED CLOSED" % name, "FAIL CLOSED" in log,
              log[-400:])
        check("[%s] it named the actual reason" % name, expected in log,
              log[-400:])
        check("[%s] it did not go on to resolve anything" % name,
              "startup anchors resolved" not in log, log[-400:])
        check("[%s] the game is still running, vanilla" % name,
              observed["alive"], "the game died")

    fc.close_game()
    put_profile(a.install_root, profile)

    # ---- the install itself, compared against its committed baseline ----
    print("\n=== the game installation ===")
    verify = install_surface_findings(os.path.dirname(os.path.abspath(a.out)))
    report["install_verify"] = verify
    findings = verify.get("findings", [])
    outside = [f for f in findings
               if not any(f["path"].startswith(p)
                          for p in ALLOWED_SURFACE_PREFIXES)]
    modified = [f for f in findings if f["kind"] != "added"]
    check("nothing was created outside the designed bootstrap surface",
          not outside, [f["path"] for f in outside][:8])
    check("no original game file was modified, resized, rehashed or removed",
          not modified, [(f["kind"], f["path"]) for f in modified][:8])
    check("the surface that WAS created is the proxy and the framework "
          "directory, and it is actually there",
          any(f["path"] == "MISERY/Binaries/Win64/dwmapi.dll"
              for f in findings),
          "%d finding(s)" % len(findings))

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
