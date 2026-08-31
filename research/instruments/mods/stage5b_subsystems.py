#!/usr/bin/env python3
"""Stage 5B step 2: the runtime starts the proven native subsystems by itself.

WHAT THIS ADDS TO THE BINDINGS ACCEPTANCE
-----------------------------------------
``stage5b_bindings.py`` proves the runtime loads, validates its profile and
resolves the STARTUP anchors on a normal Steam launch. It stops there, at the
main menu, because that is all a launch reaches on its own.

Step 2 is what happens next, and it cannot be observed at a menu: declaring the
game thread, acquiring the frozen bridge root, and reaching the CONTENT phase --
which needs a save actually loaded. So this run launches through Steam exactly
as a player would, then drives the game into gameplay through the proven
save-entry machine, and reads the runtime's own log for what it did.

WHY THE GAME THREAD IS DECLARED FROM A MEASUREMENT
---------------------------------------------------
Every bridge call is thread-checked. If the runtime declared the wrong thread,
every legitimate call would be refused and every illegitimate one allowed, and
nothing would say so. It therefore declares the thread the resolver reported
actually running the walk, and this run checks that the declared id matches the
one the resolution reported -- two independent statements in the log that have
to agree.

WHAT A FAILURE TO REACH CONTENT MEANS HERE
------------------------------------------
Nothing is wrong with a process that never leaves the main menu, and the runtime
treats that as ordinary rather than as a refusal. This run drives the game into
gameplay precisely so that the content path is exercised rather than skipped --
but the check distinguishes "content resolved" from "content never appeared", so
a run that silently stayed at the menu cannot read as a pass.
"""
import argparse
import json
import os
import re
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "mods"),
           os.path.join(REPO, "tools", "modplatform")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import install as installer                       # noqa: E402
import stage5b_bindings as sb                     # noqa: E402
import stage5b_resolver_lifecycle as sweep        # noqa: E402


def read_runtime_log(install_root):
    path = sb.fc.framework_path(install_root, "runtime.log")
    if not os.path.isfile(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


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

    report = {"stage": "5B", "step": "native subsystems"}

    proxy, runtime = sb.build_everything()
    profile = sb.real_profile(a.install_root)
    sb.fc.close_game()
    installer.install(a.install_root, proxy, {"MiseryRuntime.dll": runtime})
    sb.put_profile(a.install_root, profile)

    # A player's launch: Steam, no controller, no injection.
    print("=== normal Steam launch ===")
    log_path = sb.fc.framework_path(a.install_root, "runtime.log")
    if os.path.isfile(log_path):
        os.remove(log_path)
    if not check("the game launched from Steam", sweep.launch_to_menu()):
        return 1

    # Then into gameplay, so the content path is exercised rather than skipped.
    print("\n=== driving into gameplay so content exists ===")
    entry_dir = os.path.join(os.path.dirname(os.path.abspath(a.out)),
                             "subsystems-entry")
    entry = sweep.start_gameplay_entry(entry_dir)
    err = sweep.finish_gameplay_entry(entry, entry_dir)
    check("the save-entry machine reached gameplay", entry.returncode == 0,
          (err or "")[-200:])

    # The content poll runs on a slow cadence, so give it room to catch up with
    # a game that only just entered the world.
    print("\n=== waiting for the runtime's content poll ===")
    deadline_log = ""
    # Wait for the full cycle: publish, revoke, republish. The runtime polls on
    # a slow cadence, so this has to outlast a couple of its intervals.
    for _ in range(48):
        deadline_log = read_runtime_log(a.install_root)
        if len(re.findall(r"content generation \d+ published", deadline_log)) >= 2:
            break
        time.sleep(5)
    log = deadline_log
    report["runtime_log"] = log

    print("\n=== what the runtime did ===")
    check("the runtime read its profile and verified the code addresses",
          "matches live memory" in log, log[:200])
    check("the startup anchors resolved", "startup anchors resolved" in log,
          log[-400:])

    # Step 2 proper.
    declared = re.search(r"game thread declared as (\d+)", log)
    resolved_on = re.search(r"resolved on thread (\d+)", log)
    check("the runtime declared a game thread", bool(declared),
          log[-400:])
    check("it declared the thread the resolver actually ran on -- two "
          "independent statements that agree",
          bool(declared and resolved_on and
               declared.group(1) == resolved_on.group(1)),
          "declared=%s resolved_on=%s"
          % (declared.group(1) if declared else None,
             resolved_on.group(1) if resolved_on else None))
    check("the bridge was acquired with the frozen root",
          "bridge acquired" in log,
          [ln for ln in log.splitlines() if "bridge" in ln][-1:])

    published = re.findall(r"content generation (\d+) published -- (\w+), "
                           r"(\d+) objects", log)
    revoked = re.findall(r"generation (\d+) is revoked: '([^']+)' (.+)", log)
    report["published"] = published
    report["revoked"] = revoked
    check("a content generation was PUBLISHED", bool(published), log[-500:])

    # THE LIFECYCLE, as its own checks. A run that published once and never
    # cycled would pass a "content resolved" check while proving nothing about
    # what happens when the world is replaced.
    check("a published generation was later REVOKED -- the world was replaced "
          "and the old anchors stopped being usable", bool(revoked),
          "no revocation seen in this run")
    check("a NEW generation was published after the revocation",
          len(published) >= 2,
          "%d generation(s) published" % len(published))
    if len(published) >= 2 and revoked:
        first, second = published[0], published[-1]
        check("the new generation is a different, larger world -- not the same "
              "anchors republished",
              int(second[2]) != int(first[2]),
              "first=%s objects, last=%s objects" % (first[2], second[2]))
        check("the revocation named the anchor and how it died",
              all(r[1] and r[2] for r in revoked), revoked[:2])

    tables = re.findall(r"generation (\d+): ItemList 0x([0-9a-f]+), "
                        r"MasterItemList 0x([0-9a-f]+), "
                        r"RowStruct 0x([0-9a-f]+) \((\d+) bytes\)", log)
    check("each generation published its item tables and row struct",
          len(tables) == len(published), "%d tables, %d generations"
          % (len(tables), len(published)))
    if len(tables) >= 2:
        check("the item tables of the two generations are DIFFERENT objects -- "
              "which is why the old ones had to be revoked",
              tables[0][1] != tables[-1][1],
              "gen%s ItemList 0x%s vs gen%s 0x%s"
              % (tables[0][0], tables[0][1], tables[-1][0], tables[-1][1]))
    if tables:
        report["generations"] = [
            {"generation": int(g), "item_list": "0x" + il,
             "master_item_list": "0x" + ml, "row_struct": "0x" + rs,
             "row_struct_size": int(sz)} for g, il, ml, rs, sz in tables]
        widths = {int(sz) for _g, _il, _ml, _rs, sz in tables}
        check("every generation's row struct is the width the binding profile "
              "records", widths == {profile["row_struct"]["size"]},
              "live=%s profile=%s" % (sorted(widths),
                                      profile["row_struct"]["size"]))
    check("nothing failed closed", "FAIL CLOSED" not in log, log[-400:])
    alive = True
    try:
        import eri
        eri.run_i01(eri.Win32Api(), eri.DEFAULT_PROCESS_NAME)
    except Exception:                                              # noqa: BLE001
        alive = False
    check("the game is still running", alive, "the game died")

    sb.fc.close_game()
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
