#!/usr/bin/env python3
"""E-3c: cook a Blueprint child against a surrogate MISERY gameplay parent.

    generated minimal surrogate parent
      -> Blueprint child derived from it
      -> exact UE 5.4.4 compile/cook

Bounded by research/evidence/E-3c/preregistration.md (Tier A, committed before
any cook). This driver does the authoring + cook + container inspection half.
The runtime half is a separate instrument and a separate decision.

WHAT IT REUSES
--------------
Stage 3's cook and packaging, unmodified: the same editor, the same
`-run=Cook -TargetPlatform=Windows -unversioned`, the same IoStore packaging and
container reader. Only the assets being authored are new.

THE EXCLUSION IS STRUCTURAL, AND IS STILL CHECKED
-------------------------------------------------
`tools/modkit/build.py:cooked_files_for` selects `Mods/<mod_id>/...` and nothing
else. The surrogate lives at `/Game/SurvivalGameKitV2/...`, outside that prefix,
so it cannot reach a container by construction. That is a good argument and not
a measurement, so the container is read back and the parent path is required to
be absent from it. A build that shipped the surrogate would produce a false PASS
downstream, which is the one outcome worth spending a check on.
"""
import argparse
import json
import os
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "tools", "modkit"),
           os.path.join(REPO, "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import build as modkit                                            # noqa: E402
from content import iostore_chunks as ic                          # noqa: E402

# The real class, from live reflection (CR-01 master-classes-i05-i06.json,
# LOG-0063). Everything downstream keys off this one identity.
PARENT_PACKAGE = ("/Game/SurvivalGameKitV2/Blueprints/Items/WorldItems/"
                  "BP_StaticMasterItem")
PARENT_CLASS_PATH = PARENT_PACKAGE + "." + "BP_StaticMasterItem_C"
PARENT_ASSET_NAME = "BP_StaticMasterItem"
PARENT_DIR = "/Game/SurvivalGameKitV2/Blueprints/Items/WorldItems"

MOD_ID = "e3cprobe"
CHILD_DIR = "/Game/Mods/%s" % MOD_ID
CHILD_NAME = "BP_MiseryTestWorldItem"

WORK = r"D:\UEScratch\E3C"


def run_editor(plan_path, report_path, log_path):
    env = dict(os.environ)
    env["E3C_PLAN"] = plan_path
    env["E3C_REPORT"] = report_path
    command = [modkit.EDITOR_CMD, modkit.KIT_PROJECT, "-run=pythonscript",
               "-script=%s" % os.path.join(os.path.dirname(
                   os.path.abspath(__file__)), "e3c_editor.py"),
               "-unattended", "-nopause", "-nosplash", "-stdout"]
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                              env=env)
    report = None
    if os.path.isfile(report_path):
        with open(report_path, encoding="utf-8") as handle:
            report = json.load(handle)
    return proc.returncode, report


def cook_errors(log_path):
    """The cook's own words, not a summary of them.

    Errors and warnings that name our packages are what decides whether a stage
    failed and what it demanded. They are extracted verbatim: a paraphrased
    cooker error is the exact thing this experiment must not produce.
    """
    if not os.path.isfile(log_path):
        return [], []
    errors, mentions = [], []
    with open(log_path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stripped = line.rstrip("\n")
            low = stripped.lower()
            if "error" in low or "fatal" in low:
                errors.append(stripped[:400])
            if ("staticmasteritem" in low or "e3cprobe" in low or
                    "miserytestworlditem" in low):
                mentions.append(stripped[:400])
    return errors[-80:], mentions[-120:]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stage", default="S0",
                    choices=("S0", "S1", "S2", "S3"))
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    os.makedirs(WORK, exist_ok=True)
    report = {"experiment": "E-3c", "stage": a.stage,
              "parent_class_path": PARENT_CLASS_PATH, "mod_id": MOD_ID}

    plan = {"stage": a.stage,
            "surrogate_dir": PARENT_DIR, "surrogate_name": PARENT_ASSET_NAME,
            "child_dir": CHILD_DIR, "child_name": CHILD_NAME,
            "expected_parent_class_path": PARENT_CLASS_PATH}
    plan_path = os.path.join(WORK, "plan-%s.json" % a.stage)
    with open(plan_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(plan, handle, indent=2)

    print("=== authoring (%s) ===" % a.stage)
    editor_report_path = os.path.join(WORK, "editor-%s.json" % a.stage)
    editor_log = os.path.join(WORK, "editor-%s.log" % a.stage)
    rc, editor_report = run_editor(plan_path, editor_report_path, editor_log)
    report["editor_returncode"] = rc
    report["editor"] = editor_report
    if editor_report is None:
        report["verdict"] = "BLOCKED"
        report["blocked_reason"] = ("the editor produced no report; see %s"
                                    % editor_log)
        print("  BLOCKED: no editor report -- see %s" % editor_log)
    else:
        for s in editor_report["steps"]:
            print("  [%s] %s%s" % ("ok" if s["ok"] else "FAILED", s["step"],
                                   "" if s["ok"] else "  -- " + s["detail"]))
        if editor_report.get("exception"):
            print("  editor exception:\n%s" % editor_report["exception"][-1500:])

    if editor_report is None or not editor_report.get("ok"):
        report["verdict"] = report.get("verdict") or "AUTHORING_FAILED"
        write(report, a.out)
        return 1

    print("\n=== cook (exact UE 5.4.4) ===")
    cook_log = os.path.join(WORK, "cook-%s.log" % a.stage)
    began = time.time()
    cook_rc = modkit.cook(cook_log)
    report["cook_returncode"] = cook_rc
    report["cook_seconds"] = round(time.time() - began, 1)
    errors, mentions = cook_errors(cook_log)
    report["cook_errors"] = errors
    report["cook_mentions"] = mentions
    print("  cook returned %d in %.0fs" % (cook_rc, report["cook_seconds"]))
    for line in mentions[-12:]:
        print("   | %s" % line)
    if cook_rc != 0:
        report["verdict"] = "COOK_FAILED"
        print("  cook FAILED -- the errors are the result, see %s" % cook_log)
        for line in errors[-15:]:
            print("   ! %s" % line)
        write(report, a.out)
        return 1

    print("\n=== what the cook produced ===")
    cooked_child = os.path.join(modkit.COOKED_ROOT, "Mods", MOD_ID)
    produced = []
    for base, _dirs, files in os.walk(cooked_child):
        for name in sorted(files):
            produced.append(os.path.join(base, name).replace(os.sep, "/"))
    report["cooked_child_files"] = produced
    print("  child package files: %d" % len(produced))
    for path in produced:
        print("   %s" % os.path.basename(path))

    # Did the cook also emit the surrogate? It is outside the packaged prefix
    # either way, but whether the COOKER produced it is worth recording: it is
    # the difference between "not shipped" and "not built".
    surrogate_cooked = os.path.join(modkit.COOKED_ROOT, "SurvivalGameKitV2",
                                    "Blueprints", "Items", "WorldItems")
    report["surrogate_cooked_files"] = (
        sorted(os.listdir(surrogate_cooked))
        if os.path.isdir(surrogate_cooked) else [])
    print("  surrogate cooked separately: %s"
          % (report["surrogate_cooked_files"] or "no"))

    report["verdict"] = "COOKED"
    write(report, a.out)
    return 0


def write(report, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, default=str)
        handle.write("\n")
    print("\n%s -> %s" % (report.get("verdict", "?"), path))


if __name__ == "__main__":
    raise SystemExit(main())
