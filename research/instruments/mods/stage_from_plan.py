#!/usr/bin/env python3
"""Point the runner's container staging at the Stage 4 load plan.

The staging list used to be a hand-maintained array in ``runner-config.json``:
someone built a container, then remembered to add it. That is precisely the
per-mod knowledge Stage 4 exists to remove, so the list is now COMPUTED -- the
mods declare their content, the plan orders them, and the profile falls out.

This does not execute anything. It rewrites one config file, and the runner
stages from it on its next cycle. Stage 5 is the stage that gets to do this
automatically at launch; here it is still a deliberate, inspectable step.

Containers that predate Stage 4 are carried in an explicit LEGACY list rather
than being silently tolerated: the radio is Stage 3 regression coverage, and the
two probe containers are the control that proves "packages registered"
discriminates. Naming them keeps ``expect`` an exact allow-list, so a forgotten
experiment still fails the gate.
"""
import argparse
import io
import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "tools", "modframework"),
           os.path.join(REPO, "tools", "modkit")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import container_report                                            # noqa: E402
import execution                                                   # noqa: E402
import resolve                                                     # noqa: E402

RUNNER_CONFIG = os.path.join(REPO, "research", "instruments", "runner",
                             "runner-config.json")

# Not produced by any Stage 4 mod. Each is here for a stated reason.
LEGACY_STAGE = [
    {"src": "D:/UEScratch/MBPLKit/out/prod", "stem": "MBPLRadio_P"},
]
LEGACY_EXPECT = [
    "MBPLRadio_P",              # Stage 3 regression coverage
    "MiseryModKit_P",           # predates the gate, left in place
    "CT03Probe20260828_P",      # bare .pak: the "packages registered" control
]


def build_profile(root):
    plan, _report = resolve.plan_from_root(
        root, container_reader=container_report.read_container)
    profile = execution.staging_profile(plan)
    profile["stage"] = list(LEGACY_STAGE) + profile["stage"]
    profile["expect"] = sorted(set(LEGACY_EXPECT) | set(profile["expect"]))
    return plan, profile


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default="D:/UEScratch/ModsRoot")
    ap.add_argument("--config", default=RUNNER_CONFIG)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    plan, profile = build_profile(a.root)
    if not plan.load_order:
        raise SystemExit("the load plan is empty; refusing to stage nothing over "
                         "a working configuration")
    if plan.excluded:
        raise SystemExit("the load plan excludes %s; refusing to stage a partially "
                         "accepted set" % sorted(plan.excluded))

    config = json.load(io.open(a.config, encoding="utf-8"))
    config["containers"]["stage"] = profile["stage"]
    config["containers"]["expect"] = profile["expect"]
    config["containers"]["_comment"] = [
        "COMPUTED by research/instruments/mods/stage_from_plan.py from the Stage 4",
        "load plan -- do not hand-edit the stage list. The mods under the",
        "discovery root declare their own content; this file only records what",
        "that resolved to for the next runner cycle.",
        "load_order at generation time: %s" % ", ".join(plan.load_order),
        "Entries not produced by a mod are listed in that script's LEGACY_*",
        "constants, each with a reason.",
    ]
    print(json.dumps({"load_order": plan.load_order,
                      "stage": profile["stage"],
                      "expect": profile["expect"]}, indent=2))
    if a.dry_run:
        print("\n(dry run: %s not written)" % a.config)
        return 0
    io.open(a.config, "w", encoding="utf-8", newline="\n").write(
        json.dumps(config, indent=2, ensure_ascii=False) + "\n")
    print("\nwrote %s" % a.config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
