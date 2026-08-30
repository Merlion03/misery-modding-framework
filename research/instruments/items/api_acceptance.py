#!/usr/bin/env python3
"""Stage 2 public-API acceptance, over the aggregate table.

The registry is unchanged from the unit-tested version; only the Materializer
underneath it differs. That is the claim being checked here: the policy layer
was already right, and swapping a one-item mechanism for an aggregate one
required no change above the protocol.

MUST BE RUN IN THE BACKGROUND. It holds a live session with real game state --
an attached aggregate table and a loaded probe module -- and if the process is
killed part-way, the Python object that knows the IO block's address dies with
it and shutdown() can no longer be called. That happened once; recovery was a
game restart.
"""
import argparse
import json
import os
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "items")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import definition as D            # noqa: E402
import materializer               # noqa: E402
import registry as R              # noqa: E402

CONTENT = "/Game/MBPLTest/Items/Radio"


def item(mod, local, weight, icon="T_MBPL_Radio_Icon"):
    return D.ItemDefinition(
        D.ItemId(mod, local), display_name="API %s" % local, short_name=local[:8],
        description="Public API acceptance item %s." % local,
        weight=weight, width=1, height=1,
        inventory_icon=D.AssetRef("%s/%s" % (CONTENT, icon)),
        world_mesh=D.AssetRef(CONTENT + "/SM_MBPL_Radio"),
        world_class="BP_StaticMasterItem_C")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    checks = []

    def check(label, ok, detail=""):
        checks.append({"check": label, "pass": bool(ok), "detail": str(detail)})
        print("  [%s] %-56s %s" % ("PASS" if ok else "FAIL", label, detail))
        sys.stdout.flush()
        return bool(ok)

    started = time.time()
    mat = materializer.AggregateMaterializer()
    reg = R.Registry(mat)
    A, B = item("mbpl", "api_a", 0.2), item("mbpl", "api_b", 0.3)
    OTHER = item("othermod", "api_a", 1.5)
    report = {}

    baseline = mat.existing_row_names()
    report["baseline_rows"] = len(baseline)
    print("baseline rows: %d" % len(baseline))

    info = mat.init()
    print("items init: %s" % info)
    report["init"] = info
    try:
        check("Register(A) through the public API", reg.register(A).ok)
        check("Register(B) through the public API", reg.register(B).ok)
        check("Find(A) by ItemId", reg.find(A.item_id) is A)
        check("Find(B) by derived row name", reg.find("mbpl__api_b") is B)
        check("Find of an unknown id returns None", reg.find("mbpl__nope") is None)

        dup = reg.register(item("mbpl", "api_a", 9.0))
        check("duplicate id -> already_registered",
              dup.code == R.ERR_ALREADY_REGISTERED, dup.code)
        check("the original definition is untouched", reg.find(A.item_id).weight == 0.2)

        check("two mods, same local_id, both register", reg.register(OTHER).ok)
        rows = mat.existing_row_names()
        check("all three semantic ids resolve live",
              {"mbpl__api_a", "mbpl__api_b", "othermod__api_a"} <= rows,
              "%d rows" % len(rows))
        check("MasterItemList = baseline + 3",
              len(rows) == report["baseline_rows"] + 3, len(rows))

        # A definition whose derived row name already exists live but which this
        # registry does not own: the collision oracle, not the namespace rule.
        stray = item("mbpl", "api_a", 1.0)
        reg2 = R.Registry(mat)
        collide = reg2.register(stray)
        check("a registry that does not own a live row still refuses it",
              collide.code in (R.ERR_COLLIDES_WITH_MOD, R.ERR_COLLIDES_WITH_VANILLA),
              collide.code)

        unknown = reg.unregister(D.ItemId("mbpl", "ghost"))
        check("unregister unknown -> not_registered",
              unknown.code == R.ERR_NOT_REGISTERED, unknown.code)

        check("Unregister(A)", reg.unregister(A.item_id).ok)
        rows = mat.existing_row_names()
        check("A gone from the live composite", "mbpl__api_a" not in rows)
        check("B and othermod__api_a survive",
              {"mbpl__api_b", "othermod__api_a"} <= rows)
        check("B's shared icon still valid after A's release",
              reg.find(B.item_id) is not None)
        check("unregister A twice -> not_registered",
              reg.unregister(A.item_id).code == R.ERR_NOT_REGISTERED)

        check("Register(A) again after unregister", reg.register(A).ok)
        check("back to baseline + 3",
              len(mat.existing_row_names()) == report["baseline_rows"] + 3)

        results = reg.unregister_all(mod_id="mbpl")
        check("unregister_all(mod) is scoped and deterministic",
              all(r.ok for r in results) and sorted(reg.registrations()) ==
              ["othermod__api_a"], [r.code for r in results])
    finally:
        sd = mat.shutdown()
        report["shutdown"] = sd
        print("shutdown: ok=%s dll_unloaded=%s" % (sd.get("ok"), sd.get("dll_unloaded")))

    final = mat.existing_row_names()
    check("final state is the vanilla baseline",
          len(final) == report["baseline_rows"] and not [n for n in final if "__" in n],
          len(final))

    report["checks"] = checks
    report["passed"] = sum(1 for c in checks if c["pass"])
    report["failed"] = sum(1 for c in checks if not c["pass"])
    report["elapsed_s"] = round(time.time() - started, 1)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    print("\n%d passed, %d failed in %ss -> %s"
          % (report["passed"], report["failed"], report["elapsed_s"], a.out))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
