#!/usr/bin/env python3
"""Were the ALREADY-RECORDED snapshots affected by the agreement bug?

The gameplay snapshots for launch 1 and launch 2 were taken before the
null-filtering defect was found. Rather than assert "in gameplay every route was
non-null, so the old and new logic coincide", this proves it on the recorded
data itself.

The old logic dropped any falsy candidate and compared the survivors. The new
logic keeps a route whose evidence says ``resolved`` and compares its value
INCLUDING null. The two differ on exactly one input: a route whose evidence
resolved and whose value is null. So: scan every recorded route of every
recorded snapshot for that pattern. Zero occurrences means the two
implementations return the same answer on this data, and the recorded verdicts
stand. Any occurrence means a recorded verdict must be recomputed or discarded.

    python m4_recheck_recorded.py research/evidence/M4/*.json
"""
import glob
import json
import os
import sys


def routes_of(anchor):
    for r in anchor.get("routes") or []:
        ev = r.get("evidence")
        if isinstance(ev, dict):
            yield r.get("route"), ev


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    paths = []
    for a in args:
        paths.extend(sorted(glob.glob(a)))
    if not paths:
        print("no files matched", file=sys.stderr)
        return 2

    findings, scanned = [], 0
    for p in paths:
        try:
            doc = json.load(open(p, encoding="utf-8"))
        except Exception as exc:                               # noqa: BLE001
            print("  %-46s unreadable: %r" % (os.path.basename(p), exc))
            continue
        snaps = doc.get("observations") if isinstance(doc, dict) and "observations" in doc \
            else [doc]
        for snap in snaps:
            anchors = (snap or {}).get("anchors")
            if not anchors:
                continue
            scanned += 1
            for key, anchor in anchors.items():
                for route, ev in routes_of(anchor):
                    # Only OBJECT reads are comparable this way. An array route's
                    # evidence reports num/elements and carries no "value" key at
                    # all, so testing `ev.get("value") is None` on it fires on
                    # every array read -- which is what the first version of this
                    # checker did, flagging seven healthy gameplay routes as
                    # broken. Require the key to be PRESENT before judging it.
                    if "value" not in ev:
                        continue
                    # the ONLY input on which old and new logic disagree
                    if ev.get("resolved") and not ev.get("value"):
                        findings.append({"file": os.path.basename(p), "pid": snap.get("pid"),
                                         "screen": snap.get("screen"), "anchor": key,
                                         "route": route, "property": ev.get("property"),
                                         "recorded_resolved": anchor.get("resolved")})

    print("scanned %d recorded snapshots across %d files" % (scanned, len(paths)))
    if not findings:
        print("\nNO route was recorded as readable-and-null.")
        print("On this data the pre-fix filter is a no-op, so the old and new agreement")
        print("logic return the same answer and every recorded verdict stands unchanged.")
        return 0
    print("\n%d readable-and-null routes found -- these recorded verdicts were computed by the"
          " buggy logic and must NOT be cited as correct:" % len(findings))
    for f in findings:
        print("  %-34s pid=%-6s %-16s %-18s %-34s recorded resolved=%s"
              % (f["file"], f["pid"], f["screen"] or "-", f["anchor"],
                 f["route"] or f["property"], f["recorded_resolved"]))
    return 1


if __name__ == "__main__":
    sys.exit(main())
