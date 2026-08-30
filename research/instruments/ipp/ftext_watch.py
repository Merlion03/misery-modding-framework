#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Sample three ITextData refcounts at high frequency.

WHY THE COARSE MEASUREMENT WAS NOT ENOUGH
-----------------------------------------
Sampling the counters once per hot-reload phase gave 1304 -> 1309 across four
register/unregister cycles: they climb, and they never come back down. But the
per-cycle attribution was confounded, and visibly so -- one of the rises
happened during a CLEANUP, which materializes nothing. The counter belongs to a
shared text object, so every copy anywhere in the running game moves it, and a
ten-second observation window is wide enough for the game to do plenty.

This samples only three 4-byte reads, so it can run at ~150 ms. Our
materialization writes all three fields in one tight loop, so it appears as a
SIMULTANEOUS step on all three counters within a single sample. Background
traffic does not behave that way: it touches one text at a time, for its own
reasons, at unrelated moments.

The distinction being drawn is therefore not "did the number go up" -- it did --
but "did OUR operation move it, by how much, and does anything ever give it
back".

Nothing is written. The counters are only read.
"""
import argparse
import json
import os
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                      # noqa: E402
import ftext_refcount as ftr    # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pointers", required=True,
                    help="comma-separated ITextData pointers, e.g. 0x...,0x...,0x...")
    ap.add_argument("--seconds", type=float, default=300.0)
    ap.add_argument("--interval", type=float, default=0.15)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    pointers = [ftr.as_int(p.strip()) for p in a.pointers.split(",") if p.strip()]
    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    handle = eri.open_process_read_only(api, i01["pid"])

    # Prove, once, that these pointers really are the objects we think they are,
    # before recording a single number from them.
    verified = ftr.probe_many(api, handle, pointers)
    print("pid %d  vptrs=%s same_type=%s" % (i01["pid"], verified["vptrs"],
                                             verified["all_same_concrete_type"]))
    for e in verified["entries"]:
        ss = e.get("source_string") or {}
        print("  %s rc=%-6s text=%r localized=%s"
              % (e["pointer"], e.get("refcount"), ss.get("text"), e.get("is_localized")))

    timeline, last = [], None
    started = time.time()
    deadline = started + a.seconds
    try:
        while time.time() < deadline:
            try:
                counts = tuple(ftr.read_u32(api, handle, p + ftr.TD_REFCOUNT)
                               for p in pointers)
            except Exception as exc:                           # noqa: BLE001
                timeline.append({"t": round(time.time() - started, 3), "error": repr(exc)})
                break
            if counts != last:
                delta = None if last is None else [c - l for c, l in zip(counts, last)]
                entry = {"t": round(time.time() - started, 3),
                         "at": time.strftime("%H:%M:%S", time.localtime()),
                         "counts": list(counts), "delta": delta,
                         "all_three_moved_together": bool(
                             delta and len(set(delta)) == 1 and delta[0] != 0)}
                timeline.append(entry)
                print("  [%8.3fs] %s  delta=%s%s"
                      % (entry["t"], list(counts), delta,
                         "  <-- all three together" if entry["all_three_moved_together"] else ""))
                sys.stdout.flush()
                last = counts
            time.sleep(a.interval)
    finally:
        api.close_handle(handle)

    together = [e for e in timeline if e.get("all_three_moved_together")]
    doc = {"pid": i01["pid"], "pointers": ["0x%x" % p for p in pointers],
           "interval_s": a.interval, "verified": verified, "timeline": timeline,
           "summary": {
               "distinct_states": len(timeline),
               "simultaneous_moves": len(together),
               "simultaneous_deltas": [e["delta"][0] for e in together],
               "first_counts": timeline[0]["counts"] if timeline else None,
               "last_counts": timeline[-1]["counts"] if timeline else None,
               "any_decrease": any(e.get("delta") and min(e["delta"]) < 0 for e in timeline)}}
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    print("\n%d state changes, %d of them simultaneous on all three; any decrease: %s"
          % (doc["summary"]["distinct_states"], doc["summary"]["simultaneous_moves"],
             doc["summary"]["any_decrease"]))
    print("wrote %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
