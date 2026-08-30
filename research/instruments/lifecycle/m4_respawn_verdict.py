#!/usr/bin/env python3
"""The death -> respawn verdict, computed from the captured evidence.

Classification uses FUObjectItem::SerialNumber -- the engine's own object
identity, what FWeakObjectPtr uses -- and never address equality alone. An
address can be handed back by the allocator for a different object of the same
size class, so "same address" is not "same object"; (InternalIndex,
SerialNumber) is.

Three snapshots, all from the SAME process, which is what makes identity
comparable at all:

    alive   the last full resolve before the character died
    before  the death screen, immediately before the respawn was pressed
    after   possession settled on a new pawn

Nothing here expects a particular outcome. Whether the PlayerController and the
inventory survive or are recreated is the measurement, not the assumption.
"""
import argparse
import json
import os
import sys

ANCHORS = ("world", "game_instance", "local_player", "player_controller",
           "pawn", "player_inventory")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def ident(snap, key):
    a = ((snap.get("anchors") or {}).get(key) or {})
    if not a.get("resolved"):
        return None
    e = ((a.get("identity") or {}).get("engine_identity") or {})
    if not e.get("round_trip_verified"):
        return None
    return {"internal_index": e.get("internal_index"),
            "serial_number": e.get("serial_number"),
            "address": a.get("address"),
            "object_path": (a.get("identity") or {}).get("object_path"),
            "name": a.get("name"), "class": a.get("class")}


def classify(before, after):
    """SURVIVED / RECREATED / GONE / APPEARED, by the engine's own identity."""
    if before is None and after is None:
        return "ABSENT-BOTH", "not resolvable on either side"
    if before is None:
        return "APPEARED", "not resolvable before, resolvable after"
    if after is None:
        return "GONE", "resolvable before, not resolvable after"
    b = (before["internal_index"], before["serial_number"])
    a = (after["internal_index"], after["serial_number"])
    if b == a:
        return "SURVIVED", ("same (InternalIndex, SerialNumber) %r: the engine's own object "
                            "identity says this is the same object" % (a,))
    if before["internal_index"] == after["internal_index"]:
        return "RECREATED", ("the GUObjectArray slot %d was REUSED and SerialNumber went "
                             "%r -> %r. Address comparison alone would have called this "
                             "survival if the allocator had also reused the address."
                             % (a[0], b[1], a[1]))
    return "RECREATED", ("different slot and serial: %r -> %r" % (b, a))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--alive", required=True, help="full resolve while the character was alive")
    ap.add_argument("--before", required=True, help="the death screen, before the respawn")
    ap.add_argument("--after", required=True, help="after possession settled")
    ap.add_argument("--transition", required=True, help="the 50ms possession timeline")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    alive, before, after = load(a.alive), load(a.before), load(a.after)
    trans = load(a.transition)
    rep = {"snapshots": {}}

    # ---- 0. everything below is only meaningful within ONE process ---------
    ids = [(s.get("pid"), s.get("process_start_time")) for s in (alive, before, after)]
    same_process = len(set(ids)) == 1 and all(p and t for p, t in ids)
    rep["same_process"] = {
        "pids_and_start_times": ids, "all_identical": same_process,
        "why_it_matters": ("object identity is only comparable inside one process: a new "
                           "process has a new heap, and identical paths there are different "
                           "objects. If this were false, every verdict below would be void.")}
    for label, s in (("alive", alive), ("before", before), ("after", after)):
        rep["snapshots"][label] = {
            "label": s.get("label"), "observed_at": s.get("observed_at"),
            "pid": s.get("pid"), "screen": s.get("screen"),
            "death_screen_live": s.get("death_screen_live"),
            "complete": s.get("complete"),
            "gameplay_oracle": s.get("runner_gameplay_ready"),
            "gameplay_oracle_reasons": (s.get("runner_gameplay_proof") or {}).get("reasons"),
            "cross_checks": "%s/%s run, %s skipped" % (s.get("cross_checks_passed"),
                                                       s.get("cross_checks_run"),
                                                       s.get("cross_checks_skipped_count")),
            "garbage_excluded": s.get("garbage_excluded_count")}

    # ---- 1. identity of every anchor, across both halves -------------------
    rep["identities"] = {}
    rep["classification"] = {}
    for key in ANCHORS:
        ia, ib, ic = ident(alive, key), ident(before, key), ident(after, key)
        rep["identities"][key] = {"alive": ia, "before_respawn": ib, "after_respawn": ic}
        v1, w1 = classify(ia, ib)
        v2, w2 = classify(ib, ic)
        v3, w3 = classify(ia, ic)
        rep["classification"][key] = {
            "alive -> death": {"verdict": v1, "why": w1},
            "death -> respawned": {"verdict": v2, "why": w2},
            "alive -> respawned": {"verdict": v3, "why": w3}}

    # ---- 2. the pawns, specifically ----------------------------------------
    old_pawn, new_pawn = ident(alive, "pawn"), ident(after, "pawn")
    rep["pawns"] = {"old": old_pawn, "new": new_pawn}
    if old_pawn and new_pawn:
        rep["pawns"]["are_different_objects"] = (
            (old_pawn["internal_index"], old_pawn["serial_number"])
            != (new_pawn["internal_index"], new_pawn["serial_number"]))
        rep["pawns"]["slot_reused"] = old_pawn["internal_index"] == new_pawn["internal_index"]
        rep["pawns"]["address_reused"] = old_pawn["address"] == new_pawn["address"]

    # ---- 3. no stale object reuse ------------------------------------------
    # Two distinct hazards, and they are different questions:
    #   (a) an anchor kept its address but is a DIFFERENT object -- the case
    #       address comparison cannot see, and the reason SerialNumber is used;
    #   (b) an anchor was reported resolved while absent from the walked
    #       universe -- a torn snapshot. _anchor already refuses that, so its
    #       absence here is a check that the guard held.
    stale = []
    for key in ANCHORS:
        ib, ic = ident(before, key), ident(after, key)
        if ib and ic and ib["address"] == ic["address"]:
            if (ib["internal_index"], ib["serial_number"]) != \
               (ic["internal_index"], ic["serial_number"]):
                stale.append({"anchor": key, "address": ib["address"],
                              "before": [ib["internal_index"], ib["serial_number"]],
                              "after": [ic["internal_index"], ic["serial_number"]],
                              "hazard": "same address, different object -- address comparison "
                                        "would have called this survival"})
    unresolved_but_named = [k for k in ANCHORS
                            if ((after.get("anchors") or {}).get(k) or {}).get("resolved")
                            and not ident(after, k)]
    rep["stale_object_reuse"] = {
        "same_address_different_object": stale,
        "resolved_without_a_verified_engine_identity": unresolved_but_named,
        "clean": not stale and not unresolved_but_named}

    # ---- 4. possession, in the after state ---------------------------------
    pc_after = ((after.get("anchors") or {}).get("player_controller") or {})
    pawn_routes = {r.get("route"): (r.get("evidence") or {}).get("value")
                   for r in ((after.get("anchors") or {}).get("pawn") or {}).get("routes", [])}
    rep["possession"] = {
        "routes": pawn_routes,
        "Controller_Pawn_equals_AcknowledgedPawn":
            len({v for v in pawn_routes.values() if v is not None}) == 1
            and all(v is not None for v in pawn_routes.values()),
        "note": ("both routes are read independently and the resolver refuses unless they "
                 "agree, so a resolved pawn anchor IS the agreement")}
    # and the same fact from the 50 ms timeline, which is a different instrument
    settled = [e for e in trans.get("timeline", []) if e.get("possession_agrees")]
    rep["possession"]["from_50ms_timeline"] = {
        "first_agreement_at_s": settled[0]["t"] if settled else None,
        "PlayerController": settled[0]["PlayerController"] if settled else None,
        "pawn": settled[0]["Controller_Pawn"] if settled else None}

    # ---- 5. authority / readiness ------------------------------------------
    rep["readiness"] = {
        "gameplay_oracle_after": after.get("runner_gameplay_ready"),
        "oracle": (after.get("runner_gameplay_proof") or {}).get("oracle"),
        "complete_after": after.get("complete"),
        "cross_checks_all_pass_after": after.get("cross_checks_all_pass"),
        "cross_checks_run_after": after.get("cross_checks_run"),
        "cross_checks_skipped_after": after.get("cross_checks_skipped_count")}

    # ---- 6. what the 50 ms poll could and could not see ---------------------
    tl = trans.get("timeline", [])
    rep["transition_observability"] = {
        "interval_s": trans.get("interval_s"),
        "distinct_states_seen": len(tl),
        "states": tl,
        "limit": ("Pawn and AcknowledgedPawn became non-null AND equal within a single 50 ms "
                  "sample, so any intermediate state where Pawn was set but AcknowledgedPawn "
                  "was not lasted less than one sampling interval. That is a limit of this "
                  "instrument, not evidence that no such state existed."
                  if len(tl) <= 2 else
                  "intermediate states were resolved between the death state and settled "
                  "possession; see states above")}

    rep["verdict"] = {
        "death_observed": before.get("death_screen_live", 0) > 0
                          and not ((before.get("anchors") or {}).get("pawn") or {}).get("resolved"),
        "respawn_observed": bool(settled),
        "after_is_complete_and_proven": bool(after.get("complete")
                                             and after.get("runner_gameplay_ready")),
        "no_stale_reuse": rep["stale_object_reuse"]["clean"],
        "same_process_throughout": same_process}
    rep["verdict"]["all_hold"] = all(rep["verdict"].values())

    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=False, default=str)
        f.write("\n")

    print("same process throughout: %s  %s" % (same_process, ids))
    print("\nanchor identity (InternalIndex, SerialNumber) -- the engine's own:")
    for key in ANCHORS:
        i = rep["identities"][key]
        def fmt(x):
            return "-" if not x else "idx=%s ser=%s" % (x["internal_index"], x["serial_number"])
        print("  %-18s alive[%-22s] death[%-22s] after[%-22s]"
              % (key, fmt(i["alive"]), fmt(i["before_respawn"]), fmt(i["after_respawn"])))
        print("      alive->death %-12s  death->respawned %-12s  alive->respawned %s"
              % (rep["classification"][key]["alive -> death"]["verdict"],
                 rep["classification"][key]["death -> respawned"]["verdict"],
                 rep["classification"][key]["alive -> respawned"]["verdict"]))
    print("\npawns: different objects=%s  slot_reused=%s  address_reused=%s"
          % (rep["pawns"].get("are_different_objects"), rep["pawns"].get("slot_reused"),
             rep["pawns"].get("address_reused")))
    print("stale object reuse: %s" % ("NONE" if rep["stale_object_reuse"]["clean"]
                                      else rep["stale_object_reuse"]))
    print("possession agrees after: %s (first seen at %ss by the 50ms poll)"
          % (rep["possession"]["Controller_Pawn_equals_AcknowledgedPawn"],
             rep["possession"]["from_50ms_timeline"]["first_agreement_at_s"]))
    print("readiness after: oracle=%s complete=%s checks=%s/%s"
          % (rep["readiness"]["gameplay_oracle_after"], rep["readiness"]["complete_after"],
             rep["readiness"]["cross_checks_run_after"] and
             after.get("cross_checks_passed"), rep["readiness"]["cross_checks_run_after"]))
    print("\nVERDICT: %s" % json.dumps(rep["verdict"]))
    return 0 if rep["verdict"]["all_hold"] else 1


if __name__ == "__main__":
    sys.exit(main())
