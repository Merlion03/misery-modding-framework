#!/usr/bin/env python3
"""Turn observed lifecycle timelines into M4's two answers:

  1. did the resolver return a complete, self-consistent chain in every state
     where a chain should exist, and refuse in every state where it should not;
  2. for each anchor, across each transition -- did the object SURVIVE, or was
     it RECREATED?

THE ONE RULE THAT MAKES THIS HONEST
-----------------------------------
"Survived" is a claim about object identity, and object identity is only
comparable WITHIN a single process. Inside one pid, the same address holding the
same object path means the same object survived; a different address means a new
object was built. ACROSS pids nothing survives -- a new process has a new heap,
and two identical object paths in two processes are two different objects that
happen to be named the same. This tool therefore refuses to say "survived" for a
cross-process pair, no matter how identical the paths look. Saying otherwise
would be exactly the stale-pointer thinking the project forbids.

    python m4_analyze.py --timeline t.json [--timeline t2.json] [--snapshot s.json] --out r.json
"""
import argparse
import json
import os
import sys

ANCHORS = ("world", "game_instance", "local_player", "player_controller",
           "pawn", "player_inventory")
# There is deliberately NO list of "gameplay screen names" here. The runner's
# screen classifier labels ordinary gameplay WORLD_LOADING, because that state is
# its permissive fallback for "in a world, not in a menu" -- the runner never
# needed the distinction, since it decides gameplay with prove_gameplay instead.
#
# More importantly, deriving "this was gameplay" from the resolver's own output
# would make the acceptance test circular: the chain would be judged complete in
# exactly the states where it was complete. So gameplay is taken ONLY from an
# observation explicitly marked by an independent oracle
# (readiness.prove_gameplay, via `runner.py ready`).
def is_proven_gameplay(o):
    return bool(o.get("runner_gameplay_ready"))


def load(paths):
    obs = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            doc = json.load(f)
        if isinstance(doc, dict) and "observations" in doc:
            for o in doc["observations"]:
                o.setdefault("_source", os.path.basename(p))
                obs.append(o)
        else:
            doc.setdefault("_source", os.path.basename(p))
            obs.append(doc)
    for i, o in enumerate(obs):
        o["_order"] = i
    return obs


def anchor_of(o, key):
    return (o.get("anchors") or {}).get(key) or {}


def describe(o):
    return {"order": o.get("_order"), "source": o.get("_source"), "pid": o.get("pid"),
            "screen": o.get("screen"),
            "at": o.get("observed_at"), "t": o.get("seconds_since_start"),
            "complete": o.get("complete"), "why": o.get("why")}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    # One ordered input list. The earlier two-flag form put every --snapshot
    # before every --timeline regardless of the order they were typed, which
    # silently reordered the record: a snapshot taken AFTER a timeline appeared
    # before it, and the transition table then described a sequence nobody
    # observed. Order is evidence here, so the caller supplies it explicitly.
    ap.add_argument("--input", action="append", default=[], required=True,
                    help="snapshot or timeline file, IN CHRONOLOGICAL ORDER; repeatable")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    obs = load(a.input)
    obs = [o for o in obs if "anchors" in o or "why" in o]
    report = {"observations": len(obs), "states": [describe(o) for o in obs]}

    pids = [o.get("pid") for o in obs if o.get("pid")]
    report["distinct_pids"] = sorted(set(pids))
    report["launches_observed"] = len(set(pids))

    screens = [o.get("screen") for o in obs if "anchors" in o]
    report["distinct_screens"] = sorted({s for s in screens if s}) + (
        ["<unclassified>"] if any(s is None for s in screens) else [])

    # ---- 1. did the resolver behave correctly in each state? --------------
    behaviour = []
    for o in obs:
        if "anchors" not in o:
            behaviour.append({**describe(o), "verdict": "NO-PROCESS",
                              "correct": True,
                              "reason": "no live process to resolve against; recorded, not "
                                        "guessed at"})
            continue
        screen = o.get("screen")
        proven_gameplay = is_proven_gameplay(o)
        complete = bool(o.get("complete"))
        checks_ok = bool(o.get("cross_checks_all_pass"))
        missing = [k for k in ANCHORS if not anchor_of(o, k).get("resolved")]
        explained = [k for k in missing if anchor_of(o, k).get("why")]

        # An earlier version of this scoring rule assumed the resolver should
        # REFUSE outside gameplay, and it was wrong. The observed menu screens
        # carry a genuine World, GameInstance, LocalPlayer, PlayerController and
        # even a Pawn -- MISERY's menu is a real level with a real local player.
        # So resolving a chain there is not the resolver inventing a player; it
        # is the resolver reporting what is actually there. The correctness
        # criterion is therefore not "is it complete", it is:
        #
        #   every route that answered agreed with the other routes, and every
        #   anchor that did NOT resolve said why.
        #
        # Completeness is only *required* in gameplay, where the runner has
        # independently proved a player exists.
        # The UNIVERSAL invariant, checked in every state: routes that answered
        # agreed, and every anchor that did not resolve said why. A resolver that
        # silently returns nothing is as wrong as one that silently guesses.
        correct = checks_ok and len(explained) == len(missing)
        if proven_gameplay:
            correct = correct and complete
            verdict = "COMPLETE" if complete else "INCOMPLETE"
            reason = ("full self-consistent chain in independently-proven gameplay"
                      if correct
                      else "independently-proven gameplay without a complete chain; "
                           "missing: %s" % ", ".join(missing))
        else:
            verdict = "COMPLETE" if complete else "PARTIAL"
            reason = ("what exists in this state resolved, and every absence was explained "
                      "(gameplay not independently proven here, so completeness is reported, "
                      "not required)"
                      if correct else
                      "an anchor failed with no stated reason, or a cross-check failed")
        behaviour.append({**describe(o), "verdict": verdict, "correct": correct,
                          "complete": complete, "cross_checks_all_pass": checks_ok,
                          "proven_gameplay": proven_gameplay,
                          "unresolved": missing, "reason": reason})
    report["behaviour"] = behaviour
    report["behaviour_all_correct"] = all(b["correct"] for b in behaviour)

    # ---- 2. survival across consecutive transitions -----------------------
    transitions = []
    real = [o for o in obs if "anchors" in o]
    for prev, cur in zip(real, real[1:]):
        # F6, from the red team: `None == None` made a MISSING start time count
        # as a match, degenerating the guard to bare PID equality -- and Windows
        # recycles PIDs. An unknown start time is now "not comparable", not
        # "the same".
        prev_start, cur_start = prev.get("process_start_time"), cur.get("process_start_time")
        start_known = bool(prev_start) and bool(cur_start)
        same_process = (prev.get("pid") == cur.get("pid") and start_known
                        and prev_start == cur_start)
        start_unknown = prev.get("pid") == cur.get("pid") and not start_known
        entry = {"from": describe(prev), "to": describe(cur),
                 "same_process": same_process,
                 "same_process_unverifiable": start_unknown,
                 "anchors": {}}
        for key in ANCHORS:
            pa, ca = anchor_of(prev, key), anchor_of(cur, key)
            pid_addr, cur_addr = pa.get("address"), ca.get("address")
            ppath = (pa.get("identity") or {}).get("object_path")
            cpath = (ca.get("identity") or {}).get("object_path")
            if not pa.get("resolved") and not ca.get("resolved"):
                verdict, why = "ABSENT-BOTH", "not resolvable on either side"
            elif not pa.get("resolved"):
                verdict, why = "APPEARED", "not resolvable before, resolvable after"
            elif not ca.get("resolved"):
                verdict, why = "GONE", "resolvable before, not resolvable after"
            elif start_unknown:
                verdict = "NOT-COMPARABLE"
                why = ("the same pid, but at least one observation carries no process start "
                       "time, so 'same process' cannot be established -- and Windows recycles "
                       "pids. No survival claim is made.")
            elif not same_process:
                verdict = "RECREATED (new process)"
                why = ("a different process: identity cannot survive a restart, so this is "
                       "recorded as recreation even though the object paths match"
                       if ppath == cpath else "a different process, and the paths differ too")
            elif pid_addr == cur_addr and ppath == cpath:
                # Address equality alone cannot distinguish survival from the
                # allocator handing the same block back for a new object of the
                # same size class. The object path is compared too, and the
                # verdict is still labelled as what it is: unverified by serial
                # number. FUObjectItem::SerialNumber at +0x10 is the sound test
                # and is recorded as the known upgrade.
                verdict = "SURVIVED (address+path, serial unverified)"
                why = ("same process, same address, same object path. Not proven against "
                       "FUObjectItem::SerialNumber, so allocator reuse of the same size class "
                       "is not formally excluded.")
            elif pid_addr == cur_addr:
                verdict = "AMBIGUOUS"
                why = ("same process and same address, but the object path CHANGED -- that is "
                       "allocator reuse, not survival")
            else:
                verdict, why = "RECREATED", "same process, different address: a new object"
            entry["anchors"][key] = {"verdict": verdict, "why": why,
                                     "before": {"address": pid_addr, "object_path": ppath},
                                     "after": {"address": cur_addr, "object_path": cpath}}
        transitions.append(entry)
    report["transitions"] = transitions

    # ---- 3. the survival table, in-process transitions only ---------------
    table = {k: {} for k in ANCHORS}
    for t in transitions:
        if not t["same_process"]:
            continue
        label = "%s -> %s" % (t["from"]["screen"] or "?", t["to"]["screen"] or "?")
        for k in ANCHORS:
            table[k].setdefault(label, set()).add(t["anchors"][k]["verdict"])
    report["survival_table_in_process"] = {
        k: {label: sorted(v) for label, v in sorted(rows.items())} for k, rows in table.items()}

    # ---- 4. M4 acceptance ---------------------------------------------------
    proven = [b for b in behaviour if b.get("proven_gameplay")]
    proven_ok = [b for b in proven if b["verdict"] == "COMPLETE" and b["correct"]]
    proven_pids = sorted({b["pid"] for b in proven_ok})
    report["acceptance"] = {
        "launches_observed": report["launches_observed"],
        "launches_with_independently_proven_gameplay_and_complete_chain": proven_pids,
        "launches_required": 2,
        "launches_ok": len(proven_pids) >= 2,
        "distinct_states_observed": len({(b["screen"], b["pid"]) for b in behaviour}),
        "states_required": 3,
        "states_ok": len({(b["screen"], b["pid"]) for b in behaviour}) >= 3,
        "resolver_behaved_correctly_everywhere": report["behaviour_all_correct"],
    }
    report["acceptance"]["m4_core_met"] = bool(
        report["acceptance"]["launches_ok"] and report["acceptance"]["states_ok"]
        and report["acceptance"]["resolver_behaved_correctly_everywhere"])
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=2, sort_keys=False, default=str)
        f.write("\n")

    print("observations: %d   launches: %s   screens: %s"
          % (report["observations"], report["distinct_pids"], report["distinct_screens"]))
    print("\nresolver behaviour per state:")
    for b in behaviour:
        print("  pid=%-6s %-16s %-11s %-5s %s  %s"
              % (b["pid"], b["screen"] or "-", b["verdict"],
                 "GAME" if b.get("proven_gameplay") else "",
                 "ok" if b["correct"] else "WRONG", (b["reason"] or "")[:60]))
    print("\nin-process survival:")
    for k, rows in report["survival_table_in_process"].items():
        for label, verdicts in rows.items():
            print("  %-18s %-34s %s" % (k, label, ",".join(verdicts)))
    print("\nacceptance: %s" % json.dumps(report["acceptance"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
