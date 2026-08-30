#!/usr/bin/env python3
"""Stage 4.5 acceptance: the platform contracts, exercised end to end.

WHAT THIS PROVES
----------------
That the Stage 4 load plan, the platform's lifecycle and ownership model, and
the item registration path proven in Stages 2 and 3 compose -- and that the
lifecycle guarantee survives the cases where it is actually hard.

Like the Stage 4 acceptance, this file contains no per-mod knowledge: everything
comes from the plan and from the mods' own declarations. Grep it for a mod_id
and you will not find one.

Run with ``--skip-live`` to prove everything that does not need MISERY (which is
almost all of it -- that is the architectural claim). Run without it to prove
the items path against the real game as well.
"""
import argparse
import json
import os
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "items"),
           os.path.join(REPO, "research", "instruments", "mods"),
           os.path.join(REPO, "tools", "modplatform"),
           os.path.join(REPO, "tools", "modframework"),
           os.path.join(REPO, "tools", "modkit")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import capabilities as CAP                       # noqa: E402
import console as CONSOLE                        # noqa: E402
import container_report                          # noqa: E402
import errors as E                               # noqa: E402
import events as EV                              # noqa: E402
import host as HOST                              # noqa: E402
import items_backend                             # noqa: E402
import modid                                     # noqa: E402
import reference_host                            # noqa: E402
import resolve                                   # noqa: E402


class Checks(object):
    def __init__(self):
        self.rows = []

    def __call__(self, label, ok, detail=""):
        self.rows.append({"check": label, "pass": bool(ok), "detail": str(detail)})
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", label,
                               "" if ok else "  -- %s" % detail))
        return bool(ok)

    @property
    def failed(self):
        return [r for r in self.rows if not r["pass"]]


def build_platform(root, settings_root, backend):
    plan, report = resolve.plan_from_root(
        root, container_reader=container_report.read_container)
    platform = HOST.Platform(settings_root, items_backend=backend)
    platform.declare_plan(plan.load_order)
    console = CONSOLE.Console(platform, plan=plan, discovery_report=report)
    return plan, report, platform, console


def main(argv=None):
    ap = argparse.ArgumentParser(description="Stage 4.5 acceptance")
    ap.add_argument("--root", default="D:/UEScratch/ModsRoot")
    ap.add_argument("--settings-root", default="D:/UEScratch/ModSettings")
    ap.add_argument("--out", required=True)
    ap.add_argument("--skip-live", action="store_true")
    a = ap.parse_args(argv)

    check = Checks()
    report = {"root": a.root,
              "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "api_version": str(CAP.API_VERSION)}
    session = None
    backend = None

    if a.skip_live:
        backend = items_backend.RecordingItemsBackend()
    else:
        import items_session                                       # noqa: PLC0415
        session = items_session.AggregateSession()
        info = session.init()
        report["session_init"] = info
        check("the live Items session initialised", info.get("attached"), info)
        backend = items_backend.SessionItemsBackend(session)

    plan, scan, platform, console = build_platform(a.root, a.settings_root, backend)
    report["load_order"] = list(plan.load_order)
    check("the Stage 4 plan resolved with no exclusions",
          plan.ok and not plan.excluded, plan.excluded)
    check("at least two independently namespaced mods are planned",
          len(plan.load_order) >= 2, plan.load_order)

    try:
        print("\n=== 1. capability negotiation happens before initialisation ===")
        modules, problems = reference_host.discover_modules(plan)
        report["module_problems"] = [p.as_dict() for p in problems]
        check("every planned mod's code imported", not problems,
              [p.detail for p in problems])
        check("every mod declared the capabilities it needs",
              all(m.required for m in modules),
              [(m.mod_id, m.required) for m in modules])

        outcomes = reference_host.load_all(platform, plan, modules)
        report["load_outcomes"] = outcomes
        check("every planned mod loaded", all(o["ok"] for o in outcomes), outcomes)
        check("every mod is in the LOADED state",
              all(platform.state_of(m) == HOST.LOADED for m in plan.load_order),
              {m: platform.state_of(m) for m in plan.load_order})

        print("\n=== 2. everything acquired is owned by its ModId ===")
        for mod_id in plan.load_order:
            owned = platform.record(mod_id).owner.owned_summary()
            kinds = sorted(owned["resources"])
            check("%s owns resources across %d subsystem kind(s)"
                  % (mod_id, len(kinds)), len(kinds) >= 3, kinds)
            keys = [k for kind in owned["resources"].values() for k in kind["held"]]
            foreign = [k for k in keys
                       if ":" in k and k.split(":", 1)[0] not in (mod_id,
                                                                  "platform")]
            check("%s owns nothing in another mod's namespace" % mod_id,
                  not foreign, foreign)

        print("\n=== 3. items register under each mod's own ModId ===")
        item_outcomes = reference_host.register_declared_items(platform, modules)
        report["item_outcomes"] = item_outcomes
        check("every mod registered its declared items",
              all(o["ok"] for o in item_outcomes), item_outcomes)
        rows = [row for o in item_outcomes for row in o.get("rows", [])]
        report["rows"] = rows
        check("every row name decomposes to the mod that declared it",
              all(modid.split_row_name(r) and modid.split_row_name(r)[0]
                  == o["mod_id"]
                  for o in item_outcomes for r in o.get("rows", [])), rows)
        check("two mods with the same local id produced distinct rows",
              len(set(rows)) == len(rows) and len(rows) >= 2, rows)

        print("\n=== 4. the developer console answers every required question ===")
        questions = {
            "discovered mods": "mods",
            "resolved load order": "loadorder",
            "mod state": "mods",
            "dependency/conflict failure": "why",
            "registered items": "items",
            "owned assets/resources": "owned",
            "structured subsystem errors": "errors",
        }
        answers = {}
        for question, command in sorted(questions.items()):
            result = console.run(command)
            answers[question] = result
            check("console can explain %s ('%s')" % (question, command),
                  result.get("ok"), result.get("error"))
        report["console"] = {q: answers[q].get("result") for q in answers}
        listed = answers["registered items"]["result"]["items"]
        check("the console lists items per mod",
              sum(len(row["held"]) for row in listed) == len(rows), listed)

        print("\n=== 5. inter-mod services, and what happens to a held handle ===")
        published = platform.services.published()
        report["services"] = published
        check("each mod published its own service",
              len(published) >= 2, sorted(published))
        consumer, provider = plan.load_order[-1], plan.load_order[0]
        provider_service = "%s:info" % provider
        handle = None
        if provider_service in published:
            handle = platform.record(consumer).context.services.bind(
                provider_service, "^1.0.0")
            check("%s could call %s's service" % (consumer, provider),
                  handle.call("local_id") is not None, provider_service)

        print("\n=== 6. unloading one mod releases everything it owned ===")
        victim = plan.load_order[0]
        survivor = plan.load_order[-1]
        before_rows = set(backend.rows) if hasattr(backend, "rows") else set(
            backend.live_rows())
        teardown = platform.unload(victim)
        report["teardown"] = teardown
        check("unload reported a teardown for %s" % victim,
              teardown.get("mod_id") == victim, teardown)
        check("no resource of %s was left unreleased" % victim,
              not [r for r in platform.record(victim).owner.resources()
                   if not r.released],
              [r.as_dict() for r in platform.record(victim).owner.resources()
               if not r.released])
        check("no live callback of %s remains" % victim,
              not [t for t in platform.record(victim).owner.tokens() if t.live],
              [t.key for t in platform.record(victim).owner.tokens() if t.live])

        after_rows = set(backend.rows) if hasattr(backend, "rows") else set(
            backend.live_rows())
        gone = before_rows - after_rows
        check("%s's item rows were unregistered" % victim,
              all(modid.split_row_name(r)[0] == victim for r in gone), sorted(gone))
        check("%s's item rows survived" % survivor,
              any(modid.split_row_name(r)[0] == survivor for r in after_rows),
              sorted(after_rows))

        if handle is not None:
            check("a service handle held past its provider's unload stops working",
                  not handle.available, handle.as_dict())
            try:
                handle.call("local_id")
                check("calling a dead service handle raises", False,
                      "it returned instead")
            except E.PlatformError as error:
                check("calling a dead service handle raises a structured error",
                      error.subsystem == E.SUB_SERVICES, error.name)

        print("\n=== 7. the survivor is untouched ===")
        check("%s is still LOADED" % survivor,
              platform.state_of(survivor) == HOST.LOADED,
              platform.state_of(survivor))
        survivor_owned = platform.record(survivor).owner.owned_summary()
        check("%s still owns its resources" % survivor,
              any(kind["held"] for kind in survivor_owned["resources"].values()),
              survivor_owned)
        check("%s's events still dispatch" % survivor,
              platform.events.publish_guarded(
                  EV.EVENT_MOD_LOADED, {"mod_id": survivor})["faults"] == [],
              "a fault means a dead handler was still reachable")

        print("\n=== 8. a managed host could reclaim the unloaded mod ===")
        reclaim = reference_host.is_reclaimable(platform, victim)
        report["reclaimable"] = reclaim
        check("%s is reclaimable: nothing unreleased, no live token" % victim,
              reclaim["reclaimable"], reclaim)
        alive = reference_host.is_reclaimable(platform, survivor)
        check("%s is NOT reclaimable while it is still loaded" % survivor,
              not alive["reclaimable"], alive)

        print("\n=== 9. shutdown returns the platform to nothing ===")
        reports = platform.shutdown()
        report["shutdown"] = reports
        check("shutdown unloaded the remaining mods",
              all(platform.state_of(m) in (HOST.UNLOADED, HOST.FAILED)
                  for m in plan.load_order),
              {m: platform.state_of(m) for m in plan.load_order})
        remaining = set(backend.rows) if hasattr(backend, "rows") else set(
            backend.live_rows())
        ours = [r for r in remaining if modid.split_row_name(r)]
        check("no mod item row is left registered", not ours, sorted(ours))
        check("no input action is left registered",
              platform.input.actions() == [], platform.input.actions())
        check("no service is left published",
              platform.services.published() == {},
              platform.services.published())
        for mod_id in plan.load_order:
            state = reference_host.is_reclaimable(platform, mod_id)
            check("%s is reclaimable after shutdown" % mod_id,
                  state["reclaimable"], state)

        report["diagnostics"] = platform.diagnostics()
    finally:
        if session is not None:
            try:
                report["session_shutdown"] = session.shutdown()
            except Exception as error:                             # noqa: BLE001
                report["session_shutdown_error"] = "%s: %s" % (
                    type(error).__name__, error)

    return _finish(report, check, a.out)


def _finish(report, check, out_path):
    report["checks"] = check.rows
    report["passed"] = len(check.rows) - len(check.failed)
    report["failed"] = len(check.failed)
    report["verdict"] = "PASS" if not check.failed else "FAIL"
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, default=str)
        handle.write("\n")
    print("\n%s -- %d passed, %d failed -> %s"
          % (report["verdict"], report["passed"], report["failed"], out_path))
    return 0 if not check.failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
