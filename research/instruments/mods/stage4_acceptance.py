#!/usr/bin/env python3
"""Stage 4 acceptance: mods DISCOVERED from a tree, not handed to a controller.

THE CLAIM BEING TESTED
----------------------
Dropping self-describing mod folders into a discovery root is enough for the
framework to identify, validate, order and load them -- with no per-mod
knowledge anywhere in the framework or in this file.

So this script contains no mod_id, no container name, no asset path and no item
name. Everything it acts on comes from the load plan, and the load plan comes
from the manifests. Grep it for "alphamod" and you will not find one: if you
could, the acceptance would be proving something weaker than it claims.

WHAT IS PROVEN, AND SEPARATELY
------------------------------
  1. both mods discovered from the tree, and validated
  2. the order is deterministic under shuffled enumeration AND folder renames
  3. each mod's declared content is really mounted, and its packages registered
  4. their generated assets are distinct live objects
  5. their items register under their OWN mod_id, derived not authored
  6. unregistering one mod leaves the other fully intact
  7. shutdown restores the vanilla baseline exactly
  8. the negative fixtures never reach the execution plan at all

Point 6 is the one that needs the most care: "the other is intact" is not "the
other's row is still listed". It is checked by re-reading the surviving mod's
mesh, icon and material slots from the live process after its neighbour has been
torn down.
"""
import argparse
import copy
import itertools
import json
import os
import random
import shutil
import struct
import sys
import tempfile
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "research", "instruments", "eri"),
           os.path.join(REPO, "research", "instruments", "ipp"),
           os.path.join(REPO, "research", "instruments", "items"),
           os.path.join(REPO, "tools", "modframework"),
           os.path.join(REPO, "tools", "modkit")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                        # noqa: E402
import cr01c3_recon as recon                      # noqa: E402
import cr01c5_controller as c5                    # noqa: E402
import items_session                              # noqa: E402
import materializer                               # noqa: E402
import definition as ItemsAPI                     # noqa: E402
import container_report                           # noqa: E402
import diagnostics as D                           # noqa: E402
import discovery                                  # noqa: E402
import execution                                  # noqa: E402
import namespace as ns                            # noqa: E402
import resolve                                    # noqa: E402
import treefixtures as fx                         # noqa: E402
from aggregate_acceptance import world_state      # noqa: E402

WORLD_ITEM_CLASS = "BP_StaticMasterItem_C"


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


def definition_from(declaration):
    """A declaration + its manifest-supplied mod_id -> an ItemDefinition.

    ``ItemId(mod_id, local_id)`` is constructed HERE from the mod_id the
    execution layer attached, never from anything the mod's code said. That is
    what makes "registers under its own ModId" a structural property rather
    than a convention the mod is trusted to follow.
    """
    return ItemsAPI.ItemDefinition(
        ItemsAPI.ItemId(declaration["mod_id"], declaration["local_id"]),
        display_name=declaration["display_name"],
        short_name=declaration["short_name"],
        description=declaration["description"],
        weight=declaration["weight"],
        width=declaration.get("width", 1), height=declaration.get("height", 1),
        inventory_icon=ItemsAPI.AssetRef(declaration["icon"]),
        world_mesh=ItemsAPI.AssetRef(declaration["mesh"]),
        world_class=WORLD_ITEM_CLASS,
        transform=ItemsAPI.Transform(translation=(0.0, 0.0, 5.0)))


def read_mesh_slots(api, pid, mesh_obj):
    """What the live mesh's material slots ACTUALLY are.

    Reads rather than verifies: the caller then asserts a property (every slot
    belongs to this mod's namespace) instead of comparing against a predicted
    list. A generic loader cannot predict a mod's slot names, and should not
    have to in order to check that a mod only ever got its own materials.
    """
    handle = eri.open_process_read_only(api, pid)
    try:
        i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
        namepool, objects = recon.universe(api, handle, i01["base_address"],
                                           i01["image_size_bytes"])

        def path_of(address):
            if not address:
                return None
            try:
                return eri.canonicalize_object_path(
                    eri.resolve_object_path(address, objects).get("object_path"))
            except Exception:                                      # noqa: BLE001
                return None

        def fname(entry_id):
            try:
                return eri.decode_fname_entry_id(api, handle, namepool,
                                                 entry_id).get("text")
            except Exception:                                      # noqa: BLE001
                return None

        script_structs = [
            a for a, r in objects.items()
            if r.get("name_ok") and r.get("name_text") == "StaticMaterial"
            and (objects.get(r.get("class_ptr") or 0) or {}).get("name_text")
            == "ScriptStruct"]
        if len(script_structs) != 1:
            raise RuntimeError("StaticMaterial ScriptStruct not uniquely resolved")
        stride = struct.unpack("<i", api.read_process_memory(
            handle, script_structs[0] + 0x58, 4))[0]

        data = eri._read_u64(api, handle, mesh_obj + c5.SM_STATICMATERIALS)
        count = struct.unpack("<i", api.read_process_memory(
            handle, mesh_obj + c5.SM_STATICMATERIALS + 8, 4))[0]
        if not data or count <= 0:
            raise RuntimeError("mesh 0x%x has no material slots" % mesh_obj)
        blob = api.read_process_memory(handle, data, count * stride)

        slots = []
        for index in range(count):
            material = struct.unpack_from("<Q", blob, index * stride)[0]
            slot_name = fname(struct.unpack_from("<I", blob, index * stride + 8)[0])
            parent = (eri._read_u64(api, handle, material + c5.MI_PARENT)
                      if material else 0)
            slots.append({"slot": index, "slot_name": slot_name,
                          "material_object": "0x%x" % material,
                          "material": path_of(material),
                          "parent_object": "0x%x" % parent,
                          "parent": path_of(parent)})
        return slots
    finally:
        api.close_handle(handle)


def container_state(api, stems):
    """Mounted / packages-registered for each named container, plus a control."""
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    handle = eri.open_process_read_only(api, i01["pid"])
    try:
        i14 = eri.run_i14(api, handle, i01["base_address"], i01["image_size_bytes"])
    finally:
        api.close_handle(handle)
    wanted = {stem.lower(): None for stem in stems}
    others = []
    for record in i14.get("mounted_paks", []):
        name = os.path.basename((record.get("pak_filename") or "").replace("\\", "/"))
        stem = os.path.splitext(name)[0].lower()
        if stem in wanted:
            wanted[stem] = record
        else:
            others.append({"pak": name, "mounted": record.get("is_mounted"),
                           "packages_registered":
                               record.get("has_io_container_header")})
    return {"pid": i01["pid"], "wanted": wanted, "others": others}


def prove_determinism(root, check, report):
    """Same manifests, many orders -- one plan. Twice over, two different ways."""
    _scan, found = discovery.scan(root, container_report.read_container)
    baseline = json.dumps(resolve.resolve(list(found)).as_dict(), sort_keys=True)

    permuted = set()
    for permutation in itertools.permutations(found):
        permuted.add(json.dumps(resolve.resolve(list(permutation)).as_dict(),
                                sort_keys=True))
    check("resolution is identical under every permutation of its input",
          permuted == {baseline}, "%d distinct results" % len(permuted))

    # And through the filesystem, with enumeration order deliberately scrambled.
    real_listdir = os.listdir
    shuffled_results = set()
    for seed in range(8):
        rng = random.Random(seed)

        def shuffled(path, _real=real_listdir, _rng=rng):
            entries = list(_real(path))
            _rng.shuffle(entries)
            return entries

        os.listdir = shuffled
        try:
            plan = resolve.plan_from_root(
                root, container_reader=container_report.read_container)[0]
        finally:
            os.listdir = real_listdir
        shuffled_results.add(json.dumps(plan.as_dict(), sort_keys=True))
    check("the plan is identical under 8 shuffled filesystem enumerations",
          shuffled_results == {baseline}, "%d distinct results"
          % len(shuffled_results))
    report["determinism"] = {"permutations": len(permuted),
                             "shuffled_enumerations": len(shuffled_results)}


def prove_negatives(check, report):
    """Every failure class, in one tree, alongside a healthy mod.

    Built in a throwaway directory: the point is what reaches the execution
    plan, and nothing here needs the game.
    """
    root = tempfile.mkdtemp(prefix="stage4-negative-")
    try:
        expected_bad = set()
        for build in fx.ALL_NEGATIVE:
            for subject in build(root):
                expected_bad.add(subject)
        fx.build_mod(root, "AHealthyMod", "healthymod")
        plan = resolve.plan_from_root(root)[0]

        # Membership, not equality: some negative fixtures include a mod that
        # is itself perfectly valid (the PROVIDER whose consumer asks for an
        # impossible version). Demanding an exact list would call the resolver
        # wrong for correctly loading a mod with nothing wrong with it.
        check("the healthy mod still loads despite %d broken neighbours"
              % len(fx.ALL_NEGATIVE),
              "healthymod" in plan.load_order, plan.load_order)

        named_bad = {s for s in expected_bad if not os.path.isabs(str(s))}
        leaked = sorted(named_bad & set(plan.load_order))
        check("no mod from any negative fixture reached the load plan",
              not leaked, leaked)

        for code in (D.DUPLICATE_MOD_ID, D.MISSING_DEPENDENCY,
                     D.INCOMPATIBLE_DEPENDENCY_VERSION, D.DEPENDENCY_CYCLE,
                     D.EXPLICIT_CONFLICT, D.MALFORMED_MANIFEST,
                     D.UNSUPPORTED_MANIFEST_VERSION, D.UNSUPPORTED_FRAMEWORK_API,
                     D.MISSING_ARTIFACT, D.INVALID_MOD_ID):
            check("the plan reports %s" % code,
                  any(d.code == code for d in plan.diagnostics),
                  [d.code for d in plan.diagnostics])

        # The execution layer must never be handed a declaration for an
        # excluded mod -- that is what "no partially accepted mod leaks into the
        # live execution plan" means operationally.
        declarations, _diags = execution.item_declarations(plan)
        offenders = sorted({d["mod_id"] for d in declarations}
                           - set(plan.load_order))
        check("the execution layer produced declarations only for planned mods",
              not offenders, offenders)

        for mod_id in plan.excluded:
            check("excluded %r carries no manifest in the plan" % mod_id,
                  mod_id not in plan.manifests, mod_id)
        report["negative_plan"] = plan.as_dict()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Stage 4 live acceptance")
    ap.add_argument("--root", default="D:/UEScratch/ModsRoot")
    ap.add_argument("--out", required=True)
    ap.add_argument("--skip-live", action="store_true",
                    help="run only the parts that need no game")
    a = ap.parse_args(argv)

    check = Checks()
    report = {"root": a.root,
              "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    print("\n=== 1. discovery and validation ===")
    scan_report, found = discovery.scan(a.root, container_report.read_container)
    plan = resolve.resolve(found)
    report["scan"] = scan_report
    report["plan"] = plan.as_dict()
    check("every folder in the tree was examined", len(found) >= 2,
          scan_report["folders_examined"])
    check("every discovered mod validated with no fatal diagnostic",
          plan.ok and not plan.excluded, plan.excluded)
    check("at least two independently namespaced mods were discovered",
          len(plan.load_order) >= 2, plan.load_order)
    folders = {d.folder for d in found if d.mod_id}
    check("no folder name equals the mod_id it holds, so identity cannot be "
          "coming from the folder", not (folders & set(plan.load_order)),
          sorted(folders))

    print("\n=== 2. determinism ===")
    prove_determinism(a.root, check, report)
    check("the load order honours the declared dependency graph",
          all(all(plan.load_order.index(dep.mod_id) < plan.load_order.index(mod_id)
                  for dep in plan.manifests[mod_id].dependencies)
              for mod_id in plan.load_order), plan.load_order)

    print("\n=== 8. negative fixtures ===")
    prove_negatives(check, report)

    declarations, decl_diagnostics = execution.item_declarations(plan)
    report["declarations"] = declarations
    report["declaration_diagnostics"] = [d.as_dict() for d in decl_diagnostics]
    check("every planned mod contributed item declarations",
          {d["mod_id"] for d in declarations} == set(plan.load_order),
          sorted({d["mod_id"] for d in declarations}))
    check("no declaration was allowed to name its own namespace",
          not [d for d in decl_diagnostics if "names a mod_id" in d.detail],
          [d.detail for d in decl_diagnostics])

    if a.skip_live:
        return _finish(report, check, a.out)

    api = eri.Win32Api()
    stems = [c for mod_id in plan.load_order
             for c in execution.containers_for(plan, mod_id)]
    print("\n=== 3. declared content is mounted ===")
    state = container_state(api, stems)
    report["container_state"] = {"wanted": {k: bool(v) for k, v in
                                            state["wanted"].items()},
                                 "others": state["others"]}
    for stem, record in sorted(state["wanted"].items()):
        check("%s is mounted" % stem, record is not None and record.get("is_mounted"),
              record)
        check("%s has its packages registered" % stem,
              record is not None and record.get("has_io_container_header"),
              "mounted != resolvable; read separately")
    control = [o for o in state["others"] if o["packages_registered"] is False]
    check("a bare .pak in the same directory reports NO packages registered",
          bool(control), "without this control a True above proves nothing")

    before = world_state(api)
    report["world_before"] = before
    session = items_session.AggregateSession()
    info = session.init()
    report["session_init"] = info
    check("the Items subsystem initialised", info.get("attached"), info)

    registered = {}
    try:
        print("\n=== 4-5. register each mod's items under its own mod_id ===")
        for declaration in declarations:
            mod_id = declaration["mod_id"]
            definition = definition_from(declaration)
            flat = materializer.flatten(definition)
            result = session.register(flat)
            if not check("Register(%s) succeeded" % definition.row_name,
                         result.get("ok"), result.get("detail")):
                continue
            held = session.rows[definition.row_name]
            registered.setdefault(mod_id, []).append(
                {"row_name": definition.row_name, "flat": flat,
                 "icon_object": held["icon_object"],
                 "mesh_object": held["mesh_object"]})
            check("%s derived its row name from the manifest mod_id"
                  % definition.row_name,
                  definition.row_name.startswith(mod_id + "__"),
                  definition.row_name)
            slots = read_mesh_slots(api, state["pid"], int(held["mesh_object"], 16))
            registered[mod_id][-1]["slots"] = slots
            check("%s's mesh slots all resolve to ITS OWN namespace" % mod_id,
                  all(ns.owning_mod(s["material"] or "") == mod_id for s in slots),
                  [s["material"] for s in slots])
            check("%s's slot parents all resolve to a real vanilla material"
                  % mod_id,
                  all(s["parent"] and not ns.is_mod_path(s["parent"])
                      for s in slots),
                  [s["parent"] for s in slots])

        report["registered"] = {k: [{kk: vv for kk, vv in row.items() if kk != "flat"}
                                    for row in v] for k, v in registered.items()}
        mod_ids = sorted(registered)
        check("every planned mod registered at least one item",
              set(mod_ids) == set(plan.load_order), mod_ids)

        print("\n=== 5. the mods' generated assets are distinct ===")
        meshes = {m: {r["mesh_object"] for r in rows} for m, rows in registered.items()}
        icons = {m: {r["icon_object"] for r in rows} for m, rows in registered.items()}
        all_meshes = [o for s in meshes.values() for o in s]
        all_icons = [o for s in icons.values() for o in s]
        check("no two mods share a mesh object",
              len(all_meshes) == len(set(all_meshes)), meshes)
        check("no two mods share an icon object",
              len(all_icons) == len(set(all_icons)), icons)
        materials = {m: {s["material"] for r in rows for s in r.get("slots", [])}
                     for m, rows in registered.items()}
        pairs = [(a1, b1) for a1, b1 in itertools.combinations(sorted(materials), 2)]
        check("no two mods share a material instance",
              all(not (materials[x] & materials[y]) for x, y in pairs), materials)
        check("all rows are present in the aggregate at once",
              {r["row_name"] for rows in registered.values() for r in rows}
              <= set(session.table_rows()), session.table_rows())

        print("\n=== 6. selective unregister leaves the other mod intact ===")
        victim = mod_ids[0]
        survivor = mod_ids[-1]
        check("the fixture has two distinct mods to test selectivity with",
              victim != survivor, mod_ids)
        for row in registered[victim]:
            outcome = session.unregister(row["flat"])
            check("Unregister(%s) succeeded" % row["row_name"],
                  outcome.get("ok"), outcome.get("detail"))
        live_rows = session.table_rows()
        check("every row of %r is gone" % victim,
              not [r for r in registered[victim] if r["row_name"] in live_rows],
              live_rows)
        check("every row of %r survived" % survivor,
              all(r["row_name"] in live_rows for r in registered[survivor]),
              live_rows)
        # Intact means intact, not listed: re-read the survivor from the process.
        for row in registered[survivor]:
            slots_now = read_mesh_slots(api, state["pid"],
                                        int(row["mesh_object"], 16))
            check("%r's mesh still resolves its own materials after its "
                  "neighbour was torn down" % survivor,
                  all(ns.owning_mod(s["material"] or "") == survivor
                      for s in slots_now),
                  [s["material"] for s in slots_now])
            check("%r's slot count is unchanged after the unload" % survivor,
                  len(slots_now) == len(row.get("slots", [])),
                  "%d -> %d" % (len(row.get("slots", [])), len(slots_now)))
            report.setdefault("survivor_slots_after_unload", []).append(slots_now)

        print("\n=== 7. unregister the rest ===")
        for row in registered[survivor]:
            outcome = session.unregister(row["flat"])
            check("Unregister(%s) succeeded" % row["row_name"],
                  outcome.get("ok"), outcome.get("detail"))
        check("the aggregate table is empty again", session.table_rows() == [],
              session.table_rows())
    finally:
        if session.initialised:
            try:
                report["shutdown"] = session.shutdown()
            except Exception as error:                             # noqa: BLE001
                report["shutdown_error"] = "%s: %s" % (type(error).__name__, error)
        report["notes"] = session.note[-40:]

    shutdown = report.get("shutdown") or {}
    check("shutdown completed and unloaded cleanly", shutdown.get("ok"), shutdown)

    print("\n=== 7. back to the exact baseline ===")
    after = world_state(api)
    report["world_after"] = after
    check("MasterItemList holds exactly the rows it held before",
          after["MasterItemList"] == before["MasterItemList"],
          "%d -> %d" % (before["master_rows"], after["master_rows"]))
    check("ItemList is unchanged", after["ItemList"] == before["ItemList"],
          "%d -> %d" % (before["itemlist_rows"], after["itemlist_rows"]))
    check("ParentTables.Num is back to its baseline",
          after["ParentTables"]["num"] == before["ParentTables"]["num"],
          "%s -> %s" % (before["ParentTables"], after["ParentTables"]))
    check("the ItemList subscription count is unchanged",
          after["subscriptions"] == before["subscriptions"],
          "%s -> %s" % (before["subscriptions"], after["subscriptions"]))
    release = shutdown.get("release_table") or {}
    check("the aggregate table was unrooted", release.get("rooted_after") == 0,
          release)
    check("the asset store owns nothing after shutdown",
          release.get("owned_count") == 0, release)
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
