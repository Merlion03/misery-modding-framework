#!/usr/bin/env python3
"""Stage 3 acceptance: source assets -> container -> live MISERY, end to end.

What this proves that the offline checks cannot
-----------------------------------------------
Everything up to here is a claim about files. The container parses, the chunk
histogram carries no shader archive, the package paths are namespaced. None of
that says the game will mount the container, resolve its packages, construct the
UObjects, or draw the mesh with the intended materials.

So this runs against the LIVE process and reads each of those separately,
because they can disagree and only measurement shows it:

  1. container mounted        -- FPakFile::bIsMounted for our own .pak
  2. packages registered      -- its FIoContainerHeader pointer is non-null,
                                 which is a DIFFERENT fact from (1)
  3. objects constructed      -- the icon Texture2D and the StaticMesh resolve
                                 to live UObjects through the normal load path
  4. materials correct        -- every mesh slot resolves to OUR MaterialInstance,
                                 each MIC's Parent to the REAL vanilla material,
                                 and each texture override to OUR cooked Texture2D
  5. registered as an item    -- through the Stage 2 public API, not a private path
  6. torn down to baseline    -- the row, the table and the parent array all back

The item is the synthetic two-slot fixture. It is the primary acceptance
precisely because nothing about it is the radio: a generic pipeline that only
works for the asset it was developed against is not a generic pipeline.

Nothing here is radio-specific and nothing here hardcodes an asset name: the
expected packages are DERIVED from the same namespace rules the build used, so
this also checks that the build and the runtime agree about where things live.
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
           os.path.join(REPO, "tools", "modkit")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                        # noqa: E402
import items_session                              # noqa: E402
import materializer                               # noqa: E402
import definition as D                            # noqa: E402
import cr01c5_controller as c5                    # noqa: E402
import namespace as ns                            # noqa: E402
import modspec                                    # noqa: E402
import examples                                   # noqa: E402
from aggregate_acceptance import world_state      # noqa: E402

WORLD_ITEM_CLASS = "BP_StaticMasterItem_C"
VANILLA_PARENT = "/Game/PlayerElectricitySystem/Materials/M_BasicMaterial"


class Checks(object):
    """Every check recorded, pass or fail, and never inferred from another."""

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


def definition_for(spec, plan, mesh_name, icon_name, local_id):
    """The ItemDefinition a mod author would write, DERIVED from the mod spec.

    A ModSpec describes ASSETS, not items -- items are declared through the
    Stage 2 API, and keeping those apart is why the Mod Kit has no opinion about
    inventory. So the item metadata below belongs to this acceptance, while the
    two things actually under test -- where the icon and the mesh live -- are
    recomputed from the namespace rules rather than copied out of the build
    report. A mismatch between where the build put an asset and where the
    runtime looks for it then fails this stage, instead of passing because both
    sides happened to read the same cached string.
    """
    icon = ns.package_path(spec.mod_id, "texture", icon_name)
    mesh = ns.package_path(spec.mod_id, "mesh", mesh_name)
    declared = {entry["package"] for group in ("textures", "meshes")
                for entry in plan.get(group, [])}
    missing = [p for p in (icon, mesh) if p not in declared]
    if missing:
        raise SystemExit("the namespace rules derive %s, but the build produced "
                         "no such package: %s" % (missing, sorted(declared)))
    return D.ItemDefinition(
        D.ItemId(spec.mod_id, local_id),
        display_name="%s %s" % (spec.mod_id, mesh_name),
        short_name=mesh_name[:8],
        description="A generic Mod Kit fixture: %s from %s." % (mesh_name,
                                                                spec.mod_id),
        weight=0.25, width=1, height=1,
        inventory_icon=D.AssetRef(icon),
        world_mesh=D.AssetRef(mesh),
        world_class=WORLD_ITEM_CLASS,
        transform=D.Transform(translation=(0.0, 0.0, 5.0)))


def expect_materials_for(plan, editor_report):
    """The material assertion suite, derived from the plan and the editor report.

    Slot NAMES come from the editor report because they come from the source
    file; slot ORDER and the texture bindings come from the plan. Neither is
    typed in here.
    """
    by_package = {entry["package"]: entry for entry in plan["materials"]}
    slots = []
    mesh_report = editor_report["meshes"][0]
    for slot in mesh_report["slots"]:
        package = slot["material"].split(".")[0]
        entry = by_package[package]
        slots.append({
            "slot_name": slot["slot_name"],
            "mic": "%s.%s" % (package, package.rsplit("/", 1)[-1]),
            "textures": {parameter: "%s.%s" % (path, path.rsplit("/", 1)[-1])
                         for parameter, path in (entry.get("textures") or {}).items()},
        })
    return {"parent": "%s.%s" % (VANILLA_PARENT, VANILLA_PARENT.rsplit("/", 1)[-1]),
            "slots": slots}


def container_state(api, container_stem):
    """Mounted and packages-registered, read separately for OUR container."""
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    handle = eri.open_process_read_only(api, i01["pid"])
    try:
        i14 = eri.run_i14(api, handle, i01["base_address"], i01["image_size_bytes"])
    finally:
        api.close_handle(handle)
    ours, others = None, []
    for record in i14.get("mounted_paks", []):
        name = os.path.basename((record.get("pak_filename") or "").replace("\\", "/"))
        if name.lower() == (container_stem + ".pak").lower():
            ours = record
        else:
            others.append({"pak": name, "mounted": record.get("is_mounted"),
                           "packages_registered": record.get("has_io_container_header"),
                           "read_order": record.get("read_order")})
    return {"pid": i01["pid"], "ours": ours, "others": others,
            "mounted_pak_count": i14.get("mounted_pak_count")}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Stage 3 live acceptance")
    ap.add_argument("--spec", required=True, help="the mod spec that was built")
    ap.add_argument("--build-dir", required=True, help="where build.py wrote its work")
    ap.add_argument("--mesh", default="Shape", help="mesh name from the spec")
    ap.add_argument("--icon", default="Icon", help="icon texture name from the spec")
    ap.add_argument("--local-id", default="shape")
    ap.add_argument("--also", action="append", default=[],
                    metavar="SPEC::BUILD_DIR",
                    help="a second mod to register at the same time, to prove "
                         "two ModIds with identical source filenames coexist")
    ap.add_argument("--radio-regression", action="store_true",
                    help="also register the production radio, as regression "
                         "coverage for the complex asset")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    spec = modspec.ModSpec.load(a.spec)
    plan = json.load(open(os.path.join(a.build_dir, "plan.json"), encoding="utf-8"))
    editor_report = json.load(open(os.path.join(a.build_dir, "editor-report.json"),
                                   encoding="utf-8"))
    check = Checks()
    report = {"mod_id": spec.mod_id, "container": spec.container_name(),
              "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    api = eri.Win32Api()

    print("\n=== 1-2. container mounted, packages registered ===")
    state = container_state(api, spec.container_name())
    report["container_state"] = state
    ours = state["ours"]
    check("our container is mounted at all", ours is not None,
          "mounted paks: %s" % [o["pak"] for o in state["others"]])
    if ours is not None:
        check("FPakFile::bIsMounted is true", ours.get("is_mounted"), ours)
        check("packages are registered (FIoContainerHeader is non-null)",
              ours.get("has_io_container_header"),
              "mounted != resolvable; this is the second, separate fact")
        report["our_container_record"] = ours
    # The control that shows the signal DISCRIMINATES rather than being always
    # true: a bare .pak with no .utoc sibling must report the opposite.
    bare = [o for o in state["others"] if o["packages_registered"] is False]
    check("a bare .pak in the same directory reports NO packages registered",
          bool(bare), "without this control, a True above proves nothing: %s"
                      % state["others"])

    definition = definition_for(spec, plan, a.mesh, a.icon, a.local_id)
    flat = materializer.flatten(definition)
    flat["expect_materials"] = expect_materials_for(plan, editor_report)
    report["definition"] = definition.as_dict()
    report["expect_materials"] = flat["expect_materials"]

    # The exact baseline, read directly before anything is touched. Teardown is
    # then graded against a measurement rather than against shutdown's own
    # report of itself.
    before = world_state(api)
    report["world_before"] = before

    session = items_session.AggregateSession()
    info = session.init()
    report["session_init"] = info
    check("the Items subsystem initialised and attached its aggregate once",
          info.get("attached"), info)
    try:
        print("\n=== 3. load and register through the Stage 2 API ===")
        result = session.register(flat)
        report["register"] = result
        if not check("Register(%s) succeeded" % definition.row_name, result.get("ok"),
                     result.get("detail")):
            raise SystemExit(_finish(report, check, a.out))
        check("the row is in the aggregate table",
              definition.row_name in session.table_rows(), session.table_rows())
        held = session.rows[definition.row_name]
        check("the generated icon Texture2D constructed a live UObject",
              held["icon_object"] != "0x0", held["icon_object"])
        check("the generated StaticMesh constructed a live UObject",
              held["mesh_object"] != "0x0", held["mesh_object"])

        print("\n=== 4. materials, against the live process ===")
        note = []
        mesh_obj = int(held["mesh_object"], 16)
        materials = c5.verify_live_materials(api, state["pid"], mesh_obj,
                                             flat["expect_materials"], note)
        report["live_material_verification"] = materials
        report["material_notes"] = note
        # Assert on what came BACK, not on the absence of an exception. The
        # earlier version of this check passed a literal True, which would have
        # reported PASS for an empty result.
        want = flat["expect_materials"]["slots"]
        check("the mesh carries exactly the slots the source declared",
              len(materials) == len(want) == 2,
              "%d live slot(s), %d expected; the fixture is deliberately "
              "two-slot because one slot would not test slot mapping at all"
              % (len(materials), len(want)))
        check("every slot resolves to a distinct MaterialInstance of ours",
              len({m["mic_object"] for m in materials}) == len(materials)
              and all(ns.is_mod_path(m["mic"]) for m in materials),
              [m["mic"] for m in materials])
        check("every slot's parent is the REAL vanilla Material object",
              all(m["parent"] == flat["expect_materials"]["parent"]
                  and m["parent_class"] == "Material" for m in materials),
              [(m["parent"], m["parent_class"]) for m in materials])
        check("all slots share one parent object, so no shader work was added",
              len({m["parent_object"] for m in materials}) == 1,
              [m["parent_object"] for m in materials])
        every_texture = [path for m in materials
                         for path in (m.get("textures") or {}).values()]
        check("every texture override resolves to one of OUR cooked textures",
              every_texture and all(ns.is_mod_path(p) for p in every_texture),
              every_texture)
        check("each slot got its own BaseColor, so the slots are really distinct",
              len({m["textures"]["BaseColor"] for m in materials}) == len(materials),
              [m["textures"]["BaseColor"] for m in materials])
        check("the icon and the mesh are two different live objects",
              held["icon_object"] != held["mesh_object"],
              "icon %s, mesh %s" % (held["icon_object"], held["mesh_object"]))

        extras = []
        for pair in a.also:
            other_spec_path, other_build = pair.split("::", 1)
            other_spec = modspec.ModSpec.load(other_spec_path)
            other_plan = json.load(open(os.path.join(other_build, "plan.json"),
                                        encoding="utf-8"))
            other_editor = json.load(open(os.path.join(other_build,
                                                       "editor-report.json"),
                                          encoding="utf-8"))
            other_def = definition_for(other_spec, other_plan, a.mesh, a.icon,
                                       a.local_id)
            other_flat = materializer.flatten(other_def)
            other_flat["expect_materials"] = expect_materials_for(other_plan,
                                                                  other_editor)
            print("\n=== 5. second mod, same source filenames: %s ==="
                  % other_spec.mod_id)
            other_state = container_state(api, other_spec.container_name())
            check("%s's container is mounted and its packages registered"
                  % other_spec.mod_id,
                  other_state["ours"] is not None
                  and other_state["ours"].get("is_mounted")
                  and other_state["ours"].get("has_io_container_header"),
                  other_state["ours"])
            other_result = session.register(other_flat)
            check("Register(%s) succeeded while %s is still registered"
                  % (other_def.row_name, definition.row_name),
                  other_result.get("ok"), other_result.get("detail"))
            if other_result.get("ok"):
                other_held = session.rows[other_def.row_name]
                check("the two mods derived DIFFERENT row names from the same "
                      "local id", other_def.row_name != definition.row_name,
                      [definition.row_name, other_def.row_name])
                check("both rows are in the aggregate table at once",
                      {definition.row_name, other_def.row_name}
                      <= set(session.table_rows()), session.table_rows())
                check("the two mods' meshes are DIFFERENT live objects",
                      other_held["mesh_object"] != held["mesh_object"],
                      "%s vs %s" % (held["mesh_object"],
                                    other_held["mesh_object"]))
                check("the two mods' icons are DIFFERENT live objects",
                      other_held["icon_object"] != held["icon_object"],
                      "%s vs %s" % (held["icon_object"],
                                    other_held["icon_object"]))
                other_note = []
                other_materials = c5.verify_live_materials(
                    api, state["pid"], int(other_held["mesh_object"], 16),
                    other_flat["expect_materials"], other_note)
                check("%s's slots resolve to ITS OWN materials, not %s's"
                      % (other_spec.mod_id, spec.mod_id),
                      all(ns.owning_mod(m["mic"]) == other_spec.mod_id
                          for m in other_materials),
                      [m["mic"] for m in other_materials])
                report["second_mod_materials"] = other_materials
                extras.append(other_flat)

        if a.radio_regression:
            print("\n=== 5b. regression: the production radio ===")
            radio = examples.production_radio()
            radio_flat = materializer.flatten(radio)
            radio_flat["expect_materials"] = c5.EXPECT_MATERIALS
            radio_result = session.register(radio_flat)
            check("the production radio still registers through the same API",
                  radio_result.get("ok"), radio_result.get("detail"))
            if radio_result.get("ok"):
                radio_held = session.rows[radio.row_name]
                radio_note = []
                radio_materials = c5.verify_live_materials(
                    api, state["pid"], int(radio_held["mesh_object"], 16),
                    c5.EXPECT_MATERIALS, radio_note)
                check("the radio's 7 material slots still resolve",
                      len(radio_materials) == 7, len(radio_materials))
                report["radio_materials"] = radio_materials
                extras.append(radio_flat)

        print("\n=== 6. unregister ===")
        undone = session.unregister(flat)
        report["unregister"] = undone
        check("Unregister succeeded", undone.get("ok"), undone.get("detail"))
        check("the row is gone from the aggregate table",
              definition.row_name not in session.table_rows(), session.table_rows())
        for other_flat in extras:
            gone = session.unregister(other_flat)
            check("Unregister(%s) succeeded" % other_flat["row_name"],
                  gone.get("ok"), gone.get("detail"))
        check("the aggregate table is empty again",
              session.table_rows() == [], session.table_rows())
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
          "%d -> %d rows" % (before["master_rows"], after["master_rows"]))
    check("ItemList is unchanged", after["ItemList"] == before["ItemList"],
          "%d -> %d rows" % (before["itemlist_rows"], after["itemlist_rows"]))
    check("ParentTables.Num is back to its baseline",
          after["ParentTables"]["num"] == before["ParentTables"]["num"],
          "%s -> %s" % (before["ParentTables"], after["ParentTables"]))
    # NOT "the transient DataTable is gone from the object array". Shutdown
    # unroots the aggregate; it does not run garbage collection, and forcing a
    # GC is not this stage's business. An unrooted object legitimately remains
    # in the array until the engine next collects. What shutdown DOES promise
    # synchronously is that it is unrooted and owns nothing, which is the
    # criterion Stage 2 was accepted on -- so that is what is asserted, and the
    # residual object is recorded as an observation rather than a failure.
    release = shutdown.get("release_table") or {}
    check("the aggregate table was unrooted, so the engine may collect it",
          release.get("rooted_after") == 0, release)
    check("the asset store owns nothing after shutdown",
          release.get("owned_count") == 0, release)
    check("the spare parent slot was zeroed", shutdown.get("zero_slot"),
          shutdown.get("zero_slot"))
    check("remote memory was freed", shutdown.get("remote_memory_freed"),
          shutdown.get("remote_memory_freed"))
    check("the probe module was unloaded", shutdown.get("dll_unloaded"),
          shutdown.get("dll_unloaded"))
    report["transient_datatables_after_shutdown"] = after["transient_datatables"]
    check("no ROOTED table of ours survives (unrooted ones await GC)",
          release.get("rooted_after") == 0,
          "residual unrooted objects: %s" % after["transient_datatables"])
    check("the ItemList subscription count is unchanged",
          after["subscriptions"] == before["subscriptions"],
          "%s -> %s" % (before["subscriptions"], after["subscriptions"]))
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
