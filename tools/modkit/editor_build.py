#!/usr/bin/env python3
"""Runs INSIDE UnrealEditor-Cmd. Executes a build plan; knows no particular mod.

    UnrealEditor-Cmd.exe <project> -run=pythonscript -script="editor_build.py"

The plan comes from ``MODKIT_PLAN`` in the environment, because -script takes no
arguments. Everything item-specific is in that file: this script contains no
asset name, no package path and no material value.

THE ONE WORKFLOW THAT ACTUALLY WORKS
------------------------------------
Assigning materials by mutating ``mesh.static_materials`` in place and handing
the SAME array object back to ``set_editor_property`` silently does nothing. That
cost two invalid probes and two of the owner's game restarts, because the tool
reported the assignment it INTENDED rather than the one that stuck.

So slots are assigned by building a FRESH list of ``unreal.StaticMaterial``
values, saving, reloading the asset FROM DISK, and asserting every slot. If any
assertion fails the plan is abandoned and nothing is cooked -- a half-assigned
mesh that cooks is worse than a build that stops.
"""
import json
import os
import traceback

import unreal

PLAN_PATH = os.environ.get("MODKIT_PLAN")
report = {"steps": [], "assertions": [], "errors": [], "ok": False}


def note(message):
    report["steps"].append(str(message))
    unreal.log("[modkit] %s" % message)


def check(label, ok, detail=""):
    report["assertions"].append({"check": label, "pass": bool(ok), "detail": str(detail)})
    if not ok:
        raise AssertionError("%s -- %s" % (label, detail))


def import_texture(entry):
    """One Texture2D, with the sampler settings its declared usage requires."""
    package_dir, name = entry["package"].rsplit("/", 1)
    task = unreal.AssetImportTask()
    task.filename = entry["source"]
    task.destination_path = package_dir
    task.destination_name = name
    task.automated = True
    task.replace_existing = True
    task.save = True
    task.factory = unreal.TextureFactory()
    unreal.AssetToolsHelpers.get_asset_tools().import_asset_tasks([task])
    asset = unreal.EditorAssetLibrary.load_asset(entry["package"])
    check("texture %s imported" % entry["package"], asset is not None, entry["source"])
    asset.set_editor_property("srgb", bool(entry["srgb"]))
    asset.set_editor_property(
        "compression_settings",
        getattr(unreal.TextureCompressionSettings, entry["compression"]))
    # No mips and never streamed: these are small authored maps, and a streamed
    # texture can be resident-but-black at the moment something first draws it.
    asset.set_editor_property("mip_gen_settings",
                              unreal.TextureMipGenSettings.TMGS_NO_MIPMAPS)
    asset.set_editor_property("never_stream", True)
    unreal.EditorAssetLibrary.save_asset(entry["package"])
    return asset


def import_mesh(entry):
    package_dir, name = entry["package"].rsplit("/", 1)
    task = unreal.AssetImportTask()
    task.filename = entry["source"]
    task.destination_path = package_dir
    task.destination_name = name
    task.automated = True
    task.replace_existing = True
    task.save = True
    unreal.AssetToolsHelpers.get_asset_tools().import_asset_tasks([task])
    mesh = unreal.EditorAssetLibrary.load_asset(entry["package"])
    check("mesh %s imported" % entry["package"], isinstance(mesh, unreal.StaticMesh),
          entry["source"])
    return mesh


def build_material(entry):
    """One MaterialInstanceConstant on a parent the GAME already ships.

    Referencing that parent is not packaging it: the container carries no vanilla
    bytes, and the runtime resolves the import against the real material. This is
    what keeps the cook free of shader work.
    """
    parent = unreal.EditorAssetLibrary.load_asset(entry["parent"])
    check("parent %s loads" % entry["parent"], parent is not None,
          "the parent must be a material the game ships")
    package = entry["package"]
    if unreal.EditorAssetLibrary.does_asset_exist(package):
        unreal.EditorAssetLibrary.delete_asset(package)
    package_dir, name = package.rsplit("/", 1)
    instance = unreal.AssetToolsHelpers.get_asset_tools().create_asset(
        name, package_dir, unreal.MaterialInstanceConstant,
        unreal.MaterialInstanceConstantFactoryNew())
    unreal.MaterialEditingLibrary.set_material_instance_parent(instance, parent)
    for parameter, texture_package in (entry.get("textures") or {}).items():
        texture = unreal.EditorAssetLibrary.load_asset(texture_package)
        check("material %s texture %s loads" % (name, parameter), texture is not None,
              texture_package)
        unreal.MaterialEditingLibrary.set_material_instance_texture_parameter_value(
            instance, parameter, texture)
    for parameter, value in (entry.get("scalars") or {}).items():
        unreal.MaterialEditingLibrary.set_material_instance_scalar_parameter_value(
            instance, parameter, float(value))
    unreal.EditorAssetLibrary.save_asset(package)
    return instance


def assign_slots(mesh_entry):
    """A FRESH list, then save, then reload from disk, then assert."""
    package = mesh_entry["package"]
    mesh = unreal.EditorAssetLibrary.load_asset(package)
    existing = list(mesh.static_materials)
    wanted = mesh_entry["slots"]
    check("mesh %s has %d slot(s)" % (package, len(wanted)),
          len(existing) == len(wanted),
          "the source declares %d, the plan expects %d" % (len(existing), len(wanted)))

    fresh = []
    for index, slot in enumerate(wanted):
        instance = unreal.EditorAssetLibrary.load_asset(slot["material_package"])
        check("slot %d material loads" % index, instance is not None,
              slot["material_package"])
        static_material = unreal.StaticMaterial()
        static_material.set_editor_property("material_interface", instance)
        slot_name = slot.get("slot_name") or str(
            existing[index].get_editor_property("material_slot_name"))
        static_material.set_editor_property("material_slot_name", unreal.Name(slot_name))
        fresh.append(static_material)
    mesh.set_editor_property("static_materials", fresh)
    unreal.EditorAssetLibrary.save_asset(package)
    return [str(s.get_editor_property("material_slot_name")) for s in fresh]


def verify_slots(mesh_entry):
    """Reload FROM DISK and assert. The intention is not the result."""
    package = mesh_entry["package"]
    reloaded = unreal.EditorAssetLibrary.load_asset(package)
    out = []
    for index, slot in enumerate(reloaded.static_materials):
        interface = slot.get_editor_property("material_interface")
        got = interface.get_path_name() if interface else None
        want = mesh_entry["slots"][index]["material_package"]
        check("slot %d is not null" % index, interface is not None, got)
        check("slot %d is the intended material" % index,
              got.split(".")[0] == want, "got %r want %r" % (got, want))
        out.append({"slot": index,
                    "slot_name": str(slot.get_editor_property("material_slot_name")),
                    "material": got})
    return out


def main():
    if not PLAN_PATH or not os.path.isfile(PLAN_PATH):
        report["errors"].append("MODKIT_PLAN is unset or missing: %r" % PLAN_PATH)
        return
    with open(PLAN_PATH, encoding="utf-8") as handle:
        plan = json.load(handle)
    report["mod_id"] = plan.get("mod_id")
    note("building mod %r" % plan.get("mod_id"))

    for entry in plan.get("textures", []):
        import_texture(entry)
        note("texture -> %s" % entry["package"])
    for entry in plan.get("materials", []):
        build_material(entry)
        note("material -> %s" % entry["package"])
    for entry in plan.get("meshes", []):
        import_mesh(entry)
        note("mesh -> %s" % entry["package"])

    # Save the whole mod directory before verifying, so the reload really does
    # come off disk rather than out of the editor's memory.
    for entry in plan.get("meshes", []):
        assign_slots(entry)
    unreal.EditorAssetLibrary.save_directory(plan["mod_root"], only_if_is_dirty=False,
                                             recursive=True)
    report["meshes"] = []
    for entry in plan.get("meshes", []):
        report["meshes"].append({"package": entry["package"],
                                 "slots": verify_slots(entry)})

    # PRUNE WHAT THE IMPORTER INVENTED, and it is not housekeeping.
    #
    # A glTF/FBX source carries its own material definitions, and the importer
    # materialises them as REAL UMaterial assets beside the mesh. A real
    # UMaterial is exactly what compiles new shader permutations and produces a
    # shader library -- and a library named as the game's hashes to the same
    # chunk id, with the mount order deciding who answers. This route exists to
    # avoid that, so an undeclared material must not survive into the cook.
    #
    # The mesh's slots have already been reassigned to our own instances and
    # verified from disk, so nothing still references these.
    # Against the PLAN's own products, not the spec's declarations. The planner
    # GENERATES textures -- a constant colour becomes a 4x4 image, scalars become
    # a packed mask, a missing normal becomes a flat one -- and those are
    # legitimate build outputs that the spec never names. A first version pruned
    # against the spec and deleted every generated texture, leaving the material
    # instances pointing at assets that no longer existed.
    expected = {entry["package"] for entry in plan.get("textures", [])}
    expected |= {entry["package"] for entry in plan.get("materials", [])}
    expected |= {entry["package"] for entry in plan.get("meshes", [])}
    pruned = []
    for item in [str(p) for p in unreal.EditorAssetLibrary.list_assets(
            plan["mod_root"], recursive=True)]:
        package = item.split(".")[0]
        if package in expected:
            continue
        asset = unreal.EditorAssetLibrary.load_asset(package)
        kind = type(asset).__name__ if asset else "unknown"
        if unreal.EditorAssetLibrary.delete_asset(package):
            pruned.append({"package": package, "class": kind})
            note("pruned undeclared %s %s" % (kind, package))
        else:
            check("undeclared asset %s could be removed" % package, False,
                  "it would otherwise be cooked and packaged")
    report["pruned_undeclared"] = pruned

    listed = [str(p) for p in unreal.EditorAssetLibrary.list_assets(plan["mod_root"],
                                                                   recursive=True)]
    report["assets_in_mod_root"] = sorted(listed)
    # After pruning, the mod root must contain EXACTLY what was declared.
    surplus = sorted({item.split(".")[0] for item in listed} - expected)
    check("no undeclared assets remain in the mod root", not surplus, surplus)
    for expected in plan.get("expected_object_paths", []):
        check("expected asset present: %s" % expected,
              any(item.split(".")[0] == expected.split(".")[0] for item in listed),
              expected)
    report["ok"] = True


try:
    main()
except Exception as exc:                                           # noqa: BLE001
    report["ok"] = False
    report["errors"].append("%s: %s" % (type(exc).__name__, exc))
    unreal.log_error("[modkit] " + traceback.format_exc())

out_path = os.environ.get("MODKIT_REPORT") or (PLAN_PATH or "plan") + ".report.json"
with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
    json.dump(report, handle, indent=2, sort_keys=False, default=str)
    handle.write("\n")
unreal.log("[modkit] wrote %s ok=%s" % (out_path, report.get("ok")))
