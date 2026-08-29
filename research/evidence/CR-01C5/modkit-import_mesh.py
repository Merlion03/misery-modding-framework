# MBPL mod-kit asset builder. Runs inside UnrealEditor-Cmd.exe -run=pythonscript.
#
# Imports ONE mod-authored source mesh as a UStaticMesh at
#   /Game/MBPLTest/Items/Radio/SM_MBPL_Radio
#
# GLB first (the author's recommended file), FBX as the fallback: UE 5.4 routes
# glTF through Interchange, and if that path declines the file we still have an
# equivalent source rather than a dead end.
#
# Materials are deliberately NOT authored here. The source has 7 slots and no
# texture maps, and giving it our own materials would drag shader compilation
# into the cook -- and the CR-01C4B run already established that staging shader
# archives at a higher mount priority shadows the game's own shader libraries.
# Whatever the importer assigns is left in place; a REFERENCE to an engine
# material is not the same thing as staging engine content, and an unresolved
# material degrades to the default material rather than failing.
#
# Touches nothing outside D:/UEScratch. No MISERY package or asset is read,
# copied or referenced.
import json
import os
import traceback

import unreal

OUT = "D:/UEScratch/MBPLKit/out"
SRC_GLB = "D:/Dev/Models/Radio/mbpl_radio.glb"
SRC_FBX = "D:/Dev/Models/Radio/mbpl_radio.fbx"
PKG_DIR = "/Game/MBPLTest/Items/Radio"
ASSET_NAME = "SM_MBPL_Radio"
PKG_PATH = "%s/%s" % (PKG_DIR, ASSET_NAME)

report = {"package_path": PKG_PATH, "errors": [], "notes": [], "attempts": []}


def note(msg):
    report["notes"].append(str(msg))
    unreal.log("[MBPL] %s" % msg)


def try_import(src, label):
    task = unreal.AssetImportTask()
    task.filename = src
    task.destination_path = PKG_DIR
    task.destination_name = ASSET_NAME
    task.automated = True
    task.replace_existing = True
    task.save = True
    unreal.AssetToolsHelpers.get_asset_tools().import_asset_tasks([task])
    imported = list(task.get_editor_property("imported_object_paths") or [])
    report["attempts"].append({"source": src, "label": label, "imported": imported})
    note("%s import ran; imported=%s" % (label, imported))
    return unreal.EditorAssetLibrary.load_asset(PKG_PATH)


try:
    mesh = None
    if os.path.isfile(SRC_GLB):
        try:
            mesh = try_import(SRC_GLB, "glb")
        except Exception as exc:  # noqa: BLE001
            report["attempts"].append({"source": SRC_GLB, "label": "glb",
                                       "error": "%s: %s" % (type(exc).__name__, exc)})
            note("glb import raised: %s" % exc)
    if mesh is None and os.path.isfile(SRC_FBX):
        note("falling back to the FBX source")
        mesh = try_import(SRC_FBX, "fbx")

    if mesh is None:
        raise RuntimeError("no importer produced an asset at %s" % PKG_PATH)
    if not isinstance(mesh, unreal.StaticMesh):
        raise RuntimeError("imported asset is %s, not a StaticMesh"
                           % mesh.get_class().get_name())

    unreal.EditorAssetLibrary.save_asset(PKG_PATH)

    bounds = mesh.get_bounds()
    mats = mesh.static_materials
    report["class"] = mesh.get_class().get_name()
    report["imported"] = {
        "object_path": mesh.get_path_name(),
        "num_lods": int(mesh.get_num_lods()),
        "num_triangles_lod0": int(mesh.get_num_triangles(0)),
        "num_vertices_lod0": int(mesh.get_num_vertices(0)),
        "num_material_slots": len(mats),
        "material_slots": [str(m.material_slot_name) for m in mats],
        "materials": [(m.material_interface.get_path_name()
                       if m.material_interface else None) for m in mats],
        "bounds_extent": [bounds.box_extent.x, bounds.box_extent.y, bounds.box_extent.z],
        "bounds_origin": [bounds.origin.x, bounds.origin.y, bounds.origin.z],
    }
    # everything this asset drags into the cook, so staging can be checked against it
    deps = unreal.EditorAssetLibrary.find_package_referencers_for_asset(PKG_PATH, False)
    report["referencers"] = [str(d) for d in deps]
    ar = unreal.AssetRegistryHelpers.get_asset_registry()
    report["hard_dependencies"] = [str(d) for d in ar.get_dependencies(
        unreal.Name(PKG_PATH.rsplit("/", 1)[0] + "/" + ASSET_NAME),
        unreal.AssetRegistryDependencyOptions(include_hard_package_references=True))] \
        if hasattr(unreal, "AssetRegistryDependencyOptions") else []
    note("imported %s: %s" % (report["class"], report["imported"]))
    report["ok"] = True
except Exception as exc:  # noqa: BLE001
    report["ok"] = False
    report["errors"].append("%s: %s" % (type(exc).__name__, exc))
    unreal.log_error("[MBPL] " + traceback.format_exc())

if not os.path.isdir(OUT):
    os.makedirs(OUT)
with open(os.path.join(OUT, "import_mesh.json"), "w") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
unreal.log("[MBPL] wrote %s/import_mesh.json" % OUT)
