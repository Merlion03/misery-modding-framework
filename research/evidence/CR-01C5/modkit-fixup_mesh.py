# Point every material slot of SM_MBPL_Radio at an ENGINE material, then delete
# the seven mod-authored materials the glTF import generated.
#
# WHY. The source has no texture maps, so those seven materials carry nothing
# but PBR constants -- but they would still drag shader compilation into the
# cook, and CR-01C4B established that a mod container carrying
# ShaderArchive-Global-* / ShaderArchive-MISERY-* shadows the game's own shader
# libraries at the higher mount priority. Referencing an engine material that
# the shipped game already contains is not the same as staging engine content,
# and if it somehow fails to resolve the renderer falls back to the default
# material rather than failing. The deliverable is a visible radio mesh, not a
# shaded one.
import json
import os
import traceback

import unreal

OUT = "D:/UEScratch/MBPLKit/out"
PKG_PATH = "/Game/MBPLTest/Items/Radio/SM_MBPL_Radio"
ENGINE_MATERIAL = "/Engine/EngineMaterials/WorldGridMaterial"
GENERATED = ["M_Radio_Body", "M_Radio_Battery", "M_Radio_Metal", "M_Radio_Rubber",
             "M_Radio_Screen", "M_Radio_Emissive", "M_Radio_Tape"]
DIR = "/Game/MBPLTest/Items/Radio"

report = {"package_path": PKG_PATH, "errors": [], "notes": []}


def note(m):
    report["notes"].append(str(m))
    unreal.log("[MBPL] %s" % m)


try:
    mesh = unreal.EditorAssetLibrary.load_asset(PKG_PATH)
    if not isinstance(mesh, unreal.StaticMesh):
        raise RuntimeError("not a StaticMesh at %s" % PKG_PATH)

    eng = unreal.EditorAssetLibrary.load_asset(ENGINE_MATERIAL)
    if eng is None:
        raise RuntimeError("engine material not loadable: %s" % ENGINE_MATERIAL)

    before = [(str(m.material_slot_name),
               m.material_interface.get_path_name() if m.material_interface else None)
              for m in mesh.static_materials]
    report["slots_before"] = before

    slots = mesh.static_materials
    new_slots = []
    for m in slots:
        m.material_interface = eng
        new_slots.append(m)
    mesh.set_editor_property("static_materials", new_slots)
    unreal.EditorAssetLibrary.save_asset(PKG_PATH)

    mesh = unreal.EditorAssetLibrary.load_asset(PKG_PATH)
    report["slots_after"] = [
        (str(m.material_slot_name),
         m.material_interface.get_path_name() if m.material_interface else None)
        for m in mesh.static_materials]

    deleted = []
    for name in GENERATED:
        p = "%s/%s" % (DIR, name)
        if unreal.EditorAssetLibrary.does_asset_exist(p):
            if unreal.EditorAssetLibrary.delete_asset(p):
                deleted.append(p)
    report["deleted_generated_materials"] = deleted
    report["remaining_in_dir"] = [str(x) for x in
                                  unreal.EditorAssetLibrary.list_assets(DIR, recursive=False)]

    bounds = mesh.get_bounds()
    report["mesh"] = {
        "object_path": mesh.get_path_name(),
        "num_lods": int(mesh.get_num_lods()),
        "num_triangles_lod0": int(mesh.get_num_triangles(0)),
        "num_material_slots": len(mesh.static_materials),
        "bounds_box_extent_cm": [bounds.box_extent.x, bounds.box_extent.y, bounds.box_extent.z],
        "bounds_origin": [bounds.origin.x, bounds.origin.y, bounds.origin.z],
    }
    note("mesh %s" % report["mesh"])
    report["ok"] = True
except Exception as exc:  # noqa: BLE001
    report["ok"] = False
    report["errors"].append("%s: %s" % (type(exc).__name__, exc))
    unreal.log_error("[MBPL] " + traceback.format_exc())

if not os.path.isdir(OUT):
    os.makedirs(OUT)
with open(os.path.join(OUT, "fixup_mesh.json"), "w") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
unreal.log("[MBPL] wrote %s/fixup_mesh.json" % OUT)
