# OFFLINE MEASUREMENT ONLY. Re-import the GLB to a SEPARATE package path so the
# seven authored materials exist again and can be cooked, WITHOUT touching
# SM_MBPL_Radio, which is currently staged and in use by the live game.
import json
import os
import traceback

import unreal

OUT = "D:/UEScratch/MBPLKit/out"
SRC = "D:/Dev/Models/Radio/mbpl_radio.glb"
PKG_DIR = "/Game/MBPLMatProbe"
ASSET_NAME = "SM_MatProbe_Radio"
PKG_PATH = "%s/%s" % (PKG_DIR, ASSET_NAME)

report = {"package_path": PKG_PATH, "errors": [], "notes": []}
try:
    task = unreal.AssetImportTask()
    task.filename = SRC
    task.destination_path = PKG_DIR
    task.destination_name = ASSET_NAME
    task.automated = True
    task.replace_existing = True
    task.save = True
    unreal.AssetToolsHelpers.get_asset_tools().import_asset_tasks([task])
    report["imported"] = [str(x) for x in
                          (task.get_editor_property("imported_object_paths") or [])]

    mesh = unreal.EditorAssetLibrary.load_asset(PKG_PATH)
    report["is_static_mesh"] = isinstance(mesh, unreal.StaticMesh)
    if mesh:
        report["slots"] = [
            (str(m.material_slot_name),
             m.material_interface.get_path_name() if m.material_interface else None)
            for m in mesh.static_materials]
    report["assets_in_dir"] = [str(x) for x in
                               unreal.EditorAssetLibrary.list_assets(PKG_DIR, recursive=True)]
    report["ok"] = True
except Exception as exc:  # noqa: BLE001
    report["ok"] = False
    report["errors"].append("%s: %s" % (type(exc).__name__, exc))
    unreal.log_error("[MBPL] " + traceback.format_exc())

if not os.path.isdir(OUT):
    os.makedirs(OUT)
with open(os.path.join(OUT, "import_mat_probe.json"), "w") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
unreal.log("[MBPL] wrote import_mat_probe.json")
