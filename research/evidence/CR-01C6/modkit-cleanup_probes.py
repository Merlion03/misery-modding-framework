# OFFLINE. Delete the accumulated material-probe assets from the mod kit.
#
# The STAND-IN parent /Game/PlayerElectricitySystem/Materials/M_BasicMaterial is
# deliberately KEPT: it is what lets the kit author MaterialInstanceConstants
# against the vanilla material's parameter names, it is never shipped in any
# container, and deleting it would make the production materials unbuildable.
import json
import os
import traceback

import unreal

OUT = "D:/UEScratch/MBPLKit/out"
PROBE_DIRS = ["/Game/MBPLArmProbe", "/Game/MBPLArmProbe2", "/Game/MBPLArmProbe3",
              "/Game/MBPLProbe4", "/Game/MBPLMatProbe", "/Game/MBPLA2Probe"]
KEEP = "/Game/PlayerElectricitySystem/Materials/M_BasicMaterial"

report = {"deleted": [], "kept": [], "errors": []}
try:
    for d in PROBE_DIRS:
        if not unreal.EditorAssetLibrary.does_directory_exist(d):
            continue
        assets = [str(a) for a in unreal.EditorAssetLibrary.list_assets(d, recursive=True)]
        if unreal.EditorAssetLibrary.delete_directory(d):
            report["deleted"].append({"dir": d, "assets": len(assets)})
        else:
            report["errors"].append("could not delete %s" % d)
    report["kept"].append({"asset": KEEP,
                           "why": "the stand-in parent: it lets the kit author MICs against "
                                  "the vanilla parameter names, is never shipped, and the "
                                  "production materials cannot be rebuilt without it",
                           "still_exists": unreal.EditorAssetLibrary.does_asset_exist(KEEP)})
    report["radio_dir_after"] = [
        str(a) for a in unreal.EditorAssetLibrary.list_assets(
            "/Game/MBPLTest/Items/Radio", recursive=True)]
    report["ok"] = True
except Exception as exc:  # noqa: BLE001
    report["ok"] = False
    report["errors"].append("%s: %s" % (type(exc).__name__, exc))
    unreal.log_error("[MBPL] " + traceback.format_exc())
with open(os.path.join(OUT, "cleanup_probes.json"), "w") as h:
    json.dump(report, h, indent=2, sort_keys=True)
unreal.log("[MBPL] cleanup ok=%s" % report.get("ok"))
