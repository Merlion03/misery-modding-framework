# OFFLINE BUILD ONLY. The ARM channel-order experiment, plus a probe for a
# hidden emissive parameter on M_BasicMaterial.
#
# WHY THIS CANNOT BE ANSWERED OFFLINE. Deciding whether ARM is (AO,R,Metallic)
# or (Metallic,R,AO) requires rendering the VANILLA M_BasicMaterial, and the mod
# kit may not contain MISERY content. The stand-in parent authored here has our
# own channel wiring, so rendering it locally would only echo our own choice
# back. The experiment therefore has to be observed IN GAME, against the real
# parent, which the cooked MIC references purely by package path.
#
# THE EXPERIMENT. One mesh, two treatments that cannot be confused:
#     slot 0            ARM = (R 1.0, G 0.35, B 0.0)
#     slots 1..5        ARM = (R 0.0, G 0.35, B 1.0)
#     slot 6            emissive probe -- a vector override named "Emissive" on
#                       a parent whose shipped instances never set one. If the
#                       real material has such a parameter it lights up; if it
#                       does not, the override is simply not found and ignored.
# Green is 0.35 in both, because roughness is channel G under BOTH conventions
# and holding it fixed keeps the comparison to the single open bit.
#
# Whichever slot reads as bare metal identifies Metallic. The other reads dark
# because its AO channel is 0.
import json
import os
import traceback

import unreal

OUT = "D:/UEScratch/MBPLKit/out"
SRC = "D:/UEScratch/MBPLKit/Source_PNG/arm"
PARENT_PATH = "/Game/PlayerElectricitySystem/Materials/M_BasicMaterial"
DIR = "/Game/MBPLArmProbe"
MESH = "/Game/MBPLMatProbe/SM_MatProbe_Radio"

report = {"errors": [], "notes": []}


def note(m):
    report["notes"].append(str(m))
    unreal.log("[MBPL] %s" % m)


def imp(png, asset, srgb, comp):
    path = "%s/%s" % (DIR, asset)
    t = unreal.AssetImportTask()
    t.filename = "%s/%s" % (SRC, png)
    t.destination_path = DIR
    t.destination_name = asset
    t.automated = True
    t.replace_existing = True
    t.save = True
    t.factory = unreal.TextureFactory()
    unreal.AssetToolsHelpers.get_asset_tools().import_asset_tasks([t])
    tex = unreal.EditorAssetLibrary.load_asset(path)
    if tex is None:
        raise RuntimeError("import failed: %s" % asset)
    tex.set_editor_property("srgb", srgb)
    tex.set_editor_property("compression_settings", comp)
    tex.set_editor_property("mip_gen_settings", unreal.TextureMipGenSettings.TMGS_NO_MIPMAPS)
    tex.set_editor_property("never_stream", True)
    unreal.EditorAssetLibrary.save_asset(path)
    return path


def mic(name, parent, textures, vectors=None):
    path = "%s/%s" % (DIR, name)
    if unreal.EditorAssetLibrary.does_asset_exist(path):
        unreal.EditorAssetLibrary.delete_asset(path)
    m = unreal.AssetToolsHelpers.get_asset_tools().create_asset(
        name, DIR, unreal.MaterialInstanceConstant,
        unreal.MaterialInstanceConstantFactoryNew())
    unreal.MaterialEditingLibrary.set_material_instance_parent(m, parent)
    for pn, tp in textures.items():
        unreal.MaterialEditingLibrary.set_material_instance_texture_parameter_value(
            m, pn, unreal.EditorAssetLibrary.load_asset(tp))
    for pn, v in (vectors or {}).items():
        try:
            unreal.MaterialEditingLibrary.set_material_instance_vector_parameter_value(
                m, pn, unreal.LinearColor(v[0], v[1], v[2], 1.0))
        except Exception as exc:  # noqa: BLE001
            report["errors"].append("vector %s on %s: %s" % (pn, name, exc))
    unreal.EditorAssetLibrary.save_asset(path)
    return path


try:
    parent = unreal.EditorAssetLibrary.load_asset(PARENT_PATH)
    if parent is None:
        raise RuntimeError("stand-in parent missing at %s" % PARENT_PATH)

    # give the stand-in an Emissive vector parameter so the probe MIC can carry
    # the override; whether the REAL parent has one is exactly what is under test
    mel = unreal.MaterialEditingLibrary
    have = [p for p in mel.get_vector_parameter_names(parent)] if hasattr(
        mel, "get_vector_parameter_names") else []
    if "Emissive" not in [str(x) for x in have]:
        n = mel.create_material_expression(
            parent, unreal.MaterialExpressionVectorParameter, -400, 900)
        n.set_editor_property("parameter_name", "Emissive")
        mel.connect_material_property(n, "", unreal.MaterialProperty.MP_EMISSIVE_COLOR)
        mel.recompile_material(parent)
        unreal.EditorAssetLibrary.save_asset(PARENT_PATH)
        note("added an Emissive vector parameter to the STAND-IN only")

    bc = imp("T_Probe_BC.png", "T_Probe_BC", True,
             unreal.TextureCompressionSettings.TC_DEFAULT)
    nrm = imp("T_Probe_N.png", "T_Probe_N", False,
              unreal.TextureCompressionSettings.TC_NORMALMAP)
    r_hot = imp("T_ARM_Rhot.png", "T_ARM_Rhot", False,
                unreal.TextureCompressionSettings.TC_MASKS)
    b_hot = imp("T_ARM_Bhot.png", "T_ARM_Bhot", False,
                unreal.TextureCompressionSettings.TC_MASKS)

    mi_r = mic("MI_ARM_Rhot", parent, {"BaseColor": bc, "ARM": r_hot, "Normal": nrm})
    mi_b = mic("MI_ARM_Bhot", parent, {"BaseColor": bc, "ARM": b_hot, "Normal": nrm})
    mi_e = mic("MI_EmissiveProbe", parent, {"BaseColor": bc, "ARM": b_hot, "Normal": nrm},
               {"Emissive": (1.0, 0.111, 0.044)})

    mesh = unreal.EditorAssetLibrary.load_asset(MESH)
    slots = mesh.static_materials
    assign = []
    for i, s in enumerate(slots):
        target = mi_r if i == 0 else (mi_e if i == len(slots) - 1 else mi_b)
        s.material_interface = unreal.EditorAssetLibrary.load_asset(target)
        assign.append((i, str(s.material_slot_name), target))
    mesh.set_editor_property("static_materials", slots)
    unreal.EditorAssetLibrary.save_asset(MESH)
    report["slot_assignment"] = assign
    report["assets"] = [str(x) for x in unreal.EditorAssetLibrary.list_assets(DIR, True)]
    note("slots: %s" % assign)
    report["ok"] = True
except Exception as exc:  # noqa: BLE001
    report["ok"] = False
    report["errors"].append("%s: %s" % (type(exc).__name__, exc))
    unreal.log_error("[MBPL] " + traceback.format_exc())

if not os.path.isdir(OUT):
    os.makedirs(OUT)
with open(os.path.join(OUT, "arm_probe.json"), "w") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
unreal.log("[MBPL] wrote arm_probe.json")
