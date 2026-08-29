# OFFLINE MEASUREMENT ONLY. Route A2 cook experiment.
#
# Question: does "MaterialInstanceConstant + tiny constant Texture2Ds" introduce
# any shader library at all, or only ordinary package chunks?
#
# The mod kit has none of MISERY's content and may not copy it, so the parent is
# a STAND-IN we author ourselves at the same package path with the same
# parameter names. That is deliberate and it is not a copy of the vanilla asset:
# a cooked MaterialInstanceConstant with no static overrides carries no shaders
# of its own, only parameter data plus an import of its parent's package PATH.
# The stand-in is therefore excluded from the container, and at runtime that
# import would resolve against the game's real material.
#
# What is being measured here is only the SHADER FOOTPRINT of the instance and
# its textures. Nothing is staged.
import json
import os
import traceback

import unreal

OUT = "D:/UEScratch/MBPLKit/out"
PARENT_DIR = "/Game/PlayerElectricitySystem/Materials"
PARENT_NAME = "M_BasicMaterial"
PARENT_PATH = "%s/%s" % (PARENT_DIR, PARENT_NAME)
PROBE_DIR = "/Game/MBPLA2Probe"
TEX_PARAMS = ["BaseColor", "ARM", "Normal"]

# authored GLB values for one slot, encoded as uniform constants
BODY_BASECOLOR = (0.048, 0.056, 0.036, 1.0)
BODY_METALLIC = 0.25
BODY_ROUGHNESS = 0.62
NEUTRAL_NORMAL = (0.5, 0.5, 1.0, 1.0)

report = {"errors": [], "notes": []}


def note(m):
    report["notes"].append(str(m))
    unreal.log("[MBPL] %s" % m)


SRC = "D:/UEScratch/MBPLKit/Source_PNG/a2"


def import_constant_texture(png_name, asset_name, srgb, compression):
    """TextureFactory cannot create an empty Texture2D, so the tiny constant is
    authored as a 4x4 PNG on disk and imported through the same AssetImportTask
    path already proven for the icon."""
    path = "%s/%s" % (PROBE_DIR, asset_name)
    task = unreal.AssetImportTask()
    task.filename = "%s/%s" % (SRC, png_name)
    task.destination_path = PROBE_DIR
    task.destination_name = asset_name
    task.automated = True
    task.replace_existing = True
    task.save = True
    task.factory = unreal.TextureFactory()
    unreal.AssetToolsHelpers.get_asset_tools().import_asset_tasks([task])
    tex = unreal.EditorAssetLibrary.load_asset(path)
    if tex is None:
        raise RuntimeError("import produced nothing for %s" % asset_name)
    tex.set_editor_property("srgb", srgb)
    tex.set_editor_property("compression_settings", compression)
    tex.set_editor_property("mip_gen_settings", unreal.TextureMipGenSettings.TMGS_NO_MIPMAPS)
    tex.set_editor_property("never_stream", True)
    unreal.EditorAssetLibrary.save_asset(path)
    return path, True


try:
    # ---- 1. the stand-in parent, authored here, with the three texture params
    if not unreal.EditorAssetLibrary.does_asset_exist(PARENT_PATH):
        mf = unreal.MaterialFactoryNew()
        parent = unreal.AssetToolsHelpers.get_asset_tools().create_asset(
            PARENT_NAME, PARENT_DIR, unreal.Material, mf)
        mel = unreal.MaterialEditingLibrary
        nodes = {}
        for i, pname in enumerate(TEX_PARAMS):
            n = mel.create_material_expression(
                parent, unreal.MaterialExpressionTextureSampleParameter2D, -400, i * 250)
            n.set_editor_property("parameter_name", pname)
            nodes[pname] = n
        mel.connect_material_property(nodes["BaseColor"], "RGB",
                                      unreal.MaterialProperty.MP_BASE_COLOR)
        mel.connect_material_property(nodes["Normal"], "RGB",
                                      unreal.MaterialProperty.MP_NORMAL)
        # ARM: R/G/B split out to AO / Roughness / Metallic. The ORDER here is
        # this stand-in's own choice and proves nothing about the vanilla graph;
        # it exists only so the parameter is real and the instance can override it.
        mel.connect_material_property(nodes["ARM"], "R", unreal.MaterialProperty.MP_AMBIENT_OCCLUSION)
        mel.connect_material_property(nodes["ARM"], "G", unreal.MaterialProperty.MP_ROUGHNESS)
        mel.connect_material_property(nodes["ARM"], "B", unreal.MaterialProperty.MP_METALLIC)
        mel.recompile_material(parent)
        unreal.EditorAssetLibrary.save_asset(PARENT_PATH)
        note("authored stand-in parent at %s" % PARENT_PATH)
    parent = unreal.EditorAssetLibrary.load_asset(PARENT_PATH)

    # ---- 2. tiny constant textures encoding one slot's authored values
    bc_path, bc_ok = import_constant_texture(
        "T_Radio_Body_BC.png", "T_Radio_Body_BC", True,
        unreal.TextureCompressionSettings.TC_DEFAULT)
    arm_path, arm_ok = import_constant_texture(
        "T_Radio_Body_ARM.png", "T_Radio_Body_ARM", False,
        unreal.TextureCompressionSettings.TC_MASKS)
    n_path, n_ok = import_constant_texture(
        "T_Neutral_N.png", "T_Neutral_N", False,
        unreal.TextureCompressionSettings.TC_NORMALMAP)
    report["textures"] = {"BaseColor": bc_path, "ARM": arm_path, "Normal": n_path,
                          "source_init_ok": [bc_ok, arm_ok, n_ok]}

    # ---- 3. the MaterialInstanceConstant, NO static overrides
    mic_name = "MI_MBPL_Radio_Body"
    mic_path = "%s/%s" % (PROBE_DIR, mic_name)
    if unreal.EditorAssetLibrary.does_asset_exist(mic_path):
        unreal.EditorAssetLibrary.delete_asset(mic_path)
    mic = unreal.AssetToolsHelpers.get_asset_tools().create_asset(
        mic_name, PROBE_DIR, unreal.MaterialInstanceConstant,
        unreal.MaterialInstanceConstantFactoryNew())
    unreal.MaterialEditingLibrary.set_material_instance_parent(mic, parent)
    for pname, p in (("BaseColor", bc_path), ("ARM", arm_path), ("Normal", n_path)):
        unreal.MaterialEditingLibrary.set_material_instance_texture_parameter_value(
            mic, pname, unreal.EditorAssetLibrary.load_asset(p))
    unreal.EditorAssetLibrary.save_asset(mic_path)

    mic = unreal.EditorAssetLibrary.load_asset(mic_path)
    report["mic"] = {
        "path": mic_path,
        "parent": mic.get_editor_property("parent").get_path_name(),
        "has_static_permutation": bool(
            mic.get_editor_property("b_has_static_permutation_resource"))
        if "b_has_static_permutation_resource" in dir(mic) else None,
        "texture_parameter_values": [
            (str(v.get_editor_property("parameter_info").get_editor_property("name")),
             v.get_editor_property("parameter_value").get_path_name()
             if v.get_editor_property("parameter_value") else None)
            for v in mic.get_editor_property("texture_parameter_values")],
        # static_parameters_runtime is not exposed to Python; whether the
        # instance carries its own permutation is read from the COOKED result
        # and from live reflection instead, which is the stronger evidence anyway.
    }
    report["assets_in_probe_dir"] = [str(x) for x in
                                     unreal.EditorAssetLibrary.list_assets(PROBE_DIR,
                                                                           recursive=True)]
    note("MIC: %s" % report["mic"])
    report["ok"] = True
except Exception as exc:  # noqa: BLE001
    report["ok"] = False
    report["errors"].append("%s: %s" % (type(exc).__name__, exc))
    unreal.log_error("[MBPL] " + traceback.format_exc())

if not os.path.isdir(OUT):
    os.makedirs(OUT)
with open(os.path.join(OUT, "a2_cook_probe.json"), "w") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
unreal.log("[MBPL] wrote a2_cook_probe.json")
