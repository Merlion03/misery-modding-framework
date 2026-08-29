# OFFLINE BUILD ONLY. ARM channel-order probe, second attempt.
#
# The first probe was inconclusive and the reasons were design faults, not bad
# luck: the surfaces were small and curved, roughness 0.35 is only semi-glossy,
# the base colour was neutral grey so the two readings differed mainly in
# BRIGHTNESS, and driving the opposite channel to AO=0 darkened whichever side
# was metallic. Brightness was exactly the wrong cue to rely on.
#
# This one is built to be unmistakable:
#   * four large separated boxes, 0.4 m each, 0.6 m apart -- flat faces, not curves
#   * roughness 0.02, so metal reads as a mirror rather than a sheen
#   * saturated RED base colour, so the tell is SPECULAR CHARACTER: a metal box
#     becomes a red-tinted mirror with no diffuse, a dielectric stays bright red
#     with a small white highlight. That difference survives AO darkening.
#   * a REFERENCE box whose ARM is (1.0, 0.02, 1.0) -- metallic AND unoccluded
#     under EITHER reading. The question becomes "which of A or B matches the
#     reference", which is far easier than judging either in isolation.
#   * the emissive test gets a whole box, not a thin strip, and probes three
#     plausible parameter names at once.
import json
import os
import traceback

import unreal

OUT = "D:/UEScratch/MBPLKit/out"
SRC = "D:/UEScratch/MBPLKit/Source_PNG/arm2"
PARENT_PATH = "/Game/PlayerElectricitySystem/Materials/M_BasicMaterial"
DIR = "/Game/MBPLArmProbe2"
MESH_NAME = "SM_ArmProbe2"
MESH_PATH = "%s/%s" % (DIR, MESH_NAME)

report = {"errors": [], "notes": []}


def note(m):
    report["notes"].append(str(m))
    unreal.log("[MBPL] %s" % m)


def imp_tex(png, asset, srgb, comp):
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
        raise RuntimeError("texture import failed: %s" % asset)
    tex.set_editor_property("srgb", srgb)
    tex.set_editor_property("compression_settings", comp)
    tex.set_editor_property("mip_gen_settings", unreal.TextureMipGenSettings.TMGS_NO_MIPMAPS)
    tex.set_editor_property("never_stream", True)
    unreal.EditorAssetLibrary.save_asset(path)
    return path


def mic(name, parent, textures, vectors=None, scalars=None):
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
            report["errors"].append("vector %s: %s" % (pn, exc))
    for pn, v in (scalars or {}).items():
        try:
            unreal.MaterialEditingLibrary.set_material_instance_scalar_parameter_value(
                m, pn, v)
        except Exception as exc:  # noqa: BLE001
            report["errors"].append("scalar %s: %s" % (pn, exc))
    unreal.EditorAssetLibrary.save_asset(path)
    return path


try:
    parent = unreal.EditorAssetLibrary.load_asset(PARENT_PATH)
    if parent is None:
        raise RuntimeError("stand-in parent missing at %s" % PARENT_PATH)
    mel = unreal.MaterialEditingLibrary

    # Widen the emissive probe: three plausible names, so one observation covers
    # more of the space. Names the REAL parent lacks are simply not found at
    # runtime and are ignored -- an override for a missing parameter is inert.
    existing = set()
    try:
        existing = {str(x) for x in mel.get_vector_parameter_names(parent)}
    except Exception:  # noqa: BLE001
        pass
    y = 900
    for pname in ("Emissive", "EmissiveColor"):
        if pname not in existing:
            n = mel.create_material_expression(
                parent, unreal.MaterialExpressionVectorParameter, -400, y)
            n.set_editor_property("parameter_name", pname)
            if pname == "Emissive":
                mel.connect_material_property(n, "", unreal.MaterialProperty.MP_EMISSIVE_COLOR)
            y += 250
    try:
        sn = {str(x) for x in mel.get_scalar_parameter_names(parent)}
    except Exception:  # noqa: BLE001
        sn = set()
    if "EmissiveStrength" not in sn:
        n = mel.create_material_expression(
            parent, unreal.MaterialExpressionScalarParameter, -400, y)
        n.set_editor_property("parameter_name", "EmissiveStrength")
    mel.recompile_material(parent)
    unreal.EditorAssetLibrary.save_asset(PARENT_PATH)
    note("stand-in parent carries the emissive probe parameters")

    # ---- mesh
    task = unreal.AssetImportTask()
    task.filename = "%s/arm_probe2.glb" % SRC
    task.destination_path = DIR
    task.destination_name = MESH_NAME
    task.automated = True
    task.replace_existing = True
    task.save = True
    unreal.AssetToolsHelpers.get_asset_tools().import_asset_tasks([task])
    mesh = unreal.EditorAssetLibrary.load_asset(MESH_PATH)
    if not isinstance(mesh, unreal.StaticMesh):
        raise RuntimeError("probe mesh did not import as a StaticMesh")

    # ---- textures
    bc_red = imp_tex("T2_BC_Red.png", "T2_BC_Red", True,
                     unreal.TextureCompressionSettings.TC_DEFAULT)
    bc_grey = imp_tex("T2_BC_Grey.png", "T2_BC_Grey", True,
                      unreal.TextureCompressionSettings.TC_DEFAULT)
    nrm = imp_tex("T2_N.png", "T2_N", False,
                  unreal.TextureCompressionSettings.TC_NORMALMAP)
    arm = {k: imp_tex("T2_ARM_%s.png" % k, "T2_ARM_%s" % k, False,
                      unreal.TextureCompressionSettings.TC_MASKS)
           for k in ("REF", "A", "B", "EM")}

    # ---- instances
    mics = {
        "REF": mic("MI_P2_REF", parent, {"BaseColor": bc_red, "ARM": arm["REF"],
                                         "Normal": nrm}),
        "A": mic("MI_P2_A", parent, {"BaseColor": bc_red, "ARM": arm["A"], "Normal": nrm}),
        "B": mic("MI_P2_B", parent, {"BaseColor": bc_red, "ARM": arm["B"], "Normal": nrm}),
        "EM": mic("MI_P2_EM", parent, {"BaseColor": bc_grey, "ARM": arm["EM"],
                                       "Normal": nrm},
                  vectors={"Emissive": (1.0, 0.25, 0.05),
                           "EmissiveColor": (1.0, 0.25, 0.05)},
                  scalars={"EmissiveStrength": 20.0}),
    }

    slots = mesh.static_materials
    order = ["REF", "A", "B", "EM"]
    assign = []
    for i, sl in enumerate(slots):
        key = order[i] if i < len(order) else "B"
        sl.material_interface = unreal.EditorAssetLibrary.load_asset(mics[key])
        assign.append((i, str(sl.material_slot_name), key, mics[key]))
    mesh.set_editor_property("static_materials", slots)
    unreal.EditorAssetLibrary.save_asset(MESH_PATH)

    b = mesh.get_bounds()
    report["mesh"] = {"path": MESH_PATH, "slots": len(slots),
                      "triangles_lod0": int(mesh.get_num_triangles(0)),
                      "bounds_extent_cm": [b.box_extent.x, b.box_extent.y, b.box_extent.z]}
    report["slot_assignment"] = assign
    report["assets"] = [str(x) for x in unreal.EditorAssetLibrary.list_assets(DIR, True)]
    note("mesh %s | slots %s" % (report["mesh"], assign))
    report["ok"] = True
except Exception as exc:  # noqa: BLE001
    report["ok"] = False
    report["errors"].append("%s: %s" % (type(exc).__name__, exc))
    unreal.log_error("[MBPL] " + traceback.format_exc())

if not os.path.isdir(OUT):
    os.makedirs(OUT)
with open(os.path.join(OUT, "arm_probe2.json"), "w") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
unreal.log("[MBPL] wrote arm_probe2.json")
