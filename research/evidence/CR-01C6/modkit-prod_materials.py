# OFFLINE BUILD. The seven production materials for SM_MBPL_Radio.
#
# Route A2, with everything it rests on now proven:
#   parent      the VANILLA /Game/PlayerElectricitySystem/Materials/M_BasicMaterial
#   ARM         R = AO, G = Roughness, B = Metallic          (LOG-0094)
#   parent link a cooked MIC resolves its parent import at runtime even though
#               that parent package is not shipped in our container
#   shaders     none: a MIC with no static overrides reuses the parent's shader map
#
# The Emissive slot is an APPROXIMATION and is labelled as one in the report:
# emissive is not reachable through this parent, so the LED gets the authored
# EMISSIVE colour as its BaseColor. It will read as a bright red patch, not as a
# lamp, and nothing here should be read as emissive support.
#
# The assignment uses the only pattern that has ever worked here: a FRESH list of
# unreal.StaticMaterial values, save, reload from disk, then assert every slot.
# Mutating the array in place silently does nothing, which cost two invalid
# probes and two of the owner's restarts.
import json
import os
import traceback

import unreal

OUT = "D:/UEScratch/MBPLKit/out"
SRC = "D:/UEScratch/MBPLKit/Source_PNG/prod"
PARENT_PATH = "/Game/PlayerElectricitySystem/Materials/M_BasicMaterial"
DIR = "/Game/MBPLTest/Items/Radio"
MESH_PATH = "%s/SM_MBPL_Radio" % DIR

# slot order as the mesh carries it, from the GLB import
ORDER = ["Body", "Battery", "Metal", "Rubber", "Screen", "Emissive", "Tape"]
SLOT_NAMES = ["M_Radio_%s" % k for k in ORDER]

report = {"errors": [], "notes": [], "assertions": []}


def note(m):
    report["notes"].append(str(m))
    unreal.log("[MBPL] %s" % m)


def check(label, ok, detail=""):
    report["assertions"].append({"check": label, "pass": bool(ok), "detail": str(detail)})
    if not ok:
        raise AssertionError("%s -- %s" % (label, detail))


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


try:
    parent = unreal.EditorAssetLibrary.load_asset(PARENT_PATH)
    check("vanilla parent loads", parent is not None, PARENT_PATH)

    nrm = imp_tex("T_Radio_Neutral_N.png", "T_Radio_Neutral_N", False,
                  unreal.TextureCompressionSettings.TC_NORMALMAP)
    intended = {}
    for k in ORDER:
        bc = imp_tex("T_Radio_%s_BC.png" % k, "T_Radio_%s_BC" % k, True,
                     unreal.TextureCompressionSettings.TC_DEFAULT)
        arm = imp_tex("T_Radio_%s_ARM.png" % k, "T_Radio_%s_ARM" % k, False,
                      unreal.TextureCompressionSettings.TC_MASKS)
        intended[k] = {"BaseColor": bc, "ARM": arm, "Normal": nrm}

    mics = {}
    for k in ORDER:
        name = "MI_Radio_%s" % k
        path = "%s/%s" % (DIR, name)
        if unreal.EditorAssetLibrary.does_asset_exist(path):
            unreal.EditorAssetLibrary.delete_asset(path)
        m = unreal.AssetToolsHelpers.get_asset_tools().create_asset(
            name, DIR, unreal.MaterialInstanceConstant,
            unreal.MaterialInstanceConstantFactoryNew())
        unreal.MaterialEditingLibrary.set_material_instance_parent(m, parent)
        for pn, tp in intended[k].items():
            tex = unreal.EditorAssetLibrary.load_asset(tp)
            check("texture %s for %s loads" % (pn, k), tex is not None, tp)
            unreal.MaterialEditingLibrary.set_material_instance_texture_parameter_value(
                m, pn, tex)
        unreal.EditorAssetLibrary.save_asset(path)
        mics[k] = path

    # ---- verify every MIC from a fresh load, before anything is cooked -------
    report["mic_verification"] = {}
    for k in ORDER:
        m = unreal.EditorAssetLibrary.load_asset(mics[k])
        p = m.get_editor_property("parent")
        check("MIC %s parent" % k,
              p is not None and p.get_path_name().split(".")[0] == PARENT_PATH,
              p.get_path_name() if p else None)
        got = {}
        for v in m.get_editor_property("texture_parameter_values"):
            pn = str(v.get_editor_property("parameter_info").get_editor_property("name"))
            tv = v.get_editor_property("parameter_value")
            got[pn] = tv.get_path_name() if tv else None
        for pn, want in intended[k].items():
            check("MIC %s override %s" % (k, pn), got.get(pn, "").split(".")[0] == want,
                  "got %r want %r" % (got.get(pn), want))
        report["mic_verification"][k] = {"parent": p.get_path_name(), "textures": got}

    # ---- assign with a FRESH list, save, reload from disk, assert ------------
    mesh = unreal.EditorAssetLibrary.load_asset(MESH_PATH)
    check("production mesh loads", isinstance(mesh, unreal.StaticMesh), MESH_PATH)
    existing = [str(s.get_editor_property("material_slot_name")) for s in mesh.static_materials]
    report["slot_names_before"] = existing
    check("production mesh has 7 slots", len(existing) == 7, existing)
    check("slot names match the expected order", existing == SLOT_NAMES,
          "got %r want %r" % (existing, SLOT_NAMES))

    fresh = []
    for i, k in enumerate(ORDER):
        mi = unreal.EditorAssetLibrary.load_asset(mics[k])
        check("MIC %s loads for assignment" % k, mi is not None, mics[k])
        sm = unreal.StaticMaterial()
        sm.set_editor_property("material_interface", mi)
        sm.set_editor_property("material_slot_name", unreal.Name(SLOT_NAMES[i]))
        fresh.append(sm)
    mesh.set_editor_property("static_materials", fresh)
    unreal.EditorAssetLibrary.save_asset(MESH_PATH)
    unreal.EditorAssetLibrary.save_directory(DIR, only_if_is_dirty=False, recursive=True)

    reloaded = unreal.EditorAssetLibrary.load_asset(MESH_PATH)
    after = []
    for i, sl in enumerate(reloaded.static_materials):
        mi = sl.get_editor_property("material_interface")
        sname = str(sl.get_editor_property("material_slot_name"))
        got = mi.get_path_name() if mi else None
        after.append({"slot": i, "slot_name": sname, "material": got})
        check("slot %d not null" % i, mi is not None, got)
        check("slot %d material" % i, got.split(".")[0] == mics[ORDER[i]],
              "got %r want %r" % (got, mics[ORDER[i]]))
        check("slot %d name" % i, sname == SLOT_NAMES[i],
              "got %r want %r" % (sname, SLOT_NAMES[i]))
    report["slots_after_reload"] = after
    report["approximation"] = {
        "slot": "M_Radio_Emissive",
        "what": "BaseColor is the authored EMISSIVE colour (1.000, 0.111, 0.044) instead of "
                "the authored base colour (0.520, 0.070, 0.030).",
        "why": "emissive is not reachable through M_BasicMaterial (LOG-0094). This reads as a "
               "bright red patch, NOT as a lamp, and is not emissive support.",
    }
    note("all %d assertions passed" % len(report["assertions"]))
    report["ok"] = True
except Exception as exc:  # noqa: BLE001
    report["ok"] = False
    report["errors"].append("%s: %s" % (type(exc).__name__, exc))
    unreal.log_error("[MBPL] " + traceback.format_exc())

if not os.path.isdir(OUT):
    os.makedirs(OUT)
with open(os.path.join(OUT, "prod_materials.json"), "w") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
unreal.log("[MBPL] wrote prod_materials.json ok=%s" % report.get("ok"))
