# OFFLINE BUILD ONLY. Corrected probe build.
#
# The previous two builds reported the assignment they INTENDED rather than the
# one that stuck. Both mutated the elements of mesh.static_materials in place and
# handed the same array object back, which silently did not write, and neither
# re-read the asset afterwards. fixup_mesh.py built a NEW list and verified by
# re-reading, and that one worked.
#
# So this script does three things the others did not:
#   1. builds a fresh list of unreal.StaticMaterial VALUES,
#   2. saves, then reloads the asset FROM DISK and asserts every slot,
#   3. refuses to continue -- ok=False, nothing cooked -- if any assertion fails.
# Every MIC is independently verified for parent and texture overrides too.
import json
import os
import traceback

import unreal

OUT = "D:/UEScratch/MBPLKit/out"
SRC = "D:/UEScratch/MBPLKit/Source_PNG/arm2"
PARENT_PATH = "/Game/PlayerElectricitySystem/Materials/M_BasicMaterial"
DIR = "/Game/MBPLArmProbe3"
MESH_NAME = "SM_ArmProbe3"
MESH_PATH = "%s/%s" % (DIR, MESH_NAME)

ORDER = ["REF", "A", "B", "EM"]
SLOT_NAMES = ["M_Probe_REF", "M_Probe_A", "M_Probe_B", "M_Probe_EM"]

report = {"errors": [], "notes": [], "assertions": []}


def note(m):
    report["notes"].append(str(m))
    unreal.log("[MBPL] %s" % m)


def check(label, ok, detail=""):
    report["assertions"].append({"check": label, "pass": bool(ok), "detail": str(detail)})
    if not ok:
        raise AssertionError("%s -- %s" % (label, detail))
    return True


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


def make_mic(name, parent, textures, vectors=None, scalars=None):
    path = "%s/%s" % (DIR, name)
    if unreal.EditorAssetLibrary.does_asset_exist(path):
        unreal.EditorAssetLibrary.delete_asset(path)
    m = unreal.AssetToolsHelpers.get_asset_tools().create_asset(
        name, DIR, unreal.MaterialInstanceConstant,
        unreal.MaterialInstanceConstantFactoryNew())
    unreal.MaterialEditingLibrary.set_material_instance_parent(m, parent)
    for pn, tp in textures.items():
        tex = unreal.EditorAssetLibrary.load_asset(tp)
        if tex is None:
            raise RuntimeError("texture %s did not load for %s" % (tp, name))
        unreal.MaterialEditingLibrary.set_material_instance_texture_parameter_value(m, pn, tex)
    for pn, v in (vectors or {}).items():
        unreal.MaterialEditingLibrary.set_material_instance_vector_parameter_value(
            m, pn, unreal.LinearColor(v[0], v[1], v[2], 1.0))
    for pn, v in (scalars or {}).items():
        unreal.MaterialEditingLibrary.set_material_instance_scalar_parameter_value(m, pn, v)
    unreal.EditorAssetLibrary.save_asset(path)
    return path


try:
    # import the probe geometry into the NEW folder first
    task = unreal.AssetImportTask()
    task.filename = "%s/arm_probe2.glb" % SRC
    task.destination_path = DIR
    task.destination_name = MESH_NAME
    task.automated = True
    task.replace_existing = True
    task.save = True
    unreal.AssetToolsHelpers.get_asset_tools().import_asset_tasks([task])

    parent = unreal.EditorAssetLibrary.load_asset(PARENT_PATH)
    check("stand-in parent loads", parent is not None, PARENT_PATH)

    bc_red = imp_tex("T2_BC_Red.png", "T2_BC_Red", True,
                     unreal.TextureCompressionSettings.TC_DEFAULT)
    bc_grey = imp_tex("T2_BC_Grey.png", "T2_BC_Grey", True,
                      unreal.TextureCompressionSettings.TC_DEFAULT)
    nrm = imp_tex("T2_N.png", "T2_N", False,
                  unreal.TextureCompressionSettings.TC_NORMALMAP)
    arm = {k: imp_tex("T2_ARM_%s.png" % k, "T2_ARM_%s" % k, False,
                      unreal.TextureCompressionSettings.TC_MASKS) for k in ORDER}

    intended_tex = {
        "REF": {"BaseColor": bc_red, "ARM": arm["REF"], "Normal": nrm},
        "A": {"BaseColor": bc_red, "ARM": arm["A"], "Normal": nrm},
        "B": {"BaseColor": bc_red, "ARM": arm["B"], "Normal": nrm},
        "EM": {"BaseColor": bc_grey, "ARM": arm["EM"], "Normal": nrm},
    }
    mics = {}
    for k in ORDER:
        extra = {}
        if k == "EM":
            extra = {"vectors": {"Emissive": (1.0, 0.25, 0.05),
                                 "EmissiveColor": (1.0, 0.25, 0.05)},
                     "scalars": {"EmissiveStrength": 20.0}}
        mics[k] = make_mic("MI_P2_%s" % k, parent, intended_tex[k], **extra)

    # ---- independent MIC verification, from a fresh load ---------------------
    report["mic_verification"] = {}
    for k in ORDER:
        unreal.EditorAssetLibrary.load_asset(mics[k])
        m = unreal.EditorAssetLibrary.load_asset(mics[k])
        p = m.get_editor_property("parent")
        check("MIC %s parent is the intended material" % k,
              p is not None and p.get_path_name().split(".")[0] == PARENT_PATH,
              p.get_path_name() if p else None)
        got = {}
        for v in m.get_editor_property("texture_parameter_values"):
            pname = str(v.get_editor_property("parameter_info").get_editor_property("name"))
            tv = v.get_editor_property("parameter_value")
            got[pname] = tv.get_path_name() if tv else None
        for pname, want in intended_tex[k].items():
            check("MIC %s override %s" % (k, pname),
                  got.get(pname, "").split(".")[0] == want,
                  "got %r want %r" % (got.get(pname), want))
        report["mic_verification"][k] = {"parent": p.get_path_name(), "textures": got}

    # ---- the fix: a FRESH list of StaticMaterial values ----------------------
    mesh = unreal.EditorAssetLibrary.load_asset(MESH_PATH)
    check("probe mesh loads", isinstance(mesh, unreal.StaticMesh), MESH_PATH)
    check("probe mesh slot count", len(mesh.static_materials) == len(ORDER),
          len(mesh.static_materials))

    fresh = []
    for i, k in enumerate(ORDER):
        mi = unreal.EditorAssetLibrary.load_asset(mics[k])
        check("MIC %s loads for assignment" % k, mi is not None, mics[k])
        sm = unreal.StaticMaterial()
        sm.set_editor_property("material_interface", mi)
        sm.set_editor_property("material_slot_name", unreal.Name(SLOT_NAMES[i]))
        # imported_material_slot_name is read-only on FStaticMaterial; the cooker
        # does not need it and setting it raised.
        fresh.append(sm)
    mesh.set_editor_property("static_materials", fresh)
    unreal.EditorAssetLibrary.save_asset(MESH_PATH)

    # ---- reload FROM DISK and assert ----------------------------------------
    unreal.EditorAssetLibrary.save_directory(DIR, only_if_is_dirty=False, recursive=True)
    reloaded = unreal.EditorAssetLibrary.load_asset(MESH_PATH)
    slots_after = []
    for i, sl in enumerate(reloaded.static_materials):
        mi = sl.get_editor_property("material_interface")
        sname = str(sl.get_editor_property("material_slot_name"))
        got = mi.get_path_name() if mi else None
        slots_after.append({"slot": i, "slot_name": sname, "material": got})
        check("slot %d MaterialInterface is not null" % i, mi is not None, got)
        check("slot %d material path" % i,
              got.split(".")[0] == mics[ORDER[i]],
              "got %r want %r" % (got, mics[ORDER[i]]))
        check("slot %d slot name" % i, sname == SLOT_NAMES[i],
              "got %r want %r" % (sname, SLOT_NAMES[i]))
    report["slots_after_reload"] = slots_after
    note("all slot assertions passed: %s" % slots_after)
    report["ok"] = True
except Exception as exc:  # noqa: BLE001
    report["ok"] = False
    report["errors"].append("%s: %s" % (type(exc).__name__, exc))
    unreal.log_error("[MBPL] " + traceback.format_exc())

if not os.path.isdir(OUT):
    os.makedirs(OUT)
with open(os.path.join(OUT, "arm_probe3b.json"), "w") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
unreal.log("[MBPL] wrote arm_probe3b.json  ok=%s" % report.get("ok"))
