"""E-3c, editor side: a surrogate gameplay parent and a child derived from it.

RUNS INSIDE UnrealEditor-Cmd. See research/evidence/E-3c/preregistration.md.

WHAT THIS IS
------------
The authoring half of E-3c. It creates, in the Mod Kit project:

    /Game/SurvivalGameKitV2/Blueprints/Items/WorldItems/BP_StaticMasterItem
        the SURROGATE parent, at the real class's exact object path

    /Game/Mods/<mod_id>/BP_MiseryTestWorldItem
        the child, derived from the surrogate's generated class

and reports exactly what the toolchain accepted or refused.

THE SURROGATE IS AN AUTHORING-TIME FICTION
------------------------------------------
It exists so the editor has something to compile against, because the real
parent lives inside an encrypted container and no key is being extracted. It is
NOT shipped: the packager selects `Mods/<mod_id>/...` and the surrogate sits
outside that prefix, so it cannot reach a container by construction -- and the
driver reads the container back to confirm that rather than trusting it.

If the child ever binds to this surrogate at runtime, E-3c has FAILED even if
the object spawns and behaves. A subclass of our own stub is not a subclass of
the game's class.

THERE IS A PRECEDENT, FOR A DATA ASSET
--------------------------------------
Stage 3 did exactly this for a Material: `M_BasicMaterial` in this project is a
stand-in authored here, at the vanilla object path, deliberately not shipped, and
the cooked child's import resolved at runtime to the real vanilla material
(LOG entries around the A2 route). That proves the SHAPE of the scheme on this
build. It does not prove this case: a Material is referenced as an object, while
a parent class decides a subclass's layout, its CDO and its SuperStruct.

STAGES
------
S0 carries the object path and class name and nothing else. The stage that first
cooks is the ANSWER to "how complete must a surrogate be", so nothing is added
pre-emptively; each addition has to be demanded by a real, recorded failure.
"""
import json
import os
import traceback

import unreal

PLAN = json.load(open(os.environ["E3C_PLAN"], encoding="utf-8"))
REPORT_PATH = os.environ["E3C_REPORT"]

SURROGATE_DIR = PLAN["surrogate_dir"]
SURROGATE_NAME = PLAN["surrogate_name"]
SURROGATE_PATH = "%s/%s" % (SURROGATE_DIR, SURROGATE_NAME)
CHILD_DIR = PLAN["child_dir"]
CHILD_NAME = PLAN["child_name"]
CHILD_PATH = "%s/%s" % (CHILD_DIR, CHILD_NAME)
STAGE = PLAN["stage"]

report = {"stage": STAGE, "steps": [], "ok": False,
          "surrogate_path": SURROGATE_PATH, "child_path": CHILD_PATH}


def step(label, ok, detail=""):
    report["steps"].append({"step": label, "ok": bool(ok),
                            "detail": str(detail)[:2000]})
    unreal.log("[E3C] %s %s %s" % ("ok " if ok else "FAILED", label,
                                   "" if ok else "-- %s" % detail))
    return bool(ok)


def make_blueprint(name, directory, parent_class):
    factory = unreal.BlueprintFactory()
    factory.set_editor_property("parent_class", parent_class)
    return unreal.AssetToolsHelpers.get_asset_tools().create_asset(
        name, directory, unreal.Blueprint, factory)


try:
    tools = unreal.AssetToolsHelpers.get_asset_tools()

    # ---- 1. the surrogate parent, at the REAL class's object path ----------
    #
    # Deleted and rebuilt each run rather than reused: a surrogate left over
    # from a richer stage would silently answer for a poorer one, and the whole
    # point of staging is to learn which stage the cooker actually accepts.
    if unreal.EditorAssetLibrary.does_asset_exist(SURROGATE_PATH):
        unreal.EditorAssetLibrary.delete_asset(SURROGATE_PATH)
    if unreal.EditorAssetLibrary.does_asset_exist(CHILD_PATH):
        unreal.EditorAssetLibrary.delete_asset(CHILD_PATH)

    # S0: the real parent is Actor -> Object (LOG-0063), so the surrogate is an
    # empty Actor Blueprint. Nothing else is added at this stage BY DESIGN.
    surrogate = make_blueprint(SURROGATE_NAME, SURROGATE_DIR, unreal.Actor)
    if not step("the surrogate parent was created at the real object path",
                surrogate is not None, SURROGATE_PATH):
        raise SystemExit(0)

    unreal.BlueprintEditorLibrary.compile_blueprint(surrogate)
    surrogate_class = surrogate.generated_class()
    step("the surrogate compiled and produced a generated class",
         surrogate_class is not None,
         str(surrogate_class.get_path_name()) if surrogate_class else "none")
    if surrogate_class is None:
        raise SystemExit(0)

    # The generated class must be named <Asset>_C, because that suffix is what
    # makes the surrogate's class path equal the REAL class's path. If UE ever
    # named it differently the whole identity argument would collapse, so it is
    # checked rather than assumed.
    report["surrogate_class_path"] = surrogate_class.get_path_name()
    step("the surrogate's generated class carries the expected object path",
         surrogate_class.get_path_name() == PLAN["expected_parent_class_path"],
         "%s vs expected %s" % (surrogate_class.get_path_name(),
                                PLAN["expected_parent_class_path"]))

    unreal.EditorAssetLibrary.save_asset(SURROGATE_PATH)

    # ---- 2. the child, derived from the surrogate's generated class --------
    child = make_blueprint(CHILD_NAME, CHILD_DIR, surrogate_class)
    if not step("the child Blueprint was created", child is not None,
                CHILD_PATH):
        raise SystemExit(0)

    unreal.BlueprintEditorLibrary.compile_blueprint(child)
    child_class = child.generated_class()
    if not step("the child compiled against the surrogate parent",
                child_class is not None,
                str(child_class.get_path_name()) if child_class else "none"):
        raise SystemExit(0)
    report["child_class_path"] = child_class.get_path_name()

    # The child's parent as SERIALISED, read from the asset registry tag.
    #
    # UBlueprint does not expose ParentClass to Python, and reaching for it
    # aborted the first S0 run after everything of substance had already
    # succeeded. The registry tag is better evidence anyway: it is what was
    # written to the asset, not what happens to be in memory.
    #
    # NON-FATAL by design. This is a convenience reading of the authoring-time
    # binding; the authoritative evidence is the cooked package's import table,
    # which the driver inspects after the cook. A convenience check must not be
    # able to stop the experiment it is describing.
    parent_tag = None
    try:
        registry = unreal.AssetRegistryHelpers.get_asset_registry()
        data = registry.get_asset_by_object_path(CHILD_PATH + "." + CHILD_NAME)
        parent_tag = data.get_tag_value("ParentClass") if data else None
    except Exception as error:                                     # noqa: BLE001
        report["parent_tag_error"] = str(error)[:400]
    report["child_parent_class_tag"] = parent_tag
    if parent_tag:
        step("the child's serialised parent is the surrogate's class path",
             PLAN["expected_parent_class_path"] in str(parent_tag),
             str(parent_tag))
    else:
        # Recorded, not asserted: absence here says nothing about the binding.
        report["steps"].append({
            "step": "the child's serialised parent could not be read here",
            "ok": True,
            "detail": "not fatal -- the cooked import table is the evidence"})

    unreal.EditorAssetLibrary.save_asset(CHILD_PATH)
    report["ok"] = all(s["ok"] for s in report["steps"])

except Exception:                                                  # noqa: BLE001
    report["exception"] = traceback.format_exc()[-4000:]
    unreal.log_error("[E3C] %s" % report["exception"])
finally:
    with open(REPORT_PATH, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    unreal.log("[E3C] report -> %s" % REPORT_PATH)
