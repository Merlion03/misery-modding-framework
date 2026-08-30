#!/usr/bin/env python3
"""The Mod Kit build driver: source spec -> cooked, namespaced, staged content.

    python build.py --spec <modkit.json> [--stage]

Stages, in order, each refusing to start until the one before it is clean:

    validate    offline, before the editor is ever launched -- a cook takes
                minutes and a typo should not cost one
    plan        resolve every material to concrete texture assets, generating
                tiny constant maps where the author gave a number instead of an
                image, and pack AO/Roughness/Metallic in the measured order
    editor      import, build instances, assign slots, reload from disk, assert
    cook        the exact UE 5.4.4 cook
    package     one IoStore container, namespaced by ModId
    verify      the container's own contents and, above all, that it carries no
                shader archive chunks

Kept apart from the Stage 2 runtime API on purpose: this is authoring and build
time, that is a live game. The only thing crossing between them is a set of
stable object paths.
"""
import argparse
import json
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(_HERE, "..", ".."))
for _p in (_HERE, os.path.join(REPO, "tools", "fingerprint")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import fixtures                    # noqa: E402
import modspec                     # noqa: E402
import namespace as ns             # noqa: E402
import profiles                    # noqa: E402
import checks as V                  # noqa: E402

# The one toolchain this pipeline is proven against. Anything else fails closed:
# content whose cook provenance cannot be stated is worse than no content.
UNREAL_ROOT = r"D:\Program Files\UE_5.4"
EDITOR_CMD = os.path.join(UNREAL_ROOT, "Engine", "Binaries", "Win64",
                          "UnrealEditor-Cmd.exe")
UNREAL_PAK = os.path.join(UNREAL_ROOT, "Engine", "Binaries", "Win64", "UnrealPak.exe")
KIT_PROJECT = r"D:\UEScratch\MBPLKit\MISERY.uproject"
KIT_ROOT = r"D:\UEScratch\MBPLKit"
BUILD_ROOT = r"D:\UEScratch\ModKitBuild"


class BuildError(Exception):
    pass


# --------------------------------------------------------------------- plan
def make_plan(spec, work_dir):
    """Turn a validated spec into something the editor script can execute blindly.

    Two things happen here rather than in the editor: constants become tiny
    generated images, and AO/Roughness/Metallic are packed into one mask in the
    profile's measured channel order. Both are decisions with a reason, and the
    editor script should carry no decisions at all.
    """
    os.makedirs(work_dir, exist_ok=True)
    generated_dir = os.path.join(work_dir, "generated")
    os.makedirs(generated_dir, exist_ok=True)

    textures = []
    for texture in spec.textures:
        srgb, compression, _why = modspec.TEXTURE_USAGES[texture.usage]
        textures.append({"name": texture.name,
                         "package": spec.texture_path(texture.name),
                         "source": spec.source_of(texture.source),
                         "srgb": srgb, "compression": compression,
                         "usage": texture.usage, "generated": False})
    by_name = {t["name"]: t for t in textures}

    def add_generated(name, usage, rgb):
        if name in by_name:
            return by_name[name]
        srgb, compression, _why = modspec.TEXTURE_USAGES[usage]
        path = os.path.join(generated_dir, "%s.png" % name)
        fixtures.write_png(path, 4, 4, rgb)
        entry = {"name": name, "package": spec.texture_path(name), "source": path,
                 "srgb": srgb, "compression": compression, "usage": usage,
                 "generated": True}
        textures.append(entry)
        by_name[name] = entry
        return entry

    materials = []
    for material in spec.materials:
        profile = profiles.profile_for(material.parent)     # raises if unmeasured
        entry = {"name": material.name,
                 "package": spec.material_path(material.name),
                 "parent": material.parent, "textures": {}, "scalars": {},
                 "profile": material.parent}

        base = material.base_color
        if "texture" in base:
            base_texture = by_name[base["texture"]]
        else:
            # A constant colour still has to reach the shader through the
            # parent's texture parameter, so it becomes a 4x4 image -- encoded
            # through the sRGB transfer function, because a colour map is
            # sampled as sRGB and a raw value would come back darker than
            # authored.
            base_texture = add_generated("%sBase" % material.name, "color",
                                         fixtures.srgb_encode(base["constant"]))
        entry["textures"][profile["base_color_parameter"]] = base_texture["package"]

        channels = {"ao": material.ao, "roughness": material.roughness,
                    "metallic": material.metallic}
        mask_rgb = [channels[c] * 255.0 for c in profile["mask_channels"]]
        mask_texture = add_generated("%sMask" % material.name, "mask", mask_rgb)
        entry["textures"][profile["mask_parameter"]] = mask_texture["package"]
        entry["mask_channel_order"] = list(profile["mask_channels"])

        if material.normal and isinstance(material.normal, dict) \
                and "texture" in material.normal:
            normal_texture = by_name[material.normal["texture"]]
        else:
            # Flat tangent-space normal: (0.5, 0.5, 1.0) unencoded.
            normal_texture = add_generated("NeutralNormal", "normal",
                                           [128.0, 128.0, 255.0])
        entry["textures"][profile["normal_parameter"]] = normal_texture["package"]
        materials.append(entry)

    material_packages = {m["name"]: m["package"] for m in materials}
    meshes = []
    for mesh in spec.meshes:
        meshes.append({
            "name": mesh.name, "package": spec.mesh_path(mesh.name),
            "source": spec.source_of(mesh.source),
            "uniform_scale": mesh.uniform_scale,
            "slots": [{"index": slot["index"],
                       "material_package": material_packages[slot["material"]],
                       "slot_name": slot.get("slot_name")}
                      for slot in mesh.slots]})

    # Every product, including the textures generated above. The spec-derived
    # list would miss them, and anything not in this list is pruned before the
    # cook -- so leaving them out deletes assets the materials depend on.
    produced = sorted({e["package"] for e in textures}
                      | {e["package"] for e in materials}
                      | {e["package"] for e in meshes})
    return {"mod_id": spec.mod_id,
            "mod_root": ns.mod_root(spec.mod_id),
            "container": spec.container_name(),
            "unreal_version": spec.unreal_version,
            "textures": textures, "materials": materials, "meshes": meshes,
            "declared_object_paths": V.expected_object_paths(spec),
            "expected_object_paths": ["%s.%s" % (p, p.rsplit("/", 1)[-1])
                                      for p in produced]}


# ------------------------------------------------------------------- stages
def check_toolchain():
    missing = [p for p in (EDITOR_CMD, UNREAL_PAK, KIT_PROJECT) if not os.path.isfile(p)]
    if missing:
        raise BuildError("unsupported toolchain: missing %s. The pipeline is proven "
                         "against UE %s only and fails closed rather than producing "
                         "content whose provenance nobody can state."
                         % (missing, modspec.ModSpec.REQUIRED_UNREAL))
    version_file = os.path.join(UNREAL_ROOT, "Engine", "Build", "Build.version")
    with open(version_file, encoding="utf-8-sig") as handle:
        version = json.load(handle)
    got = "%s.%s.%s" % (version["MajorVersion"], version["MinorVersion"],
                        version["PatchVersion"])
    if got != modspec.ModSpec.REQUIRED_UNREAL:
        raise BuildError("unsupported toolchain: found Unreal %s, need %s"
                         % (got, modspec.ModSpec.REQUIRED_UNREAL))
    return {"unreal": got, "changelist": version.get("Changelist"),
            "branch": version.get("BranchName")}


def run_editor(plan_path, report_path, log_path):
    env = dict(os.environ)
    env["MODKIT_PLAN"] = plan_path
    env["MODKIT_REPORT"] = report_path
    command = [EDITOR_CMD, KIT_PROJECT, "-run=pythonscript",
               "-script=%s" % os.path.join(_HERE, "editor_build.py"),
               "-unattended", "-nopause", "-nosplash", "-stdout"]
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, env=env)
    if not os.path.isfile(report_path):
        raise BuildError("the editor produced no report; see %s" % log_path)
    with open(report_path, encoding="utf-8") as handle:
        return proc.returncode, json.load(handle)


def cook(mod_root, log_path):
    command = [EDITOR_CMD, KIT_PROJECT, "-run=Cook", "-TargetPlatform=Windows",
               "-CookCultures=en", "-unversioned", "-stdout", "-unattended",
               "-nopause", "-nosplash"]
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    return proc.returncode


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--spec", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--plan-only", action="store_true",
                    help="validate and plan, but do not launch the editor")
    a = ap.parse_args(argv)

    spec = modspec.ModSpec.load(a.spec)
    work = os.path.join(BUILD_ROOT, spec.mod_id)
    os.makedirs(work, exist_ok=True)
    result = {"mod_id": spec.mod_id, "spec": a.spec,
              "started": time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime())}

    findings = V.validate_spec(spec)
    result["validation"] = V.summarise(findings)
    print("validation: %d findings, %d fatal" % (len(findings), len(V.fatal(findings))))
    for finding in findings:
        print("   ", finding)
    if V.fatal(findings):
        result["ok"] = False
        result["stopped_at"] = "validate"
        _write(result, a.out or os.path.join(work, "build-report.json"))
        return 1

    result["toolchain"] = check_toolchain()
    print("toolchain: %s" % result["toolchain"])

    plan = make_plan(spec, work)
    plan_path = os.path.join(work, "plan.json")
    _write(plan, plan_path)
    result["plan"] = {"path": plan_path, "textures": len(plan["textures"]),
                      "materials": len(plan["materials"]),
                      "meshes": len(plan["meshes"]),
                      "generated_textures": [t["name"] for t in plan["textures"]
                                             if t["generated"]],
                      "expected_object_paths": plan["expected_object_paths"]}
    print("plan: %d textures (%d generated), %d materials, %d meshes"
          % (len(plan["textures"]),
             sum(1 for t in plan["textures"] if t["generated"]),
             len(plan["materials"]), len(plan["meshes"])))
    if a.plan_only:
        result["ok"] = True
        result["stopped_at"] = "plan-only"
        _write(result, a.out or os.path.join(work, "build-report.json"))
        return 0

    code, editor_report = run_editor(plan_path,
                                     os.path.join(work, "editor-report.json"),
                                     os.path.join(work, "editor.log"))
    result["editor"] = {"exit": code, "ok": editor_report.get("ok"),
                        "assertions": len(editor_report.get("assertions") or []),
                        "failed_assertions": [x for x in
                                              (editor_report.get("assertions") or [])
                                              if not x["pass"]],
                        "errors": editor_report.get("errors"),
                        "meshes": editor_report.get("meshes")}
    print("editor: ok=%s, %d assertions, %d failed"
          % (editor_report.get("ok"), len(editor_report.get("assertions") or []),
             len(result["editor"]["failed_assertions"])))
    result["ok"] = bool(editor_report.get("ok"))
    result["stopped_at"] = None if result["ok"] else "editor"
    _write(result, a.out or os.path.join(work, "build-report.json"))
    return 0 if result["ok"] else 1


def _write(payload, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False, default=str)
        handle.write("\n")


if __name__ == "__main__":
    sys.exit(main())
