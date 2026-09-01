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
import shutil
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
import container_report            # noqa: E402

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

    blueprints = [
        {"name": b.name, "parent": b.parent,
         "surrogate_package": b.surrogate_package,
         "package": spec.blueprint_path(b.name),
         "class_path": spec.blueprint_class_path(b.name)}
        for b in spec.blueprints]

    # Every product, including the textures generated above. The spec-derived
    # list would miss them, and anything not in this list is pruned before the
    # cook -- so leaving them out deletes assets the materials depend on.
    # Blueprints are products too, so they survive the prune that removes
    # anything the plan did not declare. Omitting them here would have the
    # editor build a class and the cook then delete it.
    produced = sorted({e["package"] for e in textures}
                      | {e["package"] for e in materials}
                      | {e["package"] for e in meshes}
                      | {e["package"] for e in blueprints})
    return {"mod_id": spec.mod_id,
            "mod_root": ns.mod_root(spec.mod_id),
            "container": spec.container_name(),
            "unreal_version": spec.unreal_version,
            "textures": textures, "materials": materials, "meshes": meshes,
            "blueprints": blueprints,
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


COOKED_ROOT = os.path.join(KIT_ROOT, "Saved", "Cooked", "Windows", "MISERY",
                           "Content")
# Where a container expects its files once mounted. The cooked tree is placed
# under this prefix inside the container, which is why the response file has two
# columns: where the file is now, and where it must appear.
MOUNT_PREFIX = "../../../MISERY/Content"
# IoStore resolves a cooked file back to its package name by looking the file up
# in the package store manifest, and the manifest stores those paths relative to
# the PLATFORM cook root ("MISERY/Content/Mods/..."), not to the content dir.
# Passing the content dir as -CookedDirectory made every lookup miss, and IoStore
# still exited 0 -- with a 48-byte, empty container.
REPO_ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
COOK_PLATFORM_ROOT = os.path.join(KIT_ROOT, "Saved", "Cooked", "Windows")
# What the response file may name. IoStore keys a cooked file back to its package
# through the manifest, which lists package heads (.uasset/.umap) and bulk data
# (.ubulk) -- but never .uexp, because the zen loader merges a package head and
# its exports into ONE chunk. Listing .uexp asks IoStore to resolve a file that by
# design has no package name, which it answers with a warning and exit code 0.
LISTED_COOKED_EXTENSIONS = (".uasset", ".umap", ".ubulk")
IMPLICIT_COOKED_EXTENSIONS = (".uexp",)
# The cook writes these beside the cooked content, and IoStore refuses without
# them: "Expected -PackageStoreManifest". They describe which packages exist and
# what script objects they may import, so a container built without them could
# not have its imports resolved at runtime.
COOK_METADATA = os.path.join(KIT_ROOT, "Saved", "Cooked", "Windows", "MISERY",
                             "Metadata")


def cook(log_path):
    """The exact UE 5.4.4 cook.

    Cooks the whole kit project; the response file below is what selects only
    this mod's packages into its own container.
    """
    command = [EDITOR_CMD, KIT_PROJECT, "-run=Cook", "-TargetPlatform=Windows",
               "-CookCultures=en", "-unversioned", "-stdout", "-unattended",
               "-nopause", "-nosplash"]
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    return proc.returncode


def cooked_files_for(mod_id):
    """Every cooked file under this mod's namespace, and nothing else.

    The namespace is doing real work here: selecting one mod's content out of a
    shared cooked tree is a simple prefix match precisely BECAUSE the package
    paths were derived from the ModId rather than from source filenames.
    """
    subtree = os.path.join(COOKED_ROOT, "Mods", mod_id)
    out, skipped, unknown = [], [], []
    for dirpath, _dirs, files in os.walk(subtree):
        for name in sorted(files):
            full = os.path.join(dirpath, name)
            extension = os.path.splitext(name)[1].lower()
            if extension in IMPLICIT_COOKED_EXTENSIONS:
                skipped.append(full.replace(os.sep, "/"))
                continue
            if extension not in LISTED_COOKED_EXTENSIONS:
                unknown.append(full.replace(os.sep, "/"))
                continue
            relative = os.path.relpath(full, COOKED_ROOT).replace(os.sep, "/")
            out.append((full.replace(os.sep, "/"),
                        MOUNT_PREFIX + "/" + relative))
    if unknown:
        raise BuildError("the cook produced file types this packager does not "
                         "know how to place in a container: %s" % unknown)
    return sorted(out), sorted(skipped)


# The three files a mod ships. `global.*` is deliberately NOT among them: our
# global container would shadow the game's own, which would harm rather than
# help, so it is a by-product we discard rather than a deliverable.
STAGED_EXTENSIONS = (".pak", ".utoc", ".ucas")


def modinfo_text(spec, plan):
    """The provenance note carried inside the anchor pak.

    This is a human-readable statement, not a discovery format: it records what
    the mod is built from and states plainly that no MISERY asset is contained
    in or derived from the container. Referencing a vanilla material as a
    parent is an import, and imports ship no bytes.
    """
    lines = ["%s -- built by the MISERY Mod Kit." % spec.mod_id,
             "Unreal %s, mod-authored content only." % modspec.ModSpec.REQUIRED_UNREAL,
             ""]
    # Author-supplied and build-generated are listed apart. The planner writes
    # real image files for constant colours, packed masks and a flat normal, and
    # calling those "supplied by the mod author" would misstate provenance in the
    # one file whose whole purpose is to state it correctly.
    authored, generated = set(), set()
    for group in ("textures", "meshes"):
        for entry in plan.get(group, []):
            if not entry.get("source"):
                continue
            name = os.path.basename(entry["source"])
            (generated if entry.get("generated") else authored).add(name)
    lines.append("Source files supplied by the mod author:")
    for source in sorted(authored):
        lines.append("    " + source)
    if generated:
        lines += ["", "Images generated by the Mod Kit from the spec:"]
        for source in sorted(generated):
            lines.append("    " + source)
    lines += ["", "Generated packages:"]
    for group in ("textures", "materials", "meshes"):
        for entry in plan.get(group, []):
            lines.append("    " + entry["package"])
    lines += ["",
              "No MISERY package or asset is contained in or derived from this",
              "container. Vanilla materials are referenced as parents only."]
    return chr(10).join(lines) + chr(10)


def pak_anchor(spec, plan, work, log_path):
    """The .pak that makes the container discoverable.

    A `.utoc` is picked up only as a NEIGHBOUR of a mounted `.pak`, so the pak
    is what gets the IoStore container seen at all. It carries exactly one
    file -- the provenance note -- because its job is to be found, not to hold
    content: the content lives in the `.ucas` beside it.
    """
    anchor_dir = os.path.join(work, "anchor")
    os.makedirs(anchor_dir, exist_ok=True)
    note = os.path.join(anchor_dir, "%s.modinfo" % spec.mod_id)
    with open(note, "w", encoding="utf-8", newline=chr(10)) as handle:
        handle.write(modinfo_text(spec, plan))
    response = os.path.join(work, "pak-response.txt")
    mounted = "%s/Mods/%s/%s.modinfo" % (MOUNT_PREFIX, spec.mod_id, spec.mod_id)
    with open(response, "w", encoding="utf-8", newline=chr(10)) as handle:
        handle.write('"%s" "%s"' % (note.replace(os.sep, "/"), mounted) + chr(10))
    out_dir = os.path.join(work, "container")
    os.makedirs(out_dir, exist_ok=True)
    pak = os.path.join(out_dir, spec.container_name() + ".pak")
    command = [UNREAL_PAK, pak.replace(os.sep, "/"),
               "-Create=%s" % response.replace(os.sep, "/"),
               "-platform=Windows"]
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        log.write("command: " + " ".join(command) + chr(10) * 2)
        log.flush()
        proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    return {"exit": proc.returncode, "pak": pak,
            "bytes": os.path.getsize(pak) if os.path.isfile(pak) else None,
            "modinfo": note}


def stage(spec, work):
    """Copy the three shipped files into the discovery directory.

    The copying itself is delegated to ``runner/containers.apply_profile``,
    which already refuses any path inside the game installation and any stem
    that does not resolve to a direct child of the staging directory. A second
    implementation writing to the same directory would be a second thing to get
    wrong, so this function decides WHAT to stage and nothing else.

    `global.utoc`/`global.ucas` are built beside the mod container but are never
    staged: ours would shadow the game's own. That is asserted, not assumed.
    """
    sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "runner"))
    import containers                                              # noqa: PLC0415

    out_dir = os.path.join(work, "container")
    for extension in STAGED_EXTENSIONS:
        source = os.path.join(out_dir, spec.container_name() + extension)
        if not os.path.isfile(source):
            raise BuildError("nothing to stage: %s was never built" % source)
    actions = containers.apply_profile(
        {"stage": [{"src": out_dir, "stem": spec.container_name()}]})
    staged = [os.path.basename(item["dst"]) for item in actions["staged"]]
    surplus = sorted(set(staged) - {spec.container_name() + e
                                    for e in STAGED_EXTENSIONS})
    if surplus:
        raise BuildError("staged files beyond the three shipped ones: %s" % surplus)
    present = sorted(os.listdir(containers.DEFAULT_STAGE_DIR))
    globals_staged = [name for name in present if name.lower().startswith("global.")]
    if globals_staged:
        raise BuildError("a global container is present in the discovery directory "
                         "(%s); it would shadow the game's own" % globals_staged)
    return {"dir": containers.DEFAULT_STAGE_DIR, "staged": actions["staged"],
            "directory_now": present}


def _read_text(path):
    if not os.path.isfile(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def package(spec, work, log_path):
    """One IoStore container holding only this mod's cooked packages."""
    entries, implicit = cooked_files_for(spec.mod_id)
    if not entries:
        raise BuildError("nothing cooked under Mods/%s -- the cook either failed "
                         "or produced no content for this mod" % spec.mod_id)
    out_dir = os.path.join(work, "container")
    os.makedirs(out_dir, exist_ok=True)
    response = os.path.join(work, "response.txt")
    with open(response, "w", encoding="utf-8", newline=chr(10)) as handle:
        for source, mounted in entries:
            handle.write('"%s" "%s"' % (source, mounted) + chr(10))
    container = spec.container_name()
    # The container is named for the mod, so two mods can never write the same
    # .utoc even when their source files are identically named.
    commands = os.path.join(work, "commands.txt")
    out_slash = out_dir.replace(os.sep, "/")
    with open(commands, "w", encoding="utf-8", newline=chr(10)) as handle:
        handle.write('-Output="%s/%s.utoc" -ContainerName=%s -ResponseFile="%s"'
                     % (out_slash, container, container,
                        response.replace(os.sep, "/")) + chr(10))
    manifest = os.path.join(COOK_METADATA, "packagestore.manifest")
    script_objects = os.path.join(COOK_METADATA, "scriptobjects.bin")
    for required in (manifest, script_objects):
        if not os.path.isfile(required):
            raise BuildError("the cook produced no %s; IoStore cannot resolve "
                             "imports without it" % os.path.basename(required))
    command = [UNREAL_PAK,
               "-CreateGlobalContainer=%s/global.utoc" % out_slash,
               "-CookedDirectory=%s" % COOK_PLATFORM_ROOT.replace(os.sep, "/"),
               "-Commands=%s" % commands.replace(os.sep, "/"),
               "-PackageStoreManifest=%s" % manifest.replace(os.sep, "/"),
               "-ScriptObjects=%s" % script_objects.replace(os.sep, "/"),
               "-TargetPlatform=Windows"]
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        log.write("command: " + " ".join(command) + chr(10) * 2)
        log.flush()
        proc = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    produced = sorted(os.listdir(out_dir)) if os.path.isdir(out_dir) else []
    # IoStore reports an unresolvable cooked file as a WARNING and still exits 0,
    # so the exit code alone cannot distinguish a real container from an empty
    # one. Treat any unresolved package as fatal: a container that silently drops
    # content would fail much later, in the game, as a missing asset.
    log_text = _read_text(log_path)
    unresolved = [line.strip() for line in log_text.splitlines()
                  if "Failed to obtain package name" in line]
    out = {"exit": proc.returncode, "out_dir": out_dir, "entries": len(entries),
           "produced": produced, "response": response, "commands": commands,
           "unresolved": unresolved, "implicit_files": len(implicit)}
    if unresolved:
        out["exit"] = out["exit"] or 1
        out["error"] = ("IoStore could not resolve %d cooked file(s) to a package "
                        "name; the container would be missing them"
                        % len(unresolved))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--spec", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--plan-only", action="store_true",
                    help="validate and plan, but do not launch the editor")
    ap.add_argument("--no-cook", action="store_true",
                    help="build assets in the editor but stop before cooking")
    ap.add_argument("--stage", action="store_true",
                    help="copy the three shipped files into the discovery directory")
    ap.add_argument("--package-only", action="store_true",
                    help="reuse the existing cook and only rebuild the container")
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

    if a.package_only:
        return _finish(spec, work, result, a, plan)

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
    if not editor_report.get("ok"):
        result["ok"] = False
        result["stopped_at"] = "editor"
        _write(result, a.out or os.path.join(work, "build-report.json"))
        return 1

    if a.no_cook:
        result["ok"] = True
        result["stopped_at"] = "editor-only"
        _write(result, a.out or os.path.join(work, "build-report.json"))
        return 0

    code = cook(os.path.join(work, "cook.log"))
    result["cook"] = {"exit": code}
    print("cook: exit %d" % code)
    if code != 0:
        result["ok"] = False
        result["stopped_at"] = "cook"
        _write(result, a.out or os.path.join(work, "build-report.json"))
        return 1

    return _finish(spec, work, result, a, plan)


def _finish(spec, work, result, a, plan):
    """Package, then READ THE CONTAINER BACK and grade the build on its contents.

    The verification is not optional and not a separate command, because the
    failure it exists to catch -- a container that builds successfully and holds
    nothing -- is invisible to every other signal the build produces.
    """
    packaged = package(spec, work, os.path.join(work, "iostore.log"))
    result["package"] = packaged
    print("package: exit %d, %d cooked files -> %s"
          % (packaged["exit"], packaged["entries"], packaged["produced"]))
    if packaged["exit"] != 0:
        result["ok"] = False
        result["stopped_at"] = "package"
        _write(result, a.out or os.path.join(work, "build-report.json"))
        return 1

    anchor = pak_anchor(spec, plan, work, os.path.join(work, "pak.log"))
    result["anchor"] = anchor
    print("anchor pak: exit %d, %s bytes" % (anchor["exit"], anchor["bytes"]))
    if anchor["exit"] != 0:
        result["ok"] = False
        result["stopped_at"] = "anchor"
        _write(result, a.out or os.path.join(work, "build-report.json"))
        return 1

    utoc = os.path.join(packaged["out_dir"], spec.container_name() + ".utoc")
    report = container_report.read_container(utoc)
    findings = V.validate_container(spec, report)
    result["container"] = report
    result["container_validation"] = V.summarise(findings)
    print("container: %d entries, chunk types %s, %d package(s), %d finding(s)"
          % (report["entry_count"], report["chunk_types"],
             len(report["package_paths"]), len(findings)))
    for finding in findings:
        print("  [%s] %s" % (finding.code, finding.message))
    result["ok"] = not V.fatal(findings)
    result["stopped_at"] = None if result["ok"] else "container"
    if result["ok"] and a.stage:
        result["staging"] = stage(spec, work)
        print("staged into %s: %s"
              % (result["staging"]["dir"],
                 [os.path.basename(e["dst"]) for e in result["staging"]["staged"]]))
    _write(result, a.out or os.path.join(work, "build-report.json"))
    return 0 if result["ok"] else 1


def _write(payload, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False, default=str)
        handle.write("\n")


if __name__ == "__main__":
    sys.exit(main())
