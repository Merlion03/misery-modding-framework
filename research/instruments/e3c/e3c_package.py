#!/usr/bin/env python3
"""E-3c: package the cooked child, and prove the surrogate is not in it.

    cooked child
      -> IoStore container
      -> verify the surrogate parent package/class is NOT distributed
      -> install through the normal MBPL mod path

The verification is the point of this step. The packager selects
`Mods/<mod_id>/...` and the surrogate lives outside that prefix, so its absence
is structural -- but a structural argument is not a measurement, and shipping the
surrogate is the one failure that would make every later result meaningless by
looking like success. So the container is read back and the surrogate's package
path is required to be absent from it.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "tools", "modkit"),
           os.path.join(REPO, "tools", "modplatform"),
           os.path.join(REPO, "research", "instruments", "runner"),
           os.path.join(REPO, "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import build as modkit                                            # noqa: E402
import container_report                                           # noqa: E402
import containers                                                 # noqa: E402
import install as installer                                       # noqa: E402

MOD_ID = "e3cprobe"
CONTAINER = "Mod_%s_P" % MOD_ID
CHILD_PACKAGE = "/Game/Mods/%s/BP_MiseryTestWorldItem" % MOD_ID
SURROGATE_PACKAGE = ("/Game/SurvivalGameKitV2/Blueprints/Items/WorldItems/"
                     "BP_StaticMasterItem")
WORK = r"D:\UEScratch\E3C"


class Spec(object):
    """The two things modkit.package asks of a spec, and nothing more.

    A full modkit.json would describe textures, materials and meshes this
    experiment does not have; inventing one to satisfy a constructor would be
    adding fiction to make a tool happy.
    """

    mod_id = MOD_ID

    def container_name(self):
        return CONTAINER


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--install-root", default=installer.DEFAULT_INSTALL)
    ap.add_argument("--out", required=True)
    ap.add_argument("--no-install", action="store_true")
    a = ap.parse_args(argv)

    checks = []

    def check(label, ok, detail=""):
        checks.append({"check": label, "pass": bool(ok), "detail": str(detail)})
        print("  [%s] %s%s" % ("PASS" if ok else "FAIL", label,
                               "" if ok else "  -- %s" % detail))
        return bool(ok)

    report = {"experiment": "E-3c", "phase": "package", "mod_id": MOD_ID}
    work = os.path.join(WORK, "package")
    if os.path.isdir(work):
        shutil.rmtree(work)
    os.makedirs(work)

    print("=== packaging the child into a container ===")
    pack_log = os.path.join(WORK, "package.log")
    result = modkit.package(Spec(), work, pack_log)
    report["package"] = result
    print("  entries=%s produced=%s exit=%s"
          % (result["entries"], result["produced"], result["exit"]))
    if not check("IoStore packaged the child", result["exit"] == 0,
                 result.get("error", "see %s" % pack_log)):
        write(report, checks, a.out)
        return 1

    # THE ANCHOR PAK, without which none of this is discoverable.
    #
    # build.py says it plainly: "a .utoc is picked up only as a NEIGHBOUR of a
    # mounted .pak". The IoStore step above produces only .utoc/.ucas, so
    # skipping the anchor would have shipped a container the engine never looks
    # at -- and the live run would then have reported "the child class did not
    # load", which reads exactly like an E-3c failure and would have been a
    # packaging omission of mine.
    #
    # The plan is empty because this mod has no textures, materials or meshes;
    # modinfo_text reads those groups with .get and writes a note stating,
    # truly, that the container derives nothing from MISERY.
    anchor_log = os.path.join(WORK, "anchor.log")
    anchor = modkit.pak_anchor(Spec(), {}, work, anchor_log)
    report["anchor"] = anchor
    print("  anchor pak: %s bytes, exit %s" % (anchor.get("bytes"),
                                               anchor["exit"]))
    check("the anchor pak was created",
          anchor["exit"] == 0 and anchor.get("bytes"), anchor)

    print("\n=== what the container actually holds ===")
    utoc = os.path.join(result["out_dir"], CONTAINER + ".utoc")
    contents = container_report.read_container(utoc)
    report["container"] = contents
    packages = contents.get("package_paths") or []
    for path in packages:
        print("   %s" % path)
    check("the container holds the child package",
          any(CHILD_PACKAGE in p for p in packages), packages)

    # THE CHECK THIS STEP EXISTS FOR.
    check("the surrogate parent package is NOT in the container",
          not any(SURROGATE_PACKAGE in p for p in packages),
          [p for p in packages if SURROGATE_PACKAGE in p])
    check("nothing outside this mod's namespace is in the container",
          all(("/Mods/%s/" % MOD_ID) in p for p in packages),
          [p for p in packages if ("/Mods/%s/" % MOD_ID) not in p])

    if a.no_install:
        write(report, checks, a.out)
        return 0 if all(c["pass"] for c in checks) else 1

    print("\n=== installing through the normal mod path ===")
    # The mod folder the production framework discovers: a manifest declaring
    # the container as content, and the container beside it. Exactly the layout
    # Stage 4 defined and Step 4 taught the runtime to read.
    mod_dir = installer.framework_dir(a.install_root)
    mod_dir = os.path.join(mod_dir, "Mods", "E3cProbe")
    content_dir = os.path.join(mod_dir, "Content")
    if os.path.isdir(mod_dir):
        shutil.rmtree(mod_dir)
    os.makedirs(content_dir)
    for suffix in (".pak", ".utoc", ".ucas"):
        source = os.path.join(result["out_dir"], CONTAINER + suffix)
        if os.path.isfile(source):
            shutil.copyfile(source, os.path.join(content_dir,
                                                 CONTAINER + suffix))
    manifest = {"manifest_version": 1, "mod_id": MOD_ID,
                "name": "E-3c inheritance probe", "version": "1.0.0",
                "framework_api": "^0.4.0", "content": [CONTAINER]}
    with open(os.path.join(mod_dir, "mod.json"), "w", encoding="utf-8",
              newline="\n") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    report["mod_dir"] = mod_dir
    print("  %s" % mod_dir)

    # The engine mounts containers from the staging directory, which lives
    # OUTSIDE the game installation. Same mechanism, same guard rails, as every
    # container this project has mounted.
    profile = {"remove": [CONTAINER],
               "stage": [{"src": result["out_dir"], "stem": CONTAINER}],
               "expect": [CONTAINER]}
    actions = containers.apply_profile(profile)
    report["staging"] = actions
    print("  staged: %s" % actions.get("staged"))
    check("the container was staged for the engine",
          bool(actions.get("staged")), actions)

    write(report, checks, a.out)
    return 0 if all(c["pass"] for c in checks) else 1


def write(report, checks, path):
    report["checks"] = checks
    report["passed"] = sum(1 for c in checks if c["pass"])
    report["failed"] = sum(1 for c in checks if not c["pass"])
    report["verdict"] = "PASS" if report["failed"] == 0 else "FAIL"
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, default=str)
        handle.write("\n")
    print("\n%s -- %d passed, %d failed -> %s"
          % (report["verdict"], report["passed"], report["failed"], path))


if __name__ == "__main__":
    raise SystemExit(main())
