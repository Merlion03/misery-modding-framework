#!/usr/bin/env python3
"""Assemble a real ``Mods/`` tree from Stage 3 build output.

    Mods/
      ZZ_AlphaMod_v1/          <- folder name deliberately unlike the mod_id
        mod.json               <- mod_id: alphamod
        Content/Mod_alphamod_P.{pak,utoc,ucas}
        Code/items.py
      aa-beta-mod/             <- different case, different shape, same story
        mod.json               <- mod_id: betamod
        Content/Mod_betamod_P.{pak,utoc,ucas}
        Code/items.py

The folder names are chosen to sort in the OPPOSITE order to the mod_ids and to
look nothing like them. If any layer ever starts keying off the folder name --
for identity, for ordering, for anything -- the acceptance fails immediately
rather than in someone's install months later.

This consumes Stage 3's output through the manifest's declared content. It does
not change how Stage 3 builds anything.
"""
import argparse
import json
import os
import shutil
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "tools", "modframework"),
           os.path.join(REPO, "tools", "modkit")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import namespace as ns                                             # noqa: E402
import treefixtures as fx                                          # noqa: E402

# Folder name -> the mod it holds. The folder names sort ZZ.. before aa.. only
# if case is ignored, and after it if it is not -- either way they do not match
# the mod_id order, which is the point.
FIXTURE_LAYOUT = (
    {"folder": "ZZ_AlphaMod_v1", "mod_id": "alphamod", "version": "1.0.0",
     "build_dir": "D:/UEScratch/ModKitBuild/alphamod",
     "local_id": "shape", "mesh": "Shape", "icon": "Icon"},
    {"folder": "aa-beta-mod", "mod_id": "betamod", "version": "1.0.0",
     "build_dir": "D:/UEScratch/ModKitBuild/betamod",
     "local_id": "shape", "mesh": "Shape", "icon": "Icon",
     # betamod depends on alphamod, so the load order is forced to be
     # alphamod-then-betamod by the GRAPH -- which is also the order the folder
     # names would give if anyone were reading them backwards.
     "dependencies": [{"mod_id": "alphamod", "version": "^1.0.0"}]},
)


def build(root, layout=FIXTURE_LAYOUT, clean=True):
    if clean and os.path.isdir(root):
        shutil.rmtree(root)
    os.makedirs(root, exist_ok=True)
    made = []
    for entry in layout:
        mod_root = os.path.join(root, entry["folder"])
        os.makedirs(mod_root, exist_ok=True)
        container = ns.container_name(entry["mod_id"])
        source = os.path.join(entry["build_dir"], "container")
        fx.copy_container(mod_root, source, container)
        fx.write_items_module(
            mod_root, entry["mod_id"], local_id=entry["local_id"],
            mesh=ns.package_path(entry["mod_id"], "mesh", entry["mesh"]),
            icon=ns.package_path(entry["mod_id"], "texture", entry["icon"]))
        body = fx.manifest_body(
            entry["mod_id"],
            name="%s (Stage 4 fixture)" % entry["mod_id"],
            version=entry["version"],
            dependencies=entry.get("dependencies"),
            content=[container],
            code=["items.py"])
        fx.write_manifest(mod_root, body)
        made.append({"folder": entry["folder"], "mod_id": entry["mod_id"],
                     "root": mod_root, "container": container})
    return made


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default="D:/UEScratch/ModsRoot")
    ap.add_argument("--keep", action="store_true",
                    help="do not wipe the root first")
    a = ap.parse_args(argv)
    made = build(a.root, clean=not a.keep)
    print(json.dumps({"root": a.root, "mods": made}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
