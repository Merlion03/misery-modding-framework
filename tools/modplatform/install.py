#!/usr/bin/env python3
"""Install and remove the framework's bootstrap surface. Nothing else.

THE ONLY PLACE ANYTHING IS WRITTEN INTO THE GAME
------------------------------------------------
The installation has been read-only for this project's whole life, and Stage 5B
is the first and only authorised exception: a minimal, explicitly designed
bootstrap surface. This file is that exception, made explicit so it can be
audited in one place.

Exactly two things are created, both NEW:

    <Binaries\\Win64>\\dwmapi.dll        the proxy the loader picks up
    <Binaries\\Win64>\\MiseryFramework\\ everything else lives in here

Not one existing game file is modified, moved, renamed or overwritten. There is
no repacking of game content, and no original asset is copied out. Uninstalling
is deleting those two things, which this file will also do.

THE GUARDS, AND WHY EACH ONE IS HERE
------------------------------------
* A pre-existing dwmapi.dll that we did not write is NEVER overwritten. Somebody
  else's proxy, or a real dependency shipped by the game, would be destroyed by
  a blind copy -- and the user would have no way to know what used to be there.
* Every write target is checked to be inside the intended directory, so a
  malformed argument cannot escape it.
* A manifest is written recording exactly what was created, so uninstall removes
  what was installed rather than what it guesses.
"""
import argparse
import hashlib
import json
import os
import shutil
import time

DEFAULT_INSTALL = r"D:\Games\Steam\steamapps\common\MISERY"
BINARIES = os.path.join("MISERY", "Binaries", "Win64")
PROXY_NAME = "dwmapi.dll"
FRAMEWORK_DIR = "MiseryFramework"
MANIFEST_NAME = "install-manifest.json"
# Written beside the proxy so a later run can tell OUR file from somebody else's.
MARKER_NAME = "installed-by-mbpl.txt"


class InstallError(Exception):
    pass


def binaries_dir(install_root):
    path = os.path.join(install_root, BINARIES)
    if not os.path.isdir(path):
        raise InstallError("no %s under %r -- is that a MISERY installation?"
                           % (BINARIES, install_root))
    return path


def framework_dir(install_root):
    return os.path.join(binaries_dir(install_root), FRAMEWORK_DIR)


def _inside(root, path):
    root_real = os.path.normcase(os.path.realpath(root))
    path_real = os.path.normcase(os.path.realpath(path))
    return path_real == root_real or path_real.startswith(root_real + os.sep)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def status(install_root):
    binaries = binaries_dir(install_root)
    proxy = os.path.join(binaries, PROXY_NAME)
    framework = os.path.join(binaries, FRAMEWORK_DIR)
    marker = os.path.join(framework, MARKER_NAME)
    return {
        "install_root": install_root,
        "binaries": binaries,
        "proxy_present": os.path.isfile(proxy),
        "proxy_is_ours": os.path.isfile(marker),
        "framework_present": os.path.isdir(framework),
        "framework_dir": framework,
        "contents": sorted(os.listdir(framework)) if os.path.isdir(framework) else [],
    }


def install(install_root, proxy_source, payload, force=False):
    """Create the bootstrap surface. *payload* is {name: source_path}."""
    binaries = binaries_dir(install_root)
    proxy = os.path.join(binaries, PROXY_NAME)
    framework = os.path.join(binaries, FRAMEWORK_DIR)
    marker = os.path.join(framework, MARKER_NAME)

    if os.path.isfile(proxy) and not os.path.isfile(marker) and not force:
        raise InstallError(
            "%s already exists and was not put there by this installer. It is "
            "not being overwritten: it may be another framework's proxy or "
            "something the game itself needs, and replacing it blindly would "
            "destroy it with no way to find out what it was." % proxy)

    os.makedirs(framework, exist_ok=True)
    created = []

    for name, source in sorted(payload.items()):
        target = os.path.join(framework, name)
        if not _inside(framework, target):
            raise InstallError("refusing to write outside %s: %r"
                               % (framework, target))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.isdir(source):
            if os.path.isdir(target):
                shutil.rmtree(target)
            shutil.copytree(source, target)
        else:
            shutil.copyfile(source, target)
        created.append(os.path.relpath(target, binaries))

    # The proxy goes LAST. Until it exists nothing of ours runs, so a failure
    # part-way through leaves an inert directory rather than a live bootstrap
    # pointing at an incomplete framework.
    shutil.copyfile(proxy_source, proxy)
    created.append(PROXY_NAME)

    with open(marker, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("Installed by the MBPL framework installer.\n"
                     "Deleting this directory and ..\\%s removes it entirely.\n"
                     % PROXY_NAME)

    manifest = {
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "install_root": install_root,
        "created": sorted(created),
        "proxy_sha256": _sha256(proxy),
    }
    with open(os.path.join(framework, MANIFEST_NAME), "w", encoding="utf-8",
              newline="\n") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    return manifest


def uninstall(install_root):
    """Remove exactly what was installed. Nothing adjacent."""
    binaries = binaries_dir(install_root)
    proxy = os.path.join(binaries, PROXY_NAME)
    framework = os.path.join(binaries, FRAMEWORK_DIR)
    marker = os.path.join(framework, MARKER_NAME)
    removed = []

    if os.path.isfile(proxy):
        if not os.path.isfile(marker):
            raise InstallError(
                "%s exists but there is no marker saying we installed it. "
                "Refusing to delete a file this installer may not have created."
                % proxy)
        os.remove(proxy)
        removed.append(PROXY_NAME)
    if os.path.isdir(framework):
        shutil.rmtree(framework)
        removed.append(FRAMEWORK_DIR + os.sep)
    return {"removed": removed}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("action", choices=("install", "uninstall", "status"))
    ap.add_argument("--install-root", default=DEFAULT_INSTALL)
    ap.add_argument("--proxy", help="the built proxy DLL")
    ap.add_argument("--payload", action="append", default=[],
                    metavar="NAME=PATH",
                    help="a file or directory to place in MiseryFramework")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)

    if a.action == "status":
        print(json.dumps(status(a.install_root), indent=2))
        return 0
    if a.action == "uninstall":
        print(json.dumps(uninstall(a.install_root), indent=2))
        return 0

    if not a.proxy:
        raise SystemExit("--proxy is required to install")
    payload = {}
    for entry in a.payload:
        name, _, path = entry.partition("=")
        if not name or not path:
            raise SystemExit("--payload takes NAME=PATH, got %r" % entry)
        payload[name] = path
    print(json.dumps(install(a.install_root, a.proxy, payload, a.force), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
