#!/usr/bin/env python3
"""Build mod trees to test against -- the good ones and the broken ones.

NAMED ``treefixtures`` AND NOT ``fixtures`` ON PURPOSE
------------------------------------------------------
tools/modkit already has a ``fixtures``. These directories are put on
``sys.path`` side by side, so two modules called ``fixtures`` means whichever
path was inserted last silently wins -- which it did, and every Stage 4 test
failed with a missing attribute from the wrong module. The same defect once
shadowed tools/kb/validate.py. Distinct names are the fix; import order is not.

Used by the offline tests and by the live acceptance, so that what the tests
exercise and what the game loads are produced by the same code. A fixture
builder that drifted from the real layout would let the tests pass against a
tree the framework never actually sees.

THE NEGATIVE FIXTURES ARE THE POINT
-----------------------------------
A discovery layer is easy to write so that it works on correct input. What
decides whether it is trustworthy is what it does with a duplicate id, a cycle,
a conflict and a manifest that is not JSON -- so those are first-class fixtures
here, not test-local improvisations.
"""
import json
import os
import shutil

MANIFEST_FILENAME = "mod.json"
CONTAINER_SUFFIXES = (".pak", ".utoc", ".ucas")

# What a mod's Code/ module looks like. It returns DATA, not ItemDefinitions,
# and it does not state its own mod_id: the execution layer takes that from the
# manifest. A mod that could name its own namespace in code could register rows
# in another mod's namespace, and the manifest's authority over identity would
# be advisory rather than real.
ITEMS_MODULE_TEMPLATE = '''"""Mod code for %(mod_id)s.

Item declarations are returned as plain DATA and this module never names a
namespace: the framework supplies the mod_id from the manifest, so this file
cannot claim another mod's. That is Stage 4's rule and it still holds.

Stage 4.5 adds two things, both read by the reference host BEFORE initialize()
runs, so capability negotiation happens before the mod initialises anything:

    REQUIRED_CAPABILITIES  absent means this mod does not load
    OPTIONAL_CAPABILITIES  absent means this mod adapts

The C# equivalent is an attribute on the mod class, read by reflection before
the class is instantiated -- the same ordering, so mods written against this
shape do not need rewriting when the host becomes CoreCLR.
"""

FRAMEWORK_API = "^0.5.0"
REQUIRED_CAPABILITIES = ("core.log", "core.events", "core.settings",
                         "core.items")
OPTIONAL_CAPABILITIES = ("core.input_registry", "core.services",
                         "core.console")


def item_definitions():
    return [
        {
            "local_id": %(local_id)r,
            "display_name": %(display_name)r,
            "short_name": %(short_name)r,
            "description": %(description)r,
            "weight": %(weight)r,
            "width": 1,
            "height": 1,
            "mesh": %(mesh)r,
            "icon": %(icon)r,
        },
    ]


def initialize(ctx):
    """Everything this mod acquires becomes owned by its ModId."""
    ctx.log.info("initialising", local_id=%(local_id)r)
    ctx.settings.declare([
        {"key": "enabled", "type": "bool", "default": True,
         "description": "whether this fixture is active"},
        {"key": "scale", "type": "float", "default": 1.0,
         "description": "a numeric setting, to exercise typing"},
    ])
    ctx.events.declare("%(mod_id)s:ready", "raised once initialise completes")
    ctx.events.subscribe("platform:mod_loaded",
                         lambda payload: ctx.log.debug(
                             "saw a mod load", other=payload.get("mod_id")))
    if ctx.grant.has("core.input_registry"):
        ctx.input.register("%(mod_id)s:toggle", "Toggle %(mod_id)s", "F5")
    if ctx.grant.has("core.services"):
        ctx.services.publish("%(mod_id)s:info", "1.0.0", {
            "local_id": lambda: %(local_id)r,
            "scale": lambda: ctx.settings.get("scale"),
        })
    ctx.events.publish("%(mod_id)s:ready", {"mod_id": ctx.mod_id})
'''


def write_manifest(root, body):
    os.makedirs(root, exist_ok=True)
    path = os.path.join(root, MANIFEST_FILENAME)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(body, handle, indent=2)
        handle.write("\n")
    return path


def write_raw_manifest(root, text):
    """For fixtures whose whole point is that the file is not valid JSON."""
    os.makedirs(root, exist_ok=True)
    path = os.path.join(root, MANIFEST_FILENAME)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def manifest_body(mod_id, *, name=None, version="1.0.0", framework_api="^0.4.0",
                  manifest_version=1, dependencies=None, optional_dependencies=None,
                  conflicts=None, content=None, code=None):
    body = {
        "manifest_version": manifest_version,
        "mod_id": mod_id,
        "name": name or ("%s display name" % mod_id),
        "version": version,
        "framework_api": framework_api,
    }
    if dependencies is not None:
        body["dependencies"] = dependencies
    if optional_dependencies is not None:
        body["optional_dependencies"] = optional_dependencies
    if conflicts is not None:
        body["conflicts"] = conflicts
    if content is not None:
        body["content"] = content
    if code is not None:
        body["code"] = code
    return body


def touch_container(root, container):
    """Create placeholder container files, for tests that only need existence."""
    content_dir = os.path.join(root, "Content")
    os.makedirs(content_dir, exist_ok=True)
    made = []
    for suffix in CONTAINER_SUFFIXES:
        path = os.path.join(content_dir, container + suffix)
        with open(path, "wb") as handle:
            handle.write(b"placeholder")
        made.append(path)
    return made


def copy_container(root, source_dir, container):
    """Copy a REAL Stage 3 container into the mod's Content directory."""
    content_dir = os.path.join(root, "Content")
    os.makedirs(content_dir, exist_ok=True)
    copied = []
    for suffix in CONTAINER_SUFFIXES:
        source = os.path.join(source_dir, container + suffix)
        if not os.path.isfile(source):
            raise IOError("no %s to stage into the fixture" % source)
        target = os.path.join(content_dir, container + suffix)
        shutil.copyfile(source, target)
        copied.append(target)
    return copied


def write_items_module(root, mod_id, *, local_id, mesh, icon, weight=0.25,
                       filename="items.py"):
    code_dir = os.path.join(root, "Code")
    os.makedirs(code_dir, exist_ok=True)
    path = os.path.join(code_dir, filename)
    text = ITEMS_MODULE_TEMPLATE % {
        "mod_id": mod_id, "local_id": local_id,
        "display_name": "%s %s" % (mod_id, local_id),
        "short_name": local_id[:8],
        "description": "A Stage 4 fixture item from %s." % mod_id,
        "weight": weight, "mesh": mesh, "icon": icon,
    }
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def build_mod(root, folder, mod_id, **kwargs):
    """One well-formed mod folder. Returns its path.

    ``folder`` is deliberately a separate argument from ``mod_id`` so callers
    can make them differ -- which is how the "folder name is not identity"
    property gets tested rather than assumed.
    """
    path = os.path.join(root, folder)
    os.makedirs(path, exist_ok=True)
    write_manifest(path, manifest_body(mod_id, **kwargs))
    return path


# --------------------------------------------------------------------------
# Negative fixtures: one function per failure class Stage 4 must detect.
# --------------------------------------------------------------------------

def negative_duplicate_mod_id(root):
    """Two folders, one identity. Neither may be chosen."""
    build_mod(root, "FirstCopy", "dupemod", version="1.0.0")
    build_mod(root, "SecondCopy", "dupemod", version="2.0.0")
    return ["dupemod"]


def negative_missing_dependency(root):
    build_mod(root, "NeedsGhost", "needsghost",
              dependencies=[{"mod_id": "ghostmod", "version": "^1.0.0"}])
    return ["needsghost"]


def negative_incompatible_version(root):
    build_mod(root, "Provider", "provider", version="1.0.0")
    build_mod(root, "Consumer", "consumer",
              dependencies=[{"mod_id": "provider", "version": "^2.0.0"}])
    return ["consumer"]


def negative_dependency_cycle(root):
    build_mod(root, "CycleA", "cyclea",
              dependencies=[{"mod_id": "cycleb", "version": "^1.0.0"}])
    build_mod(root, "CycleB", "cycleb",
              dependencies=[{"mod_id": "cyclec", "version": "^1.0.0"}])
    build_mod(root, "CycleC", "cyclec",
              dependencies=[{"mod_id": "cyclea", "version": "^1.0.0"}])
    return ["cyclea", "cycleb", "cyclec"]


def negative_explicit_conflict(root):
    build_mod(root, "Fighter", "fighter",
              conflicts=[{"mod_id": "rival"}])
    build_mod(root, "Rival", "rival")
    return ["fighter", "rival"]


def negative_malformed_manifest(root):
    path = os.path.join(root, "BrokenJson")
    os.makedirs(path, exist_ok=True)
    write_raw_manifest(path, '{"manifest_version": 1, "mod_id": "broken",\n')
    return [path]


def negative_unsupported_manifest_version(root):
    build_mod(root, "FromTheFuture", "futuremod", manifest_version=99)
    return ["futuremod"]


def negative_unsupported_framework_api(root):
    build_mod(root, "NeedsNewer", "needsnewer", framework_api="^9.0.0")
    return ["needsnewer"]


def negative_missing_artifact(root):
    build_mod(root, "ClaimsContent", "claimscontent",
              content=["Mod_claimscontent_P"])
    return ["claimscontent"]


def negative_invalid_mod_id(root):
    build_mod(root, "ShoutyId", "NotLowercase")
    return ["NotLowercase"]


ALL_NEGATIVE = (
    negative_duplicate_mod_id,
    negative_missing_dependency,
    negative_incompatible_version,
    negative_dependency_cycle,
    negative_explicit_conflict,
    negative_malformed_manifest,
    negative_unsupported_manifest_version,
    negative_unsupported_framework_api,
    negative_missing_artifact,
    negative_invalid_mod_id,
)
