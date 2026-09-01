#!/usr/bin/env python3
"""Deterministic, mod-namespaced Unreal package paths.

THE PROBLEM THIS SOLVES
-----------------------
Two mods both ship ``radio.glb`` and ``icon.png``. If the build derived package
paths from the source filename alone, the second mod to be cooked would produce
``/Game/.../SM_radio`` again -- the same object path as the first. Inside one
container that is a duplicate; across two containers it is worse, because the
IoStore backend resolves a chunk id to whichever mounted container claims it
first, so one mod would silently answer for the other's assets.

So the ModId is part of the path, always, and the path is DERIVED rather than
authored. A mod cannot ask for a bare path and therefore cannot land on top of
another mod or on vanilla content.

    /Game/Mods/<mod_id>/<category>/<Prefix>_<name>

WHY /Game/Mods AND NOT SOMETHING SHORTER
----------------------------------------
The root has to be one nobody else uses. Vanilla content lives under
``/Game/SurvivalGameKitV2``, ``/Game/Blueprints``, ``/Game/MBPLTest`` and
friends; reserving a single ``Mods`` directory under ``/Game`` keeps every mod
asset in one subtree that is trivially recognisable in a container listing, in a
cooked reference, and in a crash log.

DETERMINISM IS THE POINT
------------------------
The same ModId and the same source name must give the same object path on every
machine and every run, or the ItemDefinition references a mod ships would stop
resolving after a rebuild. There is no hashing, no timestamp and no ordering
dependence here: the mapping is a pure function of (mod_id, category, name).
"""
import os
import re
import sys

_PLATFORM = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "modplatform")
if _PLATFORM not in sys.path:
    sys.path.insert(0, _PLATFORM)
import modid as _modid                                             # noqa: E402

ROOT = "/Game/Mods"

# Categories and the asset-name prefix Unreal convention gives each. The prefix
# is part of the derived name so that a listing reads as Unreal content rather
# than as a pile of anonymous objects.
CATEGORIES = {
    "mesh": ("Meshes", "SM"),
    "texture": ("Textures", "T"),
    "material": ("Materials", "MI"),
    # A Blueprint class the mod ships. Its generated class takes the usual `_C`
    # suffix, so the cooked object path is <package>.BP_<Name>_C.
    "blueprint": ("Blueprints", "BP"),
}

# Same rule as the runtime ItemId: lowercase, starts with a letter. FName
# comparison is case-insensitive, so allowing mixed case would let two ids that
# look different collide inside the game.
MOD_ID_PATTERN = _modid.PATTERN
# Asset names keep their authored case -- they become Unreal object names, where
# CamelCase is the convention -- but must still be a safe identifier.
ASSET_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")

MAX_MOD_ID = _modid.MAX_LENGTH
MAX_ASSET_NAME = 64

# A mod may not claim these: they are how vanilla and the framework are
# recognisable, and a mod that could take one could impersonate either.
RESERVED_MOD_IDS = _modid.RESERVED

# Roots a generated path must never fall under, checked as a belt-and-braces
# second line even though the derivation makes it structurally impossible.
FORBIDDEN_PREFIXES = ("/Script/", "/Engine/", "/Temp/",
                      "/Game/SurvivalGameKitV2/", "/Game/Blueprints/")


class NamespaceError(Exception):
    """A structured refusal. Carries a code so a build can act on it."""

    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail

    def as_dict(self):
        return {"code": self.code, "detail": self.detail}


def check_mod_id(mod_id):
    """Delegates to the canonical ModId contract.

    This function used to carry its own copy of the rule, and that copy had
    drifted: it accepted an id containing ``__``, which Stage 2 refuses because
    it makes ``<mod_id>__<local_id>`` ambiguous to decompose. The rule now lives
    in exactly one place (tools/modplatform/modid.py) and every stage asks it.

    The NamespaceError wrapper is kept because callers catch it by type; only
    the source of the answer changed, not the shape of the failure.
    """
    try:
        return _modid.check(mod_id)
    except _modid.ModIdError as error:
        code = ("reserved_mod_id" if error.code == _modid.ERR_RESERVED
                else "invalid_mod_id")
        raise NamespaceError(code, "%r: %s" % (mod_id, error.detail)) from error


def check_asset_name(name):
    if not isinstance(name, str) or not name:
        raise NamespaceError("invalid_asset_name", "must be a non-empty string")
    if len(name) > MAX_ASSET_NAME:
        raise NamespaceError("invalid_asset_name",
                             "longer than %d characters" % MAX_ASSET_NAME)
    if not ASSET_NAME_PATTERN.match(name):
        raise NamespaceError(
            "invalid_asset_name",
            "%r must match %s. Source FILENAMES may be anything; this is the Unreal "
            "object name derived from one, and it has to be a legal identifier"
            % (name, ASSET_NAME_PATTERN.pattern))
    return name


def package_dir(mod_id, category):
    check_mod_id(mod_id)
    if category not in CATEGORIES:
        raise NamespaceError("unknown_category",
                             "%r is not one of %s" % (category, sorted(CATEGORIES)))
    folder, _prefix = CATEGORIES[category]
    return "%s/%s/%s" % (ROOT, mod_id, folder)


def asset_name(category, name):
    check_asset_name(name)
    _folder, prefix = CATEGORIES[category]
    return "%s_%s" % (prefix, name)


def package_path(mod_id, category, name):
    """The full package path. A pure function of its three arguments."""
    path = "%s/%s" % (package_dir(mod_id, category), asset_name(category, name))
    for forbidden in FORBIDDEN_PREFIXES:
        if path.startswith(forbidden):
            raise NamespaceError(
                "forbidden_root",
                "%r falls under %r. The derivation makes this structurally impossible, "
                "so reaching it means the rules above changed and the check earned its "
                "keep" % (path, forbidden))
    return path


def object_path(mod_id, category, name):
    """``/Package/Path.ObjectName`` -- what a cooked reference actually holds."""
    path = package_path(mod_id, category, name)
    return "%s.%s" % (path, path.rsplit("/", 1)[-1])


def container_name(mod_id):
    """The IoStore container. ``_P`` marks it as a patch-priority mount."""
    check_mod_id(mod_id)
    return "Mod_%s_P" % mod_id


def mod_root(mod_id):
    check_mod_id(mod_id)
    return "%s/%s" % (ROOT, mod_id)


def is_mod_path(path):
    return isinstance(path, str) and path.startswith(ROOT + "/")


def owning_mod(path):
    """Which mod a generated path belongs to, or None if it is not one of ours."""
    if not is_mod_path(path):
        return None
    rest = path[len(ROOT) + 1:]
    return rest.split("/", 1)[0] or None
