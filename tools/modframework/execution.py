#!/usr/bin/env python3
"""Turning a resolved load plan into things to do. Still no game in this file.

WHY THIS IS SEPARATE FROM resolve.py
------------------------------------
The plan answers "what loads, in what order". This answers "and therefore which
containers get staged and which code modules get asked for their declarations".
Keeping them apart means the trustworthy part -- the graph -- can be reasoned
about without anyone wondering whether reading it had side effects. Nothing here
mounts, registers, or talks to MISERY; the live layer does that, and it takes
its orders from here.

THE ONE RULE THAT MATTERS MOST
------------------------------
A mod's code declares items WITHOUT naming a namespace. ``mod_id`` is taken from
the manifest and attached here. If a declaration could carry its own mod_id, a
mod could register rows in another mod's namespace -- and every guarantee Stage
2 and Stage 3 make about namespacing would be advisory rather than enforced. So
a declaration containing ``mod_id`` is refused rather than ignored: silently
dropping it would leave an author believing it had been honoured.

LOADING MOD CODE IS EXECUTING MOD CODE
--------------------------------------
Importing a mod's module runs it. That is inherent -- a mod is code the user
chose to install -- but it means the ORDER matters and the failure mode matters.
Modules are imported in load-plan order, each under a name derived from its
mod_id so two mods shipping ``items.py`` cannot collide in ``sys.modules``, and a
module that raises takes its own mod out of the run rather than the whole run.
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import diagnostics as D                                            # noqa: E402

_PLATFORM = os.path.join(os.path.dirname(HERE), "modplatform")
if _PLATFORM not in sys.path:
    sys.path.insert(0, _PLATFORM)
import modid                                                       # noqa: E402

# The function a mod's code module exposes. One convention, checked by name, so
# a mod that misspells it is told rather than silently contributing nothing.
DECLARATION_ENTRY_POINT = "item_definitions"

# The canonical separator, not a copy of it.
ROW_NAME_SEPARATOR = modid.SEPARATOR

# Keys a declaration may carry. `mod_id` is deliberately absent: see above.
DECLARATION_FIELDS = frozenset({
    "local_id", "display_name", "short_name", "description",
    "weight", "width", "height", "mesh", "icon",
})
REQUIRED_DECLARATION_FIELDS = ("local_id", "display_name", "short_name",
                               "description", "weight", "mesh", "icon")


def staging_profile(plan, stem_source=None):
    """Which containers to stage, in load order.

    Returns the profile shape ``runner/containers.apply_profile`` consumes, so
    the plan drives staging instead of a hand-maintained list. ``expect`` is the
    exact allow-list of what should be present afterwards.
    """
    stage, expect = [], []
    for mod_id in plan.load_order:
        manifest = plan.manifests[mod_id]
        for container in manifest.content:
            source = (stem_source(manifest, container) if stem_source
                      else manifest.content_dir())
            stage.append({"src": source, "stem": container})
            expect.append(container)
    return {"stage": stage, "expect": expect}


def containers_for(plan, mod_id):
    """The container stems one mod owns -- what a selective unload must remove."""
    manifest = plan.manifests.get(mod_id)
    return list(manifest.content) if manifest else []


def _import_module(mod_id, path, index):
    """Import one mod code file under a name that cannot collide.

    Two mods both shipping ``Code/items.py`` would otherwise fight over
    ``sys.modules['items']`` and the second import would return the first mod's
    module -- which is the same shadowing defect that once made ``fixtures``
    resolve to the wrong file.
    """
    module_name = "modframework_mod_%s_%d" % (mod_id, index)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError("%s is not importable as a module" % path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def _validate_declaration(mod_id, raw, where, out):
    if not isinstance(raw, dict):
        out.append(D.Diagnostic(D.MALFORMED_MANIFEST, mod_id,
                                "%s must be a dict, got %s"
                                % (where, type(raw).__name__)))
        return None
    if "mod_id" in raw:
        out.append(D.Diagnostic(
            D.MALFORMED_MANIFEST, mod_id,
            "%s names a mod_id. Item namespaces come from the manifest, never "
            "from mod code -- a declaration that could name its own namespace "
            "could claim another mod's." % where))
        return None
    unknown = sorted(set(raw) - DECLARATION_FIELDS)
    if unknown:
        out.append(D.Diagnostic(D.MALFORMED_MANIFEST, mod_id,
                                "%s has unknown key(s) %s" % (where, unknown)))
        return None
    missing = [field for field in REQUIRED_DECLARATION_FIELDS if field not in raw]
    if missing:
        out.append(D.Diagnostic(D.MALFORMED_MANIFEST, mod_id,
                                "%s is missing %s" % (where, missing)))
        return None
    # The row name Stage 2 will derive is "<mod_id>__<local_id>". An unchecked
    # local_id could therefore publish a name Stage 2 refuses -- or, if it
    # contained the separator, a name that decomposes to a DIFFERENT mod. The
    # rule is the mod_id rule, because both halves of the row name are subject
    # to the same FName constraints.
    # check_local_id, not check(): a LOCAL id is already namespaced by the mod
    # that declared it, so the reserved-name rule does not apply to it. An item
    # called "core" inside alphamod impersonates nothing -- its row name is
    # alphamod__core.
    try:
        modid.check_local_id(raw.get("local_id"))
    except modid.ModIdError as error:
        out.append(D.Diagnostic(
            D.MALFORMED_MANIFEST, mod_id,
            "%s has an unusable local_id: %s" % (where, error.detail)))
        return None
    declaration = dict(raw)
    # The authoritative namespace, attached HERE, from the manifest.
    declaration["mod_id"] = mod_id
    return declaration


def item_declarations(plan):
    """Ask every mod in the plan for its item declarations, in load order.

    Returns ``(declarations, diagnostics)``. Each declaration carries the
    ``mod_id`` this layer attached, so a caller building an ItemDefinition
    cannot accidentally take the namespace from the mod's own data.

    A mod whose code raises is reported and skipped; the rest of the plan still
    runs, because one broken mod taking down every other mod in the user's
    install is exactly the fragility a mod loader must not have.
    """
    out = []
    per_mod = {}
    poisoned = set()
    for index, mod_id in enumerate(plan.load_order):
        manifest = plan.manifests[mod_id]
        per_mod.setdefault(mod_id, [])
        for path in manifest.code:
            full = os.path.join(manifest.code_dir(), path)
            try:
                module = _import_module(mod_id, full, index)
            except BaseException as error:                         # noqa: BLE001
                out.append(D.Diagnostic(
                    D.MISSING_ARTIFACT, mod_id,
                    "code artifact %r could not be imported: %s: %s"
                    % (path, type(error).__name__, error)))
                poisoned.add(mod_id)
                continue
            entry = getattr(module, DECLARATION_ENTRY_POINT, None)
            if entry is None:
                # Not an error: a mod may ship code that does something other
                # than declare items. Saying nothing about it would hide a
                # misspelled entry point, so it is recorded, not fatal.
                out.append(D.Diagnostic(
                    D.OPTIONAL_DEPENDENCY_ABSENT, mod_id,
                    "code artifact %r defines no %s(); it contributes no items"
                    % (path, DECLARATION_ENTRY_POINT)))
                continue
            try:
                produced = entry()
            except BaseException as error:                         # noqa: BLE001
                out.append(D.Diagnostic(
                    D.MISSING_ARTIFACT, mod_id,
                    "%s() in %r raised %s: %s"
                    % (DECLARATION_ENTRY_POINT, path, type(error).__name__, error)))
                poisoned.add(mod_id)
                continue
            if not isinstance(produced, (list, tuple)):
                out.append(D.Diagnostic(
                    D.MALFORMED_MANIFEST, mod_id,
                    "%s() in %r returned %s, not a list"
                    % (DECLARATION_ENTRY_POINT, path, type(produced).__name__)))
                poisoned.add(mod_id)
                continue
            for position, raw in enumerate(produced):
                where = "%s:%s()[%d]" % (path, DECLARATION_ENTRY_POINT, position)
                declaration = _validate_declaration(mod_id, raw, where, out)
                if declaration is None:
                    poisoned.add(mod_id)
                else:
                    per_mod[mod_id].append(declaration)

    # A mod is accepted whole or not at all. Keeping the declarations that
    # happened to parse from a mod that also emitted an illegal one is exactly
    # the "partially accepted mod reaching the live execution plan" this stage
    # forbids -- and it is worse than it sounds, because the surviving items
    # would come from a mod whose author has already been shown to be producing
    # declarations the framework cannot accept.
    declarations = []
    for mod_id in plan.load_order:
        if mod_id in poisoned:
            out.append(D.Diagnostic(
                D.MALFORMED_MANIFEST, mod_id,
                "contributed at least one unusable item declaration, so NONE of "
                "its %d declaration(s) are used. A mod is accepted whole or not "
                "at all." % len(per_mod.get(mod_id, []))))
            continue
        declarations.extend(per_mod.get(mod_id, []))
    return declarations, out


def expected_row_names(declarations):
    """The Stage 2 row name each declaration will produce.

    Derived the same way Stage 2 derives it, so the acceptance can assert what
    it expects to see in the game before anything is registered.
    """
    return ["%s__%s" % (d["mod_id"], d["local_id"]) for d in declarations]
