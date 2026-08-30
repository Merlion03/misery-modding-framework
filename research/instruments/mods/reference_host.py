#!/usr/bin/env python3
"""The REFERENCE mod host: drives the platform from a Stage 4 load plan.

WHAT THIS IS FOR
----------------
Stage 4.5 defines the contracts. Something has to exercise them end to end
before anyone believes they are sufficient, and that something must not be the
production hosting path -- the owner was explicit that CoreCLR hosting belongs
with Stage 5. So this is a deliberately simple host that loads a mod's code the
way this repository already can (a Python module), negotiates its capabilities,
and drives it through the platform's real lifecycle.

THIS IS THE FILE STAGE 5 REPLACES. Nothing else. The platform, the ownership
model, the errors, the logging and the C# contracts all stay; the only thing
that changes is that ``_load_module`` becomes "start CoreCLR, create a
collectible AssemblyLoadContext, instantiate the mod's IMod". Keeping that
boundary in one file is what makes the closing condition checkable rather than
hopeful.

HOW A MOD DECLARES WHAT IT NEEDS
--------------------------------
Not in the manifest. Stage 4's schema is closed and its rule was "no field
without a Stage 4 consumer" -- capabilities have a Stage 4.5 consumer, not a
Stage 4 one, and bolting them into a v1 manifest would make older readers reject
files they should accept. So a mod declares them in its CODE:

    REQUIRED_CAPABILITIES = ("core.log", "core.events")
    OPTIONAL_CAPABILITIES = ("core.input_registry",)
    def initialize(ctx): ...

They are read from the module AFTER import but BEFORE ``initialize`` runs, so
negotiation still happens before any of the mod's own initialisation. That
ordering survives the move to C#, where the equivalent is an attribute on the
mod class read by reflection before the class is instantiated.
"""
import importlib.util
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.join(REPO, "tools", "modplatform"),
           os.path.join(REPO, "tools", "modframework")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import capabilities as CAP                                         # noqa: E402
import errors as E                                                 # noqa: E402
import host as HOST                                                # noqa: E402

REQUIRED_ATTR = "REQUIRED_CAPABILITIES"
OPTIONAL_ATTR = "OPTIONAL_CAPABILITIES"
API_ATTR = "FRAMEWORK_API"
ENTRY_ATTR = "initialize"
ITEMS_ATTR = "item_definitions"


class LoadedModule(object):
    __slots__ = ("mod_id", "module", "path", "required", "optional", "api")

    def __init__(self, mod_id, module, path, required, optional, api):
        self.mod_id = mod_id
        self.module = module
        self.path = path
        self.required = required
        self.optional = optional
        self.api = api


def _load_module(mod_id, path, index):
    """Import one mod's code under a name that cannot collide.

    THE STAGE 5 SEAM. Everything above and below this function is contract;
    this is the only part that knows the mods are Python today.
    """
    module_name = "misery_refhost_%s_%d" % (mod_id, index)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise E.PlatformError(E.SUB_LIFECYCLE, E.E_LOAD_FAILED,
                              "%s is not importable" % path, mod_id)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException as error:                                 # noqa: BLE001
        sys.modules.pop(module_name, None)
        raise E.PlatformError(E.SUB_LIFECYCLE, E.E_LOAD_FAILED,
                              "importing %s raised %s: %s"
                              % (os.path.basename(path), type(error).__name__,
                                 error), mod_id) from error
    return module


def _tuple_attr(module, name, mod_id):
    value = getattr(module, name, ())
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise E.PlatformError(E.SUB_LIFECYCLE, E.E_LOAD_FAILED,
                              "%s must be a list or tuple of capability names"
                              % name, mod_id)
    for item in value:
        if not isinstance(item, str):
            raise E.PlatformError(E.SUB_LIFECYCLE, E.E_LOAD_FAILED,
                                  "%s contains a non-string entry" % name, mod_id)
    return tuple(value)


def discover_modules(plan):
    """Import every planned mod's code and read its declarations.

    Importing happens for all mods BEFORE any is loaded into the platform, so a
    module that will not even import is known before the first mod's
    ``initialize`` has run and started acquiring things.
    """
    modules, problems = [], []
    for index, mod_id in enumerate(plan.load_order):
        manifest = plan.manifests[mod_id]
        for relative in manifest.code:
            path = os.path.join(manifest.code_dir(), relative)
            try:
                module = _load_module(mod_id, path, index)
                modules.append(LoadedModule(
                    mod_id, module, path,
                    _tuple_attr(module, REQUIRED_ATTR, mod_id),
                    _tuple_attr(module, OPTIONAL_ATTR, mod_id),
                    getattr(module, API_ATTR, "^%s" % CAP.API_VERSION)))
            except E.PlatformError as error:
                problems.append(error)
    return modules, problems


def load_all(platform, plan, modules):
    """Load every module into the platform, in plan order.

    One mod failing does not stop the others: that is the same rule Stage 4
    applied to discovery, and for the same reason -- a user's whole install must
    not go down because one author shipped a bug.
    """
    outcomes = []
    for loaded in modules:
        entry_point = getattr(loaded.module, ENTRY_ATTR, None)
        try:
            context = platform.load(
                loaded.mod_id, entry_point,
                api_requirement=loaded.api,
                required=loaded.required, optional=loaded.optional)
            outcomes.append({"mod_id": loaded.mod_id, "ok": True,
                             "granted": sorted(context.grant.granted)})
        except E.PlatformError as error:
            outcomes.append({"mod_id": loaded.mod_id, "ok": False,
                             "error": error.as_dict()})
    return outcomes


def register_declared_items(platform, modules):
    """Register each mod's declared items through its OWN context.

    Through the context, so every item is owned by the mod that declared it and
    is released when that mod unloads. Registering them centrally would work and
    would silently break the ownership guarantee.
    """
    outcomes = []
    for loaded in modules:
        entry = platform.record(loaded.mod_id)
        if entry.state != HOST.LOADED or entry.context is None:
            continue
        producer = getattr(loaded.module, ITEMS_ATTR, None)
        if producer is None:
            continue
        try:
            declarations = producer()
        except BaseException as error:                             # noqa: BLE001
            outcomes.append({"mod_id": loaded.mod_id, "ok": False,
                             "error": "%s() raised %s: %s"
                                      % (ITEMS_ATTR, type(error).__name__, error)})
            continue
        rows = []
        try:
            for declaration in declarations:
                rows.append(entry.context.items.register(declaration))
        except E.PlatformError as error:
            outcomes.append({"mod_id": loaded.mod_id, "ok": False,
                             "rows": rows, "error": error.as_dict()})
            continue
        outcomes.append({"mod_id": loaded.mod_id, "ok": True, "rows": rows})
    return outcomes


def is_reclaimable(platform, mod_id):
    """Could a managed host now collect this mod's assembly context?

    Stage 5 will gate ``AssemblyLoadContext.Unload()`` on exactly this question,
    and it is asked here so the answer is a platform property rather than
    something the CoreCLR host has to reconstruct. True requires that the mod is
    unloaded, that every resource it owned was released, and that no live token
    still refers to its code.
    """
    entry = platform.record(mod_id)
    if entry.state not in (HOST.UNLOADED, HOST.FAILED):
        return {"reclaimable": False, "reason": "state is %s" % entry.state}
    owner = entry.owner
    if owner is None:
        return {"reclaimable": True, "reason": "no owner was ever created"}
    unreleased = [r.as_dict() for r in owner.resources() if not r.released]
    live = [t.key for t in owner.tokens() if t.live]
    return {"reclaimable": not unreleased and not live and owner.disposed,
            "unreleased": unreleased, "live_tokens": live,
            "disposed": owner.disposed}
