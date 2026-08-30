#!/usr/bin/env python3
"""API version and capability negotiation.

THE PROBLEM VERSION NUMBERS ALONE DO NOT SOLVE
----------------------------------------------
A single API version forces every question into one number. "Does this build
have the input registry?" becomes "is the version at least 0.6?", which stops
being true the moment a subsystem ships on a different schedule, gets removed,
or is present but disabled on a particular build. Mods then start sniffing
versions, and the version number becomes load-bearing in ways nobody intended --
after which it can never be changed.

So there are two things, and they answer different questions:

  API VERSION      the shape of the ABI and of the managed surface. MAJOR is the
                   promise: a bump says mods must be rebuilt. Negotiated once.

  CAPABILITIES     named, INDEPENDENTLY versioned features. A mod asks for the
                   ones it needs by name, at load, and is either granted them or
                   refused with a structured error naming exactly what is
                   missing. It never asks "what version are you".

That split is what lets Stage 5 add managed hosting, and a later stage add
whatever gameplay systems get researched, without either touching the API
version or breaking a mod that never asked for them.

REQUIRED VERSUS OPTIONAL
------------------------
A mod names capabilities it REQUIRES -- absent means it does not load, because
running it would be running something the author never tested -- and ones it
OPTIONALLY uses, which it then has to check. Optional is what makes a mod work
across builds that differ; required is what stops it half-working on one.

WHAT IS DECLARED HERE
---------------------
Only capabilities this stage actually implements. Nothing aspirational: a
capability that is advertised but not implemented is worse than a missing one,
because a mod will branch on it and take the path that does not work.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import errors as E                                                 # noqa: E402
import modid as _modid                                             # noqa: E402
import semverlib as semver                                         # noqa: E402

# The public API version. MAJOR is the compatibility promise.
API_VERSION = semver.Version("0.5.0")

# Capability names. Namespaced under "core." so a future non-core family (say a
# researched gameplay surface) cannot collide with these.
CAP_LOG = "core.log"
CAP_EVENTS = "core.events"
CAP_SETTINGS = "core.settings"
CAP_INPUT_REGISTRY = "core.input_registry"
CAP_SERVICES = "core.services"
CAP_ITEMS = "core.items"
CAP_CONSOLE = "core.console"
CAP_DIAGNOSTICS = "core.diagnostics"

# name -> (version, what it actually gives you)
#
# core.input_registry is versioned 0.1.0 deliberately, and its description says
# what it is: mods may DECLARE input actions and the framework tracks and owns
# them, but nothing in this stage delivers engine input to them, because the
# engine's input path has not been researched. A mod that needs real key events
# must treat this capability as insufficient rather than assume it.
CAPABILITIES = {
    CAP_LOG: (semver.Version("1.0.0"),
              "per-mod structured logging with rate limiting"),
    CAP_EVENTS: (semver.Version("1.0.0"),
                 "declare, subscribe to and publish namespaced events; "
                 "platform lifecycle events only, no gameplay events"),
    CAP_SETTINGS: (semver.Version("1.0.0"),
                   "declared, typed, persisted per-mod settings"),
    CAP_INPUT_REGISTRY: (semver.Version("0.1.0"),
                         "DECLARATION and ownership of named input actions. "
                         "This stage does not deliver engine input to them: the "
                         "engine input path is unresearched, so a mod needing "
                         "real key events must not rely on this"),
    CAP_SERVICES: (semver.Version("1.0.0"),
                   "publish and consume versioned inter-mod services"),
    CAP_ITEMS: (semver.Version("1.0.0"),
                "register item definitions under the mod's own namespace"),
    CAP_CONSOLE: (semver.Version("1.0.0"),
                  "contribute commands to the developer console"),
    CAP_DIAGNOSTICS: (semver.Version("1.0.0"),
                      "read the platform's own diagnostic state"),
}


class Grant(object):
    """What a mod actually got. Checked, not assumed."""

    __slots__ = ("mod_id", "api_version", "granted", "declined")

    def __init__(self, mod_id, api_version, granted, declined):
        self.mod_id = mod_id
        self.api_version = api_version
        self.granted = granted          # {name: Version}
        self.declined = declined        # {name: reason}

    def has(self, name):
        return name in self.granted

    def require(self, name):
        """Use a capability, or fail with a structured error naming it."""
        if name not in self.granted:
            raise E.PlatformError(
                E.SUB_CAPABILITIES, E.E_CAPABILITY_NOT_GRANTED,
                "%r was not granted to %r: %s"
                % (name, self.mod_id,
                   self.declined.get(name, "it was never requested")),
                self.mod_id)
        return self.granted[name]

    def as_dict(self):
        return {"mod_id": self.mod_id, "api_version": str(self.api_version),
                "granted": {k: str(v) for k, v in sorted(self.granted.items())},
                "declined": dict(sorted(self.declined.items()))}


def describe():
    """Everything on offer. What a `capabilities` console command prints."""
    return {"api_version": str(API_VERSION),
            "capabilities": {name: {"version": str(version), "detail": detail}
                             for name, (version, detail)
                             in sorted(CAPABILITIES.items())}}


def negotiate(mod_id, api_requirement, required=(), optional=()):
    """Decide what *mod_id* gets. Raises if it cannot run at all.

    Refusing at load is the point. A mod that discovers a required capability is
    missing only when it first calls into it has already run its initialisation,
    possibly registered things, and now has to be torn back down -- from inside
    its own code path.
    """
    _modid.check(mod_id)
    want_api = (semver.Requirement(api_requirement)
                if isinstance(api_requirement, str) else api_requirement)
    if not want_api.matches(API_VERSION):
        raise E.PlatformError(
            E.SUB_CAPABILITIES, E.E_CAPABILITY_NOT_GRANTED,
            "the mod requires framework API %s and this framework is %s"
            % (want_api, API_VERSION), mod_id)

    granted, declined, missing = {}, {}, []
    for name in sorted(set(required)):
        entry = CAPABILITIES.get(name)
        if entry is None:
            missing.append(name)
            declined[name] = "this framework does not provide it"
        else:
            granted[name] = entry[0]
    if missing:
        raise E.PlatformError(
            E.SUB_CAPABILITIES, E.E_CAPABILITY_NOT_GRANTED,
            "required capabilities are unavailable: %s. Refused at load rather "
            "than at first use, so the mod never partly initialises."
            % ", ".join(missing), mod_id)

    for name in sorted(set(optional)):
        entry = CAPABILITIES.get(name)
        if entry is None:
            declined[name] = "this framework does not provide it"
        else:
            granted[name] = entry[0]
    return Grant(mod_id, API_VERSION, granted, declined)
