#!/usr/bin/env python3
"""Inter-mod services: one mod offering something another can call.

THE HAZARD THIS SUBSYSTEM IS BUILT AROUND
-----------------------------------------
A mod publishes a service. Another mod takes it and keeps it in a field. The
provider is then unloaded. If the consumer's reference still works, the whole
"unload releases everything" guarantee is a fiction -- the provider's code is
reachable, and reachable through a strong reference held by a mod the framework
has no reason to touch.

So a consumer NEVER receives the provider's object. It receives a
``ServiceHandle``: a thin front whose every call goes through the provider's
token and therefore checks liveness at call time. When the provider unloads, the
handle does not become dangerous -- it becomes a structured error, immediately,
retroactively, for every consumer that ever took one.

VERSIONING
----------
A service is published with a version and consumed with a requirement, using the
same rule as manifests. A consumer asking for a version the provider does not
satisfy is refused at bind time rather than at call time, because a mod that
discovers the mismatch halfway through a frame has no good options.

WHAT A SERVICE IS NOT
---------------------
Not a gameplay API, and not a way to reach the engine. It is a named, versioned
set of callables one mod chooses to expose to others. Everything about the game
still goes through the framework's own semantic APIs.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import errors as E                                                 # noqa: E402
import modid as _modid                                             # noqa: E402
import semverlib as semver                                         # noqa: E402

NAME_SEPARATOR = ":"
MAX_METHODS = 64


def check_service_name(name, publishing_mod=None):
    """``<mod_id>:<name>`` -- a service lives in its publisher's namespace."""
    if not isinstance(name, str) or NAME_SEPARATOR not in name:
        raise E.PlatformError(E.SUB_SERVICES, E.E_INVALID_ARGUMENT,
                              "service name %r must be '<mod_id>%s<name>'"
                              % (name, NAME_SEPARATOR), publishing_mod)
    owner, _, local = name.partition(NAME_SEPARATOR)
    if not _modid.is_valid(owner) or not _modid.PATTERN.match(local or ""):
        raise E.PlatformError(E.SUB_SERVICES, E.E_INVALID_ARGUMENT,
                              "service name %r is not '<mod_id>%s<name>' with "
                              "both parts matching %s"
                              % (name, NAME_SEPARATOR, _modid.PATTERN_TEXT),
                              publishing_mod)
    if publishing_mod is not None and owner != publishing_mod:
        raise E.PlatformError(
            E.SUB_SERVICES, E.E_INVALID_ARGUMENT,
            "%r may not publish %r: a service belongs to its publisher's "
            "namespace, so a mod cannot offer one in another mod's name"
            % (publishing_mod, name), publishing_mod)
    return name


class ServiceHandle(object):
    """What a CONSUMER holds. Never the provider's object.

    Every call re-checks the provider's token, so the moment the provider is
    unloaded every outstanding handle stops working -- including ones a consumer
    stored in a field years ago in mod-author time.
    """

    __slots__ = ("name", "version", "provider_id", "consumer_id", "_tokens")

    def __init__(self, name, version, provider_id, consumer_id, tokens):
        self.name = name
        self.version = version
        self.provider_id = provider_id
        self.consumer_id = consumer_id
        self._tokens = tokens

    @property
    def available(self):
        """False the instant the provider is unloaded."""
        return any(token.live for token in self._tokens.values())

    def methods(self):
        return sorted(name for name, token in self._tokens.items() if token.live)

    def call(self, method, *args, **kwargs):
        token = self._tokens.get(method)
        if token is None:
            raise E.PlatformError(E.SUB_SERVICES, E.E_NOT_FOUND,
                                  "service %r has no method %r"
                                  % (self.name, method), self.consumer_id)
        if not token.live:
            raise E.PlatformError(
                E.SUB_SERVICES, E.E_NOT_FOUND,
                "service %r is no longer available: its provider %r has been "
                "unloaded" % (self.name, self.provider_id), self.consumer_id)
        called, result = token.invoke(*args, **kwargs)
        if not called:
            raise E.PlatformError(E.SUB_SERVICES, E.E_NOT_FOUND,
                                  "service %r became unavailable during the call"
                                  % self.name, self.consumer_id)
        return result

    def as_dict(self):
        return {"name": self.name, "version": str(self.version),
                "provider": self.provider_id, "consumer": self.consumer_id,
                "available": self.available, "methods": self.methods()}


class ServiceRegistry(object):
    def __init__(self, logger=None):
        self._published = {}     # name -> {"version", "provider", "tokens"}
        self._bindings = []      # every handle handed out, for the console
        self._logger = logger

    def publish(self, owner, name, version, methods):
        """Publish a service. Owned, so unloading revokes it for everyone."""
        check_service_name(name, owner.mod_id)
        if name in self._published:
            raise E.PlatformError(E.SUB_SERVICES, E.E_ALREADY_EXISTS,
                                  "service %r is already published by %r"
                                  % (name, self._published[name]["provider"]),
                                  owner.mod_id)
        if not isinstance(methods, dict) or not methods:
            raise E.PlatformError(E.SUB_SERVICES, E.E_INVALID_ARGUMENT,
                                  "a service must expose at least one method",
                                  owner.mod_id)
        if len(methods) > MAX_METHODS:
            raise E.PlatformError(E.SUB_SERVICES, E.E_LIMIT_EXCEEDED,
                                  "a service may expose at most %d methods"
                                  % MAX_METHODS, owner.mod_id)
        parsed = semver.Version(version) if isinstance(version, str) else version
        tokens = {}
        for method_name in sorted(methods):
            if not _modid.PATTERN.match(method_name):
                raise E.PlatformError(E.SUB_SERVICES, E.E_INVALID_ARGUMENT,
                                      "method name %r must match %s"
                                      % (method_name, _modid.PATTERN_TEXT),
                                      owner.mod_id)
            tokens[method_name] = owner.token(
                methods[method_name], "service_method",
                "%s.%s" % (name, method_name))
        self._published[name] = {"version": parsed, "provider": owner.mod_id,
                                 "tokens": tokens}

        def release():
            for token in tokens.values():
                token.revoke()
            self._published.pop(name, None)
        return owner.own("service", name, release, str(parsed))

    def bind(self, owner, name, requirement=">=0.0.0"):
        """Take a handle on a published service.

        The handle is owned by the CONSUMER too: a consumer that unloads stops
        holding a reference into the provider, which matters when the provider
        outlives it.
        """
        entry = self._published.get(name)
        if entry is None:
            raise E.PlatformError(E.SUB_SERVICES, E.E_NOT_FOUND,
                                  "no service %r is published" % name,
                                  owner.mod_id)
        want = (semver.Requirement(requirement) if isinstance(requirement, str)
                else requirement)
        if not want.matches(entry["version"]):
            raise E.PlatformError(
                E.SUB_SERVICES, E.E_INVALID_ARGUMENT,
                "service %r is version %s, which the requirement %s excludes. "
                "Refused now rather than at call time, because a mod that finds "
                "out mid-frame has no good options."
                % (name, entry["version"], want), owner.mod_id)
        handle = ServiceHandle(name, entry["version"], entry["provider"],
                               owner.mod_id, entry["tokens"])
        self._bindings.append(handle)

        def release():
            try:
                self._bindings.remove(handle)
            except ValueError:
                pass
        owner.own("service_binding", name, release, str(entry["version"]))
        return handle

    def published(self):
        return {name: {"version": str(entry["version"]),
                       "provider": entry["provider"],
                       "methods": sorted(entry["tokens"])}
                for name, entry in sorted(self._published.items())}

    def summary(self):
        return {"published": self.published(),
                "bindings": [h.as_dict() for h in self._bindings]}
