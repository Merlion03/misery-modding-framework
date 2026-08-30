#!/usr/bin/env python3
"""Versions and version requirements. THE implementation, for every stage.

NAMED ``semverlib`` AND NOT ``semver``
--------------------------------------
There is a widely installed PyPI package called ``semver``. A module of that
name on ``sys.path`` would shadow it for the whole process, or be shadowed by
it, depending on path order -- the same class of defect that has already cost
this repository two debugging sessions. The name is deliberately not one
anybody else uses.

This was Stage 4's module. Stage 4.5 needs the same comparisons for service
versions and capability negotiation, so rather than let a second copy start
drifting -- which is exactly what happened to the ModId rule across three
stages -- it moved here and Stage 4 now imports it.

WHY A HAND-ROLLED VERSION TYPE
------------------------------
Dependency resolution has to answer one question -- "is the version this mod
provides acceptable to the mod that depends on it" -- and it has to answer it
the same way on every machine. Bringing in a full semver range grammar would
add operators nothing in Stage 4 consumes, and every unused operator is another
way for two implementations to disagree. So this supports four forms and
refuses everything else by name:

    ==X.Y.Z    exactly that version
    >=X.Y.Z    that version or newer
    ^X.Y.Z     that version or newer, but not the next MAJOR
    X.Y.Z      shorthand for ^X.Y.Z

``^`` is the default because it is the rule the framework's own API version
lives by: a MAJOR bump is the announcement that old mods stop working, and a
MINOR bump must not be. Making the common case the default keeps mod authors
from writing ``>=`` and accidentally opting in to a future breaking release.

COMPARISON IS NUMERIC, NOT LEXICAL
----------------------------------
"0.10.0" sorts BELOW "0.9.0" as text and ABOVE it as a version. Comparing the
tuple of integers is the whole reason this class exists rather than a string.
"""
import re

VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
REQUIREMENT_PATTERN = re.compile(r"^(==|>=|\^)?\s*(.+)$")
OPERATORS = ("==", ">=", "^")


class VersionError(ValueError):
    """A version or requirement that cannot be parsed. Never a silent default."""


class Version(object):
    """A MAJOR.MINOR.PATCH triple, compared numerically."""

    __slots__ = ("major", "minor", "patch")

    def __init__(self, text):
        if not isinstance(text, str):
            raise VersionError("version must be a string, got %r" % type(text).__name__)
        match = VERSION_PATTERN.match(text.strip())
        if not match:
            # Leading zeros are rejected on purpose: "1.02.0" and "1.2.0" would
            # compare equal numerically while looking like different versions in
            # a manifest, and a mod author would have no way to tell which one
            # the resolver used.
            raise VersionError(
                "%r is not MAJOR.MINOR.PATCH with no leading zeros" % text)
        self.major, self.minor, self.patch = (int(g) for g in match.groups())

    @property
    def parts(self):
        return (self.major, self.minor, self.patch)

    def __eq__(self, other):
        return isinstance(other, Version) and other.parts == self.parts

    def __lt__(self, other):
        return self.parts < other.parts

    def __le__(self, other):
        return self.parts <= other.parts

    def __gt__(self, other):
        return self.parts > other.parts

    def __ge__(self, other):
        return self.parts >= other.parts

    def __hash__(self):
        return hash(self.parts)

    def __str__(self):
        return "%d.%d.%d" % self.parts

    def __repr__(self):
        return "Version(%r)" % str(self)


class Requirement(object):
    """One acceptance test over a Version."""

    __slots__ = ("operator", "version", "text")

    def __init__(self, text):
        if not isinstance(text, str) or not text.strip():
            raise VersionError("requirement must be a non-empty string, got %r" % (text,))
        raw = text.strip()
        match = REQUIREMENT_PATTERN.match(raw)
        if match is None:
            # ``.+`` does not match a newline, so a requirement containing one
            # produced None here and the next line raised AttributeError. That
            # is not a VersionError, so it escaped every caller's except clause
            # and aborted the whole discovery scan -- one malformed manifest
            # taking down every other mod in the install.
            raise VersionError("%r is not a usable version requirement" % text)
        operator = match.group(1) or "^"
        rest = match.group(2).strip()
        # Catch an operator this grammar does not have rather than letting
        # Version() report it as a malformed number. "<2.0.0" must say that "<"
        # is unsupported, not that "<2.0.0" is not a version.
        leading = rest[:2] if rest[:2] in ("<=", "!=", "~>") else rest[:1]
        if leading and not leading[0].isdigit():
            raise VersionError(
                "%r uses an operator this framework does not support; Stage 4 "
                "understands only %s and a bare version (which means ^)"
                % (raw, ", ".join(OPERATORS)))
        self.operator = operator
        self.version = Version(rest)
        self.text = raw

    def matches(self, version):
        if not isinstance(version, Version):
            raise VersionError("can only test a Version, got %r" % (version,))
        if self.operator == "==":
            return version == self.version
        if self.operator == ">=":
            return version >= self.version
        # "^": at least this version, and not the next MAJOR. A 0.x version is
        # NOT given the usual "0.x majors are breaking" special case, because
        # that rule is a convention some ecosystems have and others do not, and
        # a resolver that silently applies it would reject dependencies the
        # author believed they had allowed.
        return (version >= self.version
                and version.major == self.version.major)

    def __str__(self):
        return self.text

    def __repr__(self):
        return "Requirement(%r)" % self.text


def parse_version(text):
    return Version(text)


def parse_requirement(text):
    return Requirement(text)
