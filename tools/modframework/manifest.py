#!/usr/bin/env python3
"""``mod.json`` -- the schema, and everything decidable about ONE mod alone.

WHAT IS IN THE SCHEMA, AND WHY NOTHING ELSE IS
----------------------------------------------
Every field below has a Stage 4 consumer that would break without it:

    manifest_version       decides how the rest of the file is read
    mod_id                 the authoritative namespace (Stage 2 rows, Stage 3 paths)
    name                   the only thing a user-facing list can show
    version                what another mod's dependency requirement is tested against
    framework_api          what this framework's own version is tested against
    dependencies           load order, and refusal when unmet
    optional_dependencies  load order when present, silence when absent
    conflicts              refusal when both are present
    content                containers to mount, and artifacts to verify exist
    code                   artifacts to verify exist and hand to the execution layer

Author, description, licence, homepage, tags and load-order hints are all
absent. Not because they are worthless -- because Stage 4 would not read them,
and a schema field nothing consumes is a field nobody validates and everybody
eventually trusts.

IDENTITY COMES FROM mod_id, FROM NOWHERE ELSE
---------------------------------------------
Not the folder name, not ``name``, not position in a load order. The fixtures
deliberately live in folders called ``AlphaMod`` and ``BetaMod`` while declaring
``alphamod`` and ``betamod``, so that any code that started keying off the
folder name fails immediately rather than in a user's install six months later.
A folder rename must be a cosmetic act.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (HERE, os.path.join(os.path.dirname(HERE), "modkit")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import diagnostics as D                                            # noqa: E402
import namespace as ns                                             # noqa: E402
import semver                                                      # noqa: E402

MANIFEST_FILENAME = "mod.json"
CONTENT_DIRNAME = "Content"
CODE_DIRNAME = "Code"

# Which manifest layouts this build of the framework can read. A manifest
# declaring anything else is refused BY NUMBER, without guessing: reading a
# future layout with today's rules is how a field silently changes meaning.
SUPPORTED_MANIFEST_VERSIONS = (1,)

# The framework's own API version, which every mod's `framework_api` is tested
# against. MAJOR is the promise: a bump says old mods stop working.
FRAMEWORK_API_VERSION = semver.Version("0.4.0")

REQUIRED_FIELDS = ("manifest_version", "mod_id", "name", "version", "framework_api")
OPTIONAL_FIELDS = ("dependencies", "optional_dependencies", "conflicts",
                   "content", "code")
KNOWN_FIELDS = frozenset(REQUIRED_FIELDS + OPTIONAL_FIELDS)

# The three files an IoStore container ships as. The manifest names the stem
# once; requiring an author to list all three would let them list two.
CONTAINER_SUFFIXES = (".pak", ".utoc", ".ucas")

MAX_NAME_LEN = 96

# Stage 2 derives an item's row name as ``<mod_id>__<local_id>``. A mod_id that
# itself contained ``__`` would make that decomposition ambiguous --
# ``a__b__c`` could be (a, b__c) or (a__b, c) -- so Stage 2's ItemId refuses it.
# Stage 3's path rule does NOT, because ``__`` is harmless inside
# ``/Game/Mods/<mod_id>/``, and each stage's own rule is locally correct.
#
# mod_id is the ONE identity both stages key off, so what a mod may actually be
# called is the INTERSECTION of the two rules, and Stage 4 is the layer that
# owns identity across both. Enforcing it here rather than loosening Stage 2 or
# tightening Stage 3 keeps each stage's rule true on its own terms; a test
# asserts this rule stays at least as strict as both.
ROW_NAME_SEPARATOR = "__"


class ManifestError(Exception):
    """Raised only for a manifest that cannot yield a mod_id at all.

    Everything else is reported as a Diagnostic, because a mod that names
    itself can be excluded BY NAME, and a report that can name the mod it
    refused is worth more than an exception that stops the whole scan.
    """


class Dependency(object):
    __slots__ = ("mod_id", "requirement", "optional")

    def __init__(self, mod_id, requirement, optional=False):
        self.mod_id = mod_id
        self.requirement = requirement
        self.optional = optional

    def as_dict(self):
        return {"mod_id": self.mod_id, "version": str(self.requirement),
                "optional": self.optional}

    def __repr__(self):
        return "Dependency(%r, %r)" % (self.mod_id, str(self.requirement))


class Conflict(object):
    """A declared incompatibility. ``requirement`` None means every version."""

    __slots__ = ("mod_id", "requirement")

    def __init__(self, mod_id, requirement=None):
        self.mod_id = mod_id
        self.requirement = requirement

    def applies_to(self, version):
        return self.requirement is None or self.requirement.matches(version)

    def as_dict(self):
        return {"mod_id": self.mod_id,
                "version": str(self.requirement) if self.requirement else None}

    def __repr__(self):
        return "Conflict(%r, %r)" % (self.mod_id, self.requirement)


class Manifest(object):
    """One parsed, self-consistent ``mod.json``.

    Constructing this object never touches another mod. Everything that needs
    the whole set -- duplicates, dependencies, conflicts, ordering -- belongs to
    resolve.py, and keeping the split honest is what lets discovery and
    validation be tested with no game and no filesystem tricks.
    """

    __slots__ = ("mod_id", "name", "version", "framework_api", "manifest_version",
                 "dependencies", "optional_dependencies", "conflicts",
                 "content", "code", "root", "manifest_path")

    def __init__(self, mod_id, name, version, framework_api, manifest_version,
                 dependencies, optional_dependencies, conflicts, content, code,
                 root, manifest_path):
        self.mod_id = mod_id
        self.name = name
        self.version = version
        self.framework_api = framework_api
        self.manifest_version = manifest_version
        self.dependencies = dependencies
        self.optional_dependencies = optional_dependencies
        self.conflicts = conflicts
        self.content = content
        self.code = code
        self.root = root
        self.manifest_path = manifest_path

    @property
    def all_dependencies(self):
        return list(self.dependencies) + list(self.optional_dependencies)

    def content_dir(self):
        return os.path.join(self.root, CONTENT_DIRNAME)

    def code_dir(self):
        return os.path.join(self.root, CODE_DIRNAME)

    def container_files(self, container):
        return [os.path.join(self.content_dir(), container + suffix)
                for suffix in CONTAINER_SUFFIXES]

    def as_dict(self):
        return {
            "mod_id": self.mod_id, "name": self.name, "version": str(self.version),
            "framework_api": str(self.framework_api),
            "manifest_version": self.manifest_version,
            "dependencies": [d.as_dict() for d in self.dependencies],
            "optional_dependencies": [d.as_dict() for d in self.optional_dependencies],
            "conflicts": [c.as_dict() for c in self.conflicts],
            "content": list(self.content), "code": list(self.code),
            "root": self.root, "manifest_path": self.manifest_path,
        }

    def __repr__(self):
        return "Manifest(%r, %s)" % (self.mod_id, self.version)


def _dependency_list(raw, field, mod_id, optional, out):
    """Parse one dependency-shaped array. Returns (deps, diagnostics)."""
    deps, problems = [], []
    if raw is None:
        return deps, problems
    if not isinstance(raw, list):
        problems.append(D.Diagnostic(D.MALFORMED_MANIFEST, mod_id,
                                     "%r must be a list, got %s"
                                     % (field, type(raw).__name__)))
        return deps, problems
    seen = set()
    for index, entry in enumerate(raw):
        where = "%s[%d]" % (field, index)
        if not isinstance(entry, dict):
            problems.append(D.Diagnostic(
                D.MALFORMED_MANIFEST, mod_id,
                "%s must be an object with mod_id and version" % where))
            continue
        unknown = sorted(set(entry) - {"mod_id", "version"})
        if unknown:
            problems.append(D.Diagnostic(
                D.MALFORMED_MANIFEST, mod_id,
                "%s has unknown key(s) %s" % (where, unknown)))
            continue
        target = entry.get("mod_id")
        try:
            ns.check_mod_id(target)
        except ns.NamespaceError as error:
            problems.append(D.Diagnostic(
                D.MALFORMED_MANIFEST, mod_id,
                "%s names an invalid mod_id: %s" % (where, error)))
            continue
        if target == mod_id:
            # A self-dependency is a one-node cycle. It is caught here as well
            # as in the graph, because catching it early names the field.
            problems.append(D.Diagnostic(
                D.MALFORMED_MANIFEST, mod_id,
                "%s depends on the mod itself" % where))
            continue
        if target in seen:
            problems.append(D.Diagnostic(
                D.MALFORMED_MANIFEST, mod_id,
                "%s names %r twice in the same list; two requirements for one "
                "dependency have no defined combination" % (where, target)))
            continue
        seen.add(target)
        if "version" not in entry:
            # No silent default. The previous one was "0.0.0", which parses as
            # ^0.0.0 -- "major must be 0" -- and therefore refused every
            # dependency at 1.0.0 or later while looking like "any version".
            out.append(D.Diagnostic(
                D.MALFORMED_MANIFEST, mod_id,
                "%s does not state a version requirement. Say so explicitly, "
                "e.g. \">=0.0.0\" for any version." % where))
            continue
        try:
            requirement = semver.Requirement(entry["version"])
        except semver.VersionError as error:
            problems.append(D.Diagnostic(
                D.MALFORMED_MANIFEST, mod_id,
                "%s has an unusable version requirement: %s" % (where, error)))
            continue
        deps.append(Dependency(target, requirement, optional=optional))
    # Sorted by mod_id so that the order dependencies were typed in cannot
    # influence anything downstream.
    deps.sort(key=lambda d: d.mod_id)
    out.extend(problems)
    return deps, problems


def _conflict_list(raw, mod_id, out):
    conflicts = []
    if raw is None:
        return conflicts
    if not isinstance(raw, list):
        out.append(D.Diagnostic(D.MALFORMED_MANIFEST, mod_id,
                                "'conflicts' must be a list, got %s"
                                % type(raw).__name__))
        return conflicts
    for index, entry in enumerate(raw):
        where = "conflicts[%d]" % index
        if not isinstance(entry, dict):
            out.append(D.Diagnostic(D.MALFORMED_MANIFEST, mod_id,
                                    "%s must be an object with mod_id" % where))
            continue
        unknown = sorted(set(entry) - {"mod_id", "version"})
        if unknown:
            out.append(D.Diagnostic(D.MALFORMED_MANIFEST, mod_id,
                                    "%s has unknown key(s) %s" % (where, unknown)))
            continue
        target = entry.get("mod_id")
        try:
            ns.check_mod_id(target)
        except ns.NamespaceError as error:
            out.append(D.Diagnostic(D.MALFORMED_MANIFEST, mod_id,
                                    "%s names an invalid mod_id: %s" % (where, error)))
            continue
        if target == mod_id:
            out.append(D.Diagnostic(D.MALFORMED_MANIFEST, mod_id,
                                    "%s declares a conflict with itself" % where))
            continue
        requirement = None
        if entry.get("version") is not None:
            try:
                requirement = semver.Requirement(entry["version"])
            except semver.VersionError as error:
                out.append(D.Diagnostic(
                    D.MALFORMED_MANIFEST, mod_id,
                    "%s has an unusable version requirement: %s" % (where, error)))
                continue
        conflicts.append(Conflict(target, requirement))
    conflicts.sort(key=lambda c: c.mod_id)
    return conflicts


def _string_list(raw, field, mod_id, out):
    """A list of plain names, e.g. container stems or code paths."""
    values = []
    if raw is None:
        return values
    if not isinstance(raw, list):
        out.append(D.Diagnostic(D.MALFORMED_MANIFEST, mod_id,
                                "%r must be a list, got %s" % (field, type(raw).__name__)))
        return values
    seen = set()
    for index, entry in enumerate(raw):
        where = "%s[%d]" % (field, index)
        if not isinstance(entry, str) or not entry.strip():
            out.append(D.Diagnostic(D.MALFORMED_MANIFEST, mod_id,
                                    "%s must be a non-empty string" % where))
            continue
        value = entry.strip()
        # A declared artifact must stay inside the mod's own folder. Without
        # this an author could declare "../../OtherMod/Content/x" and have the
        # framework verify, and later mount, a file that is not theirs.
        if (os.path.isabs(value) or value.startswith(("/", "\\"))
                or ".." in value.replace("\\", "/").split("/")
                or ":" in value):
            out.append(D.Diagnostic(
                D.MALFORMED_MANIFEST, mod_id,
                "%s (%r) must be a relative path inside the mod folder; "
                "absolute paths and .. would let a mod declare another mod's files"
                % (where, value)))
            continue
        if value in seen:
            out.append(D.Diagnostic(D.MALFORMED_MANIFEST, mod_id,
                                    "%s names %r twice" % (where, value)))
            continue
        seen.add(value)
        values.append(value)
    values.sort()
    return values


def parse(raw, root, manifest_path):
    """Parse an already-decoded ``mod.json`` body.

    Returns ``(manifest_or_None, diagnostics, declared_mod_id_or_None)``.

    A manifest is returned only when nothing fatal was found: Stage 4 must never
    hold a half-accepted manifest, because a half-accepted manifest is exactly
    what leaks into a load plan.

    The third value is what the file CLAIMED to be, and it is returned even when
    the manifest is refused. Without it a mod that named itself and then failed
    a later check could only be reported by folder path, and "the mod in
    D:\\Mods\\Thing is excluded" is a worse answer than "alphamod is excluded"
    for a user who knows their mods by name.
    """
    out = []
    subject = root

    if not isinstance(raw, dict):
        out.append(D.Diagnostic(D.MALFORMED_MANIFEST, subject,
                                "the manifest must be a JSON object, got %s"
                                % type(raw).__name__))
        return None, out, None

    # manifest_version is read FIRST and alone. Every other field's meaning is
    # defined by it, so validating anything else against today's rules before
    # knowing the version would be reading a future file with the wrong grammar.
    version_field = raw.get("manifest_version")
    if not isinstance(version_field, int) or isinstance(version_field, bool):
        out.append(D.Diagnostic(
            D.MALFORMED_MANIFEST, subject,
            "'manifest_version' must be an integer; without it the rest of the "
            "file has no defined meaning"))
        return None, out, None
    if version_field not in SUPPORTED_MANIFEST_VERSIONS:
        out.append(D.Diagnostic(
            D.UNSUPPORTED_MANIFEST_VERSION, subject,
            "manifest_version %d is not one this framework can read (%s). "
            "Refusing rather than guessing: a newer layout may give an existing "
            "field a new meaning." % (version_field,
                                      list(SUPPORTED_MANIFEST_VERSIONS))))
        return None, out, None

    mod_id = raw.get("mod_id")
    try:
        ns.check_mod_id(mod_id)
    except ns.NamespaceError as error:
        out.append(D.Diagnostic(D.INVALID_MOD_ID, subject,
                                "%r: %s" % (mod_id, error)))
        return None, out, None
    if ROW_NAME_SEPARATOR in mod_id:
        out.append(D.Diagnostic(
            D.INVALID_MOD_ID, subject,
            "%r contains %r, which Stage 2 uses to separate a mod_id from a "
            "local item id. A mod_id containing it would make the row name "
            "ambiguous to decompose." % (mod_id, ROW_NAME_SEPARATOR)))
        return None, out, None
    # From here the mod can be named, so everything is attributed to the id
    # rather than to a folder path.
    subject = mod_id

    unknown = sorted(set(raw) - KNOWN_FIELDS)
    if unknown:
        out.append(D.Diagnostic(
            D.MALFORMED_MANIFEST, subject,
            "unknown field(s) %s. Refused rather than ignored: a typo in a field "
            "name would otherwise silently disable what the author meant to say"
            % unknown))

    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        out.append(D.Diagnostic(D.MALFORMED_MANIFEST, subject,
                                "'name' must be a non-empty string"))
    elif len(name) > MAX_NAME_LEN:
        out.append(D.Diagnostic(D.MALFORMED_MANIFEST, subject,
                                "'name' is longer than %d characters" % MAX_NAME_LEN))

    version = None
    try:
        version = semver.Version(raw.get("version"))
    except semver.VersionError as error:
        out.append(D.Diagnostic(D.MALFORMED_MANIFEST, subject,
                                "'version': %s" % error))

    framework_api = None
    try:
        framework_api = semver.Requirement(raw.get("framework_api"))
    except semver.VersionError as error:
        out.append(D.Diagnostic(D.MALFORMED_MANIFEST, subject,
                                "'framework_api': %s" % error))
    else:
        if not framework_api.matches(FRAMEWORK_API_VERSION):
            out.append(D.Diagnostic(
                D.UNSUPPORTED_FRAMEWORK_API, subject,
                "the mod requires framework API %s and this framework is %s"
                % (framework_api, FRAMEWORK_API_VERSION)))

    dependencies, _ = _dependency_list(raw.get("dependencies"), "dependencies",
                                       subject, False, out)
    optional, _ = _dependency_list(raw.get("optional_dependencies"),
                                   "optional_dependencies", subject, True, out)
    # A mod_id in both lists has two different answers to "must this be
    # present", and there is no defensible way to pick one.
    both = sorted({d.mod_id for d in dependencies} & {d.mod_id for d in optional})
    if both:
        out.append(D.Diagnostic(
            D.MALFORMED_MANIFEST, subject,
            "%s appear in both dependencies and optional_dependencies, which "
            "states that they are simultaneously required and not" % both))

    conflicts = _conflict_list(raw.get("conflicts"), subject, out)
    declared_conflict_ids = {c.mod_id for c in conflicts}
    contradictory = sorted(declared_conflict_ids
                           & {d.mod_id for d in dependencies + optional})
    if contradictory:
        out.append(D.Diagnostic(
            D.MALFORMED_MANIFEST, subject,
            "%s are declared as both a dependency and a conflict" % contradictory))

    content = _string_list(raw.get("content"), "content", subject, out)
    # A container stem names a file in the SHARED staging directory, so two mods
    # declaring one stem means the second silently replaces the first's
    # container. Stems are therefore namespaced like everything else a mod owns.
    stem_prefix = ns.container_name(mod_id).rsplit("_", 1)[0] + "_"
    for stem in content:
        if not stem.startswith(stem_prefix):
            out.append(D.Diagnostic(
                D.CONTENT_NAMESPACE_MISMATCH, subject,
                "declared content %r must be namespaced to this mod, i.e. begin "
                "with %r. Container stems share one staging directory, so an "
                "unnamespaced stem lets one mod overwrite another's container."
                % (stem, stem_prefix)))
    code = _string_list(raw.get("code"), "code", subject, out)

    if D.fatal(out):
        return None, out, mod_id
    return Manifest(mod_id, name.strip(), version, framework_api, version_field,
                    dependencies, optional, conflicts, content, code,
                    root, manifest_path), out, mod_id


def load(root):
    """Read ``<root>/mod.json`` from disk and parse it.

    Returns ``(manifest_or_None, diagnostics, declared_mod_id_or_None)``. Every
    failure mode of reading a file -- absent, unreadable, not UTF-8, not JSON --
    lands as ``malformed_manifest`` against the folder, because at that point
    there is genuinely no mod_id to attribute it to.
    """
    manifest_path = os.path.join(root, MANIFEST_FILENAME)
    if not os.path.isfile(manifest_path):
        return None, [D.Diagnostic(D.MALFORMED_MANIFEST, root,
                                   "no %s in the mod folder" % MANIFEST_FILENAME)], None
    try:
        with open(manifest_path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except UnicodeDecodeError as error:
        return None, [D.Diagnostic(D.MALFORMED_MANIFEST, root,
                                   "%s is not valid UTF-8: %s"
                                   % (MANIFEST_FILENAME, error))], None
    except json.JSONDecodeError as error:
        return None, [D.Diagnostic(D.MALFORMED_MANIFEST, root,
                                   "%s is not valid JSON: %s"
                                   % (MANIFEST_FILENAME, error))], None
    except OSError as error:
        return None, [D.Diagnostic(D.MALFORMED_MANIFEST, root,
                                   "%s could not be read: %s"
                                   % (MANIFEST_FILENAME, error))], None
    return parse(raw, root, manifest_path)


def check_artifacts(manifest, container_reader=None):
    """Every declared artifact must exist, and content must be the mod's own.

    *container_reader* is injected so this stays testable with no built
    containers; when given it is called with a ``.utoc`` path and must return a
    report carrying ``package_paths`` (the shape tools/modkit/container_report
    produces).

    The namespace cross-check is the point of the second half: ``mod_id`` is the
    authoritative namespace, so a mod declaring a container whose packages
    belong to a DIFFERENT mod is claiming content that is not its own, and that
    is exactly the collision Stage 3's derived paths exist to prevent.
    """
    out = []
    for container in manifest.content:
        missing = [path for path in manifest.container_files(container)
                   if not os.path.isfile(path)]
        if missing:
            out.append(D.Diagnostic(
                D.MISSING_ARTIFACT, manifest.mod_id,
                "declared content %r is missing %s"
                % (container, [os.path.basename(p) for p in missing])))
            continue
        if container_reader is None:
            continue
        utoc = os.path.join(manifest.content_dir(), container + ".utoc")
        try:
            report = container_reader(utoc)
        except Exception as error:                                 # noqa: BLE001
            out.append(D.Diagnostic(
                D.MISSING_ARTIFACT, manifest.mod_id,
                "declared content %r could not be read: %s: %s"
                % (container, type(error).__name__, error)))
            continue
        # Compare PATHS, not owners. ns.owning_mod returns None for anything
        # outside /Game/Mods, so the old set could hold both None and a string
        # and sorted() raised TypeError -- which escaped check_artifacts, then
        # discover(), and killed the scan for every mod in the tree.
        strays = sorted(path for path in (report.get("package_paths") or [])
                        if ns.owning_mod(path) != manifest.mod_id)
        if strays:
            out.append(D.Diagnostic(
                D.CONTENT_NAMESPACE_MISMATCH, manifest.mod_id,
                "declared content %r carries %d package(s) that are not this "
                "mod's: %s. mod_id is the authoritative namespace; a mod may "
                "ship neither another mod's package paths nor vanilla ones."
                % (container, len(strays), strays[:5])))
    for path in manifest.code:
        full = os.path.join(manifest.code_dir(), path)
        if not os.path.isfile(full):
            out.append(D.Diagnostic(
                D.MISSING_ARTIFACT, manifest.mod_id,
                "declared code artifact %r does not exist under %s"
                % (path, CODE_DIRNAME)))
    return out
