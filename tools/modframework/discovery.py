#!/usr/bin/env python3
"""Find the mod folders under a discovery root. Nothing else.

WHY DISCOVERY IS ITS OWN LAYER
------------------------------
It is the only part of Stage 4 that touches the filesystem, and therefore the
only part whose answer can depend on the machine. Isolating it means validation
and resolution can be tested by handing them a list -- no temp directories, no
ordering tricks, no game.

DETERMINISM IS NOT "os.listdir HAPPENS TO BE SORTED"
----------------------------------------------------
``os.listdir`` returns entries in whatever order the filesystem hands back. On
NTFS that is usually alphabetical, on ext4 it is hash order, and after enough
renames it is neither. Code that works today because the directory happened to
enumerate conveniently is code that reorders someone's mods after they rename a
folder. So every listing here is sorted explicitly, and the sort key is the
mod_id wherever one exists -- the folder name only orders things that could not
be parsed and therefore have no id to sort by.

CASE, AND WHY FOLDERS ARE COMPARED CASE-INSENSITIVELY
-----------------------------------------------------
Windows filesystems are case-insensitive; the repository's own tooling runs on
Windows. Two folders differing only in case cannot both exist there but can on
a mod author's Linux machine, so the folder scan reports such a pair rather
than silently depending on which platform is reading.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import diagnostics as D                                            # noqa: E402
import manifest as M                                               # noqa: E402


class DiscoveryError(Exception):
    """The root itself is unusable. A missing root is not a mod problem."""


class Discovered(object):
    """One candidate folder and what parsing it produced."""

    __slots__ = ("folder", "root", "manifest", "diagnostics", "declared_mod_id")

    def __init__(self, folder, root, manifest, diagnostics, declared_mod_id=None):
        self.folder = folder            # the folder NAME, never an identity
        self.root = root                # its absolute path
        self.manifest = manifest        # None when it could not be accepted
        self.diagnostics = list(diagnostics)
        # What the file CLAIMED, even if it was then refused. A mod that named
        # itself is reported by that name; only a manifest too broken to yield
        # an id falls back to the folder path.
        self.declared_mod_id = declared_mod_id or (manifest.mod_id if manifest
                                                   else None)

    @property
    def mod_id(self):
        return self.manifest.mod_id if self.manifest else None

    @property
    def identity(self):
        """How this folder is named in a report, accepted or not."""
        return self.declared_mod_id or self.root

    def as_dict(self):
        return {"folder": self.folder, "root": self.root,
                "mod_id": self.mod_id, "declared_mod_id": self.declared_mod_id,
                "manifest": self.manifest.as_dict() if self.manifest else None,
                "diagnostics": [d.as_dict() for d in
                                sorted(self.diagnostics, key=D.sort_key)]}

    def __repr__(self):
        return "Discovered(%r -> %r)" % (self.folder, self.mod_id)


def candidate_folders(root):
    """Every immediate subdirectory of *root*, sorted by name.

    A subdirectory without a ``mod.json`` is NOT a candidate and is not
    reported: users keep notes, backups and screenshots beside their mods, and
    a discovery layer that called every stray folder a broken mod would train
    them to ignore its output. A folder WITH a mod.json that cannot be parsed
    is a different matter entirely, and is reported loudly.
    """
    if not os.path.isdir(root):
        raise DiscoveryError("the discovery root %r does not exist or is not a "
                             "directory" % root)
    entries = []
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if not os.path.isdir(path):
            continue
        if not os.path.isfile(os.path.join(path, M.MANIFEST_FILENAME)):
            continue
        entries.append((name, path))
    return entries


def discover(root, container_reader=None, check_artifacts=True):
    """Scan *root* and parse every mod folder found under it.

    Returns a list of :class:`Discovered`, ordered deterministically: accepted
    mods by ``mod_id``, then unparseable folders by folder name. Ordering by
    mod_id rather than by folder name is what makes renaming ``AlphaMod`` to
    ``ZZZ_AlphaMod`` a cosmetic act.

    Artifact checks happen here because they need the folder on disk, but they
    are still per-mod: nothing in this function compares two mods.
    """
    candidates = candidate_folders(root)

    # Case-insensitive folder collisions are settled BEFORE anything is parsed,
    # and they refuse EVERY member of the colliding group.
    #
    # The first version refused only the folder it met second, which left the
    # first one accepted -- so on a case-sensitive filesystem the mod that
    # loaded was whichever folder name sorted first by codepoint. Renaming
    # `alphamod/` to `Alphamod/` flipped which of two unrelated mods reached the
    # live plan. That is the folder name deciding identity, and it failed OPEN.
    # The duplicate-mod_id rule drops both claimants for exactly this reason;
    # this now does the same.
    by_key = {}
    for name, _path in candidates:
        by_key.setdefault(name.lower(), []).append(name)
    colliding = {key: sorted(names) for key, names in by_key.items()
                 if len(names) > 1}

    found = []
    for name, path in candidates:
        parsed, problems, declared = M.load(path)
        problems = list(problems)
        siblings = colliding.get(name.lower())
        if siblings:
            problems.append(D.Diagnostic(
                D.MALFORMED_MANIFEST, path,
                "the folder name collides case-insensitively with %s. On Windows "
                "these are one folder and on Linux they are two, so which mod "
                "this is would depend on the machine reading the directory. "
                "EVERY folder in the group is refused: keeping the one whose "
                "name happens to sort first would let a rename decide which mod "
                "loads." % [n for n in siblings if n != name]))
            parsed = None
        if parsed is not None and check_artifacts:
            artifact_problems = M.check_artifacts(parsed, container_reader)
            problems.extend(artifact_problems)
            if D.fatal(artifact_problems):
                # A mod missing a declared artifact is not partially loadable.
                # Dropping the manifest here is what stops a half-present mod
                # from reaching the resolver as if it were whole.
                parsed = None
        found.append(Discovered(name, path, parsed, problems, declared))

    found.sort(key=lambda d: (d.mod_id is None, d.mod_id or "", d.folder))
    return found


def scan(root, container_reader=None, check_artifacts=True):
    """Discovery as a report: the list plus its diagnostics, already ordered."""
    found = discover(root, container_reader, check_artifacts)
    problems = [d for entry in found for d in entry.diagnostics]
    return {
        "root": os.path.abspath(root),
        "folders_examined": [entry.folder for entry in found],
        "discovered": [entry.as_dict() for entry in found],
        "diagnostics": D.summarise(problems),
    }, found
