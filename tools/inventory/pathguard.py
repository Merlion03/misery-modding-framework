#!/usr/bin/env python3
"""Output-path guard: refuse to write anything inside a MISERY installation.

Why this module exists
----------------------
plan.md section 1.5 layer 1 ("Изоляция") states as a *mechanism* that no tool
accepts a path inside the game installation as an output path, and decision D-01
declares the installation a read-only research target. Until this module existed
layer 1 was only a sentence in a docstring: ``snapshot_install.py`` disclaimed
responsibility and put it on the caller, so

    snapshot_install.py --out <install>\\anything.json

would have written into the installation and silently invalidated the very
baseline that layer 3 (``verify_install.py``) compares against. Layer 1 is now
enforced here, in one place. Do not copy-paste these checks; import them: a
copy-pasted guard drifts from the original, and a docstring claiming otherwise
stops anyone from looking. ``find_misery.write_document`` used to carry exactly
such a copy, built on ``os.path.abspath``, which resolves neither symlinks nor
NTFS junctions, so an ``--out`` path through a junction pointing below the
installation root was accepted and the file landed inside the tree. That copy is
gone; ``find_misery`` imports this module.

Who imports it, exactly (verified, not asserted)
------------------------------------------------
Every tool in ``tools/`` that opens a file for writing, WITH ONE KNOWN
EXCEPTION, routes the path through ``check_output_path`` first:

* ``tools/discovery/find_misery.py`` -- ``write_document``, guarding ``--out``;
* ``tools/inventory/snapshot_install.py`` -- ``write_json``, guarding ``--out``;
* ``tools/inventory/verify_install.py`` -- guards ``--json`` twice, at argument
  parse time and again at the moment of writing;
* ``tools/kb/validate.py`` -- writes nothing at all, so there is nothing to
  guard.

The exception is ``tools/kb/new_log_entry.py``: it appends to
``research/RESEARCH_LOG.md``, its ``--log`` flag accepts an arbitrary path, and
it does NOT import this module, so ``new_log_entry.py --log <install>\\x.md``
still writes inside an installation. That is a real gap in layer 1, recorded here
rather than papered over, because the previous version of this paragraph claimed
"imported by every tool that writes a file" and was therefore false. Fixing it is
a two-line change in that tool (import pathguard, pass the log path and a root
through ``check_output_path``); until it lands, the claim above is exactly as
narrow as it reads. The content tools of M1+ must import this module from the
start.

Importing from another tools/ subdirectory
-----------------------------------------
``tools/`` is deliberately not a Python package (the scripts are run directly,
not as ``-m`` modules), so a tool in a sibling directory bootstraps sys.path::

    import os, sys
    _INVENTORY = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "inventory")
    if _INVENTORY not in sys.path:
        sys.path.insert(0, _INVENTORY)
    import pathguard

Which locations are protected
-----------------------------
This is the second defect this module was rebuilt to fix. The first version
compared the output path against exactly one root: whatever the current
invocation happened to name (``--install-dir``, or the caller's own default).
That guard protects correctly on every *correct* invocation and turns itself off
on the one invocation that is already wrong -- a mistyped ``--install-dir``
names a directory that is not an installation, and writing into the real
installation then exits 0. That is the "иллюзия надёжности" plan.md 1.5 says it
is avoiding, so the set of protected roots is now the union of three sources,
and a check fires when the output resolves inside *any* of them:

1. **named** -- the root the invocation passed in (``install_root``). Unchanged
   behaviour, still the first thing checked, so the common case is unaffected.
2. **structural** -- every ancestor of the output path that *is* a MISERY
   installation, decided by the same predicate discovery uses to conclude "this
   really is it" (plan.md 2.1 step 6: ``MISERY\\Binaries\\Win64\\
   MISERY-Win64-Shipping.exe`` and ``MISERY\\Content\\Paks\\global.utoc`` both
   present, see ``INSTALL_MARKERS``). This is the primitive that makes the guard
   machine-independent: it needs no configuration, works on a fresh clone on a
   machine nobody has configured, protects a second installation in a second
   Steam library, and cannot be defeated by naming the wrong root, because it
   asks about the output path itself rather than about the argument.
3. **recorded / configured** -- every installation location this repository or
   this machine already knows about: ``MISERY_GAME_DIR``,
   ``research/config/local.json``, the ``install_dir`` of every
   ``research/builds/*/install.json`` and ``install_dirs`` of
   ``research/builds/index.json`` (i.e. the persisted results of the discovery
   mechanism), plus ``CONFIGURED_INSTALL_ROOTS``. Source 2 alone would miss an
   installation that is *temporarily* not recognizable -- mid-Steam-update, with
   ``global.utoc`` replaced or absent -- which is exactly a moment when writing
   into the tree would be unrecoverable. Reading these files is cheap (a few KB)
   and failures are ignored: this source can only ever *add* protection.

Where this stops short, measured rather than guessed
----------------------------------------------------
The three sources leave exactly one gap, and it is worth stating precisely
instead of implying there is none. On a machine that is not the research machine,
with a fresh clone (nothing recorded under ``research/builds``, no
``local.json``, ``MISERY_GAME_DIR`` unset) AND the installation *temporarily
unrecognizable* because a Steam update has removed or replaced ``global.utoc``,
source 2 goes quiet and source 3 is empty, so a wrongly named ``--install-dir``
does let an output path into that tree. Verified by experiment: with the tree
intact the write is refused by source 2; with ``global.utoc`` removed and an
empty repository it is accepted; setting ``MISERY_GAME_DIR`` or writing
``local.json`` refuses it again, as does any completed discovery run, because
that records the path under ``research/builds``.

Requiring only ``MISERY-Win64-Shipping.exe`` would close it, and is not done: one
well-known filename is easy to hit by accident, a false protected root makes a
legitimate directory permanently unwritable with no override (there is none, by
design, see below), and plan.md 2.1 step 6 defines the predicate as both files.
The trade is documented here so the next person can weigh it, rather than
discovered by them.

No escape hatch, deliberately (D-01)
------------------------------------
There is no flag, environment variable or argument that removes a protected
root. D-01 makes the installation a read-only research target unconditionally,
and the defect being fixed here is precisely "one mistyped argument disables the
guard"; an override would reintroduce it in a form that looks official. The
environment and the config file are read *only* as additions. If a legitimate
output location is ever misdetected as an installation (it would have to contain
both marker files at their exact relative paths), the answer is to write
somewhere under the repository -- ``research/`` or ``workspace/`` -- which is
where tool output belongs anyway, not to switch the guard off.

What the guard actually compares
--------------------------------
Both the candidate output path and every protected root are reduced to an
absolute, real, normal-cased path before comparison, which is what makes the
check survive the Windows-specific ways a path can be spelled differently while
naming the same location:

* **relative paths** -- resolved against the *current* working directory, so
  ``--out x.json`` run with the installation as cwd is refused, not accepted;
* **case** -- ``os.path.normcase`` folds case (and ``/`` to ``\\``), so
  ``d:\\games\\...`` and ``D:\\Games\\...`` compare equal;
* **trailing separators and ``.``/``..`` segments** -- removed by ``normpath``;
* **short (8.3) names** -- ``os.path.realpath`` expands ``PROGRA~1`` to its long
  form for the part of the path that exists on disk; the output file itself
  usually does not exist yet, so the longest existing ancestor is resolved and
  the not-yet-existing tail is appended to it;
* **symlinks / junctions** -- also expanded by ``realpath``, so a junction or a
  symlink pointing into the installation, or below it, cannot be used to step
  around the check;
* **different drives** -- ``os.path.commonpath`` raises ``ValueError`` for paths
  with no common anchor; that means "outside", not "cannot tell".

One thing a path comparison cannot see, and what is done about it
----------------------------------------------------------------
A **hard link** has no target to resolve: two directory entries simply *are* the
same file, and ``realpath`` returns whichever name it was given. So

    mklink /H <somewhere-safe>\\out.json <install>\\MISERY\\Content\\Paks\\global.utoc

produces an output path that resolves outside every installation while opening it
with mode ``"w"`` truncates a file inside one. Verified by experiment, not
assumed: the guard accepted the path and the installation file was overwritten.
No amount of normalizing helps, because the containment question is being asked
about a name when the thing at risk is the file.

``check_output_path`` therefore also refuses an output path that **already exists
and carries more than one name** (``st_nlink > 1``). This is deliberately
conservative rather than exact: enumerating a file's other names is a
platform-specific call (``FindFirstFileNameW``), and "this file is reachable
under another name, so I cannot prove the other name is outside the installation"
is the honest answer, in the direction a safety check should fail. A normal file
has exactly one name, so nothing legitimate is affected; if a multiply-linked
output path is ever genuinely wanted, delete it or write under a fresh name --
the guard names the count in its message so the cause is obvious. The residual
gap is stated plainly: a *not yet existing* output path cannot be hard-linked to
anything (the link would create it), and a directory hard link does not exist on
NTFS, so the remaining hole is narrower than the tool boundary in "Scope" below.

Not covered, and not claimed: TOCTOU. The check runs, then the caller opens the
file. A local process that replaces a directory in the path with a junction in
between wins. Closing that needs an open-then-verify-by-handle sequence, which is
layer-1 work only if the threat model ever includes a hostile local process; it
currently does not (see "Scope").

The installation root itself is refused as well: writing *to* the root path
(clobbering the directory) is exactly the failure D-01 exists to prevent.

Failure mode: ``OutputPathRefused`` is raised *before* any file is created or
opened, so no partial output is ever left behind. The message names the
offending path, the protected root and which of the three sources contributed
it, so a refusal caused by a mistyped argument is diagnosable. Tool CLIs catch
it, print the message (which cites D-01) and exit non-zero.

Scope: this is layer 1 -- it prevents *our* tools from being pointed at an
installation. It is not a filesystem-level sandbox and does not stop any other
process; that is what layer 3 detection is for.
"""

from __future__ import annotations

import json
import os

__all__ = [
    "OutputPathRefused",
    "CONFIGURED_INSTALL_ROOTS",
    "INSTALL_MARKERS",
    "resolve_real",
    "is_inside",
    "looks_like_install_root",
    "structural_install_roots",
    "known_install_roots",
    "protected_roots",
    "hard_link_count",
    "check_output_path",
]

# The validation predicate of plan.md 2.1 step 6, i.e. the definition of "this
# directory is a MISERY installation". ``find_misery`` declares the same two
# relative paths as SHIPPING_EXE_REL / GLOBAL_UTOC_REL for discovery; the two
# declarations must move together if the game layout ever changes, and a test in
# tests/test_discovery.py asserts they are identical so drift is caught.
INSTALL_MARKERS = (
    os.path.join("MISERY", "Binaries", "Win64", "MISERY-Win64-Shipping.exe"),
    os.path.join("MISERY", "Content", "Paks", "global.utoc"),
)

# The one place where the known installation location of the research machine is
# written down. It is a *floor*, not the whole answer: on any other machine the
# structural predicate and the recorded discovery results below supply the real
# location. Adding an entry here can only widen protection.
CONFIGURED_INSTALL_ROOTS = (
    r"D:\Games\Steam\steamapps\common\MISERY",
)

# Same variable discovery step 1 honours (find_misery.ENV_OVERRIDE). Read here as
# an additional protected root only -- never as a way to drop one.
ENV_INSTALL_DIR = "MISERY_GAME_DIR"

LOCAL_CONFIG_RELPATH = os.path.join("research", "config", "local.json")
BUILDS_RELPATH = os.path.join("research", "builds")
BUILD_INDEX_RELPATH = os.path.join("research", "builds", "index.json")

# Refuse to read a "config" file that is really something else; these documents
# are a few KB in practice.
_MAX_CONFIG_BYTES = 4 << 20


class OutputPathRefused(Exception):
    """An output path was rejected because it lies inside an installation."""


def default_repo_root() -> str:
    """Repository root: this file lives in ``<repo>/tools/inventory/``."""
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def resolve_real(path: str) -> str:
    """Reduce *path* to an absolute, real, normalized path.

    Relative paths are resolved against the current working directory. The
    longest existing prefix of the path is passed through ``os.path.realpath``
    so that 8.3 short names, symlinks and junctions are expanded even when the
    final component does not exist yet (the usual case for an output file).
    """
    if path is None or not str(path).strip():
        raise ValueError("path must be a non-empty string")

    # %LOCALAPPDATA% and friends: paths that pass through a document field are
    # stored in the %VAR% form (constraint C-13), and a protected root must be
    # compared expanded or it would silently protect nothing.
    candidate = os.path.abspath(os.path.expandvars(str(path)))

    tail: list[str] = []
    head = candidate
    while not os.path.exists(head):
        parent = os.path.dirname(head)
        if parent == head:  # reached the anchor ("C:\\", "/"); nothing exists
            break
        tail.append(os.path.basename(head))
        head = parent

    resolved = os.path.realpath(head)
    for part in reversed(tail):
        resolved = os.path.join(resolved, part)
    return os.path.normpath(resolved)


def _is_inside_keys(inner_key: str, outer_key: str) -> bool:
    """Containment test on already resolved, normal-cased paths."""
    if inner_key == outer_key:
        return True
    try:
        common = os.path.commonpath([inner_key, outer_key])
    except ValueError:
        # No common anchor (different drives, or one path is a UNC share and the
        # other is not). Cannot be inside.
        return False
    return common == outer_key


def is_inside(inner: str, outer: str) -> bool:
    """True when *inner* is *outer* itself or lies below it.

    Comparison is done on resolved, normal-cased paths, so it is
    case-insensitive on Windows and immune to separator and 8.3 spelling.
    """
    return _is_inside_keys(
        os.path.normcase(resolve_real(inner)), os.path.normcase(resolve_real(outer))
    )


def looks_like_install_root(path: str) -> bool:
    """True when *path* satisfies the plan.md 2.1 step 6 validation predicate.

    Both marker files must be present. One of them is not enough on purpose: a
    single well-known name is easy to hit by accident (a copy of the shipping
    executable in ``workspace/bin/`` must not make its parent untouchable),
    while both, at their exact relative positions, mean the directory really is
    an installation tree.
    """
    try:
        return all(
            os.path.isfile(os.path.join(path, marker)) for marker in INSTALL_MARKERS
        )
    except OSError:
        # An unreadable or malformed path is not an installation root; the named
        # and recorded roots still apply.
        return False


def _ancestors(resolved: str) -> list[str]:
    """*resolved* and every directory above it, nearest first."""
    chain = []
    current = resolved
    while True:
        chain.append(current)
        parent = os.path.dirname(current)
        if not parent or parent == current:
            return chain
        current = parent


def structural_install_roots(path: str) -> list[str]:
    """Ancestors of *path* (including itself) that are MISERY installations.

    This is the machine-independent half of the guard: it answers "is the output
    path inside an installation" by looking at the output path, so it does not
    depend on the invocation naming the right root, on any configuration, or on
    discovery having been run on this machine.
    """
    resolved = resolve_real(path)
    return [
        candidate for candidate in _ancestors(resolved)
        if looks_like_install_root(candidate)
    ]


def _read_json(path: str):
    """Parse *path*, or return None. Never raises: this is a best-effort source."""
    try:
        if os.path.getsize(path) > _MAX_CONFIG_BYTES:
            return None
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def _install_dirs_from_local_config(repo_root: str) -> list[str]:
    document = _read_json(os.path.join(repo_root, LOCAL_CONFIG_RELPATH))
    if not isinstance(document, dict):
        return []
    found = []
    for key in ("install_dir", "misery_game_dir"):
        value = document.get(key)
        if isinstance(value, str) and value.strip():
            found.append(value)
    return found


def _install_dirs_from_builds(repo_root: str) -> list[str]:
    """Every install_dir recorded by a previous discovery run in this repository."""
    found: list[str] = []

    index = _read_json(os.path.join(repo_root, BUILD_INDEX_RELPATH))
    if isinstance(index, dict):
        for entry in index.values():
            if not isinstance(entry, dict):
                continue
            for value in entry.get("install_dirs") or []:
                if isinstance(value, str) and value.strip():
                    found.append(value)

    builds_dir = os.path.join(repo_root, BUILDS_RELPATH)
    try:
        names = sorted(os.listdir(builds_dir))
    except OSError:
        names = []
    for name in names:
        document = _read_json(os.path.join(builds_dir, name, "install.json"))
        if isinstance(document, dict):
            value = document.get("install_dir")
            if isinstance(value, str) and value.strip():
                found.append(value)
    return found


def known_install_roots(repo_root: str | None = None) -> list[tuple[str, str]]:
    """(source, path) pairs for every installation this machine knows about.

    Sources are configuration and the persisted output of the discovery
    mechanism, never a live registry read: the guard must be fast enough to call
    before every write and must not fail when the registry is unavailable.
    """
    root = repo_root or default_repo_root()
    pairs: list[tuple[str, str]] = []

    for value in CONFIGURED_INSTALL_ROOTS:
        pairs.append(("configured (pathguard.CONFIGURED_INSTALL_ROOTS)", value))

    env_value = os.environ.get(ENV_INSTALL_DIR)
    if env_value and env_value.strip():
        pairs.append(("%s environment variable" % ENV_INSTALL_DIR, env_value))

    for value in _install_dirs_from_local_config(root):
        pairs.append((LOCAL_CONFIG_RELPATH, value))
    for value in _install_dirs_from_builds(root):
        pairs.append(("recorded discovery result under %s" % BUILDS_RELPATH, value))

    return pairs


def protected_roots(
    install_root: str | None = None,
    *,
    out_path: str | None = None,
    repo_root: str | None = None,
) -> list[tuple[str, str]]:
    """(source, resolved root) pairs that *out_path* must not fall inside.

    The named root comes first so that the message a caller most likely expects
    is the one it gets; duplicates (the usual case -- the named root is also the
    configured one) are collapsed on their normal-cased resolved form.
    """
    pairs: list[tuple[str, str]] = []
    if install_root is not None and str(install_root).strip():
        pairs.append(("--install-dir / caller-supplied root", str(install_root)))
    if out_path is not None:
        for candidate in structural_install_roots(out_path):
            pairs.append((
                "detected installation above the output path (plan.md 2.1 step 6)",
                candidate,
            ))
    pairs.extend(known_install_roots(repo_root))

    resolved: list[tuple[str, str]] = []
    seen: set[str] = set()
    for source, value in pairs:
        try:
            real = resolve_real(value)
        except ValueError:
            continue
        key = os.path.normcase(real)
        if key in seen:
            continue
        seen.add(key)
        resolved.append((source, real))
    return resolved


def hard_link_count(resolved: str) -> int:
    """How many directory entries name *resolved*, or 1 when that is unknowable.

    Only meaningful for an existing regular file. A path that does not exist yet
    cannot be a hard link to anything -- creating the link would create the path
    -- and a directory cannot be hard-linked on NTFS, so both answer 1. An
    unreadable path also answers 1: the containment check above is the thing that
    protects it, and a stat failure must not turn into a spurious refusal.
    """
    try:
        if not os.path.isfile(resolved):
            return 1
        return max(1, int(os.stat(resolved).st_nlink))
    except (OSError, ValueError, AttributeError):
        return 1


def check_output_path(
    out_path: str,
    install_root: str | None,
    *,
    what: str = "output path",
    repo_root: str | None = None,
) -> str:
    """Return the resolved *out_path*, or raise if it is inside an installation.

    Call this before creating, opening or truncating anything. The returned
    string is the resolved path and is safe to write to as far as layer 1 is
    concerned; callers may use it instead of the raw argument so that logs and
    JSON reports record the same path that was checked.

    *install_root* is the root the invocation names and is required: a caller
    that does not know which tree it is working on is a bug, not a licence to
    skip the check. It is only the *first* of the protected roots -- see the
    module docstring -- so passing the wrong one no longer disables the guard.
    """
    if install_root is None or not str(install_root).strip():
        raise ValueError("install_root must be a non-empty path")

    resolved_out = resolve_real(out_path)
    out_key = os.path.normcase(resolved_out)

    for source, root in protected_roots(
        install_root, out_path=resolved_out, repo_root=repo_root
    ):
        if _is_inside_keys(out_key, os.path.normcase(root)):
            raise OutputPathRefused(
                # %s, not %r: repr() doubles every backslash in a Windows path, which
                # makes the offending path harder to recognize in a log.
                'refusing to write inside the game installation: %s "%s" resolves to '
                "%s, which is inside the installation root %s (protected because: %s). "
                "The installation is a read-only research target (plan.md decision "
                "D-01; safety model 1.5, layer 1: no tool accepts a path inside the "
                "installation as an output path). Nothing was written. Choose a path "
                "under the repository (research/, workspace/) instead."
                % (what, str(out_path), resolved_out, root, source)
            )

    # A hard link resolves to itself, so the loop above cannot see through one:
    # <safe>\out.json and <install>\...\global.utoc can be the same file, and
    # opening the first with mode "w" truncates the second. Refuse an output path
    # that already carries more than one name -- see the module docstring.
    links = hard_link_count(resolved_out)
    if links > 1:
        raise OutputPathRefused(
            'refusing to write through a multiply-linked path: %s "%s" resolves to '
            "%s, which already has %d names (hard links). A path comparison cannot "
            "prove that the other name lies outside the game installation -- a hard "
            "link has no target to resolve -- so this write could truncate a file "
            "inside the installation while looking harmless. The installation is a "
            "read-only research target (plan.md decision D-01; safety model 1.5, "
            "layer 1). Nothing was written. Delete that path or write under a fresh "
            "name under the repository (research/, workspace/)."
            % (what, str(out_path), resolved_out, links)
        )
    return resolved_out
