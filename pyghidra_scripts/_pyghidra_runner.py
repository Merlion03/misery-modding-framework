#!/usr/bin/env python3
"""Shared PyGhidra driver for S-03/S-04/S-05 (plan.md §7.3, §7.2).

Why this file lives in ``pyghidra_scripts/`` and not ``tools/static/``
-----------------------------------------------------------------------
The task that produced this module named ``tools/static/pyghidra_runner.py``
as its suggested location, "or wherever you land the shared driver". The
project's own hard rule 2 says otherwise: "Tools under tools/ and
pyghidra_scripts/ are STANDARD LIBRARY ONLY (pyghidra_scripts/ additionally
uses the Ghidra/PyGhidra API, which is the whole point of that directory)".
The PyGhidra-API carve-out is written against ``pyghidra_scripts/`` BY NAME,
not against "whichever directory the driver happens to live in" -- so a
driver that imports ``pyghidra``/``jpype`` belongs here, not under
``tools/static/``, which stays import-clean of both. Everything in this file
that IS standard library (path guarding, JSON shape, argument parsing) could
have lived in ``tools/``; everything that makes it worth writing (opening a
program through PyGhidra) could not. Splitting the two would have meant two
files importing each other across the boundary for no benefit, so the whole
module sits on the PyGhidra side of the line.

What problem this solves
-------------------------
S-03, S-04 and S-05 (``dump_xrefs_for_string.py``, ``dump_function.py``,
``dump_callgraph.py``) all need the same four things before they can ask
Ghidra anything: the pinned JDK, the four redirected containment directories,
a verified copy of the target binary, and a live ``Program`` object opened
from the ALREADY-ANALYSED project at
``D:\\Tools\\ghidra-projects\\T05-primary-default-analysis`` without
re-importing or re-analysing it (that analysis cost 5717 s / 95 min once,
measured by T-05, and re-spending it per script would waste the wave). Writing
that four times would drift the way any copy-pasted safety check drifts
(pathguard's own docstring is written about exactly this failure mode).  This
module writes it once, mirroring ``tools/static/ghidra_import.py``'s JDK-pin
and containment functions (imported below, not copied) and adding the one
thing ``ghidra_import.py`` deliberately does NOT do: hold a live, in-process
``Program`` for a script to read from.

The mechanism, and the one that does NOT work (found by reading Java source,
not by trial and error)
------------------------------------------------------------------------------
The task described driving these scripts through
``analyzeHeadless <project> <name> -process <program> -noanalysis
-scriptPath <dir> -postScript <script.py> <args>``, the same shape
``tools/static/ghidra_import.py`` already uses for
``ghidra_scripts/SetAnalyzerSet.java``. That shape works for a **Java**
``-preScript``/``-postScript``. It does **not** work for a **Python**
``-postScript`` run through plain ``analyzeHeadless.bat``, and this was
verified by reading ``ghidra.pyghidra.PyGhidraScriptProvider`` (decompiled
from ``PyGhidra-src.zip``) rather than by a failing run: its
``getScriptInstance`` throws
``"Ghidra was not started with PyGhidra. Python is not available"`` whenever
its static ``scriptRunner`` field is unset, and that field is set from
Python-side code (``pyghidra.internal.plugin.plugin.setup_plugin()``,
called only from ``PyGhidraLauncher._pre_launch_init()``) -- which never runs
inside the plain-Java bootstrap that ``support\\analyzeHeadless.bat`` performs
via ``launch.bat``. A pure-Java ``analyzeHeadless.bat -postScript foo.py``
would reach that provider with ``scriptRunner`` still ``None`` and fail with
that exact message before a single line of ``foo.py`` ran.

The mechanism that DOES work, and that this module uses, is the *other*
direction: **Python embeds the JVM** (the direction ``docs/toolchain.md``
§8.2 already verified with ``pyghidra.start()`` + version query), not "the
JVM embeds Python". Concretely: ``pyghidra.start()`` (a thin wrapper around
``pyghidra.launcher.HeadlessPyGhidraLauncher``) boots the JVM and Ghidra's
headless application state entirely from this Python process; once started,
``pyghidra.open_project(root, name, create=False)`` opens the EXISTING
project directory tree (verified present:
``D:\\tools\\ghidra-projects\\T05-primary-default-analysis.{gpr,rep}``,
2.0 GiB) without importing anything, and ``pyghidra.program_context(project,
path)`` opens the named domain file (``/MISERY-Win64-Shipping.exe``) as a
``Program`` -- again without triggering analysis, because that function never
calls ``AutoAnalysisManager`` at all (contrast the *deprecated*
``pyghidra.open_program()``/``run_script()``, which do, and which also call
``project.save(program)`` on the way out -- both are avoided here on purpose:
a read-only tool must not analyse and must not save). This was proved against
the real project, not assumed: see ``research/evidence/S-03/README.md`` for
the timed, logged run (JVM start + project open + program open + close, ~9 s
total, project files unchanged in content -- only ``project.prp`` and
``versioned/~index.dat`` had their mtime touched by Ghidra's own
open/close bookkeeping, confirmed by re-reading both before and after).

``launcher.java_home`` is set with the property SETTER, never read through the
getter, and this is deliberate rather than stylistic: the getter's fallback
path invokes ``LaunchSupport -jdk_home -save``, and ``-save`` WRITES the
chosen JDK into ``<ghidra-install>\\support\\launch.properties`` -- inside the
Ghidra installation directory, which matches neither
``D:\\Dev\\MiseryFramework`` nor the ``D:\\Tools\\ghidra-*``/
``D:\\Tools\\venv-research`` exception this project's tools are confined to
(the installation is ``D:\\Tools\\ghidra_12.1.3_PUBLIC``, an underscored name
that the ``ghidra-*`` glob does not match). Setting ``.java_home`` directly
before ``.start()`` short-circuits that whole branch and never touches the
installation directory. Verified: a run of this module never changes any file
under ``D:\\Tools\\ghidra_12.1.3_PUBLIC``.

Containment and JDK pinning are REUSED, not reimplemented
-----------------------------------------------------------
``ghidra_import.probe_jdk`` (spawns the pinned ``java -version`` and parses
the banner; refuses anything other than major version 21 -- plan.md 17.1a /
A-15) and ``ghidra_import.build_vm_options``/``ensure_containment`` (the four
``-D...`` properties that keep settings/cache/temp off C:, which has ~1-4 GiB
free on this machine) are imported from ``tools/static/ghidra_import.py`` and
handed to ``pyghidra``'s launcher as ``launcher.vm_args``, exactly the hook
``pyghidra.__main__`` itself uses for ``-D``/``-X`` passthrough. This is the
same containment recipe ``ghidra_import.py`` uses for ``analyzeHeadless.bat``,
applied to a differently-launched JVM: the four system properties mean the
same thing to Ghidra regardless of which process set them.

Read-only by construction
--------------------------
``open_existing_program`` never opens a transaction on the returned
``Program`` and never calls ``project.save()``. A script built on top of this
module that calls ``program.startTransaction(...)`` is doing something this
module was not designed for and the safety property documented above no
longer holds for it -- none of S-03/S-04/S-05 do this.

C-13 (public repository) as it applies to what these scripts can emit
------------------------------------------------------------------------
Everything here can emit is METADATA about the binary (addresses, sizes,
counts, Ghidra-assigned names, reference types) plus SHORT literal reads
(a needle string, a handful of bytes) -- never a bulk verbatim reconstruction
of proprietary content. The precedent is S-01 (``research/evidence/S-01/
README.md``): counts, hashes and a bounded number of literal samples are
committed; the bulk extract is not. Decompiled C-like pseudocode in
particular is NOT written into ``research/evidence/`` in full by the tools
in this module's family -- S-04's own module docstring explains why and what
it writes instead (a hash and a bounded excerpt).

Determinism
-----------
Every document built through :func:`build_document` takes an explicit
``recorded_at`` (ISO-8601 UTC). Passing the SAME value on two runs against
the same project/target makes the two JSON documents byte-identical, which is
a stronger and cheaper check than diffing "everything except one volatile
field" -- and it is the same idiom ``research/reflection/*/`` (RF-01,
``--recorded-at``) already established for this project. Leaving it unset
timestamps the run as it actually happened, which is what a single real run
should do.

Standard library plus ``pyghidra``/``jpype1`` (both installed in
``D:\\Tools\\venv-research``, plan.md 17.1/8.2). Import this module, and run
anything that calls :func:`open_existing_program`, with
``D:\\Tools\\venv-research\\Scripts\\python.exe`` -- :func:`require_pyghidra`
gives a clear, actionable error rather than an ``ImportError`` traceback if
run under any other interpreter.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Iterator

_HERE = os.path.dirname(os.path.abspath(__file__))              # pyghidra_scripts/
_REPO = os.path.dirname(_HERE)                                    # repo root
_TOOLS_STATIC = os.path.join(_REPO, "tools", "static")
_TOOLS_INVENTORY = os.path.join(_REPO, "tools", "inventory")
for _extra in (_TOOLS_STATIC, _TOOLS_INVENTORY):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

# Stdlib-only imports from tools/static and tools/inventory. Reused, not
# copied: JDK pinning and containment must stay defined in exactly one place
# (pathguard's own docstring is written about precisely this drift).
import ghidra_import as _gi  # noqa: E402
import pathguard  # noqa: E402

GENERATOR_NAME = "pyghidra_scripts/_pyghidra_runner.py"
GENERATOR_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# defaults -- this project's one known-good project/target, all overridable
# ---------------------------------------------------------------------------

DEFAULT_GHIDRA_ROOT = _gi.DEFAULT_GHIDRA_ROOT
DEFAULT_JDK_HOME = _gi.DEFAULT_JDK_HOME
DEFAULT_CONTAINMENT_ROOT = _gi.DEFAULT_CONTAINMENT_ROOT
DEFAULT_PROJECT_ROOT = _gi.DEFAULT_PROJECT_ROOT
REQUIRED_JDK_MAJOR = _gi.REQUIRED_JDK_MAJOR

# The T-05 default-analysis project this wave reuses (task instructions;
# verified present, 2.0 GiB, before this module was written).
DEFAULT_PROJECT_NAME = "T05-primary-default-analysis"
DEFAULT_PROGRAM_PATH = "/MISERY-Win64-Shipping.exe"

# The verified analysis copy the T05 project was imported from, and the
# build_key it must hash to (S-01/RF-01/T-05 all cite the same digest).
DEFAULT_TARGET_COPY = os.path.join(DEFAULT_CONTAINMENT_ROOT, "bin",
                                   "MISERY-Win64-Shipping.exe")
DEFAULT_EXPECT_SHA256 = (
    "0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383"
)
DEFAULT_BUILD_KEY = "sha256:" + DEFAULT_EXPECT_SHA256

DEFAULT_MAXMEM = "2G"
DEFAULT_DECOMPILE_TIMEOUT_SECONDS = 60

# Reused verbatim: sorted keys, indent 2, LF, UTF-8, trailing newline --
# ghidra_import.py's own determinism section explains why.
dump_json = _gi.dump_json
now_iso_utc = _gi.now_iso_utc
sha256_file = _gi.sha256_file
sha256_text = _gi.sha256_text


def dump_jsonl(records: list[dict]) -> str:
    """One sorted-keys JSON object per line, LF, trailing newline -- JSONL
    sibling of :data:`dump_json`, same rationale (diffable text, plan.md 7.2).
    """
    import json
    lines = [json.dumps(r, sort_keys=True, ensure_ascii=False) for r in records]
    return "\n".join(lines) + ("\n" if lines else "")


class PrerequisiteError(Exception):
    """A precondition was not met; nothing was started. Mirrors
    ``ghidra_import.PrerequisiteError`` (kept as a separate class rather than
    imported, so a caller can catch each module's failures independently;
    both are handled identically by every script's ``main()``)."""


class PyGhidraUnavailable(PrerequisiteError):
    """``pyghidra``/``jpype`` are not importable under the running
    interpreter."""


def require_pyghidra() -> None:
    """Raise :class:`PyGhidraUnavailable` with an actionable message, or
    return. Called before anything else touches ``pyghidra``/``jpype`` so a
    wrong-interpreter run fails with a one-line fix instead of a traceback
    three imports deep."""
    try:
        import jpype  # noqa: F401
        import pyghidra  # noqa: F401
    except ImportError as error:
        raise PyGhidraUnavailable(
            "pyghidra/jpype are not importable under this interpreter (%s). "
            "Run this tool with the canonical interpreter instead: "
            "D:\\Tools\\venv-research\\Scripts\\python.exe, which has "
            "pyghidra 3.1.0 and jpype1 1.7.1 installed (plan.md §17.1/§8.2). "
            "Underlying error: %s" % (sys.executable, error)
        ) from error


# ---------------------------------------------------------------------------
# target-copy verification (task requirement: verify before touching it)
# ---------------------------------------------------------------------------

def verify_target_copy(copy_path: str, expect_sha256: str | None) -> dict:
    """Hash *copy_path* and compare to *expect_sha256*. Raise on mismatch or
    a missing file; never silently proceeds. This is a chain-of-custody check
    on the artifact the reused Ghidra project claims to have been imported
    from -- opening the project itself does not touch this file at all (the
    analysed database is self-contained), so this is what stands between "we
    are looking at the T05 project" and "we are looking at the T05 project,
    which really was built from the 0eef3715... build".
    """
    if not os.path.isfile(copy_path):
        raise PrerequisiteError(
            "analysis copy not found: %s. This should be the verified copy "
            "an earlier ghidra_import.py run made under "
            "D:\\Tools\\ghidra-workspace\\bin\\ -- it is not re-created here "
            "on purpose (a missing copy means the chain of custody to the "
            "build_key is broken, and a fresh copy would not fix that)."
            % copy_path)
    digest = sha256_file(copy_path)
    matches = expect_sha256 is None or digest.lower() == expect_sha256.lower()
    record = {
        "path": copy_path,
        "bytes": os.path.getsize(copy_path),
        "sha256": digest,
        "sha256_expected": expect_sha256,
        "sha256_matches": matches,
    }
    if not matches:
        raise PrerequisiteError(
            "sha256 mismatch on the analysis copy: %s hashes to %s but %s "
            "was expected (build_key). Refusing to proceed -- the reused "
            "Ghidra project would not provably be about the build this run "
            "claims. Nothing was started." % (copy_path, digest, expect_sha256))
    return record


# ---------------------------------------------------------------------------
# opening the existing, already-analysed program
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def open_existing_program(
    project_root: str = DEFAULT_PROJECT_ROOT,
    project_name: str = DEFAULT_PROJECT_NAME,
    program_path: str = DEFAULT_PROGRAM_PATH,
    *,
    ghidra_root: str = DEFAULT_GHIDRA_ROOT,
    jdk_home: str = DEFAULT_JDK_HOME,
    containment_root: str = DEFAULT_CONTAINMENT_ROOT,
    maxmem: str = DEFAULT_MAXMEM,
    verbose: bool = False,
    install_root: str | None = None,
    repo_root: str | None = None,
) -> Iterator[tuple[Any, Any]]:
    """Yield ``(project, program)`` for the ALREADY-ANALYSED program at
    *program_path* inside the existing project *project_name* under
    *project_root*. Imports/analyses nothing. See the module docstring for
    the mechanism and why the ``analyzeHeadless -postScript`` shape is not
    used here.

    Raises :class:`PyGhidraUnavailable` if ``pyghidra``/``jpype`` are not
    importable, :class:`ghidra_import.PrerequisiteError` if the pinned JDK is
    missing or the wrong major version, and lets any ``pyghidra``-raised
    error (project not found, program not found in the project) propagate --
    those are Ghidra's own diagnostics and rewrapping them would only lose
    information.
    """
    require_pyghidra()
    _gi.probe_jdk(jdk_home)  # raises PrerequisiteError on wrong/missing JDK
    _gi.ensure_containment(containment_root, install_root=install_root,
                           repo_root=repo_root)
    vm_options = _gi.build_vm_options(containment_root, maxmem=maxmem)

    import pyghidra
    from pyghidra.launcher import HeadlessPyGhidraLauncher

    if not pyghidra.started():
        launcher = HeadlessPyGhidraLauncher(verbose=verbose, install_dir=ghidra_root)
        # Property SETTER only -- see module docstring "the getter's fallback
        # path invokes LaunchSupport -save", which writes inside the Ghidra
        # installation directory. This line is the whole reason that never
        # happens.
        launcher.java_home = jdk_home
        launcher.vm_args = launcher.vm_args + ["-Xmx" + maxmem] + vm_options
        launcher.start()

    project = pyghidra.open_project(str(project_root), str(project_name), create=False)
    try:
        with pyghidra.program_context(project, str(program_path)) as program:
            yield project, program
    finally:
        project.close()


# ---------------------------------------------------------------------------
# address / function resolution shared by S-04 and S-05
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r"^(0[xX])?[0-9A-Fa-f]+$")


def parse_address(program: Any, text: str):
    """Resolve *text* to a Ghidra ``Address`` in *program*.

    Accepts Ghidra's own ``Address.toString()`` form (bare hex, e.g.
    ``140001d70``, as printed throughout this project's evidence and by
    Ghidra itself) and a ``0x``-prefixed form for convenience; the ``0x``
    prefix is stripped before handing the string to
    ``AddressFactory.getAddress`` because Ghidra's own parser does not
    recognise it. Raises :class:`ValueError` naming the input if Ghidra
    cannot resolve it -- never returns ``None`` silently.
    """
    raw = str(text).strip()
    if not raw:
        raise ValueError("empty address string")
    candidate = raw[2:] if raw[:2] in ("0x", "0X") else raw
    if not _HEX_RE.match(candidate):
        raise ValueError(
            "%r does not look like a hex address (accepted forms: "
            "'140001d70', '0x140001d70')" % text)
    addr = program.getAddressFactory().getAddress(candidate)
    if addr is None:
        raise ValueError(
            "Ghidra's AddressFactory could not resolve %r (tried %r) in "
            "this program's address spaces" % (text, candidate))
    return addr


def resolve_function(program: Any, spec: str):
    """Resolve *spec* to a Ghidra ``Function``: by hex address (entry point
    or any address inside the function body) if it parses as one, else by
    exact symbol name via the function manager's name search. Raises
    :class:`ValueError` naming what was tried if nothing resolves.
    """
    fm = program.getFunctionManager()
    looks_hex = bool(_HEX_RE.match(spec[2:] if spec[:2] in ("0x", "0X") else spec))
    if looks_hex:
        try:
            addr = parse_address(program, spec)
        except ValueError:
            addr = None
        if addr is not None:
            func = fm.getFunctionAt(addr)
            if func is None:
                func = fm.getFunctionContaining(addr)
            if func is not None:
                return func
            raise ValueError(
                "%r parses as an address but no function starts at or "
                "contains it" % spec)
    # Fall back to a name search across every function in the program.
    # getFunctions(String, String) needs a namespace; global scope in Ghidra's
    # API is expressed as null, which jpype accepts as Python None here.
    matches = []
    for func in fm.getFunctions(True):
        if func.getName() == spec:
            matches.append(func)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ValueError(
            "%d functions are named %r (ambiguous); use one of their "
            "addresses instead: %s"
            % (len(matches), spec,
               ", ".join(str(f.getEntryPoint()) for f in matches[:10])))
    raise ValueError(
        "%r did not resolve as a hex address or as an exact function name"
        % spec)


def describe_function_brief(func: Any) -> dict:
    """The small, address/name-only shape used for "containing function" /
    "callee" / "caller" fields across S-03/S-04/S-05, so the three scripts
    describe a function identically."""
    if func is None:
        return None
    return {
        "name": func.getName(),
        "entry": str(func.getEntryPoint()),
        "is_thunk": bool(func.isThunk()),
        "is_external": bool(func.isExternal()),
    }


# ---------------------------------------------------------------------------
# reference-type classification, shared by S-03 (xrefs) and S-05 (callgraph)
# ---------------------------------------------------------------------------

# Ghidra's RefType carries many refined subtypes (UNCONDITIONAL_CALL,
# COMPUTED_CALL, CONDITIONAL_JUMP, ...). The task asks for "DATA, READ, WRITE,
# CALL as Ghidra classifies it" -- read literally as "report Ghidra's own
# classification", not as "force every reference into exactly one of four
# buckets" (Ghidra's own model does not do that; RefType.isCall() and
# RefType.isFlow() are independent predicates, not a partition). Both are
# reported: `name` is RefType.getName() verbatim (Ghidra's own string, e.g.
# "DATA", "READ", "WRITE", "UNCONDITIONAL_CALL"), and `bucket` is the coarse
# DATA/READ/WRITE/CALL/JUMP/OTHER grouping the task's own wording names,
# derived from the is*() predicates so a consumer that wants the simple
# answer does not have to know Ghidra's subtype vocabulary.
def classify_ref_type(ref_type: Any) -> dict:
    is_call = bool(ref_type.isCall())
    is_jump = bool(ref_type.isJump())
    is_data = bool(ref_type.isData())
    is_read = bool(ref_type.isRead())
    is_write = bool(ref_type.isWrite())
    if is_call:
        bucket = "CALL"
    elif is_write:
        bucket = "WRITE"
    elif is_read:
        bucket = "READ"
    elif is_data:
        bucket = "DATA"
    elif is_jump:
        bucket = "JUMP"
    else:
        bucket = "OTHER"
    return {
        "name": ref_type.getName(),
        "bucket": bucket,
        "is_call": is_call,
        "is_jump": is_jump,
        "is_data": is_data,
        "is_read": is_read,
        "is_write": is_write,
        "is_flow": bool(ref_type.isFlow()),
        "is_computed": bool(ref_type.isComputed()),
        "is_conditional": bool(ref_type.isConditional()),
    }


# ---------------------------------------------------------------------------
# shared CLI plumbing
# ---------------------------------------------------------------------------

def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    """The Ghidra-project/JDK/containment/target-copy flag group shared by
    every script in this family. Tool-specific arguments (needle, function
    spec, depth, output paths) are added by each script after calling this.
    """
    g = parser.add_argument_group("ghidra project (defaults: T05 default-analysis)")
    g.add_argument("--project-root", default=DEFAULT_PROJECT_ROOT,
                   help="Ghidra project root directory")
    g.add_argument("--project-name", default=DEFAULT_PROJECT_NAME,
                   help="Ghidra project name (no extension)")
    g.add_argument("--program", default=DEFAULT_PROGRAM_PATH,
                   help="domain file path of the program inside the project")
    g.add_argument("--ghidra-root", default=DEFAULT_GHIDRA_ROOT,
                   help="Ghidra installation directory")
    g.add_argument("--jdk-home", default=DEFAULT_JDK_HOME,
                   help="JDK to pin; major version must be %d" % REQUIRED_JDK_MAJOR)
    g.add_argument("--containment-root", default=DEFAULT_CONTAINMENT_ROOT,
                   help="root of the redirected settings/cache/temp directories")
    g.add_argument("--maxmem", default=DEFAULT_MAXMEM,
                   help="JVM heap (-Xmx) for this read-only run")
    g.add_argument("--verbose", action="store_true",
                   help="verbose JVM/Ghidra startup output on stderr")
    g.add_argument("--install-dir", default=None,
                   help="installation root the output-path guard checks against")

    t = parser.add_argument_group("target-copy verification (task requirement)")
    t.add_argument("--target-copy", default=DEFAULT_TARGET_COPY,
                   help="the analysis copy the reused project was imported from")
    t.add_argument("--expect-sha256", default=DEFAULT_EXPECT_SHA256, metavar="HEX",
                   help="sha256 --target-copy must have; refuses to proceed on mismatch")
    t.add_argument("--skip-copy-verification", action="store_true",
                   help=("skip the target-copy hash check (for tests / non-T05 "
                        "projects only -- never skip this against the real project)"))

    d = parser.add_argument_group("determinism")
    d.add_argument("--recorded-at", default=None, metavar="ISO8601",
                   help=("fix generated_at to this value instead of now(); pass the "
                        "SAME value on two runs to get byte-identical JSON, the "
                        "determinism proof this tool family uses"))


def open_program_from_args(args: argparse.Namespace):
    """``open_existing_program`` wired from the common argument group above,
    after verifying the target copy (unless explicitly skipped)."""
    if not args.skip_copy_verification:
        verify_target_copy(args.target_copy, args.expect_sha256)
    return open_existing_program(
        args.project_root, args.project_name, args.program,
        ghidra_root=args.ghidra_root, jdk_home=args.jdk_home,
        containment_root=args.containment_root, maxmem=args.maxmem,
        verbose=args.verbose, install_root=args.install_dir)


def recorded_at(args: argparse.Namespace) -> str:
    return args.recorded_at if args.recorded_at else now_iso_utc()


def write_json_guarded(document: dict, out_path: str,
                       install_root: str | None, what: str,
                       *, repo_root: str | None = None) -> str:
    """``dump_json(document)`` written to *out_path*, refusing any path
    inside an installation (layer 1, D-01) -- the same guard every writer in
    this repository goes through before opening a file."""
    target = pathguard.check_output_path(
        out_path, install_root or pathguard.CONFIGURED_INSTALL_ROOTS[0],
        what=what, repo_root=repo_root)
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dump_json(document))
    return target


def write_jsonl_guarded(records: list[dict], out_path: str,
                        install_root: str | None, what: str,
                        *, repo_root: str | None = None) -> str:
    target = pathguard.check_output_path(
        out_path, install_root or pathguard.CONFIGURED_INSTALL_ROOTS[0],
        what=what, repo_root=repo_root)
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dump_jsonl(records))
    return target


def handle_prerequisite_errors(func):
    """Decorator for a script's ``main(argv) -> int``: catches the error
    types every script in this family can raise while resolving arguments,
    verifying the target copy, or opening the program, prints ``error: ...``
    to stderr and returns 2 -- mirrors ``ghidra_import.main``'s own
    try/except shape so all four tools fail the same way."""
    import functools

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (PrerequisiteError, pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2
        except OSError as error:
            print("error: %s" % error, file=sys.stderr)
            return 2
    return wrapper
