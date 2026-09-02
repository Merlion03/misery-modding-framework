#!/usr/bin/env python3
"""Build the Stage 5 native pieces with MSVC.

Kept as a module rather than a shell script because the batch file has to be
written with CRLF endings and invoked through cmd from its own directory -- the
recipe the existing probe-DLL build already proved on this machine. A .sh or a
LF batch file does not run here, and finding that out again each time is waste.
"""
import os
import subprocess

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VCVARS = r"D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
VCVARS_VER = "14.38"
BUILD_DIR = os.path.join(REPO, "workspace", "msvc-stage5")

# The .NET hosting headers and import library. Pinned to the 8.0 pack because
# that is the runtime the managed host targets; the 10.0 pack is present too and
# choosing implicitly would make the build depend on which SDK was installed
# last.
DOTNET_PACK = (r"C:\Program Files\dotnet\packs\Microsoft.NETCore.App.Host.win-x64"
               r"\8.0.25\runtimes\win-x64\native")

UE_RUNTIME = r"D:\Program Files\UE_5.4\Engine\Source\Runtime"

# The same definitions the proven probe build uses. They make the UE headers
# compile standalone, without a UBT module.
UE_DEFINES = (
    "/DPLATFORM_WINDOWS=1 /DPLATFORM_MICROSOFT=1 /DPLATFORM_64BITS=1 "
    "/DUE_BUILD_SHIPPING=1 /DUE_BUILD_DEVELOPMENT=0 /DUE_BUILD_TEST=0 "
    "/DUE_BUILD_DEBUG=0 /DWITH_EDITOR=0 /DWITH_EDITORONLY_DATA=0 "
    "/DWITH_ENGINE=0 /DWITH_SERVER_CODE=1 /DWITH_UNREAL_DEVELOPER_TOOLS=0 "
    "/DWITH_PLUGIN_SUPPORT=0 /DWITH_ACCESSIBILITY=0 /DIS_MONOLITHIC=1 "
    "/DIS_PROGRAM=0 /DCORE_API= /DCOREUOBJECT_API= /DTRACELOG_API= "
    "/DUNICODE /D_UNICODE /DPLATFORM_EXCEPTIONS_DISABLED=0 "
    "/D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DNTDDI_VERSION=0x0A000000 "
    "/DUBT_COMPILED_PLATFORM=Windows /DOVERRIDE_PLATFORM_HEADER_NAME=Windows")

UE_INCLUDES = ('/I"{0}\\Core\\Public" /I"{0}\\TraceLog\\Public" '
               '/I"{0}\\Core\\Internal"'.format(UE_RUNTIME))


class BuildError(Exception):
    pass


def _run_batch(name, lines, cwd=None):
    os.makedirs(BUILD_DIR, exist_ok=True)
    path = os.path.join(BUILD_DIR, name)
    with open(path, "w", newline="\r\n") as handle:
        handle.write("\r\n".join(lines) + "\r\n")
    result = subprocess.run([path], capture_output=True, text=True,
                            cwd=cwd or BUILD_DIR, shell=True)
    return result


# Compiler warnings that are treated as build failures.
#
# Not a style list. Each of these means the compiler silently produced something
# other than what the source says, so a "successful" build is a build that did
# the wrong thing quietly.
#
# C4129 earned its place: five path literals in ManagedHost.cpp were written
# with single backslashes ("\Mods"), MSVC dropped each unrecognised escape, the
# DLL linked, and the runtime looked for its mods in a directory whose name had
# no separator in it. The compiler did warn. Nobody saw it, because output was
# shown only when a build FAILED.
FATAL_WARNINGS = {
    "C4129": "unrecognised escape sequence -- the compiler dropped a backslash",
}


def _check_warnings(out_name, result):
    """Surface compiler warnings from a build that otherwise succeeded."""
    warnings = [line for line in (result.stdout or "").splitlines()
                if ": warning C" in line]
    if not warnings:
        return
    fatal = [line for line in warnings
             if any(code in line for code in FATAL_WARNINGS)]
    for line in warnings:
        print("  build warning: " + line.strip())
    if fatal:
        raise BuildError(
            "%s compiled, but with %d warning(s) meaning the compiler did not "
            "build what the source says:\n%s"
            % (out_name, len(fatal), "\n".join(fatal)))


def build_exe(sources, out_name, extra=""):
    """A standalone host-side test executable."""
    out = os.path.join(BUILD_DIR, out_name)
    if os.path.isfile(out):
        os.remove(out)
    quoted = " ".join('"%s"' % s for s in sources)
    lines = [
        "@echo off",
        'call "%s" -vcvars_ver=%s >nul 2>&1' % (VCVARS, VCVARS_VER),
        'cl /nologo /EHsc /std:c++17 /MT %s %s /Fe:"%s" /link /INCREMENTAL:NO'
        % (extra, quoted, out),
    ]
    result = _run_batch("_build_%s.bat" % out_name.replace(".", "_"), lines)
    if not os.path.isfile(out):
        raise BuildError("%s did not build:\n%s\n%s"
                         % (out_name, result.stdout[-4000:], result.stderr[-2000:]))
    # Test executables are held to the same standard as the DLL.
    #
    # They were not, and that cost exactly what FATAL_WARNINGS exists to
    # prevent: discovery_harness.cpp wrote a path as "\\*" with one backslash,
    # MSVC dropped the unrecognised escape, and the harness's cleanup silently
    # swept a directory that did not exist. C4129 WAS emitted. Nobody saw it,
    # because this was the one build path that never looked. A guard covering
    # some of the builds is a guard that will be missing from the one that
    # matters.
    _check_warnings(out_name, result)
    return out


def build_dll(sources, out_name, extra="", libs=""):
    """The runtime DLL that gets loaded into MISERY."""
    out = os.path.join(BUILD_DIR, out_name)
    if os.path.isfile(out):
        os.remove(out)
    quoted = " ".join('"%s"' % s for s in sources)
    lines = [
        "@echo off",
        'call "%s" -vcvars_ver=%s >nul 2>&1' % (VCVARS, VCVARS_VER),
        'cl /nologo /LD /MT /EHsc /std:c++17 %s %s %s /Fe:"%s" /link '
        '/INCREMENTAL:NO %s' % (UE_DEFINES, UE_INCLUDES + " " + extra, quoted,
                                out, libs),
    ]
    result = _run_batch("_build_%s.bat" % out_name.replace(".", "_"), lines)
    if not os.path.isfile(out):
        raise BuildError("%s did not build:\n%s\n%s"
                         % (out_name, result.stdout[-6000:], result.stderr[-2000:]))
    _check_warnings(out_name, result)
    return out


# WHAT MiseryRuntime.dll IS MADE OF -- stated ONCE.
#
# This list drifted three times between an ad-hoc build and the acceptance
# script that ships the artifact, and each time the symptom was an unresolved
# external minutes into a run that had already launched the game. A list that
# lives in two places is a list that will disagree with itself.
#
# Anything that builds the production runtime imports this. Adding a translation
# unit means adding it here, and nothing else.
MISERY_RUNTIME_SOURCES = (
    "RuntimeBootstrap.cpp",     # the proxy's entry point and the lifecycle
    "ContentGeneration.cpp",    # published/revoked content anchors
    "ItemsBackend.cpp",         # fills the proven path from profile+generation
    "CR01C5ProbeDll.cpp",       # the proven registration path itself
    "BridgeTables.cpp",         # the frozen mod-facing bridge
    "Json.cpp",                 # the binding profile reader
    "Bindings.cpp",             # and its validation
    "Resolver.cpp",             # the object walk
    "ResolveOnGameThread.cpp",  # which runs it in bounded game-thread slices
    "UE54TickerCarrier.cpp",    # the build-specific way onto that thread
    "ManagedHost.cpp",          # CoreCLR, started from the installation
    "ModDiscovery.cpp",         # which mods that installation holds
    "ModManifest.cpp",          # Stage 4 ids, versions, manifests
    "ModResolve.cpp",           # and its deterministic load plan
)


# The offline test harnesses, and what each links against.
#
# Recorded here for the same reason the proxy's link line is: until now these
# were built by hand, so tests/ skipped silently on any machine where nobody had
# run the right cl.exe invocation from memory. A test that quietly does not run
# is worse than no test, because the suite still reports green.
MISERY_TEST_HARNESSES = {
    # The JSON escaper, exposed for a differential against Python's own writer.
    # Registered here as well as built by its own test, so neither "nobody ran
    # build_harnesses" nor "the test skipped" can hide it.
    "json_escape_harness.exe": ("json_escape_harness.cpp", ("Json.cpp",)),
    # StringArena is header-only, so the harness needs no translation unit but
    # its own. It pins that an oversized reply is refused rather than answered.
    "arena_harness.exe": ("arena_harness.cpp", ()),
    # Resolver.cpp for ReadBytes: VerifyCode compares the profile's recorded
    # bytes against live memory, and that read is the resolver's.
    "bindings_harness.exe": ("bindings_harness.cpp",
                             ("Bindings.cpp", "Json.cpp", "Resolver.cpp")),
    "slot_validation_harness.exe": ("slot_validation_harness.cpp",
                                    ("Resolver.cpp",)),
    "discovery_harness.exe": ("discovery_harness.cpp",
                              ("ModDiscovery.cpp", "ModManifest.cpp",
                               "ModResolve.cpp", "Json.cpp")),
    # The differential against Stage 4's Python planner. See
    # tests/test_mod_plan.py: this is what makes "a port, not a fork" checkable.
    "mod_plan_harness.exe": ("mod_plan_harness.cpp",
                             ("ModDiscovery.cpp", "ModManifest.cpp",
                              "ModResolve.cpp", "Json.cpp")),
}


def build_harnesses(repo_root):
    """Build every offline harness. Returns {exe_name: path}."""
    internal = os.path.join(repo_root, "runtime", "MiseryRuntime", "Internal")
    tests = os.path.join(repo_root, "runtime", "tests")
    built = {}
    for out_name, (main_source, deps) in sorted(MISERY_TEST_HARNESSES.items()):
        sources = [os.path.join(tests, main_source)]
        sources += [os.path.join(internal, name) for name in deps]
        built[out_name] = build_exe(sources, out_name)
    return built


def runtime_sources(repo_root):
    """Absolute paths for MISERY_RUNTIME_SOURCES."""
    internal = os.path.join(repo_root, "runtime", "MiseryRuntime", "Internal")
    return [os.path.join(internal, name) for name in MISERY_RUNTIME_SOURCES]


def build_runtime(repo_root, out_name="MiseryRuntime.dll"):
    """The production runtime, with the nethost include and import library.

    One function so the flags cannot drift from the source list the way the
    source list already drifted from its callers three times.
    """
    return build_dll(runtime_sources(repo_root), out_name,
                     extra='/I"%s"' % DOTNET_PACK,
                     libs='"%s"' % os.path.join(DOTNET_PACK, "libnethost.lib"))


def build_proxy(boot_dir, out_name, sources, def_file, asm_file, libs=""):
    """The bootstrap proxy: assembled thunks plus C++, linked with a .def.

    Separate from build_dll because it needs ml64 and an explicit export
    definition file -- the ordinals have to match the DLL being stood in front
    of, and only a .def can pin them.
    """
    out = os.path.join(BUILD_DIR, out_name)
    if os.path.isfile(out):
        os.remove(out)
    obj = os.path.join(BUILD_DIR, "proxy_thunks.obj")
    quoted = " ".join('"%s"' % s for s in sources)
    lines = [
        "@echo off",
        'call "%s" -vcvars_ver=%s >nul 2>&1' % (VCVARS, VCVARS_VER),
        'ml64 /nologo /c /Fo"%s" "%s"' % (obj, asm_file),
        'if errorlevel 1 exit /b 1',
        'cl /nologo /LD /MT /EHsc /std:c++17 /I"%s" %s "%s" /Fe:"%s" '
        '/link /INCREMENTAL:NO /DEF:"%s" %s'
        % (boot_dir, quoted, obj, out, def_file, libs),
    ]
    result = _run_batch("_build_%s.bat" % out_name.replace(".", "_"), lines)
    if not os.path.isfile(out) or os.path.getsize(out) == 0:
        raise BuildError("%s did not build:\n%s\n%s"
                         % (out_name, result.stdout[-6000:], result.stderr[-2000:]))
    _check_warnings(out_name, result)
    return out


def run(path, timeout=300):
    return subprocess.run([path], capture_output=True, text=True, timeout=timeout,
                          cwd=BUILD_DIR)


if __name__ == "__main__":
    test = build_exe(
        [os.path.join(REPO, "runtime", "tests", "bridge_core_test.cpp")],
        "bridge_core_test.exe")
    result = run(test)
    print(result.stdout)
    if result.stderr.strip():
        print("stderr:", result.stderr[-2000:])
    raise SystemExit(result.returncode)
