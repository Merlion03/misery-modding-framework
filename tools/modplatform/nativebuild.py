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
    return out


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
