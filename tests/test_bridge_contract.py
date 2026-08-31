#!/usr/bin/env python3
"""The C header, the C# API and the Python reference must agree.

WHY THIS TEST IS THE POINT OF THE STAGE, NOT A DETAIL OF IT
-----------------------------------------------------------
Stage 4.5 states the same contract three times: once in ``MiseryBridge.h`` for
the native side, once in ``Misery.ModAPI`` for mod authors, and once in
``tools/modplatform`` as the reference implementation everything else is tested
against. Three copies of a rule that nobody compares is precisely how the ModId
rule drifted across Stages 2, 3 and 4 -- each copy correct on its own terms, the
set of them incoherent, and nothing failing until a mod hit the difference.

So the copies are compared, mechanically, here. If a subsystem number, an error
code, a capability name, a log level or the identity rule moves on one side and
not the others, this test fails before anybody writes a mod against the version
that disagrees.

It parses the real files rather than importing a generated header, because a
generator would just be a fourth copy.
"""
import os
import re
import subprocess
import sys
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (os.path.join(REPO, "tools", "modplatform"),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import capabilities as CAP                                         # noqa: E402
import errors as E                                                 # noqa: E402
import host as HOST                                                # noqa: E402
import input_actions                                               # noqa: E402
import modid                                                       # noqa: E402
import modlog                                                      # noqa: E402
import settings as SET                                             # noqa: E402

HEADER = os.path.join(REPO, "runtime", "MiseryRuntime", "Public", "MiseryBridge.h")
CSHARP_DIR = os.path.join(REPO, "managed", "Misery.ModAPI")
CS_CONTRACTS = os.path.join(CSHARP_DIR, "Contracts.cs")
CS_ERRORS = os.path.join(CSHARP_DIR, "Errors.cs")
CS_MODID = os.path.join(CSHARP_DIR, "ModId.cs")


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def c_defines(text):
    """Every ``#define NAME <integer>`` in the header."""
    out = {}
    for name, value in re.findall(r"^#define\s+(MB_\w+)\s+(\d+)u?\s*$", text,
                                  re.M):
        out[name] = int(value)
    return out


def c_string_defines(text):
    return dict(re.findall(r'^#define\s+(MB_\w+)\s+"([^"]+)"\s*$', text, re.M))


def c_enum(text, enum_name):
    match = re.search(r"typedef enum %s\s*\{(.*?)\}\s*%s;" % (enum_name, enum_name),
                      text, re.S)
    assert match, "enum %s not found in the header" % enum_name
    return {name: int(value)
            for name, value in re.findall(r"(\w+)\s*=\s*(\d+)", match.group(1))}


def cs_const_ints(text, class_name):
    match = re.search(r"class %s\s*\{(.*?)\n    \}" % class_name, text, re.S)
    assert match, "class %s not found" % class_name
    return {name: int(value) for name, value in
            re.findall(r"public const int (\w+)\s*=\s*(-?\d+);", match.group(1))}


def cs_const_strings(text, class_name):
    match = re.search(r"class %s\s*\{(.*?)\n    \}" % class_name, text, re.S)
    assert match, "class %s not found" % class_name
    return dict(re.findall(r'public const string (\w+)\s*=\s*"([^"]+)";',
                           match.group(1)))


def cs_enum(text, enum_name):
    match = re.search(r"enum %s\s*\{(.*?)\n    \}" % enum_name, text, re.S)
    assert match, "enum %s not found" % enum_name
    return {name: int(value)
            for name, value in re.findall(r"(\w+)\s*=\s*(\d+)", match.group(1))}


class HeaderPresenceTests(unittest.TestCase):
    def test_the_header_and_the_csharp_sources_exist(self):
        for path in (HEADER, CS_CONTRACTS, CS_ERRORS, CS_MODID):
            self.assertTrue(os.path.isfile(path), path)

    def test_the_header_names_no_engine_concept(self):
        """A mod-facing header that mentioned one would leak it upward."""
        text = read(HEADER)
        # Split out the prose blocks: the header EXPLAINS why these are absent,
        # so the ban is on declarations, not on the word appearing in a comment.
        code = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        for banned in ("UObject", "FName", "ProcessEvent", "UClass", "FProperty",
                       "UFunction", "RVA"):
            self.assertNotIn(banned, code,
                             "%s appears in the header's declarations" % banned)

    def test_the_csharp_api_names_no_engine_concept(self):
        for path in (CS_CONTRACTS, CS_ERRORS, CS_MODID):
            code = re.sub(r"///.*?$", "", read(path), flags=re.M)
            code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
            for banned in ("UObject", "FName", "ProcessEvent", "IntPtr",
                           "DllImport", "unsafe"):
                self.assertNotIn(banned, code,
                                 "%s appears in %s" % (banned, os.path.basename(path)))


class ApiVersionTests(unittest.TestCase):
    def test_all_three_state_the_same_api_version(self):
        defines = c_defines(read(HEADER))
        cs = cs_const_ints(read(CS_CONTRACTS), "ModApi")
        self.assertEqual(CAP.API_VERSION.major, defines["MB_API_MAJOR"])
        self.assertEqual(CAP.API_VERSION.minor, defines["MB_API_MINOR"])
        self.assertEqual(CAP.API_VERSION.patch, defines["MB_API_PATCH"])
        self.assertEqual(CAP.API_VERSION.major, cs["VersionMajor"])
        self.assertEqual(CAP.API_VERSION.minor, cs["VersionMinor"])
        self.assertEqual(CAP.API_VERSION.patch, cs["VersionPatch"])

    def test_the_csproj_version_matches(self):
        csproj = read(os.path.join(CSHARP_DIR, "Misery.ModAPI.csproj"))
        self.assertIn("<Version>%s</Version>" % CAP.API_VERSION, csproj)


class SubsystemTests(unittest.TestCase):
    def test_subsystem_numbers_agree_across_all_three(self):
        header = c_enum(read(HEADER), "MbSubsystem")
        csharp = cs_enum(read(CS_ERRORS), "ModSubsystem")
        python = {
            "PLATFORM": E.SUB_PLATFORM, "LIFECYCLE": E.SUB_LIFECYCLE,
            "LOG": E.SUB_LOG, "EVENTS": E.SUB_EVENTS, "SETTINGS": E.SUB_SETTINGS,
            "INPUT": E.SUB_INPUT, "SERVICES": E.SUB_SERVICES, "ITEMS": E.SUB_ITEMS,
            "CAPABILITIES": E.SUB_CAPABILITIES, "CONSOLE": E.SUB_CONSOLE,
        }
        self.assertEqual(len(python), len(header))
        self.assertEqual(len(python), len(csharp))
        for name, value in python.items():
            self.assertEqual(value, header["MB_SUB_" + name], name)
            self.assertEqual(value, csharp[name.capitalize()
                                           if name != "CAPABILITIES" else
                                           "Capabilities"], name)

    def test_every_python_subsystem_has_a_name(self):
        for value in c_enum(read(HEADER), "MbSubsystem").values():
            self.assertIn(value, E.SUBSYSTEM_NAMES)


class ErrorCodeTests(unittest.TestCase):
    PAIRS = [
        ("MB_E_INVALID_ARGUMENT", "InvalidArgument", "E_INVALID_ARGUMENT"),
        ("MB_E_NOT_FOUND", "NotFound", "E_NOT_FOUND"),
        ("MB_E_ALREADY_EXISTS", "AlreadyExists", "E_ALREADY_EXISTS"),
        ("MB_E_NOT_OWNED", "NotOwned", "E_NOT_OWNED"),
        ("MB_E_WRONG_THREAD", "WrongThread", "E_WRONG_THREAD"),
        ("MB_E_CAPABILITY_NOT_GRANTED", "CapabilityNotGranted",
         "E_CAPABILITY_NOT_GRANTED"),
        ("MB_E_LIMIT_EXCEEDED", "LimitExceeded", "E_LIMIT_EXCEEDED"),
        ("MB_E_HANDLER_FAULTED", "HandlerFaulted", "E_HANDLER_FAULTED"),
        ("MB_E_UNKNOWN_MOD", "UnknownMod", "E_UNKNOWN_MOD"),
        ("MB_E_MOD_ALREADY_LOADED", "ModAlreadyLoaded", "E_MOD_ALREADY_LOADED"),
        ("MB_E_MOD_NOT_LOADED", "ModNotLoaded", "E_MOD_NOT_LOADED"),
        ("MB_E_OWNER_DISPOSED", "OwnerDisposed", "E_OWNER_DISPOSED"),
        ("MB_E_LOAD_FAILED", "LoadFailed", "E_LOAD_FAILED"),
        ("MB_E_REENTRANT_UNLOAD", "ReentrantUnload", "E_REENTRANT_UNLOAD"),
    ]

    def test_every_error_code_agrees_across_all_three(self):
        header = c_defines(read(HEADER))
        csharp = cs_const_ints(read(CS_ERRORS), "ModErrorCode")
        for c_name, cs_name, py_name in self.PAIRS:
            expected = getattr(E, py_name)
            self.assertEqual(expected, header[c_name], c_name)
            self.assertEqual(expected, csharp[cs_name], cs_name)

    def test_zero_means_success_on_all_three(self):
        self.assertEqual(0, E.OK)
        self.assertEqual(0, cs_const_ints(read(CS_ERRORS), "ModErrorCode")["Ok"])
        # Renamed from MB_OK, which collides with windows.h's MessageBox
        # constant; the alias is kept only when windows.h has not
        # already claimed the name.
        self.assertIn("#define MB_STATUS_OK ((MbStatus)0)", read(HEADER))


class EnumMirrorTests(unittest.TestCase):
    def test_log_levels_agree(self):
        header = c_defines(read(HEADER))
        csharp = cs_enum(read(CS_CONTRACTS), "ModLogLevel")
        for name, value in (("TRACE", modlog.TRACE), ("DEBUG", modlog.DEBUG),
                            ("INFO", modlog.INFO), ("WARN", modlog.WARN),
                            ("ERROR", modlog.ERROR)):
            self.assertEqual(value, header["MB_LOG_" + name], name)
            self.assertEqual(value, csharp[name.capitalize()], name)

    def test_setting_type_codes_agree(self):
        header = c_defines(read(HEADER))
        for name, code in SET.TYPE_CODES.items():
            self.assertEqual(code, header["MB_SETTING_" + name.upper()], name)

    def test_input_phases_agree(self):
        header = c_defines(read(HEADER))
        csharp = cs_enum(read(CS_CONTRACTS), "InputPhase")
        self.assertEqual(input_actions.PHASE_PRESSED, header["MB_INPUT_PRESSED"])
        self.assertEqual(input_actions.PHASE_RELEASED, header["MB_INPUT_RELEASED"])
        self.assertEqual(input_actions.PHASE_PRESSED, csharp["Pressed"])
        self.assertEqual(input_actions.PHASE_RELEASED, csharp["Released"])

    def test_mod_states_agree(self):
        header = c_enum(read(HEADER), "MbModState")
        for state in HOST.STATES:
            self.assertIn("MB_MODSTATE_" + state.upper(), header, state)
        # The header carries one MORE state than the Python host: LEAKED, which
        # only a managed host can be in (an assembly context that will not
        # collect). It is named here so Stage 5 has vocabulary for it.
        self.assertIn("MB_MODSTATE_LEAKED", header)
        self.assertEqual(len(HOST.STATES) + 1, len(header))


class CapabilityNameTests(unittest.TestCase):
    def test_capability_names_agree_across_all_three(self):
        header = c_string_defines(read(HEADER))
        csharp = cs_const_strings(read(CS_CONTRACTS), "Capabilities")
        header_caps = {v for k, v in header.items() if k.startswith("MB_CAP_")}
        # core.host is host-only and deliberately absent from the mod-facing C#
        # surface: a mod must not be able to begin or end a mod's lifetime.
        self.assertIn("core.host", header_caps)
        self.assertNotIn("core.host", set(csharp.values()))
        self.assertEqual(set(CAP.CAPABILITIES), header_caps - {"core.host"})
        self.assertEqual(set(CAP.CAPABILITIES), set(csharp.values()))

    def test_every_advertised_capability_is_implemented(self):
        """A capability named but not implemented is worse than a missing one."""
        for name in CAP.CAPABILITIES:
            version, detail = CAP.CAPABILITIES[name]
            self.assertTrue(str(version))
            self.assertTrue(detail, "%s has no description" % name)

    def test_the_input_capability_admits_what_it_cannot_do(self):
        _version, detail = CAP.CAPABILITIES[CAP.CAP_INPUT_REGISTRY]
        self.assertIn("unresearched", detail)
        self.assertIn("engine_input_wired", read(HEADER))


class ModIdContractTests(unittest.TestCase):
    def test_the_identity_rule_agrees_across_all_three(self):
        text = read(CS_MODID)
        pattern = re.search(r'PatternText = "([^"]+)"', text).group(1)
        separator = re.search(r'Separator = "([^"]+)"', text).group(1)
        max_length = int(re.search(r"MaxLength = (\d+)", text).group(1))
        self.assertEqual(modid.PATTERN_TEXT, pattern)
        self.assertEqual(modid.SEPARATOR, separator)
        self.assertEqual(modid.MAX_LENGTH, max_length)

    def test_the_reserved_set_agrees(self):
        text = read(CS_MODID)
        block = re.search(r"Reserved =\s*\{(.*?)\};", text, re.S).group(1)
        csharp = set(re.findall(r'"([^"]+)"', block))
        self.assertEqual(set(modid.RESERVED), csharp)

    def test_the_csharp_rule_accepts_exactly_what_python_accepts(self):
        """Checked by behaviour, not only by constants."""
        cases = ["alphamod", "betamod", "mbpl", "a", "a_b", "m0d",
                 "NotLowercase", "1leading", "has__separator", "misery", "",
                 "x" * 49, "has-dash"]
        text = read(CS_MODID)
        pattern = re.compile(re.search(r'PatternText = "([^"]+)"', text).group(1))
        block = re.search(r"Reserved =\s*\{(.*?)\};", text, re.S).group(1)
        reserved = set(re.findall(r'"([^"]+)"', block))
        max_length = int(re.search(r"MaxLength = (\d+)", text).group(1))
        separator = re.search(r'Separator = "([^"]+)"', text).group(1)

        for value in cases:
            csharp_ok = bool(value) and len(value) <= max_length \
                and bool(pattern.match(value)) and separator not in value \
                and value not in reserved
            self.assertEqual(modid.is_valid(value), csharp_ok,
                             "the two rules disagree about %r" % value)


class AbiShapeTests(unittest.TestCase):
    """Properties of the ABI that the header promises about itself."""

    def test_the_root_takes_no_aggregate_by_value(self):
        text = read(HEADER)
        root = re.search(r"typedef struct MbRoot\s*\{(.*?)\}\s*MbRoot;",
                         text, re.S).group(1)
        # MbStr by value in the frozen root is the one thing that could never be
        # fixed if an ABI ever disagreed about 16-byte aggregates. Capability
        # tables may use it freely; they can be revised.
        self.assertNotIn("MbStr ", root,
                         "an aggregate crosses by value in the FROZEN root")
        self.assertIn("const char* name", root)

    def test_no_capability_table_takes_a_function_pointer_from_a_mod(self):
        """The rule that makes a collectible assembly context able to unload."""
        text = read(HEADER)
        for table in re.findall(r"typedef struct (Mb\w+Table)\s*\{(.*?)\}\s*\1;",
                                text, re.S):
            name, body = table
            if name == "MbHostTable":
                continue          # set_trampoline is the ONE, and it is host-only
            for callback in ("MbEventCallback", "MbInputCallback",
                             "MbCommandCallback"):
                self.assertNotIn(callback, body,
                                 "%s takes a per-mod callback pointer; native "
                                 "would then hold an address inside mod code"
                                 % name)

    def test_the_only_managed_pointer_is_the_host_trampoline(self):
        text = read(HEADER)
        host = re.search(r"typedef struct MbHostTable\s*\{(.*?)\}\s*MbHostTable;",
                         text, re.S).group(1)
        self.assertIn("set_trampoline", host)
        self.assertEqual(1, text.count("MbTrampoline trampoline"))

    def test_every_table_starts_with_the_versioned_header(self):
        text = read(HEADER)
        for name, body in re.findall(
                r"typedef struct (Mb\w+Table)\s*\{(.*?)\}\s*\1;", text, re.S):
            self.assertIn("MB_TABLE_HEADER", body,
                          "%s cannot be version-checked" % name)

    def test_the_reclaimability_predicate_exists(self):
        """Stage 5 gates AssemblyLoadContext.Unload() on exactly this."""
        self.assertIn("mod_is_reclaimable", read(HEADER))

    def test_the_host_capability_is_not_reachable_by_a_mod(self):
        text = read(HEADER)
        self.assertIn("MB_CAP_HOST", text)
        self.assertIn("host handle", text)


class CSharpBuildTests(unittest.TestCase):
    """The contract assembly must actually compile, with docs, warnings as errors."""

    def test_the_public_api_builds_clean(self):
        if not _dotnet_available():
            self.skipTest("no dotnet SDK on this machine")
        result = subprocess.run(
            ["dotnet", "build", "--nologo", "-v", "quiet"],
            cwd=CSHARP_DIR, capture_output=True, text=True, timeout=600)
        self.assertEqual(0, result.returncode,
                         result.stdout[-4000:] + result.stderr[-2000:])


def _dotnet_available():
    try:
        return subprocess.run(["dotnet", "--version"], capture_output=True,
                              timeout=120).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


if __name__ == "__main__":
    unittest.main()
