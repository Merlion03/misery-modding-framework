"""Per-mod settings, held to settings.py's semantics -- and its bytes.

The reference has defined these since Stage 4.5: declared not free-form; four
types that survive every boundary; one file per mod named by ModId; a stored
value that no longer fits falls back and is REPORTED; keys the mod no longer
declares survive on disk; release forgets and never writes.

WHY THE FILE BYTES ARE COMPARED, NOT JUST THE ANSWERS
-----------------------------------------------------
A user's settings file is read by both implementations over time -- the runtime
in the game, the reference in tooling -- so the two must produce the same
document for the same state, down to how a float is spelled. Python's json.dump
uses repr() for floats; the runtime mimics it. If they ever disagree, this test
is where it shows, not a user's settings silently rewritten.

ONE CLASSIFIED DISCREPANCY
--------------------------
Key length. The reference accepts keys up to MAX_KEY = 64; the public C#
contract (ModId.ValidateLocalId, MaxLength = 48) refuses anything over 48 at
construction. The native port mirrors the reference, so the differential
compares like with like, and no key in the 49..64 range can reach native from a
mod written in C#. Recorded here rather than silently resolved.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tools", "modplatform"))

import errors as E                                                 # noqa: E402
import host as HOST                                                # noqa: E402
import nativebuild as nb                                           # noqa: E402
import settings as SET                                             # noqa: E402

INTERNAL = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
SOURCES = ["BridgeTables.cpp", "Json.cpp", "ModManifest.cpp", "ModResolve.cpp",
           "ModDiscovery.cpp"]

SCHEMA = ('[{"key":"enabled","type":"bool","default":true,"description":"on"},'
          '{"key":"threshold","type":"float","default":0.5,"description":"t"},'
          '{"key":"count","type":"int","default":3,"description":""},'
          '{"key":"name","type":"string","default":"x","description":""}]')

# Each scenario is a script both sides run. Answers and final bytes must agree.
SCENARIOS = {
    "round trip": [
        "declare " + SCHEMA,
        "get bool enabled", "get float threshold", "get int count", "get string name",
        "set float threshold 0.9", "get float threshold",
        "set int count 42", "set string name hello world", "set bool enabled false",
        "save", "reload",
        "get float threshold", "get int count", "get string name", "get bool enabled",
        "file",
    ],
    "refusals": [
        "declare " + SCHEMA,
        "declare " + SCHEMA,                       # ALREADY_EXISTS
        "get float thresold",                      # typo: NOT_FOUND
        "get bool threshold",                      # wrong type
        "set bool threshold true",                 # bool does not satisfy float
        "set bool count true",                     # bool does not satisfy int
        "set string count 5",                      # string does not satisfy int
        "set float threshold 1",                   # an int DOES satisfy float
        "get float threshold",
    ],
    "unsaved changes are forgotten on unload": [
        "declare " + SCHEMA,
        "set float threshold 0.9", "save",
        "set float threshold 0.1",                 # dirty, unsaved
        "reload",
        "get float threshold",                     # 0.9: the saved one
        "file",
    ],
    "a failed mod persists nothing": [
        "declare " + SCHEMA,
        "set float threshold 0.9", "save",
        "set float threshold 0.1",
        "fail",
        "get float threshold",
        "file",
    ],
    "save with nothing dirty writes the same bytes": [
        "declare " + SCHEMA, "set int count 7", "save", "file", "save", "file",
    ],
    "float spellings agree": [
        "declare " + SCHEMA,
        "set float threshold 1", "save", "file",
        "set float threshold 0.1", "save", "file",
        "set float threshold 1e-07", "save", "file",
        "set float threshold 123456789.125", "save", "file",
        "set float threshold 2.5e+20", "save", "file",
    ],
    "an empty schema is allowed": [
        "declare []", "get bool enabled",
    ],
    "bad schemas are refused for the reference's reasons": [
        'declare [{"key":"Enabled","type":"bool","default":true}]',      # pattern
        'declare [{"key":"a","type":"colour","default":1}]',             # type
        'declare [{"key":"a","type":"int"}]',                            # no default
        'declare [{"key":"a","type":"int","default":true}]',             # bool != int
        'declare [{"key":"a","type":"int","default":1,"extra":1}]',      # unknown key
        'declare [{"key":"a","type":"int","default":1},{"key":"a","type":"int","default":2}]',
        'declare [{"key":"a","type":"int","default":1}]',                # now fine
        "get int a",
    ],
}


def build_harness():
    return nb.build_exe(
        [os.path.join(REPO, "runtime", "tests", "settings_harness.cpp")] +
        [os.path.join(INTERNAL, name) for name in SOURCES],
        "settings_harness.exe")


def render(value):
    """The harness's vocabulary for a value the reference returned."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return repr(value)
    return str(value)


class TheNamedCasesPass(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.result = nb.run(build_harness())
        cls.lines = cls.result.stdout.splitlines()

    def test_every_case_passed(self):
        self.assertEqual([], [ln for ln in self.lines if "[FAIL]" in ln],
                         self.result.stdout)

    def test_the_harness_reported_success(self):
        self.assertTrue(json.loads(self.lines[-1])["ok"], self.result.stdout)


class NativeAgreesWithTheReference(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.exe = build_harness()

    def native(self, script):
        root = tempfile.mkdtemp(prefix="mbpl-settings-native-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        result = subprocess.run([self.exe, "--script", root],
                                input="".join(l + "\n" for l in script),
                                capture_output=True, text=True, timeout=300)
        answers = result.stdout.splitlines()
        self.assertEqual(len(script), len(answers), result.stdout + result.stderr)
        return answers

    def reference(self, script):
        """The same script through settings.py, via the reference host."""
        root = tempfile.mkdtemp(prefix="mbpl-settings-ref-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        platform = HOST.Platform(root)
        platform.declare_plan(["alphamod"])
        state = {"schema": None, "ctx": None}

        def load(entry=None):
            def wrapped(ctx):
                state["ctx"] = ctx
                if entry is not None:
                    entry(ctx)
            platform.load("alphamod", wrapped, required=["core.settings"])

        load()
        answers = []
        path = os.path.join(root, "alphamod.json")
        for line in script:
            try:
                if line.startswith("declare "):
                    definitions = json.loads(line[8:])
                    state["schema"] = line[8:]
                    state["ctx"].settings.declare(definitions)
                    answers.append("ok")
                elif line.startswith("get "):
                    _, _type, key = line.split(" ", 2)
                    answers.append(render(platform.settings.get("alphamod", key)))
                elif line.startswith("set "):
                    _, type_name, key, raw = line.split(" ", 3)
                    value = {"bool": lambda v: v == "true",
                             "int": int,
                             "float": lambda v: float(v) if "." in v or "e" in v.lower() else int(v),
                             "string": str}[type_name](raw)
                    platform.settings.set("alphamod", key, value)
                    answers.append("ok")
                elif line == "save":
                    platform.settings.save("alphamod")
                    answers.append("ok")
                elif line in ("reload", "fail"):
                    # The reference has no "fail a loaded mod" API: a mod that
                    # fails does so inside load(), which tears it down through
                    # the SAME release path unload uses. The property under
                    # test -- teardown never persists -- is therefore the same
                    # observation on both sides, and the native harness's
                    # mod_failed is compared against the reference's unload.
                    platform.unload("alphamod")
                    load()
                    if state["schema"] is not None:
                        state["ctx"].settings.declare(json.loads(state["schema"]))
                    answers.append("ok")
                elif line == "file":
                    if os.path.isfile(path):
                        with open(path, "rb") as handle:
                            answers.append(handle.read().hex())
                    else:
                        answers.append("none")
                else:
                    answers.append("unknown-command")
            except E.PlatformError as error:
                answers.append("%d,%d" % (error.subsystem, error.code))
        return answers

    # Declared types per key in SCHEMA, so a typed read can be recognised.
    DECLARED = {"enabled": "bool", "threshold": "float", "count": "int", "name": "string"}

    def test_every_scenario_agrees(self):
        classified = []
        for name, script in SCENARIOS.items():
            with self.subTest(scenario=name):
                native = self.native(script)
                reference = self.reference(script)
                for line, n, r in zip(script, native, reference):
                    with self.subTest(scenario=name, line=line):
                        if line == "file" and n != "none" and r != "none":
                            # Decoded for a readable failure; equality is on bytes.
                            self.assertEqual(bytes.fromhex(r).decode("utf-8"),
                                             bytes.fromhex(n).decode("utf-8"))
                            continue
                        if line.startswith("get "):
                            _, wanted, key = line.split(" ", 2)
                            declared = self.DECLARED.get(key)
                            if declared is not None and declared != wanted:
                                # THE TYPED-READ DISCREPANCY, CLASSIFIED.
                                #
                                # The reference's get() is untyped: Python hands
                                # back the stored value whatever the caller had
                                # in mind. Production cannot: the public contract
                                # is T Get<T>(SettingKey<T>) and the ABI has four
                                # typed get_* slots, so a read through the wrong
                                # type is refused as SETTINGS x INVALID_ARGUMENT.
                                # Stored state agrees -- the reference's answer
                                # IS the declared value -- only the surfacing
                                # differs, and the frozen production boundary
                                # takes precedence. Not ported; oracle untouched.
                                self.assertEqual("%d,%d" % (E.SUB_SETTINGS,
                                                            E.E_INVALID_ARGUMENT), n)
                                self.assertNotIn(",", r, "the reference returned a value")
                                classified.append((name, line, r, n))
                                continue
                        self.assertEqual(r, n)
        if classified:
            print("\nclassified divergences (typed read; state agrees, surfacing "
                  "differs): %d" % len(classified))
            for item in classified:
                print("   scenario=%r line=%r reference=%s runtime=%s" % item)

    def test_the_file_the_runtime_writes_is_what_the_reference_writes(self):
        """Stated on its own: byte-identical documents for identical state."""
        script = SCENARIOS["round trip"]
        native = self.native(script)[-1]
        reference = self.reference(script)[-1]
        self.assertEqual(bytes.fromhex(reference), bytes.fromhex(native))
        # And it is the reference's shape: flat, sorted, indent 2, newline.
        document = bytes.fromhex(native).decode("utf-8")
        self.assertEqual(json.dumps(json.loads(document), indent=2, sort_keys=True) + "\n",
                         document)


class TheKeyLengthDiscrepancyIsClassified(unittest.TestCase):
    """Reference and native accept 49..64; the C# contract refuses over 48."""

    def test_reference_and_native_accept_a_60_character_key(self):
        key = "k" + "x" * 59
        schema = '[{"key":"%s","type":"int","default":1}]' % key
        exe = build_harness()
        root = tempfile.mkdtemp(prefix="mbpl-settings-len-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        native = subprocess.run([exe, "--script", root], input="declare %s\n" % schema,
                                capture_output=True, text=True, timeout=120).stdout.strip()
        self.assertEqual("ok", native, "native mirrors the reference's MAX_KEY = 64")
        self.assertEqual(64, SET.MAX_KEY)

    def test_the_csharp_contract_is_stricter_and_says_so(self):
        source = open(os.path.join(REPO, "managed", "Misery.ModAPI", "ModId.cs"),
                      encoding="utf-8").read()
        self.assertIn("public const int MaxLength = 48;", source)
        print("\nclassified: C# refuses setting keys over 48 chars at construction; "
              "the reference and native accept up to 64. No valid C# input can "
              "observe the difference.")


if __name__ == "__main__":
    unittest.main()
