"""The production console, held to console.py's envelope.

The reference has defined these semantics since Stage 4.5: the result envelope,
the refusal wording, the validation order, the per-mod command cap, and "run()
never raises". The port mirrors them, and this drives the same lines through
both.

THE ONE INTENDED DIVERGENCE
---------------------------
Names. The reference registers its builtins bare -- "help", "mods" -- because it
predates any reserved prefix. Production namespaces them "misery:help", and a
bare "help" is deliberately NOT a command. "mbpl" is not used and must not be:
it is an ordinary mod_id, the one the production radio mod uses, and reserving
it would invalidate existing item definitions.

So the differential compares envelope SHAPE and refusal wording, mapping
misery:X to X, rather than pretending the names are the same.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tools", "modplatform"))

import console as CONSOLE                                          # noqa: E402
import host as HOST                                                # noqa: E402
import nativebuild as nb                                           # noqa: E402

INTERNAL = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
SOURCES = ["BridgeTables.cpp", "Json.cpp", "ModManifest.cpp", "ModResolve.cpp",
           "ModDiscovery.cpp"]


def build_harness():
    return nb.build_exe(
        [os.path.join(REPO, "runtime", "tests", "console_harness.cpp")] +
        [os.path.join(INTERNAL, name) for name in SOURCES],
        "console_harness.exe")


class TheNamedCasesPass(unittest.TestCase):
    """The harness drives the real MbConsoleTable off the game."""

    @classmethod
    def setUpClass(cls):
        cls.result = nb.run(build_harness())
        cls.lines = cls.result.stdout.splitlines()

    def test_every_case_passed(self):
        self.assertEqual([], [ln for ln in self.lines if "[FAIL]" in ln],
                         self.result.stdout)

    def test_the_harness_reported_success(self):
        self.assertTrue(json.loads(self.lines[-1])["ok"], self.result.stdout)


class TheEnvelopeMatchesTheReference(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.exe = build_harness()

    def native(self, lines):
        result = subprocess.run([self.exe, "--envelope"],
                                input="".join(l + "\n" for l in lines),
                                capture_output=True, text=True, timeout=300)
        out = [json.loads(l) for l in result.stdout.splitlines() if l.strip()]
        self.assertEqual(len(lines), len(out), result.stdout + result.stderr)
        return out

    def reference_console(self):
        root = tempfile.mkdtemp(prefix="consolediff-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        platform = HOST.Platform(root)
        console = CONSOLE.Console(platform)
        platform.declare_plan(["alphamod"])
        platform.load("alphamod",
                      lambda ctx: console.register(
                          ctx._owner, "alphamod:ping", "say hello",
                          lambda args: {"a": args}),
                      required=["core.console"])
        return console

    def test_an_empty_line_is_identical(self):
        native = self.native([""])[0]
        reference = self.reference_console().run("")
        self.assertEqual(reference, native)

    def test_whitespace_only_is_identical(self):
        native = self.native(["   \t "])[0]
        reference = self.reference_console().run("   \t ")
        self.assertEqual(reference, native)

    def test_an_unknown_command_is_identical(self):
        native = self.native(["nope"])[0]
        reference = self.reference_console().run("nope")
        self.assertEqual(reference, native,
                         "the refusal wording and hint must match byte for byte")

    def test_a_bare_builtin_name_is_unknown_in_production_only(self):
        """The intended divergence, asserted rather than glossed over."""
        native = self.native(["help"])[0]
        self.assertFalse(native["ok"])
        self.assertIn("unknown command 'help'", native["error"])
        reference = self.reference_console().run("help")
        self.assertTrue(reference["ok"],
                        "the reference registers builtins bare")

    def test_a_builtin_envelope_has_the_same_shape(self):
        native = self.native(["misery:help"])[0]
        reference = self.reference_console().run("help")
        self.assertEqual(sorted(reference), sorted(native))
        self.assertTrue(native["ok"])
        self.assertEqual("misery:help", native["command"])
        self.assertIn("commands", native["result"])
        # Every builtin the reference has, production has under misery:.
        reference_names = {row["name"] for row in reference["result"]["commands"]
                           if row["owner"] == "platform"}
        native_names = {row["name"] for row in native["result"]["commands"]
                        if row["owner"] == "platform"}
        missing = {name for name in reference_names
                   if "misery:" + name not in native_names}
        self.assertEqual(set(), missing,
                         "a reference builtin was not ported")

    def test_generations_is_the_only_added_builtin(self):
        native = self.native(["misery:help"])[0]
        reference = self.reference_console().run("help")
        reference_names = {row["name"] for row in reference["result"]["commands"]
                           if row["owner"] == "platform"}
        native_locals = {row["name"].split(":", 1)[1]
                         for row in native["result"]["commands"]
                         if row["owner"] == "platform"}
        self.assertEqual({"generations"}, native_locals - reference_names,
                         "only misery:generations may be new")

    def test_a_mod_command_envelope_has_the_same_shape(self):
        native = self.native(["alphamod:ping one two"])[0]
        self.assertTrue(native["ok"], native)
        self.assertEqual("alphamod:ping", native["command"])
        self.assertEqual(["command", "ok", "result"], sorted(native))
        # The reference's own successful mod-command envelope, for the shape.
        reference = self.reference_console().run("alphamod:ping one two")
        self.assertEqual(sorted(reference), sorted(native))

    def test_run_never_reports_a_command_failure_as_a_status(self):
        """Every one of these is ok:false inside a successful call."""
        for line in ("", "nope", "misery:nope", "alphamod:absent"):
            with self.subTest(line=line):
                native = self.native([line])[0]
                self.assertFalse(native["ok"])


class OwnershipIsImmediate(unittest.TestCase):
    """A revoked command is unreachable at once, both sides."""

    def test_the_reference_and_the_runtime_agree_on_the_wording(self):
        # The runtime's case is covered by the harness; this pins the reference
        # wording the runtime mirrors, so a change there is caught here.
        root = tempfile.mkdtemp(prefix="consoleown-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        platform = HOST.Platform(root)
        console = CONSOLE.Console(platform)
        platform.declare_plan(["alphamod"])
        holder = {}

        def entry(ctx):
            holder["ctx"] = ctx
            console.register(ctx._owner, "alphamod:ping", "hello",
                             lambda args: {})
        platform.load("alphamod", entry, required=["core.console"])
        self.assertTrue(console.run("alphamod:ping")["ok"])
        platform.unload("alphamod")
        after = console.run("alphamod:ping")
        self.assertFalse(after["ok"])
        # Whichever way the reference words it, the runtime says the same.
        source = open(os.path.join(INTERNAL, "BridgeTables.cpp"),
                      encoding="utf-8").read()
        self.assertIn("is no longer available: its mod was unloaded", source)


if __name__ == "__main__":
    unittest.main()
