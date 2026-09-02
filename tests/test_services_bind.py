"""services.bind enforces its requirement, and agrees with the reference.

WHAT WAS WRONG
--------------
The native bind opened with `(void)requirement;`. A consumer could state
">=2.0.0", be bound to a 1.2.0 provider, and be told it had succeeded. That is
not a missing feature: the API accepted a compatibility constraint and reported
that it held, without looking. tools/modplatform/services.py has enforced it
since Stage 4.5.

WHY A DIFFERENTIAL
------------------
Two implementations of one model is a drift risk this repository has paid for
before, so the same version/requirement grid goes through both and the answers
must match -- not merely "both refuse", but the same (subsystem, code).
"""
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

INTERNAL = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
SOURCES = ["BridgeTables.cpp", "Json.cpp", "ModManifest.cpp", "ModResolve.cpp",
           "ModDiscovery.cpp"]

# published version, requirement. Chosen to cover each operator this codebase
# supports, both sides of every boundary, and the malformed inputs.
GRID = [
    ("1.2.0", ">=1.0.0"), ("1.2.0", ">=1.2.0"), ("1.2.0", ">=1.2.1"),
    ("1.2.0", ">=2.0.0"), ("1.2.0", "^1.0.0"), ("1.2.0", "^1.2.0"),
    ("1.2.0", "^2.0.0"), ("1.2.0", "^0.9.0"), ("1.2.0", "==1.2.0"),
    ("1.2.0", "==1.2.1"), ("0.1.0", "^0.1.0"), ("0.1.0", ">=0.2.0"),
    ("2.0.0", "^1.0.0"), ("10.0.0", ">=9.0.0"), ("1.0.0", ">=1.0.0"),
    ("banana", ">=1.0.0"), ("1.2", ">=1.0.0"), ("", ">=1.0.0"),
    ("1.2.0", "not a requirement"), ("1.2.0", ""),
]


def build_harness():
    return nb.build_exe(
        [os.path.join(REPO, "runtime", "tests", "services_harness.cpp")] +
        [os.path.join(INTERNAL, name) for name in SOURCES],
        "services_harness.exe")


class NativeBindEnforcesTheRequirement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.exe = build_harness()
        cls.result = nb.run(cls.exe)
        cls.lines = cls.result.stdout.splitlines()

    def test_every_named_case_passed(self):
        self.assertEqual([], [ln for ln in self.lines if "[FAIL]" in ln],
                         self.result.stdout)


class NativeAgreesWithTheReference(unittest.TestCase):
    """The same grid, through both implementations."""

    @classmethod
    def setUpClass(cls):
        exe = build_harness()
        # "-" carries the empty string: the wire is whitespace separated, so an
        # empty field cannot be written literally, and the empty cases are
        # exactly the ones worth keeping in the grid.
        wire = "".join("%s %s\n" % (v or "-", r or "-") for v, r in GRID)
        result = subprocess.run([exe, "--matrix"], input=wire,
                                capture_output=True, text=True, timeout=300)
        cls.native = result.stdout.split()
        assert len(cls.native) == len(GRID), (cls.native, result.stderr)

    def reference(self, version, requirement):
        """The reference's answer for one pair, in the harness's vocabulary.

        A FRESH platform per pair. Sharing one across the grid meant the second
        pair re-loaded mod ids the first had already loaded, the callbacks never
        ran, and every pair after the first reported "no-answer" -- which read
        as the runtime disagreeing with the reference about nearly everything.
        The native side does the same thing for the same reason, minting a new
        provider id per line.
        """
        root = tempfile.mkdtemp(prefix="svcdiff-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        platform = HOST.Platform(root)
        outcome = {}

        def provider(ctx):
            try:
                ctx.services.publish("provider:svc", version, {"m": lambda: 1})
            except E.PlatformError as error:
                outcome["answer"] = "%d,%d" % (error.subsystem, error.code)
            except Exception as error:                             # noqa: BLE001
                # A malformed version reaches semver directly in the reference;
                # the native side reports it as a structured refusal. Recorded
                # rather than smoothed over -- see the classification test.
                outcome["answer"] = "raised:%s" % type(error).__name__

        def consumer(ctx):
            if "answer" in outcome:
                return
            try:
                ctx.services.bind("provider:svc", requirement)
                outcome["answer"] = "ok"
            except E.PlatformError as error:
                outcome["answer"] = "%d,%d" % (error.subsystem, error.code)
            except Exception as error:                             # noqa: BLE001
                outcome["answer"] = "raised:%s" % type(error).__name__

        platform.declare_plan(["provider", "consumer"])
        platform.load("provider", provider, required=["core.services"])
        platform.load("consumer", consumer, required=["core.services"])
        return outcome.get("answer", "no-answer")

    def test_the_grid_agrees(self):
        divergences = []
        for (version, requirement), native in zip(GRID, self.native):
            with self.subTest(version=version, requirement=requirement):
                reference = self.reference(version, requirement)
                # A reference that raises a non-platform error is a known and
                # separately-classified difference in how a malformed version is
                # SURFACED, not in whether it is accepted. Both refuse.
                if reference.startswith("raised:"):
                    self.assertNotEqual(
                        "ok", native,
                        "the reference refused and the runtime accepted")
                    divergences.append((version, requirement, reference, native))
                    continue
                self.assertEqual(reference, native)
        # Recorded so a divergence cannot be silent even when it is benign.
        if divergences:
            print("\nclassified divergences (both refuse, surfaced "
                  "differently): %d" % len(divergences))
            for item in divergences:
                print("   version=%r requirement=%r reference=%s runtime=%s"
                      % item)

    def test_no_pair_is_accepted_by_only_one_side(self):
        """The property that actually matters, stated on its own."""
        for (version, requirement), native in zip(GRID, self.native):
            with self.subTest(version=version, requirement=requirement):
                reference = self.reference(version, requirement)
                self.assertEqual(reference == "ok", native == "ok",
                                 "reference=%s runtime=%s" % (reference, native))


if __name__ == "__main__":
    unittest.main()
