"""Service calls, held to services.py: publish, bind, call, release, describe.

WHAT WAS WRONG
--------------
The native table shipped with call and release as nullptr; the managed host
DISCARDED the method handlers at publish (only the names crossed) and Call
returned string.Empty as though something had been invoked; Version was the
literal "1.0.0" for every service; and is_available resolved the binding's
target BY NAME, so a different mod republishing the same name would have made a
stale binding read as available against a service its consumer never bound to.

WHY A DIFFERENTIAL
------------------
The same scripts go through both implementations. The property that matters --
a handle held past its provider's unload stops working, at once, and comes back
for nothing -- is the reference's own headline test, re-run against native.

CLASSIFIED, NOT PORTED
----------------------
- A provider handler that THROWS. The reference's Token.invoke lets the raw
  exception propagate into the consumer. Production contains every managed
  exception at the trampoline -- nothing may cross the ABI -- so the consumer
  gets SERVICES x HANDLER_FAULTED, structurally. Accept/reject on state agrees;
  surfacing differs; the frozen boundary takes precedence.
- Nesting depth. The reference has no bound (Python's recursion limit stands in
  for one); native refuses at 16 with LIMIT_EXCEEDED. An addition, not a port.
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

INTERNAL = os.path.join(REPO, "runtime", "MiseryRuntime", "Internal")
SOURCES = ["BridgeTables.cpp", "Json.cpp", "ModManifest.cpp", "ModResolve.cpp",
           "ModDiscovery.cpp"]

SCENARIOS = {
    "call and describe": [
        'publish provider:radio 1.2.0 ["tune","scan"]',
        "bind provider:radio ^1.0.0",
        "available",
        'call tune {"f":1}',
        'call scan null',
        "call nope {}",
        "describe",
    ],
    "the provider unloads": [
        'publish provider:radio 1.2.0 ["tune"]',
        "bind provider:radio ^1.0.0",
        'call tune {}',
        "unload-provider",
        "available",
        'call tune {}',
        "describe",
    ],
    "the consumer releases": [
        'publish provider:radio 1.2.0 ["tune"]',
        "bind provider:radio ^1.0.0",
        "release",
        'call tune {}',
        "release",
    ],
    "publish refusals": [
        'publish provider:empty 1.0.0 []',
        'publish provider:bad 1.0.0 ["Tune"]',
        'publish provider:dupe 1.0.0 ["a"]',
        'publish provider:dupe 1.0.0 ["a"]',
        'publish other:mine 1.0.0 ["a"]',
    ],
}


def build_harness():
    return nb.build_exe(
        [os.path.join(REPO, "runtime", "tests", "services_harness.cpp")] +
        [os.path.join(INTERNAL, name) for name in SOURCES],
        "services_harness.exe")


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
        result = subprocess.run([self.exe, "--calls"],
                                input="".join(l + "\n" for l in script),
                                capture_output=True, text=True, timeout=300)
        answers = result.stdout.splitlines()
        self.assertEqual(len(script), len(answers), result.stdout + result.stderr)
        return answers

    def reference(self, script):
        root = tempfile.mkdtemp(prefix="mbpl-services-ref-")
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        platform = HOST.Platform(root)
        platform.declare_plan(["provider", "consumer"])
        ctx = {}

        def load(mod_id):
            platform.load(mod_id, lambda c: ctx.__setitem__(mod_id, c),
                          required=["core.services"])

        load("provider")
        load("consumer")
        handle = {"h": None}
        answers = []

        def echo(method):
            # The native stand-in echoes {"method": .., "args": ..}; so does this,
            # so the two results are the same JSON for the same call.
            def handler(args):
                return {"method": method, "args": args}
            return handler

        for line in script:
            try:
                if line.startswith("publish "):
                    _, name, version, methods_json = line.split(" ", 3)
                    names = json.loads(methods_json)
                    ctx["provider"].services.publish(
                        name, version, {m: echo(m) for m in names})
                    answers.append("ok")
                elif line.startswith("bind "):
                    _, name, requirement = line.split(" ", 2)
                    handle["h"] = ctx["consumer"].services.bind(name, requirement)
                    answers.append("ok")
                elif line.startswith("call "):
                    _, method, args_json = line.split(" ", 2)
                    result = handle["h"].call(method, json.loads(args_json))
                    answers.append(json.dumps(result, separators=(",", ":")))
                elif line == "available":
                    answers.append("true" if handle["h"].available else "false")
                elif line == "describe":
                    answers.append(json.dumps(handle["h"].as_dict(),
                                              separators=(",", ":")))
                elif line == "release":
                    # The reference releases through the owner's resource; the
                    # nearest equivalent to a consumer releasing one binding is
                    # dropping it, after which the reference has nothing to call.
                    if handle.get("released"):
                        raise E.PlatformError(E.SUB_SERVICES, E.E_NOT_OWNED,
                                              "already released", "consumer")
                    handle["released"] = True
                    answers.append("ok")
                elif line == "unload-provider":
                    platform.unload("provider")
                    load("provider")
                    answers.append("ok")
                elif line == "unload-consumer":
                    platform.unload("consumer")
                    load("consumer")
                    answers.append("ok")
                else:
                    answers.append("unknown-command")
            except E.PlatformError as error:
                answers.append("%d,%d" % (error.subsystem, error.code))
        return answers

    def test_call_and_describe_agree(self):
        script = SCENARIOS["call and describe"]
        native, reference = self.native(script), self.reference(script)
        for line, n, r in zip(script, native, reference):
            with self.subTest(line=line):
                if line == "describe":
                    self.assertEqual(json.loads(r), json.loads(n))
                elif line.startswith("call ") and "," not in n:
                    self.assertEqual(json.loads(r), json.loads(n))
                else:
                    self.assertEqual(r, n)

    def test_a_handle_held_past_its_providers_unload_stops_working(self):
        """The reference's own headline case, against native."""
        script = SCENARIOS["the provider unloads"]
        native, reference = self.native(script), self.reference(script)
        for line, n, r in zip(script, native, reference):
            with self.subTest(line=line):
                if line == "describe":
                    nd, rd = json.loads(n), json.loads(r)
                    self.assertEqual(rd["available"], nd["available"])
                    self.assertEqual(rd["methods"], nd["methods"])
                elif line.startswith("call ") and "," not in n:
                    self.assertEqual(json.loads(r), json.loads(n))
                else:
                    self.assertEqual(r, n)
        # Stated on its own: after the unload, both refuse with NOT_FOUND.
        self.assertEqual("false", native[4])
        self.assertEqual("%d,%d" % (E.SUB_SERVICES, E.E_NOT_FOUND), native[5])
        self.assertEqual(native[5], reference[5])

    def test_release_semantics(self):
        script = SCENARIOS["the consumer releases"]
        native = self.native(script)
        self.assertEqual("ok", native[2])
        # Released: OWNER_DISPOSED on call, NOT_OWNED on a second release.
        self.assertEqual("%d,%d" % (E.SUB_SERVICES, E.E_OWNER_DISPOSED), native[3])
        self.assertEqual("%d,%d" % (E.SUB_SERVICES, E.E_NOT_OWNED), native[4])

    def test_publish_refusals_agree(self):
        script = SCENARIOS["publish refusals"]
        native, reference = self.native(script), self.reference(script)
        for line, n, r in zip(script, native, reference):
            with self.subTest(line=line):
                self.assertEqual(r, n)


class TheClassifiedDiscrepanciesAreStated(unittest.TestCase):

    def test_a_throwing_handler_is_a_structured_fault_natively(self):
        source = open(os.path.join(INTERNAL, "BridgeTables.cpp"), encoding="utf-8").read()
        self.assertIn("MB_E_HANDLER_FAULTED", source)
        print("\nclassified: a provider handler that throws propagates raw in the "
              "reference; production reports SERVICES x HANDLER_FAULTED, because "
              "nothing may cross the ABI. State agrees, surfacing differs.")

    def test_the_depth_bound_is_native_only(self):
        source = open(os.path.join(INTERNAL, "BridgeTables.cpp"), encoding="utf-8").read()
        self.assertIn("kMaxServiceCallDepth = 16", source)
        reference = open(os.path.join(REPO, "tools", "modplatform", "services.py"),
                         encoding="utf-8").read()
        self.assertNotIn("depth", reference.lower())
        print("classified: native bounds nested service calls at 16; the reference "
              "has no bound. An addition, recorded, not a port.")


if __name__ == "__main__":
    unittest.main()
