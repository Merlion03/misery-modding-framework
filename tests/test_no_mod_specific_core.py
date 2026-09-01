#!/usr/bin/env python3
"""The framework and Mod Kit must know nothing about any particular mod.

WHY THIS IS A TEST AND NOT A PRINCIPLE
--------------------------------------
Stage 7 builds a reference mod to exercise the platform end to end. The failure
mode that makes such an exercise worthless is small and gradual: a special case
added "just for now" so the reference mod works, and then another, until the
platform supports one mod rather than mods.

Principles do not survive that; a grep does. Every identifier belonging to a
specific mod is listed here and required to be absent from framework and Mod Kit
CODE. A capability the reference mod needs must be expressed generically -- as a
declaration field, a manifest key, an API call -- or not at all.

CODE, NOT PROSE
---------------
Comments are excluded, because the check is about behaviour keyed to a mod and
prose is not behaviour. Several files legitimately use a fixture name to
illustrate a rule -- "a row called core inside alphamod impersonates nothing" --
and flagging those would train everyone to ignore this test, which is a worse
outcome than the one it guards against.

WHAT IS AND IS NOT "THE FRAMEWORK"
-----------------------------------
Scoped to the code that SHIPS or BUILDS content: the runtime, the public API,
the managed host, and the Mod Kit. Deliberately not research/instruments, which
is test scaffolding: an acceptance instrument must name the mod it drives, and
forbidding that would only push the naming somewhere less honest.
"""
import os
import re
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

SCOPED = (
    os.path.join("runtime", "MiseryRuntime"),
    os.path.join("managed", "Misery.ModAPI"),
    os.path.join("managed", "Misery.ModHost"),
    os.path.join("tools", "modkit"),
    os.path.join("tools", "modplatform"),
    os.path.join("tools", "modframework"),
)

SOURCE_SUFFIXES = (".cpp", ".h", ".cs", ".py")

# Every name belonging to one mod rather than to the platform. Fixture mods are
# included: the framework has no business knowing those either.
FORBIDDEN = (
    "refmod",
    "BP_RefWorldItem",
    "alphamod",
    "betamod",
    "AlphaManagedMod",
    "BetaManagedMod",
    "e3cprobe",
    "BP_MiseryTestWorldItem",
    "ghostdep",
    # Mechanic-shaped names that would signal a mod-specific core abstraction.
    "RadioMod",
    "GrenadeMod",
)

# A file may name one of these ONLY when doing so is its purpose. Each exemption
# names a specific file and a specific reason, never a pattern.
EXEMPT = {
    os.path.join("tools", "modkit", "fixtures.py"): (
        "builds throwaway fixture mods for tests; naming them is what it is "
        "for, and it ships no runtime behaviour"),
}

TRIPLE_DOUBLE = '"' * 3
TRIPLE_SINGLE = "'" * 3


def strip_comments(text, suffix):
    """Blank out comments, keeping line numbering intact.

    Deliberately crude, and crude in the SAFE direction: a `//` inside a string
    literal blanks the rest of that line, so the scan can lose a little code but
    never gains prose. A guard that under-reports fails loudly the moment the
    violation matters; one that over-reports gets switched off.
    """
    lines = text.split("\n")
    out = []
    if suffix == ".py":
        in_doc = None
        for line in lines:
            if in_doc:
                if in_doc in line:
                    line = line.split(in_doc, 1)[1]
                    in_doc = None
                else:
                    out.append("")
                    continue
            for quote in (TRIPLE_DOUBLE, TRIPLE_SINGLE):
                if line.count(quote) == 1:
                    line = line.split(quote, 1)[0]
                    in_doc = quote
                    break
            out.append(line.split("#", 1)[0])
        return "\n".join(out)

    in_block = False
    for line in lines:
        if in_block:
            if "*/" in line:
                line = line.split("*/", 1)[1]
                in_block = False
            else:
                out.append("")
                continue
        if "/*" in line:
            head, rest = line.split("/*", 1)
            if "*/" in rest:
                line = head + rest.split("*/", 1)[1]
            else:
                line = head
                in_block = True
        out.append(line.split("//", 1)[0])
    return "\n".join(out)


def scoped_files():
    for relative in SCOPED:
        root = os.path.join(REPO, relative)
        if not os.path.isdir(root):
            continue
        for base, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs
                       if d not in ("bin", "obj", "__pycache__", ".vs")]
            for name in files:
                if name.endswith(SOURCE_SUFFIXES):
                    full = os.path.join(base, name)
                    yield os.path.relpath(full, REPO).replace("\\", "/"), full


class TheCoreKnowsNoParticularMod(unittest.TestCase):
    def test_no_mod_specific_identifier_appears_in_framework_code(self):
        offences = []
        for relative, full in scoped_files():
            if relative.replace("/", os.sep) in EXEMPT:
                continue
            with open(full, encoding="utf-8", errors="replace") as handle:
                text = strip_comments(handle.read(),
                                      os.path.splitext(full)[1].lower())
            for token in FORBIDDEN:
                for match in re.finditer(re.escape(token), text):
                    line = text.count("\n", 0, match.start()) + 1
                    offences.append("%s:%d names %r" % (relative, line, token))
        self.assertEqual(
            [], offences,
            "framework or Mod Kit CODE names a specific mod. A capability a mod "
            "needs must be generic -- a declaration field, a manifest key, an "
            "API call -- or it does not belong in the core:\n  " +
            "\n  ".join(offences))

    def test_the_scope_actually_covers_something(self):
        # A guard that walks an empty tree passes for the wrong reason.
        found = list(scoped_files())
        self.assertGreater(len(found), 40,
                           "the scope matched %d files; it should cover the "
                           "runtime, the API, the host and the Mod Kit"
                           % len(found))

    def test_the_guard_would_notice_a_violation(self):
        # A grep nobody has seen fail is a grep nobody knows works. This plants
        # the exact shape of the thing being guarded against and requires the
        # scanner to find it in code and ignore it in a comment.
        sample = "\n".join([
            "// a comment naming refmod, which is prose and must be ignored",
            'const char* id = "refmod";',
        ])
        stripped = strip_comments(sample, ".cpp")
        self.assertNotIn("comment naming", stripped)
        self.assertIn('"refmod"', stripped)

    def test_every_exemption_names_a_file_that_exists(self):
        for relative in EXEMPT:
            self.assertTrue(
                os.path.isfile(os.path.join(REPO, relative)),
                "%s is exempted but does not exist; a stale exemption is a "
                "hole nobody is watching" % relative)


if __name__ == "__main__":
    unittest.main()
