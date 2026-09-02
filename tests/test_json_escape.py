"""The runtime's JSON escaper, held to a conforming writer.

WHY A DIFFERENTIAL AND NOT A TABLE
----------------------------------
The escaper this replaces handled '"', '\\' and '\\n' and passed every other
control byte through raw, so it emitted documents no conforming parser accepts.
It had no test. A table of expected outputs would have been written by whoever
wrote the escaper and would have contained the same three characters.

So the oracle is Python's own writer -- json.dumps(text, ensure_ascii=False),
which this project already depends on -- and the corpus includes every byte the
escaper must special-case rather than the ones somebody remembered.
"""
import json
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tools", "modplatform"))

import nativebuild as nb                                           # noqa: E402


def corpus():
    """Every case the contract names, plus the ones that break naive escapers."""
    cases = []
    # Every control character, which is the range RFC 8259 actually requires and
    # the range the previous implementation ignored.
    for byte in range(0x00, 0x20):
        cases.append(chr(byte))
    cases += [
        '"', "\\", '\\"', '""',
        "\x7f",                       # DEL: legal unescaped, must NOT change
        "plain ascii",
        "",
        "tab\there", "cr\rhere", "nl\nhere", "bs\bhere", "ff\fhere",
        "mod_id/with:punctuation-and_underscores",
        "éèê",         # 2-byte UTF-8
        "中文",               # 3-byte UTF-8
        "\U0001f600",                 # 4-byte UTF-8 (astral)
        "mixed 中 \t \" \\ \x01 end",
        "",               # the boundary either side of ASCII
        "a" * 500,
    ]
    return cases


class JsonEscapeMatchesAConformingWriter(unittest.TestCase):
    """The escaper agrees with json.dumps for every valid-UTF-8 input."""

    @classmethod
    def setUpClass(cls):
        cls.exe = nb.build_exe(
            [os.path.join(REPO, "runtime", "tests", "json_escape_harness.cpp"),
             os.path.join(REPO, "runtime", "MiseryRuntime", "Internal",
                          "Json.cpp")],
            "json_escape_harness.exe")

    def escape(self, raw_bytes):
        """Run one case through the runtime's escaper. Bytes in, bytes out."""
        result = subprocess.run(
            [self.exe], input=raw_bytes.hex() + "\n", capture_output=True,
            text=True, timeout=60)
        self.assertEqual(0, result.returncode, result.stderr)
        line = result.stdout.strip()
        self.assertNotEqual("!bad-hex", line, "harness rejected the input")
        return bytes.fromhex(line)

    def test_matches_json_dumps_for_every_case(self):
        for case in corpus():
            with self.subTest(case=repr(case)[:40]):
                # json.dumps gives the quoted form; the escaper returns the body.
                want = json.dumps(case, ensure_ascii=False)[1:-1]
                got = self.escape(case.encode("utf-8")).decode("utf-8")
                self.assertEqual(want, got)

    def test_every_control_byte_survives_a_real_parser(self):
        """The point of the exercise: the output must be parseable, and equal."""
        for byte in range(0x00, 0x21):
            with self.subTest(byte=byte):
                case = "a" + chr(byte) + "b"
                body = self.escape(case.encode("utf-8")).decode("utf-8")
                self.assertEqual(case, json.loads('"' + body + '"'))

    def test_del_is_left_alone(self):
        """0x7f is legal unescaped; escaping it would be a gratuitous divergence."""
        self.assertEqual(b"\x7f", self.escape(b"\x7f"))

    def test_ill_formed_utf8_cannot_produce_a_malformed_document(self):
        """Territory the oracle cannot cover, so the contract is stated here.

        Python str cannot hold ill-formed UTF-8, so json.dumps has nothing to
        say about it. The runtime's input is bytes and can. The contract is that
        such a byte becomes U+FFFD rather than reaching the document intact.
        """
        replacement = "�"
        for name, raw in (
                ("lone continuation", b"\x80"),
                ("truncated 2-byte", b"\xc3"),
                ("truncated 3-byte", b"\xe4\xb8"),
                ("over-long", b"\xc0\xaf"),
                ("surrogate", b"\xed\xa0\x80"),
                ("beyond U+10FFFF", b"\xf5\x80\x80\x80"),
                ("bare 0xff", b"\xff")):
            with self.subTest(name):
                body = self.escape(raw).decode("utf-8")
                # Parseable, and carries no byte of the ill-formed input.
                decoded = json.loads('"' + body + '"')
                self.assertIn(replacement, decoded)

    def test_a_truncated_sequence_does_not_swallow_what_follows(self):
        """A lead byte missing its continuation must not consume the next case.

        Stepping one byte on failure is what keeps a quote after a truncated
        sequence from being absorbed into it -- which would put an unescaped
        quote in the output and end the string early.
        """
        body = self.escape(b"\xe4\xb8" + b'"').decode("utf-8")
        decoded = json.loads('"' + body + '"')
        self.assertTrue(decoded.endswith('"'), decoded)


if __name__ == "__main__":
    unittest.main()
