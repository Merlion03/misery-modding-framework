#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Live enforcement gate: run tools/kb/validate.py over THIS repository.

Every other test module in tests/ builds synthetic fixtures in a temporary
directory and checks that the validator reacts correctly to them. That proves
the validator works. It does not prove that the knowledge base is clean -- and
until this module existed, nothing did: the suite stayed green for weeks while
`validate.py` exited 1 with 30 violations, because no test ever pointed it at
the real tree (plan.md 9.4/K-03: "validation runs clean" is an exit criterion,
and an exit criterion nobody executes is a wish).

This module is that missing link. It runs the validator once, as a subprocess,
against the real repository root, and then asserts several independent things
about the result.

WHY MORE THAN ONE ASSERTION, AND WHY THE RECORD COUNT MATTERS MOST
------------------------------------------------------------------
"zero violations" on its own is a trap this project has already fallen into
twice:

  * a validator that finds zero records reports zero violations and exits 0.
    An empty scan and a clean knowledge base are indistinguishable by exit
    code alone. Finding MAJOR-6 in the repo audit is the same shape: a missing
    `jsonschema` made validate.py fall back to a minimal built-in checker that
    ignored "format" and "propertyNames" -- and exited 0, so the breakage
    looked like a pass.
  * a regression in ONE markdown notation parser (inline annotation,
    table row, log entry) silently deletes a whole class of facts from the
    scan while the other notations keep producing records, so the total stays
    respectable and the loss is invisible.

So the gate asserts, separately: the result is clean; enough records were
found; each notation still yields records; the scan still reaches every
repository-root document; and the schema backend is real jsonschema rather
than the degrading fallback. Each is its own test method so a failure names
its own cause instead of hiding behind a neighbour.

A second class, DocumentedTestIdsExist, checks the other direction of the same
idea: a test name printed in a document must be a test pytest can still
collect. Its reasoning is at the bottom of this file, next to the code.

Run:  D:\\Tools\\venv-research\\Scripts\\python.exe -m pytest -q tests/test_validator_live.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / "tools" / "kb" / "validate.py"


# ---------------------------------------------------------------------------
# Plausibility floors
# ---------------------------------------------------------------------------
# Measured on 2026-08-22 with validate.py 3.1.0 over the real tree:
#
#     files    24   (json=4, markdown=13, schema=7)
#     records 228   (inline-annotation=99, table-row=117, log-entry=12)
#
# The floors below sit at roughly HALF of each measured value. That choice is
# deliberate and is the whole point of this file, so it is justified rather
# than asserted:
#
#   * They must be low enough that ordinary editorial work never trips them.
#     Splitting mixed claims (plan.md 10.3 v2.2) ADDS records; deleting a
#     stale section or folding two documents together removes some. Halving
#     the knowledge base by hand would be a deliberate act, not an accident.
#   * They must be high enough that a parser regression cannot hide. Any such
#     regression takes out a whole notation or a whole file kind at once --
#     that is how the extractors are written, one function per notation -- so
#     the failure signature is a count that COLLAPSES, not one that drifts.
#     Losing the table-row extractor alone drops the total to 111, under the
#     120 floor; losing the inline extractor drops it to 129, which the total
#     floor would survive, which is exactly why there are per-notation floors
#     underneath it.
#
# Raise these numbers when the knowledge base grows substantially. Never lower
# one to make a red test green: a falling record count is the finding, and the
# floor is the only thing that can report it.
MIN_TOTAL_RECORDS = 120
MIN_RECORDS_PER_NOTATION = {
    "inline-annotation": 55,
    "table-row": 60,
    # The log has one entry per research session and grows slowly; it is the
    # smallest notation, so its floor is set by "the extractor still works at
    # all" rather than by a fraction of the current count.
    "log-entry": 5,
}

# ---------------------------------------------------------------------------
# The json notation: a declared gap, with a ratchet instead of a floor
# ---------------------------------------------------------------------------
# The dict above has no entry for "json", and that asymmetry is deliberate and
# is a KNOWN LIMITATION rather than a relaxation. Measured on 2026-08-22 the
# validator reports `json=0`: the four machine-readable artifacts under
# research/builds/ are validated against their schemas, but not one of them
# carries a graded knowledge-base record. There is nothing to set a floor
# over, and a floor above zero would fail for the honest reason that the facts
# do not exist yet.
#
# What that costs, stated plainly, because it is the same argument this whole
# module is built on: an empty scan and a clean scan are indistinguishable by
# exit code. For the json notation the scan is empty. Everything the validator
# does ONLY for json records is therefore exercised by synthetic fixtures in
# tests/test_kb.py and by nothing else -- in particular
#
#   * the per-record linter for json records (validate.py lint_record, whose
#     notation parameter defaults to "json"; lint_markdown_record is the
#     separate, weaker path the prose notations go through),
#   * the plan.md 10.5 claim_type -> oracle matrix, which the validator's own
#     DISCLOSURES block says is applied to json records only, because the
#     markdown notations carry no claim_type field at all,
#   * the conditional shapes in research/schema/kb-record.schema.json,
#   * the build_key rule.
#
# A regression in any of those would pass this gate today. That is the gap; it
# is repeated in docs/toolchain.md section 15.2 so a reader of the docs meets
# it too.
#
# WHAT CLOSES IT: the first real json knowledge-base record. So instead of an
# inert `"json": 0` -- which asserts nothing and would sit there forever -- the
# gap is guarded by a ratchet. MIN_RECORDS_JSON stays 0 while the notation is
# empty; the moment the first json record lands,
# test_json_notation_gap_is_still_declared goes red and says: set a real
# floor. The gap can be open, but it cannot be open QUIETLY.
MIN_RECORDS_JSON = 0
# 24 files scanned on 2026-08-22. The schemas (7) and the machine-readable
# artifacts (4) are structural and are not going away; the floor guards
# against a scan that silently stops walking a directory.
MIN_FILES_SCANNED = 18

WHY_A_LOW_COUNT_IS_A_FAILURE = (
    "A SUSPICIOUSLY LOW RECORD COUNT IS A FAILURE, NOT A PASS.\n"
    "The validator reports violations only for records it actually found. If "
    "it finds nothing it reports nothing and exits 0, which is byte-for-byte "
    "the same signal as a perfectly clean knowledge base. So this assertion "
    "exists to distinguish 'clean' from 'blind'. A drop here means the "
    "extractor stopped reading a notation, the scan stopped walking a "
    "directory, or a document was emptied -- investigate the validator and "
    "the tree, and do NOT lower the floor to restore a green run."
)


def run_validator(*extra_args: str) -> tuple[int, dict, str]:
    """Run validate.py --json over the real repository. Returns (rc, doc, stderr).

    Invoked as a subprocess on purpose, with sys.executable: the exit CODE is
    half of what is under test here, and an in-process import cannot observe
    it. sys.executable also means the gate is checked against whichever
    interpreter is running the suite, which is what a developer and CI
    actually use.
    """
    completed = subprocess.run(
        [sys.executable, str(VALIDATOR), "--json", "--repo-root", str(REPO_ROOT)]
        + list(extra_args),
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            "validate.py --json did not produce parseable JSON on stdout "
            "(rc=%s): %s\n--- stdout (first 2000 chars) ---\n%s\n"
            "--- stderr (first 2000 chars) ---\n%s"
            % (completed.returncode, error, completed.stdout[:2000],
               completed.stderr[:2000])
        ) from error
    return completed.returncode, document, completed.stderr


def offender_summary(document: dict, limit: int = 12) -> str:
    """Render the files carrying violations, most first, for a failure message."""
    # files[].errors is a COUNT (int) in validate.py --json output, not a list;
    # the individual findings live in files[].findings with a "severity".
    offenders = [
        (int(entry.get("errors") or 0), entry.get("path", "?"))
        for entry in document.get("files", [])
        if entry.get("errors")
    ]
    offenders.sort(reverse=True)
    if not offenders:
        return "  (no file-level errors reported)"
    lines = [
        "  %-4d %s" % (count, path) for count, path in offenders[:limit]
    ]
    if len(offenders) > limit:
        lines.append("  ... and %d more file(s)" % (len(offenders) - limit))
    return "\n".join(lines)


class ValidatorLiveGate(unittest.TestCase):
    """The gate. One validator run, several independent assertions about it."""

    returncode: int
    document: dict
    stderr: str

    @classmethod
    def setUpClass(cls) -> None:
        if not VALIDATOR.is_file():
            raise AssertionError(
                "tools/kb/validate.py is missing at %s. This is not a reason "
                "to skip: the validator IS the knowledge-base gate (plan.md "
                "9.4/K-03), so its absence is the most severe possible "
                "failure of this check." % VALIDATOR
            )
        cls.returncode, cls.document, cls.stderr = run_validator()

    # -- layer 1: the result must be clean ---------------------------------

    def test_validator_exits_clean_over_the_real_repository(self) -> None:
        """Zero violations and exit 0 over the real tree. plan.md 9.4/K-03."""
        summary = self.document.get("summary", {})
        violations = summary.get("violations")
        by_rule = summary.get("by_rule", {})
        # summary.by_rule maps a rule id to {"errors": n, "warnings": n}. The
        # "errors" side is what counts as a violation.
        rules = ", ".join(
            "%s=%s" % (rule, counts.get("errors", 0))
            for rule, counts in sorted(
                by_rule.items(),
                key=lambda item: -int(item[1].get("errors", 0) or 0),
            )
            if counts.get("errors")
        ) or "(none)"
        self.assertEqual(
            0,
            violations,
            "the knowledge base is NOT clean: validate.py reports %s "
            "violation(s) over the real repository (exit %s).\n"
            "violations by rule: %s\n"
            "files carrying errors (count, path):\n%s\n"
            "Reproduce with:\n"
            "  %s tools\\kb\\validate.py\n"
            "Fix the records the validator names. Do not relax this test: it "
            "is the only thing in the suite that looks at the real tree."
            % (violations, self.returncode, rules,
               offender_summary(self.document), sys.executable),
        )
        self.assertEqual(
            0,
            self.returncode,
            "validate.py exited %s with %s violation(s) reported. Exit code "
            "and violation count must agree -- a non-zero exit with zero "
            "violations means the validator failed for some other reason "
            "(stderr below).\n--- stderr ---\n%s"
            % (self.returncode, violations, self.stderr[:2000]),
        )

    def test_no_unparseable_records(self) -> None:
        """A fact the validator cannot read is a problem, never an absence."""
        summary = self.document.get("summary", {})
        unparseable = summary.get("unparseable_records")
        self.assertEqual(
            0,
            unparseable,
            "%s candidate record(s) could not be parsed. An unreadable graded "
            "fact is silently ungraded, which is worse than a wrong grade "
            "because nothing reports it. Run the validator and fix the "
            "notation at the reported line(s)." % unparseable,
        )

    # -- layer 2: the scan must actually have looked at something -----------

    def test_record_count_is_plausible(self) -> None:
        """The important assertion. See WHY_A_LOW_COUNT_IS_A_FAILURE."""
        summary = self.document.get("summary", {})
        records = summary.get("records")
        self.assertIsNotNone(
            records,
            "validate.py --json reported no summary.records at all. Without "
            "a record count this gate cannot tell a clean scan from an empty "
            "one.\n" + WHY_A_LOW_COUNT_IS_A_FAILURE,
        )
        self.assertGreaterEqual(
            records,
            MIN_TOTAL_RECORDS,
            "only %s graded record(s) found across the whole repository; the "
            "floor is %s (measured baseline: 228 on 2026-08-22).\n%s"
            % (records, MIN_TOTAL_RECORDS, WHY_A_LOW_COUNT_IS_A_FAILURE),
        )

    def test_every_markdown_notation_still_yields_records(self) -> None:
        """Per-notation floors: a broken extractor cannot hide behind the total."""
        found = self.document.get("summary", {}).get("records_by_notation", {})
        for notation, floor in sorted(MIN_RECORDS_PER_NOTATION.items()):
            count = found.get(notation, 0)
            self.assertGreaterEqual(
                count,
                floor,
                "notation %r yielded %s record(s), floor %s. The knowledge "
                "base is written in this notation, so a collapse here means "
                "the extractor for it stopped matching -- those facts are now "
                "ungraded and invisible, while the other notations keep the "
                "total looking healthy.\nobserved: %s\n%s"
                % (notation, count, floor, found, WHY_A_LOW_COUNT_IS_A_FAILURE),
            )

    def test_json_notation_gap_is_still_declared(self) -> None:
        """The json notation has no floor. See MIN_RECORDS_JSON for why.

        This is not a floor check -- there is nothing to floor. It is a
        ratchet on the declaration itself: while json yields zero records the
        gap stands as documented, and the first json record that lands turns
        this into an instruction to set a real floor.
        """
        found = self.document.get("summary", {}).get("records_by_notation", {})
        count = int(found.get("json", 0) or 0)
        if count == 0:
            self.assertEqual(
                0,
                MIN_RECORDS_JSON,
                "MIN_RECORDS_JSON is %s but the json notation yields no "
                "records at all. Either the floor was raised ahead of the "
                "facts, or the json records that justified it have "
                "disappeared -- and the second case is a parser or scan "
                "regression, which is the thing this module exists to "
                "report.\nobserved: %s\n%s"
                % (MIN_RECORDS_JSON, found, WHY_A_LOW_COUNT_IS_A_FAILURE),
            )
            return
        self.assertGreater(
            MIN_RECORDS_JSON,
            0,
            "the json notation now yields %s record(s), so the declared gap "
            "is closed and the asymmetry in MIN_RECORDS_PER_NOTATION is no "
            "longer honest. THIS IS NOT A FAILURE OF THE KNOWLEDGE BASE -- it "
            "is the ratchet described above MIN_RECORDS_JSON firing exactly "
            "when it was meant to. Do this:\n"
            "  1. add \"json\" to MIN_RECORDS_PER_NOTATION with a floor at "
            "roughly half of %s, on the same reasoning as the other three;\n"
            "  2. set MIN_RECORDS_JSON above 0 so this branch stops firing;\n"
            "  3. delete the known-limitation note in docs/toolchain.md "
            "section 15.2, because the json path of the validator is now "
            "covered by the real tree and not only by fixtures.\n"
            "observed: %s" % (count, count, found),
        )
        self.assertGreaterEqual(
            count,
            MIN_RECORDS_JSON,
            "the json notation yielded %s record(s), floor %s. %s"
            % (count, MIN_RECORDS_JSON, WHY_A_LOW_COUNT_IS_A_FAILURE),
        )

    def test_scan_reaches_the_expected_breadth_of_files(self) -> None:
        """Enough files, and every repository-root document among them."""
        summary = self.document.get("summary", {})
        coverage = self.document.get("coverage", {})
        files = summary.get("files", 0)
        self.assertGreaterEqual(
            files,
            MIN_FILES_SCANNED,
            "the validator scanned only %s file(s); floor %s (baseline 24). "
            "A shrinking scan set is the same failure as a shrinking record "
            "count: the tool stopped looking.\nscanned areas: %s\n%s"
            % (files, MIN_FILES_SCANNED,
               {area: len(paths) for area, paths in
                (coverage.get("areas") or {}).items()},
               WHY_A_LOW_COUNT_IS_A_FAILURE),
        )
        missing = coverage.get("root_documents_missing")
        self.assertEqual(
            [],
            list(missing or []),
            "repository-root document(s) expected by the validator were not "
            "scanned: %s. plan.md holds the densest concentration of graded "
            "facts in the project, so leaving a root document out of the scan "
            "exempts the most important facts in the repository from the "
            "gate." % (missing,),
        )

    # -- layer 3: the checker must be the real checker ----------------------

    def test_schema_backend_is_real_jsonschema(self) -> None:
        """The degrading fallback exits 0, so it must be reported as a failure.

        Not a skip. Finding MAJOR-6 hid for weeks precisely because a missing
        jsonschema looked like a pass; making this a skip would rebuild that
        hiding place. requirements.txt pins jsonschema==4.26.0 for this reason.
        """
        document = self.document
        self.assertEqual(
            "jsonschema",
            document.get("schema_backend"),
            "schema backend is %r, not real jsonschema. The built-in fallback "
            "ignores 'format' and 'propertyNames' and still exits 0, so the "
            "run above proves less than it appears to. Install the pinned "
            "dependency (requirements.txt step 5) and re-run."
            % (document.get("schema_backend"),),
        )
        self.assertFalse(
            document.get("schema_backend_degraded"),
            "the validator reports a DEGRADED schema backend; ignored "
            "keywords: %s. Every JSON artifact was checked more weakly than "
            "its schema asks for."
            % (document.get("ignored_schema_keywords"),),
        )


# ---------------------------------------------------------------------------
# Second gate in this module: a test name printed in a document must be a test
# ---------------------------------------------------------------------------
# Why this lives here rather than in a module of its own: the thesis of this
# file is that the suite must at some point look at the REAL repository
# instead of at a fixture it built itself. A prose document naming a test that
# no longer exists is that same defect one layer out -- a claim about the tree
# that nothing checks against the tree.
#
# It is here because it happened. docs/toolchain.md section 15.1 named a
# single failing test by node id; the test was later deleted and replaced, and
# the document went on naming it for as long as nobody re-ran the block. Worse,
# the reader had no way to tell: a node id is not distinguishable by eye from
# a node id that still resolves. Meanwhile the header of
# .github/workflows/ci.yml named a test with the class segment missing, so the
# id it printed collected nothing at all -- a copy-paste nobody could have
# caught by reading.
#
# Both are mechanically decidable, and cheaply: pytest can be asked what it
# collects (about a tenth of a second for this suite) and the answer is the
# ground truth. So this checks documented node ids against it.
#
# THE ESCAPE HATCH, AND WHY IT IS NOT A HOLE
# A document sometimes needs to name a test that is GONE -- "the failure this
# block used to report was X, which no longer exists" is exactly the sentence
# that corrects a stale snapshot. Putting the marker below on that line
# declares the id as historical. The check then asserts the opposite: the id
# must NOT resolve. So an exemption is a claim too, and if the named test ever
# comes back the exemption goes red instead. Neither direction is free, and
# `grep -rn KB-NODE-GONE` lists every such claim in the repository.
NODE_ID_RE = re.compile(r"tests[\\/][A-Za-z0-9_]+\.py(?:::[A-Za-z0-9_]+)+")
NODE_ID_GONE_MARKER = "KB-NODE-GONE"

# Text the check reads. Everything else in the tree is binary, generated, or
# not prose; a suffix allow-list is the cheap way to say so.
DOC_SUFFIXES = frozenset({
    ".md", ".py", ".yml", ".yaml", ".txt", ".cfg", ".toml", ".json",
})
SKIPPED_DIRS = frozenset({
    ".git", ".github_cache", ".pytest_cache", "__pycache__", ".venv", "venv",
    "workspace", ".mypy_cache", ".ruff_cache",
})


def collect_node_ids() -> set[str]:
    """Ask pytest what this suite actually contains. Ground truth, not a guess.

    -p no:cacheprovider because this runs INSIDE a pytest process and must not
    write to the cache directory the outer run owns. --collect-only imports the
    test modules but executes no test body and no setUpClass, so the validator
    is not run a second time by this.
    """
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:cacheprovider"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    ids = {
        line.strip().replace("\\", "/")
        for line in completed.stdout.splitlines()
        if "::" in line and not line.startswith(" ")
    }
    if not ids:
        raise AssertionError(
            "pytest --collect-only returned no node ids (rc=%s), so this check "
            "has no ground truth to compare against. That is a broken suite, "
            "not a passing one.\n--- stdout ---\n%s\n--- stderr ---\n%s"
            % (completed.returncode, completed.stdout[:2000],
               completed.stderr[:2000])
        )
    return ids


def documented_node_ids() -> list[tuple[Path, int, str, bool]]:
    """Every pytest node id printed anywhere in the tree.

    Returns (path, line number, node id, declared_gone).
    """
    found: list[tuple[Path, int, str, bool]] = []
    for path in sorted(REPO_ROOT.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in DOC_SUFFIXES:
            continue
        if any(part in SKIPPED_DIRS for part in path.relative_to(REPO_ROOT).parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            declared_gone = NODE_ID_GONE_MARKER in line
            for match in NODE_ID_RE.finditer(line):
                found.append(
                    (path, number, match.group(0).replace("\\", "/"),
                     declared_gone)
                )
    return found


def node_id_resolves(node_id: str, collected: set[str]) -> bool:
    """True if pytest would run something for this id.

    A module-or-class prefix counts: `tests/<module>.py::<Class>` is a
    selector pytest accepts and expands. A method segment with the class
    segment left out is NOT a prefix of anything and does not count -- that is
    precisely the ci.yml defect, and treating it as a near-enough match would
    put the defect back.
    """
    return node_id in collected or any(
        candidate.startswith(node_id + "::") for candidate in collected
    )


class DocumentedTestIdsExist(unittest.TestCase):
    """Node ids quoted in documents must resolve; ones declared gone must not."""

    collected: set[str]
    documented: list[tuple[Path, int, str, bool]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.collected = collect_node_ids()
        cls.documented = documented_node_ids()

    def test_documented_node_ids_resolve(self) -> None:
        broken = [
            (path, number, node_id)
            for path, number, node_id, declared_gone in self.documented
            if not declared_gone and not node_id_resolves(node_id, self.collected)
        ]
        self.assertEqual(
            [],
            broken,
            "%s test name(s) are printed in documents but collect nothing:\n%s\n"
            "Each is a sentence about this repository that stopped being true "
            "without anything going red. Fix the id, or -- if the test really "
            "is gone and the document is describing history -- put the marker "
            "%s on that line, which asserts the opposite and is checked too."
            % (
                len(broken),
                "\n".join(
                    "  %s:%s  %s" % (path.relative_to(REPO_ROOT), number, node_id)
                    for path, number, node_id in broken
                ),
                NODE_ID_GONE_MARKER,
            ),
        )

    def test_node_ids_declared_gone_are_really_gone(self) -> None:
        resurrected = [
            (path, number, node_id)
            for path, number, node_id, declared_gone in self.documented
            if declared_gone and node_id_resolves(node_id, self.collected)
        ]
        self.assertEqual(
            [],
            resurrected,
            "%s node id(s) are marked %s but pytest collects them:\n%s\n"
            "The document says the test no longer exists and the suite says "
            "it does. Drop the marker and reword the sentence.\n"
            "ONE COMMON CAUSE, worth checking before rewording anything: the "
            "marker is LINE-scoped, so a line that merely EXPLAINS the marker "
            "while also naming a live test exempts that live test by "
            "accident. Move the explanation to a line of its own."
            % (
                len(resurrected),
                NODE_ID_GONE_MARKER,
                "\n".join(
                    "  %s:%s  %s" % (path.relative_to(REPO_ROOT), number, node_id)
                    for path, number, node_id in resurrected
                ),
            ),
        )

    def test_the_check_has_something_to_check(self) -> None:
        """A pass over zero documented ids proves nothing. See this module's
        opening argument: an empty scan and a clean scan look alike."""
        self.assertGreater(
            len(self.documented),
            0,
            "no pytest node id was found anywhere in the tree, so both checks "
            "above passed over an empty list. Either the documents stopped "
            "naming tests, or NODE_ID_RE / DOC_SUFFIXES stopped matching them. "
            "Scanned suffixes: %s" % sorted(DOC_SUFFIXES),
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
