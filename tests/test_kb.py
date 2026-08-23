#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for tools/kb/validate.py and tools/kb/new_log_entry.py.

Covers, per plan.md sections 9.3, 9.4 (K-03, K-05), 10.2, 10.4 (EV-03, EV-04),
10.5 (oracle matrix) and constraint C-11:

  * LOG-NNNN id auto-increment and append-only behaviour of the log generator;
  * every lint rule firing on a crafted bad record and passing on a good one;
  * the 10.5 oracle matrix rejecting a claim whose oracle cannot prove it.

Run:  D:\\Tools\\venv-research\\Scripts\\python.exe -m unittest discover -s tests
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(module_name: str, relative_path: str):
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


validate = _load("misery_kb_validate", "tools/kb/validate.py")
new_log_entry = _load("misery_kb_new_log_entry", "tools/kb/new_log_entry.py")

SHA = "sha256:" + "ab" * 32


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def good_record(**overrides) -> dict:
    """A record that must produce zero findings."""
    record = {
        "claim_type": "container-format",
        "oracle": ["container-metadata"],
        "evidence_level": "OBSERVED",
        "confidence": 0.85,
        "sources": ["F-02/utoc-header-parse", "manual-hexdump"],
        "build_key": SHA,
    }
    record.update(overrides)
    return record


def rules_of(findings, severity: str | None = None) -> set[str]:
    return {
        f.rule for f in findings
        if severity is None or f.severity == severity
    }


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _draft202012_or_skip(test):
    """The plain, registry-free validator a third party would reach for."""
    try:
        from jsonschema import Draft202012Validator
    except Exception:  # pragma: no cover - environment dependent
        test.skipTest("jsonschema is not installed in this interpreter")
    return Draft202012Validator


def _confidence_bounds_in_schema_dir():
    """Yield (path, json_pointer, subschema) for every declared confidence scale.

    Walks research/schema/*.schema.json instead of naming a pointer, so the
    published contract cannot quietly move its bound out of the test's view.
    Only nodes that declare BOTH ends of the scale are yielded: a node with an
    upper bound alone is a conditional NARROWING of the scale, such as the
    global-ucas branch that caps a name-only claim at 0.4, and that narrowing
    is a different rule with a different number.  A file that dropped its lower
    bound to slip out of this filter would drop out of the caller's coverage
    assertion instead.
    """
    schema_dir = REPO_ROOT / "research" / "schema"
    for path in sorted(schema_dir.glob("*.schema.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        stack = [("#", document)]
        while stack:
            pointer, node = stack.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    child = f"{pointer}/{key}"
                    if (isinstance(value, dict)
                            and isinstance(key, str)
                            and key.endswith("confidence")
                            and "minimum" in value
                            and ("maximum" in value or "exclusiveMaximum" in value)):
                        yield path, child, value
                    stack.append((child, value))
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    stack.append((f"{pointer}/{index}", value))


@contextlib.contextmanager
def quiet():
    """Swallow tool stdout/stderr so the test run stays readable."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield out, err


def run_log_main(argv) -> int:
    with quiet():
        return new_log_entry.main(argv)


def run_validate_main(argv) -> int:
    with quiet():
        return validate.main(argv)


# ---------------------------------------------------------------------------
# new_log_entry: id auto-increment
# ---------------------------------------------------------------------------

class TestLogIdAutoIncrement(unittest.TestCase):
    def test_first_id_when_log_is_absent_or_empty(self):
        self.assertEqual(new_log_entry.next_log_id(""), "LOG-0001")
        self.assertEqual(new_log_entry.next_log_id(new_log_entry.FILE_HEADER), "LOG-0001")

    def test_increments_from_highest_existing_id(self):
        text = (
            "# RESEARCH_LOG\n\n"
            "## 2026-08-22 - a\n- **ID:** LOG-0001\n\n"
            "## 2026-08-22 - b\n- **ID:** LOG-0007\n\n"
            "## 2026-08-22 - c\n- **ID:** LOG-0003\n"
        )
        self.assertEqual(new_log_entry.next_log_id(text), "LOG-0008")

    def test_supersedes_references_do_not_bump_the_counter(self):
        text = (
            "## 2026-08-22 - a\n"
            "- **ID:** LOG-0003\n"
            "- **Supersedes:** LOG-0099\n"
            "- **Next question:** see LOG-4242\n"
        )
        self.assertEqual(new_log_entry.next_log_id(text), "LOG-0004")

    def test_preserves_wider_id_width(self):
        text = "- **ID:** LOG-00042\n"
        self.assertEqual(new_log_entry.next_log_id(text), "LOG-00043")

    def test_next_id_after_real_append(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "RESEARCH_LOG.md"
            rc = run_log_main(["--question", "q1", "--log", str(log)])
            self.assertEqual(rc, 0)
            rc = run_log_main(["--question", "q2", "--log", str(log)])
            self.assertEqual(rc, 0)
            text = log.read_text(encoding="utf-8")
            self.assertIn("- **ID:** LOG-0001", text)
            self.assertIn("- **ID:** LOG-0002", text)
            self.assertLess(text.index("LOG-0001"), text.index("LOG-0002"))


# ---------------------------------------------------------------------------
# new_log_entry: append-only, template fidelity, TODO markers
# ---------------------------------------------------------------------------

class TestLogAppendOnly(unittest.TestCase):
    def test_creates_file_with_header_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "nested" / "RESEARCH_LOG.md"
            self.assertEqual(run_log_main(["--question", "q", "--log", str(log)]), 0)
            self.assertTrue(log.is_file())
            raw = log.read_bytes()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "log must be BOM-free")
            self.assertTrue(log.read_text(encoding="utf-8").startswith("# RESEARCH_LOG"))

    def test_existing_bytes_are_never_modified(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "RESEARCH_LOG.md"
            seed = "# RESEARCH_LOG\n\nseed text owned by another agent\n"
            write(log, seed)
            before = log.read_bytes()
            run_log_main(["--question", "q1", "--log", str(log)])
            after_one = log.read_bytes()
            run_log_main(["--question", "q2", "--log", str(log)])
            after_two = log.read_bytes()

            self.assertTrue(after_one.startswith(before))
            self.assertTrue(after_two.startswith(after_one))
            self.assertIn(seed.encode("utf-8"), after_two)

    def test_append_keeps_one_blank_line_between_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "RESEARCH_LOG.md"
            run_log_main(["--question", "q1", "--log", str(log)])
            run_log_main(["--question", "q2", "--log", str(log)])
            text = log.read_text(encoding="utf-8")
            self.assertNotIn("\n\n\n", text)
            self.assertEqual(text.count("\n## "), 2)

    def test_no_header_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "RESEARCH_LOG.md"
            run_log_main(["--question", "q", "--log", str(log), "--no-header"])
            self.assertTrue(log.read_text(encoding="utf-8").startswith("## "))

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "RESEARCH_LOG.md"
            self.assertEqual(
                run_log_main(["--question", "q", "--log", str(log), "--dry-run"]), 0)
            self.assertFalse(log.exists())


class TestLogTemplate(unittest.TestCase):
    EXPECTED_LABELS = [
        "- **ID:**",
        "- **Question:**",
        "- **Method:**",
        "- **Evidence:**",
        "- **Finding:**",
        "- **Evidence level:**",
        "- **Confidence:**",
        "- **Build:**",
        "- **Supersedes:**",
        "- **Next question:**",
    ]

    def test_field_order_matches_plan_9_3(self):
        entry = new_log_entry.render_entry(
            log_id="LOG-0042", date="2026-08-22", question="Что стартует Steam?")
        lines = entry.splitlines()
        self.assertEqual(lines[0], "## 2026-08-22 — Что стартует Steam?")
        positions = [entry.index(label) for label in self.EXPECTED_LABELS]
        self.assertEqual(positions, sorted(positions))
        # every rendered body line is one of the ten template labels
        for line in lines[1:]:
            self.assertTrue(any(line.startswith(label) for label in self.EXPECTED_LABELS),
                            f"unexpected line: {line!r}")

    def test_missing_optional_fields_render_todo_not_empty(self):
        entry = new_log_entry.render_entry(
            log_id="LOG-0001", date="2026-08-22", question="q")
        for line in entry.splitlines()[1:]:
            label, _, value = line.partition(":** ")
            self.assertTrue(value.strip(), f"empty value rendered for {label!r}")
        for label in ("- **Method:**", "- **Evidence:**", "- **Finding:**",
                      "- **Evidence level:**", "- **Confidence:**", "- **Build:**",
                      "- **Supersedes:**", "- **Next question:**"):
            index = entry.index(label)
            line = entry[index:entry.index("\n", index)]
            self.assertIn("TODO", line, f"{label} must carry a TODO marker")

    def test_supplied_fields_are_rendered_verbatim(self):
        entry = new_log_entry.render_entry(
            log_id="LOG-0009", date="2026-08-22",
            question="Совпадают ли имена RF-01 и RF-12?",
            method="RF-05 (Ghidra xrefs)",
            evidence="research/evidence/RF-05/xrefs-uobjectarray.json",
            finding="Совпадение 97%",
            level="INFERRED", confidence="0.65", build=SHA,
            supersedes="LOG-0031", next_question="Что с остальными 3%?")
        self.assertIn("- **Method:** RF-05 (Ghidra xrefs)", entry)
        self.assertIn("- **Confidence:** 0.65", entry)
        self.assertIn(f"- **Build:** build_key={SHA}", entry)
        self.assertIn("- **Supersedes:** LOG-0031", entry)
        self.assertNotIn("TODO", entry)

    def test_supersedes_none_is_accepted_explicitly(self):
        entry = new_log_entry.render_entry(
            log_id="LOG-0002", date="2026-08-22", question="q", supersedes="none")
        self.assertIn("- **Supersedes:** none", entry)

    def test_rejects_forbidden_confidence_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "RESEARCH_LOG.md"
            rc = run_log_main(
                ["--question", "q", "--confidence", "1.00", "--log", str(log)])
            self.assertEqual(rc, 2)
            self.assertFalse(log.exists())

    def test_rejects_out_of_range_confidence_and_bad_date(self):
        self.assertEqual(run_log_main(["--question", "q", "--confidence", "1.4",
                                             "--dry-run"]), 2)
        self.assertEqual(run_log_main(["--question", "q", "--date", "22-08-2026",
                                             "--dry-run"]), 2)
        self.assertEqual(run_log_main(["--question", "q", "--supersedes", "0031",
                                             "--dry-run"]), 2)


# ---------------------------------------------------------------------------
# validate.py: the good record
# ---------------------------------------------------------------------------

class TestGoodRecords(unittest.TestCase):
    def test_container_format_record_is_clean(self):
        self.assertEqual(validate.lint_record("$", good_record()), [])

    def test_property_layout_record_is_clean(self):
        record = good_record(
            claim_type="class-property",
            oracle=["runtime-reflection"],
            sources=["RF-12/dump-1", "RF-12/dump-2"],
            raw_name="MiseryCharacter::Health",
            offset=1234,
            size=4,
        )
        self.assertEqual(validate.lint_record("$", record), [])

    def test_vanilla_ue_reference_needs_no_build_key_but_needs_notes(self):
        """A build-independent record is clean only if it says why (kb-record schema).

        Since validator 3.2.0 claim_type='other' additionally needs a written
        justification: it is the one catch-all in the rule set and therefore a
        route past both the specific oracle pairings and the build_key
        requirement, so using it costs one sentence naming the missing 10.5 row.
        """
        record = {
            "claim_type": "other",
            "oracle": "external-doc",
            "evidence_level": "INFERRED",
            "confidence": 0.6,
            "sources": ["UE 5.4 source: IoStoreToc.h"],
            "notes": "Statement about vanilla UE 5.4 only, therefore build-independent.",
            "claim_type_note": "plan.md 10.5 has no row for a statement about "
                               "vanilla UE rather than about this build.",
        }
        self.assertEqual(validate.lint_record("$", record), [])

        without_notes = dict(record)
        del without_notes["notes"]
        self.assertIn("EV-BUILD", rules_of(validate.lint_record("$", without_notes),
                                           validate.SEVERITY_WARN))

    def test_name_only_global_ucas_record_is_clean_within_its_limits(self):
        record = {
            "claim_type": "native-class-exists",
            "oracle": ["global-ucas"],
            "evidence_level": "OBSERVED",
            "confidence": 0.75,
            "sources": ["RF-01/global-ucas-name-pool"],
            "raw_name": "MiseryFocusSubsystem",
            "build_key": SHA,
        }
        self.assertEqual(validate.lint_record("$", record), [])


# ---------------------------------------------------------------------------
# validate.py: EV-03
# ---------------------------------------------------------------------------

class TestEv03(unittest.TestCase):
    def test_high_confidence_with_one_source_is_rejected(self):
        findings = validate.lint_record("$", good_record(confidence=0.9, sources=["F-02"]))
        self.assertIn("EV-03", rules_of(findings, validate.SEVERITY_ERROR))

    def test_high_confidence_with_two_sources_passes(self):
        findings = validate.lint_record(
            "$", good_record(confidence=0.9, sources=["F-02", "third-party-utoc-dump"]))
        self.assertEqual(findings, [])

    def test_low_confidence_with_one_source_passes(self):
        findings = validate.lint_record("$", good_record(confidence=0.6, sources=["F-02"]))
        self.assertEqual(findings, [])

    def test_missing_sources_is_rejected(self):
        record = good_record()
        del record["sources"]
        self.assertIn("EV-03", rules_of(validate.lint_record("$", record),
                                        validate.SEVERITY_ERROR))

    def test_sources_must_be_a_list(self):
        findings = validate.lint_record("$", good_record(sources="F-02"))
        self.assertIn("EV-03", rules_of(findings, validate.SEVERITY_ERROR))

    def test_plan_6_3_source_alias_is_accepted(self):
        record = good_record()
        del record["sources"]
        record["source"] = ["RF-01", "RF-12"]
        self.assertEqual(validate.lint_record("$", record), [])

    def test_duplicate_sources_warn(self):
        findings = validate.lint_record("$", good_record(sources=["F-02", "F-02"]))
        self.assertIn("EV-03", rules_of(findings, validate.SEVERITY_WARN))


# ---------------------------------------------------------------------------
# validate.py: EV-04 and the 10.5 matrix
# ---------------------------------------------------------------------------

class TestEv04OracleMatrix(unittest.TestCase):
    def test_missing_oracle_is_rejected(self):
        record = good_record()
        del record["oracle"]
        findings = validate.lint_record("$", record)
        self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_ERROR))

    def test_unknown_oracle_value_is_rejected(self):
        findings = validate.lint_record("$", good_record(oracle=["vibes"]))
        self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_ERROR))

    def test_missing_claim_type_is_rejected(self):
        record = good_record()
        del record["claim_type"]
        self.assertIn("EV-04", rules_of(validate.lint_record("$", record),
                                        validate.SEVERITY_ERROR))

    def test_unknown_claim_type_is_rejected(self):
        findings = validate.lint_record("$", good_record(claim_type="vibes-based"))
        self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_ERROR))

    def test_matrix_rejects_asset_existence_from_global_ucas(self):
        """plan.md 10.5: asserting a /Game asset needs asset-registry or reflection.

        The one exception the plan writes out itself is the HYPOTHESIS: "Имя
        вида BP_Something_C, найденное в пуле имён, даёт только HYPOTHESIS о
        существовании соответствующего asset-а, с confidence <= 0.4".  Until
        validator 3.2.0 the matrix row was unconditional, so it rejected the
        plan's own canonical correct example (research/evidence-model.md's
        "ВЕРНОЕ оформление" table) - a gate stricter than its rule book, which
        is how the correct record becomes the one that fails.
        """
        hypothesis = {
            "claim_type": "asset-exists",
            "oracle": ["global-ucas"],
            "evidence_level": "HYPOTHESIS",
            "confidence": 0.4,
            "sources": ["RF-01/global-ucas-name-pool"],
            "build_key": SHA,
        }
        self.assertEqual(validate.lint_record("$", hypothesis), [])

        # Anything stronger than the hypothesis is the assertion, and the
        # assertion needs the matrix oracles.
        for stronger in (dict(hypothesis, confidence=0.5),
                         dict(hypothesis, evidence_level="OBSERVED")):
            findings = validate.lint_record("$", stronger)
            self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_ERROR),
                          msg=repr(stronger))
            message = " ".join(f.message for f in findings if f.rule == "EV-04")
            self.assertIn("asset-registry", message)

    def test_matrix_accepts_asset_existence_from_asset_registry(self):
        record = {
            "claim_type": "asset-exists",
            "oracle": ["asset-registry"],
            "evidence_level": "OBSERVED",
            "confidence": 0.7,
            "sources": ["I-15/asset-registry-dump"],
            "build_key": SHA,
        }
        self.assertEqual(validate.lint_record("$", record), [])

    def test_matrix_requires_both_oracles_for_function_behavior(self):
        base = {
            "claim_type": "function-behavior",
            "evidence_level": "INFERRED",
            "confidence": 0.7,
            "sources": ["ST-04/decompile", "RF-12/runtime-dump"],
            "build_key": SHA,
        }
        only_static = dict(base, oracle=["binary-analysis"])
        findings = validate.lint_record("$", only_static)
        self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_ERROR))

        both = dict(base, oracle=["binary-analysis", "runtime-reflection"])
        self.assertEqual(validate.lint_record("$", both), [])

    def test_matrix_rejects_mount_claim_from_container_metadata(self):
        record = {
            "claim_type": "container-mounted-at-runtime",
            "oracle": ["container-metadata"],
            "evidence_level": "INFERRED",
            "confidence": 0.7,
            "sources": ["F-02/utoc-header"],
            "build_key": SHA,
        }
        findings = validate.lint_record("$", record)
        self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_ERROR))

    def test_registration_mechanism_needs_two_oracles_and_warns_on_missing_recommended(self):
        record = {
            "claim_type": "item-registration-mechanism",
            "oracle": ["runtime-reflection", "asset-registry"],
            "evidence_level": "INFERRED",
            "confidence": 0.7,
            "sources": ["I-15", "RF-12"],
            "build_key": SHA,
        }
        findings = validate.lint_record("$", record)
        self.assertEqual(rules_of(findings, validate.SEVERITY_ERROR), set())
        self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_WARN))

        one_only = dict(record, oracle=["runtime-reflection"])
        self.assertIn("EV-04", rules_of(validate.lint_record("$", one_only),
                                        validate.SEVERITY_ERROR))

    def test_e3b_claim_requires_an_experiment_reference(self):
        record = {
            "claim_type": "cooked-bp-from-external-container-works",
            "oracle": ["runtime-reflection"],
            "evidence_level": "OBSERVED",
            "confidence": 0.7,
            "sources": ["E-3b/run-1"],
            "build_key": SHA,
        }
        findings = validate.lint_record("$", record)
        self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_ERROR))
        with_experiment = dict(record, experiment="E-3b")
        self.assertEqual(validate.lint_record("$", with_experiment), [])

    def test_older_claim_type_spellings_are_aliased(self):
        for alias, canonical in validate.CLAIM_TYPE_ALIASES.items():
            self.assertIn(canonical, validate.CLAIM_TYPE_ORACLE_MATRIX,
                          f"alias {alias} points at unknown {canonical}")
            self.assertEqual(validate.resolve_claim_type(alias), canonical)
        record = good_record(claim_type="property-layout",
                             oracle=["runtime-reflection"], offset=8,
                             sources=["RF-12/a", "RF-12/b"])
        self.assertEqual(validate.lint_record("$", record), [])

    def test_matrix_covers_the_kb_record_schema_enum(self):
        """Guard against vocabulary drift between validate.py and the schemas."""
        schema_path = REPO_ROOT / "research" / "schema" / "kb-record.schema.json"
        if not schema_path.is_file():
            self.skipTest("kb-record.schema.json not present yet")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        enum = schema.get("$defs", {}).get("claim_type", {}).get("enum")
        if not enum:
            self.skipTest("kb-record.schema.json declares no claim_type enum")
        declared = {value for value in enum if isinstance(value, str)}
        known = set(validate.CLAIM_TYPE_ORACLE_MATRIX) | set(validate.CLAIM_TYPE_ALIASES)
        self.assertEqual(declared - known, set(),
                         "claim types accepted by the schema but unknown to the linter")

    def test_untyped_claims_can_be_downgraded_to_a_warning(self):
        record = good_record()
        del record["claim_type"]
        strict = validate.lint_record("$", record)
        self.assertIn("EV-04", rules_of(strict, validate.SEVERITY_ERROR))
        lenient = validate.lint_record("$", record, allow_untyped_claims=True)
        self.assertEqual(rules_of(lenient, validate.SEVERITY_ERROR), set())
        self.assertIn("EV-04", rules_of(lenient, validate.SEVERITY_WARN))

    def test_static_only_layout_must_stay_a_hypothesis(self):
        """plan.md 6.3: an offset from static analysis is a HYPOTHESIS."""
        record = {
            "claim_type": "layout-observation",
            "oracle": ["binary-analysis"],
            "evidence_level": "OBSERVED",
            "confidence": 0.6,
            "sources": ["ST-06/vtable-scan"],
            "build_key": SHA,
            "offset": 40,
        }
        self.assertIn("EV-LAYOUT", rules_of(validate.lint_record("$", record),
                                            validate.SEVERITY_ERROR))
        as_hypothesis = dict(record, evidence_level="HYPOTHESIS")
        self.assertEqual(validate.lint_record("$", as_hypothesis), [])
        from_runtime = dict(record, oracle=["runtime-reflection"])
        self.assertEqual(validate.lint_record("$", from_runtime), [])

    def test_matrix_only_references_known_oracles(self):
        known = set(validate.ORACLES)
        for name, requirement in validate.CLAIM_TYPE_ORACLE_MATRIX.items():
            referenced = requirement.all_of | requirement.any_of | requirement.recommended
            self.assertTrue(referenced, f"{name} constrains nothing")
            self.assertTrue(referenced <= known,
                            f"{name} references unknown oracle(s): {referenced - known}")
            self.assertTrue(requirement.provenance,
                            f"{name} has no provenance comment")


# ---------------------------------------------------------------------------
# validate.py: C-11
# ---------------------------------------------------------------------------

class TestC11GlobalUcasBoundary(unittest.TestCase):
    def _base(self, **over):
        record = {
            "claim_type": "native-class-exists",
            "oracle": ["global-ucas"],
            "evidence_level": "HYPOTHESIS",
            "confidence": 0.4,
            "sources": ["RF-01/global-ucas-name-pool"],
            "build_key": SHA,
        }
        record.update(over)
        return record

    def test_game_path_with_global_ucas_only_is_flagged(self):
        findings = validate.lint_record("$", self._base(
            raw_name="BP_PlayerCharacter_C",
            package="/Game/Characters/BP_PlayerCharacter"))
        self.assertIn("C-11", rules_of(findings, validate.SEVERITY_ERROR))

    def test_offsets_with_global_ucas_only_are_flagged(self):
        findings = validate.lint_record("$", self._base(offset=64, size=4096))
        self.assertIn("C-11", rules_of(findings, validate.SEVERITY_ERROR))
        message = " ".join(f.message for f in findings if f.rule == "C-11")
        self.assertIn("offset", message)

    def test_unknown_placeholders_do_not_trip_c11(self):
        findings = validate.lint_record("$", self._base(size="UNKNOWN", offset=None))
        self.assertEqual(findings, [])

    def test_confidence_cap_for_blueprint_shaped_name(self):
        findings = validate.lint_record("$", self._base(
            raw_name="BP_Something_C", confidence=0.75,
            sources=["RF-01", "RF-01b"]))
        self.assertIn("C-11", rules_of(findings, validate.SEVERITY_ERROR))

    def test_evidence_level_cap_for_blueprint_shaped_name(self):
        findings = validate.lint_record("$", self._base(
            raw_name="BP_Something_C", evidence_level="OBSERVED"))
        self.assertIn("C-11", rules_of(findings, validate.SEVERITY_ERROR))

    def test_same_layout_claim_passes_with_runtime_reflection(self):
        record = self._base(
            claim_type="class-property",
            oracle=["runtime-reflection"],
            evidence_level="OBSERVED",
            confidence=0.75,
            offset=64,
            size=4096,
            package="/Game/Characters/BP_PlayerCharacter",
            raw_name="BP_PlayerCharacter_C",
        )
        self.assertEqual(validate.lint_record("$", record), [])

    def test_c12_caps_external_doc_only_confidence(self):
        record = {
            "claim_type": "other",
            "oracle": ["external-doc"],
            "evidence_level": "INFERRED",
            "confidence": 0.9,
            "sources": ["UE docs", "third-party tool"],
        }
        self.assertIn("C-12", rules_of(validate.lint_record("$", record),
                                       validate.SEVERITY_ERROR))


# ---------------------------------------------------------------------------
# validate.py: confidence, evidence_level, build_key
# ---------------------------------------------------------------------------

class TestScalarFieldRules(unittest.TestCase):
    def test_confidence_one_is_forbidden(self):
        findings = validate.lint_record("$", good_record(confidence=1.0))
        self.assertIn("EV-CONF", rules_of(findings, validate.SEVERITY_ERROR))

    def test_confidence_out_of_range(self):
        for value in (-0.1, 1.5):
            findings = validate.lint_record("$", good_record(confidence=value))
            self.assertIn("EV-CONF", rules_of(findings, validate.SEVERITY_ERROR),
                          f"confidence {value} must be rejected")

    def test_confidence_must_be_numeric(self):
        findings = validate.lint_record("$", good_record(confidence="high"))
        self.assertIn("EV-CONF", rules_of(findings, validate.SEVERITY_ERROR))

    def test_missing_confidence(self):
        record = good_record()
        del record["confidence"]
        self.assertIn("EV-CONF", rules_of(validate.lint_record("$", record),
                                          validate.SEVERITY_ERROR))

    def test_evidence_level_enum(self):
        for level in validate.EVIDENCE_LEVELS:
            findings = validate.lint_record(
                "$", good_record(evidence_level=level, confidence=0.5, sources=["F-02"],
                                 refuted_by=["LOG-0001"]))
            self.assertEqual(rules_of(findings, validate.SEVERITY_ERROR), set(),
                             f"{level} must be accepted")
        findings = validate.lint_record("$", good_record(evidence_level="PROBABLY"))
        self.assertIn("EV-LEVEL", rules_of(findings, validate.SEVERITY_ERROR))

    def test_refuted_record_must_name_what_refuted_it(self):
        findings = validate.lint_record("$", good_record(evidence_level="REFUTED"))
        self.assertIn("EV-REFUTED", rules_of(findings, validate.SEVERITY_ERROR))
        ok = good_record(evidence_level="REFUTED", refuted_by=["LOG-0042"])
        self.assertEqual(validate.lint_record("$", ok), [])

    def test_missing_evidence_level(self):
        record = good_record()
        del record["evidence_level"]
        self.assertIn("EV-LEVEL", rules_of(validate.lint_record("$", record),
                                           validate.SEVERITY_ERROR))

    def test_missing_build_key_on_build_specific_claim(self):
        record = good_record()
        del record["build_key"]
        findings = validate.lint_record("$", record)
        self.assertIn("EV-BUILD", rules_of(findings, validate.SEVERITY_ERROR))

    def test_malformed_build_key(self):
        findings = validate.lint_record("$", good_record(build_key="abc123"))
        self.assertIn("EV-BUILD", rules_of(findings, validate.SEVERITY_ERROR))

    def test_unknown_build_key_literal_is_allowed(self):
        findings = validate.lint_record("$", good_record(build_key="UNKNOWN"))
        self.assertEqual(findings, [])

    def test_layout_fields_force_build_key_even_for_lenient_claim_types(self):
        record = {
            "claim_type": "other",
            "oracle": ["external-doc"],
            "evidence_level": "INFERRED",
            "confidence": 0.5,
            "sources": ["UE 5.4 source"],
            "offset": 32,
        }
        self.assertIn("EV-BUILD", rules_of(validate.lint_record("$", record),
                                           validate.SEVERITY_ERROR))


# ---------------------------------------------------------------------------
# validate.py: mapping table, record extraction, schema layer
# ---------------------------------------------------------------------------

class TestMappingTable(unittest.TestCase):
    def test_known_artifacts_map_to_schemas(self):
        cases = {
            "builds/index.json": "build-index.schema.json",
            "builds/misery-24826585-ue5.4.4-abc/install.json": "install.schema.json",
            "builds/misery-24826585-ue5.4.4-abc/install-inventory.json":
                "install-inventory.schema.json",
            "builds/misery-24826585-ue5.4.4-abc/fingerprint.json": "fingerprint.schema.json",
            "reflection/sha256-abc/classes.jsonl": "reflection-record.schema.json",
            "reflection/sha256-abc/properties.jsonl": "reflection-record.schema.json",
            "packages/experiments/E-3b/result.json": "experiment-result.schema.json",
            "packages/package-index.jsonl": "package-index.schema.json",
            "unreal/engine-version.json": "engine-version.schema.json",
        }
        for relpath, schema in cases.items():
            rule = validate.lookup_rule(relpath)
            self.assertIsNotNone(rule, f"{relpath} is unmapped")
            self.assertEqual(rule.schema, schema)

    def test_star_does_not_cross_a_path_separator(self):
        self.assertIsNone(validate.lookup_rule("builds/a/b/install.json"))

    def test_unmapped_path_returns_none(self):
        self.assertIsNone(validate.lookup_rule("something/else.json"))

    def test_evidence_dir_is_mapped_but_schema_free(self):
        rule = validate.lookup_rule("evidence/RF-05/xrefs.json")
        self.assertIsNotNone(rule)
        self.assertIsNone(rule.schema)

    def test_windows_separators_are_normalised(self):
        rule = validate.lookup_rule(r"builds\b1\install.json")
        self.assertIsNotNone(rule)


class TestRecordExtraction(unittest.TestCase):
    def test_nested_records_are_found_with_pointers(self):
        document = {
            "generated_at": "2026-08-22T00:00:00Z",
            "executables": [
                {"path": "a.exe", "claims": [good_record()]},
            ],
        }
        found = dict(validate.iter_records(document))
        self.assertIn("$.executables[0].claims[0]", found)
        self.assertEqual(len(found), 1)

    def test_plain_data_is_not_a_record(self):
        self.assertEqual(list(validate.iter_records({"path": "a", "size": 1})), [])

    def test_schema_shaped_document_is_not_a_record(self):
        """A JSON Schema declaring claim_type/confidence must not be linted."""
        schema = {
            "type": "object",
            "properties": {
                "claim_type": {"enum": sorted(validate.CLAIM_TYPE_ORACLE_MATRIX)},
                "confidence": {"type": "number"},
                "oracle": {"type": "array"},
            },
        }
        self.assertEqual(list(validate.iter_records(schema)), [])

    def test_non_string_claim_type_is_a_finding_not_a_crash(self):
        findings = validate.lint_record("$", good_record(claim_type={"enum": ["a"]}))
        self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_ERROR))


class TestMinimalSchemaValidator(unittest.TestCase):
    SCHEMA = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["build_key", "confidence", "evidence_level"],
        "properties": {
            "build_key": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "confidence": {"type": "number", "minimum": 0.0, "exclusiveMaximum": 1.0},
            "evidence_level": {"enum": list(validate.EVIDENCE_LEVELS)},
            "sources": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "oracle": {"$ref": "#/$defs/oracleList"},
        },
        "$defs": {
            "oracleList": {
                "type": "array",
                "items": {"enum": list(validate.ORACLES)},
            },
        },
    }

    def test_valid_instance_has_no_errors(self):
        errors, ignored, backend = validate.validate_against_schema(good_record(), self.SCHEMA)
        self.assertEqual(errors, [], f"backend={backend} ignored={ignored}")

    def test_required_type_enum_pattern_and_ref_are_enforced(self):
        bad = {
            "build_key": "nope",
            "confidence": "0.9",
            "evidence_level": "PROBABLY",
            "sources": [],
            "oracle": ["vibes"],
        }
        errors, _ignored, _backend = validate.validate_against_schema(bad, self.SCHEMA)
        blob = " ".join(f"{ptr} {msg}" for ptr, msg in errors)
        self.assertIn("build_key", blob)
        self.assertIn("confidence", blob)
        self.assertIn("evidence_level", blob)
        self.assertIn("oracle", blob)

    def test_missing_required_property_is_reported(self):
        errors, _ignored, _backend = validate.validate_against_schema({}, self.SCHEMA)
        self.assertTrue(errors)

    def test_cross_file_ref_resolves_from_the_schema_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            schema_dir = Path(tmp)
            write(schema_dir / "kb-record.schema.json", json.dumps({
                "$id": "https://miseryframework.invalid/schema/kb-record.schema.json",
                "$defs": {"envelope": {"type": "object", "required": ["oracle"]}},
            }))
            composing = {
                "type": "object",
                "allOf": [{"$ref": "kb-record.schema.json#/$defs/envelope"}],
            }
            ok, _ignored, _backend = validate.validate_against_schema(
                {"oracle": ["container-metadata"]}, composing, schema_dir=schema_dir)
            self.assertEqual(ok, [])
            bad, _ignored, _backend = validate.validate_against_schema(
                {}, composing, schema_dir=schema_dir)
            self.assertTrue(bad, "cross-file $ref must actually be enforced")

    def test_real_repository_schemas_are_parseable(self):
        schema_dir = REPO_ROOT / "research" / "schema"
        if not schema_dir.is_dir():
            self.skipTest("research/schema does not exist yet")
        reports = validate.check_schema_dir(schema_dir)
        broken = {r.path: [f.message for f in r.findings if f.severity == "ERROR"]
                  for r in reports if r.errors}
        self.assertEqual(broken, {})

    def test_conditional_and_array_keywords_are_enforced(self):
        schema = {
            "type": "object",
            "properties": {
                "oracle": {"type": "array", "uniqueItems": True,
                           "contains": {"const": "runtime-reflection"}},
            },
            "if": {"properties": {"confidence": {"minimum": 0.8}},
                   "required": ["confidence"]},
            "then": {"properties": {"sources": {"minItems": 2}}},
        }
        ok = {"oracle": ["runtime-reflection", "binary-analysis"],
              "confidence": 0.9, "sources": ["a", "b"]}
        errors, ignored, _backend = validate.validate_against_schema(ok, schema)
        self.assertEqual(errors, [], f"ignored={ignored}")

        thin = {"oracle": ["runtime-reflection"], "confidence": 0.9, "sources": ["a"]}
        errors, _ignored, _backend = validate.validate_against_schema(thin, schema)
        self.assertTrue(errors, "if/then must enforce minItems on sources")

        dupes = {"oracle": ["runtime-reflection", "runtime-reflection"],
                 "confidence": 0.5, "sources": ["a"]}
        errors, _ignored, _backend = validate.validate_against_schema(dupes, schema)
        self.assertTrue(errors, "uniqueItems must be enforced")

        missing = {"oracle": ["global-ucas"], "confidence": 0.5, "sources": ["a"]}
        errors, _ignored, _backend = validate.validate_against_schema(missing, schema)
        self.assertTrue(errors, "contains must be enforced")

    def test_backend_is_reported_honestly(self):
        _errors, _ignored, backend = validate.validate_against_schema({}, self.SCHEMA)
        self.assertEqual(backend, validate.SCHEMA_BACKEND)
        self.assertIn(backend, ("jsonschema", "builtin-minimal"))


# ---------------------------------------------------------------------------
# validate.py: end to end
# ---------------------------------------------------------------------------

class TestEndToEnd(unittest.TestCase):
    def _tree(self, tmp: Path) -> tuple[Path, Path]:
        research = tmp / "research"
        schema_dir = research / "schema"
        schema_dir.mkdir(parents=True)
        return research, schema_dir

    def test_clean_tree_exits_zero_and_missing_schema_is_only_a_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research, schema_dir = self._tree(root)
            write(research / "reflection" / "k" / "classes.jsonl",
                  json.dumps(good_record(claim_type="native-class-exists",
                                         oracle=["global-ucas"],
                                         raw_name="MiseryFocusSubsystem",
                                         confidence=0.7,
                                         sources=["RF-01"]), ensure_ascii=False) + "\n")
            reports, _ignored = validate.run(root, research, schema_dir)
            self.assertEqual(len(reports), 1)
            self.assertEqual(reports[0].errors, 0)
            self.assertEqual(reports[0].warnings, 1)  # schema file absent
            self.assertEqual(validate.exit_code(reports, strict=False), 0)
            self.assertEqual(validate.exit_code(reports, strict=True), 1)

    def test_violation_makes_main_exit_one_and_json_output_is_wellformed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research, schema_dir = self._tree(root)
            bad = good_record(confidence=0.95, sources=["F-02"])
            write(research / "packages" / "package-index.jsonl",
                  json.dumps(bad) + "\n" + "{not json}\n")

            rc = run_validate_main(["--repo-root", str(root), "--research-dir", str(research),
                                "--schema-dir", str(schema_dir), "--json"])
            self.assertEqual(rc, 1)

            reports, _ignored = validate.run(root, research, schema_dir)
            payload = validate.build_json_output(reports, set(), False)
            self.assertEqual(payload["summary"]["exit_code"], 1)
            self.assertGreaterEqual(payload["summary"]["violations"], 2)
            self.assertEqual(payload["schema_backend"], validate.SCHEMA_BACKEND)
            rules = {f["rule"] for f in payload["files"][0]["findings"]}
            self.assertIn("EV-03", rules)
            self.assertIn("PARSE", rules)
            # report path is repo-relative
            self.assertEqual(payload["files"][0]["path"],
                             "research/packages/package-index.jsonl")

    def test_schema_layer_runs_when_schema_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research, schema_dir = self._tree(root)
            write(schema_dir / "build-index.schema.json",
                  json.dumps({"type": "object", "required": ["builds"]}))
            write(research / "builds" / "index.json", json.dumps({"wrong": True}))
            reports, _ignored = validate.run(root, research, schema_dir)
            report = next(r for r in reports if r.path.endswith("builds/index.json"))
            self.assertEqual(report.schema_status, "loaded")
            self.assertIn("SCHEMA", rules_of(report.findings, validate.SEVERITY_ERROR))

    def test_unmapped_artifact_warns_but_is_still_linted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research, schema_dir = self._tree(root)
            write(research / "systems" / "inventory.json",
                  json.dumps(good_record(confidence=0.9, sources=["F-02"])))
            reports, _ignored = validate.run(root, research, schema_dir)
            self.assertIn("MAP", rules_of(reports[0].findings, validate.SEVERITY_WARN))
            self.assertIn("EV-03", rules_of(reports[0].findings, validate.SEVERITY_ERROR))

    def test_bom_is_a_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research, schema_dir = self._tree(root)
            path = research / "builds" / "index.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            with io.open(path, "w", encoding="utf-8-sig", newline="\n") as fh:
                fh.write(json.dumps({"builds": []}))
            reports, _ignored = validate.run(root, research, schema_dir)
            self.assertIn("IO", rules_of(reports[0].findings, validate.SEVERITY_ERROR))

    def test_schema_directory_is_self_checked_not_linted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research, schema_dir = self._tree(root)
            write(schema_dir / "classes.schema.json", json.dumps({
                "type": "object",
                "properties": {"claim_type": {"type": "string"},
                               "confidence": {"type": "number"}},
            }))
            write(schema_dir / "broken.schema.json", "{ this is not json")
            reports, _ignored = validate.run(root, research, schema_dir)
            by_name = {Path(r.path).name: r for r in reports}
            self.assertEqual(by_name["classes.schema.json"].findings, [])
            self.assertEqual(by_name["classes.schema.json"].record_count, 0)
            self.assertIn("SCHEMA", rules_of(by_name["broken.schema.json"].findings,
                                             validate.SEVERITY_ERROR))
            self.assertEqual(validate.exit_code(reports, strict=False), 1)

    def test_sqlite_cache_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research, schema_dir = self._tree(root)
            write(research / "reflection" / "k" / "reflection.sqlite.json", "{}")
            write(research / "reflection" / "k" / "cache.sqlite", "not json at all")
            reports, _ignored = validate.run(root, research, schema_dir)
            self.assertEqual([Path(r.path).name for r in reports],
                             ["reflection.sqlite.json"])

    def test_empty_tree_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research, schema_dir = self._tree(root)
            rc = run_validate_main(["--repo-root", str(root), "--research-dir", str(research),
                                "--schema-dir", str(schema_dir)])
            self.assertEqual(rc, 0)

    def test_missing_target_returns_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research, schema_dir = self._tree(root)
            rc = run_validate_main([str(root / "nope.json"), "--repo-root", str(root),
                                "--research-dir", str(research),
                                "--schema-dir", str(schema_dir)])
            self.assertEqual(rc, 2)


# ---------------------------------------------------------------------------
# validate.py: the markdown fact layer (BLOCKER-2)
# ---------------------------------------------------------------------------
# The validator used to glob only *.json/*.jsonl and only recognise objects
# carrying evidence_level / claim_type / oracle / confidence, so it reported
# "records: 0" over a repository whose facts all live in markdown prose.  Every
# test below exists to keep that hole shut.

TABLE_HEADER = ("| ID | Утверждение | Level | Conf. | Oracle | Метод |\n"
                "|---|---|---|---|---|---|\n")


def md_records(text: str):
    extractor = validate.MarkdownExtractor("test.md", text)
    extractor.run()
    return extractor


def md_findings(text: str, reachability=None):
    extractor = md_records(text)
    findings = []
    for record in extractor.records:
        findings.extend(validate.lint_markdown_record(record, reachability=reachability))
    return extractor, findings


def table_row(claim: str, level: str = "OBSERVED", conf: str = "0.99",
              oracle: str = "`filesystem`",
              method: str = "обход ФС; повторено 2026-08-22") -> str:
    return TABLE_HEADER + f"| T-01 | {claim} | {level} | {conf} | {oracle} | {method} |\n"


class FakeReachability:
    """Stands in for git, so tests never run a state-changing git command."""

    def __init__(self, statuses: dict[str, str]) -> None:
        self.statuses = statuses

    def status(self, ref: str) -> str:
        return self.statuses.get(ref, validate.CommitReachability.STATUS_REACHABLE)


class TestMarkdownNotations(unittest.TestCase):
    """One test per notation form actually used in the repository."""

    def test_fact_table_row_is_a_record(self):
        extractor = md_records(table_row("файл X существует"))
        self.assertEqual(len(extractor.records), 1)
        record = extractor.records[0]
        self.assertEqual(record.notation, validate.NOTATION_TABLE)
        self.assertEqual(record.ident, "T-01")
        self.assertEqual(record.level, "OBSERVED")
        self.assertEqual(record.confidence, 0.99)
        self.assertEqual(record.oracles, {"filesystem"})
        self.assertEqual(validate.lint_markdown_record(record), [])

    def test_fact_table_tolerates_decoration_and_parenthetical_prose(self):
        text = TABLE_HEADER + (
            "| T-02 | вопрос | **HYPOTHESIS** (историческое) | **0.65** | "
            "`binary-analysis` (секции) + `external-doc` | PE-заголовки; A-05 |\n")
        record = md_records(text).records[0]
        self.assertEqual(record.level, "HYPOTHESIS")
        self.assertEqual(record.confidence, 0.65)
        self.assertEqual(record.oracles, {"binary-analysis", "external-doc"})

    def test_fact_table_row_with_escaped_pipe_is_not_unparseable(self):
        text = TABLE_HEADER + (
            "| T-03 | размер файла | OBSERVED | 0.99 | `filesystem` | "
            "`git cat-file -p HEAD:f \\| wc -l`; повторено |\n")
        extractor = md_records(text)
        self.assertEqual(extractor.unparseable, [])
        self.assertEqual(len(extractor.records), 1)

    def test_table_without_level_or_confidence_column_is_not_a_fact_table(self):
        text = ("| ID | Вопрос | Статус | Oracle (§10.5) |\n"
                "|---|---|---|---|\n"
                "| Q-8.3 | есть ли анти-чит | UNKNOWN | `binary-analysis` |\n")
        extractor = md_records(text)
        self.assertEqual(extractor.records, [])
        self.assertEqual(extractor.non_fact_tables, 1)

    def test_inline_parenthetical_annotation_is_a_record(self):
        text = ("Установка содержит 53 файла. "
                "*(OBSERVED, confidence 0.99, oracle: filesystem, 2026-08-22)*\n")
        extractor = md_records(text)
        self.assertEqual(len(extractor.records), 1)
        record = extractor.records[0]
        self.assertEqual(record.notation, validate.NOTATION_INLINE)
        self.assertEqual(record.level, "OBSERVED")
        self.assertEqual(record.confidence, 0.99)
        self.assertEqual(record.oracles, {"filesystem"})

    def test_inline_bold_annotation_is_a_record(self):
        text = ("Утверждение «это Development build» — **HYPOTHESIS, confidence 0.65, "
                "oracle: binary-analysis (секции) + external-doc (практика UE)**.\n")
        record = md_records(text).records[0]
        self.assertEqual(record.level, "HYPOTHESIS")
        self.assertEqual(record.confidence, 0.65)
        self.assertEqual(record.oracles, {"binary-analysis", "external-doc"})

    def test_bold_wrapping_a_graded_parenthesis_yields_one_record(self):
        text = "**Что наблюдается (OBSERVED, ~0.95).** Дальше текст.\n"
        self.assertEqual(len(md_records(text).records), 1)

    def test_bare_emphasis_is_not_an_annotation(self):
        text = "**Статус: UNKNOWN.** Обычное выделение слова, не запись.\n"
        self.assertEqual(md_records(text).records, [])

    def test_bare_level_marker_is_reported_not_dropped(self):
        extractor, findings = md_findings("Ghidra 12.1.3 стоит в D:\\Tools (`OBSERVED`).\n")
        self.assertEqual(len(extractor.records), 1)
        self.assertIn("MD-BARE", rules_of(findings, validate.SEVERITY_WARN))

    def test_research_log_entry_block_is_a_record(self):
        text = (
            "## 2026-08-22 — что это за сборка\n"
            "- **ID:** LOG-0001\n"
            "- **Method:** RF-05 (Ghidra xrefs)\n"
            "- **Evidence:** research/evidence/RF-05/xrefs.json\n"
            "- **Evidence level:** INFERRED\n"
            "- **Confidence:** 0.65\n"
            "- **Oracle:** `container-metadata` + `binary-analysis`\n"
            "- **Build:** build_key=UNKNOWN\n")
        extractor = md_records(text)
        self.assertEqual(len(extractor.records), 1)
        record = extractor.records[0]
        self.assertEqual(record.notation, validate.NOTATION_LOG)
        self.assertEqual(record.ident, "LOG-0001")
        self.assertEqual(record.level, "INFERRED")
        self.assertEqual(record.confidence, 0.65)
        self.assertEqual(record.oracles, {"container-metadata", "binary-analysis"})
        self.assertEqual(validate.lint_markdown_record(record), [])

    def test_log_oracle_field_keeps_values_and_drops_the_commentary_sentence(self):
        text = (
            "## запись\n"
            "- **ID:** LOG-0002\n"
            "- **Method:** T-02; smoke-test\n"
            "- **Evidence level:** OBSERVED\n"
            "- **Confidence:** 0.9\n"
            "- **Oracle:** `external-doc` (сверка sha256 с release notes) + `filesystem`\n"
            "  (существование путей). Утверждение относится к нашему окружению, а не к\n"
            "  сборке игры, поэтому матрица §10.5 к нему не применяется.\n")
        record = md_records(text).records[0]
        self.assertEqual(record.oracles, {"external-doc", "filesystem"})

    def test_fenced_code_block_is_not_mined_for_records(self):
        text = ("Формат записи:\n\n"
                "```markdown\n"
                "- **Evidence level:** INFERRED\n"
                "- **Confidence:** 0.65\n"
                "- **Oracle:** `global-ucas`\n"
                "```\n")
        extractor = md_records(text)
        self.assertEqual(extractor.records, [])
        self.assertEqual(extractor.unparseable, [])

    def test_ignore_directives_are_counted_not_silent(self):
        text = ("<!-- kb-validate: ignore-next -->\n"
                + table_row("учебный пример", conf="1.00"))
        extractor = md_records(text)
        self.assertEqual(extractor.records, [])
        self.assertEqual(extractor.suppressed, 1)

        exempt = md_records("<!-- kb-validate: ignore-file -->\n"
                            + table_row("весь файл — пример", conf="1.00"))
        self.assertTrue(exempt.file_exempt)
        self.assertEqual(exempt.records, [])


class TestMarkdownUnparseable(unittest.TestCase):
    """An unreadable fact must be visible as a problem, never skipped."""

    def test_two_levels_in_one_annotation_is_unparseable(self):
        text = ("Заголовок контейнера: *(байты OBSERVED 0.99, значения полей "
                "INFERRED 0.85, oracle: container-metadata)*\n")
        extractor = md_records(text)
        self.assertEqual(extractor.records, [])
        self.assertEqual(len(extractor.unparseable), 1)
        self.assertEqual(extractor.unparseable[0].notation, validate.NOTATION_INLINE)

    def test_unparseable_candidate_is_a_violation_not_a_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research = root / "research"
            write(research / "notes.md",
                  "Факт: *(байты OBSERVED 0.99, поля INFERRED 0.85, "
                  "oracle: container-metadata)*\n")
            reports, _ignored = validate.run(root, research, research / "schema")
            report = next(r for r in reports if r.path.endswith("notes.md"))
            self.assertEqual(report.unparseable_count, 1)
            self.assertIn("PARSE-MD", rules_of(report.findings, validate.SEVERITY_ERROR))
            self.assertEqual(validate.exit_code(reports, strict=False), 1)

    def test_two_levels_in_one_log_field_is_unparseable(self):
        text = ("## запись\n"
                "- **ID:** LOG-0005\n"
                "- **Evidence level:** OBSERVED (состав коммита) + INFERRED 0.9 (причина)\n"
                "- **Confidence:** 0.9\n"
                "- **Oracle:** `vcs-history`\n")
        extractor = md_records(text)
        self.assertEqual(extractor.records, [])
        self.assertEqual(len(extractor.unparseable), 1)

    def test_unreadable_level_cell_is_unparseable(self):
        extractor = md_records(table_row("что-то", level="вероятно"))
        self.assertEqual(extractor.records, [])
        self.assertEqual(len(extractor.unparseable), 1)

    def test_unreadable_confidence_cell_is_unparseable(self):
        extractor = md_records(table_row("что-то", conf="высокая"))
        self.assertEqual(extractor.records, [])
        self.assertEqual(len(extractor.unparseable), 1)

    def test_malformed_row_width_is_unparseable(self):
        text = TABLE_HEADER + "| T-09 | утверждение | OBSERVED | 0.99 |\n"
        extractor = md_records(text)
        self.assertEqual(extractor.records, [])
        self.assertEqual(len(extractor.unparseable), 1)

    def test_control_character_in_a_document_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research = root / "research"
            write(research / "log.md", "Путь `D:\\Tools\x0benv-research` (`OBSERVED`).\n")
            reports, _ignored = validate.run(root, research, research / "schema")
            report = next(r for r in reports if r.path.endswith("log.md"))
            self.assertIn("IO", rules_of(report.findings, validate.SEVERITY_ERROR))


class TestMarkdownRules(unittest.TestCase):
    """One test per rule: fires on a crafted bad record, silent on a good one."""

    def test_ev_level_bad_and_good(self):
        good = md_records(table_row("файл X существует")).records[0]
        self.assertNotIn("EV-LEVEL", rules_of(validate.lint_markdown_record(good)))
        text = ("| ID | Утверждение | Conf. | Oracle |\n"
                "|---|---|---|---|\n"
                "| T-10 | без уровня | 0.99 | `filesystem` |\n")
        record = md_records(text).records[0]
        self.assertIn("EV-LEVEL", rules_of(validate.lint_markdown_record(record),
                                           validate.SEVERITY_ERROR))

    def test_ev_conf_rejects_one_hundred_and_accepts_the_ceiling(self):
        bad = md_records(table_row("измерено точно", conf="1.00")).records[0]
        findings = validate.lint_markdown_record(bad)
        self.assertIn("EV-CONF", rules_of(findings, validate.SEVERITY_ERROR))
        self.assertIn("0.99", " ".join(f.message for f in findings))
        good = md_records(table_row("измерено точно", conf="0.99")).records[0]
        self.assertNotIn("EV-CONF", rules_of(validate.lint_markdown_record(good)))

    def test_ev_conf_rejects_out_of_range_and_missing(self):
        for value in ("1.50", "5.0"):
            record = md_records(table_row("x", conf=value)).records[0]
            self.assertIn("EV-CONF", rules_of(validate.lint_markdown_record(record),
                                              validate.SEVERITY_ERROR),
                          f"confidence {value} must be rejected")
        missing = md_records(table_row("x", conf="—")).records[0]
        self.assertIn("EV-CONF", rules_of(validate.lint_markdown_record(missing),
                                          validate.SEVERITY_ERROR))

    def test_ev_04_rejects_unknown_oracle_and_accepts_all_nine(self):
        bad = md_records(table_row("x", oracle="`vibes`")).records[0]
        self.assertIn("EV-04", rules_of(validate.lint_markdown_record(bad),
                                        validate.SEVERITY_ERROR))
        for value in validate.ORACLES:
            record = md_records(table_row("x", conf="0.5",
                                          oracle=f"`{value}`")).records[0]
            self.assertNotIn("EV-04", rules_of(validate.lint_markdown_record(record)),
                             f"{value} is part of the plan.md 10.5 v2.1 vocabulary")

    def test_ev_04_rejects_n_a_and_names_the_replacements(self):
        record = md_records(table_row("факт о нашем окружении",
                                      oracle="n/a")).records[0]
        findings = validate.lint_markdown_record(record)
        self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_ERROR))
        blob = " ".join(f.message for f in findings)
        for replacement in ("filesystem", "steam-metadata", "vcs-history"):
            self.assertIn(replacement, blob)

    def test_ev_04_missing_oracle_is_a_violation(self):
        text = ("| ID | Утверждение | Level | Conf. | Oracle |\n"
                "|---|---|---|---|---|\n"
                "| T-11 | без oracle | OBSERVED | 0.99 | |\n")
        record = md_records(text).records[0]
        self.assertIn("EV-04", rules_of(validate.lint_markdown_record(record),
                                        validate.SEVERITY_ERROR))

    def test_log_entry_without_a_build_field_is_reported(self):
        text = ("## запись\n"
                "- **ID:** LOG-0010\n"
                "- **Method:** обход ФС; повторено\n"
                "- **Evidence level:** OBSERVED\n"
                "- **Confidence:** 0.9\n"
                "- **Oracle:** `filesystem`\n")
        record = md_records(text).records[0]
        self.assertIn("EV-BUILD", rules_of(validate.lint_markdown_record(record),
                                           validate.SEVERITY_WARN))
        with_build = md_records(text + "- **Build:** build_key=UNKNOWN\n").records[0]
        self.assertNotIn("EV-BUILD", rules_of(validate.lint_markdown_record(with_build)))

    def test_ev_04_missing_oracle_in_a_log_entry_is_a_violation(self):
        text = ("## запись\n"
                "- **ID:** LOG-0009\n"
                "- **Method:** обход ФС; повторено\n"
                "- **Evidence level:** OBSERVED\n"
                "- **Confidence:** 0.9\n")
        record = md_records(text).records[0]
        self.assertIn("EV-04", rules_of(validate.lint_markdown_record(record),
                                        validate.SEVERITY_ERROR))

    def test_ev_04_missing_oracle_in_prose_is_only_a_warning(self):
        """Prose may cite a record graded elsewhere; that is not a fresh fact."""
        text = "Природа файла — *(HYPOTHESIS, confidence 0.65)*, см. A-05.\n"
        record = md_records(text).records[0]
        findings = validate.lint_markdown_record(record)
        self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_WARN))
        self.assertEqual(rules_of(findings, validate.SEVERITY_ERROR), set())

    def test_annotation_in_a_question_register_is_only_a_warning(self):
        text = ("| ID | Вопрос | Статус | Oracle (§10.5) | Заметки |\n"
                "|---|---|---|---|---|\n"
                "| A-09 | какие плагины включены | UNKNOWN | `container-metadata` | "
                "(состав активных модулей — HYPOTHESIS, confidence 0.4) |\n")
        extractor = md_records(text)
        self.assertEqual(len(extractor.records), 1)
        self.assertTrue(extractor.records[0].in_register)
        findings = validate.lint_markdown_record(extractor.records[0])
        self.assertEqual(rules_of(findings, validate.SEVERITY_ERROR), set())
        self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_WARN))

    def test_the_word_oracle_in_a_sentence_is_not_an_oracle_field(self):
        text = ("Файл разрешён к чтению (282-МБ exe — read-only oracle, "
                "интерпретация остаётся HYPOTHESIS).\n")
        record = md_records(text).records[0]
        self.assertFalse(record.oracle_present)
        self.assertEqual(record.oracle.unknown, [])
        self.assertNotIn("EV-04", rules_of(validate.lint_markdown_record(record),
                                           validate.SEVERITY_ERROR))
        self.assertIsNone(validate.find_oracle_segment(
            "282-МБ exe — read-only oracle, интерпретация HYPOTHESIS"))
        self.assertEqual(validate.find_oracle_segment("OBSERVED, oracle: filesystem"),
                         "filesystem")
        self.assertEqual(
            validate.find_oracle_segment("OBSERVED, confidence 0.99, oracle `filesystem`"),
            "`filesystem`")

    def test_draft_oracle_spellings_are_normalised_and_reported(self):
        for draft, canonical in (("appmanifest", "steam-metadata"), ("git", "vcs-history")):
            record = md_records(table_row("x", conf="0.5",
                                          oracle=f"`{draft}`")).records[0]
            self.assertEqual(record.oracles, {canonical})
            findings = validate.lint_markdown_record(record)
            self.assertIn("ORA-ALIAS", rules_of(findings, validate.SEVERITY_WARN))
            self.assertEqual(rules_of(findings, validate.SEVERITY_ERROR), set())

    def test_oracle_value_wrapped_in_prose_warns_but_is_understood(self):
        record = md_records(table_row("x", conf="0.5",
                                      oracle="требуется `runtime-reflection`")).records[0]
        self.assertEqual(record.oracles, {"runtime-reflection"})
        self.assertIn("ORA-PROSE", rules_of(validate.lint_markdown_record(record),
                                            validate.SEVERITY_WARN))

    def test_ev_03_is_split_by_claim_class(self):
        """plan.md 10.3 v2.2 / 10.4 EV-03: the method count depends on the CLASS.

        Until v2.2 this test asserted "two methods for any claim at >= 0.80",
        which is the rule the plan withdrew: it was calibrated for interpretive
        claims about the binary and applied to "the install has 53 files" as
        well, putting 20 of 29 violations on facts nobody doubts.  The rule was
        not weakened, it was split - class I got stricter, class P needs one
        method but must actually name it.
        """
        # class P (filesystem only, primitive wording), one method: allowed to 0.99
        one_method = md_records(table_row(
            "файл X существует", conf="0.99",
            method="обход ФС; повторено 2026-08-22")).records[0]
        self.assertNotIn("EV-03", rules_of(validate.lint_markdown_record(one_method)))

        # class I (a semantics-bearing oracle), one method: still a violation
        interpretive = md_records(table_row(
            "функция регистрирует предметы", conf="0.85",
            oracle="`binary-analysis`", method="ghidra headless; повторено")).records[0]
        self.assertIn("EV-03", rules_of(validate.lint_markdown_record(interpretive),
                                        validate.SEVERITY_ERROR))

        # class I with two independent data sources: clean
        thick = md_records(table_row(
            "x", conf="0.9",
            oracle="`binary-analysis` + `runtime-reflection`",
            method="строки в exe; дамп рефлексии; повторено")).records[0]
        self.assertNotIn("EV-03", rules_of(validate.lint_markdown_record(thick)))

        # class P at >= 0.80 with an EMPTY method cell: criterion 1 fails
        no_method = md_records(table_row(
            "файл X существует", conf="0.9", method="")).records[0]
        self.assertIn("EV-03", rules_of(validate.lint_markdown_record(no_method),
                                        validate.SEVERITY_ERROR))

        # below the threshold no method count is required of either class
        low = md_records(table_row("x", conf="0.6", method="один обход ФС")).records[0]
        self.assertNotIn("EV-03", rules_of(validate.lint_markdown_record(low)))

    def test_evidence_artifact_path_is_not_a_second_method(self):
        """plan.md 10.4/EV-03: an Evidence path is where the result was written."""
        text = (
            "## LOG-0001\n\n"
            "- **ID:** LOG-0001\n"
            "- **Build:** UNKNOWN\n"
            "- **Evidence level:** INFERRED\n"
            "- **Confidence:** 0.85\n"
            "- **Oracle:** binary-analysis\n"
            "- **Method:** запуск ghidra headless\n"
            "- **Evidence:** research/evidence/T-02/run1.log\n")
        record = md_records(text).records[0]
        self.assertEqual(record.sources, ["запуск ghidra headless"])
        self.assertEqual(record.evidence_refs, ["research/evidence/T-02/run1.log"])
        findings = validate.lint_markdown_record(record)
        self.assertIn("EV-03", rules_of(findings, validate.SEVERITY_ERROR))
        message = " ".join(f.message for f in findings if f.rule == "EV-03")
        self.assertIn("NOT a second method", message)

    def test_claim_class_is_derived_and_an_explicit_contradiction_is_ev_05(self):
        """plan.md 10.4/EV-05: the derivation governs, the label does not."""
        header = ("| ID | Утверждение | Level | Confidence | Oracle | Класс | Метод |\n"
                  "|---|---|---|---|---|---|---|\n")
        mislabelled = md_records(
            header + "| X-1 | файл A существует | OBSERVED | 0.99 | `filesystem` | I | "
                     "dir; повторено |\n").records[0]
        findings = validate.lint_markdown_record(mislabelled)
        self.assertIn("EV-05", rules_of(findings, validate.SEVERITY_ERROR))
        agreeing = md_records(
            header + "| X-2 | файл A существует | OBSERVED | 0.99 | `filesystem` | P | "
                     "dir; повторено |\n").records[0]
        self.assertNotIn("EV-05", rules_of(validate.lint_markdown_record(agreeing)))

    def test_mixed_primitive_and_interpretive_claim_must_be_split(self):
        """plan.md 10.3 v2.2: "Смешанные утверждения обязаны разделяться"."""
        record = md_records(table_row(
            "файл MISERY.exe существует и имеет размер 282826240 байт, следовательно "
            "в депот попала Development-сборка",
            conf="0.95", method="PE-заголовки; повторено")).records[0]
        findings = validate.lint_markdown_record(record)
        self.assertIn("MIX-SPLIT", rules_of(findings, validate.SEVERITY_ERROR))
        primitive_only = md_records(table_row(
            "файл MISERY.exe существует и имеет размер 282826240 байт",
            conf="0.95", method="PE-заголовки; повторено")).records[0]
        self.assertNotIn("MIX-SPLIT",
                         rules_of(validate.lint_markdown_record(primitive_only)))

    def test_invented_evidence_level_is_reported_not_dropped(self):
        """plan.md 10.1 closes the level list; an invented level is a violation."""
        extractor = md_records(
            "Файл найден *(VERIFIED, confidence 0.9, oracle: filesystem)*.\n")
        self.assertEqual(len(extractor.records), 0)
        self.assertEqual(len(extractor.unparseable), 1)
        self.assertIn("VERIFIED", extractor.unparseable[0].reason)

    def test_negative_confidence_is_rejected_not_made_positive(self):
        for record in (
            md_records(table_row("x", conf="-0.5")).records[0],
            md_records("Файл найден "
                       "*(OBSERVED, confidence -0.5, oracle: filesystem)*.\n").records[0],
            md_records("Файл найден *(OBSERVED -0.5, oracle: filesystem)*.\n").records[0],
        ):
            self.assertEqual(record.confidence, -0.5)
            findings = validate.lint_markdown_record(record)
            self.assertIn("EV-CONF", rules_of(findings, validate.SEVERITY_ERROR))

    def test_a_hyphen_used_as_a_dash_is_not_read_as_a_minus(self):
        """The other direction of the same ambiguity: no value corruption."""
        for text, expected in (
            ("Файл найден *(OBSERVED-0.99, oracle: filesystem)*.\n", 0.99),
            ("Файл найден *(OBSERVED - 0.9, oracle: filesystem)*.\n", 0.9),
        ):
            record = md_records(text).records[0]
            self.assertEqual(record.confidence, expected, text)

    def test_graded_table_without_an_oracle_column_reports_every_row(self):
        """plan.md Appendix A shape: ID | Наблюдение | Метод | Level | Conf."""
        text = ("| ID | Наблюдение | Метод | Level | Conf. |\n"
                "|---|---|---|---|---|\n"
                "| A-01 | в установке 53 файла | `ls` | OBSERVED | 0.99 |\n"
                "| A-02 | размер 5057001973 B | `.acf` | OBSERVED | 0.99 |\n")
        extractor, findings = md_findings(text)
        self.assertEqual(len(extractor.records), 2)
        oracle_errors = [f for f in findings
                         if f.rule == "EV-04" and f.severity == validate.SEVERITY_ERROR]
        self.assertEqual(len(oracle_errors), 2)

    def test_level_vocabulary_table_is_a_named_printed_exemption(self):
        """DEF-TABLE: plan.md 10.1 defines the levels, it does not grade claims."""
        text = ("| Уровень | Определение | Примеры |\n"
                "|---|---|---|\n"
                "| `OBSERVED` | Прямо измерено | размер файла |\n"
                "| `INFERRED` | Логически выведено | layout |\n"
                "| `HYPOTHESIS` | Предположение | адрес |\n"
                "| `UNKNOWN` | Неизвестно | анти-чит |\n")
        extractor = md_records(text)
        self.assertEqual(len(extractor.records), 0)
        self.assertEqual(len(extractor.definition_tables), 1)
        # a table that names a method is a fact table, never a definition table
        graded = md_records(
            "| Уровень | Определение | Метод |\n"
            "|---|---|---|\n"
            "| OBSERVED | файл существует | dir |\n")
        self.assertEqual(len(graded.records), 1)
        self.assertEqual(graded.definition_tables, [])

    def test_c_12_caps_external_doc_only_confidence(self):
        bad = md_records(table_row("вывод о ЭТОЙ сборке", conf="0.9",
                                   oracle="`external-doc`",
                                   method="release notes; Adoptium API")).records[0]
        self.assertIn("C-12", rules_of(validate.lint_markdown_record(bad),
                                       validate.SEVERITY_ERROR))
        good = md_records(table_row("как устроено в vanilla UE", conf="0.7",
                                    oracle="`external-doc`",
                                    method="UE 5.4 sources; docs")).records[0]
        self.assertNotIn("C-12", rules_of(validate.lint_markdown_record(good)))

    def test_c_11_layout_claim_on_global_ucas_only(self):
        bad = md_records(table_row("у класса X есть свойство Y по офсету 0x40",
                                   conf="0.3", oracle="`global-ucas`",
                                   method="парсер пула имён")).records[0]
        self.assertIn("C-11", rules_of(validate.lint_markdown_record(bad),
                                       validate.SEVERITY_ERROR))
        good = md_records(table_row("в пуле имён есть строка MiseryFocusSubsystem",
                                    conf="0.9", oracle="`global-ucas`",
                                    method="парсер пула; повторный дамп")).records[0]
        self.assertNotIn("C-11", rules_of(validate.lint_markdown_record(good)))

    def test_c_11_caps_a_game_name_known_only_from_global_ucas(self):
        bad = md_records(table_row("существует asset /Game/Items/BP_Knife",
                                   level="OBSERVED", conf="0.9",
                                   oracle="`global-ucas`",
                                   method="пул имён; повторный дамп")).records[0]
        findings = validate.lint_markdown_record(bad)
        self.assertIn("C-11", rules_of(findings, validate.SEVERITY_ERROR))
        # the plan's own "Обязательное правило" permits HYPOTHESIS <= 0.4
        allowed = md_records(table_row("существует asset /Game/Items/BP_Knife",
                                       level="HYPOTHESIS", conf="0.4",
                                       oracle="`global-ucas`",
                                       method="пул имён")).records[0]
        self.assertNotIn("C-11", rules_of(validate.lint_markdown_record(allowed)))


class TestCommitReachabilityRule(unittest.TestCase):
    """plan.md 10.5 v2.1: a vcs-history claim must cite a reachable commit."""

    UNREACHABLE = "9407f22"
    REACHABLE = "a2a6385"

    def _record(self, claim: str, oracle: str = "`vcs-history`"):
        return md_records(table_row(claim, oracle=oracle,
                                    method="`git log`; повторено")).records[0]

    def test_unreachable_commit_is_flagged(self):
        fake = FakeReachability({
            self.UNREACHABLE: validate.CommitReachability.STATUS_UNREACHABLE})
        record = self._record(f"первый коммит `{self.UNREACHABLE}` содержит два файла")
        findings = validate.lint_markdown_record(record, reachability=fake)
        self.assertIn("VCS-REACH", rules_of(findings, validate.SEVERITY_ERROR))

    def test_missing_object_is_flagged_with_its_own_message(self):
        fake = FakeReachability({
            "deadbee": validate.CommitReachability.STATUS_MISSING})
        record = self._record("коммит `deadbee` содержит правку")
        findings = [f for f in validate.lint_markdown_record(record, reachability=fake)
                    if f.rule == "VCS-REACH"]
        self.assertEqual([f.severity for f in findings], [validate.SEVERITY_ERROR])
        self.assertIn("not an object", findings[0].message)

    def test_reachable_commit_is_clean(self):
        fake = FakeReachability({})
        record = self._record(f"корневой коммит `{self.REACHABLE}` содержит два файла")
        self.assertEqual(validate.lint_markdown_record(record, reachability=fake), [])

    def test_acknowledged_rewrite_is_a_warning_not_a_violation(self):
        fake = FakeReachability({
            self.UNREACHABLE: validate.CommitReachability.STATUS_UNREACHABLE})
        record = self._record(f"прежний коммит `{self.UNREACHABLE}` **не достижим из "
                             "HEAD** после amend")
        findings = validate.lint_markdown_record(record, reachability=fake)
        self.assertIn("VCS-REACH", rules_of(findings, validate.SEVERITY_WARN))
        self.assertEqual(rules_of(findings, validate.SEVERITY_ERROR), set())

    def test_commit_claim_graded_on_the_wrong_oracle(self):
        fake = FakeReachability({})
        record = self._record(f"первый коммит `{self.REACHABLE}` содержит два файла",
                             oracle="`filesystem`")
        findings = validate.lint_markdown_record(record, reachability=fake)
        self.assertIn("VCS-ORACLE", rules_of(findings, validate.SEVERITY_ERROR))

    def test_tree_hash_citation_is_not_treated_as_a_commit(self):
        fake = FakeReachability({
            "5ee21c6": validate.CommitReachability.STATUS_NOT_A_COMMIT})
        record = self._record("дерево коммита — объект `5ee21c6`, он не меняется при amend")
        self.assertEqual(validate.lint_markdown_record(record, reachability=fake), [])

    def test_hash_shaped_tokens_that_are_not_commits_are_ignored(self):
        for text in ("установка содержит 53 файла, buildid 24826585",
                     "ContainerId = 0x3002A7A795855966",
                     "build-id misery-24826585-ue5.4.4-0eef3715244b"):
            self.assertEqual(validate.commit_hashes_in(text), [], text)

    def test_a_commit_keyword_is_required_before_a_hash_is_checked(self):
        self.assertEqual(validate.commit_hashes_in("sha256:" + "ab" * 32), [])
        self.assertEqual(validate.commit_hashes_in("коммит 9407f22"), ["9407f22"])

    def test_abbreviated_and_full_hash_are_reported_once(self):
        self.assertEqual(
            validate.commit_hashes_in("коммит `9407f22` = `9407f2217e8b2dc5c3fe8681"
                                      "759be904a1000501`"),
            ["9407f2217e8b2dc5c3fe8681759be904a1000501"])

    def test_real_repository_head_is_reachable(self):
        """Read-only sanity check: HEAD must be its own ancestor."""
        checker = validate.CommitReachability(REPO_ROOT)
        if not checker.available():
            self.skipTest("git or the repository is unavailable")
        self.assertEqual(checker.status("HEAD"),
                         validate.CommitReachability.STATUS_REACHABLE)

    def test_json_record_of_a_commit_claim_is_checked_too(self):
        fake = FakeReachability({
            self.UNREACHABLE: validate.CommitReachability.STATUS_UNREACHABLE})
        record = {
            "claim_type": "commit-content",
            "oracle": ["vcs-history"],
            "evidence_level": "OBSERVED",
            "confidence": 0.99,
            # plan.md 10.3 class P criterion 2: the method must be re-run and
            # the result reproduced, and the record has to say so.
            "sources": ["git log (re-run, reproduced)", "git ls-tree"],
            "commit": self.UNREACHABLE,
            "notes": "a claim about our own history, not about the game build",
        }
        findings = validate.lint_record("$", record, reachability=fake)
        self.assertIn("VCS-REACH", rules_of(findings, validate.SEVERITY_ERROR))
        clean = dict(record, commit=self.REACHABLE)
        self.assertEqual(validate.lint_record("$", clean, reachability=fake), [])
        unnamed = {k: v for k, v in record.items() if k != "commit"}
        self.assertIn("VCS-ORACLE", rules_of(validate.lint_record("$", unnamed,
                                                                 reachability=fake),
                                             validate.SEVERITY_ERROR))


class TestOracleVocabulary(unittest.TestCase):
    """plan.md 10.5 v2.1 closed the gap that the old workaround papered over."""

    def test_vocabulary_is_the_nine_plan_values(self):
        self.assertEqual(set(validate.ORACLES), {
            "filesystem", "steam-metadata", "vcs-history", "global-ucas",
            "asset-registry", "runtime-reflection", "binary-analysis",
            "container-metadata", "external-doc"})

    def test_every_oracle_documents_its_boundary(self):
        self.assertEqual(set(validate.ORACLE_BOUNDARIES), set(validate.ORACLES))

    def test_schema_and_validator_share_one_vocabulary(self):
        schema_path = REPO_ROOT / "research" / "schema" / "kb-record.schema.json"
        if not schema_path.is_file():
            self.skipTest("kb-record.schema.json not present yet")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        oracle = schema.get("$defs", {}).get("oracle", {})
        branches = oracle.get("anyOf") or []
        declared = {branch.get("const") for branch in branches if "const" in branch}
        if not declared:
            declared = set(oracle.get("enum") or [])
        self.assertEqual(declared, set(validate.ORACLES))
        for branch in branches:
            self.assertTrue(branch.get("description"),
                            f"oracle {branch.get('const')!r} carries no description")

    # The predecessor of the test below, test_schema_forbids_confidence_one,
    # asserted `confidence["exclusiveMaximum"] == 1` against the on-disk
    # schema.  That pinned an IMPLEMENTATION DETAIL - the name of a keyword -
    # and it pinned the wrong rule: exclusiveMaximum: 1 is the 1.00 ban alone,
    # so the schema it froze accepted 0.995 and 0.999 as legal while its own
    # prose promised a ceiling of 0.99.  The test passed, and it was the reason
    # the contract could not be fixed without a red test.  What follows asserts
    # the BEHAVIOUR instead - which values the published contract accepts - so
    # it cannot be satisfied by any keyword that fails to enforce the ceiling,
    # and cannot break when the formulation legitimately changes.
    def test_published_schemas_enforce_the_confidence_ceiling(self):
        """plan.md 10.2 v2.3: 0.00 <= confidence <= 0.99, checked by comparison.

        Every published schema that declares a confidence bound is exercised,
        not only kb-record.schema.json, because build-index, install and
        install-inventory BUNDLE a copy of the envelope and a third party
        consumes those copies directly.
        """
        Validator = _draft202012_or_skip(self)
        bounded = list(_confidence_bounds_in_schema_dir())
        self.assertTrue(bounded, "no schema declares a confidence bound at all")
        seen = set()
        for path, pointer, subschema in bounded:
            seen.add(path.name)
            with self.subTest(schema=path.name, pointer=pointer):
                # No registry and no $ref resolution: the bound is a leaf
                # subschema, which is exactly how a third-party consumer of
                # the published contract would evaluate it.
                validator = Validator(subschema)
                for legal in (0.0, 0.3, 0.79, 0.85, 0.95, 0.99):
                    self.assertTrue(
                        validator.is_valid(legal),
                        f"{legal} is inside 0.00..0.99 and must validate")
                for illegal in (0.995, 0.999, 1.0, 1.5, -0.01):
                    self.assertFalse(
                        validator.is_valid(illegal),
                        f"{illegal} is outside 0.00..0.99 and must NOT validate")
        self.assertEqual(seen, {"kb-record.schema.json", "build-index.schema.json",
                                "install.schema.json",
                                "install-inventory.schema.json"})

    def test_no_schema_text_promises_a_bound_the_schema_does_not_hold(self):
        """The defect was a message that convinces a reader a check happened."""
        for path in sorted((REPO_ROOT / "research" / "schema").glob("*.schema.json")):
            text = path.read_text(encoding="utf-8")
            for stale in ("Hence exclusiveMaximum: 1",
                          "rejects anything >= 1.00",
                          "Mandatory. 1.00 is forbidden."):
                self.assertNotIn(stale, text,
                                 f"{path.name} still carries pre-v2.3 wording {stale!r}")

    def test_bundling_schemas_still_validate_their_real_artifacts(self):
        """The ceiling change must not break the artifacts already on disk."""
        Validator = _draft202012_or_skip(self)
        pairs = (("build-index.schema.json", "builds/index.json"),
                 ("install.schema.json",
                  "builds/misery-24826585-ue5.4.4-0eef3715244b/install.json"),
                 ("install-inventory.schema.json",
                  "builds/misery-24826585-ue5.4.4-0eef3715244b/install-inventory.json"))
        for schema_name, artifact_rel in pairs:
            schema_path = REPO_ROOT / "research" / "schema" / schema_name
            artifact_path = REPO_ROOT / "research" / artifact_rel
            if not schema_path.is_file() or not artifact_path.is_file():
                self.skipTest(f"{schema_name} or {artifact_rel} not present yet")
            with self.subTest(schema=schema_name):
                schema = json.loads(schema_path.read_text(encoding="utf-8"))
                # Self-contained by construction: these schemas bundle the
                # envelope instead of $ref-ing kb-record.schema.json across
                # files, so a plain validator with no registry must suffice.
                Validator.check_schema(schema)
                instance = json.loads(artifact_path.read_text(encoding="utf-8"))
                errors = sorted(Validator(schema).iter_errors(instance),
                               key=lambda error: list(error.absolute_path))
                self.assertEqual(
                    [], [f"{list(e.absolute_path)}: {e.message}" for e in errors])

    def test_filesystem_claims_are_no_longer_routed_onto_other_oracles(self):
        """The removed workaround mislabelled a directory walk as native analysis."""
        for name in ("file-exists", "install-file-count"):
            requirement = validate.CLAIM_TYPE_ORACLE_MATRIX[name]
            self.assertEqual(requirement.all_of, frozenset({"filesystem"}))
            self.assertNotIn("binary-analysis", requirement.any_of | requirement.all_of)
            self.assertNotIn("container-metadata", requirement.any_of | requirement.all_of)
        for name, requirement in validate.CLAIM_TYPE_ORACLE_MATRIX.items():
            self.assertNotIn("plan gap: 10.5 names no filesystem oracle",
                             requirement.provenance,
                             f"{name} still cites the closed plan gap")

    def test_new_matrix_rows_match_plan_10_5_v2_1(self):
        matrix = validate.CLAIM_TYPE_ORACLE_MATRIX
        self.assertEqual(matrix["steam-metadata-fact"].all_of,
                         frozenset({"steam-metadata"}))
        self.assertEqual(matrix["disk-matches-steam-metadata"].all_of,
                         frozenset({"filesystem", "steam-metadata"}))
        self.assertEqual(matrix["commit-content"].all_of, frozenset({"vcs-history"}))
        self.assertTrue(matrix["commit-content"].requires_reachable_commit)

    def test_disk_matches_steam_needs_both_oracles(self):
        record = good_record(claim_type="disk-matches-steam-metadata",
                             oracle=["filesystem"],
                             sources=["обход ФС", "поле в .acf"])
        self.assertIn("EV-04", rules_of(validate.lint_record("$", record),
                                        validate.SEVERITY_ERROR))
        both = dict(record, oracle=["filesystem", "steam-metadata"])
        self.assertEqual(validate.lint_record("$", both), [])


class TestMarkdownDiscoveryAndReporting(unittest.TestCase):
    def test_markdown_under_research_and_docs_is_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research, docs = root / "research", root / "docs"
            write(research / "repo-audit.md", table_row("файл X существует"))
            write(docs / "toolchain.md",
                  "Ghidra 12.1.3 *(OBSERVED, confidence 0.9, oracle: filesystem)*\n")
            write(research / "builds" / "index.json", json.dumps({"builds": []}))
            reports, _ignored = validate.run(root, research, research / "schema")
            paths = {r.path for r in reports}
            self.assertIn("research/repo-audit.md", paths)
            self.assertIn("docs/toolchain.md", paths)
            self.assertEqual(sum(r.record_count for r in reports), 2)

    def test_repository_root_documents_are_in_the_scanned_set(self):
        """BLOCKER (second review): plan.md was never opened in a default run.

        discover_files() covered research/ and docs/ only, so plan.md,
        AGENTS.md, README.md and NOTICE.md were invisible - and all four
        violations the first review found by hand were in plan.md.  The scanned
        set is also printed in the report header, so a reader can see coverage
        without reading this test.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research = root / "research"
            write(research / "repo-audit.md", table_row("файл X существует"))
            for name in validate.ROOT_DOCUMENTS_EXPECTED:
                write(root / name, f"# {name}\n\nтекст без градуированных фактов\n")
            reports, _ignored = validate.run(root, research, research / "schema")
            paths = {r.path for r in reports}
            for name in validate.ROOT_DOCUMENTS_EXPECTED:
                self.assertIn(name, paths, f"{name} must be scanned by default")
            coverage = validate.scan_coverage(reports)
            self.assertEqual(coverage["root_documents_missing"], [])
            self.assertEqual(sorted(coverage["root_documents_scanned"]),
                             sorted(validate.ROOT_DOCUMENTS_EXPECTED))
            self.assertIn("(repository root)", coverage["areas"])
            # and the header actually prints it
            with quiet() as (out, _err):
                validate.print_report(reports, set(), strict=False)
            printed = out.getvalue()
            self.assertIn("scanned set", printed)
            self.assertIn("plan.md", printed)

    def test_graded_row_in_a_root_document_is_reported(self):
        """A violation planted in a root-level document must be found."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research = root / "research"
            write(research / "keep.md", "# keep\n")
            # confidence 1.00 is forbidden outright (plan.md 10.2, which states
            # that the ban covers the tables inside plan.md itself)
            write(root / "plan.md",
                  "# plan\n\n## Приложение A\n\n" + table_row("файл X существует",
                                                              conf="1.00"))
            reports, _ignored = validate.run(root, research, research / "schema")
            plan = next(r for r in reports if r.path == "plan.md")
            self.assertEqual(plan.record_count, 1)
            self.assertIn("EV-CONF", rules_of(plan.findings, validate.SEVERITY_ERROR))
            self.assertEqual(validate.exit_code(reports, strict=False), 1)

    def test_no_markdown_flag_reproduces_the_old_blind_spot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research = root / "research"
            write(research / "repo-audit.md", table_row("x", conf="1.00"))
            reports, _ignored = validate.run(root, research, research / "schema",
                                             markdown=False)
            self.assertEqual(sum(r.record_count for r in reports), 0)
            reports, _ignored = validate.run(root, research, research / "schema")
            self.assertEqual(sum(r.record_count for r in reports), 1)
            self.assertEqual(validate.exit_code(reports, strict=False), 1)

    def test_json_output_carries_the_markdown_counters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            research = root / "research"
            write(research / "notes.md",
                  table_row("x", conf="1.00")
                  + "\nЕщё: *(байты OBSERVED 0.99, поля INFERRED 0.85, "
                    "oracle: container-metadata)*\n")
            reports, _ignored = validate.run(root, research, research / "schema")
            payload = validate.build_json_output(reports, set(), False)
            summary = payload["summary"]
            self.assertEqual(summary["unparseable_records"], 1)
            self.assertEqual(summary["records_by_notation"][validate.NOTATION_TABLE], 1)
            self.assertIn("EV-CONF", summary["by_rule"])
            self.assertEqual(summary["exit_code"], 1)

    def test_degraded_schema_backend_is_reported_loudly(self):
        report = validate.degraded_backend_report({"unevaluatedProperties"},
                                                  as_error=False)
        self.assertIn("BACKEND", rules_of(report.findings, validate.SEVERITY_WARN))
        self.assertEqual(validate.exit_code([report], strict=True), 1)
        as_error = validate.degraded_backend_report(set(), as_error=True)
        self.assertEqual(validate.exit_code([as_error], strict=False), 1)
        self.assertIn("not on the", " ".join(f.message for f in as_error.findings)
                      .replace("NOT on the", "not on the"))

    def test_the_real_repository_is_scanned_and_yields_markdown_records(self):
        """Regression guard for BLOCKER-2: 'files: 9, records: 0' must not return."""
        research = REPO_ROOT / "research"
        if not research.is_dir():
            self.skipTest("research/ does not exist yet")
        reports, _ignored = validate.run(REPO_ROOT, research,
                                         research / "schema")
        markdown = [r for r in reports if r.kind == validate.KIND_MARKDOWN]
        self.assertGreaterEqual(len(markdown), 5,
                                "markdown documents must be discovered")
        self.assertGreater(sum(r.record_count for r in markdown), 50,
                           "the M0 facts live in markdown; the validator must read them")
        # BLOCKER guard: the real plan.md must be in the run and must yield
        # records, because Appendix A is a table of graded observations.
        paths = {r.path for r in reports}
        self.assertIn("plan.md", paths)
        plan = next(r for r in reports if r.path == "plan.md")
        self.assertGreater(plan.record_count, 0,
                           "plan.md Appendix A grades ~15 observations; a run that "
                           "reads none of them is not reading plan.md")


# ---------------------------------------------------------------------------
# validator 3.2.0: the defects the third adversarial review located
# ---------------------------------------------------------------------------

class TestEvidenceLevelDecidesClass(unittest.TestCase):
    """BLOCKER: derive_claim_class ignored evidence_level and inverted itself.

    plan.md 10.3 v2.3: "Класс P допустим только при evidence_level = OBSERVED.
    INFERRED и HYPOTHESIS ... всегда класс I, независимо от того, какие у неё
    oracle и как сформулирован текст."  Before the fix a claim its author had
    honestly graded INFERRED derived as class P whenever its oracles were
    primitive and its wording did not match SEMANTIC_CONCLUSION_RE - so an
    author who labelled it class I got an EV-05 ERROR telling them to change
    the oracle, the claim_type or the wording rather than the label.  The gate
    punished the correct label and rewarded the incorrect one, and it did so
    quietly: the only other output was a mild class-P warning.
    """

    def test_inferred_with_primitive_oracle_is_class_i(self):
        verdict = validate.derive_claim_class(
            {"filesystem"}, None,
            "Отладочных символов у сборки нет в виде отдельных файлов",
            "INFERRED")
        self.assertEqual(validate.CLASS_I, verdict.claim_class)
        self.assertTrue(verdict.level_decided)
        self.assertIn("INFERRED", verdict.reason)

    def test_hypothesis_with_primitive_oracle_is_class_i(self):
        verdict = validate.derive_claim_class(
            {"vcs-history"}, None, "файл существует", "HYPOTHESIS")
        self.assertEqual(validate.CLASS_I, verdict.claim_class)

    def test_observed_with_primitive_oracle_is_still_class_p(self):
        verdict = validate.derive_claim_class(
            {"filesystem"}, None, "файл размером 134 658 048 байт", "OBSERVED")
        self.assertEqual(validate.CLASS_P, verdict.claim_class)

    def test_unknown_claims_nothing_so_no_class_is_derived(self):
        verdict = validate.derive_claim_class(
            {"filesystem"}, None, "файл существует", "UNKNOWN")
        self.assertEqual(validate.CLASS_UNDETERMINED, verdict.claim_class)

    def test_level_beats_the_claim_type_and_the_oracle(self):
        """The level decides FIRST, even for a primitive-measurement row."""
        verdict = validate.derive_claim_class(
            {"filesystem"}, "file-exists", "файл существует", "INFERRED")
        self.assertEqual(validate.CLASS_I, verdict.claim_class)

    def test_wording_heuristic_cannot_turn_an_inferred_record_into_p(self):
        """The heuristic supplements the rule; it never replaces it.

        Text with no conclusion marker at all: before the fix this was the
        exact path by which an INFERRED record derived class P.
        """
        verdict = validate.derive_claim_class(
            {"filesystem"}, None, "в установке 53 файла", "INFERRED")
        self.assertEqual(validate.CLASS_I, verdict.claim_class)

    def test_class_i_label_on_an_inferred_record_is_no_longer_an_error(self):
        """The regression in one assertion: the honest label must not be punished."""
        findings = validate.lint_record("$", good_record(
            claim_type="file-exists", oracle=["filesystem"],
            evidence_level="INFERRED", confidence=0.85, claim_class="I",
            sources=["обход ФС", "сверка с манифестом"],
            statement="Отладочных символов нет в виде отдельных файлов"))
        self.assertNotIn("EV-05", rules_of(findings, validate.SEVERITY_ERROR))

    def test_class_p_label_on_an_inferred_record_is_an_error(self):
        findings = validate.lint_record("$", good_record(
            claim_type="file-exists", oracle=["filesystem"],
            evidence_level="INFERRED", confidence=0.85, claim_class="P",
            sources=["обход ФС", "сверка с манифестом"],
            statement="Отладочных символов нет в виде отдельных файлов"))
        self.assertIn("EV-05", rules_of(findings, validate.SEVERITY_ERROR))

    def test_the_three_live_shapes_now_raise_findings(self):
        """RA-38 / RA-39 / RA-40: INFERRED, primitive oracle only, one method."""
        row = TABLE_HEADER + (
            "| RA-39 | Отладочных символов у сборки нет в виде отдельных файлов "
            "| INFERRED | 0.85 | `filesystem` | рекурсивный обход ФС |\n")
        record = md_records(row).records[0]
        rules = rules_of(validate.lint_markdown_record(record),
                         validate.SEVERITY_ERROR)
        self.assertIn("EV-03", rules)
        self.assertIn("CLASS-I", rules)


class TestClassIOracleRow(unittest.TestCase):
    """plan.md 10.3 class I row: any oracle, but TOGETHER with a semantic one."""

    def _findings(self, oracle: str, conf: str, level: str = "INFERRED"):
        record = md_records(table_row(
            "вывод о сборке", level=level, conf=conf, oracle=oracle,
            method="обход ФС")).records[0]
        return validate.lint_markdown_record(record)

    def test_primitive_only_is_rejected_from_080_up(self):
        self.assertIn("CLASS-I", rules_of(self._findings("`filesystem`", "0.85"),
                                          validate.SEVERITY_ERROR))

    def test_a_semantic_oracle_satisfies_the_row(self):
        self.assertNotIn("CLASS-I", rules_of(
            self._findings("`filesystem` + `binary-analysis`", "0.85"),
            validate.SEVERITY_ERROR))

    def test_below_the_threshold_a_weak_interpretive_claim_is_allowed(self):
        """RA-02i is the honest example: INFERRED 0.70, one filesystem method."""
        self.assertNotIn("CLASS-I", rules_of(self._findings("`filesystem`", "0.70"),
                                             validate.SEVERITY_ERROR))

    def test_a_prescribed_primitive_only_matrix_row_stays_satisfiable(self):
        """plan.md 10.5 row 4 needs filesystem AND steam-metadata and nothing else.

        Applying the semantic-oracle rule there would make a row the plan
        prescribes impossible to satisfy.
        """
        findings = validate.lint_record("$", good_record(
            claim_type="disk-matches-steam-metadata",
            oracle=["filesystem", "steam-metadata"],
            evidence_level="INFERRED", confidence=0.85,
            sources=["обход ФС", "поле SizeOnDisk в .acf"]))
        self.assertEqual([], findings)

    def test_a_mixed_record_is_told_to_split_and_nothing_else(self):
        """MIX-SPLIT and "name a second method" would be contradictory advice."""
        record = md_records(table_row(
            "файл размером 134 658 048 байт, следовательно это Shipping-сборка",
            conf="0.99", oracle="`filesystem`", method="обход ФС")).records[0]
        rules = rules_of(validate.lint_markdown_record(record),
                         validate.SEVERITY_ERROR)
        self.assertIn("MIX-SPLIT", rules)
        self.assertNotIn("EV-03", rules)
        self.assertNotIn("CLASS-I", rules)


class TestConfidenceCeilingIsAComparison(unittest.TestCase):
    """MAJOR: the 0.99 ceiling was stated in three artifacts and enforced in none.

    plan.md 10.2 v2.3: the checkable condition is 0.00 <= confidence <= 0.99.
    CONFIDENCE_CEILING used to appear only inside a message string while both
    EV-CONF paths compared against MAX_CONFIDENCE_EXCLUSIVE = 1.0, so 0.995 and
    0.999 passed with no finding while the message asserted the cap was 0.99.
    """

    FORBIDDEN = (0.991, 0.995, 0.999, 1.0)
    ALLOWED = (0.0, 0.4, 0.95, 0.99)

    def test_json_layer_rejects_the_open_interval_and_one(self):
        for value in self.FORBIDDEN:
            findings = validate.lint_record("$", good_record(confidence=value))
            self.assertIn("EV-CONF", rules_of(findings, validate.SEVERITY_ERROR),
                          msg=f"confidence {value} must be rejected")

    def test_json_layer_accepts_up_to_the_ceiling(self):
        for value in self.ALLOWED:
            findings = validate.lint_record("$", good_record(confidence=value))
            self.assertNotIn("EV-CONF", rules_of(findings),
                             msg=f"confidence {value} must be accepted")

    def test_markdown_layer_rejects_the_open_interval_and_one(self):
        for value in self.FORBIDDEN:
            record = md_records(table_row("файл существует",
                                          conf=f"{value}")).records[0]
            self.assertIn("EV-CONF", rules_of(validate.lint_markdown_record(record),
                                              validate.SEVERITY_ERROR),
                          msg=f"confidence {value} must be rejected")

    def test_markdown_layer_accepts_the_ceiling_itself(self):
        record = md_records(table_row("файл существует", conf="0.99")).records[0]
        self.assertNotIn("EV-CONF", rules_of(validate.lint_markdown_record(record)))

    def test_the_ceiling_constant_is_used_as_a_comparison_operand(self):
        """The defect in one assertion: the named ceiling must decide the answer."""
        self.assertTrue(validate.exceeds_ceiling(validate.CONFIDENCE_CEILING + 0.005))
        self.assertFalse(validate.exceeds_ceiling(validate.CONFIDENCE_CEILING))

    def test_the_message_distinguishes_one_from_the_open_interval(self):
        self.assertIn("1.00", validate.ceiling_message(1.0))
        self.assertIn("open interval", validate.ceiling_message(0.995))

    def test_a_schema_bound_that_disagrees_with_the_ceiling_is_reported(self):
        """The rule was stated in three artifacts and compared against in none.

        A schema whose prose says the ceiling is 0.99 while its keyword says
        exclusiveMaximum: 1 accepts 0.995 - and the prose then convinces the
        reader that a check happened.
        """
        loose = {"properties": {"confidence": {"type": "number",
                                               "exclusiveMaximum": 1}}}
        findings = validate.check_schema_confidence_bound(loose)
        self.assertEqual(1, len(findings))
        self.assertEqual("SCHEMA", findings[0].rule)
        self.assertIn("0.995", findings[0].message)

        tight = {"properties": {"confidence": {"type": "number",
                                               "minimum": 0, "maximum": 0.99}}}
        self.assertEqual([], validate.check_schema_confidence_bound(tight))


class TestEv03CountsActsOfMeasurement(unittest.TestCase):
    """MINOR: EV-03 credited every extra oracle, and every prose clause, as a method.

    An oracle is a KIND of source, not an act of measurement.  The repository
    already contains a record saying so about itself: RESEARCH_LOG.md LOG-0001i
    states that it used one method and not two, and explains that its second
    oracle - the published FIoStoreTocHeader layout, external-doc - is
    participating rather than corroborating, because without it the bytes
    cannot be interpreted at all.  The validator credited it with two methods
    from the oracle count and a third from a clause boundary, and passed it at
    0.85.
    """

    def test_a_second_oracle_is_not_a_second_method(self):
        record = md_records(table_row(
            "что означают байты заголовка", level="INFERRED", conf="0.85",
            oracle="`container-metadata` + `external-doc`",
            method="ручное истолкование байтов по публичному layout")).records[0]
        self.assertIn("EV-03", rules_of(validate.lint_markdown_record(record),
                                        validate.SEVERITY_ERROR))

    def test_the_conjunction_i_is_not_a_method_separator(self):
        """`_split_sources` used to split on the Russian "и"."""
        self.assertEqual(1, len(validate._split_sources(
            "чтение заголовка utoc и чтение footer pak")))

    def test_a_clause_of_reasoning_is_not_a_method(self):
        self.assertFalse(validate.is_method_entry(
            "ни один из двух в одиночку это утверждение не покрывает"))
        self.assertFalse(validate.is_method_entry("перепроверено 2026-08-22"))

    def test_a_named_operation_is_a_method(self):
        for entry in ("рекурсивный обход ФС",
                      "`(Get-ChildItem -Recurse -File).Sum`",
                      "чтение полей appmanifest_2119830.acf",
                      "запуск analyzeHeadless на тестовом импорте",
                      "строки в exe"):
            self.assertTrue(validate.is_method_entry(entry), msg=entry)

    def test_json_sources_are_an_explicit_enumeration_and_stay_counted(self):
        """A JSON sources[] array is written by the author, entry by entry."""
        self.assertEqual([], validate.lint_record("$", good_record(
            confidence=0.9, sources=["RF-01", "RF-12"])))

    def test_two_prose_methods_still_pass(self):
        record = md_records(table_row(
            "x", level="INFERRED", conf="0.9",
            oracle="`binary-analysis` + `runtime-reflection`",
            method="строки в exe; дамп рефлексии")).records[0]
        self.assertNotIn("EV-03", rules_of(validate.lint_markdown_record(record)))


class TestQuotedExampleConvention(unittest.TestCase):
    """MINOR: a document that teaches the rules must be able to quote a bad record.

    research/evidence-model.md describes two defects adversarial review already
    found and fixed, and quotes one of them as OBSERVED 1.00 inside the
    sentence.  The inline extractor read that as a live graded record at the
    forbidden ceiling.  Two opposite harms followed: a reader trusting the
    count believed a forbidden 1.00 still existed, and the cheapest way to
    clear the finding was to delete an honest disclosure of a past defect.
    """

    LIVE = ("Живая запись: **OBSERVED, confidence 1.00, oracle: `filesystem`**.\n")
    QUOTED = ("Оба дефекта (`decisions.md` A-07 как **OBSERVED 1.00**) найдены "
              "состязательной проверкой. <!-- kb-validate: quoted-example -->\n")

    def test_an_unmarked_quotation_is_still_linted(self):
        """The parser never infers that a grade is a quotation."""
        extractor = md_records("# d\n\n" + self.QUOTED.replace(
            " <!-- kb-validate: quoted-example -->", ""))
        self.assertEqual(1, len(extractor.records))

    def test_a_trailing_marker_exempts_the_line(self):
        extractor = md_records("# d\n\n" + self.QUOTED + "\n" + self.LIVE)
        self.assertEqual(1, len(extractor.records),
                         "only the live record may remain")
        self.assertEqual(1.0, extractor.records[0].confidence)
        self.assertEqual(1, len(extractor.quoted_examples))

    def test_a_marker_on_its_own_line_exempts_the_next_line(self):
        extractor = md_records("# d\n\n<!-- kb-validate: quoted-example -->\n"
                               + self.QUOTED.replace(
                                   " <!-- kb-validate: quoted-example -->", ""))
        self.assertEqual([], extractor.records)
        self.assertEqual(1, len(extractor.quoted_examples))

    def test_the_exemption_is_named_counted_and_printed(self):
        """An exemption that is invisible is a hole; this one is auditable."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "research" / "teaching.md", "# d\n\n" + self.QUOTED)
            report = validate.validate_markdown_file(
                root / "research" / "teaching.md", "research/teaching.md")
            self.assertEqual(0, report.errors)
            self.assertEqual(1, len(report.quoted_examples))
            self.assertIn("research/teaching.md:L3", report.quoted_examples[0])

    def test_the_convention_is_documented_in_the_help_output(self):
        self.assertIn("quoted-example", validate.MARKUP_CONVENTIONS)
        self.assertIn("EXEMPTIONS", validate.MARKUP_CONVENTIONS)


class TestMarkdownCarriesClaimType(unittest.TestCase):
    """MINOR: the 10.5 matrix applied to JSON only, so a claim changed class
    between the two notations.

    "What is on disk matches what Steam records" has claim_type
    disk-matches-steam-metadata, deliberately excluded from the class-P claim
    types, so in JSON it derived class I; in markdown the same claim derived
    class P because both its oracles are primitive and nothing else was
    consulted.  Markdown carries 216 of the 228 records.
    """

    TYPED_HEADER = ("| ID | Утверждение | Claim type | Level | Conf. | Oracle | Метод |\n"
                    "|---|---|---|---|---|---|---|\n")

    def test_a_table_can_carry_a_claim_type_column(self):
        row = self.TYPED_HEADER + (
            "| T-01 | сумма размеров совпадает с SizeOnDisk | "
            "`disk-matches-steam-metadata` | OBSERVED | 0.95 | "
            "`filesystem` + `steam-metadata` | обход ФС; чтение .acf |\n")
        record = md_records(row).records[0]
        self.assertEqual("disk-matches-steam-metadata", record.claim_type)
        self.assertIn("сумма размеров", record.claim_text)

    def test_the_matrix_now_applies_to_a_markdown_record(self):
        row = self.TYPED_HEADER + (
            "| T-01 | функция регистрирует предметы | `function-behavior` | "
            "INFERRED | 0.85 | `binary-analysis` | ghidra headless |\n")
        record = md_records(row).records[0]
        findings = validate.lint_markdown_record(record)
        self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_ERROR))
        self.assertIn("runtime-reflection",
                      " ".join(f.message for f in findings if f.rule == "EV-04"))

    def test_the_same_claim_gets_the_same_class_in_both_notations(self):
        json_verdict = validate.derive_claim_class(
            {"filesystem", "steam-metadata"}, "disk-matches-steam-metadata",
            "сумма размеров совпадает с SizeOnDisk", "OBSERVED")
        md_verdict = validate.derive_claim_class(
            {"filesystem", "steam-metadata"}, None,
            "сумма размеров совпадает с SizeOnDisk", "OBSERVED")
        self.assertEqual(validate.CLASS_I, json_verdict.claim_class)
        self.assertEqual(validate.CLASS_I, md_verdict.claim_class,
                         "the cross-check row must be derivable without a claim_type")

    def test_a_log_entry_can_carry_a_claim_type_field(self):
        text = ("## entry\n\n"
                "- **ID:** LOG-0100\n"
                "- **Claim type:** container-format\n"
                "- **Method:** чтение полей заголовка\n"
                "- **Evidence level:** OBSERVED\n"
                "- **Confidence:** 0.85\n"
                "- **Oracle:** `container-metadata`\n"
                "- **Build:** build_key=UNKNOWN\n")
        record = md_records(text).records[0]
        self.assertEqual("container-format", record.claim_type)

    def test_a_claim_type_column_is_not_mistaken_for_the_claim_column(self):
        row = self.TYPED_HEADER + (
            "| T-01 | файл существует | `file-exists` | OBSERVED | 0.99 | "
            "`filesystem` | обход ФС; повторено |\n")
        record = md_records(row).records[0]
        self.assertEqual("файл существует", record.claim_text)

    def test_the_residual_gap_is_reported_per_record_not_in_aggregate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "research" / "facts.md",
                  table_row("файл существует", conf="0.99"))
            report = validate.validate_markdown_file(
                root / "research" / "facts.md", "research/facts.md")
            self.assertEqual(1, len(report.claim_type_gaps))
            self.assertIn("L3", report.claim_type_gaps[0])
            self.assertIn("[T-01]", report.claim_type_gaps[0])

    def test_a_class_i_record_is_not_listed_as_a_claim_type_gap(self):
        """A class I record is held to the interpretive criteria either way."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "research" / "facts.md",
                  table_row("что означают байты", level="INFERRED", conf="0.95",
                            oracle="`container-metadata` + `external-doc`",
                            method="истолкование байтов; дамп заголовка"))
            report = validate.validate_markdown_file(
                root / "research" / "facts.md", "research/facts.md")
            self.assertEqual([], report.claim_type_gaps)


class TestOtherCatchAllNeedsJustification(unittest.TestCase):
    """NIT: the 'other' row accepted any of the nine oracles and no build_key.

    It is the one catch-all in the rule set and therefore a route past both the
    specific oracle pairings and the build_key requirement.  It is kept rather
    than narrowed away - a vocabulary that cannot say "the matrix has no row
    for this yet" pushes authors to mislabel instead, and a mislabelled row is
    invisible where an honest 'other' is countable - but using it now costs one
    sentence naming the missing 10.5 row.
    """

    def test_other_without_a_justification_is_rejected(self):
        record = good_record(claim_type="other", oracle=["external-doc"],
                             confidence=0.6, sources=["UE 5.4 source"])
        findings = validate.lint_record("$", record)
        self.assertIn("EV-04", rules_of(findings, validate.SEVERITY_ERROR))
        self.assertIn("justification",
                      " ".join(f.message for f in findings if f.rule == "EV-04"))

    def test_any_of_the_justification_fields_is_accepted(self):
        for key in validate.JUSTIFICATION_KEYS:
            record = good_record(claim_type="other", oracle=["external-doc"],
                                 confidence=0.6, sources=["UE 5.4 source"],
                                 **{key: "plan.md 10.5 has no row for a vanilla-UE "
                                          "reference statement"})
            self.assertNotIn("EV-04", rules_of(validate.lint_record("$", record)),
                             msg=key)

    def test_a_markdown_record_justifies_it_in_prose(self):
        header = ("| ID | Утверждение | Claim type | Level | Conf. | Oracle | Метод |\n"
                  "|---|---|---|---|---|---|---|\n")
        bare = header + ("| T-01 | так устроен vanilla UE | `other` | INFERRED | 0.6 | "
                         "`external-doc` | чтение исходников UE |\n")
        self.assertIn("EV-04", rules_of(
            validate.lint_markdown_record(md_records(bare).records[0]),
            validate.SEVERITY_ERROR))
        said = header + ("| T-01 | так устроен vanilla UE (нет строки в матрице 10.5) | "
                         "`other` | INFERRED | 0.6 | `external-doc` | "
                         "чтение исходников UE |\n")
        self.assertNotIn("EV-04", rules_of(
            validate.lint_markdown_record(md_records(said).records[0])))


class TestClassICriteriaFiveAndSix(unittest.TestCase):
    """plan.md 10.3 class I criteria 5 and 6 were named in the docstring only.

    RA-38 is the record that made this visible: as class I at 0.95 it owes a
    stored artifact, a build_key, reproduction twice AND a described refutation
    attempt, and the validator checked only the first two.
    """

    def _warnings(self, method: str) -> set:
        record = md_records(table_row(
            "вывод о сборке", level="INFERRED", conf="0.95",
            oracle="`filesystem` + `binary-analysis`", method=method)).records[0]
        return {f.message for f in validate.lint_markdown_record(record)
                if f.rule == "CLASS-I"}

    def test_a_missing_build_key_is_reported(self):
        self.assertTrue(any("build_key" in m for m in self._warnings("обход ФС")))

    def test_a_missing_refutation_attempt_is_reported(self):
        self.assertTrue(any("refutation" in m for m in self._warnings("обход ФС")))

    def test_a_complete_record_reports_neither(self):
        complete = ("обход ФС; повторено дважды; артефакт "
                    "research/evidence/T-02/dump.log; build_key=UNKNOWN; "
                    "попытка опровержения: искали обратный контрпример")
        messages = self._warnings(complete)
        self.assertFalse(any("build_key" in m for m in messages), msg=str(messages))
        self.assertFalse(any("refutation" in m for m in messages), msg=str(messages))


if __name__ == "__main__":
    unittest.main()


class TestNewLogEntryHonoursLayerOne(unittest.TestCase):
    """plan.md 1.5 layer 1 is stated without qualification, so it must hold for EVERY
    writer. The M1.0 closure audit found new_log_entry.py was the counter-example that
    made the sentence false: --log accepted any path, including one inside the game
    installation. The other three writers were already guarded, which is precisely why
    the gap was easy to miss -- the claim read as true.
    """

    def _run(self, log_path):
        import subprocess
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "kb" / "new_log_entry.py"),
             "--log", str(log_path), "--question", "guard test",
             "--method", "m", "--evidence", "e", "--finding", "f",
             "--level", "OBSERVED", "--confidence", "0.9"],
            capture_output=True, text=True)

    def test_refuses_a_log_path_inside_an_installation(self):
        with tempfile.TemporaryDirectory() as _tmp:
            tmp = os.path.realpath(_tmp)
            # A directory carrying both plan.md 2.1 step-6 markers IS an installation as
            # far as the guard is concerned, so no real game folder is touched here.
            install = os.path.join(tmp, "FakeInstall")
            os.makedirs(os.path.join(install, "MISERY", "Binaries", "Win64"))
            os.makedirs(os.path.join(install, "MISERY", "Content", "Paks"))
            open(os.path.join(install, "MISERY", "Binaries", "Win64",
                              "MISERY-Win64-Shipping.exe"), "wb").close()
            open(os.path.join(install, "MISERY", "Content", "Paks",
                              "global.utoc"), "wb").close()

            target = os.path.join(install, "sneaky.md")
            result = self._run(target)

            self.assertNotEqual(0, result.returncode,
                                "writing inside an installation must not succeed")
            self.assertFalse(os.path.exists(target),
                             "and nothing may be written before the refusal")
            self.assertIn("D-01", result.stderr,
                          "the refusal must cite the decision it enforces")

    def test_a_path_outside_any_installation_is_still_accepted(self):
        with tempfile.TemporaryDirectory() as _tmp:
            tmp = os.path.realpath(_tmp)
            target = os.path.join(tmp, "ordinary.md")
            result = self._run(target)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(os.path.exists(target),
                            "the guard must not block legitimate output")
