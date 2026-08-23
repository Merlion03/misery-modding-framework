#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validator 3.4.0: the REDUCED annotation envelope versus the FULL record.

THE DEFECT THIS FILE PINS SHUT
------------------------------
``tools/kb/validate.py`` decides that a dict is evidence-bearing by looking for
a marker key, and ``oracle`` is one of them.  That is right.  What was wrong is
that every such dict was then linted as a FULL knowledge-base record and asked
for ``claim_type`` and ``build_key``.

``research/schema/kb-record.schema.json`` defines two evidence-bearing shapes,
not one.  ``#/$defs/annotation`` is a reduced envelope for attaching evidence
metadata to a SUB-OBJECT of a larger artifact - one container of a
fingerprint, one anomaly - and it neither defines ``claim_type`` and
``build_key`` nor permits them: it is ``additionalProperties: false``.  So the
validator demanded exactly what the schema forbids.  The two could not both be
satisfied by any document, and task F-02 measured the cost: two unfixable
errors per annotation, and a ``--no-entry-evidence`` escape hatch whose only
effect is to DELETE the grading in order to quiet the tool.

Both shapes are tested here, because a fix that merely stopped complaining
would be worse than the defect: the way to make an annotation pass everything
is to make ``is_annotation`` too generous, and then a full record could drop
its ``claim_type`` by deleting a few keys.  So each test below comes in a pair -
what the annotation is excused from, and what it is NOT excused from, plus the
full record still being held to the full rules.

Run:  D:\\Tools\\venv-research\\Scripts\\python.exe -m pytest -q tests/test_validator_annotation.py
"""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = REPO_ROOT / "research" / "schema"


def _load(module_name: str, relative_path: str):
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


validate = _load("misery_kb_validate_annotation", "tools/kb/validate.py")


def rules(findings) -> set[str]:
    return {finding.rule for finding in findings}


def errors(findings) -> list:
    return [f for f in findings if f.severity == validate.SEVERITY_ERROR]


def error_rules(findings) -> set[str]:
    return {f.rule for f in errors(findings)}


# --------------------------------------------------------------------------- #
# fixtures: the two shapes, written the way the real artifacts write them
# --------------------------------------------------------------------------- #

def class_i_annotation(**overrides) -> dict:
    """The decoded-container annotation tools/fingerprint/container_info.py emits."""
    annotation = {
        "evidence_level": "INFERRED",
        "claim_class": "I",
        "confidence": 0.85,
        "oracle": ["container-metadata", "external-doc", "filesystem"],
        "sources": [
            {"method": "F-02", "artifact": None,
             "locator": "MISERY/Content/Paks/global.utoc",
             "note": "oracle container-metadata + external-doc. Field decode against "
                     "the public FIoStoreTocHeader layout."},
            {"method": "F-02", "artifact": None,
             "locator": "MISERY/Content/Paks/global.utoc",
             "independent_of": ["F-02/field-decode"],
             "note": "oracle filesystem. Second, independent method: the layout "
                     "arithmetic closes against the size on disk."},
        ],
        "read_locus": None,
        "note": "Interpretive: this record NAMES the byte ranges and decodes them. "
                "Method re-run and reproduced.",
    }
    annotation.update(overrides)
    return annotation


def class_p_annotation(**overrides) -> dict:
    """The literal-read annotation: OBSERVED, class P, one method, 0.99."""
    annotation = {
        "evidence_level": "OBSERVED",
        "claim_class": "P",
        "confidence": 0.99,
        "oracle": ["container-metadata"],
        "sources": [
            {"method": "F-02", "artifact": None, "locator": "global.utoc@48+4",
             "note": "oracle container-metadata. Read read-only. Method re-run and "
                     "reproduced: every range was read a second time and agrees."},
        ],
        "read_locus": {
            "target": "MISERY/Content/Paks/global.utoc",
            "address_kind": "file-offset",
            "offset": 48,
            "length": 4,
            "bytes_hex": "a0 e4 0c 00",
            "note": None,
        },
        "note": "4 bytes at offset 48 of MISERY/Content/Paks/global.utoc are "
                "a0 e4 0c 00. Method re-run and reproduced.",
    }
    annotation.update(overrides)
    return annotation


def full_record(**overrides) -> dict:
    """A FULL knowledge-base record: the same evidence plus the envelope fields."""
    record = {
        "record_id": "F-03-0001",
        "statement": "the installation holds 53 files",
        "claim_type": "file-exists",
        "build_key": "sha256:" + "0e" * 32,
        "evidence_level": "OBSERVED",
        "claim_class": "P",
        "confidence": 0.99,
        "oracle": ["filesystem"],
        "sources": [{"method": "F-03", "artifact": None, "locator": "install tree",
                     "note": "walked read-only; re-run and reproduced"}],
    }
    record.update(overrides)
    return record


# --------------------------------------------------------------------------- #
# 1. recognition
# --------------------------------------------------------------------------- #

class TestShapeRecognition(unittest.TestCase):

    def test_the_reduced_envelope_is_recognised_as_an_annotation(self):
        self.assertTrue(validate.is_annotation(class_i_annotation()))
        self.assertTrue(validate.is_annotation(class_p_annotation()))

    def test_a_full_record_is_never_an_annotation(self):
        self.assertFalse(validate.is_annotation(full_record()))

    def test_one_forbidden_key_takes_the_object_out_of_the_shape(self):
        """The subset test is the whole guard, so probe every full-record key."""
        for key, value in (("claim_type", "file-exists"),
                           ("build_key", "sha256:" + "0e" * 32),
                           ("record_id", "X-1"),
                           ("recorded_at", "2026-08-23T00:00:00Z"),
                           ("statement", "something"),
                           ("refuted_by", ["X-2"])):
            with self.subTest(key=key):
                self.assertFalse(
                    validate.is_annotation(class_i_annotation(**{key: value})),
                    "a dict carrying %r must be linted as a full record" % key)

    def test_the_root_of_a_document_is_never_an_annotation(self):
        """An annotation annotates something; a whole file has no enclosing document.

        research/kb/*.json is mapped to the FULL envelope by
        ARTIFACT_SCHEMA_MAP, and such a file has nowhere to inherit a build_key
        from, so the root must keep the full rules whatever its key set is.
        """
        self.assertFalse(validate.is_annotation(class_i_annotation(), at_root=True))

    def test_a_dict_with_no_marker_key_is_not_an_annotation(self):
        self.assertFalse(validate.is_annotation({"note": "just a note"}))
        self.assertFalse(validate.is_annotation({"read_locus": None}))

    def test_a_source_object_is_not_an_annotation(self):
        """A source carrying its own oracle is a source, not a reduced envelope."""
        source = {"method": "F-02", "artifact": None, "locator": "x",
                  "oracle": "container-metadata"}
        self.assertTrue(validate.is_record(source))
        self.assertFalse(validate.is_annotation(source))

    def test_non_dicts_are_rejected(self):
        for value in (None, 3, "text", ["evidence_level"]):
            with self.subTest(value=value):
                self.assertFalse(validate.is_annotation(value))


# --------------------------------------------------------------------------- #
# 2. the annotation rule set: what it drops, and what it emphatically keeps
# --------------------------------------------------------------------------- #

class TestAnnotationIsExcusedFromExactlyTwoRules(unittest.TestCase):

    def test_the_class_i_annotation_is_clean(self):
        findings = validate.lint_annotation("$.containers[0].evidence",
                                            class_i_annotation())
        self.assertEqual([], [f.to_dict() for f in findings])

    def test_the_class_p_annotation_is_clean(self):
        findings = validate.lint_annotation("$.anomalies[0].evidence",
                                            class_p_annotation())
        self.assertEqual([], [f.to_dict() for f in findings])

    def test_the_same_object_under_lint_record_still_fails_both_rules(self):
        """The defect, stated as a test: this is what used to reach the report."""
        findings = validate.lint_record("$.containers[0].evidence",
                                        class_i_annotation())
        self.assertIn("EV-04", error_rules(findings))
        self.assertIn("EV-BUILD", error_rules(findings))

    def test_no_claim_type_finding_is_raised_on_an_annotation(self):
        findings = validate.lint_annotation("$.x", class_i_annotation())
        joined = " ".join(f.message for f in findings)
        self.assertNotIn("claim_type", joined)

    def test_no_build_key_finding_is_raised_on_an_annotation(self):
        findings = validate.lint_annotation("$.x", class_i_annotation())
        self.assertNotIn("EV-BUILD", rules(findings))

    def test_criterion_5_does_not_ask_a_0_95_annotation_for_a_build_key(self):
        """plan.md 10.3 class I criterion 5 is satisfied by the enclosing document.

        The annotation has no build_key property and forbids one, so warning
        about its absence would be the same deadlock in a lower severity.
        """
        annotation = class_i_annotation(
            confidence=0.95,
            note="Interpretive. Saved raw artifact under research/evidence/T-02/. "
                 "Reproduced twice. Refutation attempt: we looked for the field at "
                 "the alternative offset and did not find it.")
        findings = validate.lint_annotation("$.x", annotation)
        self.assertNotIn(
            "build_key", " ".join(f.message for f in findings),
            "criterion 5 must not be asked of a shape that cannot answer it")

    def test_a_full_record_at_0_95_is_still_asked_for_criterion_5(self):
        """The suppression is bound to the SHAPE, not switched off globally."""
        record = full_record(
            evidence_level="INFERRED", claim_class="I", confidence=0.95,
            claim_type="build-identity",
            oracle=["binary-analysis", "external-doc"],
            build_key=None,
            statement="the image was linked by MSVC 19.x",
            sources=[{"method": "A"}, {"method": "B"}])
        findings = validate.lint_record("$.x", record)
        self.assertIn("build_key", " ".join(f.message for f in findings))


class TestAnnotationKeepsEveryOtherRule(unittest.TestCase):

    def test_a_missing_evidence_level_is_an_error(self):
        annotation = class_i_annotation()
        del annotation["evidence_level"]
        self.assertIn("EV-LEVEL", error_rules(validate.lint_annotation("$.x", annotation)))

    def test_an_invented_evidence_level_is_an_error(self):
        annotation = class_i_annotation(evidence_level="PROBABLE")
        self.assertIn("EV-LEVEL", error_rules(validate.lint_annotation("$.x", annotation)))

    def test_the_confidence_ceiling_holds(self):
        for value in (1.0, 0.995, 0.999):
            with self.subTest(confidence=value):
                annotation = class_p_annotation(confidence=value)
                self.assertIn("EV-CONF",
                              error_rules(validate.lint_annotation("$.x", annotation)))

    def test_a_missing_confidence_is_an_error(self):
        annotation = class_i_annotation()
        del annotation["confidence"]
        self.assertIn("EV-CONF", error_rules(validate.lint_annotation("$.x", annotation)))

    def test_an_unknown_oracle_is_an_error(self):
        annotation = class_i_annotation(oracle=["hexdump"])
        self.assertIn("EV-04", error_rules(validate.lint_annotation("$.x", annotation)))

    def test_a_missing_oracle_is_an_error(self):
        annotation = class_i_annotation()
        del annotation["oracle"]
        self.assertIn("EV-04", error_rules(validate.lint_annotation("$.x", annotation)))

    def test_missing_sources_is_an_error(self):
        annotation = class_i_annotation()
        del annotation["sources"]
        self.assertIn("EV-03", error_rules(validate.lint_annotation("$.x", annotation)))

    def test_a_class_i_annotation_at_0_85_still_needs_two_methods(self):
        annotation = class_i_annotation(sources=[{"method": "F-02", "note": "decode"}])
        self.assertIn("EV-03", error_rules(validate.lint_annotation("$.x", annotation)))

    def test_a_mislabelled_class_is_still_ev_05(self):
        """INFERRED is class I unconditionally (plan.md 10.3 v2.3)."""
        annotation = class_i_annotation(claim_class="P")
        self.assertIn("EV-05", error_rules(validate.lint_annotation("$.x", annotation)))

    def test_external_doc_alone_is_still_capped_at_0_7(self):
        annotation = class_i_annotation(oracle=["external-doc"], confidence=0.85)
        self.assertIn("C-12", error_rules(validate.lint_annotation("$.x", annotation)))

    def test_a_mixed_annotation_is_still_split(self):
        """The class-P sentence plus a name for the bytes is one record too many."""
        annotation = class_p_annotation(
            note="4 bytes at offset 48 of global.utoc are a0 e4 0c 00, which is the "
                 "DirectoryIndexSize field and its value is 844960. Re-run, reproduced.")
        self.assertIn("MIX-SPLIT", error_rules(validate.lint_annotation("$.x", annotation)))

    def test_a_refuted_annotation_is_told_where_refuted_by_lives(self):
        annotation = class_i_annotation(evidence_level="REFUTED", claim_class="I")
        findings = validate.lint_annotation("$.x", annotation)
        self.assertIn("EV-REFUTED", rules(findings))
        self.assertIn("refuted_by", " ".join(f.message for f in findings))


# --------------------------------------------------------------------------- #
# 3. the dispatch, end to end through validate_file
# --------------------------------------------------------------------------- #

class TestDispatchThroughValidateFile(unittest.TestCase):

    def _run(self, document: dict, name: str = "unmapped-probe.json"):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / name
            path.write_text(json.dumps(document, indent=2), encoding="utf-8")
            return validate.validate_file(path, "probe/" + name, SCHEMA_DIR, set())

    def test_an_annotation_inside_a_document_is_counted_and_not_flagged(self):
        document = {"containers": [{"path": "global.utoc", "kind": "utoc",
                                    "evidence": class_i_annotation()}]}
        report = self._run(document)
        self.assertEqual(1, report.annotation_count)
        self.assertEqual(1, report.record_count)
        self.assertEqual([], [f.to_dict() for f in report.findings
                              if f.rule in ("EV-04", "EV-BUILD")])

    def test_a_full_record_inside_a_document_keeps_the_full_rules(self):
        document = {"records": [{"evidence_level": "OBSERVED", "confidence": 0.9,
                                 "oracle": ["filesystem"], "statement": "x",
                                 "sources": [{"method": "m"}]}]}
        report = self._run(document)
        self.assertEqual(0, report.annotation_count)
        self.assertIn("EV-04", {f.rule for f in report.findings})

    def test_the_annotation_count_is_reported_in_json_output(self):
        document = {"a": {"evidence": class_i_annotation()},
                    "b": {"evidence": class_p_annotation()}}
        report = self._run(document)
        self.assertEqual(2, report.annotation_count)
        self.assertEqual(2, report.to_dict()["annotation_count"])


# --------------------------------------------------------------------------- #
# 4. the constant is pinned to the schema it copies
# --------------------------------------------------------------------------- #

class TestAnnotationKeysMatchTheSchema(unittest.TestCase):
    """ANNOTATION_KEYS duplicates a closed property set; pin it so it cannot drift.

    The validator must run with research/schema/ missing, so the set is a
    literal in the source rather than a runtime read.  A literal copy of another
    file's contract is only safe when something fails the moment the two differ.
    """

    def test_the_key_set_is_exactly_the_schema_property_set(self):
        schema = json.loads((SCHEMA_DIR / "kb-record.schema.json").read_text(
            encoding="utf-8"))
        annotation = schema["$defs"]["annotation"]
        self.assertEqual(set(annotation["properties"]), set(validate.ANNOTATION_KEYS))

    def test_the_schema_still_forbids_the_two_dropped_properties(self):
        """If the schema ever gains claim_type/build_key, the fix must be revisited."""
        schema = json.loads((SCHEMA_DIR / "kb-record.schema.json").read_text(
            encoding="utf-8"))
        annotation = schema["$defs"]["annotation"]
        self.assertFalse(annotation.get("additionalProperties", True))
        self.assertNotIn("claim_type", annotation["properties"])
        self.assertNotIn("build_key", annotation["properties"])

    def test_the_full_record_only_keys_are_absent_from_the_annotation(self):
        self.assertEqual(frozenset(),
                         validate.ANNOTATION_KEYS & validate.FULL_RECORD_ONLY_KEYS)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
