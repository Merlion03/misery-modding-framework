#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for validator 3.3.0: plan.md 10.3 правка v2.4 and the normative-sentence reader.

Two behaviours are pinned here, and both were introduced together because both
come from the same mistake - treating the SHAPE of a sentence as the shape of a
record:

  * plan.md 10.3 v2.4.  Class P is decided by the NATURE of the claim, not by a
    white list of oracles.  `binary-analysis` and `container-metadata` are
    admissible in class P, under one additional mandatory condition: the claim
    states the offset (or another determinate address) AND the length.  Rule
    v2.3 stays dominant on top of it - INFERRED and HYPOTHESIS are class I
    unconditionally, whatever the oracle and however precise the offset.

  * the normative-sentence reader.  A sentence that ENUMERATES the permitted
    levels as part of a requirement ("Exit criteria: ... подтверждённая запись
    (OBSERVED/INFERRED с confidence >= 0.7 и сигнатурой)") states the rule
    records must satisfy; reading it as a record packing two levels into one
    span raised PARSE-MD on the plan's own exit criteria.

Run:  D:\\Tools\\venv-research\\Scripts\\python.exe -m pytest -q tests/test_validator_class_p_offset.py
"""

from __future__ import annotations

import importlib.util
import sys
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


validate = _load("misery_kb_validate_v24", "tools/kb/validate.py")


# The plan's own canonical class P example, verbatim from plan.md 10.3
# "Смешанные утверждения обязаны разделяться".
CANONICAL_P = ("четыре байта по смещению 48 в `MISERY-Windows.utoc` равны "
               "`a0 e4 0c 00`")
# The class I half of the same canonical pair.
CANONICAL_I = "это поле `DirectoryIndexSize` и его значение 844 960"


class TestOffsetConditionAdmitsClassP(unittest.TestCase):
    """The three cases task A names, plus the oracle sets around them."""

    def test_container_metadata_with_an_offset_is_class_p(self):
        verdict = validate.derive_claim_class(
            {"container-metadata"}, None, CANONICAL_P, "OBSERVED")
        self.assertEqual(validate.CLASS_P, verdict.claim_class)
        self.assertFalse(verdict.mixed)

    def test_the_same_claim_without_an_offset_is_not_class_p(self):
        verdict = validate.derive_claim_class(
            {"container-metadata"}, None,
            "заголовок `MISERY-Windows.utoc` прочитан, значение равно 844 960",
            "OBSERVED")
        self.assertEqual(validate.CLASS_I, verdict.claim_class)
        self.assertIn("offset", verdict.reason)

    def test_inferred_with_an_offset_is_still_class_i(self):
        """v2.3 stays dominant: the level decides before the oracle is looked at."""
        verdict = validate.derive_claim_class(
            {"container-metadata"}, None, CANONICAL_P, "INFERRED")
        self.assertEqual(validate.CLASS_I, verdict.claim_class)
        self.assertTrue(verdict.level_decided)

    def test_hypothesis_with_an_offset_is_still_class_i(self):
        verdict = validate.derive_claim_class(
            {"binary-analysis"}, None, CANONICAL_P, "HYPOTHESIS")
        self.assertEqual(validate.CLASS_I, verdict.claim_class)
        self.assertTrue(verdict.level_decided)

    def test_binary_analysis_with_an_offset_is_class_p(self):
        verdict = validate.derive_claim_class(
            {"binary-analysis"}, None,
            "16 байт по смещению 64 в `MISERY-Win64-Shipping.exe` равны нулю",
            "OBSERVED")
        self.assertEqual(validate.CLASS_P, verdict.claim_class)

    def test_a_missing_evidence_level_does_not_inherit_the_admission(self):
        """The NEW admission does not inherit the older tolerance for no level.

        derive_claim_class() falls through a missing level for the three
        unconditional oracles (that record already has an EV-LEVEL finding).
        v2.4 grants class P to a literal read AT `OBSERVED`; a read that does
        not say it was observed is not one on the record.
        """
        verdict = validate.derive_claim_class(
            {"container-metadata"}, None, CANONICAL_P, None)
        self.assertEqual(validate.CLASS_I, verdict.claim_class)

    def test_the_unconditional_oracles_are_unchanged(self):
        verdict = validate.derive_claim_class(
            {"filesystem"}, None, "в установке 53 файла", "OBSERVED")
        self.assertEqual(validate.CLASS_P, verdict.claim_class)

    def test_a_semantic_oracle_still_forces_class_i(self):
        verdict = validate.derive_claim_class(
            {"container-metadata", "external-doc"}, None, CANONICAL_P, "OBSERVED")
        self.assertEqual(validate.CLASS_I, verdict.claim_class)

    def test_binary_oracles_remain_semantics_bearing(self):
        """v2.4 must not empty the class I "нужен семантический источник" row.

        The two oracles CAN carry a literal read; that does not stop them
        carrying semantics, and subtracting them from SEMANTIC_ORACLES would
        have switched the class I oracle row off for exactly the records it was
        written for.
        """
        self.assertIn("binary-analysis", validate.SEMANTIC_ORACLES)
        self.assertIn("container-metadata", validate.SEMANTIC_ORACLES)
        self.assertNotIn("filesystem", validate.SEMANTIC_ORACLES)


class TestNamingTheBytesIsClassI(unittest.TestCase):
    """plan.md 10.3 v2.4 class I: naming WHAT was read is the interpretation."""

    def test_offset_plus_a_named_field_is_a_mixed_record(self):
        verdict = validate.derive_claim_class(
            {"container-metadata"}, None,
            CANONICAL_P + ", " + CANONICAL_I, "OBSERVED")
        self.assertEqual(validate.CLASS_I, verdict.claim_class)
        self.assertTrue(verdict.mixed, "the canonical A-07 pair written as one "
                                       "record must demand the split")

    def test_a_camelcase_layout_identifier_counts_as_naming(self):
        self.assertTrue(validate.names_what_the_bytes_are(
            "смещение 48, 4 байта, `DirectoryIndexSize`"))
        self.assertTrue(validate.names_what_the_bytes_are("`FIoStoreTocHeader`"))

    def test_a_file_name_is_not_a_layout_identifier(self):
        """MISERY-Windows.utoc must not read as a struct field name."""
        self.assertFalse(validate.names_what_the_bytes_are(
            "четыре байта по смещению 48 в MISERY-Windows.utoc равны a0 e4 0c 00"))

    def test_perechisleny_is_not_a_layout_word(self):
        """"перечислены" means "are listed" and says nothing about a layout.

        It was the accidental trigger on plan.md A-05 in the first draft of this
        rule - a real class I row reached for an unrelated reason.
        """
        self.assertFalse(validate.names_what_the_bytes_are(
            "прочие файлы его каталога там перечислены"))
        self.assertTrue(validate.names_what_the_bytes_are("перечисление флагов"))


class TestDeterminateAddressDetection(unittest.TestCase):
    """What the offset test accepts, and the false positives it must refuse.

    The direction is deliberate: a false negative costs an author one clause,
    a false positive admits an interpretation as a measurement.
    """

    def assert_address(self, text: str) -> None:
        self.assertTrue(validate.states_determinate_address(text), text)

    def refute_address(self, text: str) -> None:
        self.assertFalse(validate.states_determinate_address(text), text)

    def test_accepted_forms(self):
        self.assert_address("четыре байта по смещению 48 равны a0 e4 0c 00")
        self.assert_address("16 байт по смещению 64 — нули")
        self.assert_address("4 bytes at offset 48")
        self.assert_address("смещение 0x30, длина 4 байта")
        self.assert_address("uint64 по смещению 56")
        self.assert_address("dword по адресу 0x140001000")
        self.assert_address("байты 48-51")
        self.assert_address("bytes 0x30..0x33")
        self.assert_address("байт 16 = 6")

    def test_an_address_without_a_length_is_refused(self):
        """plan.md 10.3 v2.4 requires BOTH halves, and says so in one sentence."""
        self.refute_address("смещение 20 = 144")
        self.refute_address("offset 44 = 65 536")

    def test_a_length_without_an_address_is_refused(self):
        """A file size is a `filesystem` claim and needs no offset at all."""
        self.refute_address("файл размером 134 658 048 байт")
        self.refute_address("282 826 240 B, 10 секций")

    def test_a_date_is_not_a_byte_range(self):
        """The regression that made plan.md A-13 derive as a measurement.

        "номинально 2030-10-19" matched a bare N-M range, so an interpretive
        PE-section claim with no offset in it at all cleared the offset
        condition. The address keyword in front of the range is mandatory for
        exactly this reason.
        """
        self.refute_address("PE link timestamp 1918640348, номинально 2030-10-19")
        self.refute_address("branch ++UE5+Release-5.4-CL-35576357")

    def test_a_version_number_is_not_a_virtual_address(self):
        """Without a leading \\b, "va" matches inside "Java 25"."""
        self.refute_address("Ghidra 11.4.2 на Java 25, прочитано 4 байта")

    def test_a_bare_offset_word_is_not_an_address(self):
        self.refute_address("прочитано по смещению, длина 4 байта")
        self.refute_address("48 и 4 байта")


class TestNormativeLevelEnumeration(unittest.TestCase):
    """plan.md line 533: a requirement that NAMES the levels is not a record."""

    EXIT_CRITERION_SPAN = "`OBSERVED`/`INFERRED` с confidence ≥ 0.7 и сигнатурой"
    EXIT_CRITERION_LINE = (
        "**Exit criteria:** для каждой цели из §7.4 есть либо подтверждённая "
        "запись (`OBSERVED`/`INFERRED` с confidence ≥ 0.7 и сигнатурой), либо "
        "явная запись в `unknowns.md` с описанием, что именно заблокировало.")

    def test_the_exit_criterion_is_recognised(self):
        self.assertTrue(validate.is_normative_level_enumeration(
            self.EXIT_CRITERION_SPAN, self.EXIT_CRITERION_LINE))

    def test_a_record_stating_a_grade_as_a_value_is_not_exempt(self):
        """Condition 2 is the load-bearing one: a grade is never a threshold."""
        self.assertFalse(validate.is_normative_level_enumeration(
            "OBSERVED/INFERRED, confidence 0.85",
            "Критерий: OBSERVED/INFERRED, confidence 0.85"))

    def test_prose_between_the_levels_is_not_an_enumeration(self):
        """Two graded claims in one span still have to be split."""
        self.assertFalse(validate.is_normative_level_enumeration(
            "OBSERVED для байтов и INFERRED для разбора, confidence ≥ 0.7",
            "Критерий: OBSERVED для байтов и INFERRED для разбора, confidence ≥ 0.7"))

    def test_without_requirement_vocabulary_it_is_not_exempt(self):
        self.assertFalse(validate.is_normative_level_enumeration(
            "`OBSERVED`/`INFERRED` с confidence ≥ 0.7",
            "Запись про контейнер: `OBSERVED`/`INFERRED` с confidence ≥ 0.7"))

    def test_one_level_is_never_an_enumeration(self):
        """The exemption is not extended to single-level spans.

        A single graded span phrased as a requirement is the `quoted-example`
        case, and that one needs the explicit marker on purpose - the parser
        must not infer that a grade is a quotation.
        """
        self.assertFalse(validate.is_normative_level_enumeration(
            "OBSERVED, до 0.99, oracle `container-metadata`",
            "Обязательное правило: OBSERVED, до 0.99, oracle `container-metadata`"))

    def test_the_extractor_yields_neither_a_record_nor_a_parse_error(self):
        document = (
            "# Milestone\n"
            "\n"
            + self.EXIT_CRITERION_LINE + "\n")
        extractor = validate.MarkdownExtractor("plan.md", document)
        extractor.run()
        self.assertEqual([], [u.excerpt for u in extractor.unparseable])
        self.assertEqual(1, len(extractor.normative_enumerations))
        self.assertEqual(
            [], [r.pointer for r in extractor.records if r.level is not None])

    def test_a_genuine_two_level_record_still_fails_to_parse(self):
        """The general rule must not swallow the defect PARSE-MD exists for."""
        document = (
            "# Заметка\n"
            "\n"
            "Контейнер прочитан (OBSERVED, 0.99, INFERRED, 0.85, "
            "oracle `container-metadata`).\n")
        extractor = validate.MarkdownExtractor("research/x.md", document)
        extractor.run()
        self.assertEqual([], extractor.normative_enumerations)
        self.assertTrue(any("evidence levels" in u.reason
                            for u in extractor.unparseable),
                        [u.reason for u in extractor.unparseable])


class TestPlanDocumentItself(unittest.TestCase):
    """The two live sentences this change is about, read from plan.md."""

    @classmethod
    def setUpClass(cls):
        text = (REPO_ROOT / "plan.md").read_text(encoding="utf-8")
        cls.extractor = validate.MarkdownExtractor("plan.md", text)
        cls.extractor.run()

    def test_plan_md_has_no_unparseable_inline_annotation(self):
        self.assertEqual(
            [], [(u.line, u.excerpt) for u in self.extractor.unparseable])

    def test_the_exit_criterion_of_section_7_4_is_exempt_and_named(self):
        self.assertTrue(
            any("OBSERVED" in excerpt and "INFERRED" in excerpt
                for _line, excerpt in self.extractor.normative_enumerations),
            self.extractor.normative_enumerations)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
