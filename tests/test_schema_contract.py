#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The PUBLISHED schema contract, exercised the way a third party consumes it.

Every check here runs through a PLAIN `jsonschema.Draft202012Validator` built
from one file read off disk, with NO custom registry, NO base-URI rewriting and
NO network access.  That is deliberate and it is the point of the file.  The
repository is public (MIT, github.com/Merlion03/misery-modding-framework), so
the schemas are consumed by an editor, a CI step, or four lines of Python -
never by tools/kb/validate.py, which builds an offline registry of its own and
would therefore hide exactly the defects a stranger hits first.

WHAT THIS FILE PINS

  * plan.md 10.3 правка v2.4.  Class P is decided by the NATURE of the claim,
    not by a white list of oracles: `binary-analysis` and `container-metadata`
    are admissible for class P for a literal read at a determinate place.  The
    shape of Appendix A row A-07 - OBSERVED, class P, oracle
    `container-metadata`, confidence 0.99, ONE source - must be ACCEPTED.
    Before this contract was brought up to v2.4 it was rejected twice over, on
    the three-oracle white list and on `sources` minItems 2, which is to say
    the project's published contract rejected the example the plan holds up as
    its canonical correct record.

  * plan.md 10.3 правка v2.3, and it stays dominant.  `INFERRED`,
    `HYPOTHESIS` and `REFUTED` mean a conclusion beyond direct observation was
    drawn, so the record is class I whatever its oracles are and however
    precise its offset is.  No oracle set and no `read_locus` may buy the
    single-source exemption for a record that is not `OBSERVED`.

  * plan.md 10.2 правка v2.3.  The ceiling is a COMPARISON:
    0.00 <= confidence <= 0.99.  0.995 and 0.999 are forbidden exactly as 1.00
    is, and the bound must be present in all four self-contained schemas and
    not only in kb-record.schema.json.

  * plan.md 10.5 v2.1.  The oracle vocabulary is CLOSED at nine values.

  * The three bundling schemas carry a copy of the kb-record envelope, so the
    copy must express the same revision as the original.  A bundle frozen one
    revision behind is the same defect as no bundle at all: a consumer that
    validates against install.schema.json gets a different contract from one
    that validates against kb-record.schema.json.

  * The real artifacts under research/builds/ still validate, offline, against
    the schema each of them is mapped to.

WHERE THE SCHEMA/VALIDATOR BOUNDARY LIES, because these tests are written to
that boundary and not past it.  plan.md states the v2.4 condition on the
WORDING of the claim - "в утверждении указано смещение (или иной
детерминированный адрес) И длина" - and says explicitly, right after the
canonical A-07 pair, that the condition belongs to the formulation of the
record and is not part of its `oracle` field.  No JSON Schema keyword can read
a Russian sentence.  So the schema requires the record to CARRY the address and
the extent as data, in `read_locus`, and the two prose halves stay with
tools/kb/validate.py: `states_determinate_address()` reads the sentence for the
address and the extent, and `names_what_the_bytes_are()` refuses class P to a
sentence that names WHAT the bytes are.  The tests below therefore assert that
the schema accepts a record carrying `read_locus` - NOT that the schema
certifies the wording, which it does not and does not claim to.  The validator
remains the stricter gate: a record can pass every check in this file and still
be refused there, and `test_schema_is_not_the_stricter_gate` pins that ordering
by example.

Run:  D:\\Tools\\venv-research\\Scripts\\python.exe -m pytest -q tests/test_schema_contract.py
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = REPO_ROOT / "research" / "schema"
BUILDS_DIR = REPO_ROOT / "research" / "builds"

# The five self-contained schemas: each one carries the whole kb-record
# envelope, so each one can be handed to a plain validator on its own.  The
# other three files in research/schema/ ($ref across files) need a registry and
# are out of scope here BY CONSTRUCTION, not by omission - see
# test_cross_file_schemas_are_declared_not_forgotten.
#
# engine-version.schema.json (task K-02) is the fourth bundle and the first one
# outside research/builds/.  It is bundled for the same reason the other three
# are: research/unreal/engine-version.json is a committed artifact of a public
# repository, so the consumer who matters is a stranger pointing a bare
# Draft202012Validator at the file with nothing configured.  Listing it here is
# the deliberate decision this enumeration exists to force - adding a bundle
# without it turns the whole contract suite below into a check that skips the
# new copy.
KB_RECORD = "kb-record.schema.json"
BUNDLES = (
    "build-index.schema.json",
    "engine-version.schema.json",
    "install-inventory.schema.json",
    "install.schema.json",
)
SELF_CONTAINED = (KB_RECORD,) + BUNDLES

# plan.md 10.5 v2.1: the vocabulary is closed at nine values.
NINE_ORACLES = (
    "filesystem",
    "steam-metadata",
    "vcs-history",
    "global-ucas",
    "asset-registry",
    "runtime-reflection",
    "binary-analysis",
    "container-metadata",
    "external-doc",
)

# plan.md 10.3 v2.4: admissible for class P without further condition.
CLASS_P_UNCONDITIONAL = ("filesystem", "steam-metadata", "vcs-history")
# plan.md 10.3 v2.4: admissible for class P only for a literal read at a
# determinate place, which in a JSON record means a read_locus.
CLASS_P_CONDITIONAL = ("binary-analysis", "container-metadata")
# The four the plan never admits: they cannot carry a literal read at a place.
NEVER_CLASS_P = ("global-ucas", "asset-registry", "runtime-reflection",
                 "external-doc")

BUILD_KEY = "sha256:" + "0" * 64


def _require_jsonschema(test):
    try:
        from jsonschema import Draft202012Validator  # noqa: F401
        from jsonschema.validators import validator_for  # noqa: F401
    except ImportError:  # pragma: no cover
        test.skipTest("jsonschema is not installed in this interpreter")


def _load(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def _kb_record_of(name: str) -> dict:
    """The kb-record contract as `name` publishes it.

    For kb-record.schema.json that is the document; for a bundle it is the
    embedded copy under $defs.  Both are handed to a plain validator with no
    registry, which is the whole point.
    """
    document = _load(name)
    if name == KB_RECORD:
        return document
    return document["$defs"][KB_RECORD]


def _errors(subschema: dict, instance) -> list:
    from jsonschema import Draft202012Validator

    return sorted(Draft202012Validator(subschema).iter_errors(instance),
                  key=lambda error: list(error.absolute_schema_path))


def a07(**overrides) -> dict:
    """plan.md Appendix A row A-07, primitive half, as a JSON record.

    Verbatim from plan.md 10.3 "Смешанные утверждения обязаны разделяться":

        > Четыре байта по смещению 48 в `MISERY-Windows.utoc` равны
        > `a0 e4 0c 00`.
        > *(OBSERVED, confidence 0.99, oracle: container-metadata, класс P)*

    ONE source on purpose.  That is the whole content of the finding this file
    exists for: the plan grants a class-P record a single method up to the 0.99
    ceiling, and the published contract used to refuse this record both for its
    oracle and for its single source.
    """
    record = {
        "id": "A-07",
        "claim": ("Четыре байта по смещению 48 в MISERY-Windows.utoc равны "
                  "a0 e4 0c 00."),
        "claim_type": None,
        "claim_class": "P",
        "evidence_level": "OBSERVED",
        "confidence": 0.99,
        "sources": [
            {
                "method": "I-02",
                "artifact": "research/evidence/I-02/utoc-header.txt",
                "locator": "byte 48",
                "oracle": "container-metadata",
            },
        ],
        "oracle": ["container-metadata"],
        "read_locus": {
            "target": "MISERY/Content/Paks/MISERY-Windows.utoc",
            "address_kind": "file-offset",
            "offset": 48,
            "length": 4,
            "bytes_hex": "a0 e4 0c 00",
        },
        "build_key": BUILD_KEY,
        "recorded_at": "2026-08-22T12:19:17Z",
    }
    record.update(overrides)
    return {key: value for key, value in record.items() if value is not _ABSENT}


class _Absent:
    def __repr__(self):  # pragma: no cover - debugging aid only
        return "<absent>"


_ABSENT = _Absent()


def primitive_record(**overrides) -> dict:
    """A class-P record on an UNCONDITIONAL oracle: the plain filesystem fact."""
    record = {
        "claim": "Файл MISERY/Content/Paks/global.utoc существует, размер 623 байта.",
        "claim_type": "file-exists",
        "claim_class": "P",
        "evidence_level": "OBSERVED",
        "confidence": 0.99,
        "sources": ["I-01"],
        "oracle": ["filesystem"],
        "build_key": BUILD_KEY,
        "recorded_at": "2026-08-22T12:19:17Z",
    }
    record.update(overrides)
    return {key: value for key, value in record.items() if value is not _ABSENT}


class SchemaContractTestCase(unittest.TestCase):
    """Base: one plain validator per self-contained schema, no registry."""

    def setUp(self):
        _require_jsonschema(self)

    def assert_accepted(self, record, *, message=""):
        for name in SELF_CONTAINED:
            with self.subTest(schema=name):
                errors = _errors(_kb_record_of(name), record)
                self.assertEqual(
                    [], [error.message for error in errors],
                    f"{name} rejects a record the contract must accept. {message}")

    def assert_rejected(self, record, *, message=""):
        for name in SELF_CONTAINED:
            with self.subTest(schema=name):
                errors = _errors(_kb_record_of(name), record)
                self.assertNotEqual(
                    [], errors,
                    f"{name} accepts a record the contract must reject. {message}")


class TestSchemasArePublishable(SchemaContractTestCase):
    """A schema a stranger cannot load is not published, whatever it says."""

    def test_every_schema_file_is_a_valid_draft_2020_12_schema(self):
        from jsonschema import Draft202012Validator
        from jsonschema.validators import validator_for

        files = sorted(SCHEMA_DIR.glob("*.schema.json"))
        self.assertNotEqual([], files, "research/schema/ holds no schemas")
        for path in files:
            with self.subTest(schema=path.name):
                document = json.loads(path.read_text(encoding="utf-8"))
                cls = validator_for(document, Draft202012Validator)
                cls.check_schema(document)

    def test_a_plain_validator_builds_from_each_self_contained_schema(self):
        from jsonschema import Draft202012Validator

        for name in SELF_CONTAINED:
            with self.subTest(schema=name):
                Draft202012Validator(_kb_record_of(name)).is_valid({})

    def test_cross_file_schemas_are_declared_not_forgotten(self):
        """The four remaining schemas $ref across files, so they need a registry.

        Pinned as a fact rather than left implicit: a future edit that makes
        one of them self-contained, or that gives a bundle a cross-file $ref,
        should show up here and be a deliberate decision about what a third
        party can validate offline.
        """
        cross_file = []
        for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
            text = path.read_text(encoding="utf-8")
            document = json.loads(text)
            has_embedded = KB_RECORD in document.get("$defs", {})
            refs_sibling = f'"{KB_RECORD}#/$defs/' in text
            if refs_sibling and not has_embedded:
                cross_file.append(path.name)
        self.assertEqual(
            ["experiment-result.schema.json", "fingerprint.schema.json",
             "instrument-run-manifest.schema.json", "reflection-record.schema.json"],
            sorted(cross_file))


class TestA07IsAccepted(SchemaContractTestCase):
    """plan.md 10.3 v2.4 through its own canonical example."""

    def test_a07_exact_shape_is_accepted(self):
        self.assert_accepted(
            a07(),
            message="This IS plan.md Appendix A row A-07: OBSERVED, class P, "
                    "oracle container-metadata, confidence 0.99, one source.")

    def test_a07_is_accepted_with_binary_analysis_too(self):
        self.assert_accepted(a07(oracle=["binary-analysis"]))

    def test_a07_is_accepted_with_a_hex_offset_and_an_rva(self):
        self.assert_accepted(a07(
            oracle=["binary-analysis"],
            read_locus={"address_kind": "rva", "offset": "0x1000", "length": 8}))

    def test_a07_without_an_explicit_class_label_is_accepted(self):
        """The exemption is keyed on the derived shape, not on the label."""
        self.assert_accepted(a07(claim_class=_ABSENT))

    def test_the_single_source_exemption_actually_reaches_a07(self):
        """The finding, isolated: it is the ONE source that used to fail.

        Two sources always validated, because then the EV-03 branch has
        nothing to say.  Asserting the accept above is only meaningful next to
        this: the same record with two sources passed even under the v2.2
        contract, so a green test on two sources would have proved nothing.
        """
        record = a07()
        self.assertEqual(1, len(record["sources"]))
        self.assert_accepted(record)

    def test_a_class_p_record_on_an_unconditional_oracle_is_accepted(self):
        self.assert_accepted(primitive_record())

    def test_every_unconditional_oracle_is_accepted_for_class_p(self):
        for oracle, claim_type in zip(
                CLASS_P_UNCONDITIONAL,
                ("file-exists", "steam-metadata-fact", "commit-content")):
            with self.subTest(oracle=oracle):
                extra = {"commit": "0eef371"} if oracle == "vcs-history" else {}
                self.assert_accepted(primitive_record(
                    oracle=[oracle], claim_type=claim_type, **extra))


class TestV23StaysDominant(SchemaContractTestCase):
    """plan.md 10.3 v2.3: the LEVEL decides, whatever the oracles are."""

    def test_a07_with_inferred_is_rejected(self):
        self.assert_rejected(
            a07(evidence_level="INFERRED"),
            message="plan.md 10.3 v2.3: INFERRED means a conclusion beyond "
                    "direct observation, so the record is class I and cannot "
                    "hold the class P label or take the single-source exemption.")

    def test_a07_with_hypothesis_is_rejected(self):
        self.assert_rejected(a07(evidence_level="HYPOTHESIS"))

    def test_a07_with_refuted_is_rejected(self):
        self.assert_rejected(a07(evidence_level="REFUTED",
                                 refuted_by=["E-3b"]))

    def test_a07_with_unknown_is_rejected(self):
        """UNKNOWN asserts nothing, so it is not a measurement either."""
        self.assert_rejected(a07(evidence_level="UNKNOWN", confidence=0.2))

    def test_no_oracle_set_rescues_an_inferred_class_p_label(self):
        """"whatever the oracles are" - so try all nine, one at a time."""
        for oracle in NINE_ORACLES:
            with self.subTest(oracle=oracle):
                self.assert_rejected(a07(evidence_level="INFERRED",
                                         oracle=[oracle]))

    def test_a_read_locus_does_not_rescue_an_inferred_class_p_label(self):
        """The v2.4 admission is additional to v2.3, never a way around it."""
        self.assert_rejected(a07(
            evidence_level="INFERRED",
            read_locus={"offset": 48, "length": 4, "bytes_hex": "a0 e4 0c 00"}))

    def test_the_inferred_class_i_half_of_a07_is_accepted(self):
        """The other half of the canonical pair must of course validate.

        plan.md grades it INFERRED, confidence 0.85, oracle
        container-metadata + external-doc, class I - and class I at 0.85 needs
        two sources, which is the rule, not a workaround.
        """
        self.assert_accepted({
            "id": "A-07-I",
            "claim": ("Это поле DirectoryIndexSize, его значение 844 960, и "
                      "контейнер зашифрован."),
            "claim_class": "I",
            "evidence_level": "INFERRED",
            "confidence": 0.85,
            "sources": ["I-02", "external-doc:FIoStoreTocHeader"],
            "oracle": ["container-metadata", "external-doc"],
            "build_key": BUILD_KEY,
            "recorded_at": "2026-08-22T12:19:17Z",
        })

    def test_an_inferred_record_is_fine_once_it_stops_claiming_class_p(self):
        """The rejection above is about the class, not about the level."""
        self.assert_accepted(a07(evidence_level="INFERRED",
                                 claim_class="I",
                                 sources=["I-02", "F-02"]))


class TestOracleVocabularyIsClosed(SchemaContractTestCase):
    """plan.md 10.5 v2.1: nine values, and the list is closed."""

    def test_the_vocabulary_is_exactly_the_nine(self):
        for name in SELF_CONTAINED:
            with self.subTest(schema=name):
                branches = _kb_record_of(name)["$defs"]["oracle"]["anyOf"]
                self.assertEqual(list(NINE_ORACLES),
                                 [branch["const"] for branch in branches])

    def test_an_oracle_outside_the_nine_is_rejected(self):
        """The draft spellings that actually appeared in this repository."""
        for invented in ("appmanifest", "git", "n/a", "utoc", "",
                         "Container-Metadata"):
            with self.subTest(oracle=invented):
                self.assert_rejected(a07(oracle=[invented]))

    def test_an_empty_oracle_list_is_rejected(self):
        self.assert_rejected(a07(oracle=[]))

    def test_a_record_with_no_oracle_at_all_is_rejected(self):
        self.assert_rejected(a07(oracle=_ABSENT))


class TestClassPOracleAdmission(SchemaContractTestCase):
    """plan.md 10.3 v2.4: which oracles can carry class P, and on what terms."""

    def test_the_four_semantic_oracles_are_never_class_p(self):
        for oracle in NEVER_CLASS_P:
            with self.subTest(oracle=oracle):
                self.assert_rejected(
                    a07(oracle=[oracle]),
                    message="plan.md 10.3 v2.4 admits a literal read at a "
                            "determinate place; this oracle cannot carry one.")

    def test_a_conditional_oracle_without_a_read_locus_loses_the_exemption(self):
        """Fails CLOSED, which is the direction the plan asks for.

        Without a stated offset the read is not reproducible as written, so
        class P is inadmissible - the record is class I, and class I at 0.99
        needs a second independent source.
        """
        for oracle in CLASS_P_CONDITIONAL:
            with self.subTest(oracle=oracle):
                self.assert_rejected(a07(oracle=[oracle], read_locus=_ABSENT))

    def test_the_same_record_validates_as_class_i_with_two_sources(self):
        """The remedy the schema leaves open, so the rejection is actionable."""
        for oracle in CLASS_P_CONDITIONAL:
            with self.subTest(oracle=oracle):
                self.assert_accepted(a07(oracle=[oracle],
                                         read_locus=_ABSENT,
                                         claim_class=_ABSENT,
                                         sources=["I-02", "F-02"]))

    def test_a_null_read_locus_does_not_satisfy_the_condition(self):
        """`null` spells "not a binary read at an address", not "trust me"."""
        self.assert_rejected(a07(read_locus=None))

    def test_a_read_locus_needs_both_the_address_and_the_extent(self):
        """plan.md 10.3 v2.4 requires BOTH, and they fail for different reasons."""
        for partial in ({"offset": 48}, {"length": 4}, {},
                        {"bytes_hex": "a0 e4 0c 00"}):
            with self.subTest(read_locus=partial):
                self.assert_rejected(a07(read_locus=partial))

    def test_a_read_locus_rejects_a_nonsensical_extent(self):
        for bad in ({"offset": 48, "length": 0},
                    {"offset": -1, "length": 4},
                    {"offset": 48, "length": "four"},
                    {"offset": "forty-eight", "length": 4}):
            with self.subTest(read_locus=bad):
                self.assert_rejected(a07(read_locus=bad))

    def test_a_read_locus_refuses_an_absolute_target_path(self):
        """C-13: no literal user-profile paths in a public repository."""
        for target in ("D:\\Games\\Steam\\steamapps\\common\\MISERY\\a.utoc",
                       "C:/Users/somebody/a.utoc",
                       "\\\\host\\share\\a.utoc",
                       "/home/somebody/a.utoc"):
            with self.subTest(target=target):
                self.assert_rejected(a07(read_locus={
                    "target": target, "offset": 48, "length": 4}))

    def test_a_read_locus_accepts_an_install_relative_target(self):
        self.assert_accepted(a07(read_locus={
            "target": "MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe",
            "offset": 60, "length": 4}))

    def test_an_unknown_read_locus_member_is_rejected(self):
        """additionalProperties: false, so a typo cannot pass for a locus."""
        self.assert_rejected(a07(read_locus={
            "offset": 48, "length": 4, "offsett": 52}))

    def test_read_locus_is_not_a_top_level_offset(self):
        """Why the fields are nested, pinned so a later edit cannot flatten them.

        tools/kb/validate.py LAYOUT_KEYS reads a TOP-LEVEL 'offset' or 'size'
        as a claim about memory layout, and rule EV-LAYOUT then caps it at
        HYPOTHESIS (plan.md 6.3).  claims_layout() inspects top-level keys
        only, so nesting the read locus keeps a container read from colliding
        with a rule written for property offsets.
        """
        for name in SELF_CONTAINED:
            with self.subTest(schema=name):
                envelope = _kb_record_of(name)["$defs"]["envelope"]["properties"]
                self.assertIn("read_locus", envelope)
                self.assertNotIn("offset", envelope)
                self.assertNotIn("length", envelope)


class TestConfidenceCeiling(SchemaContractTestCase):
    """plan.md 10.2 v2.3: the ceiling is a comparison, 0.00 <= c <= 0.99."""

    def test_099_is_accepted(self):
        self.assert_accepted(a07(confidence=0.99))

    def test_the_open_interval_below_one_is_rejected(self):
        for value in (0.995, 0.999, 0.9999):
            with self.subTest(confidence=value):
                self.assert_rejected(
                    a07(confidence=value),
                    message="plan.md 10.2 v2.3: a value in (0.99, 1.00) "
                            "expresses a precision the scale does not have and "
                            "is forbidden exactly as 1.00 is.")

    def test_one_is_rejected(self):
        self.assert_rejected(a07(confidence=1.0))

    def test_above_one_and_below_zero_are_rejected(self):
        for value in (1.01, 2, -0.01):
            with self.subTest(confidence=value):
                self.assert_rejected(a07(confidence=value))

    def test_zero_is_accepted(self):
        self.assert_accepted(a07(confidence=0))

    def test_the_bound_is_declared_in_every_self_contained_schema(self):
        """The previous pass was asked to fix this; here is where it is pinned.

        It DID land in all four - the check exists so it stays landed, and so
        that a bundle frozen one revision behind is caught here rather than by
        a consumer.
        """
        for name in SELF_CONTAINED:
            with self.subTest(schema=name):
                confidence = _kb_record_of(name)["$defs"]["confidence"]
                self.assertEqual(0.99, confidence["maximum"])
                self.assertEqual(0, confidence["minimum"])
                self.assertNotIn("exclusiveMaximum", confidence)

    def test_every_confidence_scale_in_the_tree_shares_the_ceiling(self):
        """Including the cross-file schemas, by reading the keyword directly."""
        found = 0
        for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
            document = json.loads(path.read_text(encoding="utf-8"))

            def walk(node, pointer):
                nonlocal found
                if isinstance(node, dict):
                    if node.get("title") == "Confidence":
                        found += 1
                        self.assertEqual(
                            0.99, node.get("maximum"),
                            f"{path.name}{pointer} declares another ceiling")
                    for key, value in node.items():
                        walk(value, f"{pointer}/{key}")
                elif isinstance(node, list):
                    for index, value in enumerate(node):
                        walk(value, f"{pointer}/{index}")

            walk(document, "")
        self.assertEqual(len(SELF_CONTAINED), found,
                         "expected exactly one confidence scale per self-contained "
                         "schema: one in kb-record.schema.json and one in each bundled "
                         "copy of it. A count that drifts from len(SELF_CONTAINED) means "
                         "either a bundle went missing from that tuple or some schema "
                         "grew a second, unbundled confidence scale of its own")


class TestTheBundlesAreNotFrozenBehind(SchemaContractTestCase):
    """A bundled copy one revision behind is a second, wrong contract."""

    def test_every_self_contained_schema_cites_v23_and_v24(self):
        for name in SELF_CONTAINED:
            with self.subTest(schema=name):
                text = (SCHEMA_DIR / name).read_text(encoding="utf-8")
                self.assertIn("v2.3", text)
                self.assertIn("v2.4", text)

    def test_no_schema_claims_a_revision_it_does_not_implement(self):
        """A citation of 10.3 v2.2 alone is now a false statement.

        v2.2 may still be NAMED - the history of the rule is worth keeping -
        but only where v2.3 or v2.4 is named in the same breath, otherwise the
        sentence tells a reader the file implements a superseded revision.
        """
        for name in SELF_CONTAINED:
            with self.subTest(schema=name):
                document = _load(name)
                stale = []

                def walk(node, pointer):
                    if isinstance(node, dict):
                        for key, value in node.items():
                            walk(value, f"{pointer}/{key}")
                    elif isinstance(node, list):
                        for index, value in enumerate(node):
                            walk(value, f"{pointer}/{index}")
                    elif isinstance(node, str) and "10.3 v2.2" in node:
                        if "v2.3" not in node and "v2.4" not in node:
                            stale.append(pointer)

                walk(document, "")
                self.assertEqual([], stale)

    def test_the_bundled_copy_matches_kb_record(self):
        """One deliberate deviation, and it must stay the only one.

        The bundled confidence $comment opens with a sentence saying the copy
        is bundled.  Everything else has to be identical, because a bundle is
        a copy and not a fork.
        """
        base = _load(KB_RECORD)
        for name in BUNDLES:
            with self.subTest(schema=name):
                copy = json.loads(json.dumps(_kb_record_of(name)))
                deviation = copy["$defs"]["confidence"]["$comment"]
                self.assertIn("This copy of the envelope is bundled", deviation)
                copy["$defs"]["confidence"]["$comment"] = \
                    base["$defs"]["confidence"]["$comment"]
                self.assertEqual(base, copy)

    def test_class_p_shape_admits_exactly_five_oracles(self):
        """Read out of the keyword, so the shape cannot drift from the prose."""
        for name in SELF_CONTAINED:
            with self.subTest(schema=name):
                shape = _kb_record_of(name)["$defs"]["class_p_shape"]
                admitted = None
                for branch in shape["allOf"]:
                    items = (branch.get("properties", {})
                                   .get("oracle", {})
                                   .get("items"))
                    if isinstance(items, dict) and "enum" in items:
                        admitted = items["enum"]
                self.assertEqual(
                    list(CLASS_P_UNCONDITIONAL) + list(CLASS_P_CONDITIONAL),
                    admitted)

    def test_class_p_shape_requires_observed(self):
        for name in SELF_CONTAINED:
            with self.subTest(schema=name):
                shape = _kb_record_of(name)["$defs"]["class_p_shape"]
                levels = [branch.get("properties", {})
                                .get("evidence_level", {})
                                .get("const")
                          for branch in shape["allOf"]]
                self.assertIn("OBSERVED", levels)


class TestTheReducedEnvelopeIsNotALoophole(SchemaContractTestCase):
    """$defs/annotation is the envelope minus bookkeeping, not minus rules."""

    def annotation_of(self, name):
        # $defs/annotation refs its siblings as "#/$defs/...", and a JSON pointer
        # starting at "#" resolves against the ROOT of the schema document.  Lifting
        # the definition out and handing the bare object to a validator makes the
        # fragment its own root, so every sibling ref becomes a PointerToNowhere.
        # Keep the surrounding $defs in scope and point at the definition instead.
        # Still a plain validator with no registry and no network: the whole thing
        # resolves inside one in-memory document, which is the property under test.
        root = _kb_record_of(name)
        return {"$defs": root["$defs"], "$ref": "#/$defs/annotation"}

    def assert_annotation(self, payload, *, accepted):
        for name in SELF_CONTAINED:
            with self.subTest(schema=name):
                errors = _errors(self.annotation_of(name), payload)
                if accepted:
                    self.assertEqual([], [error.message for error in errors])
                else:
                    self.assertNotEqual([], errors)

    def test_a_class_p_annotation_on_a_binary_read_is_accepted(self):
        self.assert_annotation({
            "evidence_level": "OBSERVED",
            "claim_class": "P",
            "confidence": 0.99,
            "sources": ["F-02"],
            "oracle": ["container-metadata"],
            "read_locus": {"offset": 48, "length": 4, "bytes_hex": "a0 e4 0c 00"},
        }, accepted=True)

    def test_a_class_p_annotation_without_a_read_locus_is_rejected(self):
        self.assert_annotation({
            "evidence_level": "OBSERVED",
            "claim_class": "P",
            "confidence": 0.99,
            "oracle": ["container-metadata"],
        }, accepted=False)

    def test_an_inferred_annotation_cannot_call_itself_class_p(self):
        self.assert_annotation({
            "evidence_level": "INFERRED",
            "claim_class": "P",
            "oracle": ["filesystem"],
        }, accepted=False)

    def test_an_inferred_annotation_is_fine_as_class_i(self):
        self.assert_annotation({
            "evidence_level": "INFERRED",
            "claim_class": "I",
            "confidence": 0.85,
            "oracle": ["container-metadata", "external-doc"],
        }, accepted=True)

    def test_an_annotation_still_needs_only_its_level(self):
        """The reduction itself is intact: nothing new became mandatory."""
        self.assert_annotation({"evidence_level": "OBSERVED"}, accepted=True)


class TestTheRealArtifactsStillValidate(SchemaContractTestCase):
    """The tree, offline, through the same plain validator."""

    CASES = (
        ("index.json", "build-index.schema.json"),
        ("install.json", "install.schema.json"),
        ("install-inventory.json", "install-inventory.schema.json"),
    )

    def artifacts(self):
        found = []
        for path in sorted(BUILDS_DIR.rglob("*.json")):
            for stem, schema in self.CASES:
                if path.name == stem:
                    found.append((path, schema))
        return found

    def test_the_build_directory_actually_holds_artifacts(self):
        """Guard against a green suite that validated nothing at all."""
        found = self.artifacts()
        self.assertNotEqual([], found, "research/builds/ holds no artifacts")
        self.assertGreaterEqual(len(found), 3)

    def test_every_artifact_validates_against_its_schema(self):
        from jsonschema import Draft202012Validator

        for path, schema in self.artifacts():
            with self.subTest(artifact=path.name, schema=schema):
                document = _load(schema)
                instance = json.loads(path.read_text(encoding="utf-8"))
                errors = sorted(
                    Draft202012Validator(document).iter_errors(instance),
                    key=lambda error: list(error.path))
                self.assertEqual(
                    [], [f"{list(error.path)}: {error.message}"
                         for error in errors],
                    f"{path.relative_to(REPO_ROOT)} no longer validates "
                    f"against {schema}")

    def test_the_artifacts_validate_with_no_registry_and_no_network(self):
        """Same check, stated as the property it is really about.

        install-inventory.schema.json $refs 'kb-record.schema.json#/$defs/...'
        and resolves it against its own relative $id, i.e. against the copy
        embedded in the same document.  If that ever regressed into a real
        cross-file or cross-host reference, a plain validator would raise
        Unretrievable here instead of returning errors.
        """
        from jsonschema import Draft202012Validator

        for path, schema in self.artifacts():
            with self.subTest(artifact=path.name):
                instance = json.loads(path.read_text(encoding="utf-8"))
                validator = Draft202012Validator(_load(schema))
                self.assertTrue(validator.is_valid(instance))


class TestTheBoundaryIsHonest(SchemaContractTestCase):
    """The schema must not claim to enforce what only the validator can."""

    def test_schema_is_not_the_stricter_gate(self):
        """A record the schema accepts and the validator refuses.

        The claim text names WHAT was read - 'поле DirectoryIndexSize' - which
        plan.md 10.3 v2.4 puts in class I however precise the offset is.  The
        schema cannot see that: read_locus is present and every keyword is
        satisfied, so it accepts.  tools/kb/validate.py reads the sentence and
        refuses.  This asymmetry is the design, and the test exists so nobody
        later reads a passing schema as a class-P certificate.
        """
        record = a07(claim=("Поле DirectoryIndexSize по смещению 48, четыре "
                            "байта, равно 844 960."))
        self.assert_accepted(record)

    def test_the_schema_says_where_the_boundary_is(self):
        """A rule left to another tool has to be written down as such.

        Not a style check: the defect this whole pass exists to close was a
        contract that ASSERTED a rule it did not enforce, and the remedy is a
        contract that says which half it enforces and which half it does not.
        """
        for name in SELF_CONTAINED:
            with self.subTest(schema=name):
                document = _kb_record_of(name)
                shape = json.dumps(document["$defs"]["class_p_shape"],
                                   ensure_ascii=False)
                locus = json.dumps(document["$defs"]["read_locus"],
                                   ensure_ascii=False)
                for needle in ("tools/kb/validate.py",
                               "states_determinate_address",
                               "names_what_the_bytes_are"):
                    self.assertIn(needle, shape + locus,
                                  f"{name} does not say that {needle} owns "
                                  "the prose half of the v2.4 condition")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
