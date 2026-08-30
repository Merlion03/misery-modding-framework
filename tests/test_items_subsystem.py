#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Items subsystem (Stage 2).

No game process is opened. The registry talks to a ``Materializer`` through a
three-method protocol, so all of the POLICY -- identity, namespacing, collision
arbitration, duplicate handling, ownership bookkeeping, unregister determinism
-- is testable with a recording double. That separation is the reason the
subsystem exists; if these tests needed MISERY running, the split would not be
real.

The fake materializer deliberately records what it was asked to do and can be
told to fail, because "the registry left itself unchanged when the game refused"
is exactly as important as "the registry updated when the game accepted".
"""
import os
import sys
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "items"))

import definition as D          # noqa: E402
import examples                 # noqa: E402
import registry as R            # noqa: E402


class FakeMaterializer(R.Materializer):
    """Records calls; can be told to fail, or to be unable to enumerate rows."""

    def __init__(self, existing=(), fail_materialize=False, fail_release=False,
                 rows_unknown=False):
        self.existing = set(existing)
        self.fail_materialize = fail_materialize
        self.fail_release = fail_release
        self.rows_unknown = rows_unknown
        self.materialized = []
        self.dematerialized = []
        self._next_handle = 1

    def existing_row_names(self):
        return None if self.rows_unknown else set(self.existing)

    def materialize(self, definition):
        self.materialized.append(definition.row_name)
        if self.fail_materialize:
            return {"ok": False, "detail": "the game refused the write"}
        handle = self._next_handle
        self._next_handle += 1
        self.existing.add(definition.row_name)
        return {"ok": True, "handle": handle,
                "content_handles": {r.object_path: handle for r in definition.content_refs()}}

    def dematerialize(self, registration):
        self.dematerialized.append(registration.definition.row_name)
        if self.fail_release:
            return {"ok": False, "detail": "could not release"}
        self.existing.discard(registration.definition.row_name)
        return {"ok": True, "released": len(registration.content_handles)}


# ---------------------------------------------------------------- identity
class Identity(unittest.TestCase):

    def test_row_name_is_derived_not_authored(self):
        self.assertEqual(D.ItemId("mbpl", "radio").row_name, "mbpl__radio")

    def test_separator_is_rejected_in_either_half(self):
        """Two different ItemIds must never derive one row name."""
        for mod_id, local_id in (("a__b", "c"), ("a", "b__c")):
            with self.assertRaises(D.DefinitionError) as cm:
                D.ItemId(mod_id, local_id)
            self.assertIn(cm.exception.code,
                          (D.ERR_INVALID_MOD_ID, D.ERR_INVALID_LOCAL_ID))

    def test_uppercase_is_rejected(self):
        """FName comparison is case-insensitive, so Radio and radio would
        collide in the game while looking distinct here."""
        with self.assertRaises(D.DefinitionError):
            D.ItemId("mbpl", "Radio")

    def test_reserved_namespaces(self):
        for reserved in ("misery", "sgk", "vanilla"):
            with self.assertRaises(D.DefinitionError) as cm:
                D.ItemId(reserved, "thing")
            self.assertEqual(cm.exception.code, D.ERR_RESERVED_NAMESPACE)

    def test_parse_returns_none_for_a_vanilla_name(self):
        """This is how the registry tells a row it could own from one that is
        not its to touch."""
        self.assertIsNone(D.ItemId.parse("Gas_Mask"))
        self.assertIsNone(D.ItemId.parse("bandage"))
        self.assertEqual(D.ItemId.parse("mbpl__radio"), D.ItemId("mbpl", "radio"))

    def test_two_mods_may_use_the_same_local_name(self):
        a = D.ItemId("mbpl", "radio")
        b = D.ItemId("othermod", "radio")
        self.assertNotEqual(a, b)
        self.assertNotEqual(a.row_name, b.row_name)


# ------------------------------------------------------------- definition
class Definition(unittest.TestCase):

    def test_a_valid_definition_is_fully_valid(self):
        d = examples.simple_item()
        self.assertEqual(d.row_name, "mbpl__simple_probe")
        self.assertEqual(d.effective_drag_icon(), d.inventory_icon)

    def test_zero_scale_is_refused(self):
        """A zeroed FTransform is the DEFAULT, so this is an easy mistake: the
        actor spawns correctly and is invisible. It cost a gate once."""
        with self.assertRaises(D.DefinitionError) as cm:
            D.Transform(scale=(0.0, 0.0, 0.0))
        self.assertEqual(cm.exception.code, D.ERR_FIELD_RANGE)

    def test_contradictory_stacking_is_refused(self):
        with self.assertRaises(D.DefinitionError) as cm:
            D.ItemDefinition(
                D.ItemId("mbpl", "x"), "N", "S", "D", weight=1, width=1, height=1,
                allow_stacking=False, max_stack=5,
                inventory_icon=D.AssetRef("/Game/a"), world_mesh=D.AssetRef("/Game/b"),
                world_class="C")
        self.assertEqual(cm.exception.field, "max_stack")

    def test_drag_icon_policy_must_state_intent(self):
        """Supplying a drag icon while leaving the policy on 'follow the
        inventory icon' is ambiguous, and is refused rather than guessed."""
        with self.assertRaises(D.DefinitionError) as cm:
            D.ItemDefinition(
                D.ItemId("mbpl", "x"), "N", "S", "D", weight=1, width=1, height=1,
                inventory_icon=D.AssetRef("/Game/a"), world_mesh=D.AssetRef("/Game/b"),
                world_class="C", drag_icon=D.AssetRef("/Game/c"))
        self.assertEqual(cm.exception.field, "drag_icon")

    def test_explicit_drag_icon_is_used(self):
        d = D.ItemDefinition(
            D.ItemId("mbpl", "x"), "N", "S", "D", weight=1, width=1, height=1,
            inventory_icon=D.AssetRef("/Game/a"), world_mesh=D.AssetRef("/Game/b"),
            world_class="C", drag_icon=D.AssetRef("/Game/c"),
            drag_icon_policy=D.DRAG_ICON_EXPLICIT)
        self.assertEqual(d.effective_drag_icon().package, "/Game/c")
        self.assertEqual(len(d.content_refs()), 3)

    def test_overlong_text_is_refused_not_truncated(self):
        with self.assertRaises(D.DefinitionError) as cm:
            D.ItemDefinition(
                D.ItemId("mbpl", "x"), "N" * 500, "S", "D", weight=1, width=1, height=1,
                inventory_icon=D.AssetRef("/Game/a"), world_mesh=D.AssetRef("/Game/b"),
                world_class="C")
        self.assertEqual(cm.exception.code, D.ERR_TEXT_TOO_LONG)

    def test_errors_are_structured(self):
        try:
            D.ItemId("mbpl", "Radio")
        except D.DefinitionError as exc:
            self.assertIn("code", exc.as_dict())
            self.assertIn("field", exc.as_dict())
        else:
            self.fail("expected DefinitionError")


# --------------------------------------------------------------- registry
class RegisterFindUnregister(unittest.TestCase):

    def setUp(self):
        self.fake = FakeMaterializer(existing={"Gas_Mask", "bandage"})
        self.reg = R.Registry(self.fake)

    def test_register_then_find(self):
        d = examples.production_radio()
        result = self.reg.register(d)
        self.assertTrue(result.ok, result.detail)
        self.assertIs(self.reg.find(d.item_id), d)
        self.assertIs(self.reg.find("mbpl__radio"), d)
        self.assertIsNone(self.reg.find("mbpl__nope"))

    def test_duplicate_registration_is_refused_not_replaced(self):
        """Replacing would orphan the first registration's owned content and
        leave the game holding a row nobody claims."""
        self.reg.register(examples.production_radio())
        again = self.reg.register(examples.negative_same_mod_collision())
        self.assertFalse(again.ok)
        self.assertEqual(again.code, R.ERR_ALREADY_REGISTERED)
        # the original is untouched
        self.assertEqual(self.reg.find("mbpl__radio").weight, 0.5)

    def test_collision_with_vanilla_is_rejected_never_shadowed(self):
        self.fake.existing.add("mbpl__radio")
        result = self.reg.register(examples.production_radio())
        self.assertFalse(result.ok)
        self.assertEqual(result.code, R.ERR_COLLIDES_WITH_MOD)

    def test_a_bare_vanilla_collision_reports_as_vanilla(self):
        fake = FakeMaterializer(existing={"Gas_Mask"})
        reg = R.Registry(fake)

        class Sneaky(D.ItemDefinition):
            @property
            def row_name(self):
                return "Gas_Mask"

        d = Sneaky(D.ItemId("mbpl", "x"), "N", "S", "D", weight=1, width=1, height=1,
                   inventory_icon=D.AssetRef("/Game/a"), world_mesh=D.AssetRef("/Game/b"),
                   world_class="C")
        result = reg.register(d)
        self.assertEqual(result.code, R.ERR_COLLIDES_WITH_VANILLA)

    def test_two_mods_with_the_same_local_name_both_register(self):
        """Namespacing must make this NOT a collision."""
        self.assertTrue(self.reg.register(examples.production_radio()).ok)
        self.assertTrue(self.reg.register(examples.colliding_item()).ok)
        self.assertEqual(sorted(self.reg.registrations()),
                         ["mbpl__radio", "othermod__radio"])

    def test_unknown_existing_rows_refuses_rather_than_risking_overwrite(self):
        fake = FakeMaterializer(rows_unknown=True)
        result = R.Registry(fake).register(examples.simple_item())
        self.assertEqual(result.code, R.ERR_BACKEND_UNAVAILABLE)
        self.assertEqual(fake.materialized, [], "must not write when it cannot check")

    def test_a_failed_materialize_leaves_the_registry_unchanged(self):
        fake = FakeMaterializer(fail_materialize=True)
        reg = R.Registry(fake)
        result = reg.register(examples.simple_item())
        self.assertEqual(result.code, R.ERR_MATERIALIZE_FAILED)
        self.assertEqual(reg.registrations(), {})
        self.assertIsNone(reg.find("mbpl__simple_probe"))

    def test_unregister_releases_and_forgets(self):
        d = examples.production_radio()
        self.reg.register(d)
        result = self.reg.unregister(d.item_id)
        self.assertTrue(result.ok, result.detail)
        self.assertIsNone(self.reg.find(d.item_id))
        self.assertEqual(self.fake.dematerialized, ["mbpl__radio"])

    def test_unregister_of_something_not_registered_is_reported_not_silent(self):
        result = self.reg.unregister(D.ItemId("mbpl", "ghost"))
        self.assertFalse(result.ok)
        self.assertEqual(result.code, R.ERR_NOT_REGISTERED)

    def test_unregister_twice_reports_the_second_time(self):
        d = examples.simple_item()
        self.reg.register(d)
        self.assertTrue(self.reg.unregister(d.item_id).ok)
        self.assertEqual(self.reg.unregister(d.item_id).code, R.ERR_NOT_REGISTERED)

    def test_a_failed_release_KEEPS_the_registration(self):
        """Dropping it would leave the game holding a row and rooted content
        that nothing claims -- an unreachable leak instead of a reported error."""
        fake = FakeMaterializer(fail_release=True)
        reg = R.Registry(fake)
        d = examples.simple_item()
        reg.register(d)
        result = reg.unregister(d.item_id)
        self.assertEqual(result.code, R.ERR_RELEASE_FAILED)
        self.assertTrue(result.data["registration_kept"])
        self.assertIsNotNone(reg.find(d.item_id))

    def test_unregister_all_is_deterministic_and_scoped(self):
        self.reg.register(examples.production_radio())
        self.reg.register(examples.simple_item())
        self.reg.register(examples.colliding_item())
        results = self.reg.unregister_all(mod_id="mbpl")
        self.assertTrue(all(r.ok for r in results))
        self.assertEqual(self.fake.dematerialized, ["mbpl__radio", "mbpl__simple_probe"])
        self.assertEqual(sorted(self.reg.registrations()), ["othermod__radio"])

    def test_ownership_is_recorded_per_registration(self):
        d = examples.production_radio()
        self.reg.register(d)
        entry = self.reg.registrations()["mbpl__radio"]
        self.assertEqual(sorted(entry["content_handles"]),
                         sorted(r.object_path for r in d.content_refs()))

    def test_results_are_structured(self):
        result = self.reg.register("not a definition")
        self.assertEqual(result.code, R.ERR_INVALID_DEFINITION)
        self.assertFalse(result)
        self.assertIn("code", result.as_dict())


# ------------------------------------------------- no radio in the core
class NoRadioSpecialCase(unittest.TestCase):

    def test_the_core_has_no_item_specific_BEHAVIOUR(self):
        """The claim is about behaviour, so this inspects CODE, not prose.

        A first version of this test grepped the raw file and failed on the
        registry's own docstring, which says "there is nothing radio-specific in
        this file". That sentence is documentation, not a special case, and a
        test that cannot tell the difference would push the next person to
        delete the explanation rather than the coupling.

        So the source is parsed, docstrings are discarded, and what remains --
        every identifier and every string literal that actually executes -- is
        searched for any knowledge of a particular item.
        """
        import ast as _ast
        core = os.path.join(REPO, "research", "instruments", "items")
        banned = ("radio", "mbpl", "sm_mbpl", "t_mbpl", "staticmasteritem")
        for name in ("definition.py", "registry.py"):
            with open(os.path.join(core, name), encoding="utf-8") as f:
                tree = _ast.parse(f.read())
            docstrings = set()
            for node in _ast.walk(tree):
                if isinstance(node, (_ast.Module, _ast.ClassDef, _ast.FunctionDef,
                                     _ast.AsyncFunctionDef)):
                    doc = _ast.get_docstring(node, clean=False)
                    if doc is not None:
                        docstrings.add(doc)
            live = []
            for node in _ast.walk(tree):
                if isinstance(node, _ast.Constant) and isinstance(node.value, str):
                    if node.value not in docstrings:
                        live.append(node.value)
                elif isinstance(node, _ast.Name):
                    live.append(node.id)
                elif isinstance(node, _ast.Attribute):
                    live.append(node.attr)
                elif isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef,
                                       _ast.ClassDef)):
                    live.append(node.name)
            blob = " ".join(live).lower()
            for word in banned:
                self.assertNotIn(
                    word, blob,
                    "%s has executable code mentioning %r; the core must not know about "
                    "any particular item" % (name, word))

    def test_the_radio_definition_reproduces_the_proven_run(self):
        """If the definition layer cannot express the values that actually
        passed acceptance, 'the radio is just a definition' is not yet true."""
        ok, differences = examples.radio_matches_proven_controller()
        self.assertTrue(ok, "definition differs from the proven controller: %r" % differences)

    def test_all_examples_go_through_the_same_constructor(self):
        for name, factory in examples.ALL_EXAMPLES.items():
            self.assertIsInstance(factory(), D.ItemDefinition, name)


if __name__ == "__main__":
    unittest.main()
