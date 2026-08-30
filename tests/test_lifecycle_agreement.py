#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the lifecycle resolver's agreement rule (M4).

WHY THIS FILE EXISTS
--------------------
An adversarial reviewer pointed out that across the entire M4 evidence corpus,
the resolver's central promise -- "refuses rather than guessing when the routes
disagree" -- is never actually demonstrated. Every recorded observation is of a
settled state, and the only refusals on record are of the "all routes read null"
kind. Two routes returning two DIFFERENT non-null pointers, and the resolver
declining to pick one, has never been observed live, because that happens only
inside a world transition and a graph walk takes about ten seconds.

That reviewer was right, and "it is obvious from the code" is not evidence. So
the rule is exercised here directly, with no game running: `_agree` is a pure
function over route answers, which makes it exactly the piece that can be
tested rather than asserted.

The cases below are the ones that mattered in practice, not a shotgun:

  * the DEATH SCREEN case that started all of this -- one route readable and
    null, the other naming the corpse. The pre-fix code filtered the null out
    and let the survivor agree with itself.
  * the LoadMap case the red team found -- GameViewportClient::World reads a
    genuine null while other routes still name the old world.
  * an unreadable route, which must NOT be confused with a route that read null.
  * two different non-null pointers: the promise itself.

Standard library only. No game process is opened.
"""
import os
import sys
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "lifecycle"))


def _agree():
    """Import lazily so a missing optional dependency fails one test, not all."""
    import resolver
    return resolver._agree


READ_OK = lambda name, value: ({"resolved": True, "property": name}, value)   # noqa: E731
UNREADABLE = lambda name: ({"resolved": False, "property": name,             # noqa: E731
                            "why": "not declared on this class"}, None)


class AgreementRule(unittest.TestCase):
    def test_two_routes_naming_the_same_object_agree(self):
        value, agreed, why = _agree()(
            [READ_OK("AController::Pawn", 0x1000),
             READ_OK("APlayerController::AcknowledgedPawn", 0x1000)], "the Pawn")
        self.assertTrue(agreed)
        self.assertEqual(value, 0x1000)
        self.assertIsNone(why)

    def test_death_screen_null_versus_corpse_is_a_disagreement(self):
        """The case that exposed the bug: Pawn null, AcknowledgedPawn still set.

        The pre-fix code dropped the null and let the lone survivor agree with
        itself, reporting a possessed pawn for a controller that had already
        un-possessed it.
        """
        value, agreed, why = _agree()(
            [READ_OK("AController::Pawn", None),
             READ_OK("APlayerController::AcknowledgedPawn", 0x2000)], "the Pawn")
        self.assertFalse(agreed, "a readable null must not be filtered away")
        self.assertIsNone(value)
        self.assertIn("disagree", why)
        self.assertIn("null", why)

    def test_loadmap_window_viewport_null_versus_stale_world(self):
        """UEngine::LoadMap nulls GameViewportClient::World at UnrealEngine.cpp:15183
        while the old world is still named by the searches. The resolver must
        refuse, not return the world the engine has already let go of."""
        value, agreed, why = _agree()(
            [READ_OK("GameViewportClient::World", None),
             READ_OK("ULevel::OwningWorld", 0xDEAD),
             READ_OK("the unique world owning a GameInstance", 0xDEAD)], "the active World")
        self.assertFalse(agreed)
        self.assertIsNone(value)

    def test_two_different_pointers_refuse(self):
        """The promise in the module docstring, exercised directly."""
        value, agreed, why = _agree()(
            [READ_OK("GameViewportClient::World", 0xAAAA),
             READ_OK("ULevel::OwningWorld", 0xBBBB)], "the active World")
        self.assertFalse(agreed)
        self.assertIsNone(value)
        self.assertIn("disagree", why)
        self.assertIn("refusing to pick one", why)

    def test_an_unreadable_route_is_not_an_answer(self):
        """A route that could not be read must abstain -- it must not be treated
        as having answered null, which would manufacture a disagreement."""
        value, agreed, why = _agree()(
            [UNREADABLE("GameViewportClient::World"),
             READ_OK("ULevel::OwningWorld", 0xCAFE)], "the active World")
        self.assertTrue(agreed, "an unreadable route must abstain, not disagree")
        self.assertEqual(value, 0xCAFE)

    def test_no_readable_route_at_all(self):
        value, agreed, why = _agree()(
            [UNREADABLE("a"), UNREADABLE("b")], "the active World")
        self.assertFalse(agreed)
        self.assertIn("no route", why)

    def test_every_readable_route_returned_null(self):
        """The death screen once both routes have gone null. Distinct message,
        because 'nobody could read it' and 'everybody read null' are different
        facts about the game and should not share a diagnosis."""
        value, agreed, why = _agree()(
            [READ_OK("AController::Pawn", None),
             READ_OK("APlayerController::AcknowledgedPawn", None)], "the possessed Pawn")
        self.assertFalse(agreed)
        self.assertIn("every route that could be read returned null", why)

    def test_a_single_readable_route_does_not_prove_agreement(self):
        """One route is still allowed to decide -- but the caller is the one that
        must add a second, and this test pins the behaviour so a future change
        cannot quietly turn one route into 'agreement' for a new anchor."""
        value, agreed, _why = _agree()([READ_OK("only", 0x99)], "x")
        self.assertTrue(agreed)
        self.assertEqual(value, 0x99)

    def test_empty_answer_list(self):
        value, agreed, why = _agree()([], "x")
        self.assertFalse(agreed)
        self.assertIsNone(value)


if __name__ == "__main__":
    unittest.main()
