#!/usr/bin/env python3
"""Stage 4.5: the core mod platform, tested with no game attached.

The tests that matter most here are the lifecycle ones. "No callback may target
unloaded mod code" is easy to satisfy in the quiet case and hard in exactly four
situations, each of which has a test below by name:

    * a mod unloaded HALFWAY THROUGH a dispatch whose handler list was captured
      before the unload started
    * a mod that unloads itself from inside its own handler
    * an event raised while a mod is being torn down
    * a service handle a consumer captured and kept past its provider's unload

If the guarantee is real, all four are boring. That is the point of writing them.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (os.path.join(REPO, "tools", "modplatform"),
           os.path.join(REPO, "tools", "modkit"),
           os.path.join(REPO, "tools", "modframework"),
           os.path.join(REPO, "research", "instruments", "items")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import capabilities as CAP                                         # noqa: E402
import console as CONSOLE                                          # noqa: E402
import errors as E                                                 # noqa: E402
import events as EV                                                # noqa: E402
import host as HOST                                                # noqa: E402
import input_actions                                               # noqa: E402
import modid                                                       # noqa: E402
import modlog                                                      # noqa: E402
import ownership                                                   # noqa: E402
import semverlib                                                   # noqa: E402

ALL_CAPS = sorted(CAP.CAPABILITIES)


class PlatformCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="modplatform-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.platform = HOST.Platform(self.root)

    def plan(self, *mod_ids):
        self.platform.declare_plan(list(mod_ids))

    def load(self, mod_id, entry=None, **kwargs):
        kwargs.setdefault("required", ALL_CAPS)
        return self.platform.load(mod_id, entry, **kwargs)


# ---------------------------------------------------------------- ModId ----

class CanonicalModIdTests(unittest.TestCase):
    """One rule, and it must stay at least as strict as every consumer's."""

    def test_the_known_divergence_is_now_refused_everywhere(self):
        import definition as stage2                                # noqa: PLC0415
        import namespace as stage3                                 # noqa: PLC0415
        self.assertFalse(modid.is_valid("has__separator"))
        with self.assertRaises(Exception):
            stage3.check_mod_id("has__separator")
        with self.assertRaises(Exception):
            stage2.ItemId("has__separator", "x")

    def test_every_stage_now_reads_the_canonical_constants(self):
        import definition as stage2                                # noqa: PLC0415
        import namespace as stage3                                 # noqa: PLC0415
        self.assertIs(stage3.RESERVED_MOD_IDS, modid.RESERVED)
        self.assertIs(stage2.RESERVED_MOD_IDS, modid.RESERVED)
        self.assertIs(stage3.MOD_ID_PATTERN, modid.PATTERN)
        self.assertIs(stage2.ID_PATTERN, modid.PATTERN)
        self.assertEqual(stage2.SEPARATOR, modid.SEPARATOR)

    def test_the_reserved_set_did_not_lose_anything_it_used_to_hold(self):
        # Consolidating is only safe if it is a SUPERSET of the sets it
        # replaced. A first draft ALSO added the framework's own vocabulary and
        # reserved "mbpl" -- the id the proven production radio actually uses.
        previously_reserved = {"misery", "sgk", "engine", "core", "game",
                               "vanilla", "mods", "temp", "script"}
        self.assertTrue(previously_reserved <= modid.RESERVED)

    def test_ids_in_active_use_are_still_valid(self):
        for mod_id in ("mbpl", "alphamod", "betamod", "othermod"):
            self.assertTrue(modid.is_valid(mod_id), mod_id)

    def test_row_names_round_trip_unambiguously(self):
        name = modid.row_name("alphamod", "shape")
        self.assertEqual("alphamod__shape", name)
        self.assertEqual(("alphamod", "shape"), modid.split_row_name(name))

    def test_a_vanilla_row_name_is_not_ours(self):
        self.assertIsNone(modid.split_row_name("BuildPart_Bookcase"))

    def test_local_ids_are_not_subject_to_the_reserved_rule(self):
        # "core" as a LOCAL id impersonates nothing: the row is alphamod__core.
        self.assertEqual("core", modid.check_local_id("core"))
        self.assertFalse(modid.is_valid("core"))

    def test_errors_name_which_rule_refused(self):
        cases = {"": modid.ERR_EMPTY, "Nope": modid.ERR_SYNTAX,
                 "a__b": modid.ERR_SEPARATOR, "misery": modid.ERR_RESERVED,
                 "x" * 60: modid.ERR_TOO_LONG, 5: modid.ERR_NOT_A_STRING}
        for value, expected in cases.items():
            with self.assertRaises(modid.ModIdError) as caught:
                modid.check(value)
            self.assertEqual(expected, caught.exception.code, repr(value))


# ------------------------------------------------------------ ownership ----

class OwnershipTests(unittest.TestCase):
    def test_resources_release_in_reverse_acquisition_order(self):
        """A later resource may depend on an earlier one."""
        owner = ownership.Owner("alphamod")
        order = []
        for name in ("first", "second", "third"):
            owner.own("thing", name, lambda n=name: order.append(n))
        owner.dispose()
        self.assertEqual(["third", "second", "first"], order)

    def test_release_is_idempotent(self):
        owner = ownership.Owner("alphamod")
        calls = []
        resource = owner.own("thing", "a", lambda: calls.append(1))
        self.assertTrue(resource.release())
        self.assertFalse(resource.release())
        owner.dispose()
        self.assertEqual([1], calls)

    def test_one_resource_that_will_not_release_does_not_strand_the_rest(self):
        owner = ownership.Owner("alphamod")
        released = []
        owner.own("thing", "ok1", lambda: released.append("ok1"))
        owner.own("thing", "bad", lambda: (_ for _ in ()).throw(RuntimeError("no")))
        owner.own("thing", "ok2", lambda: released.append("ok2"))
        report = owner.dispose()
        self.assertEqual(["ok2", "ok1"], released)
        self.assertEqual(1, len(report["faults"]))

    def test_acquiring_after_dispose_is_refused(self):
        owner = ownership.Owner("alphamod")
        owner.dispose()
        with self.assertRaises(E.PlatformError) as caught:
            owner.own("thing", "late", lambda: None)
        self.assertEqual(E.E_OWNER_DISPOSED, caught.exception.code)

    def test_disposing_twice_is_refused_rather_than_silently_repeated(self):
        owner = ownership.Owner("alphamod")
        owner.dispose()
        with self.assertRaises(E.PlatformError) as caught:
            owner.dispose()
        self.assertEqual(E.E_REENTRANT_UNLOAD, caught.exception.code)

    def test_a_token_checks_liveness_at_call_time_not_capture_time(self):
        owner = ownership.Owner("alphamod")
        calls = []
        token = owner.token(lambda: calls.append(1), "cb", "k")
        captured = [token]                       # captured while live
        owner.dispose()                          # revoked afterwards
        for entry in captured:
            entry.invoke()
        self.assertEqual([], calls)

    def test_dispose_revokes_before_releasing(self):
        """Anything a release function does can no longer reach mod code."""
        owner = ownership.Owner("alphamod")
        calls = []
        token = owner.token(lambda: calls.append("handler"), "cb", "k")
        owner.own("thing", "a", lambda: token.invoke())
        owner.dispose()
        self.assertEqual([], calls)


# --------------------------------------------------------------- events ----

class EventTests(PlatformCase):
    def test_a_mod_cannot_declare_an_event_in_another_namespace(self):
        self.plan("alphamod")
        problems = []

        def entry(ctx):
            try:
                ctx.events.declare("betamod:sneaky")
            except E.PlatformError as error:
                problems.append(error)
        self.load("alphamod", entry)
        self.assertEqual(1, len(problems))
        self.assertEqual(E.SUB_EVENTS, problems[0].subsystem)

    def test_subscribing_to_an_undeclared_event_is_refused(self):
        self.plan("alphamod")
        problems = []

        def entry(ctx):
            try:
                ctx.events.subscribe("alphamod:typo", lambda p: None)
            except E.PlatformError as error:
                problems.append(error)
        self.load("alphamod", entry)
        self.assertEqual(E.E_NOT_FOUND, problems[0].code)

    def test_a_faulting_handler_does_not_stop_the_others(self):
        self.plan("alphamod", "betamod")
        seen = []
        self.load("alphamod", lambda ctx: ctx.events.subscribe(
            EV.EVENT_MOD_LOADED, lambda p: (_ for _ in ()).throw(RuntimeError("x"))))
        self.load("betamod", lambda ctx: ctx.events.subscribe(
            EV.EVENT_MOD_LOADED, lambda p: seen.append(p)))
        result = self.platform.events.publish_guarded(EV.EVENT_MOD_LOADED, {})
        self.assertEqual(1, result["ran"])
        self.assertEqual(1, len(result["faults"]))
        self.assertEqual("alphamod", result["faults"][0]["mod_id"])

    def test_UNLOAD_MIDWAY_THROUGH_A_DISPATCH(self):
        """The list was captured before the unload. The rest must still be safe."""
        self.plan("alphamod", "betamod")
        calls = []
        self.load("alphamod", lambda ctx: ctx.events.subscribe(
            EV.EVENT_MOD_LOADED, lambda p: (calls.append("alpha"),
                                            self.platform.unload("betamod"))))
        self.load("betamod", lambda ctx: ctx.events.subscribe(
            EV.EVENT_MOD_LOADED, lambda p: calls.append("beta")))
        self.platform.events.publish_guarded(EV.EVENT_MOD_LOADED, {})
        self.assertIn("alpha", calls)
        self.assertNotIn("beta", calls,
                         "a handler ran for a mod unloaded earlier in the "
                         "same dispatch")

    def test_A_MOD_UNLOADING_ITSELF_FROM_ITS_OWN_HANDLER(self):
        self.plan("alphamod")
        outcome = {}

        def handler(_payload):
            try:
                self.platform.unload("alphamod")
                outcome["result"] = "unloaded"
            except E.PlatformError as error:
                outcome["error"] = error
        self.load("alphamod", lambda ctx: ctx.events.subscribe(
            EV.EVENT_MOD_UNLOADING, handler))
        self.platform.unload("alphamod")
        # The nested attempt is refused; the outer unload still completes.
        self.assertEqual(E.E_REENTRANT_UNLOAD, outcome["error"].code)
        self.assertEqual(HOST.UNLOADED, self.platform.state_of("alphamod"))

    def test_AN_EVENT_RAISED_WHILE_A_MOD_IS_TORN_DOWN(self):
        self.plan("alphamod", "betamod")
        calls = []

        def alpha(ctx):
            ctx.events.subscribe(EV.EVENT_MOD_UNLOADED,
                                 lambda p: calls.append(("alpha", p)))
            # Releasing this raises an event while alpha itself is disposing.
            ctx._owner.own("thing", "noisy", lambda: self.platform.events
                           .publish_guarded(EV.EVENT_MOD_UNLOADED,
                                            {"mod_id": "during-teardown"}))
        self.load("alphamod", alpha)
        self.load("betamod", lambda ctx: ctx.events.subscribe(
            EV.EVENT_MOD_UNLOADED, lambda p: calls.append(("beta", p))))
        self.platform.unload("alphamod")
        # Alpha's own handler must never fire once its teardown has begun.
        self.assertEqual([], [c for c in calls if c[0] == "alpha"])
        self.assertTrue([c for c in calls if c[0] == "beta"])

    def test_dispatch_depth_is_bounded(self):
        self.plan("alphamod")

        def entry(ctx):
            ctx.events.declare("alphamod:loop")
            ctx.events.subscribe(
                "alphamod:loop",
                lambda p: self.platform.events.publish("alphamod:loop", p))
        self.load("alphamod", entry)
        result = self.platform.events.publish_guarded("alphamod:loop", {})
        self.assertTrue(result["faults"], "unbounded recursion was not stopped")

    def test_subscribing_during_a_dispatch_takes_effect_next_time(self):
        self.plan("alphamod")
        calls = []

        def entry(ctx):
            ctx.events.declare("alphamod:tick")

            def late(_p):
                calls.append("late")

            def first(_p):
                calls.append("first")
                if len(calls) == 1:
                    ctx.events.subscribe("alphamod:tick", late)
            ctx.events.subscribe("alphamod:tick", first)
        self.load("alphamod", entry)
        self.platform.events.publish("alphamod:tick")
        self.assertEqual(["first"], calls)
        self.platform.events.publish("alphamod:tick")
        self.assertEqual(["first", "first", "late"], calls)


# ------------------------------------------------------------- services ----

class ServiceTests(PlatformCase):
    def _publish(self):
        self.plan("alphamod", "betamod")
        self.load("alphamod", lambda ctx: ctx.services.publish(
            "alphamod:math", "1.2.0", {"add": lambda a, b: a + b}))

    def test_a_consumer_can_call_a_published_service(self):
        self._publish()
        holder = {}
        self.load("betamod", lambda ctx: holder.setdefault(
            "h", ctx.services.bind("alphamod:math", "^1.0.0")))
        self.assertEqual(5, holder["h"].call("add", 2, 3))

    def test_A_HANDLE_HELD_PAST_ITS_PROVIDERS_UNLOAD_STOPS_WORKING(self):
        self._publish()
        holder = {}
        self.load("betamod", lambda ctx: holder.setdefault(
            "h", ctx.services.bind("alphamod:math", "^1.0.0")))
        self.platform.unload("alphamod")
        self.assertFalse(holder["h"].available)
        with self.assertRaises(E.PlatformError) as caught:
            holder["h"].call("add", 1, 1)
        self.assertEqual(E.SUB_SERVICES, caught.exception.subsystem)

    def test_an_incompatible_version_is_refused_at_bind_not_at_call(self):
        self._publish()
        problems = []

        def beta(ctx):
            try:
                ctx.services.bind("alphamod:math", "^2.0.0")
            except E.PlatformError as error:
                problems.append(error)
        self.load("betamod", beta)
        self.assertEqual(E.E_INVALID_ARGUMENT, problems[0].code)

    def test_a_mod_cannot_publish_in_another_namespace(self):
        self.plan("alphamod")
        problems = []

        def entry(ctx):
            try:
                ctx.services.publish("betamod:math", "1.0.0", {"add": lambda: 1})
            except E.PlatformError as error:
                problems.append(error)
        self.load("alphamod", entry)
        self.assertTrue(problems)


# ------------------------------------------------------------- settings ----

class SettingsTests(PlatformCase):
    SCHEMA = [{"key": "enabled", "type": "bool", "default": True,
               "description": "on"},
              {"key": "threshold", "type": "float", "default": 0.5,
               "description": "t"}]

    def test_declared_settings_round_trip_through_disk(self):
        self.plan("alphamod")
        self.load("alphamod", lambda ctx: ctx.settings.declare(self.SCHEMA))
        self.platform.settings.set("alphamod", "threshold", 0.9)
        written = self.platform.settings.save("alphamod")
        self.assertEqual(1, len(written))
        with open(written[0], encoding="utf-8") as handle:
            self.assertEqual(0.9, json.load(handle)["threshold"])

    def test_an_undeclared_key_is_refused_not_defaulted(self):
        self.plan("alphamod")
        self.load("alphamod", lambda ctx: ctx.settings.declare(self.SCHEMA))
        with self.assertRaises(E.PlatformError) as caught:
            self.platform.settings.get("alphamod", "thresold")   # typo
        self.assertEqual(E.E_NOT_FOUND, caught.exception.code)

    def test_a_wrong_type_is_refused(self):
        self.plan("alphamod")
        self.load("alphamod", lambda ctx: ctx.settings.declare(self.SCHEMA))
        with self.assertRaises(E.PlatformError):
            self.platform.settings.set("alphamod", "enabled", "yes")

    def test_a_bool_does_not_satisfy_an_int_setting(self):
        self.plan("alphamod")
        self.load("alphamod", lambda ctx: ctx.settings.declare(
            [{"key": "count", "type": "int", "default": 1, "description": ""}]))
        with self.assertRaises(E.PlatformError):
            self.platform.settings.set("alphamod", "count", True)

    def test_a_stored_value_that_no_longer_fits_falls_back_and_is_reported(self):
        path = os.path.join(self.root, "alphamod.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"threshold": "not a number"}, handle)
        self.plan("alphamod")
        self.load("alphamod", lambda ctx: ctx.settings.declare(self.SCHEMA))
        self.assertEqual(0.5, self.platform.settings.get("alphamod", "threshold"))
        self.assertTrue(self.platform.settings.substitutions)

    def test_a_key_the_mod_no_longer_declares_survives_on_disk(self):
        path = os.path.join(self.root, "alphamod.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"old_key": 7, "threshold": 0.25}, handle)
        self.plan("alphamod")
        self.load("alphamod", lambda ctx: ctx.settings.declare(self.SCHEMA))
        self.platform.settings.set("alphamod", "threshold", 0.75)
        self.platform.settings.save("alphamod")
        with open(path, encoding="utf-8") as handle:
            stored = json.load(handle)
        self.assertEqual(7, stored["old_key"])


# ---------------------------------------------------------------- input ----

class InputTests(PlatformCase):
    def test_actions_are_owned_and_released(self):
        self.plan("alphamod")
        self.load("alphamod", lambda ctx: ctx.input.register(
            "alphamod:toggle", "Toggle", "F5"))
        self.assertEqual(1, len(self.platform.input.actions()))
        self.platform.unload("alphamod")
        self.assertEqual([], self.platform.input.actions())

    def test_a_handler_stops_firing_once_its_mod_unloads(self):
        self.plan("alphamod")
        calls = []
        self.load("alphamod", lambda ctx: ctx.input.register(
            "alphamod:toggle", "Toggle", None,
            lambda name, phase: calls.append(name)))
        self.platform.input.deliver("alphamod:toggle", input_actions.PHASE_PRESSED)
        self.assertEqual(1, len(calls))
        self.platform.unload("alphamod")
        with self.assertRaises(E.PlatformError):
            self.platform.input.deliver("alphamod:toggle",
                                        input_actions.PHASE_PRESSED)
        self.assertEqual(1, len(calls))

    def test_the_registry_says_plainly_that_engine_input_is_not_wired(self):
        # If this ever becomes True, it must be because the engine input path
        # was researched and wired -- not because someone made the flag nicer.
        self.assertFalse(self.platform.input.summary()["engine_input_wired"])
        self.assertIn("unresearched", self.platform.input.summary()["note"])


# --------------------------------------------------------- capabilities ----

class CapabilityTests(PlatformCase):
    def test_a_missing_required_capability_refuses_the_load(self):
        self.plan("alphamod")
        with self.assertRaises(E.PlatformError) as caught:
            self.platform.load("alphamod", None, required=["core.nonexistent"])
        self.assertEqual(E.E_CAPABILITY_NOT_GRANTED, caught.exception.code)
        self.assertEqual(HOST.FAILED, self.platform.state_of("alphamod"))

    def test_a_missing_optional_capability_is_not_fatal(self):
        self.plan("alphamod")
        context = self.platform.load("alphamod", None, required=["core.log"],
                                     optional=["core.nonexistent"])
        self.assertFalse(context.grant.has("core.nonexistent"))
        self.assertEqual(HOST.LOADED, self.platform.state_of("alphamod"))

    def test_using_an_ungranted_capability_names_it(self):
        self.plan("alphamod")
        context = self.platform.load("alphamod", None, required=["core.log"])
        with self.assertRaises(E.PlatformError) as caught:
            _ = context.events
        self.assertEqual(E.E_CAPABILITY_NOT_GRANTED, caught.exception.code)
        self.assertIn("core.events", str(caught.exception))

    def test_a_future_major_api_is_refused(self):
        self.plan("alphamod")
        with self.assertRaises(E.PlatformError):
            self.platform.load("alphamod", None, api_requirement="^9.0.0")

    def test_the_api_minor_is_forward_compatible(self):
        # A mod built against an earlier MINOR of the same MAJOR must still load.
        current = CAP.API_VERSION
        older = semverlib.Version("%d.%d.0" % (current.major,
                                               max(0, current.minor - 1)))
        self.plan("alphamod")
        self.platform.load("alphamod", None, api_requirement="^%s" % older,
                           required=["core.log"])
        self.assertEqual(HOST.LOADED, self.platform.state_of("alphamod"))

    def test_no_capability_is_advertised_that_is_not_implemented(self):
        # Every advertised capability must be reachable from a context.
        self.plan("alphamod")
        context = self.platform.load("alphamod", None, required=ALL_CAPS)
        for name, accessor in (("core.events", "events"),
                               ("core.settings", "settings"),
                               ("core.input_registry", "input"),
                               ("core.services", "services"),
                               ("core.items", "items")):
            self.assertIn(name, CAP.CAPABILITIES)
            self.assertIsNotNone(getattr(context, accessor))


# ----------------------------------------------------------- host states ----

class LifecycleTests(PlatformCase):
    def test_a_failing_entry_point_releases_what_it_already_acquired(self):
        self.plan("alphamod")
        released = []

        def entry(ctx):
            ctx.events.declare("alphamod:ping")
            ctx.input.register("alphamod:toggle", "Toggle")
            ctx._owner.own("thing", "tracked", lambda: released.append("tracked"))
            raise RuntimeError("author bug")

        with self.assertRaises(E.PlatformError) as caught:
            self.load("alphamod", entry)
        self.assertEqual(E.E_LOAD_FAILED, caught.exception.code)
        self.assertEqual(HOST.FAILED, self.platform.state_of("alphamod"))
        self.assertEqual(["tracked"], released)
        # And nothing it registered survives.
        self.assertEqual([], self.platform.input.actions())
        self.assertNotIn("alphamod:ping", self.platform.events.declared())

    def test_failure_and_unload_use_the_same_teardown(self):
        self.plan("alphamod", "betamod")
        self.load("alphamod", lambda ctx: ctx.input.register(
            "alphamod:a", "A"))

        def failing(ctx):
            ctx.input.register("betamod:b", "B")
            raise RuntimeError("bug")
        with self.assertRaises(E.PlatformError):
            self.load("betamod", failing)
        good = self.platform.record("alphamod")
        bad = self.platform.record("betamod")
        self.platform.unload("alphamod")
        self.assertEqual(sorted(good.teardown), sorted(bad.teardown))

    def test_unloading_one_mod_leaves_the_other_untouched(self):
        self.plan("alphamod", "betamod")
        self.load("alphamod", lambda ctx: ctx.input.register("alphamod:a", "A"))
        self.load("betamod", lambda ctx: ctx.input.register("betamod:b", "B"))
        self.platform.unload("alphamod")
        names = [a["name"] for a in self.platform.input.actions()]
        self.assertEqual(["betamod:b"], names)
        self.assertEqual(HOST.LOADED, self.platform.state_of("betamod"))

    def test_shutdown_unloads_in_reverse_load_order(self):
        self.plan("first", "second", "third")
        for mod_id in ("first", "second", "third"):
            self.load(mod_id)
        reports = self.platform.shutdown()
        self.assertEqual(["third", "second", "first"],
                         [r["mod_id"] for r in reports])

    def test_loading_twice_is_refused(self):
        self.plan("alphamod")
        self.load("alphamod")
        with self.assertRaises(E.PlatformError) as caught:
            self.load("alphamod")
        self.assertEqual(E.E_MOD_ALREADY_LOADED, caught.exception.code)

    def test_an_unknown_mod_is_named(self):
        with self.assertRaises(E.PlatformError) as caught:
            self.platform.load("nosuchmod")
        self.assertEqual(E.E_UNKNOWN_MOD, caught.exception.code)

    def test_a_context_is_unusable_after_unload(self):
        self.plan("alphamod")
        context = self.load("alphamod")
        self.platform.unload("alphamod")
        self.assertFalse(context.alive)
        with self.assertRaises(E.PlatformError):
            _ = context.events


# ------------------------------------------------------------- logging ----

class LoggingTests(PlatformCase):
    def test_a_mod_cannot_attribute_a_record_to_another_mod(self):
        self.plan("alphamod")
        context = self.load("alphamod")
        record = context.log.info("hello")
        self.assertEqual("alphamod", record.mod_id)

    def test_the_budget_stops_one_mod_drowning_the_log(self):
        router = modlog.LogRouter(budget=5, window=1000)
        logger = modlog.ModLogger(router, "alphamod")
        for _ in range(50):
            logger.info("spam")
        self.assertEqual(45, router.drops_for("alphamod"))
        # And the drop is announced exactly once.
        announcements = [r for r in router.buffer.tail(100)
                         if "budget exceeded" in r.message]
        self.assertEqual(1, len(announcements))

    def test_a_throwing_sink_does_not_break_the_caller(self):
        router = modlog.LogRouter(sinks=[lambda r: (_ for _ in ()).throw(IOError())])
        modlog.ModLogger(router, "alphamod").info("still fine")
        self.assertEqual(1, len(router.buffer))


# ------------------------------------------------------- structured errors --

class ErrorTests(unittest.TestCase):
    def test_an_error_names_its_subsystem_and_code(self):
        error = E.PlatformError(E.SUB_EVENTS, E.E_NOT_FOUND, "no such event",
                                "alphamod")
        self.assertEqual("events.not_found", error.name)
        self.assertEqual("alphamod", error.as_wire()["mod_id"])

    def test_the_wire_form_is_two_ints_and_two_strings(self):
        wire = E.PlatformError(E.SUB_ITEMS, E.E_INVALID_ARGUMENT, "d", "m").as_wire()
        self.assertIsInstance(wire["subsystem"], int)
        self.assertIsInstance(wire["code"], int)
        self.assertIsInstance(wire["detail"], str)
        self.assertEqual({"subsystem", "code", "detail", "mod_id"}, set(wire))

    def test_zero_is_never_a_real_error_code(self):
        self.assertEqual(0, E.OK)
        self.assertNotIn(0, [E.E_INVALID_ARGUMENT, E.E_NOT_FOUND,
                             E.E_ALREADY_EXISTS, E.E_NOT_OWNED])

    def test_every_subsystem_has_a_name(self):
        for value in (E.SUB_PLATFORM, E.SUB_LIFECYCLE, E.SUB_LOG, E.SUB_EVENTS,
                      E.SUB_SETTINGS, E.SUB_INPUT, E.SUB_SERVICES, E.SUB_ITEMS,
                      E.SUB_CAPABILITIES, E.SUB_CONSOLE):
            self.assertIn(value, E.SUBSYSTEM_NAMES)


# -------------------------------------------------------------- console ----

class ConsoleTests(PlatformCase):
    def setUp(self):
        super().setUp()
        self.console = CONSOLE.Console(self.platform)

    def test_it_can_answer_every_question_the_stage_requires(self):
        self.plan("alphamod")
        self.load("alphamod", lambda ctx: (
            ctx.input.register("alphamod:a", "A"),
            ctx.events.declare("alphamod:ping")))
        required = {
            "discovered mods": "mods",
            "resolved load order": "loadorder",
            "mod state": "mods",
            "dependency/conflict failure": "why",
            "registered items": "items",
            "owned assets/resources": "owned",
            "structured subsystem errors": "errors",
        }
        for question, command in sorted(required.items()):
            result = self.console.run(command)
            self.assertTrue(result["ok"], "%s -> %s" % (question, result))

    def test_a_mod_command_stops_working_when_its_mod_unloads(self):
        self.plan("alphamod")
        context = self.load("alphamod")
        self.console.register(context._owner, "alphamod:hello", "hi",
                              lambda args: "hello")
        self.assertTrue(self.console.run("alphamod:hello")["ok"])
        self.platform.unload("alphamod")
        result = self.console.run("alphamod:hello")
        self.assertFalse(result["ok"])

    def test_a_mod_cannot_register_a_command_outside_its_namespace(self):
        self.plan("alphamod")
        context = self.load("alphamod")
        with self.assertRaises(E.PlatformError):
            self.console.register(context._owner, "betamod:evil", "x",
                                  lambda a: None)

    def test_an_unknown_command_is_reported_not_raised(self):
        result = self.console.run("definitely_not_a_command")
        self.assertFalse(result["ok"])
        self.assertIn("unknown command", result["error"])

    def test_a_throwing_command_is_reported_not_raised(self):
        self.plan("alphamod")
        context = self.load("alphamod")
        self.console.register(context._owner, "alphamod:boom", "x",
                              lambda args: (_ for _ in ()).throw(RuntimeError("x")))
        result = self.console.run("alphamod:boom")
        self.assertFalse(result["ok"])

    def test_output_renders_deterministically(self):
        self.plan("alphamod")
        self.load("alphamod")
        first = CONSOLE.render(self.console.run("mods"))
        second = CONSOLE.render(self.console.run("mods"))
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
