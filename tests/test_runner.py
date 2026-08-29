#!/usr/bin/env python3
"""Tests for research/instruments/runner.

What is testable without a running game, and what is not, is the whole design
question here. These tests cover the parts where a defect would be silent:

  * session state -- that an address CANNOT cross a process boundary, and that
    a reused pid is rejected rather than accepted on the pid alone;
  * container consistency -- that a TOC whose blocks run past its CAS is
    rejected, that a leftover container fails the gate, and that staging
    refuses a path inside the game installation;
  * the settle predicate -- that a still-growing object census is not called
    ready, using injected clock/sleeper so the test costs no wall-clock time;
  * the gameplay invariants -- against synthetic object graphs shaped like the
    three states that actually occur: main menu, playtest hub, loaded session.

The synthetic graph is the important one. It is what lets "the playtest hub
must not pass" be a test rather than a comment, and the hub is precisely the
state that defeats a naive "is there a pawn?" check.
"""
import calendar
import json
import os
import struct
import sys
import tempfile
import time
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RUNNER_DIR = os.path.join(REPO_ROOT, "research", "instruments", "runner")
for _p in (RUNNER_DIR, os.path.join(REPO_ROOT, "tools", "inventory")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import containers            # noqa: E402
import lifecycle             # noqa: E402
import readiness             # noqa: E402
import saveentry             # noqa: E402
import saves                 # noqa: E402
import session as session_state  # noqa: E402


# --------------------------------------------------------------------------
# session state
# --------------------------------------------------------------------------

class SessionStateTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "session-state.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_address_fields_never_survive_a_restart(self):
        state = session_state.ProcessScopedState(
            pid=1234, start_time="2026-08-29T10:00:00Z", exe_path=r"C:\g.exe",
            build_sha256="abc", loaded_probe_module="Probe.dll",
            base_address=0x7ff600000000, image_size_bytes=138403840,
            remote_module_base=0x180000000, remote_io=0x20000000,
            remote_path=0x30000000)
        self.assertTrue(state.has_addresses())
        carried = state.carry_across_restart()
        self.assertFalse(carried.has_addresses(),
                         "an address survived a restart; that is the bug this "
                         "module exists to make impossible")
        self.assertIsNone(carried.pid)
        self.assertEqual(carried.loaded_probe_module, "Probe.dll")

    def test_every_declared_address_field_is_actually_an_attribute(self):
        state = session_state.ProcessScopedState()
        for field in session_state.ADDRESS_FIELDS:
            self.assertTrue(hasattr(state, field), field)
            self.assertIn(field, state.to_dict())

    def test_reused_pid_is_rejected_on_start_time(self):
        session_state.save(self.path, session_state.ProcessScopedState(
            pid=4242, start_time="2026-08-29T10:00:00Z", exe_path=r"C:\g.exe",
            base_address=0x1000))
        # Same pid, different start time: Windows handed the number to something else.
        state, _extra, why = session_state.load(
            self.path, lambda pid: ("2026-08-29T11:30:00Z", r"C:\g.exe"))
        self.assertIn("reused", why)
        self.assertFalse(state.has_addresses())

    def test_matching_process_keeps_its_addresses(self):
        session_state.save(self.path, session_state.ProcessScopedState(
            pid=4242, start_time="2026-08-29T10:00:00Z", exe_path=r"C:\g.exe",
            base_address=0x1000))
        state, _extra, why = session_state.load(
            self.path, lambda pid: ("2026-08-29T10:00:00Z", r"C:\g.exe"))
        self.assertIsNone(why)
        self.assertEqual(state.base_address, 0x1000)

    def test_dead_process_drops_addresses(self):
        session_state.save(self.path, session_state.ProcessScopedState(
            pid=4242, start_time="2026-08-29T10:00:00Z", base_address=0x1000))
        state, _extra, why = session_state.load(self.path, lambda pid: None)
        self.assertIn("not running", why)
        self.assertFalse(state.has_addresses())

    def test_missing_file_is_not_an_error(self):
        state, extra, why = session_state.load(
            os.path.join(self.tmp.name, "nope.json"), lambda pid: None)
        self.assertEqual(extra, {})
        self.assertIn("no session state", why)
        self.assertFalse(state.has_addresses())


# --------------------------------------------------------------------------
# containers
# --------------------------------------------------------------------------

def _synthetic_toc(block_offsets_and_sizes, *, magic=containers.IOSTORE_MAGIC,
                   flags=0x08, entry_size=12, enc_guid=b"\0" * 16):
    """Build a minimal but structurally real .utoc with a block table."""
    header_size = 144
    entry_count = 0
    phash_seeds = 0
    no_phash = 0
    header = bytearray(header_size)
    header[0:16] = magic
    header[16] = 6                                   # version
    struct_fields = containers.struct.pack_into
    struct_fields("<I", header, 20, header_size)     # TocHeaderSize
    struct_fields("<I", header, 24, entry_count)     # TocEntryCount
    struct_fields("<I", header, 28, len(block_offsets_and_sizes))
    struct_fields("<I", header, 32, entry_size)      # TocCompressedBlockEntrySize
    struct_fields("<I", header, 36, 0)               # CompressionMethodNameCount
    struct_fields("<I", header, 40, 32)              # CompressionMethodNameLength
    struct_fields("<I", header, 44, 65536)           # CompressionBlockSize
    struct_fields("<I", header, 48, 0)               # DirectoryIndexSize
    struct_fields("<I", header, 52, 1)               # PartitionCount
    struct_fields("<Q", header, 56, 0x1122334455667788)
    header[64:80] = enc_guid
    header[80] = flags
    struct_fields("<I", header, 84, phash_seeds)
    struct_fields("<Q", header, 88, 0xFFFFFFFFFFFFFFFF)
    struct_fields("<I", header, 96, no_phash)
    body = bytearray()
    for offset, size in block_offsets_and_sizes:
        entry = bytearray(12)
        struct_fields("<Q", entry, 0, offset)
        struct_fields("<I", entry, 4, (size << 8) | (offset >> 32 & 0xFF))
        struct_fields("<I", entry, 8, size)
        body += entry
    return bytes(header) + bytes(body)


class ContainerTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.stage = os.path.join(self.tmp.name, "Paks")
        os.makedirs(self.stage)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, stem, blocks, ucas_bytes, *, pak=True, **kwargs):
        with open(os.path.join(self.stage, stem + ".utoc"), "wb") as f:
            f.write(_synthetic_toc(blocks, **kwargs))
        with open(os.path.join(self.stage, stem + ".ucas"), "wb") as f:
            f.write(b"\0" * ucas_bytes)
        if pak:
            with open(os.path.join(self.stage, stem + ".pak"), "wb") as f:
                f.write(b"PAK\0")

    def test_coherent_container_is_mountable(self):
        self._write("Good_P", [(0, 100), (100, 100)], 256)
        rep = containers.check_stage_dir(self.stage)
        self.assertTrue(rep["consistent"], rep["containers"])

    def test_blocks_past_the_end_of_the_ucas_are_rejected(self):
        # This is the TOC-from-one-build / CAS-from-another signature.
        self._write("Torn_P", [(0, 100), (100, 5000)], 256)
        rep = containers.check_stage_dir(self.stage)
        self.assertFalse(rep["consistent"])
        reasons = rep["containers"][0]["reasons"]
        self.assertTrue(any("run past the end" in r for r in reasons), reasons)

    def test_encrypted_container_is_rejected(self):
        self._write("Enc_P", [(0, 10)], 64, flags=0x08 | 0x02)
        rep = containers.check_stage_dir(self.stage)
        self.assertFalse(rep["consistent"])
        self.assertTrue(any("Encrypted" in r for r in rep["containers"][0]["reasons"]))

    def test_missing_pak_is_named_as_a_staging_error(self):
        self._write("NoPak_P", [(0, 10)], 64, pak=False)
        rep = containers.check_stage_dir(self.stage)
        self.assertFalse(rep["consistent"])
        self.assertTrue(any("mount point missing" in r
                            for r in rep["containers"][0]["reasons"]))

    def test_leftover_container_fails_the_expectation(self):
        self._write("Wanted_P", [(0, 10)], 64)
        self._write("Leftover_P", [(0, 10)], 64)
        rep = containers.check_stage_dir(self.stage, expected=["Wanted_P"])
        self.assertFalse(rep["consistent"])
        self.assertEqual(rep["unexpected_containers"], ["Leftover_P"])

    def test_missing_expected_container_fails(self):
        rep = containers.check_stage_dir(self.stage, expected=["Wanted_P"])
        self.assertFalse(rep["consistent"])
        self.assertEqual(rep["missing_containers"], ["Wanted_P"])

    def test_pak_only_container_is_listed_not_judged(self):
        with open(os.path.join(self.stage, "PakOnly_P.pak"), "wb") as f:
            f.write(b"PAK\0")
        rep = containers.check_stage_dir(self.stage)
        self.assertEqual(rep["pak_only_containers"], ["PakOnly_P"])
        self.assertTrue(rep["consistent"])

    def test_staging_refuses_a_stage_dir_inside_the_game_installation(self):
        """The guard must fire on the DIRECTORY, before anything is created.

        With an empty profile there is no file for a per-file guard to catch,
        so a stage_dir inside the installation would otherwise be created and
        the run would report success. That was a real defect, found here.
        """
        install = containers.pathguard.CONFIGURED_INSTALL_ROOTS[0]
        inside = os.path.join(install, "MISERY", "Content", "Paks", "runner-test")
        with self.assertRaises(Exception):
            containers.apply_profile({}, stage_dir=inside)
        self.assertFalse(os.path.exists(inside), "the guard let a directory be created")
        with self.assertRaises(Exception):
            containers.apply_profile({"stage": [{"src": self.stage, "stem": "X_P"}]},
                                     stage_dir=inside)

    def test_removal_refuses_a_stem_that_escapes_the_stage_directory(self):
        outside = os.path.join(self.tmp.name, "outside.utoc")
        with open(outside, "wb") as f:
            f.write(b"x")
        with self.assertRaises(Exception):
            containers.apply_profile({"remove": [os.path.join("..", "outside")]},
                                     stage_dir=self.stage)
        self.assertTrue(os.path.isfile(outside), "a file outside the stage dir was removed")

    def test_dry_run_changes_nothing(self):
        self._write("Old_P", [(0, 10)], 64)
        actions = containers.apply_profile({"remove": ["Old_P"]}, stage_dir=self.stage,
                                           dry_run=True)
        self.assertEqual(actions["removed"], [])
        self.assertTrue(os.path.isfile(os.path.join(self.stage, "Old_P.utoc")))


# --------------------------------------------------------------------------
# the settle predicate
# --------------------------------------------------------------------------

class _FakeClock:
    def __init__(self):
        self.now = 1000.0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class _StubEri:
    """Just enough of eri for wait_runtime_inspectable."""

    DEFAULT_GUOBJECTARRAY_RVA = 0
    DEFAULT_NAMEPOOL_RVA = 0
    DEFAULT_NAME_POOL_INITIALIZED_RVA = 0
    DEFAULT_I02_SAMPLE_SIZE = 1
    DEFAULT_I02_MAX_SCAN_INDICES = 1

    def __init__(self, counts):
        self.counts = list(counts)
        self.calls = 0

    def run_i02(self, *_a, **_k):
        value = self.counts[min(self.calls, len(self.counts) - 1)]
        self.calls += 1
        if isinstance(value, Exception):
            raise value
        return {"num_elements": value, "objects_ptr_live_va": 0x1000}

    def run_i03(self, *_a, **_k):
        return {"namepool_live_va": 0x2000, "name_pool_initialized": True}


class SettleTests(unittest.TestCase):

    def _wait(self, counts, **kwargs):
        clock = _FakeClock()
        return readiness.wait_runtime_inspectable(
            _StubEri(counts), None, None, 0, 0, clock=clock.time, sleeper=clock.sleep,
            **kwargs)

    def test_a_growing_census_is_not_ready(self):
        with self.assertRaises(readiness.NotReady):
            self._wait([60000, 90000, 130000, 180000, 230000, 280000, 330000,
                        380000, 430000], timeout_s=20, interval_s=2.0)

    def test_a_settled_census_is_ready(self):
        result = self._wait([200000, 200010, 200020], timeout_s=60, interval_s=2.0)
        self.assertEqual(result["num_elements"], 200020)
        self.assertEqual(len(result["settle_window"]), 3)

    def test_a_census_below_the_floor_is_not_ready(self):
        with self.assertRaises(readiness.NotReady) as ctx:
            self._wait([100, 100, 100], timeout_s=10, interval_s=2.0)
        self.assertIn("below floor", str(ctx.exception))

    def test_read_failures_reset_the_settle_window(self):
        with self.assertRaises(readiness.NotReady):
            self._wait([200000, 200000, RuntimeError("torn read")],
                       timeout_s=12, interval_s=2.0)


# --------------------------------------------------------------------------
# gameplay invariants over a synthetic object graph
# --------------------------------------------------------------------------

# The FNamePool address the reflection path needs. Any non-None value: the
# graph stub resolves properties from its own tables, not from a real pool.
NAMEPOOL_SENTINEL = 0x2000


class _Graph:
    """A synthetic UObject graph with a real SuperStruct chain and real memory.

    Addresses are small integers and ``memory`` is what a u64 read returns, so
    readiness walks it with exactly the code it uses against the game: the
    SuperStruct chain at +0x40, ChildProperties at +0x50, and a possession
    pointer at whatever offset the fixture declares for AController::Pawn.
    """

    def __init__(self):
        self.objects = {}
        self.memory = {}
        self.properties = {}          # chain head -> [property dicts]
        self._next = 0x1000
        self._chain = 0x900000

    def _alloc(self):
        self._next += 0x1000
        return self._next

    def add(self, name, class_addr, outer=None, *, valid=True, address=None):
        address = address or self._alloc()
        self.objects[address] = {"valid": valid, "name_text": name, "name_ok": True,
                                 "class_ptr": class_addr, "outer_ptr": outer,
                                 "outer_ok": outer is not None}
        return address

    def add_class(self, name, outer, super_addr, meta_class_addr, properties=()):
        address = self.add(name, meta_class_addr, outer)
        self.memory[address + readiness.USTRUCT_SUPER_STRUCT_OFFSET] = super_addr
        if properties:
            self._chain += 0x100
            self.memory[address + _CHILD_PROPERTIES_OFFSET] = self._chain
            self.properties[self._chain] = list(properties)
        return address

    def write_u64(self, address, value):
        self.memory[address] = value


_CHILD_PROPERTIES_OFFSET = 0x50       # eri.USTRUCT_CHILD_PROPERTIES_OFFSET


class _GraphEri:
    """The slice of eri that readiness actually uses, over a _Graph."""

    UCLASS_SELF_REFERENCE_NAME = "Class"
    UCLASS_SELF_REFERENCE_OBJECT_PATH = "/Script/CoreUObject.Class"
    USTRUCT_CHILD_PROPERTIES_OFFSET = _CHILD_PROPERTIES_OFFSET

    def __init__(self, graph):
        self.graph = graph

    def resolve_object_path(self, address, objects, **_k):
        parts = []
        cursor, depth = address, 0
        while cursor and depth < 32:
            record = objects.get(cursor)
            if record is None or not record.get("name_ok"):
                return {"object_path": None}
            parts.append(record["name_text"])
            cursor = record.get("outer_ptr")
            depth += 1
        parts.reverse()
        if not parts:
            return {"object_path": None}
        return {"object_path": parts[0] + ("." + ".".join(parts[1:]) if len(parts) > 1 else "")}

    @staticmethod
    def canonicalize_object_path(path):
        return path

    def _read_u64(self, _api, _handle, address):
        return self.graph.memory.get(address, 0)

    def walk_property_chain(self, _api, _handle, chain_head, **_k):
        return {"accepted": self.graph.properties.get(chain_head, [])}


PAWN_PROPERTY_OFFSET = 720            # AController::Pawn, as measured on this build
ACK_PAWN_PROPERTY_OFFSET = 824        # APlayerController::AcknowledgedPawn


def _prop(name, offset):
    return {"raw_name": name, "offset": offset, "size": 8,
            "property_class": "FObjectProperty"}


def _build_graph(*, state, possess=True, ack_agrees=True, inventory_owner="controller"):
    """Build one of: 'menu', 'hub', 'session', 'client'."""
    g = _Graph()
    core = g.add("/Script/CoreUObject", None)
    engine_pkg = g.add("/Script/Engine", None)

    class_meta = g._alloc()
    g.objects[class_meta] = {"valid": True, "name_text": "Class", "name_ok": True,
                             "class_ptr": class_meta, "outer_ptr": core, "outer_ok": True}
    uobject = g.add_class("Object", core, 0, class_meta)
    g.memory[class_meta + readiness.USTRUCT_SUPER_STRUCT_OFFSET] = uobject
    bpgc = g.add_class("BlueprintGeneratedClass", core, uobject, class_meta)

    actor = g.add_class("Actor", engine_pkg, uobject, class_meta)
    pawn_cls = g.add_class("Pawn", engine_pkg, actor, class_meta)
    controller_cls = g.add_class("Controller", engine_pkg, actor, class_meta,
                                 properties=[_prop("Pawn", PAWN_PROPERTY_OFFSET)])
    player_controller = g.add_class(
        "PlayerController", engine_pkg, controller_cls, class_meta,
        properties=[_prop("AcknowledgedPawn", ACK_PAWN_PROPERTY_OFFSET)])
    info = g.add_class("Info", engine_pkg, actor, class_meta)
    game_mode_base = g.add_class("GameModeBase", engine_pkg, info, class_meta)
    net_driver = g.add_class("NetDriver", engine_pkg, uobject, class_meta)
    world_class = g.add_class("World", engine_pkg, uobject, class_meta)
    level_class = g.add_class("Level", engine_pkg, uobject, class_meta)
    component = g.add_class("ActorComponent", engine_pkg, uobject, class_meta)

    if state == "menu":
        return g

    world_pkg = g.add("/Game/Maps/Level", None)
    world = g.add("L_MenuMap03" if state == "hub_menu" else "NewMapGENTEST",
                  world_class, world_pkg)
    level = g.add("PersistentLevel", level_class, world)

    if state == "hub":
        hub_pawn_class = g.add_class("BP_PlaytestBeginPlyer_C", world_pkg, pawn_cls, bpgc)
        hub_mode_class = g.add_class("PlaytestBeginPGmaemode_C", world_pkg, game_mode_base, bpgc)
        inv_class = g.add_class("BP_PlayerInventory_C", world_pkg, component, bpgc)
        hub_pawn = g.add("BP_PlaytestBeginPlyer_C_0", hub_pawn_class, level)
        g.add("PlaytestBeginPGmaemode_C_0", hub_mode_class, level)
        controller = g.add("BP_MiseryPlayerController_C_0", player_controller, level)
        g.add("BP_PlayerInventory", inv_class, controller)
        g.write_u64(controller + PAWN_PROPERTY_OFFSET, hub_pawn)
        g.write_u64(controller + ACK_PAWN_PROPERTY_OFFSET, hub_pawn)
        return g

    pawn_class = g.add_class("BP_SGKMasterCharacter_C", world_pkg, pawn_cls, bpgc)
    ai_class = g.add_class("BP_CrayFish_C", world_pkg, pawn_cls, bpgc)
    inv_class = g.add_class("BP_PlayerInventory_C", world_pkg, component, bpgc)
    mode_class = g.add_class("BP_SGKGameMode_C", world_pkg, game_mode_base, bpgc)

    player_pawn = g.add("BP_SGKMasterCharacter_C", pawn_class, level)
    # Thirty-three AI pawns, exactly the situation that makes "a pawn exists"
    # meaningless in this game and forces the possession check.
    for index in range(33):
        g.add("BP_CrayFish_C_%d" % index, ai_class, level)
    controller = g.add("BP_SGKController_C", player_controller, level)
    owner = controller if inventory_owner == "controller" else player_pawn
    g.add("BP_PlayerInventory", inv_class, owner)
    if possess:
        g.write_u64(controller + PAWN_PROPERTY_OFFSET, player_pawn)
        g.write_u64(controller + ACK_PAWN_PROPERTY_OFFSET,
                    player_pawn if ack_agrees else g.add("Other", ai_class, level))
    if state == "session":
        g.add("BP_SGKGameMode_C_0", mode_class, level)
    if state == "client":
        g.add("BP_SGKGameMode_C_0", mode_class, level)
        g.add("IpNetDriver_0", net_driver, world)
    return g


class GameplayInvariantTests(unittest.TestCase):

    def _verdict(self, state, expect=None, namepool=NAMEPOOL_SENTINEL, **kwargs):
        graph = _build_graph(state=state, **kwargs)
        return readiness.prove_gameplay(_GraphEri(graph), None, None, graph.objects,
                                        namepool=namepool,
                                        expect=expect or {"authority": "standalone"})

    def test_loaded_session_is_ready(self):
        verdict = self._verdict("session")
        self.assertTrue(verdict["ready"], verdict["reasons"])
        self.assertTrue(verdict["facts"]["has_authority"])
        self.assertEqual(verdict["facts"]["net_mode_observed"], "standalone")
        self.assertEqual(verdict["facts"]["player_pawn"]["class"], "BP_SGKMasterCharacter_C")

    def test_the_possessed_pawn_is_picked_out_of_thirty_four(self):
        """34 live pawns, 33 of them AI. Only possession identifies the player's."""
        verdict = self._verdict("session")
        self.assertTrue(verdict["ready"], verdict["reasons"])
        self.assertEqual(verdict["facts"]["possession"]["Pawn"]["declared_on"], "Controller")
        self.assertEqual(verdict["facts"]["possession"]["AcknowledgedPawn"]["declared_on"],
                         "PlayerController")

    def test_unpossessed_controller_is_not_ready(self):
        """The player has not spawned yet: Pawn is null."""
        verdict = self._verdict("session", possess=False)
        self.assertFalse(verdict["ready"])
        self.assertTrue(any("possesses no pawn" in r for r in verdict["reasons"]),
                        verdict["reasons"])

    def test_mid_possession_is_not_ready(self):
        """Pawn and AcknowledgedPawn disagree -- a half-built player."""
        verdict = self._verdict("session", ack_agrees=False)
        self.assertFalse(verdict["ready"])
        self.assertTrue(any("mid-possession" in r for r in verdict["reasons"]),
                        verdict["reasons"])

    def test_inventory_owned_by_something_else_is_not_ready(self):
        verdict = self._verdict("session", inventory_owner="pawn")
        self.assertFalse(verdict["ready"])
        self.assertTrue(any("Outer" in r for r in verdict["reasons"]), verdict["reasons"])

    def test_main_menu_is_not_ready(self):
        verdict = self._verdict("menu")
        self.assertFalse(verdict["ready"])
        self.assertTrue(any("no live World" in r for r in verdict["reasons"]),
                        verdict["reasons"])

    def test_playtest_hub_is_not_ready(self):
        """The state that defeats a naive 'is there a pawn?' check."""
        verdict = self._verdict("hub")
        self.assertFalse(verdict["ready"])
        self.assertTrue(any("playtest-hub" in r for r in verdict["reasons"]),
                        verdict["reasons"])

    def test_client_without_authority_fails_a_standalone_expectation(self):
        verdict = self._verdict("client", expect={"authority": "standalone"})
        self.assertFalse(verdict["ready"])
        self.assertEqual(verdict["facts"]["net_mode_observed"], "networked")
        self.assertTrue(any("authority" in r for r in verdict["reasons"]), verdict["reasons"])

    def test_wrong_world_name_fails(self):
        verdict = self._verdict("session", expect={"authority": "standalone",
                                                   "world_name": "SomeOtherLevel"})
        self.assertFalse(verdict["ready"])
        self.assertTrue(any("expected a live World" in r for r in verdict["reasons"]))

    def test_wrong_pawn_class_fails(self):
        verdict = self._verdict("session", expect={"authority": "standalone",
                                                   "player_pawn_class": "BP_SomethingElse_C"})
        self.assertFalse(verdict["ready"])
        self.assertTrue(any("expected BP_SomethingElse_C" in r for r in verdict["reasons"]))

    def test_missing_namepool_fails_rather_than_skipping_the_check(self):
        """An invariant that cannot be evaluated must fail, never vanish."""
        verdict = self._verdict("session", namepool=None)
        self.assertFalse(verdict["ready"])
        self.assertTrue(any("not silently skipped" in r for r in verdict["reasons"]),
                        verdict["reasons"])

    def test_super_chain_self_check_catches_a_wrong_offset(self):
        """A chain that does not terminate at UObject yields NO ancestry.

        This is the live self-verification of USTRUCT_SUPER_STRUCT_OFFSET: if
        the offset were wrong for a build, the walk would not reach
        /Script/CoreUObject.Object, and every ancestry answer must then be
        False rather than accidentally-True.
        """
        graph = _build_graph(state="session")
        dangling = graph.add_class("Orphan_C", None, 0x999999, 0)
        paths = readiness.ancestor_paths(_GraphEri(graph), None, None, dangling,
                                         graph.objects, {})
        self.assertEqual(paths, frozenset())

    def test_missing_player_inventory_is_named(self):
        graph = _build_graph(state="session")
        for address, record in list(graph.objects.items()):
            if record["name_text"] == "BP_PlayerInventory":
                del graph.objects[address]
        verdict = readiness.prove_gameplay(_GraphEri(graph), None, None, graph.objects,
                                           namepool=NAMEPOOL_SENTINEL,
                                           expect={"authority": "standalone"})
        self.assertFalse(verdict["ready"])
        self.assertTrue(any("BP_PlayerInventory" in r for r in verdict["reasons"]))


# --------------------------------------------------------------------------
# UI state classification
# --------------------------------------------------------------------------

def _screen(classes, worlds):
    """A minimal object graph carrying just the classes and worlds a screen has."""
    objects = {}
    address = 0x10000
    world_class = address
    objects[world_class] = {"valid": True, "name_text": "World", "name_ok": True,
                            "class_ptr": world_class, "outer_ptr": None}
    for name in classes:
        address += 0x100
        class_addr = address
        objects[class_addr] = {"valid": True, "name_text": name, "name_ok": True,
                               "class_ptr": 0, "outer_ptr": None}
        address += 0x100
        objects[address] = {"valid": True, "name_text": name + "_0", "name_ok": True,
                            "class_ptr": class_addr, "outer_ptr": None}
    for name in worlds:
        address += 0x100
        objects[address] = {"valid": True, "name_text": name, "name_ok": True,
                            "class_ptr": world_class, "outer_ptr": None}
    return objects


class ScreenClassificationTests(unittest.TestCase):

    def _name(self, classes, worlds):
        state = saveentry.classify_state(_screen(classes, worlds))
        return state and state["name"]

    def test_thank_you_screen(self):
        self.assertEqual(self._name(["WD_PlaytestNote01_C", "BP_PlaytestBeginPlyer_C"],
                                    ["PlaytestHub"]), "THANK_YOU_SCREEN")

    def test_main_menu(self):
        self.assertEqual(self._name(["BP_MainMenu_C", "BP_SGKMenuGameMode_C"],
                                    ["L_MenuMap03"]), "MAIN_MENU")

    def test_menu_map_is_matched_by_prefix_not_by_name(self):
        """The backdrop level is chosen at random per launch (L_MenuMap07,
        L_MenuMap03 measured on consecutive launches). Pinning the name made the
        classifier fall through at an ordinary main menu."""
        for suffix in ("01", "03", "07", "12"):
            self.assertEqual(self._name(["BP_MainMenu_C", "BP_SGKMenuGameMode_C"],
                                        ["L_MenuMap" + suffix]), "MAIN_MENU", suffix)

    def test_load_game_menu_wins_over_main_menu(self):
        """The load list is drawn OVER the main menu, so both signatures are live;
        the save-metadata object is the discriminator and must be matched first."""
        self.assertEqual(self._name(["BP_MainMenu_C", "BP_SGKMenuGameMode_C",
                                     "BP_SGKSaveGameMetaData_C"],
                                    ["L_MenuMap03"]), "LOAD_GAME_MENU")

    def test_world_loading_is_the_fallback(self):
        self.assertEqual(self._name(["BP_AIManager_C"], ["NewMapGENTEST"]), "WORLD_LOADING")

    def test_save_metadata_during_a_level_load_is_not_the_load_menu(self):
        """Measured: BP_SGKSaveGameMetaData_C stays live while the level loads. If
        that still classified as LOAD_GAME_MENU the machine would click the save
        row a second time, at a live game."""
        self.assertEqual(self._name(["BP_SGKSaveGameMetaData_C", "BP_AIManager_C"],
                                    ["NewMapGENTEST"]), "WORLD_LOADING")

    def test_the_note_screen_is_never_the_loading_fallback(self):
        self.assertEqual(self._name(["WD_PlaytestNote01_C"], ["PlaytestHub"]),
                         "THANK_YOU_SCREEN")

    def test_death_screen_is_recognised_and_halts(self):
        """Found by leaving the acceptance session idle for an hour: the
        character starved. A survival game's unattended loop meets this screen,
        and the runner must recognise it rather than call it unknown -- and must
        refuse to press respawn, which would change the save."""
        state = saveentry.classify_state(
            _screen(["BP_DeathScreen_C", "BP_AIManager_C"], ["NewMapGENTEST"]))
        self.assertEqual(state["name"], "DEATH_SCREEN")
        self.assertTrue(state["halt"])
        self.assertIsNone(state["action"])

    def test_death_screen_wins_over_the_loading_fallback(self):
        self.assertEqual(self._name(["BP_DeathScreen_C"], ["NewMapGENTEST"]),
                         "DEATH_SCREEN")

    def test_an_unrecognised_screen_classifies_as_nothing(self):
        """And nothing is what makes the machine stop instead of guessing a key."""
        self.assertIsNone(self._name(["BP_SomeUnknownScreen_C"], ["L_MenuMap03"]))


class SaveRowTests(unittest.TestCase):
    """The load-list row is computed, never configured."""

    SLOTS = [
        {"slot": "123", "ticks": 200, "time": "b", "level": "M"},
        {"slot": "123_Auto", "ticks": 300, "time": "a", "level": "M"},
        {"slot": "Old", "ticks": 100, "time": "c", "level": "M"},
    ]

    def test_rows_are_ordered_newest_first(self):
        ordered = sorted(self.SLOTS, key=lambda s: s["ticks"], reverse=True)
        self.assertEqual([s["slot"] for s in ordered], ["123_Auto", "123", "Old"])

    def test_row_of_slot_uses_that_order(self):
        original = saves.read_save_slots
        saves.read_save_slots = lambda save_dir=None: [
            dict(s, row=i) for i, s in enumerate(
                sorted(self.SLOTS, key=lambda x: x["ticks"], reverse=True))]
        try:
            entry, _all = saves.row_of_slot("123")
            self.assertEqual(entry["row"], 1)
            # An autosave lands on top and pushes the configured save down a row.
            # A hardcoded row index would now be loading the wrong save silently.
            self.assertEqual(saves.row_of_slot("123_Auto")[0]["row"], 0)
        finally:
            saves.read_save_slots = original

    def test_absent_slot_is_a_hard_failure(self):
        original = saves.read_save_slots
        saves.read_save_slots = lambda save_dir=None: []
        try:
            with self.assertRaises(saves.SaveParseError):
                saves.row_of_slot("nope")
        finally:
            saves.read_save_slots = original

    def test_fstring_reads_ascii_and_utf16(self):
        reader = saves._Reader(struct.pack("<i", 6) + b"hello\x00")
        self.assertEqual(reader.fstring(), "hello")
        text = "Сохранение".encode("utf-16-le") + b"\x00\x00"
        reader = saves._Reader(struct.pack("<i", -(len(text) // 2)) + text)
        self.assertEqual(reader.fstring(), "Сохранение")

    def test_type_name_reads_a_nested_node_list(self):
        """UE 5.4's FPropertyTypeName: pre-order (FName, InnerCount) nodes.

        This exact shape -- ArrayProperty<StructProperty<S_SaveMetaData<path>>> --
        is what a MISERY save's metadata array carries, and reading it as UE4's
        old single-FName type is what makes the file look corrupt.
        """
        def node(name, inner):
            raw = name.encode("ascii") + b"\x00"
            return struct.pack("<i", len(raw)) + raw + struct.pack("<i", inner)
        data = (node("ArrayProperty", 1) + node("StructProperty", 2)
                + node("S_SaveMetaData", 1) + node("/Game/S_SaveMetaData", 0)
                + node("guid-here", 0))
        nodes = saves.read_type_name(saves._Reader(data))
        self.assertEqual([n[0] for n in nodes],
                         ["ArrayProperty", "StructProperty", "S_SaveMetaData",
                          "/Game/S_SaveMetaData", "guid-here"])


# --------------------------------------------------------------------------
# lifecycle helpers that do not need a game
# --------------------------------------------------------------------------

class _FakeK32:
    pass


class LifecycleTests(unittest.TestCase):

    def test_filetime_epoch_conversion(self):
        class FT:
            dwLowDateTime = 0
            dwHighDateTime = 0
        self.assertIsNone(lifecycle._filetime_to_iso(FT()))
        # The expected instant is computed, not typed: a hand-written epoch
        # constant is exactly the kind of thing that is wrong by three days and
        # then "fixed" by changing the code it was testing.
        wanted = "2026-08-29T10:00:00Z"
        epoch = calendar.timegm(time.strptime(wanted, "%Y-%m-%dT%H:%M:%SZ"))
        ticks = int((epoch + 11644473600) * 10_000_000)
        FT.dwLowDateTime = ticks & 0xFFFFFFFF
        FT.dwHighDateTime = ticks >> 32
        self.assertEqual(lifecycle._filetime_to_iso(FT()), wanted)

    def test_wait_for_new_process_refuses_two_candidates(self):
        clock = _FakeClock()
        original = lifecycle.find_processes
        lifecycle.find_processes = lambda name=lifecycle.PROCESS_NAME, k=None: [
            {"pid": 10, "start_time": "2026-08-29T10:00:00Z", "exe_path": "a"},
            {"pid": 11, "start_time": "2026-08-29T10:00:00Z", "exe_path": "a"}]
        try:
            with self.assertRaises(lifecycle.LifecycleError) as ctx:
                lifecycle.wait_for_new_process(timeout_s=5, clock=clock.time,
                                               sleeper=clock.sleep)
            self.assertIn("refusing to guess", str(ctx.exception))
        finally:
            lifecycle.find_processes = original

    def test_wait_for_new_process_excludes_the_old_pid(self):
        clock = _FakeClock()
        original = lifecycle.find_processes
        lifecycle.find_processes = lambda name=lifecycle.PROCESS_NAME, k=None: [
            {"pid": 10, "start_time": "2026-08-29T10:00:00Z", "exe_path": "a"},
            {"pid": 11, "start_time": "2026-08-29T10:00:00Z", "exe_path": "a"}]
        try:
            found = lifecycle.wait_for_new_process(excluded_pids=[10], timeout_s=5,
                                                   clock=clock.time, sleeper=clock.sleep)
            self.assertEqual(found["pid"], 11)
        finally:
            lifecycle.find_processes = original

    def test_prove_gone_times_out_while_a_process_remains(self):
        clock = _FakeClock()
        original = lifecycle.find_processes
        lifecycle.find_processes = lambda name=lifecycle.PROCESS_NAME, k=None: [
            {"pid": 10, "start_time": None, "exe_path": None}]
        try:
            with self.assertRaises(lifecycle.LifecycleError):
                lifecycle.prove_gone([10], timeout_s=3, clock=clock.time,
                                     sleeper=clock.sleep)
        finally:
            lifecycle.find_processes = original


# --------------------------------------------------------------------------
# registry and config
# --------------------------------------------------------------------------

class RegistryTests(unittest.TestCase):

    def test_shipped_config_parses_and_declares_the_current_build(self):
        with open(os.path.join(RUNNER_DIR, "runner-config.json"), encoding="utf-8") as f:
            config = json.load(f)
        index_path = os.path.join(REPO_ROOT, "research", "builds", "index.json")
        with open(index_path, encoding="utf-8") as f:
            index = json.load(f)
        key = "sha256:" + config["build"]["expected_sha256"]
        self.assertIn(key, index,
                      "the runner's expected build is not a build this repository knows")
        self.assertEqual(index[key]["build_id"], config["build"]["build_id"])

    def test_probe_registry_entries_are_real_scripts(self):
        import runner
        for name, entry in runner.PROBES.items():
            script = os.path.join(REPO_ROOT, entry["script"])
            self.assertTrue(os.path.isfile(script), "%s -> %s" % (name, script))
            self.assertIn("armed", entry)
            self.assertIn("what", entry)

    def test_armed_probe_is_refused_without_the_flag(self):
        import runner
        original = dict(runner.PROBES)
        runner.PROBES["fake-armed"] = {"script": "research/instruments/ipp/cr01c3_recon.py",
                                       "argv": [], "armed": True, "what": "test"}
        try:
            with self.assertRaises(runner.CycleFailed) as ctx:
                runner.phase_probe("fake-armed", tempfile.gettempdir(), [], allow_armed=False)
            self.assertIn("--allow-armed-probe", str(ctx.exception))
        finally:
            runner.PROBES.clear()
            runner.PROBES.update(original)

    def test_unknown_probe_is_refused(self):
        import runner
        with self.assertRaises(runner.CycleFailed):
            runner.phase_probe("no-such-probe", tempfile.gettempdir(), [])


if __name__ == "__main__":
    unittest.main()
