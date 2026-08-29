#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The probe teardown invariant, enforced.

    Shutdown requested -> stop handshake confirms -> wait_stopped_ok == 1
      -> ONLY THEN FreeLibrary

This module exists because the invariant was violated once, in the worst way an
invariant can be: silently, on an error path nobody had exercised. On the first
armed CR-01C3D attempt a controller-side decode bug raised before Shutdown ran,
the teardown path unloaded the probe DLL anyway, and the engine's still-
registered FTSTicker callback ticked into freed memory and killed the game.

The fix is not "call Shutdown in the finally" -- that was the first patch, and
it is still not enough, because Shutdown itself can fail, time out, or report a
handshake that did not complete. The invariant is that the module is unloaded
ONLY on a confirmed stop, and that everything the loaded module still points at
(notably the remote IO block holding g_io) stays alive when it is not.

A leaked, still-loaded probe costs one game restart. Unloading code the engine
can still reach costs the session.
"""
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "ipp"))
sys.path.insert(0, os.path.join(REPO_ROOT, "research", "instruments", "eri"))

import probe_teardown  # noqa: E402


class FakeKernel32:
    """Records what the teardown actually did to the target process."""

    def __init__(self, free_library_fails=False):
        self.free_library_calls = 0
        self.free_library_fails = free_library_fails
        self.waits = 0
        self.closed = 0

    def GetProcAddress(self, module, name):
        assert name == b"FreeLibrary"
        return 0xF00D

    def GetModuleHandleW(self, name):
        return 0xBEEF

    def CreateRemoteThread(self, hproc, attrs, stack, start, param, flags, tid):
        assert start == 0xF00D, "teardown must only ever remote-call FreeLibrary"
        self.free_library_calls += 1
        return 0 if self.free_library_fails else 0x1234

    def WaitForSingleObject(self, handle, timeout):
        self.waits += 1
        return 0

    def CloseHandle(self, handle):
        self.closed += 1
        return True


def patched_call_export(result=None, raises=None):
    """Replace p04.call_export for the duration of one test."""
    calls = []

    def fake(k, hproc, base, dll, export, arg, timeout):
        calls.append(export)
        if raises is not None:
            raise raises
        return result

    return fake, calls


class ProbeTeardownInvariant(unittest.TestCase):
    def setUp(self):
        self._real = probe_teardown.p04.call_export

    def tearDown(self):
        probe_teardown.p04.call_export = self._real

    # ---- the one path on which unloading is permitted --------------------
    def test_unloads_only_after_a_confirmed_stop_handshake(self):
        probe_teardown.p04.call_export, calls = patched_call_export(result=0)
        k = FakeKernel32()
        out = probe_teardown.shutdown_then_unload(
            k, 1, 0x1000, "probe.dll", 0x2000,
            lambda: {"wait_stopped_ok": 1, "state": 3})
        self.assertEqual(calls, ["Shutdown"], "Shutdown must be requested first")
        self.assertTrue(out["unloaded"])
        self.assertTrue(out["safe_to_free_remote_memory"])
        self.assertIsNone(out["left_loaded_reason"])
        self.assertEqual(k.free_library_calls, 1)

    # ---- every failure mode must LEAVE IT LOADED -------------------------
    def test_handshake_not_confirmed_leaves_module_loaded(self):
        probe_teardown.p04.call_export, _ = patched_call_export(result=0)
        k = FakeKernel32()
        out = probe_teardown.shutdown_then_unload(
            k, 1, 0x1000, "probe.dll", 0x2000,
            lambda: {"wait_stopped_ok": 0, "state": 1})
        self.assertFalse(out["unloaded"])
        self.assertFalse(out["safe_to_free_remote_memory"])
        self.assertIn("wait_stopped_ok", out["left_loaded_reason"])
        self.assertEqual(k.free_library_calls, 0, "must NOT unload on an unconfirmed stop")

    def test_shutdown_raising_leaves_module_loaded(self):
        probe_teardown.p04.call_export, _ = patched_call_export(raises=RuntimeError("boom"))
        k = FakeKernel32()
        out = probe_teardown.shutdown_then_unload(
            k, 1, 0x1000, "probe.dll", 0x2000, lambda: {"wait_stopped_ok": 1})
        self.assertFalse(out["unloaded"])
        self.assertFalse(out["safe_to_free_remote_memory"])
        self.assertEqual(k.free_library_calls, 0)

    def test_shutdown_timeout_leaves_module_loaded(self):
        probe_teardown.p04.call_export, _ = patched_call_export(result=None)
        k = FakeKernel32()
        out = probe_teardown.shutdown_then_unload(
            k, 1, 0x1000, "probe.dll", 0x2000, lambda: {"wait_stopped_ok": 1})
        self.assertFalse(out["unloaded"])
        self.assertEqual(k.free_library_calls, 0)

    def test_a_raising_readback_leaves_module_loaded(self):
        """This is the exact shape of the bug that crashed the game: the decode
        of the shared IO block raised, so the handshake could not be read."""
        probe_teardown.p04.call_export, _ = patched_call_export(result=0)
        k = FakeKernel32()

        def exploding_read():
            raise TypeError("a bytes-like object is required, not 'int'")

        out = probe_teardown.shutdown_then_unload(
            k, 1, 0x1000, "probe.dll", 0x2000, exploding_read)
        self.assertFalse(out["unloaded"])
        self.assertFalse(out["safe_to_free_remote_memory"])
        self.assertIn("stop handshake", out["left_loaded_reason"])
        self.assertEqual(k.free_library_calls, 0)

    def test_freelibrary_failing_is_reported_as_still_loaded(self):
        probe_teardown.p04.call_export, _ = patched_call_export(result=0)
        k = FakeKernel32(free_library_fails=True)
        out = probe_teardown.shutdown_then_unload(
            k, 1, 0x1000, "probe.dll", 0x2000, lambda: {"wait_stopped_ok": 1})
        self.assertEqual(k.free_library_calls, 1)
        self.assertFalse(out["unloaded"])
        self.assertFalse(out["safe_to_free_remote_memory"])

    # ---- nothing loaded is not a failure ---------------------------------
    def test_module_never_loaded_is_not_a_teardown_failure(self):
        probe_teardown.p04.call_export, calls = patched_call_export(result=0)
        k = FakeKernel32()
        out = probe_teardown.shutdown_then_unload(
            k, 1, None, "probe.dll", 0x2000, lambda: {"wait_stopped_ok": 1})
        self.assertFalse(out["attempted"])
        self.assertTrue(out["safe_to_free_remote_memory"],
                        "if nothing was ever loaded, nothing points at the IO block")
        self.assertEqual(calls, [], "no Shutdown to request")
        self.assertEqual(k.free_library_calls, 0)

    def test_it_never_raises(self):
        """Teardown runs in a finally; if it raised it would mask the original
        error and skip the rest of the cleanup."""
        for kwargs in ({"result": 0}, {"result": None}, {"raises": RuntimeError("x")}):
            probe_teardown.p04.call_export, _ = patched_call_export(**kwargs)
            for reader in (lambda: {"wait_stopped_ok": 1},
                           lambda: {"wait_stopped_ok": 0},
                           lambda: (_ for _ in ()).throw(ValueError("nope"))):
                out = probe_teardown.shutdown_then_unload(
                    FakeKernel32(), 1, 0x1000, "probe.dll", 0x2000, reader)
                self.assertIsInstance(out, dict)


class ControllersUseTheInvariant(unittest.TestCase):
    """The three armed controllers must all route teardown through the helper,
    and must derive the handshake offsets rather than hand-counting them."""

    CONTROLLERS = ("cr01c3b_controller.py", "cr01c3c_controller.py", "cr01c3d_controller.py")

    def _source(self, name):
        path = os.path.join(REPO_ROOT, "research", "instruments", "ipp", name)
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def test_each_controller_calls_the_helper(self):
        for name in self.CONTROLLERS:
            src = self._source(name)
            self.assertIn("probe_teardown.shutdown_then_unload", src, name)

    def test_no_controller_calls_freelibrary_directly(self):
        for name in self.CONTROLLERS:
            src = self._source(name)
            self.assertNotIn(b"FreeLibrary".decode(), src,
                             "%s must not unload on its own; the invariant lives in "
                             "probe_teardown" % name)

    def test_remote_memory_is_only_freed_when_it_is_safe(self):
        for name in self.CONTROLLERS:
            src = self._source(name)
            self.assertIn('if td["safe_to_free_remote_memory"]:', src, name)

    def test_handshake_offsets_agree_with_the_full_unpack(self):
        import struct
        import cr01c3b_controller as b
        import cr01c3c_controller as c
        import cr01c3d_controller as d
        for mod in (b, c, d):
            buf = bytearray(mod.IO_SIZE)
            struct.pack_into("<I", buf, mod._OUTPUT_BLOCK_OFFSET + 8, 3)
            struct.pack_into("<I", buf, mod._OUTPUT_BLOCK_OFFSET + 12, 1)
            full = mod.unpack_io(bytes(buf))
            self.assertEqual(struct.unpack_from("<I", buf, mod.STATE_OFFSET)[0], full["state"])
            self.assertEqual(struct.unpack_from("<I", buf, mod.WAIT_STOPPED_OK_OFFSET)[0],
                             full["wait_stopped_ok"])


if __name__ == "__main__":
    unittest.main()
