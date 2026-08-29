#!/usr/bin/env python3
"""The probe teardown invariant.

    Shutdown requested
      -> the dispatcher's own stop handshake completes
      -> wait_stopped_ok == 1
      -> ONLY THEN FreeLibrary

If Shutdown fails, raises, times out, or the handshake does not report
wait_stopped_ok == 1, the module is LEFT LOADED and the caller reports BLOCKED.

WHY THIS EXISTS. The carrier registers an FTSTicker callback whose code lives in
the probe module. Unloading the module while that callback is still registered
makes the engine tick into freed memory and takes the game down -- which is
exactly what happened on the first armed CR-01C3D attempt, where a controller
exception skipped Shutdown and the teardown path unloaded anyway. A leaked,
still-loaded probe costs one game restart; unloading code the engine can still
reach costs the session and any unsaved progress with it.

The same reasoning applies to the remote IO block: the loaded module holds a
pointer to it (g_io), so when the module is left loaded the IO allocation must be
left alive too. Freeing it would leave a live dispatcher writing into unmapped
memory -- the identical failure one indirection further out.
"""
import os
import sys

IPP = os.path.dirname(os.path.abspath(__file__))
if IPP not in sys.path:
    sys.path.insert(0, IPP)
import ipp_controller as ipp  # noqa: E402
import p04_controller as p04  # noqa: E402


def shutdown_then_unload(k, hproc, remote_base, dll_path, rio, read_io, run_note=None,
                         timeout_ms=20000):
    """Returns a dict describing what happened. Never raises.

    Keys: attempted, shutdown_rc, wait_stopped_ok, state, unloaded,
          safe_to_free_remote_memory, left_loaded_reason.

    ``safe_to_free_remote_memory`` is the caller's signal for whether the remote
    IO/path allocations may be released: only ever true when the module is
    actually gone.
    """
    note = run_note.append if run_note is not None else (lambda _m: None)
    out = {"attempted": False, "shutdown_rc": None, "wait_stopped_ok": None, "state": None,
           "unloaded": False, "safe_to_free_remote_memory": False, "left_loaded_reason": None}
    if remote_base is None:
        out["safe_to_free_remote_memory"] = True     # nothing was ever loaded
        out["left_loaded_reason"] = None
        return out
    out["attempted"] = True

    try:
        out["shutdown_rc"] = p04.call_export(k, hproc, remote_base, dll_path, "Shutdown",
                                             rio, timeout_ms)
    except Exception as exc:                          # noqa: BLE001
        out["left_loaded_reason"] = "Shutdown raised: %r" % (exc,)
        note("TEARDOWN BLOCKED: %s -- leaving the probe LOADED" % out["left_loaded_reason"])
        return out
    if out["shutdown_rc"] is None:
        out["left_loaded_reason"] = "Shutdown returned no result (thread timed out)"
        note("TEARDOWN BLOCKED: %s -- leaving the probe LOADED" % out["left_loaded_reason"])
        return out

    try:
        st = read_io()
        out["wait_stopped_ok"] = st.get("wait_stopped_ok")
        out["state"] = st.get("state")
    except Exception as exc:                          # noqa: BLE001
        out["left_loaded_reason"] = "could not read back the stop handshake: %r" % (exc,)
        note("TEARDOWN BLOCKED: %s -- leaving the probe LOADED" % out["left_loaded_reason"])
        return out

    if out["wait_stopped_ok"] != 1:
        out["left_loaded_reason"] = ("stop handshake did not confirm: wait_stopped_ok=%r"
                                     % (out["wait_stopped_ok"],))
        note("TEARDOWN BLOCKED: %s -- leaving the probe LOADED" % out["left_loaded_reason"])
        return out

    # Handshake confirmed: the ticker is unregistered and the dispatcher is
    # stopped, so the module is no longer reachable from engine code.
    try:
        free_lib = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"FreeLibrary")
        thread = k.CreateRemoteThread(hproc, None, 0, free_lib, remote_base, 0, None)
        if not thread:
            out["left_loaded_reason"] = "CreateRemoteThread(FreeLibrary) failed"
            note("TEARDOWN BLOCKED: %s -- leaving the probe LOADED" % out["left_loaded_reason"])
            return out
        k.WaitForSingleObject(thread, ipp.WAIT_TIMEOUT_MS)
        k.CloseHandle(thread)
    except Exception as exc:                          # noqa: BLE001
        out["left_loaded_reason"] = "FreeLibrary raised: %r" % (exc,)
        note("TEARDOWN BLOCKED: %s -- leaving the probe LOADED" % out["left_loaded_reason"])
        return out

    out["unloaded"] = True
    out["safe_to_free_remote_memory"] = True
    note("teardown: stop handshake confirmed (wait_stopped_ok=1), module unloaded")
    return out
