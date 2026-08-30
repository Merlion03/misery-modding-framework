#!/usr/bin/env python3
"""The aggregate items session: ONE runtime table, MANY rows, one attachment.

WHAT CHANGED AND WHY
--------------------
The mechanism this replaces created a NEW ``UDataTable`` per registration and
attached it into the composite's single spare parent slot. That works for
exactly one item and then fails closed at ``ParentTables.Num == 2`` -- correctly,
since no array growth is authorised. It was never the intended architecture; it
was what a one-item gate needed.

The aggregate is the intended shape:

    Items init      create + root ONE table, RowStruct = the real S_ItemDetails,
                    attach it to MasterItemList ONCE
    Register        materialize a temp S_ItemDetails, AddRow(ItemId) into that
                    table, keep only this registration's asset handles
    Unregister      RemoveRow(ItemId) from that table, release only this
                    registration's assets
    Items shutdown  remove whatever rows remain, detach, zero the spare slot,
                    release everything, restore the vanilla baseline exactly

WHY THIS IS A SESSION AND NOT A COMMAND
---------------------------------------
The table is rooted by the probe's asset store, and that store dies with the
probe module. So an aggregate that survives across registrations REQUIRES the
module to stay loaded across them -- which means the subsystem is a live session,
not a sequence of independent child processes. That is a real architectural
consequence and it is why this file exists at all.

THE ATTACHMENT POLICY, STATED
-----------------------------
The aggregate is attached at init and stays attached until shutdown, EVEN WHEN
EMPTY. The alternative -- detach when the last row goes -- was rejected: attach
and detach each rebuild ~496 composite rows and invalidate every MasterItemList
row pointer, so a mod that registers and unregisters one item repeatedly would
churn the whole table for nothing. An empty attached parent contributes no rows,
so it costs nothing to leave. This is tested, not assumed.
"""
import ctypes
import json
import os
import struct
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(REPO, "research", "instruments", "eri")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import eri                                   # noqa: E402
import ipp_controller as ipp                 # noqa: E402
import gt01_controller as gt                 # noqa: E402
import p04_controller as p04                 # noqa: E402
import probe_teardown                        # noqa: E402
import cr01c5_controller as c5               # noqa: E402
import io_layout                             # noqa: E402
import read_datatable_rows as rdr            # noqa: E402
import cr01c3_recon as recon                 # noqa: E402

# The scalar output block. Everything from here to the end of the IO is written
# by the probe and must survive from one registration to the next -- above all
# table_ptr, store_handle and trigger_fname, which ARE the aggregate.
_ELEMENT_OFFSETS, _ELEMENT_TOKENS = io_layout.offsets(c5.IO_FMT)
OUTPUT_BLOCK_BYTE = _ELEMENT_OFFSETS[c5.OUT_INDEX]

# Fields written back individually. Their offsets are proved against unpack_io
# before a single byte is sent to the game.
_INDEX_OF = {}


def _locate_u64(raw, value):
    """Element indices whose 8-byte read equals *value*."""
    hits = []
    for index, (offset, token) in enumerate(zip(_ELEMENT_OFFSETS, _ELEMENT_TOKENS)):
        if token != "Q":
            continue
        if struct.unpack_from("<Q", raw, offset)[0] == value:
            hits.append(index)
    return hits


def build_index_map(raw, decoded):
    """Element indices of the two handle fields this module writes by hand.

    DERIVED, not guessed. A first version of this hardcoded an arithmetic guess
    at where the C5 output block starts; a wrong index there would write an
    asset handle over a table pointer. So the anchors are the two loaded object
    POINTERS, which are distinctive enough to locate uniquely, and the handles
    are then at their documented offsets from those anchors -- the same label
    orders unpack_io itself uses.

    Every result is checked by IoLayout against the working decoder before use;
    if an anchor is not unique, nothing is returned and the caller fails closed.
    """
    out = {}
    for anchor, handle, delta in (("icon_object", "icon_store_handle", 4),
                                  ("mesh_object", "mesh_store_handle", 3)):
        value = decoded.get(anchor)
        if not value:
            raise SessionError(
                "cannot locate %s: %s is null, so there is no distinctive anchor to find "
                "it from. Load the asset before proving the layout." % (handle, anchor))
        hits = _locate_u64(raw, value)
        if len(hits) != 1:
            raise SessionError(
                "cannot locate %s: the anchor value for %s appears %d times in the IO "
                "block, so the index is ambiguous" % (handle, anchor, len(hits)))
        out[anchor] = hits[0]
        out[handle] = hits[0] + delta
    return out


class SessionError(Exception):
    pass


class AggregateSession(object):
    """One live aggregate table, for as long as the session is initialised."""

    def __init__(self, note=None):
        self.note = note if note is not None else []
        self.api = eri.Win32Api()
        self.k = None
        self.hp = None
        self.pid = None
        self.rbase = self.rio = self.rpath = None
        self.dll = None
        self.resolved = None
        self.offs = self.toffs = self.woffs = None
        self.layout = None
        self.initialised = False
        self.rows = {}            # row_name -> {"handles": {...}}
        self.table_ptr = None
        self._buf = None
        self._rd = None

    # ---- plumbing ----------------------------------------------------------
    def _read_raw(self):
        rd = ctypes.c_size_t(0)
        self.k.ReadProcessMemory(self.hp, self.rio, self._buf, c5.IO_SIZE, ctypes.byref(rd))
        return bytearray(self._buf.raw)

    def _write_raw(self, data):
        wr = ctypes.c_size_t(0)
        self.k.WriteProcessMemory(self.hp, self.rio, bytes(data), c5.IO_SIZE,
                                  ctypes.byref(wr))

    def _read_io(self):
        return c5.unpack_io(bytes(self._read_raw()))

    def _call(self, export, field, timeout=120.0):
        before = self._read_io()[field]
        p04.call_export(self.k, self.hp, self.rbase, self.dll, export, self.rio,
                        ipp.WAIT_TIMEOUT_MS)
        state = self._read_io()
        deadline = time.time() + timeout
        while time.time() < deadline and state[field] == before:
            time.sleep(0.05)
            state = self._read_io()
        return state

    def _say(self, message):
        self.note.append(message)

    # ---- init --------------------------------------------------------------
    def init(self, attach=True):
        if self.initialised:
            raise SessionError("this session is already initialised; a second aggregate "
                               "table must never be created while one is live")
        self.k, _ = gt._k32full()
        i01 = eri.run_i01(self.api, eri.DEFAULT_PROCESS_NAME)
        self.pid = i01["pid"]
        if ipp.sha256_of_file(i01["exe_path"]) != c5.fts.EXPECTED_BUILD_SHA256:
            raise SessionError("build fingerprint mismatch")
        img = c5.DiskImage(i01["exe_path"])
        addrs = c5.verify_carrier_addresses(self.api, self.pid, i01["base_address"], img,
                                            self.note)
        handle = eri.open_process_read_only(self.api, self.pid)
        try:
            r = c5.resolve(self.api, handle, i01["base_address"], i01["image_size_bytes"],
                           img, self.note)
            self.offs, _ = c5.verify_fields(self.api, handle, r["np"], r["row_struct"],
                                            c5.VALUES)
            self.toffs, _ = c5.text_fields(self.api, handle, r["np"], r["row_struct"],
                                           c5.TEXTS)
            self.woffs = c5.world_offsets(self.api, handle, r["np"], r["row_struct"],
                                          r["objs"])
        finally:
            self.api.close_handle(handle)
        self.resolved = r

        self.dll = c5.build_dll()
        sigs = {"add": img.bytes_at(c5.fts.RVA_ADD_TICKER, 16),
                "get": img.bytes_at(c5.fts.RVA_GET_CORE_TICKER, 16),
                "malloc": img.bytes_at(c5.fts.RVA_FMEMORY_MALLOC, 16)}
        carrier = {"add_ticker": addrs["add_ticker"],
                   "get_core_ticker": addrs["get_core_ticker"],
                   "fmemory_malloc": addrs["fmemory_malloc"]}

        self.hp = self.k.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, self.pid)
        if not self.hp:
            raise SessionError("OpenProcess failed")
        path_bytes = (self.dll + "\x00").encode("utf-16-le")
        self.rpath = self.k.VirtualAllocEx(self.hp, None, len(path_bytes),
                                           ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                           ipp.PAGE_READWRITE)
        wr = ctypes.c_size_t(0)
        self.k.WriteProcessMemory(self.hp, self.rpath, path_bytes, len(path_bytes),
                                  ctypes.byref(wr))
        loader = self.k.GetProcAddress(self.k.GetModuleHandleW("kernel32.dll"),
                                       b"LoadLibraryW")
        thread = self.k.CreateRemoteThread(self.hp, None, 0, loader, self.rpath, 0, None)
        self.k.WaitForSingleObject(thread, ipp.WAIT_TIMEOUT_MS)
        self.k.CloseHandle(thread)
        self.rbase = ipp.find_remote_module_base(self.k, self.pid, c5.DLL_NAME)
        if self.rbase is None:
            raise SessionError("probe DLL not loaded")

        packed = c5.pack_io(carrier, sigs, r, self.offs, self.toffs, self.woffs)
        self.rio = self.k.VirtualAllocEx(self.hp, None, c5.IO_SIZE,
                                         ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                         ipp.PAGE_READWRITE)
        self.k.WriteProcessMemory(self.hp, self.rio, packed, len(packed), ctypes.byref(wr))
        self._buf = ctypes.create_string_buffer(c5.IO_SIZE)

        if p04.call_export(self.k, self.hp, self.rbase, self.dll, "Init", self.rio,
                           ipp.WAIT_TIMEOUT_MS) != 0:
            raise SessionError("Init failed")

        state = self._call("RunCreate", "create_ran")
        if state["create_ran"] != 1:
            raise SessionError("aggregate table creation failed err=%s"
                               % c5.err_text(state["err"]))
        self.table_ptr = state["table_ptr"]
        self._say("aggregate table created at 0x%x, rooted, RowStruct = the live "
                  "S_ItemDetails" % self.table_ptr)

        # The layout is proved lazily, on the first registration -- its anchors
        # are the loaded icon and mesh POINTERS, which do not exist yet.

        if attach:
            state = self._call("RunAttach", "attach_ran")
            if state["attach_ran"] != 1:
                raise SessionError("attach failed err=%s" % c5.err_text(state["err"]))
            self._say("aggregate attached to MasterItemList once; "
                      "ParentTables.Num %d -> %d"
                      % (state["parent_num_before"], state["parent_num_after_attach"]))
        self.initialised = True
        return {"table_ptr": "0x%x" % self.table_ptr, "attached": bool(attach),
                "pid": self.pid}

    # ---- per-item IO -------------------------------------------------------
    def _bind_item_bytes(self, spec):
        """Rewrite the item-owned part of the live IO, preserving the aggregate.

        A fresh pack gives every input for this item; the scalar output block is
        copied back verbatim from the live IO, because that block IS the
        aggregate -- table_ptr, its store handle, the interned trigger, and the
        attach bookkeeping.
        """
        c5.bind_item(spec)
        img = c5.DiskImage(eri.run_i01(self.api, eri.DEFAULT_PROCESS_NAME)["exe_path"])
        sigs = {"add": img.bytes_at(c5.fts.RVA_ADD_TICKER, 16),
                "get": img.bytes_at(c5.fts.RVA_GET_CORE_TICKER, 16),
                "malloc": img.bytes_at(c5.fts.RVA_FMEMORY_MALLOC, 16)}
        # Rebuild with the SAME carrier values the session was initialised with,
        # read straight back out of the live IO so they cannot drift.
        live = self._read_raw()
        fresh = bytearray(c5.pack_io(
            {"add_ticker": struct.unpack_from("<Q", live, _ELEMENT_OFFSETS[3])[0],
             "get_core_ticker": struct.unpack_from("<Q", live, _ELEMENT_OFFSETS[4])[0],
             "fmemory_malloc": struct.unpack_from("<Q", live, _ELEMENT_OFFSETS[5])[0]},
            sigs, self.resolved, self.offs, self.toffs, self.woffs))
        fresh[OUTPUT_BLOCK_BYTE:] = live[OUTPUT_BLOCK_BYTE:]
        self._write_raw(fresh)

    def _set_u64(self, name, value):
        raw = self._read_raw()
        struct.pack_into("<Q", raw, self.layout.offset(name), value)
        self._write_raw(raw)

    # ---- register ----------------------------------------------------------
    def register(self, spec):
        if not self.initialised:
            raise SessionError("the items session is not initialised")
        row = spec["row_name"]
        if row in self.rows:
            return {"ok": False, "code": "already_registered", "detail": "%r is held" % row}
        self._bind_item_bytes(spec)

        state = self._call("RunInternRow", "internrow_ran")
        if state["internrow_ran"] != 1:
            return {"ok": False, "code": "intern_failed",
                    "detail": c5.err_text(state["err"])}
        state = self._call("RunLoadIcon", "loadicon_ran")
        if state["loadicon_ran"] != 1:
            return {"ok": False, "code": "icon_failed", "detail": c5.err_text(state["err"])}
        icon_handle, icon_obj = state["icon_store_handle"], state["icon_object"]
        state = self._call("RunLoadMesh", "loadmesh_ran")
        if state["loadmesh_ran"] != 1:
            return {"ok": False, "code": "mesh_failed", "detail": c5.err_text(state["err"])}
        mesh_handle, mesh_obj = state["mesh_store_handle"], state["mesh_object"]
        if self.layout is None:
            raw, decoded = bytes(self._read_raw()), self._read_io()
            self.layout = io_layout.IoLayout(c5.IO_FMT, raw, decoded,
                                             build_index_map(raw, decoded))
            self._say("IO field offsets proved against the working decoder: %s"
                      % sorted(self.layout.verified))
        state = self._call("RunPopulate", "populate_ran")
        if state["populate_ran"] != 1:
            return {"ok": False, "code": "populate_failed",
                    "detail": c5.err_text(state["err"])}

        self.rows[row] = {"spec": dict(spec),
                          "icon_handle": icon_handle, "mesh_handle": mesh_handle,
                          "icon_object": "0x%x" % icon_obj,
                          "mesh_object": "0x%x" % mesh_obj,
                          "row_fname": state["row_fname"]}
        return {"ok": True, "row_name": row, "owned_count": state["owned_count"],
                "handles": {"icon": icon_handle, "mesh": mesh_handle},
                "textdata": {"defaults": state["empty_textdata"],
                             "ours": state["our_textdata"]}}

    # ---- unregister --------------------------------------------------------
    def unregister(self, spec):
        if not self.initialised:
            raise SessionError("the items session is not initialised")
        row = spec["row_name"]
        held = self.rows.get(row)
        if held is None:
            return {"ok": False, "code": "not_registered", "detail": "%r is not held" % row}
        self._bind_item_bytes(spec)
        state = self._call("RunInternRow", "internrow_ran")
        if state["internrow_ran"] != 1:
            return {"ok": False, "code": "intern_failed",
                    "detail": c5.err_text(state["err"])}

        p04.call_export(self.k, self.hp, self.rbase, self.dll, "RunRemoveRow", self.rio,
                        ipp.WAIT_TIMEOUT_MS)
        # RunRemoveRow reports no completion field, so it is confirmed by reading
        # the aggregate's own RowMap -- a stronger check than a self-report.
        deadline = time.time() + 30.0
        while time.time() < deadline and row in self.table_rows():
            time.sleep(0.05)
        if row in self.table_rows():
            return {"ok": False, "code": "remove_failed",
                    "detail": "the row is still in the aggregate after RemoveRow"}

        # Release ONLY this registration's handles. The store refcounts by asset,
        # so an icon shared with another registration survives this.
        self._set_u64("icon_store_handle", held["icon_handle"])
        self._set_u64("mesh_store_handle", held["mesh_handle"])
        released = {}
        for export, field, key in (("RunReleaseMesh", "releasemesh_ran", "mesh"),
                                   ("RunReleaseIcon", "releaseicon_ran", "icon")):
            state = self._call(export, field)
            released[key] = {"ran": state[field], "owned_count": state["owned_count"]}
            if state[field] != 1:
                return {"ok": False, "code": "release_failed",
                        "detail": "%s: %s" % (key, c5.err_text(state["err"]))}
        del self.rows[row]
        return {"ok": True, "row_name": row, "released": released,
                "owned_count": released["icon"]["owned_count"]}

    # ---- queries -----------------------------------------------------------
    def table_rows(self):
        """The aggregate's own rows, by full FName identity.

        Comparison index AND number. Keying on the index alone collapses Foo and
        Foo_1, which this project has already been bitten by once as a 460
        against a real 496.
        """
        handle = eri.open_process_read_only(self.api, self.pid)
        try:
            np = self.resolved["np"]
            rows, _diag = rdr.read_rowmap(self.api, handle, self.table_ptr)
            names = []
            for cmp_index, number, _value in rows:
                text = eri.decode_fname_entry_id(self.api, handle, np, cmp_index).get("text")
                names.append(text if number == 0 else "%s_%d" % (text, number - 1))
            return names
        finally:
            self.api.close_handle(handle)

    # ---- shutdown ----------------------------------------------------------
    def shutdown(self):
        if not self.initialised:
            return {"ok": True, "detail": "not initialised"}
        report = {"rows_at_shutdown": sorted(self.rows), "removed": []}
        # Remaining rows go out through the SAME unregister a caller would use,
        # so shutdown cannot become a second, less-tested way of doing the same
        # thing -- and so a bug in unregister cannot hide behind a tidier path.
        for row in sorted(self.rows):
            outcome = self.unregister(dict(self.rows[row]["spec"]))
            report["removed"].append({"row": row, "ok": outcome.get("ok"),
                                      "code": outcome.get("code")})
        state = self._call("RunDetach", "detach_ran")
        report["detach"] = {"ran": state["detach_ran"],
                            "parent_num_after": state["parent_num_after_detach"]}
        state = self._call("RunZeroSlot", "zero_ran")
        report["zero_slot"] = {"ran": state["zero_ran"]}
        state = self._call("RunRelease", "release_ran")
        report["release_table"] = {"ran": state["release_ran"],
                                   "rooted_after": state["rooted_after_release"],
                                   "owned_count": state["owned_count"]}

        def read_safe():
            raw = self._read_raw()
            return {"wait_stopped_ok": struct.unpack_from(
                        "<I", raw, c5.WAIT_STOPPED_OK_OFFSET)[0],
                    "state": struct.unpack_from("<I", raw, c5.STATE_OFFSET)[0]}

        teardown = probe_teardown.shutdown_then_unload(
            self.k, self.hp, self.rbase, self.dll, self.rio, read_safe, self.note)
        report["teardown"] = teardown
        if teardown.get("safe_to_free_remote_memory"):
            for block in (self.rpath, self.rio):
                if block:
                    self.k.VirtualFreeEx(self.hp, block, 0, ipp.MEM_RELEASE)
            report["remote_memory_freed"] = True
        try:
            report["dll_unloaded"] = ipp.confirm_dll_unloaded(self.pid, c5.DLL_NAME)
        except Exception:                                      # noqa: BLE001
            report["dll_unloaded"] = None
        self.k.CloseHandle(self.hp)
        self.initialised = False
        self.rows.clear()
        report["ok"] = bool(teardown.get("unloaded"))
        return report
