#!/usr/bin/env python3
"""The build-specific half: turn an ``ItemDefinition`` into a live row.

This is the ONLY component that knows what ``S_ItemDetails`` looks like on a
particular game build, and it knows it indirectly -- everything it does goes
through the already-proven CR-01C5 controller, which resolves every field by
live reflection and refuses on any mismatch.

The dependency runs one way ON PURPOSE. This module imports the stable schema;
the schema imports nothing from here. If it ever went the other way the
build-independent layer would start acquiring build concerns, which is the exact
failure ``docs/mod-item-definition-boundary.md`` exists to prevent.

WHAT THIS LAYER IS EXPECTED TO DO
---------------------------------
Absorb churn. It changes when the game changes; the definitions above it do not.
So the flattening below is written to be obvious rather than clever: one
definition field to one controller input, with the proven-write field set named
in one place.
"""
import os
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_IPP = os.path.join(REPO, "research", "instruments", "ipp")
for _p in (_IPP, os.path.dirname(os.path.abspath(__file__))):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from registry import Materializer                                 # noqa: E402

CONTROLLER = os.path.join(_IPP, "cr01c5_controller.py")
WORKSPACE = os.path.join(REPO, "workspace", "items")


def flatten(definition):
    """An ItemDefinition -> the controller's build-specific input dict.

    Every value here traces to a field whose write has been verified live. The
    drag icon is resolved through the definition's own policy rather than being
    re-decided, so "which icon does the ghost use" has exactly one answer in the
    codebase.
    """
    drag = definition.effective_drag_icon()
    return {
        "row_name": definition.row_name,
        # The trigger is a data-neutral RemoveRow of a name that must NOT exist.
        # Derived per item so two concurrent registrations cannot share one.
        "trigger_name": "%s__neutral_trigger" % definition.row_name,
        "state_path": os.path.join(WORKSPACE, "%s.json" % definition.row_name),
        "icon_package": definition.inventory_icon.package,
        "icon_asset": definition.inventory_icon.asset,
        "drag_icon_package": drag.package,
        "drag_icon_asset": drag.asset,
        "mesh_package": definition.world_mesh.package,
        "mesh_asset": definition.world_mesh.asset,
        "world_class": definition.world_class,
        "texts": {"Name": definition.display_name,
                  "ShortName": definition.short_name,
                  "Description": definition.description},
        "values": {"Weight": definition.weight,
                   "Width": definition.width,
                   "Height": definition.height,
                   "MaxStack": definition.max_stack,
                   "AllowStacking": 1 if definition.allow_stacking else 0},
        "drag_size": tuple(definition.drag_icon_size),
        "scale": tuple(definition.transform.scale),
        "translation": tuple(definition.transform.translation),
    }


class C5Materializer(Materializer):
    """Drives the proven controller in a child process, one item at a time.

    A child process rather than an in-process call, because the controller
    loads a probe DLL into the game, runs it, and unloads it -- and that whole
    cycle is what has been proven. Importing it and calling ``run()`` directly
    would be a new, unproven arrangement of a mechanism that currently works.
    """

    def __init__(self, python=None, timeout=900):
        self.python = python or sys.executable
        self.timeout = timeout
        self.calls = []
        os.makedirs(WORKSPACE, exist_ok=True)

    # ---- the protocol ------------------------------------------------------
    def existing_row_names(self):
        """Every row the game currently resolves, read live and read-only.

        Returns None on any failure. None means UNKNOWN, and the registry
        treats that as a refusal to write -- which is the point: a collision
        that cannot be ruled out must not be risked.
        """
        try:
            import eri
            import cr01c3_recon as recon
            import read_datatable_rows as rdr
            api = eri.Win32Api()
            i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
            handle = eri.open_process_read_only(api, i01["pid"])
            try:
                namepool, objects = recon.universe(api, handle, i01["base_address"],
                                                   i01["image_size_bytes"])

                def class_name(address):
                    cls = eri._read_u64(api, handle,
                                        address + eri.DEFAULT_CLASS_PRIVATE_OFFSET)
                    return (objects.get(cls) or {}).get("name_text")

                master = [a for a, r in objects.items()
                          if r.get("name_ok") and r.get("name_text") == "MasterItemList"
                          and class_name(a) == "CompositeDataTable"]
                if len(master) != 1:
                    return None
                rows, _diag = rdr.read_rowmap(api, handle, master[0])
                names = set()
                for cmp_index, number, _value in rows:
                    try:
                        text = eri.decode_fname_entry_id(
                            api, handle, namepool, cmp_index).get("text")
                    except Exception:                              # noqa: BLE001
                        return None    # a name we could not decode is an unknown row
                    if text is None:
                        return None
                    # THE NUMBER IS PART OF THE NAME. An FName is (comparison
                    # index, number); number 0 means no suffix and N means
                    # "_<N-1>". Keying on the comparison index alone collapses
                    # Foo and Foo_1 into one entry -- this project has already
                    # paid for that exact mistake once, as a row undercount of
                    # 460 against a real 496, and a collision oracle that
                    # undercounts is one that can miss a collision.
                    names.add(text if number == 0 else "%s_%d" % (text, number - 1))
                return names
            finally:
                api.close_handle(handle)
        except Exception:                                          # noqa: BLE001
            return None

    def materialize(self, definition):
        spec = flatten(definition)
        outcome = self._run(["--arm", "--item-spec", _spec_path(spec)])
        self.calls.append(("materialize", definition.row_name, outcome["exit"]))
        if outcome["exit"] != 0:
            return {"ok": False, "detail": outcome["detail"], "exit": outcome["exit"]}
        return {"ok": True, "handle": spec["state_path"],
                "content_handles": {r.object_path: spec["state_path"]
                                    for r in definition.content_refs()},
                "detail": "registered via the CR-01C5 path"}

    def dematerialize(self, registration):
        spec = flatten(registration.definition)
        outcome = self._run(["--cleanup", "--item-spec", _spec_path(spec)])
        self.calls.append(("dematerialize", registration.definition.row_name,
                           outcome["exit"]))
        if outcome["exit"] != 0:
            return {"ok": False, "detail": outcome["detail"], "exit": outcome["exit"]}
        return {"ok": True, "detail": "unregistered and released"}

    # ---- plumbing ----------------------------------------------------------
    def _run(self, args):
        proc = subprocess.run([self.python, CONTROLLER] + args, capture_output=True,
                              text=True, timeout=self.timeout, cwd=REPO)
        tail = (proc.stderr or "").strip().splitlines()[-2:]
        return {"exit": proc.returncode,
                "detail": " | ".join(tail) if tail else "exit %d" % proc.returncode}


def _spec_path(spec):
    import json
    os.makedirs(WORKSPACE, exist_ok=True)
    path = os.path.join(WORKSPACE, "%s.spec.json" % spec["row_name"])
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(spec, f, indent=2, sort_keys=True, default=str)
        f.write("\n")
    return path
